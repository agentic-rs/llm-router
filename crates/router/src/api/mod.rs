pub mod access;
pub mod codec;
pub mod endpoints;
pub mod error;
pub mod identity;
pub mod models;
pub mod providers;
pub mod response;

use crate::api::identity::AccountIdentityResolver;
use anyhow::Result;
use arc_swap::ArcSwap;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::response::Response as AxumResponse;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokn_accounts::registry::Registry as ProviderRegistry;
use tokn_accounts::routing::RouteResolver;
use tokn_accounts::{AccountInventory, AccountPool, AccountPoolRuleset};
use tokn_config::ProxyProviderMode;
use tokn_config::RouteMode;
use tokn_config::{AgentId, Config, ModelFamily, ProfileConfig};
use tokn_core::account::AccountConfig;
use tokn_core::event::EventBus;

const PIPELINE_RETRY_POLICY: tokn_requests::RetryPolicy =
  tokn_requests::RetryPolicy::new(2, Duration::from_millis(100));
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing::{Level, Span};

type ReloadFuture = Pin<Box<dyn Future<Output = std::result::Result<ReloadReport, String>> + Send>>;

#[derive(Clone)]
pub struct AdminReloader {
  reload: Arc<dyn Fn() -> ReloadFuture + Send + Sync>,
}

impl AdminReloader {
  pub fn new<F, Fut>(reload: F) -> Self
  where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<ReloadReport, String>> + Send + 'static,
  {
    Self {
      reload: Arc::new(move || Box::pin(reload())),
    }
  }

  async fn reload(&self) -> std::result::Result<ReloadReport, String> {
    (self.reload)().await
  }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ReloadReport {
  pub status: &'static str,
  pub generation: u64,
  pub accounts: usize,
  pub route_mode: &'static str,
}

#[derive(Clone)]
pub struct LiveAppState {
  current: Arc<ArcSwap<AppState>>,
  admin_reloader: Arc<OnceLock<AdminReloader>>,
}

impl LiveAppState {
  pub fn new(state: AppState) -> Self {
    Self {
      current: Arc::new(ArcSwap::from_pointee(state)),
      admin_reloader: Arc::new(OnceLock::new()),
    }
  }

  pub fn current(&self) -> AppState {
    self.current.load_full().as_ref().clone()
  }

  pub fn swap(&self, state: AppState) {
    self.current.store(Arc::new(state));
  }

  pub fn set_admin_reloader(&self, reloader: AdminReloader) -> std::result::Result<(), AdminReloader> {
    self.admin_reloader.set(reloader)
  }

  async fn reload(&self) -> std::result::Result<ReloadReport, String> {
    let Some(reloader) = self.admin_reloader.get() else {
      return Err("admin config reload is not configured".into());
    };
    reloader.reload().await
  }
}

#[derive(Clone)]
pub struct AppState {
  /// Inbound client credentials and per-key provider authorization.
  pub access: Arc<tokn_access::AccessStore>,
  /// Explicit switch for client API-key enforcement. Passthrough modes ignore it.
  pub api_key_enabled: bool,
  pub inventory: Arc<AccountInventory>,
  pub pool: Arc<AccountPool>,
  pub provider_registry: Arc<ProviderRegistry>,
  pub identity: Arc<AccountIdentityResolver>,
  pub route: Arc<RouteResolver>,
  pub default_policy: Arc<RequestPolicyRuntime>,
  pub profiles: Arc<BTreeMap<String, Arc<RequestPolicyRuntime>>>,
  pub http: reqwest::Client,
  pub events: Arc<EventBus>,
  pub body_max_bytes: usize,
  pub cors_allowed_origins: Arc<BTreeSet<String>>,
  pub cors_allow_localhost: bool,
  pub proxy_provider_modes: Arc<std::collections::BTreeMap<String, ProxyProviderMode>>,
  /// Shared `tokn-requests` pipeline used for router-owned JSON endpoints.
  pub request_pipeline: Arc<tokn_requests::Pipeline>,
  /// Shared `tokn-requests` pipeline used when the resolved route mode is
  /// [`RouteMode::Passthrough`]. Forwards the inbound request verbatim
  /// (no JSON parse, no cross-endpoint translation) while still
  /// emitting `RecordEvent::*` for observability and persistence.
  pub passthrough_pipeline: Arc<tokn_requests::Pipeline>,
  /// Shared `tokn-requests` pipeline used when router-owned JSON
  /// endpoints run in [`RouteMode::Switch`]. The body stays verbatim,
  /// but inbound auth is stripped before provider auth is injected.
  pub switch_pipeline: Arc<tokn_requests::Pipeline>,
  /// Shared `tokn-requests` pipeline used by the MITM proxy passthrough
  /// path. Unlike [`Self::passthrough_pipeline`], this variant does **no
  /// account resolution** — the intercepted TLS host is the upstream
  /// and the client's own `Authorization` reaches it unchanged. Wired
  /// via `RunConfig` keys (`proxy.host`, `proxy.path`, `proxy.method`,
  /// `proxy.provider_id`, `proxy.account_id`) that the proxy transport
  /// layer fills before calling `run_with`.
  pub proxy_passthrough_pipeline: Arc<tokn_requests::Pipeline>,
  /// Shared `tokn-requests` pipeline used by the MITM proxy `switch`
  /// path. This variant resolves the provider from the intercepted URL,
  /// selects a configured account for that provider, and forwards the
  /// request bytes verbatim with router-managed auth injection.
  pub proxy_switch_pipeline: Arc<tokn_requests::Pipeline>,
}

#[derive(Clone)]
pub struct RequestPolicyRuntime {
  pub mode: RouteMode,
  pub agent_id: Option<AgentId>,
  pub default_provider_id: Option<String>,
  pub ruleset: AccountPoolRuleset,
  pub pool: Arc<AccountPool>,
  pub route: Arc<RouteResolver>,
  pub model_families: Vec<ModelFamily>,
  pub request_pipeline: Arc<tokn_requests::Pipeline>,
  pub passthrough_pipeline: Arc<tokn_requests::Pipeline>,
  pub switch_pipeline: Arc<tokn_requests::Pipeline>,
}

#[derive(Clone)]
struct PolicyBuildDeps {
  cfg: Config,
  inventory: Arc<AccountInventory>,
  http: reqwest::Client,
  events: Arc<EventBus>,
}

struct PolicySpec {
  mode: RouteMode,
  agent_id: Option<AgentId>,
  default_provider_id: Option<String>,
  providers: Option<Vec<String>>,
  accounts: Option<Vec<String>>,
  families: Vec<ModelFamily>,
}

/// Header name used for request ids. Honors inbound `x-request-id` if present.
pub const REQUEST_ID_HEADER: &str = "x-request-id";
pub const SESSION_ID_HEADER: &str = "x-session-id";

pub(crate) fn is_router_owned_header(name: &axum::http::HeaderName) -> bool {
  let name = name.as_str();
  name.starts_with("x-tokn-router-") || name == "x-route-mode" || name == "x-behave-as"
}

pub(crate) fn first_header<'a>(headers: &'a HeaderMap, names: &[&str]) -> Option<&'a str> {
  names.iter().find_map(|name| {
    headers
      .get(*name)
      .and_then(|v| v.to_str().ok())
      .map(str::trim)
      .filter(|s| !s.is_empty())
  })
}

tokio::task_local! {
  static REQUEST_TRACKING: Mutex<RequestTracking>;
}

#[derive(Default)]
struct RequestTracking {
  account: Option<Arc<str>>,
  upstream_url: Option<Arc<str>>,
}

#[allow(dead_code)]
pub(crate) fn record_upstream_url(url: &str) {
  let _ = REQUEST_TRACKING.try_with(|state| {
    state.lock().upstream_url = Some(Arc::from(url));
  });
}

fn tracking_snapshot() -> (String, String) {
  REQUEST_TRACKING
    .try_with(|state| {
      let g = state.lock();
      (
        g.account.as_deref().unwrap_or("-").to_string(),
        g.upstream_url.as_deref().unwrap_or("-").to_string(),
      )
    })
    .unwrap_or_else(|_| ("-".into(), "-".into()))
}

async fn track_request(req: Request<axum::body::Body>, next: Next) -> Response<axum::body::Body> {
  REQUEST_TRACKING
    .scope(Mutex::new(RequestTracking::default()), next.run(req))
    .await
}

pub fn router(state: AppState) -> Router {
  router_live(LiveAppState::new(state))
}

pub fn router_live(state: LiveAppState) -> Router {
  let request_id_header = HeaderName::from_static(REQUEST_ID_HEADER);
  let cors = cors_layer(state.clone());

  // TraceLayer is customised so the per-request span carries `request_id`
  // (set by SetRequestIdLayer below) and emits a single info-level summary
  // line at the response edge with status + latency. Per-step debug events
  // come from the handlers themselves and inherit this span.
  let trace = TraceLayer::new_for_http()
    .make_span_with(|req: &Request<_>| {
      let request_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
      tracing::info_span!(
        "http",
        method = %req.method(),
        uri = %req.uri(),
        request_id = %request_id,
        account = tracing::field::Empty,
        upstream_url = tracing::field::Empty,
        status = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
      )
    })
    .on_request(|req: &Request<_>, _span: &Span| {
      let len = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
      tracing::debug!(content_length = %len, "request started");
    })
    .on_response(|resp: &Response<_>, latency: Duration, span: &Span| {
      let status = resp.status();
      let ms = latency.as_millis() as u64;
      let (account, upstream_url) = tracking_snapshot();
      span.record("status", status.as_u16());
      span.record("latency_ms", ms);
      span.record("account", account.as_str());
      span.record("upstream_url", upstream_url.as_str());
      if status.is_server_error() || status.is_client_error() {
        tracing::event!(Level::WARN, status = %status, latency_ms = ms, account = %account, upstream_url = %upstream_url, "request finished with error");
      } else {
        tracing::event!(Level::INFO, status = %status, latency_ms = ms, account = %account, upstream_url = %upstream_url, "request finished");
      }
    })
    .on_failure(
      |err: tower_http::classify::ServerErrorsFailureClass, latency: Duration, _span: &Span| {
        let (account, upstream_url) = tracking_snapshot();
        tracing::warn!(error = %err, latency_ms = latency.as_millis() as u64, account = %account, upstream_url = %upstream_url, "request failed");
      },
    );

  // Profile-prefixed routes: /{profile}/v1/...
  let profile_routes = Router::new()
    .route("/{profile}/v1/providers", get(providers::list_providers_with_profile))
    .route("/{profile}/v1/models", get(models::list_models_with_profile))
    .route(
      "/{profile}/v1/chat/completions",
      post(endpoints::chat_completions_with_profile),
    )
    .route("/{profile}/v1/responses", post(endpoints::responses_with_profile))
    .route("/{profile}/v1/messages", post(endpoints::messages_with_profile));

  let client_routes = Router::new()
    .route("/v1/providers", get(providers::list_providers))
    .route("/v1/models", get(models::list_models))
    .route("/v1/chat/completions", post(endpoints::chat_completions))
    .route("/v1/responses", post(endpoints::responses))
    .route("/v1/messages", post(endpoints::messages))
    .merge(profile_routes)
    .layer(middleware::from_fn_with_state(state.clone(), access::authenticate))
    // CORS must be outside authentication so browser preflight requests do
    // not need an API key. The origin predicate reads the live state, which
    // lets config reloads replace the allowlist without rebuilding the router.
    .layer(cors);

  Router::new()
    .merge(client_routes)
    .route("/admin/config/reload", post(admin_config_reload))
    .route("/healthz", get(health))
    .with_state(state.clone())
    // Layers run outermost-first on request, innermost-first on response.
    // SetRequestIdLayer with MakeRequestUuid only assigns a fresh UUID when
    // the inbound request lacks the header, so client-supplied ids pass
    // through unchanged. PropagateRequestIdLayer copies it onto the
    // response so clients can correlate.
    .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
    .layer(trace)
    .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
    .layer(middleware::from_fn(track_request))
}

fn cors_layer(state: LiveAppState) -> CorsLayer {
  let allowed_origins = AllowOrigin::predicate(move |origin: &HeaderValue, _| {
    origin.to_str().ok().is_some_and(|origin| {
      let state = state.current();
      state.cors_allowed_origins.contains(origin) || (state.cors_allow_localhost && is_localhost_origin(origin))
    })
  });
  CorsLayer::new()
    .allow_origin(allowed_origins)
    .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
    .allow_headers(AllowHeaders::mirror_request())
    .expose_headers([HeaderName::from_static(REQUEST_ID_HEADER)])
    .max_age(Duration::from_secs(600))
}

fn is_localhost_origin(origin: &str) -> bool {
  let Ok(origin) = reqwest::Url::parse(origin) else {
    return false;
  };
  if !matches!(origin.scheme(), "http" | "https")
    || !origin.username().is_empty()
    || origin.password().is_some()
    || origin.path() != "/"
    || origin.query().is_some()
    || origin.fragment().is_some()
  {
    return false;
  }
  origin.host_str().is_some_and(|host| {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || matches!(host, "::1" | "[::1]")
  })
}

async fn health() -> &'static str {
  "ok"
}

async fn admin_config_reload(axum::extract::State(state): axum::extract::State<LiveAppState>) -> AxumResponse {
  match state.reload().await {
    Ok(report) => Json(report).into_response(),
    Err(message) if message == "admin config reload is not configured" => (
      axum::http::StatusCode::NOT_FOUND,
      Json(serde_json::json!({
        "error": {
          "message": message,
          "type": "not_found",
          "code": 404,
          "request_id": serde_json::Value::Null,
        }
      })),
    )
      .into_response(),
    Err(message) => (
      axum::http::StatusCode::UNPROCESSABLE_ENTITY,
      Json(serde_json::json!({
        "error": {
          "message": message,
          "type": "reload_failed",
          "code": 422,
          "request_id": serde_json::Value::Null,
        }
      })),
    )
      .into_response(),
  }
}

pub fn build_state(cfg: &Config, accounts: &[AccountConfig], events: Arc<EventBus>) -> Result<AppState> {
  build_state_inner(cfg, accounts, events, StateBuildKind::Api)
}

pub fn build_proxy_state(cfg: &Config, accounts: &[AccountConfig], events: Arc<EventBus>) -> Result<AppState> {
  build_state_inner(cfg, accounts, events, StateBuildKind::Proxy)
}

#[derive(Clone, Copy)]
enum StateBuildKind {
  Api,
  Proxy,
}

fn build_state_inner(
  cfg: &Config,
  accounts: &[AccountConfig],
  events: Arc<EventBus>,
  kind: StateBuildKind,
) -> Result<AppState> {
  cfg.validate()?;
  let provider_registry = Arc::new(ProviderRegistry::builtin());
  let _ = validate_proxy_provider_modes(cfg, provider_registry.as_ref());
  validate_policy_providers(cfg, provider_registry.as_ref())?;
  validate_policy_accounts(cfg, accounts)?;
  let identity = Arc::new(AccountIdentityResolver::from_accounts(accounts));
  let default_mode = effective_default_mode(cfg);
  let inventory = if accounts.is_empty() && matches!(default_mode, RouteMode::Passthrough) {
    AccountInventory::empty()
  } else {
    let registry = provider_registry.clone();
    AccountInventory::from_accounts_with(accounts, move |account| registry.build(account))?
  };
  let pool = AccountPool::from_inventory(&inventory, cfg, &AccountPoolRuleset::all())?;
  let default_families = effective_default_families(cfg);
  if matches!(kind, StateBuildKind::Api) {
    validate_api_default_provider_modes(cfg, default_mode)?;
  }
  let route = Arc::new(RouteResolver::with_default_provider(
    default_mode,
    cfg.defaults.default_provider_id.clone(),
    &default_families,
  ));
  let http = tokn_core::util::http::build_client(&cfg.proxy.to_http_options())?;
  let body_max_bytes = if cfg.db.enabled { cfg.db.body_max_bytes } else { 0 };
  let default_policy = build_policy_runtime(
    "default",
    PolicySpec {
      mode: default_mode,
      agent_id: cfg.defaults.agent_id.clone(),
      default_provider_id: cfg.defaults.default_provider_id.clone(),
      providers: cfg.defaults.providers.clone(),
      accounts: cfg.defaults.accounts.clone(),
      families: default_families,
    },
    PolicyBuildDeps {
      cfg: cfg.clone(),
      inventory: inventory.clone(),
      http: http.clone(),
      events: events.clone(),
    },
  );
  let mut profiles = BTreeMap::new();
  for (name, profile) in &cfg.profiles {
    let runtime = build_profile_runtime(
      name,
      profile,
      default_policy.as_ref(),
      PolicyBuildDeps {
        cfg: cfg.clone(),
        inventory: inventory.clone(),
        http: http.clone(),
        events: events.clone(),
      },
    );
    profiles.insert(name.clone(), runtime);
  }
  let proxy_passthrough_pipeline = build_proxy_passthrough_pipeline(http.clone(), events.clone());
  let proxy_switch_pipeline = build_proxy_switch_pipeline(pool.clone(), http.clone(), events.clone());
  let cors_allowed_origins = if cfg.server.cors.enabled {
    cfg.server.cors.canonical_allowed_origins()?
  } else {
    BTreeSet::new()
  };
  Ok(AppState {
    access: Arc::new(tokn_access::AccessStore::disabled()),
    api_key_enabled: cfg.api_key.enabled,
    inventory,
    pool,
    provider_registry,
    identity,
    route,
    request_pipeline: default_policy.request_pipeline.clone(),
    passthrough_pipeline: default_policy.passthrough_pipeline.clone(),
    switch_pipeline: default_policy.switch_pipeline.clone(),
    default_policy,
    profiles: Arc::new(profiles),
    http,
    events,
    body_max_bytes,
    cors_allowed_origins: Arc::new(cors_allowed_origins),
    cors_allow_localhost: cfg.server.cors.enabled && cfg.server.cors.allow_localhost,
    proxy_provider_modes: Arc::new(cfg.proxy_mode.provider_modes.clone()),
    proxy_passthrough_pipeline,
    proxy_switch_pipeline,
  })
}

fn effective_default_mode(cfg: &Config) -> RouteMode {
  if cfg.defaults.mode == RouteMode::Route && cfg.server.route_mode != RouteMode::Route {
    cfg.server.route_mode
  } else {
    cfg.defaults.mode
  }
}

fn effective_default_families(cfg: &Config) -> Vec<ModelFamily> {
  if cfg.defaults.model_families.is_empty() {
    cfg.model_families.clone()
  } else {
    cfg.defaults.model_families.clone()
  }
}

fn build_profile_runtime(
  name: &str,
  profile: &ProfileConfig,
  default_policy: &RequestPolicyRuntime,
  deps: PolicyBuildDeps,
) -> Arc<RequestPolicyRuntime> {
  let mode = profile.mode.unwrap_or(default_policy.mode);
  let agent_id = profile.agent_id.clone().or_else(|| default_policy.agent_id.clone());
  let default_provider_id = profile
    .default_provider_id
    .clone()
    .or_else(|| default_policy.default_provider_id.clone());
  let providers = profile.providers.clone().or_else(|| {
    default_policy
      .ruleset
      .providers
      .as_ref()
      .map(|providers| providers.iter().cloned().collect())
  });
  let accounts = profile.accounts.clone().or_else(|| {
    default_policy
      .ruleset
      .accounts
      .as_ref()
      .map(|accounts| accounts.iter().cloned().collect())
  });
  let families = profile
    .model_families
    .clone()
    .unwrap_or_else(|| default_policy.model_families.clone());
  build_policy_runtime(
    name,
    PolicySpec {
      mode,
      agent_id,
      default_provider_id,
      providers,
      accounts,
      families,
    },
    deps,
  )
}

fn build_policy_runtime(name: &str, spec: PolicySpec, deps: PolicyBuildDeps) -> Arc<RequestPolicyRuntime> {
  let route = Arc::new(RouteResolver::with_default_provider(
    spec.mode,
    spec.default_provider_id.clone(),
    &spec.families,
  ));
  let ruleset = AccountPoolRuleset::from_filters(spec.providers, spec.accounts);
  let pool = AccountPool::from_inventory(&deps.inventory, &deps.cfg, &ruleset)
    .expect("building account pool from validated inventory must not fail");
  Arc::new(RequestPolicyRuntime {
    mode: spec.mode,
    agent_id: spec.agent_id,
    default_provider_id: spec.default_provider_id,
    ruleset,
    pool: pool.clone(),
    route: route.clone(),
    model_families: spec.families,
    request_pipeline: build_request_pipeline(
      format!("router-{name}"),
      pool.clone(),
      route.clone(),
      deps.http.clone(),
      deps.events.clone(),
    ),
    passthrough_pipeline: build_passthrough_pipeline(
      format!("router-{name}-passthrough"),
      pool.clone(),
      route.clone(),
      deps.http.clone(),
      deps.events.clone(),
      PassthroughAuthMode::PreserveClient,
    ),
    switch_pipeline: build_passthrough_pipeline(
      format!("router-{name}-switch"),
      pool,
      route,
      deps.http,
      deps.events,
      PassthroughAuthMode::Router,
    ),
  })
}

fn validate_api_default_provider_modes(cfg: &Config, default_mode: RouteMode) -> Result<()> {
  let mut missing = Vec::new();
  if matches!(default_mode, RouteMode::Passthrough | RouteMode::Switch) && cfg.defaults.default_provider_id.is_none() {
    missing.push("defaults.default_provider_id".to_string());
  }
  for (profile_name, profile) in &cfg.profiles {
    let mode = profile.mode.unwrap_or(default_mode);
    let default_provider_id = profile
      .default_provider_id
      .as_ref()
      .or(cfg.defaults.default_provider_id.as_ref());
    if matches!(mode, RouteMode::Passthrough | RouteMode::Switch) && default_provider_id.is_none() {
      missing.push(format!("profiles.{profile_name}.default_provider_id"));
    }
  }
  if missing.is_empty() {
    return Ok(());
  }
  anyhow::bail!(
    "API passthrough/switch policies require default_provider_id: {}",
    missing.join(", ")
  )
}

fn validate_proxy_provider_modes(cfg: &Config, provider_registry: &ProviderRegistry) -> Result<()> {
  let mut unresolved = Vec::new();
  for provider_id in cfg.proxy_mode.provider_modes.keys() {
    if provider_registry.resolve(provider_id).is_none() {
      tracing::warn!(
        provider_id = %provider_id,
        "ignoring unresolved [proxy_mode].provider_modes entry"
      );
      unresolved.push(provider_id.clone());
    }
  }
  if unresolved.is_empty() {
    return Ok(());
  }
  anyhow::bail!(
    "[proxy_mode].provider_modes contains unresolved provider ids: {}",
    unresolved.join(", ")
  );
}

fn validate_policy_providers(cfg: &Config, provider_registry: &ProviderRegistry) -> Result<()> {
  let mut unresolved = Vec::new();
  if let Some(provider_id) = cfg.defaults.default_provider_id.as_deref() {
    if provider_registry.resolve(provider_id).is_none() {
      unresolved.push(format!("defaults.default_provider_id:{provider_id}"));
    }
  }
  for provider_id in cfg
    .defaults
    .providers
    .iter()
    .flat_map(|providers| providers.iter().map(String::as_str))
  {
    if provider_registry.resolve(provider_id).is_none() {
      unresolved.push(format!("defaults.providers:{provider_id}"));
    }
  }
  for (profile_name, profile) in &cfg.profiles {
    if let Some(provider_id) = profile.default_provider_id.as_deref() {
      if provider_registry.resolve(provider_id).is_none() {
        unresolved.push(format!("profiles.{profile_name}.default_provider_id:{provider_id}"));
      }
    }
    for provider_id in profile
      .providers
      .iter()
      .flat_map(|providers| providers.iter().map(String::as_str))
    {
      if provider_registry.resolve(provider_id).is_none() {
        unresolved.push(format!("profiles.{profile_name}.providers:{provider_id}"));
      }
    }
  }
  if unresolved.is_empty() {
    return Ok(());
  }
  anyhow::bail!(
    "profile/default provider filters contain unknown provider ids: {}",
    unresolved.join(", ")
  )
}

fn validate_policy_accounts(cfg: &Config, accounts: &[AccountConfig]) -> Result<()> {
  let known = accounts
    .iter()
    .map(|account| account.id.as_str())
    .collect::<BTreeSet<_>>();
  let mut unresolved = Vec::new();
  for account_id in cfg
    .defaults
    .accounts
    .iter()
    .flat_map(|accounts| accounts.iter().map(String::as_str))
  {
    if !known.contains(account_id) {
      unresolved.push(format!("defaults.accounts:{account_id}"));
    }
  }
  for (profile_name, profile) in &cfg.profiles {
    for account_id in profile
      .accounts
      .iter()
      .flat_map(|accounts| accounts.iter().map(String::as_str))
    {
      if !known.contains(account_id) {
        unresolved.push(format!("profiles.{profile_name}.accounts:{account_id}"));
      }
    }
  }
  if unresolved.is_empty() {
    return Ok(());
  }
  anyhow::bail!(
    "profile/default account filters contain unknown account ids: {}",
    unresolved.join(", ")
  )
}

/// Construct the default `tokn-requests` pipeline for router-owned JSON
/// endpoints. The pipeline shares `AppState.events` so persistence
/// (`RequestEventHandler`) receives `StageEvent::*` and `RecordEvent::*`
/// automatically.
fn build_request_pipeline(
  name: impl Into<smol_str::SmolStr>,
  pool: Arc<AccountPool>,
  route: Arc<RouteResolver>,
  http: reqwest::Client,
  events: Arc<EventBus>,
) -> Arc<tokn_requests::Pipeline> {
  use tokn_requests::stages::{
    DefaultBuildHeaders, DefaultConvertRequest, DefaultConvertResponse, DefaultExtract, DefaultSend,
    PoolAccountSelector, PoolResolve,
  };
  let selector = Arc::new(PoolAccountSelector::new(pool, route));
  let profile = tokn_requests::Profile::full(
    name,
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(http)),
    Arc::new(DefaultConvertResponse::new()),
  );
  Arc::new(tokn_requests::Pipeline::new_with_retry(
    Arc::new(profile),
    events,
    PIPELINE_RETRY_POLICY,
  ))
}

/// Construct the passthrough `tokn-requests` pipeline. Forwards the
/// inbound request body bytes verbatim with no JSON parsing or
/// cross-endpoint translation. Auth is still injected by the provider
/// during Send (via the upstream account handle), and observability
/// events still flow through `events` so persistence works.
///
/// Mirrors the behaviour of the legacy `crates/router/src/relay/passthrough.rs`
/// helpers but reuses the standard pipeline plumbing.
fn build_passthrough_pipeline(
  name: impl Into<smol_str::SmolStr>,
  pool: Arc<AccountPool>,
  route: Arc<RouteResolver>,
  http: reqwest::Client,
  events: Arc<EventBus>,
  auth_mode: PassthroughAuthMode,
) -> Arc<tokn_requests::Pipeline> {
  use tokn_requests::stages::{
    DefaultSend, PassthroughBuildHeaders, PassthroughConvertRequest, PassthroughConvertResponse, PassthroughExtract,
    PoolAccountSelector, PoolResolve,
  };
  let selector = Arc::new(PoolAccountSelector::new(pool, route));
  let profile = tokn_requests::Profile::full(
    name,
    Arc::new(PassthroughExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(match auth_mode {
      PassthroughAuthMode::PreserveClient => PassthroughBuildHeaders::new(),
      PassthroughAuthMode::Router => PassthroughBuildHeaders::router_auth(),
    }),
    Arc::new(PassthroughConvertRequest),
    Arc::new(DefaultSend::new(http)),
    Arc::new(PassthroughConvertResponse::new()),
  );
  Arc::new(tokn_requests::Pipeline::new_with_retry(
    Arc::new(profile),
    events,
    PIPELINE_RETRY_POLICY,
  ))
}

#[derive(Clone, Copy)]
enum PassthroughAuthMode {
  PreserveClient,
  Router,
}

/// Construct the proxy-passthrough `tokn-requests` pipeline used by the
/// MITM proxy when the resolved route mode is
/// [`RouteMode::Passthrough`]. Unlike [`build_passthrough_pipeline`],
/// this variant performs **no account resolution** — the intercepted
/// TLS host is the upstream, the client's `Authorization` reaches it
/// untouched, and there is no provider-side auth injection.
///
/// The proxy transport layer supplies per-request hints
/// (`proxy.host`, `proxy.path`, `proxy.method`, …) through a
/// [`tokn_requests::RunConfig`] passed to `Pipeline::run_with`.
/// [`ProxyResolve`] and [`ProxySend`] read those keys; the remaining
/// stages are the same as the standard passthrough variant.
fn build_proxy_passthrough_pipeline(http: reqwest::Client, events: Arc<EventBus>) -> Arc<tokn_requests::Pipeline> {
  use tokn_requests::stages::{
    PassthroughBuildHeaders, PassthroughConvertRequest, PassthroughConvertResponse, PassthroughExtract, ProxyResolve,
    ProxySend,
  };
  let profile = tokn_requests::Profile::full(
    "router-proxy-passthrough",
    Arc::new(PassthroughExtract),
    Arc::new(ProxyResolve),
    Arc::new(PassthroughBuildHeaders::preserve_host()),
    Arc::new(PassthroughConvertRequest),
    Arc::new(ProxySend::new(http)),
    Arc::new(PassthroughConvertResponse::new()),
  );
  Arc::new(tokn_requests::Pipeline::new_with_retry(
    Arc::new(profile),
    events,
    PIPELINE_RETRY_POLICY,
  ))
}

fn build_proxy_switch_pipeline(
  pool: Arc<AccountPool>,
  http: reqwest::Client,
  events: Arc<EventBus>,
) -> Arc<tokn_requests::Pipeline> {
  use tokn_requests::stages::{
    PassthroughBuildHeaders, PassthroughConvertRequest, PassthroughConvertResponse, PassthroughExtract,
    ProxyProviderResolve, ProxySend,
  };
  let profile = tokn_requests::Profile::full(
    "router-proxy-switch",
    Arc::new(PassthroughExtract),
    Arc::new(ProxyProviderResolve::new(pool)),
    Arc::new(PassthroughBuildHeaders::preserve_host_with_router_auth()),
    Arc::new(PassthroughConvertRequest),
    Arc::new(ProxySend::new(http)),
    Arc::new(PassthroughConvertResponse::new()),
  );
  Arc::new(tokn_requests::Pipeline::new(Arc::new(profile), events))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{Account as AccountCfg, Config, ProfileConfig, RouteMode};
  use crate::util::secret::Secret;
  use axum::body::{to_bytes, Body};
  use axum::http::{header, Method, Request, StatusCode};
  use axum::routing::get;
  use bytes::Bytes;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokn_headers::inbound::{PROJECT_ID_HEADERS, REQUEST_ID_HEADERS, SESSION_ID_HEADERS};
  use tower::ServiceExt;

  fn zai_account() -> AccountCfg {
    zai_account_with_id("acct")
  }

  fn zai_account_with_id(id: &str) -> AccountCfg {
    zai_account_with_id_and_base(id, None)
  }

  fn zai_account_with_id_and_base(id: &str, base_url: Option<String>) -> AccountCfg {
    AccountCfg {
      id: id.into(),
      provider: "zai-coding-plan".into(),
      enabled: true,
      tier: tokn_core::account::AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url,
      headers: Default::default(),
      auth_type: None,
      username: None,
      api_key: Some(Secret::new("sk-test".into())),
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: toml::Table::new(),
    }
  }

  fn openai_account_with_id_and_base(id: &str, base_url: Option<String>) -> AccountCfg {
    AccountCfg {
      id: id.into(),
      provider: "openai".into(),
      enabled: true,
      tier: tokn_core::account::AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url,
      headers: Default::default(),
      auth_type: Some(tokn_core::account::AuthType::Bearer),
      username: None,
      api_key: Some(Secret::new("sk-openai-test".into())),
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: Default::default(),
    }
  }

  fn core_account(cfg: AccountCfg) -> AccountConfig {
    let s = toml::to_string(&cfg).expect("serialize account");
    toml::from_str(&s).expect("parse core account")
  }

  struct ControlledUpstream {
    base_url: String,
    arrived: tokio::sync::oneshot::Receiver<()>,
    release: tokio::sync::oneshot::Sender<()>,
    request: tokio::sync::oneshot::Receiver<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
  }

  async fn controlled_chat_upstream(label: &'static str) -> ControlledUpstream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let (arrived_tx, arrived) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let (request_tx, request) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let req = read_http_request(&mut stream).await;
      let _ = arrived_tx.send(());
      let _ = release_rx.await;
      let body = chat_completion_body(label);
      let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
      );
      stream.write_all(resp.as_bytes()).await.unwrap();
      stream.write_all(body.as_bytes()).await.unwrap();
      stream.flush().await.unwrap();
      let _ = request_tx.send(req);
    });
    ControlledUpstream {
      base_url,
      arrived,
      release,
      request,
      task,
    }
  }

  async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
      let n = stream.read(&mut chunk).await.unwrap();
      assert!(n > 0, "connection closed before request was complete");
      buf.extend_from_slice(&chunk[..n]);
      let Some(header_end) = find_header_end(&buf) else {
        continue;
      };
      let headers = String::from_utf8_lossy(&buf[..header_end]);
      let content_len = headers
        .lines()
        .find_map(|line| {
          line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
      if buf.len() >= header_end + 4 + content_len {
        return buf;
      }
    }
  }

  fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
  }

  fn chat_completion_body(label: &str) -> String {
    serde_json::json!({
      "id": format!("chatcmpl-{label}"),
      "object": "chat.completion",
      "created": 0,
      "model": "glm-4.7",
      "choices": [{
        "index": 0,
        "message": {
          "role": "assistant",
          "content": label,
        },
        "finish_reason": "stop",
      }],
      "usage": {
        "prompt_tokens": 1,
        "completion_tokens": 1,
        "total_tokens": 2,
      },
    })
    .to_string()
  }

  fn routed_state_for_upstream(base_url: String) -> AppState {
    let mut cfg = Config::default();
    cfg.defaults.mode = RouteMode::Route;
    build_state(
      &cfg,
      &[core_account(zai_account_with_id_and_base("routed", Some(base_url)))],
      Arc::new(EventBus::noop()),
    )
    .expect("routed test state should build")
  }

  fn chat_request(request_id: &str) -> Request<Body> {
    Request::builder()
      .method(Method::POST)
      .uri("/v1/chat/completions")
      .header("content-type", "application/json")
      .header("x-request-id", request_id)
      .body(Body::from(Bytes::from_static(
        br#"{"model":"glm-4.7","messages":[{"role":"user","content":"hi"}],"stream":false}"#,
      )))
      .unwrap()
  }

  fn state_with_api_key(providers: Vec<String>) -> (AppState, String) {
    let temp = tempfile::tempdir().unwrap();
    let access = tokn_access::AccessStore::open(temp.path().join("access.db")).unwrap();
    let created = access.create_key("test-client", providers).unwrap();
    let mut cfg = Config::default();
    cfg.api_key.enabled = true;
    let mut state = build_state(&cfg, &[core_account(zai_account())], Arc::new(EventBus::noop())).unwrap();
    state.access = Arc::new(access);
    (state, created.token)
  }

  fn cors_preflight(origin: &str) -> Request<Body> {
    Request::builder()
      .method(Method::OPTIONS)
      .uri("/v1/responses")
      .header(header::ORIGIN, origin)
      .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
      .header(
        header::ACCESS_CONTROL_REQUEST_HEADERS,
        concat!(
          "authorization,x-api-key,content-type,openai-beta,",
          "x-client-session-id,x-opencode-request,x-opencode-project,",
          "x-future-client-metadata"
        ),
      )
      .body(Body::empty())
      .unwrap()
  }

  fn cors_state(origin: &str, api_key_enabled: bool) -> AppState {
    let mut cfg = Config::default();
    cfg.api_key.enabled = api_key_enabled;
    cfg.server.cors.enabled = true;
    cfg.server.cors.allowed_origins = vec![origin.into()];
    build_state(&cfg, &[core_account(zai_account())], Arc::new(EventBus::noop())).unwrap()
  }

  fn localhost_cors_state() -> AppState {
    let mut cfg = Config::default();
    cfg.server.cors.enabled = true;
    cfg.server.cors.allow_localhost = true;
    build_state(&cfg, &[core_account(zai_account())], Arc::new(EventBus::noop())).unwrap()
  }

  #[tokio::test]
  async fn cors_preflight_precedes_authentication_and_is_scoped_to_client_routes() {
    let origin = "https://app.example.com";
    let app = router(cors_state(origin, true));

    let preflight = app.clone().oneshot(cors_preflight(origin)).await.unwrap();
    assert_eq!(preflight.status(), StatusCode::OK);
    assert_eq!(
      preflight.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
      origin
    );
    assert!(preflight
      .headers()
      .get(header::ACCESS_CONTROL_ALLOW_METHODS)
      .unwrap()
      .to_str()
      .unwrap()
      .contains("POST"));
    let allowed_headers = preflight
      .headers()
      .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
      .unwrap()
      .to_str()
      .unwrap();
    let allowed_headers = allowed_headers.split(',').map(str::trim).collect::<BTreeSet<_>>();
    assert_eq!(
      allowed_headers,
      BTreeSet::from([
        "authorization",
        "content-type",
        "openai-beta",
        "x-api-key",
        "x-client-session-id",
        "x-future-client-metadata",
        "x-opencode-project",
        "x-opencode-request",
      ])
    );
    assert!(preflight
      .headers()
      .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
      .is_none());

    let unauthorized = app
      .clone()
      .oneshot(
        Request::get("/v1/providers")
          .header(header::ORIGIN, origin)
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
      unauthorized.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
      origin
    );
    assert_eq!(
      unauthorized
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .unwrap(),
      REQUEST_ID_HEADER
    );

    let health = app
      .clone()
      .oneshot(
        Request::get("/healthz")
          .header(header::ORIGIN, origin)
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert!(health.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    let admin_preflight = app
      .oneshot(
        Request::builder()
          .method(Method::OPTIONS)
          .uri("/admin/config/reload")
          .header(header::ORIGIN, origin)
          .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert!(admin_preflight
      .headers()
      .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
      .is_none());
  }

  #[tokio::test]
  async fn cors_policy_follows_live_config_reload() {
    let first_origin = "https://first.example.com";
    let second_origin = "http://localhost:3000";
    let live = LiveAppState::new(cors_state(first_origin, false));
    let app = router_live(live.clone());

    let first = app.clone().oneshot(cors_preflight(first_origin)).await.unwrap();
    assert_eq!(
      first.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
      first_origin
    );

    live.swap(localhost_cors_state());

    let stale = app.clone().oneshot(cors_preflight(first_origin)).await.unwrap();
    assert!(stale.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    let current = app.oneshot(cors_preflight(second_origin)).await.unwrap();
    assert_eq!(
      current.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
      second_origin
    );
  }

  #[tokio::test]
  async fn cors_can_allow_localhost_origin_family() {
    let app = router(localhost_cors_state());
    for origin in [
      "http://localhost",
      "https://localhost:8443",
      "http://app.localhost:3000",
      "https://nested.app.localhost",
      "http://127.0.0.1:5173",
      "https://[::1]:9443",
    ] {
      let response = app.clone().oneshot(cors_preflight(origin)).await.unwrap();
      assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::try_from(origin).unwrap()),
        "origin should be allowed: {origin}"
      );
    }

    for origin in [
      "http://localhost.example.com",
      "http://examplelocalhost",
      "http://127.0.0.2:5173",
      "http://192.168.1.10",
      "https://example.com",
    ] {
      let response = app.clone().oneshot(cors_preflight(origin)).await.unwrap();
      assert!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        "origin should be rejected: {origin}"
      );
    }
  }

  #[tokio::test]
  async fn configured_api_keys_require_authentication() {
    let (state, _) = state_with_api_key(Vec::new());
    let response = router(state)
      .oneshot(Request::get("/v1/providers").body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
      response.headers().get(axum::http::header::WWW_AUTHENTICATE).unwrap(),
      "Bearer"
    );
  }

  #[tokio::test]
  async fn enabled_api_key_authentication_without_keys_fails_closed() {
    let mut cfg = Config::default();
    cfg.api_key.enabled = true;
    let state = build_state(&cfg, &[core_account(zai_account())], Arc::new(EventBus::noop())).unwrap();

    let response = router(state)
      .oneshot(Request::get("/v1/providers").body(Body::empty()).unwrap())
      .await
      .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn configured_keys_are_not_enforced_when_api_key_authentication_is_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let access = tokn_access::AccessStore::open(temp.path().join("access.db")).unwrap();
    access.create_key("test-client", Vec::new()).unwrap();
    let mut state = build_state(
      &Config::default(),
      &[core_account(zai_account())],
      Arc::new(EventBus::noop()),
    )
    .unwrap();
    state.access = Arc::new(access);

    let response = router(state)
      .oneshot(Request::get("/v1/providers").body(Body::empty()).unwrap())
      .await
      .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
  }

  #[tokio::test]
  async fn wildcard_api_key_can_list_every_configured_provider() {
    let (state, token) = state_with_api_key(Vec::new());
    let response = router(state)
      .oneshot(
        Request::get("/v1/providers")
          .header("authorization", format!("Bearer {token}"))
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"][0]["id"], "zai-coding-plan");
  }

  #[tokio::test]
  async fn provider_restricted_key_filters_discovery_and_denies_routing() {
    let (state, token) = state_with_api_key(vec!["openai".into()]);
    let app = router(state);
    let providers = app
      .clone()
      .oneshot(
        Request::get("/v1/providers")
          .header("authorization", format!("Bearer {token}"))
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(providers.status(), StatusCode::OK);
    let body = to_bytes(providers.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"].as_array().unwrap().len(), 0);

    let models = app
      .clone()
      .oneshot(
        Request::get("/v1/models")
          .header("authorization", format!("Bearer {token}"))
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(models.status(), StatusCode::OK);
    let body = to_bytes(models.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"].as_array().unwrap().len(), 0);

    let mut request = chat_request("restricted-key");
    request
      .headers_mut()
      .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let denied = app.oneshot(request).await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
  }

  #[tokio::test]
  async fn authenticated_request_emits_api_key_attribution() {
    let temp = tempfile::tempdir().unwrap();
    let access = tokn_access::AccessStore::open(temp.path().join("access.db")).unwrap();
    let created = access.create_key("test-client", vec!["openai".into()]).unwrap();
    let mut cfg = Config::default();
    cfg.api_key.enabled = true;
    let events = Arc::new(EventBus::new(32));
    let mut receiver = events.subscribe();
    let mut state = build_state(&cfg, &[core_account(zai_account())], events).unwrap();
    state.access = Arc::new(access);

    let mut request = chat_request("attributed-key");
    request
      .headers_mut()
      .insert("authorization", format!("Bearer {}", created.token).parse().unwrap());
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut attribution = None;
    while let Ok(event) = receiver.try_recv() {
      if let tokn_core::event::Event::Requests(request) = event.as_ref() {
        if let tokn_core::request_event::RequestEventPayload::Record(
          tokn_core::request_event::RecordEvent::InboundConnection { user, api_key_id, .. },
        ) = &request.payload
        {
          attribution = Some((user.clone(), api_key_id.clone()));
          break;
        }
      }
    }
    let (user, api_key_id) = attribution.expect("authenticated inbound connection event");
    assert_eq!(user.as_deref(), Some("test-client"));
    assert_eq!(api_key_id.as_deref(), Some(created.id.as_str()));
  }

  async fn one_shot_models_upstream(
    model_id: &'static str,
  ) -> (
    String,
    tokio::sync::oneshot::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
  ) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let (req_tx, req_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let task = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buf = vec![0_u8; 4096];
      let n = stream.read(&mut buf).await.unwrap();
      buf.truncate(n);
      let body = format!(r#"{{"object":"list","data":[{{"id":"{model_id}","object":"model"}}]}}"#);
      let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
      );
      stream.write_all(resp.as_bytes()).await.unwrap();
      stream.write_all(body.as_bytes()).await.unwrap();
      stream.flush().await.unwrap();
      let _ = req_tx.send(buf);
    });
    (base_url, req_rx, task)
  }

  /// Build the same layer stack the real router uses, around a stub handler.
  /// This isolates the request-id middleware from `AppState` construction.
  fn test_router() -> Router {
    let header = HeaderName::from_static(REQUEST_ID_HEADER);
    Router::new()
      .route("/probe", get(|| async { "ok" }))
      .layer(PropagateRequestIdLayer::new(header.clone()))
      .layer(SetRequestIdLayer::new(header, MakeRequestUuid))
  }

  #[tokio::test]
  async fn inbound_request_id_passes_through() {
    let app = test_router();
    let req = Request::builder()
      .uri("/probe")
      .header(REQUEST_ID_HEADER, "client-supplied-123")
      .body(Body::empty())
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let echoed = resp
      .headers()
      .get(REQUEST_ID_HEADER)
      .expect("response missing x-request-id")
      .to_str()
      .unwrap();
    assert_eq!(echoed, "client-supplied-123");
  }

  #[tokio::test]
  async fn missing_request_id_is_generated() {
    let app = test_router();
    let req = Request::builder().uri("/probe").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let id = resp
      .headers()
      .get(REQUEST_ID_HEADER)
      .expect("response missing generated x-request-id")
      .to_str()
      .unwrap();
    // MakeRequestUuid emits a hyphenated uuid v4.
    assert!(uuid::Uuid::parse_str(id).is_ok(), "not a uuid: {id}");
  }

  #[test]
  fn first_header_uses_priority_and_ignores_empty_values() {
    let mut headers = HeaderMap::new();
    headers.insert("x-session-id", "   ".parse().unwrap());
    headers.insert("x-client-session-id", " client-session ".parse().unwrap());
    headers.insert("x-opencode-session", "opencode-session".parse().unwrap());

    assert_eq!(first_header(&headers, SESSION_ID_HEADERS), Some("client-session"));
  }

  #[test]
  fn build_state_allows_empty_accounts_in_passthrough_mode() {
    let mut cfg = Config::default();
    cfg.server.route_mode = RouteMode::Passthrough;
    let bus = EventBus::new(16);

    let state =
      build_proxy_state(&cfg, &[], Arc::new(bus)).expect("proxy passthrough mode should allow empty accounts");
    assert_eq!(state.pool.len(), 0);
  }

  #[test]
  fn build_state_rejects_api_passthrough_without_default_provider_id() {
    let mut cfg = Config::default();
    cfg.defaults.mode = RouteMode::Passthrough;
    let err = match build_state(&cfg, &[zai_account()], Arc::new(EventBus::noop())) {
      Ok(_) => panic!("API passthrough must require default_provider_id"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("defaults.default_provider_id"));
  }

  #[test]
  fn build_state_rejects_api_switch_without_default_provider_id() {
    let mut cfg = Config::default();
    cfg.defaults.mode = RouteMode::Switch;
    let err = match build_state(&cfg, &[zai_account()], Arc::new(EventBus::noop())) {
      Ok(_) => panic!("API switch must require provider"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("defaults.default_provider_id"));
  }

  #[test]
  fn build_state_rejects_empty_accounts_in_non_passthrough_mode() {
    let mut cfg = Config::default();
    cfg.server.route_mode = RouteMode::Route;
    let bus = EventBus::new(16);

    let res = build_proxy_state(&cfg, &[], Arc::new(bus));
    assert!(res.is_err(), "non-passthrough mode should require accounts");
    let err = res.err().expect("checked above");
    assert!(err.to_string().contains("no accounts configured"));
  }

  fn passthrough_state(
    body_max_bytes: usize,
    default_mode: RouteMode,
    proxy_provider_mode: ProxyProviderMode,
    profile_name: &str,
  ) -> AppState {
    let mut cfg = Config::default();
    cfg.server.route_mode = RouteMode::Passthrough;
    cfg.defaults.mode = default_mode;
    if matches!(default_mode, RouteMode::Passthrough | RouteMode::Switch) {
      cfg.defaults.default_provider_id = Some("zai-coding-plan".into());
    }
    cfg.db.enabled = true;
    cfg.db.body_max_bytes = body_max_bytes;
    cfg
      .proxy_mode
      .provider_modes
      .insert("openai".into(), proxy_provider_mode);
    cfg.profiles.insert(profile_name.into(), ProfileConfig::default());
    build_state(&cfg, &[zai_account()], Arc::new(EventBus::noop())).expect("test state should build")
  }

  #[tokio::test]
  async fn admin_config_reload_swaps_live_state() {
    let initial = passthrough_state(1, RouteMode::Passthrough, ProxyProviderMode::Passthrough, "old-profile");
    let replacement = passthrough_state(2, RouteMode::Fuzzy, ProxyProviderMode::Switch, "new-profile");
    let live = LiveAppState::new(initial);
    let live_for_reload = live.clone();
    assert!(live
      .set_admin_reloader(AdminReloader::new(move || {
        let live = live_for_reload.clone();
        let replacement = replacement.clone();
        async move {
          live.swap(replacement);
          Ok(ReloadReport {
            status: "reloaded",
            generation: 1,
            accounts: 0,
            route_mode: "passthrough",
          })
        }
      }))
      .is_ok());
    let app = router_live(live.clone());

    let resp = app
      .oneshot(
        Request::builder()
          .method("POST")
          .uri("/admin/config/reload")
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let current = live.current();
    assert_eq!(current.body_max_bytes, 2);
    assert_eq!(current.default_policy.mode, RouteMode::Fuzzy);
    assert_eq!(current.route.resolve_mode(None).unwrap(), RouteMode::Fuzzy);
    assert_eq!(
      current.proxy_provider_modes.get("openai"),
      Some(&ProxyProviderMode::Switch)
    );
    assert!(current.profiles.contains_key("new-profile"));
    assert!(!current.profiles.contains_key("old-profile"));
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "reloaded");
    assert_eq!(json["generation"], 1);
    assert_eq!(json["accounts"], 0);
    assert_eq!(json["route_mode"], "passthrough");
  }

  #[tokio::test]
  async fn admin_config_reload_failure_keeps_live_state() {
    let live = LiveAppState::new(passthrough_state(
      1,
      RouteMode::Passthrough,
      ProxyProviderMode::Passthrough,
      "old-profile",
    ));
    assert!(live
      .set_admin_reloader(AdminReloader::new(|| async { Err("invalid config".into()) }))
      .is_ok());
    let app = router_live(live.clone());

    let resp = app
      .oneshot(
        Request::builder()
          .method("POST")
          .uri("/admin/config/reload")
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let current = live.current();
    assert_eq!(current.body_max_bytes, 1);
    assert_eq!(current.default_policy.mode, RouteMode::Passthrough);
    assert_eq!(current.route.resolve_mode(None).unwrap(), RouteMode::Passthrough);
    assert_eq!(
      current.proxy_provider_modes.get("openai"),
      Some(&ProxyProviderMode::Passthrough)
    );
    assert!(current.profiles.contains_key("old-profile"));
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["type"], "reload_failed");
    assert_eq!(json["error"]["message"], "invalid config");
  }

  #[tokio::test]
  async fn routed_requests_keep_in_flight_policy_and_new_requests_use_reloaded_policy() {
    let old_upstream = controlled_chat_upstream("old").await;
    let new_upstream = controlled_chat_upstream("new").await;
    let live = LiveAppState::new(routed_state_for_upstream(old_upstream.base_url.clone()));
    let replacement = routed_state_for_upstream(new_upstream.base_url.clone());
    let live_for_reload = live.clone();
    assert!(live
      .set_admin_reloader(AdminReloader::new(move || {
        let live = live_for_reload.clone();
        let replacement = replacement.clone();
        async move {
          live.swap(replacement);
          Ok(ReloadReport {
            status: "reloaded",
            generation: 1,
            accounts: 1,
            route_mode: "route",
          })
        }
      }))
      .is_ok());
    let app = router_live(live);

    let old_request = {
      let app = app.clone();
      tokio::spawn(async move { app.oneshot(chat_request("old-request")).await.unwrap() })
    };

    tokio::time::timeout(std::time::Duration::from_secs(2), old_upstream.arrived)
      .await
      .expect("old request should reach old upstream before reload")
      .unwrap();
    let reload = app
      .clone()
      .oneshot(
        Request::builder()
          .method(Method::POST)
          .uri("/admin/config/reload")
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(reload.status(), StatusCode::OK);
    let _ = to_bytes(reload.into_body(), usize::MAX).await.unwrap();

    old_upstream.release.send(()).unwrap();
    let old_response = old_request.await.unwrap();
    assert_eq!(old_response.status(), StatusCode::OK);
    let old_body = to_bytes(old_response.into_body(), usize::MAX).await.unwrap();
    assert!(
      String::from_utf8_lossy(&old_body).contains("chatcmpl-old"),
      "old in-flight request should finish with old upstream response"
    );
    old_upstream.task.await.unwrap();
    let old_raw_request = String::from_utf8_lossy(&old_upstream.request.await.unwrap()).to_string();
    assert!(
      old_raw_request.contains(r#""model":"glm-4.7""#),
      "old upstream should receive the pre-reload request"
    );

    let new_request = {
      let app = app.clone();
      tokio::spawn(async move { app.oneshot(chat_request("new-request")).await.unwrap() })
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), new_upstream.arrived)
      .await
      .expect("new request should reach reloaded upstream")
      .unwrap();
    new_upstream.release.send(()).unwrap();
    let new_response = new_request.await.unwrap();
    assert_eq!(new_response.status(), StatusCode::OK);
    let new_body = to_bytes(new_response.into_body(), usize::MAX).await.unwrap();
    assert!(
      String::from_utf8_lossy(&new_body).contains("chatcmpl-new"),
      "new request should finish with reloaded upstream response"
    );
    new_upstream.task.await.unwrap();
    let new_raw_request = String::from_utf8_lossy(&new_upstream.request.await.unwrap()).to_string();
    assert!(
      new_raw_request.contains(r#""model":"glm-4.7""#),
      "new upstream should receive the post-reload request"
    );
  }

  #[test]
  fn build_state_allows_unknown_proxy_provider_mode_provider() {
    let mut cfg = Config::default();
    cfg.server.route_mode = RouteMode::Passthrough;
    cfg
      .proxy_mode
      .provider_modes
      .insert("made-up-provider".into(), ProxyProviderMode::Switch);
    let bus = EventBus::new(16);

    let res = build_proxy_state(&cfg, &[], Arc::new(bus));
    assert!(
      res.is_ok(),
      "unknown provider ids should only warn and not fail state construction"
    );
  }

  #[test]
  fn validate_proxy_provider_modes_returns_error_for_unknown_provider() {
    let mut cfg = Config::default();
    cfg
      .proxy_mode
      .provider_modes
      .insert("made-up-provider".into(), ProxyProviderMode::Switch);
    let registry = ProviderRegistry::builtin();

    let res = validate_proxy_provider_modes(&cfg, &registry);
    let err = res.expect_err("helper should still return an error for outside callers");
    assert!(err.to_string().contains("unresolved provider ids"));
    assert!(err.to_string().contains("made-up-provider"));
  }

  #[tokio::test]
  async fn route_mode_not_implemented_returns_json_error_body() {
    let cfg = Config::default();
    let accounts = vec![zai_account()];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("POST")
      .uri("/v1/responses")
      .header("content-type", "application/json")
      .header("x-route-mode", "route")
      .body(Body::from(Bytes::from_static(br#"{"model":"unknown","input":"hi"}"#)))
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
      resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok()),
      Some("application/json")
    );

    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let message = json["error"]["message"].as_str().unwrap();
    assert!(!message.is_empty());
    assert!(message.contains("responses"));
    assert!(message.contains("unknown"));
    assert_eq!(json["error"]["type"], "not_implemented_error");
    assert_eq!(json["error"]["code"], 501);
  }

  #[tokio::test]
  async fn api_switch_forwards_verbatim_to_default_provider_with_router_auth() {
    let upstream = controlled_chat_upstream("switch").await;
    let mut cfg = Config::default();
    cfg.defaults.mode = RouteMode::Switch;
    cfg.defaults.default_provider_id = Some("zai-coding-plan".into());
    let state = build_state(
      &cfg,
      &[core_account(zai_account_with_id_and_base(
        "switch",
        Some(upstream.base_url.clone()),
      ))],
      Arc::new(EventBus::noop()),
    )
    .unwrap();
    let app = router(state);
    let inbound_body =
      Bytes::from_static(br#"{"stream":false,"messages":[{"role":"user","content":"hi"}],"model":"glm-4.7"}"#);

    let request = Request::builder()
      .method(Method::POST)
      .uri("/v1/chat/completions")
      .header("content-type", "application/json")
      .header("authorization", "Bearer client-secret-must-not-leak")
      .body(Body::from(inbound_body.clone()))
      .unwrap();
    let response = tokio::spawn(async move { app.oneshot(request).await.unwrap() });

    tokio::time::timeout(std::time::Duration::from_secs(2), upstream.arrived)
      .await
      .expect("switch request should reach upstream")
      .unwrap();
    upstream.release.send(()).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    upstream.task.await.unwrap();
    let raw_request = String::from_utf8_lossy(&upstream.request.await.unwrap()).to_string();
    let lower = raw_request.to_ascii_lowercase();
    assert!(
      raw_request.contains(std::str::from_utf8(&inbound_body).unwrap()),
      "switch should forward the original body bytes, got:\n{raw_request}"
    );
    assert!(
      lower.contains("authorization: bearer sk-test"),
      "switch should inject router account auth, got:\n{raw_request}"
    );
    assert!(
      !raw_request.contains("client-secret-must-not-leak"),
      "switch must strip inbound client auth"
    );
  }

  #[tokio::test]
  async fn profile_provider_filter_excludes_other_provider_accounts() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
      "openai-only".into(),
      ProfileConfig {
        providers: Some(vec!["openai".into()]),
        ..Default::default()
      },
    );
    let accounts = vec![zai_account()];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    assert_eq!(state.profiles.get("openai-only").unwrap().pool.len(), 0);
    let app = router(state);

    let req = Request::builder()
      .method("POST")
      .uri("/openai-only/v1/responses")
      .header("content-type", "application/json")
      .body(Body::from(Bytes::from_static(br#"{"model":"glm-4.6","input":"hi"}"#)))
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
  }

  #[tokio::test]
  async fn profile_models_uses_prefiltered_policy_pool() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let (req_tx, req_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buf = vec![0_u8; 4096];
      let n = stream.read(&mut buf).await.unwrap();
      buf.truncate(n);
      let body = br#"{"object":"list","data":[{"id":"policy-only-model","object":"model"}]}"#;
      let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
      );
      stream.write_all(resp.as_bytes()).await.unwrap();
      stream.write_all(body).await.unwrap();
      stream.flush().await.unwrap();
      let _ = req_tx.send(buf);
    });

    let mut cfg = Config::default();
    cfg.profiles.insert(
      "work".into(),
      ProfileConfig {
        accounts: Some(vec!["local".into()]),
        ..Default::default()
      },
    );
    let accounts = vec![
      zai_account_with_id_and_base("local", Some(upstream_url)),
      zai_account_with_id("excluded"),
    ];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    assert_eq!(state.pool.len(), 2);
    assert_eq!(state.profiles.get("work").unwrap().pool.len(), 1);
    let app = router(state);

    let req = Request::builder()
      .method("GET")
      .uri("/work/v1/models")
      .body(Body::empty())
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let ids = json["data"]
      .as_array()
      .unwrap()
      .iter()
      .filter_map(|model| model["id"].as_str())
      .collect::<Vec<_>>();
    assert_eq!(ids, vec!["policy-only-model"]);

    let upstream_req = req_rx.await.unwrap();
    let upstream_req = String::from_utf8_lossy(&upstream_req);
    assert!(upstream_req.starts_with("GET /models "));
    server.await.unwrap();
  }

  #[tokio::test]
  async fn api_switch_models_uses_default_provider_only() {
    let (default_base, default_req, default_task) = one_shot_models_upstream("default-provider-model").await;
    let (other_base, other_req, other_task) = one_shot_models_upstream("other-provider-model").await;

    let mut cfg = Config::default();
    cfg.defaults.mode = RouteMode::Switch;
    cfg.defaults.default_provider_id = Some("zai-coding-plan".into());
    let accounts = vec![
      zai_account_with_id_and_base("default", Some(default_base)),
      openai_account_with_id_and_base("other", Some(other_base)),
    ];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("GET")
      .uri("/v1/models")
      .body(Body::empty())
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let ids = json["data"]
      .as_array()
      .unwrap()
      .iter()
      .filter_map(|model| model["id"].as_str())
      .collect::<Vec<_>>();
    assert_eq!(ids, vec!["default-provider-model"]);
    assert_eq!(json["route_mode"], "switch");

    let default_upstream_req = String::from_utf8_lossy(&default_req.await.unwrap()).to_ascii_lowercase();
    assert!(default_upstream_req.starts_with("get /models "));
    assert!(default_upstream_req.contains("authorization: bearer sk-test"));
    default_task.await.unwrap();

    assert!(
      tokio::time::timeout(std::time::Duration::from_millis(100), other_req)
        .await
        .is_err(),
      "switch /v1/models should not query non-default provider"
    );
    other_task.abort();
  }

  #[tokio::test]
  async fn models_falls_back_to_local_catalogue_when_remote_fails() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buf = vec![0_u8; 4096];
      let _ = stream.read(&mut buf).await.unwrap();
      let body = br#"{"error":"upstream unavailable"}"#;
      let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
      );
      stream.write_all(resp.as_bytes()).await.unwrap();
      stream.write_all(body).await.unwrap();
      stream.flush().await.unwrap();
    });

    let cfg = Config::default();
    let accounts = vec![zai_account_with_id_and_base("local", Some(upstream_url))];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("GET")
      .uri("/v1/models")
      .body(Body::empty())
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let ids = json["data"]
      .as_array()
      .unwrap()
      .iter()
      .filter_map(|model| model["id"].as_str())
      .collect::<Vec<_>>();
    assert!(ids.contains(&"glm-5.1"));
    assert_eq!(json["data"][0]["x_tokn_router"]["provider"], "zai-coding-plan");

    server.await.unwrap();
  }

  #[tokio::test]
  async fn models_falls_back_to_local_catalogue_when_remote_is_empty() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buf = vec![0_u8; 4096];
      let _ = stream.read(&mut buf).await.unwrap();
      let body = br#"{"object":"list","data":[]}"#;
      let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
      );
      stream.write_all(resp.as_bytes()).await.unwrap();
      stream.write_all(body).await.unwrap();
      stream.flush().await.unwrap();
    });

    let cfg = Config::default();
    let accounts = vec![zai_account_with_id_and_base("local", Some(upstream_url))];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("GET")
      .uri("/v1/models")
      .body(Body::empty())
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let ids = json["data"]
      .as_array()
      .unwrap()
      .iter()
      .filter_map(|model| model["id"].as_str())
      .collect::<Vec<_>>();
    assert!(ids.contains(&"glm-5.1"));

    server.await.unwrap();
  }

  #[tokio::test]
  async fn providers_uses_prefiltered_policy_pool() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
      "work".into(),
      ProfileConfig {
        accounts: Some(vec!["local".into()]),
        ..Default::default()
      },
    );
    let accounts = vec![zai_account_with_id("local"), zai_account_with_id("excluded")];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("GET")
      .uri("/work/v1/providers")
      .body(Body::empty())
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["object"], "list");
    assert_eq!(json["route_mode"], "route");
    let providers = json["data"].as_array().unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["id"], "zai-coding-plan");
    assert_eq!(providers[0]["accounts"], 1);
    assert!(providers[0]["endpoints"]
      .as_array()
      .unwrap()
      .iter()
      .any(|endpoint| endpoint == "chat_completions"));
  }

  #[tokio::test]
  async fn exact_mode_models_are_provider_prefixed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buf = vec![0_u8; 4096];
      let _ = stream.read(&mut buf).await.unwrap();
      let body = br#"{"object":"list","data":[{"id":"glm-4.6","object":"model"}]}"#;
      let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
      );
      stream.write_all(resp.as_bytes()).await.unwrap();
      stream.write_all(body).await.unwrap();
      stream.flush().await.unwrap();
    });

    let mut cfg = Config::default();
    cfg.profiles.insert(
      "exact".into(),
      ProfileConfig {
        mode: Some(RouteMode::Exact),
        accounts: Some(vec!["local".into()]),
        ..Default::default()
      },
    );
    let accounts = vec![zai_account_with_id_and_base("local", Some(upstream_url))];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("GET")
      .uri("/exact/v1/models")
      .body(Body::empty())
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["route_mode"], "exact");
    assert_eq!(json["data"][0]["id"], "zai-coding-plan/glm-4.6");
    assert_eq!(json["data"][0]["x_tokn_router"]["upstream_id"], "glm-4.6");
    assert_eq!(json["data"][0]["x_tokn_router"]["model_id"], "zai-coding-plan/glm-4.6");

    server.await.unwrap();
  }

  #[test]
  fn profile_without_providers_inherits_unrestricted_defaults() {
    let mut cfg = Config::default();
    cfg.profiles.insert("work".into(), ProfileConfig::default());
    let accounts = vec![zai_account()];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();

    let work = state.profiles.get("work").expect("work profile");
    assert!(state.default_policy.ruleset.providers.is_none());
    assert!(work.ruleset.providers.is_none());
    assert_eq!(work.pool.len(), 1);
  }

  #[test]
  fn profile_inherits_default_provider_id() {
    let mut cfg = Config::default();
    cfg.defaults.default_provider_id = Some("zai-coding-plan".into());
    cfg.profiles.insert(
      "work".into(),
      ProfileConfig {
        mode: Some(RouteMode::Passthrough),
        ..Default::default()
      },
    );
    let state = build_state(&cfg, &[zai_account()], Arc::new(EventBus::noop())).unwrap();
    let work = state.profiles.get("work").expect("work profile");
    assert_eq!(work.default_provider_id.as_deref(), Some("zai-coding-plan"));
    let resolved = work.route.resolve("glm-4.6", None).unwrap();
    assert_eq!(
      resolved.selector,
      tokn_accounts::routing::RouteSelector::Provider("zai-coding-plan".into())
    );
  }

  #[test]
  fn profile_providers_replace_default_providers() {
    let mut cfg = Config::default();
    cfg.defaults.providers = Some(vec!["openai".into()]);
    cfg.profiles.insert(
      "zai-only".into(),
      ProfileConfig {
        providers: Some(vec!["zai-coding-plan".into()]),
        ..Default::default()
      },
    );
    let accounts = vec![zai_account()];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();

    let providers = state
      .profiles
      .get("zai-only")
      .and_then(|profile| profile.ruleset.providers.as_ref())
      .expect("profile should have provider filter");
    assert!(providers.contains("zai-coding-plan"));
    assert!(!providers.contains("openai"));
    assert_eq!(state.profiles.get("zai-only").unwrap().pool.len(), 1);
  }

  #[test]
  fn profile_accounts_replace_default_accounts() {
    let mut cfg = Config::default();
    cfg.defaults.accounts = Some(vec!["other".into()]);
    cfg.profiles.insert(
      "agent".into(),
      ProfileConfig {
        accounts: Some(vec!["acct".into()]),
        ..Default::default()
      },
    );
    let accounts = vec![zai_account(), zai_account_with_id("other")];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();

    let profile_accounts = state
      .profiles
      .get("agent")
      .and_then(|profile| profile.ruleset.accounts.as_ref())
      .expect("profile should have account filter");
    assert!(profile_accounts.contains("acct"));
    assert!(!profile_accounts.contains("other"));
    let account_ids = state
      .profiles
      .get("agent")
      .unwrap()
      .pool
      .all()
      .iter()
      .map(|account| account.id())
      .collect::<Vec<_>>();
    assert_eq!(account_ids, vec!["acct".to_string()]);
  }

  #[test]
  fn profile_model_families_replace_default_families() {
    let mut cfg = Config::default();
    cfg.defaults.model_families = vec![ModelFamily {
      name: "glm-family".into(),
      members: vec!["glm-4.7".into()],
    }];
    cfg.profiles.insert(
      "work".into(),
      ProfileConfig {
        mode: Some(RouteMode::Fuzzy),
        model_families: Some(vec![ModelFamily {
          name: "glm-family".into(),
          members: vec!["glm-5.1".into()],
        }]),
        ..Default::default()
      },
    );
    let accounts = vec![zai_account()];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let work = state.profiles.get("work").expect("work profile");

    assert_eq!(work.model_families.len(), 1);
    assert_eq!(work.model_families[0].members, vec!["glm-5.1".to_string()]);
    let resolved = work.route.resolve("glm-family", None).unwrap();
    assert_eq!(
      resolved.selector,
      tokn_accounts::routing::RouteSelector::Fuzzy {
        candidates: vec!["glm-5.1".into()]
      }
    );
  }

  #[test]
  fn build_state_rejects_unknown_policy_provider_filters() {
    let mut cfg = Config::default();
    cfg.defaults.default_provider_id = Some("made-up-provider".into());
    let err = match build_state(&cfg, &[], Arc::new(EventBus::noop())) {
      Ok(_) => panic!("unknown default provider id must fail"),
      Err(err) => err,
    };
    assert!(err
      .to_string()
      .contains("defaults.default_provider_id:made-up-provider"));

    let mut cfg = Config::default();
    cfg.defaults.providers = Some(vec!["made-up-provider".into()]);
    let err = match build_state(&cfg, &[], Arc::new(EventBus::noop())) {
      Ok(_) => panic!("unknown default provider must fail"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("defaults.providers:made-up-provider"));

    let mut cfg = Config::default();
    cfg.profiles.insert(
      "work".into(),
      ProfileConfig {
        providers: Some(vec!["made-up-provider".into()]),
        ..Default::default()
      },
    );
    let err = match build_state(&cfg, &[], Arc::new(EventBus::noop())) {
      Ok(_) => panic!("unknown profile provider must fail"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("profiles.work.providers:made-up-provider"));
  }

  #[test]
  fn build_state_rejects_unknown_policy_account_filters() {
    let accounts = vec![zai_account()];
    let mut cfg = Config::default();
    cfg.defaults.accounts = Some(vec!["missing".into()]);
    let err = match build_state(&cfg, &accounts, Arc::new(EventBus::noop())) {
      Ok(_) => panic!("unknown default account must fail"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("defaults.accounts:missing"));

    let mut cfg = Config::default();
    cfg.profiles.insert(
      "work".into(),
      ProfileConfig {
        accounts: Some(vec!["missing".into()]),
        ..Default::default()
      },
    );
    let err = match build_state(&cfg, &accounts, Arc::new(EventBus::noop())) {
      Ok(_) => panic!("unknown profile account must fail"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("profiles.work.accounts:missing"));
  }

  #[tokio::test]
  async fn unknown_profile_path_returns_bad_request() {
    let cfg = Config::default();
    let accounts = vec![zai_account()];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("POST")
      .uri("/missing/v1/responses")
      .header("content-type", "application/json")
      .body(Body::from(Bytes::from_static(br#"{"model":"glm-4.6","input":"hi"}"#)))
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn old_mode_path_is_not_magic_without_matching_profile() {
    let cfg = Config::default();
    let accounts = vec![zai_account()];
    let state = build_state(&cfg, &accounts, Arc::new(EventBus::noop())).unwrap();
    let app = router(state);

    let req = Request::builder()
      .method("POST")
      .uri("/fuzzy/v1/responses")
      .header("content-type", "application/json")
      .body(Body::from(Bytes::from_static(br#"{"model":"glm-4.6","input":"hi"}"#)))
      .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
  }

  #[test]
  fn is_router_owned_header_does_not_include_request_session_project_id_headers() {
    use axum::http::HeaderName;

    for header in REQUEST_ID_HEADERS.iter() {
      let name = HeaderName::try_from(*header).unwrap();
      assert!(!is_router_owned_header(&name), "{header} should NOT be router-owned");
    }

    for header in SESSION_ID_HEADERS.iter() {
      let name = HeaderName::try_from(*header).unwrap();
      assert!(!is_router_owned_header(&name), "{header} should NOT be router-owned");
    }

    for header in PROJECT_ID_HEADERS.iter() {
      let name = HeaderName::try_from(*header).unwrap();
      assert!(!is_router_owned_header(&name), "{header} should NOT be router-owned");
    }
  }
}

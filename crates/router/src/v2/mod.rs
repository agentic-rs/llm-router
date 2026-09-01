mod discovery;
mod selector;

use crate::api::error::ApiError;
use crate::api::identity::AccountIdentityResolver;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::{ConnectInfo, Extension, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use selector::{
  PoolAwareSend, ProxyPoolAwareSend, V2AccountSelector, V2ClientResolve, V2ProxyResolve, V2_PROXY_ORIGIN_KEY,
};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error as _;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokn_access::AccessContext;
use tokn_accounts::link::{
  build_account_pool_runtimes, link_account_pools, link_provider_graph, AccountPoolRuntimes, ProviderDestination,
  ProviderGraph,
};
use tokn_accounts::registry::Registry;
use tokn_core::account::AccountConfig;
use tokn_core::event::{Event as CoreEvent, EventBus};
use tokn_core::provider::Endpoint;
use tokn_core::request_event::{RecordEvent, RequestEvent, RequestEventPayload};
use tokn_core::upstream_url::{CanonicalHttpOrigin, CanonicalUpstreamUrl, CleartextHttpPolicy};
use tokn_core::AgentId;
use tokn_policy::{
  CanonicalAuthority, CanonicalHost, ClientAuthPlan, ConnectAction, CredentialPolicy, ForwardProxyListenerPlan,
  GatewayPlan, HttpAction, HttpMatch, IngressAuthority, ListenerId, ListenerPlan, LlmApiListenerPlan, ManagedRetry,
  ModelSelector, ProfileId, ProviderId, RelayCredentials, RelayDestination, RelayRetry, RetryPolicyId, RouteKind,
  RoutePlan, WireIdentity,
};
use tokn_requests::stages::{
  DefaultBuildHeaders, DefaultConvertRequest, DefaultConvertResponse, DefaultExtract, PassthroughBuildHeaders,
  PassthroughConvertRequest, PassthroughConvertResponse, PassthroughExtract, PoolResolve, ProxySend,
};
use tokn_requests::{ExecutionRequest, Pipeline, Profile, RawInbound, RequestService, RunConfig, RunConfigBuilder};
use tower_http::request_id::SetRequestIdLayer;

use crate::request_id::REQUEST_ID_HEADER;

#[derive(Clone)]
struct ProfileRuntime {
  api_service: Option<tokn_service::HttpService>,
  proxy_service: Option<tokn_service::HttpService>,
  route_kind: RouteKind,
  record_mode: &'static str,
  credential_policy: CredentialPolicy,
  agent_id: Option<AgentId>,
  api_destination: Option<ProviderDestination>,
  proxy_destination: ProxyDestination,
}

#[derive(Clone)]
enum ProxyDestination {
  Managed,
  Fixed {
    provider: ProviderId,
    base: CanonicalUpstreamUrl,
  },
  Original,
}

/// Router state for one compiled v2 LLM API listener.
///
/// Each profile owns a route-specific six-stage pipeline. Listener bindings
/// choose among those pipelines; there is no second request engine behind the
/// state.
#[derive(Clone)]
pub struct AppState {
  listener_id: ListenerId,
  listener: LlmApiListenerPlan,
  profiles: Arc<BTreeMap<ProfileId, ProfileRuntime>>,
  discovery: Arc<discovery::DiscoveryRuntime>,
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
  request_limits: tokn_config::v2::RequestLimitsPlan,
}

impl AppState {
  pub fn listener_id(&self) -> &ListenerId {
    &self.listener_id
  }

  pub fn bind(&self) -> std::net::SocketAddr {
    self.listener.bind()
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    self.listener.client_auth()
  }

  fn select_profile(
    &self,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    endpoint: Endpoint,
  ) -> Result<&ProfileRuntime, ApiError> {
    let host = request_host(uri, headers)?;
    let operation = operation_name(endpoint);
    let action = self
      .listener
      .http_bindings()
      .iter()
      .find(|binding| http_matches(binding.matcher(), host.as_ref(), method, uri.path(), Some(operation)))
      .map(|binding| binding.action())
      .unwrap_or_else(|| self.listener.default_http_action());
    match action {
      HttpAction::Route(profile_id) => self
        .profiles
        .get(profile_id)
        .ok_or_else(|| ApiError::internal(format!("listener selected missing profile '{profile_id}'"))),
      HttpAction::Reject => Err(ApiError::forbidden("request rejected by v2 listener policy")),
    }
  }

  fn discovery_profiles(&self, uri: &Uri, headers: &HeaderMap) -> Result<BTreeSet<ProfileId>, ApiError> {
    let path = uri.path();
    let prefix = path
      .strip_suffix("models")
      .or_else(|| path.strip_suffix("providers"))
      .ok_or_else(|| ApiError::internal(format!("unsupported v2 discovery path '{path}'")))?;
    let host = request_host(uri, headers)?;
    let mut profiles = self
      .listener
      .http_bindings()
      .iter()
      .filter(|binding| {
        let matcher = binding.matcher();
        (matcher.hosts().is_empty()
          || host
            .as_ref()
            .is_some_and(|host| matcher.hosts().iter().any(|pattern| pattern.matches(host))))
          && (matcher.path_prefixes().is_empty()
            || matcher
              .path_prefixes()
              .iter()
              .any(|candidate| candidate.starts_with(prefix) || prefix.starts_with(candidate.as_str())))
      })
      .filter_map(|binding| match binding.action() {
        HttpAction::Route(profile) => Some(profile.clone()),
        HttpAction::Reject => None,
      })
      .collect::<BTreeSet<_>>();

    if profiles.is_empty() && path.starts_with("/v1/") {
      collect_profile(self.listener.default_http_action(), &mut profiles);
    }
    if profiles.is_empty() {
      return Err(ApiError::bad_request(format!(
        "no v2 profile is bound to discovery path '{path}'"
      )));
    }
    Ok(profiles)
  }
}

#[derive(Clone)]
pub struct ForwardProxyState {
  listener_id: ListenerId,
  listener: ForwardProxyListenerPlan,
  profiles: Arc<BTreeMap<ProfileId, ProfileRuntime>>,
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
  identity: Arc<AccountIdentityResolver>,
  provider_registry: Arc<Registry>,
  ca: Option<Arc<crate::proxy::ProxyCa>>,
  outbound: tokn_core::util::http::HttpClientOptions,
  request_limits: tokn_config::v2::RequestLimitsPlan,
}

impl ForwardProxyState {
  pub fn listener_id(&self) -> &ListenerId {
    &self.listener_id
  }

  pub fn bind(&self) -> SocketAddr {
    self.listener.bind()
  }

  fn connect_action(&self, host: &CanonicalHost, port: u16) -> ConnectAction {
    self
      .listener
      .connect_rules()
      .iter()
      .find(|rule| {
        let matcher = rule.matcher();
        (matcher.hosts().is_empty() || matcher.hosts().iter().any(|pattern| pattern.matches(host)))
          && (matcher.ports().is_empty() || matcher.ports().contains(&port))
      })
      .map(|rule| rule.action())
      .unwrap_or_else(|| self.listener.default_connect_action())
  }

  fn select_profile(
    &self,
    ingress: &IngressAuthority,
    method: &Method,
    uri: &Uri,
  ) -> Result<&ProfileRuntime, ApiError> {
    let operation = proxy_operation(method, uri.path()).map(operation_name);
    let action = self
      .listener
      .http_bindings()
      .iter()
      .find(|binding| http_matches(binding.matcher(), Some(ingress.host()), method, uri.path(), operation))
      .map(|binding| binding.action())
      .unwrap_or_else(|| self.listener.default_http_action());
    match action {
      HttpAction::Route(profile_id) => self
        .profiles
        .get(profile_id)
        .ok_or_else(|| ApiError::internal(format!("listener selected missing profile '{profile_id}'"))),
      HttpAction::Reject => Err(ApiError::forbidden("request rejected by v2 listener policy")),
    }
  }

  pub(crate) fn connect_action_for(&self, ingress: &IngressAuthority) -> ConnectAction {
    self.connect_action(ingress.host(), ingress.port())
  }

  pub(crate) fn pinned_tls_config(&self, ingress: &IngressAuthority) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    self
      .ca
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("listener '{}' has no interception CA", self.listener_id))?
      .pinned_server_config(ingress.host())
  }

  pub(crate) async fn authenticate_proxy(
    &self,
    headers: &mut HeaderMap,
  ) -> Result<AccessContext, ProxyAuthenticationError> {
    let authorization = headers
      .get_all(axum::http::header::PROXY_AUTHORIZATION)
      .iter()
      .map(|value| value.to_str().ok())
      .collect::<Option<Vec<_>>>();
    let token = match (self.listener.client_auth(), authorization.as_deref()) {
      (ClientAuthPlan::None, _) => None,
      (ClientAuthPlan::LocalKeys, Some([value])) => {
        let mut parts = value.split_ascii_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
          (Some(scheme), Some(token), None) if scheme.eq_ignore_ascii_case("bearer") => Some(token.to_string()),
          _ => return Err(ProxyAuthenticationError::Rejected),
        }
      }
      (ClientAuthPlan::LocalKeys, _) => return Err(ProxyAuthenticationError::Rejected),
    };
    headers.remove(axum::http::header::PROXY_AUTHORIZATION);
    let Some(token) = token else {
      return Ok(AccessContext::unrestricted());
    };
    let access = self.access.clone();
    tokio::task::spawn_blocking(move || access.authenticate(Some(&token)))
      .await
      .map_err(|error| {
        tracing::error!(%error, "v2 proxy authentication task failed");
        ProxyAuthenticationError::Unavailable
      })?
      .map_err(|_| ProxyAuthenticationError::Rejected)
  }

  pub(crate) async fn dispatch_http(
    &self,
    ingress: &IngressAuthority,
    scheme: &'static str,
    access: AccessContext,
    connection: InboundConnectionInfo,
    request: Request<hyper::body::Incoming>,
  ) -> Response {
    match self
      .dispatch_http_inner(ingress, scheme, access, connection, request)
      .await
    {
      Ok(response) => response,
      Err(error) => error.into_response(),
    }
  }

  async fn dispatch_http_inner(
    &self,
    ingress: &IngressAuthority,
    scheme: &'static str,
    access: AccessContext,
    connection: InboundConnectionInfo,
    request: Request<hyper::body::Incoming>,
  ) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    let runtime = self.select_profile(ingress, &parts.method, &parts.uri)?;
    let service = runtime
      .proxy_service
      .as_ref()
      .ok_or_else(|| ApiError::internal("selected profile cannot run on a forward-proxy listener"))?;
    let path_and_query = parts.uri.path_and_query().map_or("/", |value| value.as_str());
    let origin = canonical_origin(scheme, ingress);
    let inbound_url = format!("{origin}{path_and_query}");
    emit_inbound_connection(
      &self.events,
      &access,
      request_id(&parts.headers)?,
      connection.local_addr.map(|addr| SmolStr::new(addr.to_string())),
      connection.peer_addr.map(|addr| SmolStr::new(addr.to_string())),
      runtime.record_mode,
      "proxy",
      &parts.method,
      Some(SmolStr::new(inbound_url)),
    );
    let request_endpoint = tokn_core::request_event::RequestEndpoint::infer_from_path(parts.uri.path());
    let max_wire_bytes = self
      .listener
      .request_body_max_bytes()
      .min(self.request_limits.max_wire_bytes());
    let raw_body = match axum::body::to_bytes(axum::body::Body::new(body), max_wire_bytes).await {
      Ok(body) => body,
      Err(error)
        if error
          .source()
          .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
      {
        return Err(ApiError::payload_too_large(format!(
          "proxy request body exceeds the configured {} byte limit",
          max_wire_bytes
        )));
      }
      Err(error) => return Err(ApiError::bad_request(format!("read proxy request body: {error}"))),
    };
    let headers: tokn_headers::HeaderMap = (&parts.headers).into();
    let (decoded_body, body_json) = if runtime.route_kind == RouteKind::Managed {
      let endpoint = request_endpoint
        .resolved()
        .ok_or_else(|| ApiError::bad_request("managed proxy routes require a supported LLM operation path"))?;
      let mut decoded = crate::api::codec::decode_json_request_with_limit(
        &parts.headers,
        raw_body.clone(),
        self.request_limits.max_decoded_bytes(),
      )?;
      crate::api::endpoints::apply_endpoint_compat_defaults(endpoint, &parts.headers, &mut decoded)?;
      (decoded.decoded_body, decoded.value)
    } else {
      let decoded = decode_opaque_body_for_inspection(
        &parts.headers,
        raw_body.clone(),
        self.request_limits.max_decoded_bytes(),
      )?;
      (decoded, serde_json::Value::Null)
    };
    let destination = proxy_destination(runtime, ingress, scheme, path_and_query)?;
    let (destination_scheme, destination_authority, destination_path) = url_destination(&destination);
    let mut config = RunConfig::builder()
      .with_agent_id_opt(runtime.agent_id.clone())
      .with_str(
        tokn_requests::stages::resolve::proxy::keys::HOST,
        destination_authority.clone(),
      )
      .with_str(
        tokn_requests::stages::resolve::proxy::keys::PATH,
        destination_path.clone(),
      )
      .with_str(tokn_requests::stages::send::proxy::send_keys::PATH, destination_path)
      .with_str(
        tokn_requests::stages::send::proxy::send_keys::METHOD,
        parts.method.as_str(),
      )
      .with_str(
        tokn_requests::stages::send::proxy::send_keys::SCHEME,
        destination_scheme,
      )
      .with_str(V2_PROXY_ORIGIN_KEY, origin.clone());
    config = match &runtime.proxy_destination {
      ProxyDestination::Fixed { provider, .. } => config.with_str(
        tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID,
        provider.to_string(),
      ),
      ProxyDestination::Original if runtime.credential_policy == CredentialPolicy::Client => {
        with_original_proxy_identity(
          config,
          &parts.headers,
          &destination,
          ingress.host().as_str(),
          &self.identity,
          &self.provider_registry,
        )
      }
      ProxyDestination::Managed | ProxyDestination::Original => {
        config.with_str(tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID, origin)
      }
    };
    if runtime.credential_policy == CredentialPolicy::Account {
      config = config.with(tokn_requests::stages::send::proxy::send_keys::INJECT_AUTH, true);
    }
    if let Some(providers) = access.providers.provider_ids() {
      config = config.with(
        tokn_requests::stages::ACCESS_ALLOWED_PROVIDERS_KEY,
        serde_json::Value::Array(providers.iter().cloned().map(serde_json::Value::String).collect()),
      );
    }
    let request = ExecutionRequest::new(RawInbound {
      request_endpoint,
      headers,
      raw_body,
      decoded_body,
      body_json,
      request_id: parts
        .headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(SmolStr::new),
    })
    .with_config(config.build())
    .into_http(parts.method, parts.uri)
    .map_err(|error| ApiError::internal(format!("building v2 proxy service message: {error}")))?;
    service
      .execute(request)
      .await
      .map(crate::api::response::converted_to_axum)
      .map_err(crate::api::endpoints::request_error_to_api_error)
  }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct InboundConnectionInfo {
  local_addr: Option<SocketAddr>,
  peer_addr: Option<SocketAddr>,
}

struct ApiRequestContext {
  access: AccessContext,
  connection: InboundConnectionInfo,
}

impl InboundConnectionInfo {
  pub(crate) fn new(local_addr: Option<SocketAddr>, peer_addr: SocketAddr) -> Self {
    Self {
      local_addr,
      peer_addr: Some(peer_addr),
    }
  }
}

impl<S> FromRequestParts<S> for InboundConnectionInfo
where
  S: Send + Sync,
{
  type Rejection = Infallible;

  async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
    Ok(Self {
      local_addr: parts.extensions.get::<SocketAddr>().copied(),
      peer_addr: parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr),
    })
  }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ProxyAuthenticationError {
  Rejected,
  Unavailable,
}

pub async fn serve_forward_proxy<F>(state: ForwardProxyState, bind: SocketAddr, shutdown: F) -> anyhow::Result<()>
where
  F: Future<Output = ()> + Send,
{
  crate::proxy::serve_v2_policy(bind, state.outbound.clone(), Arc::new(state), shutdown).await
}

pub struct RuntimeStates {
  pub llm_api: Vec<AppState>,
  pub forward_proxy: Vec<ForwardProxyState>,
}

#[derive(Clone, Copy)]
enum PipelineMode {
  Full,
  DryRun,
}

struct LinkedRuntimes {
  profiles: Arc<BTreeMap<ProfileId, ProfileRuntime>>,
  discovery: Arc<discovery::DiscoveryRuntime>,
}

/// Build one shared v2 runtime generation for every configured listener.
pub fn build_runtime_states(
  plan: GatewayPlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
) -> anyhow::Result<RuntimeStates> {
  build_runtime_states_with_service(plan, tokn_config::v2::ServicePlan::default(), accounts, access, events)
}

pub fn build_runtime_states_with_service(
  plan: GatewayPlan,
  service: tokn_config::v2::ServicePlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
) -> anyhow::Result<RuntimeStates> {
  let plan = Arc::new(plan);
  let outbound = service.outbound().to_http_client_options();
  let request_limits = service.request_limits();
  let linked = build_profile_runtimes(plan.clone(), accounts, events.clone(), &outbound, PipelineMode::Full)?;
  let identity = Arc::new(AccountIdentityResolver::from_accounts(accounts));
  let provider_registry = Arc::new(Registry::builtin());
  let mut llm_api = Vec::new();
  let mut forward_proxy = Vec::new();
  for (listener_id, listener) in plan.listeners() {
    match listener {
      ListenerPlan::LlmApi(listener) => llm_api.push(AppState {
        listener_id: listener_id.clone(),
        listener: listener.clone(),
        profiles: linked.profiles.clone(),
        discovery: linked.discovery.clone(),
        access: access.clone(),
        events: events.clone(),
        request_limits,
      }),
      ListenerPlan::ForwardProxy(listener) => {
        let ca = listener
          .tls()
          .map(|tls| crate::proxy::load_or_generate_ca(tls.ca_dir(), false).map(Arc::new))
          .transpose()
          .map_err(|error| anyhow::anyhow!("load v2 proxy CA for listener '{listener_id}': {error}"))?;
        forward_proxy.push(ForwardProxyState {
          listener_id: listener_id.clone(),
          listener: listener.clone(),
          profiles: linked.profiles.clone(),
          access: access.clone(),
          events: events.clone(),
          identity: identity.clone(),
          provider_registry: provider_registry.clone(),
          ca,
          outbound: outbound.clone(),
          request_limits,
        });
      }
    }
  }
  Ok(RuntimeStates { llm_api, forward_proxy })
}

/// Build one independent Axum state per configured v2 LLM API listener.
pub fn build_states(
  plan: GatewayPlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
) -> anyhow::Result<Vec<AppState>> {
  build_states_with_service(plan, tokn_config::v2::ServicePlan::default(), accounts, access, events)
}

pub fn build_states_with_service(
  plan: GatewayPlan,
  service: tokn_config::v2::ServicePlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
) -> anyhow::Result<Vec<AppState>> {
  build_api_states(plan, service, accounts, access, events, PipelineMode::Full)
}

/// Build v2 LLM listener states whose pipelines stop immediately before the
/// upstream send stage. Listener bindings, profiles, routes, account pools,
/// headers, and request conversion remain identical to the live runtime.
pub fn build_dry_run_states(
  plan: GatewayPlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
) -> anyhow::Result<Vec<AppState>> {
  build_dry_run_states_with_service(plan, tokn_config::v2::ServicePlan::default(), accounts, access, events)
}

pub fn build_dry_run_states_with_service(
  plan: GatewayPlan,
  service: tokn_config::v2::ServicePlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
) -> anyhow::Result<Vec<AppState>> {
  build_api_states(plan, service, accounts, access, events, PipelineMode::DryRun)
}

fn build_api_states(
  plan: GatewayPlan,
  service: tokn_config::v2::ServicePlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
  mode: PipelineMode,
) -> anyhow::Result<Vec<AppState>> {
  let plan = Arc::new(plan);
  let outbound = service.outbound().to_http_client_options();
  let request_limits = service.request_limits();
  let linked = build_profile_runtimes(plan.clone(), accounts, events.clone(), &outbound, mode)?;
  Ok(
    plan
      .listeners()
      .iter()
      .filter_map(|(listener_id, listener)| match listener {
        ListenerPlan::LlmApi(listener) => Some(AppState {
          listener_id: listener_id.clone(),
          listener: listener.clone(),
          profiles: linked.profiles.clone(),
          discovery: linked.discovery.clone(),
          access: access.clone(),
          events: events.clone(),
          request_limits,
        }),
        ListenerPlan::ForwardProxy(_) => None,
      })
      .collect(),
  )
}

fn build_profile_runtimes(
  plan: Arc<GatewayPlan>,
  accounts: &[AccountConfig],
  events: Arc<EventBus>,
  outbound: &tokn_core::util::http::HttpClientOptions,
  mode: PipelineMode,
) -> anyhow::Result<LinkedRuntimes> {
  let mut reachable_profiles = BTreeSet::new();
  for listener in plan.listeners().values() {
    collect_profile(listener.default_http_action(), &mut reachable_profiles);
    for binding in listener.http_bindings() {
      collect_profile(binding.action(), &mut reachable_profiles);
    }
  }

  let registry = Registry::builtin();
  let providers = link_provider_graph(&plan, accounts, &registry)?;
  let linked_pools = link_account_pools(&plan, &providers)?;
  let managed_http = tokn_core::util::http::build_managed_client(outbound)?;
  let opaque_http = tokn_core::util::http::build_opaque_client(outbound)?;
  let discovery = Arc::new(discovery::DiscoveryRuntime::new(
    &plan,
    &providers,
    &linked_pools,
    &registry,
    managed_http.clone(),
    &reachable_profiles,
  )?);
  let pools = build_account_pool_runtimes(&linked_pools);

  let mut profiles = BTreeMap::new();
  for profile_id in reachable_profiles {
    let profile_plan = plan
      .profile(&profile_id)
      .ok_or_else(|| anyhow::anyhow!("listener references missing profile '{profile_id}'"))?;
    let route = plan.route(profile_plan.route()).ok_or_else(|| {
      anyhow::anyhow!(
        "profile '{profile_id}' references missing route '{}'",
        profile_plan.route()
      )
    })?;
    let agent_id = wire_agent(profile_plan.wire_identity());
    let (api_service, proxy_service, api_destination, proxy_destination) = match route {
      RoutePlan::Managed(route) => {
        if route.header_patches().is_some() {
          anyhow::bail!("profile '{profile_id}' uses unsupported managed header patches");
        }
        let retry = managed_retry_policy(&plan, route.retry())?;
        let (selector, selection_state) = V2AccountSelector::new(plan.clone(), profile_plan.route().clone(), &pools)?;
        let name = format!("v2-{profile_id}");
        let extract = Arc::new(DefaultExtract);
        let resolve = Arc::new(PoolResolve::new(Arc::new(selector)));
        let build_headers = Arc::new(DefaultBuildHeaders::with_provider_defaults());
        let convert_request = Arc::new(DefaultConvertRequest);
        let profile = match mode {
          PipelineMode::Full => Profile::full(
            name,
            extract,
            resolve,
            build_headers,
            convert_request,
            Arc::new(PoolAwareSend::new(managed_http.clone(), selection_state)),
            Arc::new(DefaultConvertResponse::new()),
          ),
          PipelineMode::DryRun => Profile::without_send(name, extract, resolve, build_headers, convert_request),
        };
        let service = RequestService::http_from_pipeline(Arc::new(Pipeline::new_with_retry(
          Arc::new(profile),
          events.clone(),
          retry,
        )));
        (Some(service.clone()), Some(service), None, ProxyDestination::Managed)
      }
      RoutePlan::Relay(route) => {
        if route.header_patches().is_some() {
          anyhow::bail!("profile '{profile_id}' uses unsupported relay header patches");
        }
        let retry = relay_retry_policy(&plan, route.retry())?;
        let proxy_service = build_proxy_relay_service(
          &profile_id,
          route,
          &plan,
          &providers,
          &pools,
          opaque_http.clone(),
          events.clone(),
        )?;
        let linked_destination = match route.destination() {
          RelayDestination::Original => None,
          RelayDestination::FixedProvider(provider) => Some(
            providers
              .destination(provider)
              .cloned()
              .ok_or_else(|| anyhow::anyhow!("profile '{profile_id}' references missing provider '{provider}'"))?,
          ),
        };
        let (api_service, api_destination) = match (route.destination(), route.credentials()) {
          (RelayDestination::Original, _) => (None, None),
          (RelayDestination::FixedProvider(_), RelayCredentials::AccountPool(_)) => {
            let (selector, selection_state) =
              V2AccountSelector::new(plan.clone(), profile_plan.route().clone(), &pools)?;
            let name = format!("v2-{profile_id}-api");
            let extract = Arc::new(PassthroughExtract);
            let resolve = Arc::new(PoolResolve::new(Arc::new(selector)));
            let build_headers = Arc::new(PassthroughBuildHeaders::router_auth());
            let convert_request = Arc::new(PassthroughConvertRequest);
            let profile = match mode {
              PipelineMode::Full => Profile::full(
                name,
                extract,
                resolve,
                build_headers,
                convert_request,
                Arc::new(PoolAwareSend::new(opaque_http.clone(), selection_state)),
                Arc::new(PassthroughConvertResponse::new()),
              ),
              PipelineMode::DryRun => Profile::without_send(name, extract, resolve, build_headers, convert_request),
            };
            (
              Some(RequestService::http_from_pipeline(Arc::new(Pipeline::new_with_retry(
                Arc::new(profile),
                events.clone(),
                retry,
              )))),
              None,
            )
          }
          (RelayDestination::FixedProvider(provider), RelayCredentials::Client) => {
            let name = format!("v2-{profile_id}-api");
            let extract = Arc::new(PassthroughExtract);
            let resolve = Arc::new(V2ClientResolve::new(Some(provider.clone())));
            let build_headers = Arc::new(PassthroughBuildHeaders::new());
            let convert_request = Arc::new(PassthroughConvertRequest);
            let profile = match mode {
              PipelineMode::Full => Profile::full(
                name,
                extract,
                resolve,
                build_headers,
                convert_request,
                Arc::new(ProxySend::forward_all_statuses(opaque_http.clone())),
                Arc::new(PassthroughConvertResponse::new()),
              ),
              PipelineMode::DryRun => Profile::without_send(name, extract, resolve, build_headers, convert_request),
            };
            (
              Some(RequestService::http_from_pipeline(Arc::new(Pipeline::new_with_retry(
                Arc::new(profile),
                events.clone(),
                retry,
              )))),
              linked_destination.clone(),
            )
          }
        };
        let proxy_destination = match linked_destination {
          Some(destination) => ProxyDestination::Fixed {
            provider: destination.provider_id().clone(),
            base: destination.target().base_url().clone(),
          },
          None => ProxyDestination::Original,
        };
        (api_service, Some(proxy_service), api_destination, proxy_destination)
      }
    };
    let runtime = ProfileRuntime {
      api_service,
      proxy_service,
      route_kind: route.kind(),
      record_mode: request_record_mode(route),
      credential_policy: route.credential_policy(),
      agent_id,
      api_destination,
      proxy_destination,
    };
    profiles.insert(profile_id, runtime);
  }
  Ok(LinkedRuntimes {
    profiles: Arc::new(profiles),
    discovery,
  })
}

fn build_proxy_relay_service(
  profile_id: &ProfileId,
  route: &tokn_policy::RelayRoute,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
  http: reqwest::Client,
  events: Arc<EventBus>,
) -> anyhow::Result<tokn_service::HttpService> {
  let retry = relay_retry_policy(plan, route.retry())?;
  let name = format!("v2-{profile_id}-proxy");
  let profile = match route.credentials() {
    RelayCredentials::AccountPool(account_pool) => {
      let origins = match route.destination() {
        RelayDestination::FixedProvider(_) => BTreeMap::new(),
        RelayDestination::Original => provider_origins(plan, providers, pools, account_pool)?,
      };
      let (resolve, selection_state) = V2ProxyResolve::new(route, pools, origins)?;
      let build_headers = match route.destination() {
        RelayDestination::FixedProvider(_) => PassthroughBuildHeaders::router_auth(),
        RelayDestination::Original => PassthroughBuildHeaders::preserve_host_with_router_auth(),
      };
      Profile::full(
        name,
        Arc::new(PassthroughExtract),
        Arc::new(resolve),
        Arc::new(build_headers),
        Arc::new(PassthroughConvertRequest),
        Arc::new(ProxyPoolAwareSend::new(http, selection_state)),
        Arc::new(PassthroughConvertResponse::new()),
      )
    }
    RelayCredentials::Client => {
      let fixed_provider = match route.destination() {
        RelayDestination::FixedProvider(provider) => Some(provider.clone()),
        RelayDestination::Original => None,
      };
      let build_headers = match route.destination() {
        RelayDestination::FixedProvider(_) => PassthroughBuildHeaders::new(),
        RelayDestination::Original => PassthroughBuildHeaders::preserve_host(),
      };
      Profile::full(
        name,
        Arc::new(PassthroughExtract),
        Arc::new(V2ClientResolve::new(fixed_provider)),
        Arc::new(build_headers),
        Arc::new(PassthroughConvertRequest),
        Arc::new(ProxySend::forward_all_statuses(http)),
        Arc::new(PassthroughConvertResponse::new()),
      )
    }
  };
  Ok(RequestService::http_from_pipeline(Arc::new(Pipeline::new_with_retry(
    Arc::new(profile),
    events,
    retry,
  ))))
}

fn managed_retry_policy(plan: &GatewayPlan, retry: &ManagedRetry) -> anyhow::Result<tokn_requests::RetryPolicy> {
  match retry {
    ManagedRetry::Never => Ok(tokn_requests::RetryPolicy::default()),
    ManagedRetry::Recoverable(policy_id) => retry_policy(plan, policy_id, false),
  }
}

fn relay_retry_policy(plan: &GatewayPlan, retry: &RelayRetry) -> anyhow::Result<tokn_requests::RetryPolicy> {
  match retry {
    RelayRetry::Never => Ok(tokn_requests::RetryPolicy::default()),
    RelayRetry::SafeMethods(policy_id) => retry_policy(plan, policy_id, true),
    RelayRetry::Buffered(policy_id) => retry_policy(plan, policy_id, false),
  }
}

fn retry_policy(
  plan: &GatewayPlan,
  policy_id: &RetryPolicyId,
  safe_methods: bool,
) -> anyhow::Result<tokn_requests::RetryPolicy> {
  let policy = plan
    .retry_policy(policy_id)
    .ok_or_else(|| anyhow::anyhow!("route references missing retry policy '{policy_id}'"))?;
  let max_retries = policy.max_retries();
  let initial_backoff = policy.initial_backoff();
  Ok(if safe_methods {
    tokn_requests::RetryPolicy::safe_methods(max_retries, initial_backoff)
  } else {
    tokn_requests::RetryPolicy::new(max_retries, initial_backoff)
  })
}

fn provider_origins(
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
  pool_id: &tokn_policy::AccountPoolId,
) -> anyhow::Result<BTreeMap<String, tokn_policy::ProviderId>> {
  let pool = plan
    .account_pool(pool_id)
    .ok_or_else(|| anyhow::anyhow!("origin relay references missing account-pool policy '{pool_id}'"))?;
  let runtime = pools
    .runtime(pool_id)
    .ok_or_else(|| anyhow::anyhow!("origin relay references missing account pool '{pool_id}'"))?;
  let bound_providers = runtime
    .pool()
    .active()
    .iter()
    .chain(runtime.pool().fallback())
    .map(|account| account.binding().provider_id())
    .collect::<BTreeSet<_>>();
  let eligible = plan.providers().keys().filter(|provider_id| {
    bound_providers.contains(provider_id)
      && pool
        .selector()
        .providers()
        .is_none_or(|allowed| allowed.contains(*provider_id))
  });
  let mut origins = BTreeMap::new();
  for provider_id in eligible {
    let provider = plan
      .provider(provider_id)
      .ok_or_else(|| anyhow::anyhow!("account pool '{pool_id}' references missing provider '{provider_id}'"))?;
    let target = providers
      .target(provider_id)
      .ok_or_else(|| anyhow::anyhow!("account pool '{pool_id}' has no target for provider '{provider_id}'"))?;
    let mut claimed = provider
      .origins()
      .iter()
      .map(|origin| origin.as_str().to_string())
      .collect::<BTreeSet<_>>();
    claimed.insert(target.base_url().origin().to_string());
    for origin in claimed {
      if let Some(first) = origins.insert(origin.clone(), provider_id.clone()) {
        anyhow::bail!("proxy origin '{origin}' maps to both provider '{first}' and provider '{provider_id}'");
      }
    }
  }
  Ok(origins)
}

fn proxy_destination(
  runtime: &ProfileRuntime,
  ingress: &IngressAuthority,
  scheme: &'static str,
  path_and_query: &str,
) -> Result<reqwest::Url, ApiError> {
  let path_and_query = path_and_query
    .parse::<axum::http::uri::PathAndQuery>()
    .map_err(|error| ApiError::bad_request(format!("invalid proxy request path: {error}")))?;
  match &runtime.proxy_destination {
    ProxyDestination::Managed | ProxyDestination::Original => {
      let origin = CanonicalHttpOrigin::parse(&canonical_origin(scheme, ingress), CleartextHttpPolicy::Allow)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
      let url = origin
        .request_url(&path_and_query)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
      Ok(url)
    }
    ProxyDestination::Fixed { base, .. } => {
      let url = base
        .relay_url(&path_and_query)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
      Ok(url)
    }
  }
}

fn with_original_proxy_identity(
  config: RunConfigBuilder,
  headers: &HeaderMap,
  destination: &reqwest::Url,
  fallback_provider_id: &str,
  identity: &AccountIdentityResolver,
  provider_registry: &Registry,
) -> RunConfigBuilder {
  let resolved = identity.resolve(headers, destination.as_str(), provider_registry);
  config
    .with_str(
      tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID,
      resolved.provider_id.unwrap_or_else(|| fallback_provider_id.to_string()),
    )
    .with_str_opt(
      tokn_requests::stages::resolve::proxy::keys::ACCOUNT_ID,
      resolved.account_id,
    )
}

fn url_destination(url: &reqwest::Url) -> (String, String, String) {
  let authority = url.authority().to_string();
  let mut path = url.path().to_string();
  if let Some(query) = url.query() {
    path.push('?');
    path.push_str(query);
  }
  (url.scheme().to_string(), authority, path)
}

fn canonical_origin(scheme: &str, ingress: &IngressAuthority) -> String {
  let authority = display_authority(ingress, scheme);
  format!("{scheme}://{authority}")
}

fn display_authority(ingress: &IngressAuthority, scheme: &str) -> String {
  let host = if ingress.host().is_ipv6() {
    format!("[{}]", ingress.host())
  } else {
    ingress.host().to_string()
  };
  let default_port = if scheme == "https" { 443 } else { 80 };
  if ingress.port() == default_port {
    host
  } else {
    format!("{host}:{}", ingress.port())
  }
}

fn proxy_operation(method: &Method, path: &str) -> Option<Endpoint> {
  if method == Method::POST {
    Endpoint::infer_from(path)
  } else {
    None
  }
}

fn decode_opaque_body_for_inspection(
  headers: &HeaderMap,
  raw_body: Bytes,
  max_decoded_bytes: usize,
) -> Result<Bytes, ApiError> {
  let decoded = crate::api::codec::request_content_encoding(headers).and_then(|encoding| {
    crate::api::codec::decode_body_bytes_with_limit(raw_body.clone(), encoding, max_decoded_bytes)
  });
  match decoded {
    Ok(body) => Ok(body),
    Err(error) => {
      tracing::debug!(%error, "could not decode opaque request body for inspection");
      Ok(raw_body)
    }
  }
}

pub fn router(state: AppState) -> Router {
  let max_wire_bytes = state.request_limits.max_wire_bytes();
  let state = Arc::new(state);
  let request_id_header = axum::http::HeaderName::from_static(REQUEST_ID_HEADER);
  Router::new()
    .route("/v1/chat/completions", post(chat_completions))
    .route("/v1/responses", post(responses))
    .route("/v1/messages", post(messages))
    .route("/v1/providers", get(list_providers))
    .route("/v1/models", get(list_models))
    .route("/{profile}/v1/chat/completions", post(chat_completions))
    .route("/{profile}/v1/responses", post(responses))
    .route("/{profile}/v1/messages", post(messages))
    .route("/{profile}/v1/providers", get(list_providers))
    .route("/{profile}/v1/models", get(list_models))
    .route("/healthz", get(health))
    .layer(middleware::from_fn_with_state(state.clone(), authenticate))
    .layer(middleware::from_fn(crate::request_id::propagate_request_id))
    .layer(SetRequestIdLayer::new(
      request_id_header,
      crate::request_id::MakeRouterRequestId,
    ))
    .layer(DefaultBodyLimit::max(max_wire_bytes))
    .with_state(state)
}

async fn health() -> &'static str {
  "ok"
}

async fn list_providers(
  State(state): State<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  uri: Uri,
  headers: HeaderMap,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
  let profiles = state.discovery_profiles(&uri, &headers)?;
  Ok(axum::Json(state.discovery.providers(&profiles, &access)))
}

async fn list_models(
  State(state): State<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  uri: Uri,
  headers: HeaderMap,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
  let profiles = state.discovery_profiles(&uri, &headers)?;
  state.discovery.models(&profiles, &access).await.map(axum::Json)
}

async fn authenticate(State(state): State<Arc<AppState>>, mut request: Request, next: Next) -> Response {
  if request.uri().path() == "/healthz" {
    request.extensions_mut().insert(AccessContext::unrestricted());
    return next.run(request).await;
  }

  if let Some(endpoint) = Endpoint::infer_from(request.uri().path()) {
    match state.select_profile(request.method(), request.uri(), request.headers(), endpoint) {
      Ok(runtime) if runtime.credential_policy == CredentialPolicy::Client => {
        request.extensions_mut().insert(AccessContext::unrestricted());
        return next.run(request).await;
      }
      Ok(_) | Err(_) => {}
    }
  }

  let context = match state.listener.client_auth() {
    ClientAuthPlan::None => Ok(AccessContext::unrestricted()),
    ClientAuthPlan::LocalKeys => {
      let token = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(char::is_whitespace))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .filter(|token| !token.is_empty())
        .or_else(|| request.headers().get("x-api-key").and_then(|value| value.to_str().ok()));
      state.access.authenticate(token)
    }
  };
  match context {
    Ok(context) => {
      if state.listener.client_auth() == ClientAuthPlan::LocalKeys {
        request.headers_mut().remove(axum::http::header::AUTHORIZATION);
        request.headers_mut().remove("x-api-key");
      }
      request.extensions_mut().insert(context);
      next.run(request).await
    }
    Err(error) => {
      let message = match error {
        tokn_access::AuthenticationError::Missing => "missing API key",
        tokn_access::AuthenticationError::Invalid | tokn_access::AuthenticationError::Revoked => "invalid API key",
      };
      ApiError::unauthorized(message).into_response()
    }
  }
}

fn collect_profile(action: &HttpAction, profiles: &mut BTreeSet<ProfileId>) {
  if let HttpAction::Route(profile_id) = action {
    profiles.insert(profile_id.clone());
  }
}

async fn chat_completions(
  State(state): State<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  connection: InboundConnectionInfo,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  handle(
    state,
    ApiRequestContext { access, connection },
    method,
    uri,
    headers,
    body,
    Endpoint::ChatCompletions,
  )
  .await
}

async fn responses(
  State(state): State<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  connection: InboundConnectionInfo,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  handle(
    state,
    ApiRequestContext { access, connection },
    method,
    uri,
    headers,
    body,
    Endpoint::Responses,
  )
  .await
}

async fn messages(
  State(state): State<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  connection: InboundConnectionInfo,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  handle(
    state,
    ApiRequestContext { access, connection },
    method,
    uri,
    headers,
    body,
    Endpoint::Messages,
  )
  .await
}

async fn handle(
  state: Arc<AppState>,
  context: ApiRequestContext,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
  endpoint: Endpoint,
) -> Result<Response, ApiError> {
  let runtime = state.select_profile(&method, &uri, &headers, endpoint)?;
  emit_inbound_connection(
    &state.events,
    &context.access,
    request_id(&headers)?,
    context.connection.local_addr.map(|addr| SmolStr::new(addr.to_string())),
    context.connection.peer_addr.map(|addr| SmolStr::new(addr.to_string())),
    runtime.record_mode,
    "requests",
    &method,
    None,
  );
  let (raw_body, decoded_body, body_json) = if runtime.route_kind == RouteKind::Managed {
    let mut decoded =
      crate::api::codec::decode_json_request_with_limit(&headers, body, state.request_limits.max_decoded_bytes())?;
    crate::api::endpoints::apply_endpoint_compat_defaults(endpoint, &headers, &mut decoded)?;
    (decoded.raw_body, decoded.decoded_body, decoded.value)
  } else {
    let decoded = decode_opaque_body_for_inspection(&headers, body.clone(), state.request_limits.max_decoded_bytes())?;
    (body, decoded, serde_json::Value::Null)
  };
  let request_id = headers
    .get(REQUEST_ID_HEADER)
    .and_then(|value| value.to_str().ok())
    .map(SmolStr::new);
  let raw = RawInbound {
    request_endpoint: endpoint.into(),
    headers: (&headers).into(),
    raw_body,
    decoded_body,
    body_json,
    request_id,
  };
  let mut config = RunConfig::builder().with_agent_id_opt(runtime.agent_id.clone());
  if let Some(destination) = &runtime.api_destination {
    let url = destination.operation_url(endpoint).map_err(|error| {
      ApiError::internal(format!(
        "resolve operation URL for provider '{}': {error}",
        destination.provider_id()
      ))
    })?;
    let (scheme, authority, path) = url_destination(&url);
    config = config
      .with_str(tokn_requests::stages::resolve::proxy::keys::HOST, authority)
      .with_str(
        tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID,
        destination.provider_id().to_string(),
      )
      .with_str(tokn_requests::stages::resolve::proxy::keys::PATH, path.clone())
      .with_str(tokn_requests::stages::send::proxy::send_keys::PATH, path)
      .with_str(tokn_requests::stages::send::proxy::send_keys::METHOD, method.as_str())
      .with_str(tokn_requests::stages::send::proxy::send_keys::SCHEME, scheme);
  }
  if let Some(providers) = context.access.providers.provider_ids() {
    config = config.with(
      tokn_requests::stages::ACCESS_ALLOWED_PROVIDERS_KEY,
      serde_json::Value::Array(providers.iter().cloned().map(serde_json::Value::String).collect()),
    );
  }
  let request = ExecutionRequest::new(raw)
    .with_config(config.build())
    .into_http(method, uri)
    .map_err(|error| ApiError::internal(format!("building v2 request service message: {error}")))?;
  runtime
    .api_service
    .as_ref()
    .ok_or_else(|| ApiError::internal("selected profile cannot run on an LLM API listener"))?
    .execute(request)
    .await
    .map(crate::api::response::converted_to_axum)
    .map_err(crate::api::endpoints::request_error_to_api_error)
}

fn request_id(headers: &HeaderMap) -> Result<SmolStr, ApiError> {
  headers
    .get(REQUEST_ID_HEADER)
    .and_then(|value| value.to_str().ok())
    .map(SmolStr::new)
    .ok_or_else(|| ApiError::internal("request id missing after transport admission"))
}

#[allow(clippy::too_many_arguments)]
fn emit_inbound_connection(
  events: &EventBus,
  access: &AccessContext,
  request_id: SmolStr,
  local_addr: Option<SmolStr>,
  peer_addr: Option<SmolStr>,
  mode: &str,
  pipeline_id: &str,
  inbound_method: &Method,
  url: Option<SmolStr>,
) {
  events.emit(CoreEvent::Requests(RequestEvent {
    request_id,
    attempt: 0,
    ts: tokn_core::util::now_unix_ms(),
    payload: RequestEventPayload::Record(RecordEvent::InboundConnection {
      user: access.key_name.clone().map(SmolStr::from),
      api_key_id: access.key_id.clone().map(SmolStr::from),
      local_addr,
      peer_addr,
      mode: SmolStr::new(mode),
      method: SmolStr::new(pipeline_id),
      inbound_method: SmolStr::new(inbound_method.as_str()),
      url,
    }),
  }));
}

fn request_record_mode(route: &RoutePlan) -> &'static str {
  match route {
    RoutePlan::Managed(route) => match route.target().model() {
      ModelSelector::Capability => "route",
      ModelSelector::Qualified { .. } => "exact",
      ModelSelector::Family(_) => "fuzzy",
    },
    RoutePlan::Relay(route) => match route.credentials() {
      RelayCredentials::Client => "passthrough",
      RelayCredentials::AccountPool(_) => "switch",
    },
  }
}

fn request_host(uri: &Uri, headers: &HeaderMap) -> Result<Option<tokn_policy::CanonicalHost>, ApiError> {
  let authority = uri.authority().map(|authority| authority.as_str()).or_else(|| {
    headers
      .get(axum::http::header::HOST)
      .and_then(|value| value.to_str().ok())
  });
  authority
    .map(|authority| {
      CanonicalAuthority::parse(authority)
        .map(|authority| authority.host().clone())
        .map_err(|error| ApiError::bad_request(format!("invalid request authority: {error}")))
    })
    .transpose()
}

fn http_matches(
  matcher: &HttpMatch,
  host: Option<&tokn_policy::CanonicalHost>,
  method: &Method,
  path: &str,
  operation: Option<&str>,
) -> bool {
  (matcher.hosts().is_empty() || host.is_some_and(|host| matcher.hosts().iter().any(|pattern| pattern.matches(host))))
    && (matcher.path_prefixes().is_empty()
      || matcher
        .path_prefixes()
        .iter()
        .any(|prefix| path.starts_with(prefix.as_str())))
    && (matcher.methods().is_empty()
      || matcher
        .methods()
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(method.as_str())))
    && (matcher.operations().is_empty()
      || operation.is_some_and(|operation| {
        matcher
          .operations()
          .iter()
          .any(|candidate| candidate.as_str() == operation)
      }))
}

fn operation_name(endpoint: Endpoint) -> &'static str {
  match endpoint {
    Endpoint::ChatCompletions => "chat_completions",
    Endpoint::Responses => "responses",
    Endpoint::Messages => "messages",
  }
}

fn wire_agent(identity: &WireIdentity) -> Option<AgentId> {
  match identity {
    WireIdentity::None | WireIdentity::ProviderDefault => None,
    WireIdentity::Named(identity) => Some(AgentId::from(identity.as_str())),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::{to_bytes, Body};
  use tokn_core::account::{AccountTier, AuthType, Secret};
  use tokn_core::request_event::StageEvent;
  use tokn_policy::{HostPattern, OperationId, WireIdentityId};
  use tower::ServiceExt;

  fn canonical_host(value: &str) -> tokn_policy::CanonicalHost {
    CanonicalAuthority::parse(value).unwrap().host().clone()
  }

  #[test]
  fn request_record_modes_preserve_legacy_route_labels() {
    let pool = tokn_policy::AccountPoolId::new("primary").unwrap();
    let managed = |model| {
      RoutePlan::Managed(tokn_policy::ManagedRoute::new(
        tokn_policy::ManagedTarget::new(pool.clone(), tokn_policy::ProviderSelector::Any, model),
        tokn_policy::OperationPolicy::TranslateCompatible,
        None,
        ManagedRetry::Never,
      ))
    };
    let relay = |credentials| {
      RoutePlan::Relay(tokn_policy::RelayRoute::new(
        RelayDestination::Original,
        credentials,
        None,
        RelayRetry::Never,
      ))
    };

    assert_eq!(request_record_mode(&managed(ModelSelector::Capability)), "route");
    assert_eq!(
      request_record_mode(&managed(ModelSelector::Qualified {
        namespace: tokn_policy::QualificationNamespace::Provider,
      })),
      "exact"
    );
    assert_eq!(
      request_record_mode(&managed(ModelSelector::Family(Box::new([])))),
      "fuzzy"
    );
    assert_eq!(request_record_mode(&relay(RelayCredentials::Client)), "passthrough");
    assert_eq!(
      request_record_mode(&relay(RelayCredentials::AccountPool(pool))),
      "switch"
    );
  }

  #[test]
  fn request_host_prefers_uri_authority_and_validates_host_header() {
    let uri = "https://api.example.com/v1/responses".parse::<Uri>().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::HOST, "ignored.example.com".parse().unwrap());
    assert_eq!(
      request_host(&uri, &headers).unwrap(),
      Some(canonical_host("api.example.com"))
    );

    let relative = "/v1/responses".parse::<Uri>().unwrap();
    assert_eq!(
      request_host(&relative, &headers).unwrap(),
      Some(canonical_host("ignored.example.com"))
    );
    headers.insert(axum::http::header::HOST, "bad host".parse().unwrap());
    assert!(request_host(&relative, &headers).is_err());
    assert_eq!(request_host(&relative, &HeaderMap::new()).unwrap(), None);
  }

  #[test]
  fn http_binding_match_combines_dimensions() {
    let matcher = HttpMatch::new(
      vec![HostPattern::exact(canonical_host("api.example.com"))].into_boxed_slice(),
      vec![SmolStr::new("/v1")].into_boxed_slice(),
      vec![SmolStr::new("POST")].into_boxed_slice(),
      vec![OperationId::new("responses").unwrap()].into_boxed_slice(),
    )
    .unwrap();
    let host = canonical_host("api.example.com");
    assert!(http_matches(
      &matcher,
      Some(&host),
      &Method::POST,
      "/v1/responses",
      Some("responses")
    ));
    assert!(!http_matches(
      &matcher,
      Some(&canonical_host("other.example.com")),
      &Method::POST,
      "/v1/responses",
      Some("responses")
    ));
    assert!(!http_matches(
      &matcher,
      Some(&host),
      &Method::GET,
      "/v1/responses",
      Some("responses")
    ));
    assert!(!http_matches(
      &matcher,
      Some(&host),
      &Method::POST,
      "/other",
      Some("responses")
    ));
    assert!(!http_matches(
      &matcher,
      Some(&host),
      &Method::POST,
      "/v1/responses",
      Some("messages")
    ));
    assert!(!http_matches(
      &matcher,
      Some(&host),
      &Method::POST,
      "/v1/responses",
      None
    ));
  }

  #[test]
  fn operation_names_and_wire_identity_match_runtime_contracts() {
    assert_eq!(operation_name(Endpoint::ChatCompletions), "chat_completions");
    assert_eq!(operation_name(Endpoint::Responses), "responses");
    assert_eq!(operation_name(Endpoint::Messages), "messages");
    assert_eq!(wire_agent(&WireIdentity::None), None);
    assert_eq!(wire_agent(&WireIdentity::ProviderDefault), None);
    assert_eq!(
      wire_agent(&WireIdentity::Named(WireIdentityId::new("codex_cli").unwrap())),
      Some(AgentId::from("codex_cli"))
    );

    let profile = ProfileId::new("default").unwrap();
    let mut profiles = BTreeSet::new();
    collect_profile(&HttpAction::Reject, &mut profiles);
    assert!(profiles.is_empty());
    collect_profile(&HttpAction::Route(profile.clone()), &mut profiles);
    assert_eq!(profiles, BTreeSet::from([profile]));
  }

  #[test]
  fn original_client_proxy_identity_resolves_codex_account_from_full_url_and_bearer() {
    let token = "codex-access-token-that-is-long-enough-to-fingerprint";
    let mut account = account_for_provider(tokn_core::provider::ID_CODEX);
    account.id = "codex-primary".into();
    account.api_key = None;
    account.access_token = Some(Secret::new(token.into()));
    let identity = AccountIdentityResolver::from_accounts(&[account]);
    let registry = Registry::builtin();
    let destination = reqwest::Url::parse("https://chatgpt.com/backend-api/codex/responses").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
      axum::http::header::AUTHORIZATION,
      format!("Bearer {token}").parse().unwrap(),
    );

    let config = with_original_proxy_identity(
      RunConfig::builder(),
      &headers,
      &destination,
      "chatgpt.com",
      &identity,
      &registry,
    )
    .build();

    assert_eq!(
      config.get_str(tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID),
      Some(tokn_core::provider::ID_CODEX)
    );
    assert_eq!(
      config.get_str(tokn_requests::stages::resolve::proxy::keys::ACCOUNT_ID),
      Some("codex-primary")
    );
  }

  #[test]
  fn original_client_proxy_identity_fingerprints_unknown_bearer_and_uses_bare_host_fallback() {
    let token = "unknown-client-token-that-is-long-enough-to-fingerprint";
    let identity = AccountIdentityResolver::default();
    let registry = Registry::builtin();
    let destination = reqwest::Url::parse("https://unregistered.example/v1/responses").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
      axum::http::header::AUTHORIZATION,
      format!("Bearer {token}").parse().unwrap(),
    );

    let config = with_original_proxy_identity(
      RunConfig::builder(),
      &headers,
      &destination,
      "unregistered.example",
      &identity,
      &registry,
    )
    .build();

    assert_eq!(
      config.get_str(tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID),
      Some("unregistered.example")
    );
    assert!(config
      .get_str(tokn_requests::stages::resolve::proxy::keys::ACCOUNT_ID)
      .is_some_and(|account_id| account_id.starts_with("account_fp_")));
  }

  #[tokio::test]
  async fn dry_run_listener_executes_v2_policy_without_sending_upstream() {
    let plan = tokn_config::v2::parse(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "managed" }

[profiles.managed]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "primary"
provider = { kind = "fixed", provider = "local" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.primary]
accounts = ["acct"]
providers = ["local"]

[providers.local]
driver = "openai"
base_url = "http://127.0.0.1:1/v1"
"#,
      std::path::Path::new("dry-run.toml"),
    )
    .unwrap();
    let account = AccountConfig {
      id: "acct".into(),
      provider: "local".into(),
      enabled: true,
      tier: AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: Some(AuthType::Bearer),
      username: None,
      api_key: Some(Secret::new("test-key".into())),
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
    };
    let events = Arc::new(EventBus::new(32));
    let mut receiver = events.subscribe();
    let mut states =
      build_dry_run_states(plan, &[account], Arc::new(tokn_access::AccessStore::disabled()), events).unwrap();
    let app = router(states.pop().unwrap());

    let response = app
      .oneshot(
        Request::post("/v1/responses")
          .header("content-type", "application/json")
          .body(Body::from(r#"{"model":"gpt-4o","input":"hello"}"#))
          .unwrap(),
      )
      .await
      .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);
    let mut converted = false;
    let mut sent = false;
    let mut stopped = false;
    while let Ok(event) = receiver.try_recv() {
      let tokn_core::event::Event::Requests(event) = &*event else {
        continue;
      };
      match &event.payload {
        tokn_core::request_event::RequestEventPayload::Stage(StageEvent::ConvertRequest(_)) => converted = true,
        tokn_core::request_event::RequestEventPayload::Stage(StageEvent::Send(_)) => sent = true,
        tokn_core::request_event::RequestEventPayload::Stage(StageEvent::Error { stop, .. }) => stopped = *stop,
        _ => {}
      }
    }
    assert!(converted);
    assert!(stopped);
    assert!(!sent);
  }

  #[tokio::test]
  async fn discovery_lists_listener_provider_and_falls_back_to_local_models() {
    let plan = tokn_config::v2::parse(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "managed" }

[profiles.managed]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "primary"
provider = { kind = "fixed", provider = "local" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.primary]
accounts = ["missing"]
providers = ["local"]

[providers.local]
driver = "openai"
base_url = "http://127.0.0.1:1/v1"
"#,
      std::path::Path::new("discovery.toml"),
    )
    .unwrap();
    let mut states = build_states(
      plan,
      &[account_for_provider("local")],
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
    )
    .unwrap();
    let state = states.pop().unwrap();
    let discovery_profiles = state
      .discovery_profiles(&"/v1/providers".parse().unwrap(), &HeaderMap::new())
      .unwrap();
    let restricted = AccessContext {
      key_id: Some("restricted".into()),
      key_name: Some("restricted".into()),
      providers: tokn_access::ProviderAccess::from_provider_ids(vec!["other".into()]).unwrap(),
    };
    assert!(state.discovery.providers(&discovery_profiles, &restricted)["data"]
      .as_array()
      .unwrap()
      .is_empty());
    let app = router(state);

    let response = app
      .clone()
      .oneshot(Request::get("/v1/providers").body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["route_mode"], "route");
    assert_eq!(body["data"][0]["id"], "local");
    assert_eq!(body["data"][0]["driver"], "openai");
    assert_eq!(body["data"][0]["accounts"], 1);

    let response = app
      .oneshot(Request::get("/v1/models").body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    let models = body["data"].as_array().unwrap();
    assert!(models.iter().any(|model| model["id"] == "gpt-4o"));
    assert!(models.iter().all(|model| model["x_tokn_router"]["provider"] == "local"));
  }

  #[tokio::test]
  async fn profile_compatibility_routes_use_the_bound_exact_policy() {
    let plan = tokn_config::v2::parse(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[[bindings]]
id = "work"
listener = "api"
action = { kind = "route", profile = "exact" }
path_prefixes = ["/work/v1/"]
methods = ["POST"]

[profiles.exact]
route = "exact"

[routes.exact]
kind = "managed"
account_pool = "primary"
provider = { kind = "fixed", provider = "local" }
model = { kind = "qualified", namespace = "provider" }
operation = "translate_compatible"

[account_pools.primary]
accounts = ["missing"]
providers = ["local"]

[providers.local]
driver = "openai"
base_url = "http://127.0.0.1:1/v1"
"#,
      std::path::Path::new("profile-discovery.toml"),
    )
    .unwrap();
    let mut states = build_dry_run_states(
      plan,
      &[account_for_provider("local")],
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
    )
    .unwrap();
    let app = router(states.pop().unwrap());

    let response = app
      .clone()
      .oneshot(Request::get("/work/v1/models").body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body: serde_json::Value =
      serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["route_mode"], "exact");
    assert!(body["data"]
      .as_array()
      .unwrap()
      .iter()
      .any(|model| model["id"] == "local/gpt-4o"));

    let response = app
      .oneshot(
        Request::post("/work/v1/responses")
          .header("content-type", "application/json")
          .body(Body::from(r#"{"model":"local/gpt-4o","input":"hello"}"#))
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);
  }

  #[tokio::test]
  async fn configured_wire_limit_rejects_large_llm_request() {
    let compiled = tokn_config::v2::parse_config(
      r#"
schema_version = 2

[service.request_limits]
max_wire_bytes = 4
max_decoded_bytes = 1024

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "managed" }

[profiles.managed]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "primary"
provider = { kind = "fixed", provider = "local" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.primary]
accounts = ["missing"]
providers = ["local"]

[providers.local]
driver = "openai"
base_url = "http://127.0.0.1:1/v1"
"#,
      std::path::Path::new("wire-limit.toml"),
    )
    .unwrap();
    let (plan, service) = compiled.into_parts();
    let account = account_for_provider("local");
    let mut states = build_states_with_service(
      plan,
      service,
      &[account],
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
    )
    .unwrap();

    let response = router(states.pop().unwrap())
      .oneshot(
        Request::post("/v1/responses")
          .header("content-type", "application/json")
          .body(Body::from(r#"{"model":"gpt-5"}"#))
          .unwrap(),
      )
      .await
      .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
  }

  #[tokio::test]
  async fn configured_decoded_limit_rejects_compressed_llm_request() {
    let compiled = tokn_config::v2::parse_config(
      r#"
schema_version = 2

[service.request_limits]
max_wire_bytes = 1024
max_decoded_bytes = 8

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "managed" }

[profiles.managed]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "primary"
provider = { kind = "fixed", provider = "local" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.primary]
accounts = ["missing"]
providers = ["local"]

[providers.local]
driver = "openai"
base_url = "http://127.0.0.1:1/v1"
"#,
      std::path::Path::new("decoded-limit.toml"),
    )
    .unwrap();
    let (plan, service) = compiled.into_parts();
    let account = account_for_provider("local");
    let mut states = build_states_with_service(
      plan,
      service,
      &[account],
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
    )
    .unwrap();
    let body = br#"{"model":"gpt-5","input":"compressible compressible"}"#;
    let encoded =
      crate::api::codec::encode_body_bytes(body, Some(crate::api::codec::ContentEncodingKind::Gzip)).unwrap();

    let response = router(states.pop().unwrap())
      .oneshot(
        Request::post("/v1/responses")
          .header("content-type", "application/json")
          .header("content-encoding", "gzip")
          .body(Body::from(encoded))
          .unwrap(),
      )
      .await
      .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
  }

  #[test]
  fn opaque_body_inspection_falls_back_to_wire_bytes_on_decode_errors() {
    let mut headers = HeaderMap::new();
    headers.insert("content-encoding", "gzip".parse().unwrap());
    let raw = Bytes::from_static(b"not gzip");

    assert_eq!(
      decode_opaque_body_for_inspection(&headers, raw.clone(), 1024).unwrap(),
      raw
    );
  }

  #[test]
  fn opaque_body_inspection_limit_does_not_reject_passthrough() {
    let mut headers = HeaderMap::new();
    headers.insert("content-encoding", "gzip".parse().unwrap());
    let body = b"more than four bytes";
    let encoded =
      crate::api::codec::encode_body_bytes(body, Some(crate::api::codec::ContentEncodingKind::Gzip)).unwrap();

    assert_eq!(
      decode_opaque_body_for_inspection(&headers, encoded.clone(), 4).unwrap(),
      encoded
    );
  }

  fn account_for_provider(provider: &str) -> AccountConfig {
    AccountConfig {
      id: "missing".into(),
      provider: provider.into(),
      enabled: true,
      tier: AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: Some(AuthType::Bearer),
      username: None,
      api_key: Some(Secret::new("test-key".into())),
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
}

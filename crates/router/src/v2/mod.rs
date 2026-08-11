mod selector;

use crate::api::error::ApiError;
use axum::body::Bytes;
use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use selector::{PoolAwareSend, V2AccountSelector};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokn_access::AccessContext;
use tokn_accounts::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph};
use tokn_accounts::registry::Registry;
use tokn_core::account::AccountConfig;
use tokn_core::event::EventBus;
use tokn_core::provider::Endpoint;
use tokn_core::AgentId;
use tokn_policy::{
  CanonicalAuthority, CanonicalHost, ClientAuthPlan, ConnectAction, ForwardProxyListenerPlan, GatewayPlan, HttpAction,
  HttpMatch, ListenerId, ListenerPlan, LlmApiListenerPlan, ManagedRetry, ProfileId, RelayRetry, RouteKind, RoutePlan,
  WireIdentity,
};
use tokn_requests::stages::{
  DefaultBuildHeaders, DefaultConvertRequest, DefaultConvertResponse, DefaultExtract, PassthroughBuildHeaders,
  PassthroughConvertRequest, PassthroughConvertResponse, PassthroughExtract, PoolResolve,
};
use tokn_requests::{ExecutionRequest, Pipeline, Profile, RawInbound, RequestService, RunConfig};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

const REQUEST_ID_HEADER: &str = "x-request-id";

#[derive(Clone)]
struct ProfileRuntime {
  service: tokn_service::HttpService,
  route_kind: RouteKind,
  agent_id: Option<AgentId>,
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
  access: Arc<tokn_access::AccessStore>,
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
      .find(|binding| http_matches(binding.matcher(), host.as_ref(), method, uri.path(), operation))
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
}

#[derive(Clone)]
pub struct ForwardProxyState {
  listener_id: ListenerId,
  listener: ForwardProxyListenerPlan,
  access: Arc<tokn_access::AccessStore>,
}

impl ForwardProxyState {
  pub fn listener_id(&self) -> &ListenerId {
    &self.listener_id
  }

  pub fn bind(&self) -> SocketAddr {
    self.listener.bind()
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    self.listener.client_auth()
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
}

pub fn build_forward_proxy_states(
  plan: &GatewayPlan,
  access: Arc<tokn_access::AccessStore>,
) -> anyhow::Result<Vec<ForwardProxyState>> {
  let mut states = Vec::new();
  for (listener_id, listener) in plan.listeners() {
    let ListenerPlan::ForwardProxy(listener) = listener else {
      continue;
    };
    let intercept = listener.default_connect_action() == ConnectAction::Intercept
      || listener
        .connect_rules()
        .iter()
        .any(|rule| rule.action() == ConnectAction::Intercept);
    if intercept {
      anyhow::bail!("v2 forward-proxy listener '{listener_id}' uses CONNECT interception, which is not supported yet");
    }
    states.push(ForwardProxyState {
      listener_id: listener_id.clone(),
      listener: listener.clone(),
      access: access.clone(),
    });
  }
  Ok(states)
}

pub async fn serve_forward_proxy<F>(state: ForwardProxyState, bind: SocketAddr, shutdown: F) -> anyhow::Result<()>
where
  F: Future<Output = ()> + Send,
{
  let policy_state = state.clone();
  let connect_policy: crate::proxy::ProxyConnectPolicy =
    Arc::new(move |host, port| policy_state.connect_action(host, port));
  let client_auth = match state.listener.client_auth() {
    ClientAuthPlan::None => None,
    ClientAuthPlan::LocalKeys => Some(state.access.clone()),
  };
  crate::proxy::serve_connect_policy(bind, Default::default(), connect_policy, client_auth, shutdown).await
}

/// Build one independent Axum state per configured v2 LLM API listener.
pub fn build_states(
  plan: GatewayPlan,
  accounts: &[AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
) -> anyhow::Result<Vec<AppState>> {
  let plan = Arc::new(plan);
  let mut reachable_profiles = BTreeSet::new();
  let mut has_llm_listener = false;
  for listener in plan.listeners().values() {
    let ListenerPlan::LlmApi(listener) = listener else {
      continue;
    };
    has_llm_listener = true;
    collect_profile(listener.default_http_action(), &mut reachable_profiles);
    for binding in listener.http_bindings() {
      collect_profile(binding.action(), &mut reachable_profiles);
    }
  }

  if !has_llm_listener {
    return Ok(Vec::new());
  }

  let registry = Registry::builtin();
  let providers = link_provider_graph(&plan, accounts, &registry)?;
  let pools = link_account_pools(&plan, &providers)?;
  let pools = build_account_pool_runtimes(&pools);
  let managed_http = tokn_core::util::http::build_managed_client(&Default::default())?;
  let opaque_http = tokn_core::util::http::build_opaque_client(&Default::default())?;

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
    let (selector, selection_state) = V2AccountSelector::new(plan.clone(), profile_plan.route().clone(), &pools)?;
    let resolve = Arc::new(PoolResolve::new(Arc::new(selector)));
    let send = Arc::new(PoolAwareSend::new(
      match route.kind() {
        RouteKind::Managed => managed_http.clone(),
        RouteKind::Relay => opaque_http.clone(),
        RouteKind::Transparent => {
          anyhow::bail!(
            "profile '{profile_id}' uses transparent route '{}' on an unsupported listener path",
            profile_plan.route()
          )
        }
      },
      selection_state,
    ));
    let profile = match route {
      RoutePlan::Managed(route) => {
        if route.header_patches().is_some() || !matches!(route.retry(), ManagedRetry::Never) {
          anyhow::bail!("profile '{profile_id}' uses unsupported managed patches or retry policy");
        }
        Profile::full(
          format!("v2-{profile_id}"),
          Arc::new(DefaultExtract),
          resolve,
          Arc::new(DefaultBuildHeaders::with_provider_defaults()),
          Arc::new(DefaultConvertRequest),
          send,
          Arc::new(DefaultConvertResponse::new()),
        )
      }
      RoutePlan::Relay(route) => {
        if route.header_patches().is_some() || !matches!(route.retry(), RelayRetry::Never) {
          anyhow::bail!("profile '{profile_id}' uses unsupported relay patches or retry policy");
        }
        Profile::full(
          format!("v2-{profile_id}"),
          Arc::new(PassthroughExtract),
          resolve,
          Arc::new(PassthroughBuildHeaders::router_auth()),
          Arc::new(PassthroughConvertRequest),
          send,
          Arc::new(PassthroughConvertResponse::new()),
        )
      }
      RoutePlan::Transparent(_) => unreachable!("transparent profiles were rejected above"),
    };
    let pipeline = Arc::new(Pipeline::new(Arc::new(profile), events.clone()));
    let runtime = ProfileRuntime {
      service: RequestService::http_from_pipeline(pipeline),
      route_kind: route.kind(),
      agent_id: wire_agent(profile_plan.wire_identity()),
    };
    profiles.insert(profile_id, runtime);
  }

  let profiles = Arc::new(profiles);
  let mut states = Vec::new();
  for (listener_id, listener) in plan.listeners() {
    match listener {
      ListenerPlan::LlmApi(listener) => states.push(AppState {
        listener_id: listener_id.clone(),
        listener: listener.clone(),
        profiles: profiles.clone(),
        access: access.clone(),
      }),
      ListenerPlan::ForwardProxy(_) => {}
    }
  }
  Ok(states)
}

pub fn router(state: AppState) -> Router {
  let state = Arc::new(state);
  let request_id_header = axum::http::HeaderName::from_static(REQUEST_ID_HEADER);
  Router::new()
    .route("/v1/chat/completions", post(chat_completions))
    .route("/v1/responses", post(responses))
    .route("/v1/messages", post(messages))
    .route("/healthz", get(health))
    .layer(middleware::from_fn_with_state(state.clone(), authenticate))
    .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
    .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
    .with_state(state)
}

async fn health() -> &'static str {
  "ok"
}

async fn authenticate(State(state): State<Arc<AppState>>, mut request: Request, next: Next) -> Response {
  if request.uri().path() == "/healthz" {
    request.extensions_mut().insert(AccessContext::unrestricted());
    return next.run(request).await;
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
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  handle(state, access, method, uri, headers, body, Endpoint::ChatCompletions).await
}

async fn responses(
  State(state): State<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  handle(state, access, method, uri, headers, body, Endpoint::Responses).await
}

async fn messages(
  State(state): State<Arc<AppState>>,
  Extension(access): Extension<AccessContext>,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Response, ApiError> {
  handle(state, access, method, uri, headers, body, Endpoint::Messages).await
}

async fn handle(
  state: Arc<AppState>,
  access: AccessContext,
  method: Method,
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
  endpoint: Endpoint,
) -> Result<Response, ApiError> {
  let runtime = state.select_profile(&method, &uri, &headers, endpoint)?;
  let (raw_body, decoded_body, body_json) = if runtime.route_kind == RouteKind::Managed {
    let mut decoded = crate::api::codec::decode_json_request(&headers, body)?;
    crate::api::endpoints::apply_endpoint_compat_defaults(endpoint, &headers, &mut decoded)?;
    (decoded.raw_body, decoded.decoded_body, decoded.value)
  } else {
    let encoding = crate::api::codec::request_content_encoding(&headers)?;
    let decoded = crate::api::codec::decode_body_bytes(body.clone(), encoding)?;
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
  if let Some(providers) = access.providers.provider_ids() {
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
    .service
    .execute(request)
    .await
    .map(crate::api::response::converted_to_axum)
    .map_err(crate::api::endpoints::request_error_to_api_error)
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
  operation: &str,
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
      || matcher
        .operations()
        .iter()
        .any(|candidate| candidate.as_str() == operation))
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
  use tokn_policy::{HostPattern, OperationId, WireIdentityId};

  fn canonical_host(value: &str) -> tokn_policy::CanonicalHost {
    CanonicalAuthority::parse(value).unwrap().host().clone()
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
      "responses"
    ));
    assert!(!http_matches(
      &matcher,
      Some(&canonical_host("other.example.com")),
      &Method::POST,
      "/v1/responses",
      "responses"
    ));
    assert!(!http_matches(
      &matcher,
      Some(&host),
      &Method::GET,
      "/v1/responses",
      "responses"
    ));
    assert!(!http_matches(
      &matcher,
      Some(&host),
      &Method::POST,
      "/other",
      "responses"
    ));
    assert!(!http_matches(
      &matcher,
      Some(&host),
      &Method::POST,
      "/v1/responses",
      "messages"
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
}

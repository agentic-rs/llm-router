//! Listener-family adapters for the v2 HTTP serving pipeline.
//!
//! These adapters retain transport facts that disappear once a request moves
//! into admission and execution. In particular, a local error must close a
//! framed HTTP/1 request because the body may not have been fully consumed.

use super::connect::{prepare_connect_upgrade, ConnectSession, ConnectUpgradeSender};
use super::events::{
  client_identity, connect_action, connect_policy_selection, downstream_response_head, error_termination,
  request_admitted_connect, request_admitted_http, request_started,
};
use super::response_body::observe_downstream_body;
use super::{
  admit_forward_proxy_request, admit_intercepted_https_request, admit_llm_api_request,
  authenticate_forward_proxy_client, authenticate_llm_api_client, handle_admitted_http, request_body_present,
  ConnectUpgradeUnavailableReason, ForwardProxyAdmission, ListenerServerState, ServerError,
};
use crate::runtime::dispatch_connect;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::header::{HeaderValue, CONNECTION, PROXY_AUTHORIZATION};
use http::{Method, Request, StatusCode, Version};
use tokn_events::{ConnectReady, IngressKind, RequestOutcome, RequestPhase, RequestSource, TrafficEventKind};
use tokn_policy::ListenerId;
use tokn_requests::{RequestCompletion, RequestLifecycle, RequestTermination};

/// Serve one request received by a direct LLM API listener.
///
/// Request version and body framing are captured before admission or
/// authentication can reject the request. Authentication consumes only the
/// listener credential on success; the admitted request then enters the
/// shared route/body/resolve/execute pipeline.
pub(super) async fn handle_llm_api_request(state: &ListenerServerState, mut request: Request<Body>) -> Response {
  let version = request.version();
  let body_present = request_body_present(&request);
  let started = request_started(listener_source(state, IngressKind::LlmApi), &request, body_present);
  let mut lifecycle = match begin_lifecycle(state, started).await {
    Ok(lifecycle) => lifecycle,
    Err(error) => return materialize_local_error(state.listener().id(), error, version, body_present),
  };

  let admitted = match admit_llm_api_request(&request) {
    Ok(admitted) => admitted,
    Err(error) => {
      return complete_http_result(state, lifecycle, Err(error.into()), version, body_present).await;
    }
  };
  if let Err(error) = publish_boundary(
    &mut lifecycle,
    TrafficEventKind::Admitted(request_admitted_http(&admitted)),
    RequestPhase::Admission,
  )
  .await
  {
    return complete_http_result(state, lifecycle, Err(error), version, body_present).await;
  }

  let access = match authenticate_llm_api_client(state.resource().client_auth(), request.headers_mut()).await {
    Ok(access) => access,
    Err(error) => {
      return complete_http_result(
        state,
        lifecycle,
        Err(ServerError::llm_auth(error)),
        version,
        body_present,
      )
      .await;
    }
  };
  if let Err(error) = publish_boundary(
    &mut lifecycle,
    TrafficEventKind::Authenticated(client_identity(&access)),
    RequestPhase::Authentication,
  )
  .await
  {
    return complete_http_result(state, lifecycle, Err(error), version, body_present).await;
  }

  let result = handle_admitted_http(state, admitted, &access, request, body_present, &mut lifecycle).await;
  complete_http_result(state, lifecycle, result, version, body_present).await
}

/// Serve one request received by a cleartext forward-proxy listener.
///
/// Ordinary absolute-form HTTP requests enter the shared HTTP pipeline after
/// proxy authentication. CONNECT requests reject every body representation,
/// authenticate, select policy, establish any tunnel transport, and transfer
/// the prepared upgrade to the owning connection before returning 200.
pub(super) async fn handle_forward_proxy_request(
  state: &ListenerServerState,
  mut request: Request<Body>,
  upgrades: &ConnectUpgradeSender,
) -> Response {
  let version = request.version();
  let body_present = request_body_present(&request);
  let is_connect = request.method() == Method::CONNECT;
  let close_http1 = body_present || is_connect;
  let started = request_started(
    listener_source(state, IngressKind::ForwardProxy),
    &request,
    body_present,
  );
  let mut lifecycle = match begin_lifecycle(state, started).await {
    Ok(lifecycle) => lifecycle,
    Err(error) => return materialize_local_error(state.listener().id(), error, version, close_http1),
  };
  let admitted = match admit_forward_proxy_request(&request) {
    Ok(admitted) => admitted,
    Err(error) => {
      return complete_http_result(state, lifecycle, Err(error.into()), version, close_http1).await;
    }
  };

  match admitted {
    ForwardProxyAdmission::Http(admitted) => {
      if let Err(error) = publish_boundary(
        &mut lifecycle,
        TrafficEventKind::Admitted(request_admitted_http(&admitted)),
        RequestPhase::Admission,
      )
      .await
      {
        return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
      }
      let access = match authenticate_forward_proxy_client(state.resource().client_auth(), request.headers_mut()).await
      {
        Ok(access) => access,
        Err(error) => {
          return complete_http_result(
            state,
            lifecycle,
            Err(ServerError::proxy_auth(error)),
            version,
            close_http1,
          )
          .await;
        }
      };
      if let Err(error) = publish_boundary(
        &mut lifecycle,
        TrafficEventKind::Authenticated(client_identity(&access)),
        RequestPhase::Authentication,
      )
      .await
      {
        return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
      }
      let result = handle_admitted_http(state, admitted, &access, request, body_present, &mut lifecycle).await;
      complete_http_result(state, lifecycle, result, version, close_http1).await
    }
    ForwardProxyAdmission::Connect(authority) => {
      if let Err(error) = publish_boundary(
        &mut lifecycle,
        TrafficEventKind::Admitted(request_admitted_connect(&authority)),
        RequestPhase::Admission,
      )
      .await
      {
        return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
      }
      if body_present {
        let error = ServerError::connect_body_unsupported(state.listener().id().clone());
        return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
      }

      let access = match authenticate_forward_proxy_client(state.resource().client_auth(), request.headers_mut()).await
      {
        Ok(access) => access,
        Err(error) => {
          return complete_http_result(
            state,
            lifecycle,
            Err(ServerError::proxy_auth(error)),
            version,
            close_http1,
          )
          .await;
        }
      };
      if let Err(error) = publish_boundary(
        &mut lifecycle,
        TrafficEventKind::Authenticated(client_identity(&access)),
        RequestPhase::Authentication,
      )
      .await
      {
        return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
      }

      let dispatch = match dispatch_connect(state.listener(), authority) {
        Ok(dispatch) => dispatch,
        Err(error) => {
          return complete_http_result(state, lifecycle, Err(error.into()), version, close_http1).await;
        }
      };
      if let Err(error) = publish_boundary(
        &mut lifecycle,
        TrafficEventKind::PolicySelected(connect_policy_selection(&dispatch)),
        RequestPhase::Policy,
      )
      .await
      {
        return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
      }
      let event_action = connect_action(dispatch.action());
      let event_authority = dispatch.authority().to_string();
      let request_id = lifecycle.request_id().clone();
      let mut upgrade = match prepare_connect_upgrade(state, dispatch, access, request_id, &mut request).await {
        Ok(upgrade) => upgrade,
        Err(error) => {
          return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
        }
      };
      let permit = match upgrades.clone().try_reserve_owned() {
        Ok(permit) => permit,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
          let site = upgrade.session().dispatch().site().clone();
          let error = ServerError::connect_upgrade_unavailable(site, ConnectUpgradeUnavailableReason::QueueFull);
          return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
          let site = upgrade.session().dispatch().site().clone();
          let error = ServerError::connect_upgrade_unavailable(site, ConnectUpgradeUnavailableReason::OwnerClosed);
          return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
        }
      };
      if let Err(error) = publish_boundary(
        &mut lifecycle,
        TrafficEventKind::ConnectReady(ConnectReady {
          action: event_action,
          authority: event_authority.into(),
        }),
        RequestPhase::Connect,
      )
      .await
      {
        return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
      }
      upgrade.attach_lifecycle(lifecycle);
      permit.send(upgrade);
      StatusCode::OK.into_response()
    }
  }
}

/// Serve one HTTPS request decoded inside an authenticated CONNECT session.
///
/// The original CONNECT authority remains the immutable ingress destination,
/// and the outer access context is reused for every inner keep-alive request.
/// Proxy credentials are first-hop metadata and can never reach a selected
/// origin or provider.
pub(super) async fn handle_intercepted_https_request(
  state: &ListenerServerState,
  session: &ConnectSession,
  mut request: Request<Body>,
) -> Response {
  let version = request.version();
  let body_present = request_body_present(&request);
  let is_connect = request.method() == Method::CONNECT;
  let close_http1 = body_present || is_connect;
  let started = request_started(
    listener_source(
      state,
      IngressKind::InterceptedHttps {
        parent_connect_id: session.request_id().clone(),
      },
    ),
    &request,
    body_present,
  );
  let mut lifecycle = match begin_lifecycle(state, started).await {
    Ok(lifecycle) => lifecycle,
    Err(error) => return materialize_local_error(state.listener().id(), error, version, close_http1),
  };
  request.headers_mut().remove(PROXY_AUTHORIZATION);
  let admitted = match admit_intercepted_https_request(&request, session.dispatch().authority()) {
    Ok(admitted) => admitted,
    Err(error) => {
      return complete_http_result(state, lifecycle, Err(error.into()), version, close_http1).await;
    }
  };
  if let Err(error) = publish_boundary(
    &mut lifecycle,
    TrafficEventKind::Admitted(request_admitted_http(&admitted)),
    RequestPhase::Admission,
  )
  .await
  {
    return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
  }
  if let Err(error) = publish_boundary(
    &mut lifecycle,
    TrafficEventKind::Authenticated(client_identity(session.access())),
    RequestPhase::Authentication,
  )
  .await
  {
    return complete_http_result(state, lifecycle, Err(error), version, close_http1).await;
  }
  let result = handle_admitted_http(state, admitted, session.access(), request, body_present, &mut lifecycle).await;
  complete_http_result(state, lifecycle, result, version, close_http1).await
}

fn listener_source(state: &ListenerServerState, ingress: IngressKind) -> RequestSource {
  RequestSource::Listener {
    listener_id: state.listener().id().as_str().into(),
    ingress,
    local_addr: None,
    peer_addr: None,
  }
}

async fn begin_lifecycle(
  state: &ListenerServerState,
  started: tokn_events::RequestStarted,
) -> Result<RequestLifecycle, ServerError> {
  state
    .gateway()
    .request_events()
    .begin(started)
    .await
    .map_err(|source| ServerError::event_publication(RequestPhase::Admission, source))
}

async fn publish_boundary(
  lifecycle: &mut RequestLifecycle,
  kind: TrafficEventKind,
  phase: RequestPhase,
) -> Result<(), ServerError> {
  lifecycle
    .publish_boundary(kind)
    .await
    .map(|_| ())
    .map_err(|source| ServerError::event_publication(phase, source))
}

async fn complete_http_result(
  state: &ListenerServerState,
  mut lifecycle: RequestLifecycle,
  result: Result<Response, ServerError>,
  version: Version,
  close_http1: bool,
) -> Response {
  let (response, termination) = match result {
    Ok(response) => {
      let status = response.status().as_u16();
      let termination = RequestTermination::new(RequestCompletion::new(
        RequestOutcome::Delivered,
        RequestPhase::Complete,
        Some(status),
        None,
      ));
      (response, termination)
    }
    Err(error) => {
      let phase = error.phase();
      let termination = error_termination(&error, phase);
      let response = materialize_local_error(state.listener().id(), error, version, close_http1);
      (response, termination)
    }
  };

  if let Err(source) = publish_boundary(
    &mut lifecycle,
    TrafficEventKind::DownstreamResponseHead(downstream_response_head(&response)),
    RequestPhase::DownstreamResponse,
  )
  .await
  {
    return materialize_local_error(state.listener().id(), source, version, close_http1);
  }
  observe_downstream_body(
    response,
    lifecycle,
    termination,
    state.gateway().defaults().request_body_limits().max_decoded_bytes(),
  )
}

/// Turn a classified local failure into its stable wire response.
///
/// The wire response uses only the safe classification. Internal logs retain
/// the rich error chain so operators can identify the exact policy location,
/// selected upstream, or transport failure without exposing it to clients.
pub(super) fn materialize_local_error(
  listener: &ListenerId,
  error: ServerError,
  version: Version,
  close_http1: bool,
) -> Response {
  let status = error.status();
  let error_code = error.code();
  if status.is_server_error() {
    tracing::error!(%listener, %status, error_code, error = %error, "local HTTP request failed");
  } else {
    tracing::warn!(%listener, %status, error_code, error = %error, "local HTTP request was rejected");
  }

  let mut response = error.into_response();
  if close_http1 && matches!(version, Version::HTTP_10 | Version::HTTP_11) {
    response
      .headers_mut()
      .insert(CONNECTION, HeaderValue::from_static("close"));
  }
  response
}

#[cfg(test)]
mod tests {
  use super::super::connect::connect_upgrade_channel;
  use super::*;
  use crate::runtime::{link_gateway_runtime, materialize_listeners, GatewayServerState, GatewayServingDefaults};
  use axum::body::to_bytes;
  use http::header::{CONTENT_LENGTH, HOST, PROXY_AUTHENTICATE, TRANSFER_ENCODING, WWW_AUTHENTICATE};
  use http::{Method, StatusCode};
  use smol_str::SmolStr;
  use std::collections::{BTreeMap, BTreeSet};
  use std::net::{Ipv4Addr, SocketAddr};
  use std::path::PathBuf;
  use std::sync::Arc;
  use tokio::io::AsyncReadExt;
  use tokio::net::TcpListener;
  use tokio::sync::mpsc::error::TryRecvError;
  use tokio::time::{timeout, Duration};
  use tokn_access::AccessContext;
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_core::util::http::HttpClientOptions;
  use tokn_events::{EventHub, GatewayEvent, HubBuilder};
  use tokn_persistence::RequestPersistenceConsumer;
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, ClientAuthPlan, ConnectAction,
    ForwardProxyListenerPlan, GatewayPlan, HttpAction, ListenerPlan, LlmApiListenerPlan, ManagedRetry, ManagedRoute,
    ManagedTarget, ModelGroupId, ModelSelector, ProfileId, ProfilePlan, ProviderId, RouteId, RoutePlan, UpstreamId,
    UpstreamPlan, UpstreamSelector, WireIdentity,
  };
  use tokn_requests::RequestLifecycleEmitter;

  fn listener_id() -> ListenerId {
    ListenerId::new("listener").unwrap()
  }

  fn local_error(version: Version, body_present: bool) -> Response {
    materialize_local_error(
      &listener_id(),
      ServerError::from(super::super::AdmissionError::MissingHost),
      version,
      body_present,
    )
  }

  fn listener_state(plan: ListenerPlan) -> (tempfile::TempDir, ListenerServerState) {
    let temp = tempfile::tempdir().unwrap();
    let listener = listener_id();
    let plan = GatewayPlan::new(
      BTreeMap::from([(listener.clone(), plan)]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let runtime = Arc::new(
      link_gateway_runtime(
        &plan,
        &[],
        &Registry::builtin(),
        &crate::runtime::RuntimeNameRegistry::builtin(),
      )
      .unwrap(),
    );
    let access_path = temp.path().join("access.db");
    let resources = materialize_listeners(runtime.listeners(), Some(&access_path)).unwrap();
    let resource = resources.listener(&listener).unwrap().clone();
    let gateway = Arc::new(
      GatewayServerState::build(
        runtime,
        &HttpClientOptions {
          system: false,
          ..HttpClientOptions::default()
        },
        GatewayServingDefaults::new(super::super::RequestBodyLimits::new(1024, 1024)),
      )
      .unwrap(),
    );
    (temp, ListenerServerState::new(gateway, resource))
  }

  fn authenticated_state() -> (tempfile::TempDir, ListenerServerState) {
    listener_state(ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
      ClientAuthPlan::LocalKeys,
      Box::default(),
      HttpAction::Reject,
    )))
  }

  fn proxy_state(client_auth: ClientAuthPlan, connect: ConnectAction) -> (tempfile::TempDir, ListenerServerState) {
    listener_state(ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 42_501)),
      client_auth,
      Box::default(),
      HttpAction::Reject,
      Box::default(),
      connect,
      None,
    )))
  }

  fn managed_event_state() -> (tempfile::TempDir, ListenerServerState, EventHub<GatewayEvent>, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let requests_dir = temp.path().join("requests");
    let persistence = RequestPersistenceConsumer::open(&requests_dir, "test-version").unwrap();
    let (publisher, hub) = HubBuilder::new().consumer(persistence).start().unwrap();

    let listener = listener_id();
    let profile = ProfileId::new("profile").unwrap();
    let route = RouteId::new("route").unwrap();
    let pool = AccountPoolId::new("pool").unwrap();
    let upstream = UpstreamId::new("upstream").unwrap();
    let plan = GatewayPlan::new(
      BTreeMap::from([(
        listener.clone(),
        ListenerPlan::LlmApi(LlmApiListenerPlan::new(
          SocketAddr::from((Ipv4Addr::LOCALHOST, 42_502)),
          ClientAuthPlan::None,
          Box::default(),
          HttpAction::Route(profile.clone()),
        )),
      )]),
      BTreeMap::from([(profile, ProfilePlan::new(route.clone(), WireIdentity::None))]),
      BTreeMap::from([(
        route,
        RoutePlan::Managed(ManagedRoute::new(
          ManagedTarget::new(
            pool.clone(),
            UpstreamSelector::Fixed(upstream.clone()),
            ModelSelector::Capability,
          ),
          tokn_policy::OperationPolicy::TranslateCompatible,
          None,
          ManagedRetry::Never,
        )),
      )]),
      BTreeMap::from([(
        pool,
        AccountPoolPlan::new(
          AccountSelector::all(),
          AccountSelectionStrategy::RoundRobin,
          Duration::from_secs(30),
          None,
        ),
      )]),
      BTreeMap::from([(
        upstream,
        UpstreamPlan::new(
          ProviderId::new(ID_LLAMA_CPP).unwrap(),
          Some("https://upstream.example/v1/".into()),
          Box::default(),
          false,
        )
        .with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("fixture")]))),
      )]),
      BTreeMap::<ModelGroupId, _>::new(),
    );
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.tier = AccountTier::Active;
    let runtime = Arc::new(
      link_gateway_runtime(
        &plan,
        &[account],
        &Registry::builtin(),
        &crate::runtime::RuntimeNameRegistry::builtin(),
      )
      .unwrap(),
    );
    let resources = materialize_listeners(runtime.listeners(), None).unwrap();
    let resource = resources.listener(&listener).unwrap().clone();
    let gateway = Arc::new(
      GatewayServerState::build_with_events(
        runtime,
        &HttpClientOptions {
          system: false,
          ..HttpClientOptions::default()
        },
        GatewayServingDefaults::new(super::super::RequestBodyLimits::new(1024, 1024)),
        RequestLifecycleEmitter::new(publisher),
      )
      .unwrap(),
    );
    (temp, ListenerServerState::new(gateway, resource), hub, requests_dir)
  }

  fn connect_request(target: SocketAddr) -> http::request::Builder {
    Request::builder()
      .method(Method::CONNECT)
      .uri(target.to_string())
      .version(Version::HTTP_11)
  }

  fn connect_request_with_upgrade_token(target: SocketAddr) -> Request<Body> {
    let mut request = connect_request(target).body(Body::empty()).unwrap();
    let mut request_without_upgrade = Request::new(());
    request
      .extensions_mut()
      .insert(hyper::upgrade::on(&mut request_without_upgrade));
    request
  }

  #[test]
  fn framed_http1_errors_close_the_connection() {
    for version in [Version::HTTP_10, Version::HTTP_11] {
      let response = local_error(version, true);
      assert_eq!(response.headers()[CONNECTION], "close");
    }
  }

  #[test]
  fn unframed_http1_errors_leave_connection_policy_to_the_server() {
    let response = local_error(Version::HTTP_11, false);
    assert!(!response.headers().contains_key(CONNECTION));
  }

  #[test]
  fn framed_http2_errors_do_not_emit_a_connection_header() {
    let response = local_error(Version::HTTP_2, true);
    assert!(!response.headers().contains_key(CONNECTION));
  }

  #[tokio::test]
  async fn direct_auth_rejection_challenges_and_closes_framed_http1() {
    let (_temp, state) = authenticated_state();
    let request = Request::builder()
      .method(Method::POST)
      .uri("/v1/responses")
      .version(Version::HTTP_11)
      .header(HOST, "client.example")
      .header(CONTENT_LENGTH, "1")
      .body(Body::from("x"))
      .unwrap();

    let response = handle_llm_api_request(&state, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[WWW_AUTHENTICATE], "Bearer");
    assert_eq!(response.headers()[CONNECTION], "close");
  }

  #[tokio::test]
  async fn invalid_managed_json_is_persisted_from_started_through_terminal_response() {
    let (_temp, state, hub, requests_dir) = managed_event_state();
    let request = Request::builder()
      .method(Method::POST)
      .uri("/v1/responses")
      .version(Version::HTTP_11)
      .header(HOST, "client.example")
      .header(CONTENT_LENGTH, "1")
      .body(Body::from("{"))
      .unwrap();

    let response = handle_llm_api_request(&state, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[CONNECTION], "close");
    let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(std::str::from_utf8(&response_body)
      .unwrap()
      .contains("invalid_request_body"));
    hub.shutdown().await.unwrap();

    let day_files = tokn_persistence::requests::day_files(&requests_dir).unwrap();
    assert_eq!(day_files.len(), 1);
    let connection = tokn_persistence::requests::open_day_db(&day_files[0]).unwrap();
    let row = connection
      .query_row(
        "SELECT status, request_error, inbound_req_method, inbound_req_url,
                inbound_req_body, account_id, provider_id, model
         FROM requests",
        [],
        |row| {
          Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
          ))
        },
      )
      .unwrap();
    assert_eq!(row.0, 400);
    assert_eq!(row.1, "request_body: the managed request body is not valid JSON");
    assert_eq!(row.2, "POST");
    assert_eq!(row.3, "/v1/responses");
    assert_eq!(row.4, b"{");
    assert_eq!((&row.5, &row.6, &row.7), (&None, &None, &None));
  }

  #[tokio::test]
  async fn forward_http_uses_proxy_auth_and_the_shared_error_close_policy() {
    let (_temp, state) = proxy_state(ClientAuthPlan::LocalKeys, ConnectAction::Reject);
    let (upgrades, mut receiver) = connect_upgrade_channel();
    let request = Request::builder()
      .method(Method::GET)
      .uri("http://origin.example/v1/models")
      .version(Version::HTTP_11)
      .header(CONTENT_LENGTH, "0")
      .body(Body::empty())
      .unwrap();

    let response = handle_forward_proxy_request(&state, request, &upgrades).await;

    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert_eq!(response.headers()[PROXY_AUTHENTICATE], "Bearer");
    assert_eq!(response.headers()[CONNECTION], "close");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
  }

  #[tokio::test]
  async fn connect_rejects_every_body_representation_before_auth_or_dial() {
    let (_temp, state) = proxy_state(ClientAuthPlan::LocalKeys, ConnectAction::Tunnel);
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));

    let requests = [
      connect_request(target)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap(),
      connect_request(target)
        .header(CONTENT_LENGTH, "1")
        .body(Body::from("x"))
        .unwrap(),
      connect_request(target)
        .header(TRANSFER_ENCODING, "chunked")
        .body(Body::empty())
        .unwrap(),
      connect_request(target).body(Body::from("x")).unwrap(),
    ];

    for request in requests {
      let (upgrades, mut receiver) = connect_upgrade_channel();
      let response = handle_forward_proxy_request(&state, request, &upgrades).await;

      assert_eq!(response.status(), StatusCode::BAD_REQUEST);
      assert_eq!(response.headers()[CONNECTION], "close");
      assert!(!response.headers().contains_key(PROXY_AUTHENTICATE));
      assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }
  }

  #[tokio::test]
  async fn rejected_connect_and_missing_proxy_auth_never_schedule_an_upgrade() {
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));

    let (_temp, rejected_state) = proxy_state(ClientAuthPlan::None, ConnectAction::Reject);
    let (upgrades, mut receiver) = connect_upgrade_channel();
    let response = handle_forward_proxy_request(
      &rejected_state,
      connect_request(target).body(Body::empty()).unwrap(),
      &upgrades,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[CONNECTION], "close");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

    let (_temp, authenticated_state) = proxy_state(ClientAuthPlan::LocalKeys, ConnectAction::Tunnel);
    let (upgrades, mut receiver) = connect_upgrade_channel();
    let response = handle_forward_proxy_request(
      &authenticated_state,
      connect_request(target).body(Body::empty()).unwrap(),
      &upgrades,
    )
    .await;
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert_eq!(response.headers()[PROXY_AUTHENTICATE], "Bearer");
    assert_eq!(response.headers()[CONNECTION], "close");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
  }

  #[tokio::test]
  async fn missing_hyper_upgrade_token_fails_before_tunnel_dial() {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = upstream_listener.local_addr().unwrap();
    let (_temp, state) = proxy_state(ClientAuthPlan::None, ConnectAction::Tunnel);
    let (upgrades, mut receiver) = connect_upgrade_channel();

    let response =
      handle_forward_proxy_request(&state, connect_request(target).body(Body::empty()).unwrap(), &upgrades).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers()[CONNECTION], "close");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    let upstream_listener = upstream_listener.into_std().unwrap();
    assert_eq!(
      upstream_listener.accept().unwrap_err().kind(),
      std::io::ErrorKind::WouldBlock
    );
  }

  #[tokio::test]
  async fn tunnel_is_open_and_owned_before_connect_returns_ok() {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = upstream_listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { upstream_listener.accept().await.unwrap().0 });
    let (_temp, state) = proxy_state(ClientAuthPlan::None, ConnectAction::Tunnel);
    let (upgrades, mut receiver) = connect_upgrade_channel();

    let response = handle_forward_proxy_request(&state, connect_request_with_upgrade_token(target), &upgrades).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(CONNECTION));
    let mut upstream = timeout(Duration::from_secs(1), accept).await.unwrap().unwrap();
    let upgrade = receiver.try_recv().unwrap();
    assert_eq!(upgrade.session().access(), &AccessContext::unrestricted());
    assert_eq!(
      upgrade.session().dispatch().authority().authority().to_string(),
      target.to_string()
    );
    assert_eq!(upgrade.session().dispatch().site().listener_id(), &listener_id());
    assert!(upgrade.session().dispatch().site().rule_id().is_none());

    drop(upgrade);
    let mut byte = [0u8; 1];
    assert_eq!(
      timeout(Duration::from_secs(1), upstream.read(&mut byte))
        .await
        .unwrap()
        .unwrap(),
      0
    );
  }

  #[tokio::test]
  async fn tunnel_failure_and_closed_upgrade_owner_fail_before_ok() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let unavailable = reservation.local_addr().unwrap();
    drop(reservation);
    let (_temp, state) = proxy_state(ClientAuthPlan::None, ConnectAction::Tunnel);
    let (upgrades, mut receiver) = connect_upgrade_channel();

    let response =
      handle_forward_proxy_request(&state, connect_request_with_upgrade_token(unavailable), &upgrades).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.headers()[CONNECTION], "close");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = upstream_listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { upstream_listener.accept().await.unwrap().0 });
    let (upgrades, receiver) = connect_upgrade_channel();
    drop(receiver);

    let response = handle_forward_proxy_request(&state, connect_request_with_upgrade_token(target), &upgrades).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers()[CONNECTION], "close");
    let mut upstream = timeout(Duration::from_secs(1), accept).await.unwrap().unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(
      timeout(Duration::from_secs(1), upstream.read(&mut byte))
        .await
        .unwrap()
        .unwrap(),
      0
    );
  }
}

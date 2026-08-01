//! Listener-family adapters for the v2 HTTP serving pipeline.
//!
//! These adapters retain transport facts that disappear once a request moves
//! into admission and execution. In particular, a local error must close a
//! framed HTTP/1 request because the body may not have been fully consumed.

use super::connect::{prepare_connect_upgrade, ConnectUpgradeSender};
use super::{
  admit_forward_proxy_request, admit_llm_api_request, authenticate_forward_proxy_client, authenticate_llm_api_client,
  handle_admitted_http, request_body_present, ConnectUpgradeUnavailableReason, ForwardProxyAdmission,
  ListenerServerState, ServerError,
};
use crate::runtime::dispatch_connect;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::header::{HeaderValue, CONNECTION};
use http::{Method, Request, StatusCode, Version};
use tokn_policy::ListenerId;

/// Serve one request received by a direct LLM API listener.
///
/// Request version and body framing are captured before admission or
/// authentication can reject the request. Authentication consumes only the
/// listener credential on success; the admitted request then enters the
/// shared route/body/resolve/execute pipeline.
pub(super) async fn handle_llm_api_request(state: &ListenerServerState, mut request: Request<Body>) -> Response {
  let version = request.version();
  let body_present = request_body_present(&request);

  let result: Result<Response, ServerError> = async {
    let admitted = admit_llm_api_request(&request)?;
    let access = authenticate_llm_api_client(state.resource().client_auth(), request.headers_mut())
      .await
      .map_err(ServerError::llm_auth)?;
    handle_admitted_http(state, admitted, &access, request, body_present).await
  }
  .await;

  match result {
    Ok(response) => response,
    Err(error) => materialize_local_error(state.listener().id(), error, version, body_present),
  }
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

  let result: Result<Response, ServerError> = async {
    let admitted = admit_forward_proxy_request(&request)?;
    match admitted {
      ForwardProxyAdmission::Http(admitted) => {
        let access = authenticate_forward_proxy_client(state.resource().client_auth(), request.headers_mut())
          .await
          .map_err(ServerError::proxy_auth)?;
        handle_admitted_http(state, admitted, &access, request, body_present).await
      }
      ForwardProxyAdmission::Connect(authority) => {
        if body_present {
          return Err(ServerError::connect_body_unsupported(state.listener().id().clone()));
        }

        let access = authenticate_forward_proxy_client(state.resource().client_auth(), request.headers_mut())
          .await
          .map_err(ServerError::proxy_auth)?;
        let dispatch = dispatch_connect(state.listener(), authority)?;
        let upgrade = prepare_connect_upgrade(state, dispatch, access, &mut request).await?;
        let site = upgrade.session().dispatch().site().clone();
        upgrades.try_send(upgrade).map_err(|error| match error {
          tokio::sync::mpsc::error::TrySendError::Full(_) => {
            ServerError::connect_upgrade_unavailable(site, ConnectUpgradeUnavailableReason::QueueFull)
          }
          tokio::sync::mpsc::error::TrySendError::Closed(_) => {
            ServerError::connect_upgrade_unavailable(site, ConnectUpgradeUnavailableReason::OwnerClosed)
          }
        })?;
        Ok(StatusCode::OK.into_response())
      }
    }
  }
  .await;

  match result {
    Ok(response) => response,
    Err(error) => materialize_local_error(state.listener().id(), error, version, body_present || is_connect),
  }
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
  use http::header::{CONTENT_LENGTH, HOST, PROXY_AUTHENTICATE, TRANSFER_ENCODING, WWW_AUTHENTICATE};
  use http::{Method, StatusCode};
  use std::collections::BTreeMap;
  use std::net::{Ipv4Addr, SocketAddr};
  use std::sync::Arc;
  use tokio::io::AsyncReadExt;
  use tokio::net::TcpListener;
  use tokio::sync::mpsc::error::TryRecvError;
  use tokio::time::{timeout, Duration};
  use tokn_access::AccessContext;
  use tokn_accounts::registry::Registry;
  use tokn_core::util::http::HttpClientOptions;
  use tokn_policy::{
    ClientAuthPlan, ConnectAction, ForwardProxyListenerPlan, GatewayPlan, HttpAction, ListenerPlan, LlmApiListenerPlan,
  };

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
    let upstream = timeout(Duration::from_secs(1), accept).await.unwrap().unwrap();
    let upgrade = receiver.try_recv().unwrap();
    assert_eq!(upgrade.session().access(), &AccessContext::unrestricted());
    assert_eq!(
      upgrade.session().dispatch().authority().authority().to_string(),
      target.to_string()
    );
    assert_eq!(upgrade.session().dispatch().site().listener_id(), &listener_id());
    assert!(upgrade.session().dispatch().site().rule_id().is_none());

    let run_error = upgrade.run().await.unwrap_err();
    assert_eq!(run_error.site().listener_id(), &listener_id());
    drop(upstream);
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

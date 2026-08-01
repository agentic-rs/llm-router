//! Listener-family adapters for the v2 HTTP serving pipeline.
//!
//! These adapters retain transport facts that disappear once a request moves
//! into admission and execution. In particular, a local error must close a
//! framed HTTP/1 request because the body may not have been fully consumed.

use super::{
  admit_llm_api_request, authenticate_llm_api_client, handle_admitted_http, request_body_present, ListenerServerState,
  ServerError,
};
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::header::{HeaderValue, CONNECTION};
use http::{Request, Version};
use tokn_policy::ListenerId;

/// Serve one request received by a direct LLM API listener.
///
/// Request version and body framing are captured before admission or
/// authentication can reject the request. Authentication consumes only the
/// listener credential on success; the admitted request then enters the
/// shared route/body/resolve/execute pipeline.
pub async fn handle_llm_api_request(state: &ListenerServerState, mut request: Request<Body>) -> Response {
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

/// Turn a classified local failure into its stable wire response.
///
/// The wire response uses only the safe classification. Internal logs retain
/// the rich error chain so operators can identify the exact policy location,
/// selected upstream, or transport failure without exposing it to clients.
pub(super) fn materialize_local_error(
  listener: &ListenerId,
  error: ServerError,
  version: Version,
  body_present: bool,
) -> Response {
  let status = error.status();
  let error_code = error.code();
  if status.is_server_error() {
    tracing::error!(%listener, %status, error_code, error = %error, "local HTTP request failed");
  } else {
    tracing::warn!(%listener, %status, error_code, error = %error, "local HTTP request was rejected");
  }

  let mut response = error.into_response();
  if body_present && matches!(version, Version::HTTP_10 | Version::HTTP_11) {
    response
      .headers_mut()
      .insert(CONNECTION, HeaderValue::from_static("close"));
  }
  response
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{link_gateway_runtime, materialize_listeners, GatewayServerState, GatewayServingDefaults};
  use http::header::{CONTENT_LENGTH, HOST, WWW_AUTHENTICATE};
  use http::{Method, StatusCode};
  use std::collections::BTreeMap;
  use std::net::{Ipv4Addr, SocketAddr};
  use std::sync::Arc;
  use tokn_accounts::registry::Registry;
  use tokn_core::util::http::HttpClientOptions;
  use tokn_policy::{ClientAuthPlan, GatewayPlan, HttpAction, ListenerPlan, LlmApiListenerPlan};

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

  fn authenticated_state() -> (tempfile::TempDir, ListenerServerState) {
    let temp = tempfile::tempdir().unwrap();
    let listener = listener_id();
    let plan = GatewayPlan::new(
      BTreeMap::from([(
        listener.clone(),
        ListenerPlan::LlmApi(LlmApiListenerPlan::new(
          SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
          ClientAuthPlan::LocalKeys,
          Box::default(),
          HttpAction::Reject,
        )),
      )]),
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
        &HttpClientOptions::default(),
        GatewayServingDefaults::new(super::super::RequestBodyLimits::new(1024, 1024)),
      )
      .unwrap(),
    );
    (temp, ListenerServerState::new(gateway, resource))
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
}

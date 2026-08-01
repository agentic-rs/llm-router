//! Shared HTTP serving pipeline after listener-specific admission and client
//! authentication.
//!
//! The listener adapter supplies immutable request-target facts and the
//! authenticated access context. This pipeline then fixes the listener route
//! before polling the body, admits that body according to the route family,
//! resolves one target, executes one attempt, and bridges the response.

use super::events::policy_selection;
use super::{
  buffer_matched_body, managed_response_to_axum, opaque_response_to_axum, AdmittedHttpRequest, BufferedRequestBody,
  ListenerServerState, ServerError,
};
use crate::runtime::{
  match_http, HttpExecutionOutcome, HttpExecutionRequest, HttpRequestSemantics, HttpRouteMatch,
  ObservedHttpExecutionOutcome,
};
use axum::body::Body;
use axum::response::Response;
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderMap, Request};
use hyper::body::Body as HttpBody;
use smol_str::SmolStr;
use tokn_access::AccessContext;
use tokn_events::{RequestPhase, TrafficEventKind};
use tokn_requests::RequestLifecycle;

/// Retain whether the inbound request carried a body representation before
/// its body is moved or polled.
///
/// Framing headers are intentionally authoritative even for an empty body, so
/// `Content-Length: 0` remains distinguishable from an absent representation.
pub fn request_body_present(request: &Request<Body>) -> bool {
  request.headers().contains_key(CONTENT_LENGTH)
    || request.headers().contains_key(TRANSFER_ENCODING)
    || !request.body().is_end_stream()
}

/// Serve one already-admitted, authenticated non-CONNECT HTTP request.
///
/// `body_present` must be captured with [`request_body_present`] before the
/// listener adapter consumes any request state. This function deliberately
/// does not decide HTTP/1 connection reuse; an adapter may conservatively
/// close a framed request on any returned local error.
pub async fn handle_admitted_http(
  state: &ListenerServerState,
  admitted: AdmittedHttpRequest,
  access: &AccessContext,
  request: Request<Body>,
  body_present: bool,
  lifecycle: &mut RequestLifecycle,
) -> Result<Response, ServerError> {
  let (head, request_kind) = admitted.into_parts();
  let route_match = match_http(state.listener(), head, request_kind);
  let selection = policy_selection(&route_match);
  lifecycle
    .publish_boundary(TrafficEventKind::PolicySelected(selection))
    .await
    .map_err(|source| ServerError::event_publication(RequestPhase::Policy, source))?;
  let matched = match route_match {
    HttpRouteMatch::Reject(site) => return Err(ServerError::route_rejected(site)),
    HttpRouteMatch::Route(matched) => matched,
  };

  let (parts, body) = request.into_parts();
  let headers = parts.headers;
  let (observation, buffered) = buffer_matched_body(
    &matched,
    &headers,
    body,
    body_present,
    state.gateway().defaults().request_body_limits(),
  )
  .await
  .into_parts();
  lifecycle
    .publish_boundary(TrafficEventKind::RequestBody(observation))
    .await
    .map_err(|source| ServerError::event_publication(RequestPhase::RequestBody, source))?;
  let buffered = buffered?;
  let session_id = inbound_session_id(&headers);

  let (semantics, execution_request) = match buffered {
    BufferedRequestBody::Managed(body) => {
      let (value, requested_model) = body.into_parts();
      (
        HttpRequestSemantics::Managed { requested_model },
        HttpExecutionRequest::managed(headers, value),
      )
    }
    BufferedRequestBody::Opaque { wire_body } => (
      HttpRequestSemantics::Opaque,
      HttpExecutionRequest::opaque(headers, wire_body),
    ),
  };
  let routed = matched.resolve(semantics, session_id.as_deref(), &access.providers)?;
  if !lifecycle.is_enabled() {
    let outcome = state
      .gateway()
      .http_execution()
      .execute(routed, execution_request)
      .await?;
    return match outcome {
      HttpExecutionOutcome::Managed { response, .. } => managed_response_to_axum(response).map_err(ServerError::from),
      HttpExecutionOutcome::Opaque { response, .. } => opaque_response_to_axum(response).map_err(ServerError::from),
      HttpExecutionOutcome::CoolingDown { site, retry_at } => Err(ServerError::cooling_down(site, retry_at)),
      HttpExecutionOutcome::NoEligible { site, reason } => Err(ServerError::no_eligible(site, reason)),
    };
  }
  let outcome = state
    .gateway()
    .http_execution()
    .execute_observed(
      routed,
      execution_request,
      lifecycle,
      state.gateway().defaults().request_body_limits().max_decoded_bytes(),
    )
    .await?;
  match outcome {
    ObservedHttpExecutionOutcome::Managed { response, attempt, .. } => {
      bridge_attempt(managed_response_to_axum(response), attempt, lifecycle).await
    }
    ObservedHttpExecutionOutcome::Opaque { response, attempt, .. } => {
      bridge_attempt(opaque_response_to_axum(response), attempt, lifecycle).await
    }
    ObservedHttpExecutionOutcome::CoolingDown { site, retry_at } => Err(ServerError::cooling_down(site, retry_at)),
    ObservedHttpExecutionOutcome::NoEligible { site, reason } => Err(ServerError::no_eligible(site, reason)),
  }
}

async fn bridge_attempt(
  response: Result<Response, super::ResponseBridgeError>,
  attempt: Option<crate::runtime::attempts::AttemptBodyPlan>,
  lifecycle: &mut RequestLifecycle,
) -> Result<Response, ServerError> {
  match response {
    Ok(response) => Ok(attach_attempt(response, attempt)),
    Err(error) => {
      if let Some(attempt) = attempt {
        attempt
          .publish_terminal(lifecycle)
          .await
          .map_err(|source| ServerError::event_publication(RequestPhase::UpstreamResponse, source))?;
      }
      Err(error.into())
    }
  }
}

fn attach_attempt(mut response: Response, attempt: Option<crate::runtime::attempts::AttemptBodyPlan>) -> Response {
  if let Some(attempt) = attempt {
    response.extensions_mut().insert(attempt);
  }
  response
}

/// Project native headers only for best-effort correlation lookup. Execution
/// retains and consumes the original byte-preserving map.
fn inbound_session_id(headers: &HeaderMap) -> Option<SmolStr> {
  let semantic_headers = tokn_headers::HeaderMap::from(headers);
  tokn_headers::inbound::inbound_correlation(&semantic_headers).session_id
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{
    admit_llm_api_request, link_gateway_runtime, materialize_listeners, GatewayServerState, GatewayServingDefaults,
    RequestBodyLimits, RuntimeNameRegistry,
  };
  use bytes::Bytes;
  use http::header::{HeaderValue, HOST};
  use http::Method;
  use hyper::body::{Frame, SizeHint};
  use std::collections::BTreeMap;
  use std::convert::Infallible;
  use std::net::{Ipv4Addr, SocketAddr};
  use std::pin::Pin;
  use std::sync::Arc;
  use std::task::{Context, Poll};
  use tokn_access::AccessContext;
  use tokn_accounts::registry::Registry;
  use tokn_core::util::http::HttpClientOptions;
  use tokn_events::{CapturedHeaders, CapturedUri, Correlation, IngressKind, RequestSource, RequestStarted};
  use tokn_policy::{ClientAuthPlan, GatewayPlan, HttpAction, ListenerId, ListenerPlan, LlmApiListenerPlan};
  use tokn_requests::RequestLifecycleEmitter;

  fn listener_id() -> ListenerId {
    ListenerId::new("listener").unwrap()
  }

  fn reject_state() -> ListenerServerState {
    let listener = listener_id();
    let plan = GatewayPlan::new(
      BTreeMap::from([(
        listener.clone(),
        ListenerPlan::LlmApi(LlmApiListenerPlan::new(
          SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
          ClientAuthPlan::None,
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
    let runtime =
      Arc::new(link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap());
    let resources = materialize_listeners(runtime.listeners(), None).unwrap();
    let resource = resources.listener(&listener).unwrap().clone();
    let gateway = Arc::new(
      GatewayServerState::build(
        runtime,
        &HttpClientOptions::default(),
        GatewayServingDefaults::new(RequestBodyLimits::new(1024, 1024)),
      )
      .unwrap(),
    );
    ListenerServerState::new(gateway, resource)
  }

  #[derive(Debug)]
  struct PanicOnPollBody;

  impl HttpBody for PanicOnPollBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
      self: Pin<&mut Self>,
      _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
      panic!("rejected request body must not be polled")
    }

    fn is_end_stream(&self) -> bool {
      false
    }

    fn size_hint(&self) -> SizeHint {
      SizeHint::default()
    }
  }

  #[test]
  fn body_presence_distinguishes_absence_from_explicit_empty_framing() {
    let absent = Request::new(Body::empty());
    assert!(!request_body_present(&absent));

    let explicit_empty = Request::builder()
      .header(CONTENT_LENGTH, "0")
      .body(Body::empty())
      .unwrap();
    assert!(request_body_present(&explicit_empty));

    let streamed = Request::new(Body::new(PanicOnPollBody));
    assert!(request_body_present(&streamed));
  }

  #[test]
  fn semantic_correlation_ignores_unrepresentable_headers_without_mutating_native_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("x-session-id", HeaderValue::from_static("session-42"));
    headers.insert("x-opaque", HeaderValue::from_bytes(b"\x80native").unwrap());
    let original = headers.clone();

    assert_eq!(inbound_session_id(&headers).as_deref(), Some("session-42"));
    assert_eq!(headers, original);
    assert_eq!(headers["x-opaque"].as_bytes(), b"\x80native");
  }

  #[tokio::test]
  async fn listener_rejection_happens_before_body_polling() {
    let state = reject_state();
    let request = Request::builder()
      .method(Method::POST)
      .uri("/v1/responses")
      .header(HOST, "client.example")
      .body(Body::new(PanicOnPollBody))
      .unwrap();
    let admitted = admit_llm_api_request(&request).unwrap();
    let started = RequestStarted {
      source: RequestSource::Listener {
        listener_id: "listener".into(),
        ingress: IngressKind::LlmApi,
        local_addr: None,
        peer_addr: None,
      },
      http_version: Some("HTTP/1.1".into()),
      method: "POST".into(),
      target: CapturedUri::exact("/v1/responses"),
      headers: CapturedHeaders::default(),
      body_present: true,
      correlation: Correlation::default(),
    };
    let mut lifecycle = RequestLifecycleEmitter::disabled().begin(started).await.unwrap();

    let result = handle_admitted_http(
      &state,
      admitted,
      &AccessContext::unrestricted(),
      request,
      true,
      &mut lifecycle,
    )
    .await;

    let Err(ServerError::RouteRejected { site }) = result else {
      panic!("expected explicit route rejection")
    };
    assert_eq!(site.listener_id(), &listener_id());
  }
}

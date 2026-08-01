use crate::{BodyCapture, CapturedHeaders, CapturedUri, RequestId, TokenUsage};
use smol_str::SmolStr;
use std::net::SocketAddr;

/// Public gateway event domain.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GatewayEvent {
  Traffic(TrafficEvent),
}

/// One ordered observation for an inbound or embedded request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficEvent {
  pub request_id: RequestId,
  /// Zero for the current single-attempt runtime. Future retries increment it.
  pub attempt: u32,
  /// Monotonic sequence within this request attempt.
  pub sequence: u32,
  pub at_unix_ms: i64,
  /// Monotonic elapsed time since [`TrafficEventKind::Started`].
  pub elapsed_ms: u64,
  pub kind: TrafficEventKind,
}

/// Stable traffic boundaries independent of the internal pipeline layout.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrafficEventKind {
  Started(RequestStarted),
  Admitted(RequestAdmitted),
  Authenticated(ClientIdentity),
  PolicySelected(PolicySelection),
  RequestBody(RequestBodyObservation),
  TargetSelected(TargetSelection),
  UpstreamRequest(HttpRequestSnapshot),
  UpstreamResponseHead(HttpResponseHead),
  BodyProgress(BodyProgress),
  BodyFinished(BodyFinished),
  DownstreamResponseHead(HttpResponseHead),
  Usage(TokenUsage),
  ConnectReady(ConnectReady),
  ConnectClosed(ConnectClosed),
  Finished(RequestFinished),
}

/// Where a request entered the shared gateway execution model.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestSource {
  Listener {
    listener_id: SmolStr,
    ingress: IngressKind,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
  },
  Embedded {
    profile_id: SmolStr,
  },
}

/// Listener transport that produced a request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IngressKind {
  LlmApi,
  ForwardProxy,
  InterceptedHttps { parent_connect_id: RequestId },
}

/// Correlation facts retained independently from the gateway-generated id.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Correlation {
  pub client_request_id: Option<SmolStr>,
  pub session_id: Option<SmolStr>,
  pub thread_id: Option<SmolStr>,
  pub parent_thread_id: Option<SmolStr>,
  pub parent_session_id: Option<SmolStr>,
  pub project_id: Option<SmolStr>,
  pub turn_id: Option<SmolStr>,
}

/// Raw request facts captured before admission, authentication, or body parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestStarted {
  pub source: RequestSource,
  pub http_version: Option<SmolStr>,
  pub method: SmolStr,
  pub target: CapturedUri,
  pub headers: CapturedHeaders,
  pub body_present: bool,
  pub correlation: Correlation,
}

/// Request-target facts established by listener admission.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestAdmitted {
  Http {
    scheme: SmolStr,
    authority: SmolStr,
    path_and_query: CapturedUri,
    operation: Option<SmolStr>,
  },
  Connect {
    authority: SmolStr,
  },
}

/// Non-secret authenticated client identity.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientIdentity {
  Anonymous,
  LocalKey { key_id: SmolStr, key_name: Option<SmolStr> },
  Embedded,
}

/// Compiled listener or embedded action selected before request body parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySelection {
  pub binding_id: Option<SmolStr>,
  pub action: SelectedAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SelectedAction {
  Reject,
  Http {
    profile_id: SmolStr,
    route_id: SmolStr,
    family: HttpFamily,
  },
  Connect {
    action: ConnectAction,
  },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpFamily {
  Managed,
  Relay,
  Transparent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnectAction {
  Intercept,
  Tunnel,
  Reject,
}

/// Wire and semantic body facts, including failures before target selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestBodyObservation {
  pub wire: BodyCapture,
  pub decoded: Option<BodyCapture>,
  pub requested_model: Option<SmolStr>,
  pub stream: Option<bool>,
  pub initiator: Option<SmolStr>,
  pub outcome: BodyOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BodyOutcome {
  Accepted,
  Rejected(EventFailure),
}

/// Request-time target facts detached from provider and account handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetSelection {
  pub family: HttpFamily,
  pub account_id: Option<SmolStr>,
  pub provider_id: Option<SmolStr>,
  pub upstream_id: Option<SmolStr>,
  pub requested_model: Option<SmolStr>,
  pub upstream_model: Option<SmolStr>,
  pub requested_operation: Option<SmolStr>,
  pub upstream_operation: Option<SmolStr>,
}

/// One fully prepared HTTP request at a transport boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequestSnapshot {
  pub method: SmolStr,
  pub uri: CapturedUri,
  pub headers: CapturedHeaders,
  pub body: BodyCapture,
}

/// Response metadata observed before polling its body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponseHead {
  pub status: u16,
  pub headers: CapturedHeaders,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BodyLeg {
  Upstream,
  Downstream,
}

/// Monotonic body-transfer update used by library observers and CLI progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyProgress {
  pub leg: BodyLeg,
  pub bytes_seen: u64,
  pub chunks: u64,
}

/// Final bounded body observation for one side of the gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyFinished {
  pub leg: BodyLeg,
  pub capture: BodyCapture,
  pub result: BodyResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BodyResult {
  Complete,
  Failed(EventFailure),
  Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectReady {
  pub action: ConnectAction,
  pub authority: SmolStr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectClosed {
  pub action: ConnectAction,
  pub client_to_upstream_bytes: Option<u64>,
  pub upstream_to_client_bytes: Option<u64>,
  pub result: BodyResult,
}

/// Safe, stable failure classification exposed to every consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventFailure {
  pub code: SmolStr,
  pub message: SmolStr,
}

/// Lifecycle location for terminal progress and failure reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestPhase {
  Admission,
  Authentication,
  Policy,
  RequestBody,
  TargetSelection,
  UpstreamRequest,
  UpstreamResponse,
  DownstreamResponse,
  Connect,
  Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestOutcome {
  Delivered,
  Rejected,
  Failed,
  Cancelled,
}

/// Exactly one terminal event for every started request or CONNECT exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFinished {
  pub outcome: RequestOutcome,
  pub phase: RequestPhase,
  pub downstream_status: Option<u16>,
  pub failure: Option<EventFailure>,
  pub attempts: u32,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::CaptureOmission;

  #[test]
  fn body_parse_failure_requires_no_invented_routing_facts() {
    let request_id = RequestId::new("gateway-request");
    let body_failure = EventFailure {
      code: SmolStr::new("invalid_json"),
      message: SmolStr::new("request body is not valid JSON"),
    };
    let body_event = TrafficEvent {
      request_id: request_id.clone(),
      attempt: 0,
      sequence: 2,
      at_unix_ms: 10,
      elapsed_ms: 1,
      kind: TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Complete(bytes::Bytes::from_static(b"{")),
        decoded: Some(BodyCapture::Complete(bytes::Bytes::from_static(b"{"))),
        requested_model: None,
        stream: None,
        initiator: None,
        outcome: BodyOutcome::Rejected(body_failure.clone()),
      }),
    };
    let finished = TrafficEvent {
      request_id,
      attempt: 0,
      sequence: 3,
      at_unix_ms: 10,
      elapsed_ms: 1,
      kind: TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Rejected,
        phase: RequestPhase::RequestBody,
        downstream_status: Some(400),
        failure: Some(body_failure),
        attempts: 0,
      }),
    };

    let TrafficEventKind::RequestBody(observed) = body_event.kind else {
      panic!("expected body event")
    };
    assert_eq!(observed.requested_model, None);
    assert!(matches!(observed.outcome, BodyOutcome::Rejected(_)));
    assert!(matches!(finished.kind, TrafficEventKind::Finished(_)));
  }

  #[test]
  fn omitted_body_still_reports_transport_progress() {
    let capture = BodyCapture::Omitted {
      reason: CaptureOmission::Disabled,
      bytes_seen: 8192,
    };

    assert_eq!(capture.bytes(), None);
    assert_eq!(capture.bytes_seen(), 8192);
  }
}

use crate::{BodyCapture, CapturedHeaders, CapturedUri, RequestId, TokenUsage};
use smol_str::SmolStr;
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;

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
  /// Monotonic sequence across the complete logical request, starting at one.
  pub sequence: u64,
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
  AttemptStarted(AttemptStarted),
  AttemptRequest(AttemptHttpRequest),
  AttemptResponseHead(AttemptHttpResponseHead),
  BodyProgress(BodyProgress),
  BodyFinished(BodyFinished),
  DownstreamResponseHead(HttpResponseHead),
  AttemptUsage(AttemptUsage),
  AttemptFinished(AttemptFinished),
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
///
/// Producers emit this boundary once after body admission, whether admission
/// succeeds or fails. `decoded` is present only for bytes that represent the
/// final decoded payload; an intermediate compression layer must not be
/// reported as the decoded request body.
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

/// One-based identifier for an upstream attempt within a logical request.
///
/// Request-wide observations deliberately carry no attempt value. This makes
/// an early admission or parsing failure unambiguously a request with zero
/// attempts rather than a synthetic "attempt zero".
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttemptNo(NonZeroU32);

impl AttemptNo {
  pub const FIRST: Self = Self(NonZeroU32::MIN);

  pub const fn new(value: u32) -> Option<Self> {
    match NonZeroU32::new(value) {
      Some(value) => Some(Self(value)),
      None => None,
    }
  }

  pub const fn get(self) -> u32 {
    self.0.get()
  }
}

impl fmt::Display for AttemptNo {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.get().fmt(formatter)
  }
}

/// Opens one selected upstream attempt immediately before execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptStarted {
  pub attempt: AttemptNo,
  pub target: TargetSelection,
}

/// Wire-truth request for one selected upstream attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptHttpRequest {
  pub attempt: AttemptNo,
  pub request: HttpRequestSnapshot,
}

/// Response metadata observed for one selected upstream attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptHttpResponseHead {
  pub attempt: AttemptNo,
  pub response: HttpResponseHead,
}

/// Provider-reported usage attributed to one selected upstream attempt.
///
/// Multiple observations may carry sparse updates. Consumers can combine them
/// with [`TokenUsage::merge_from`] without erasing earlier fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptUsage {
  pub attempt: AttemptNo,
  pub usage: TokenUsage,
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
///
/// This is wire truth. Matching status values later carried by terminal
/// summaries are fallbacks for paths where no response head was observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponseHead {
  pub status: u16,
  pub headers: CapturedHeaders,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BodyLeg {
  Upstream { attempt: AttemptNo },
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

/// How one opened upstream attempt ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttemptOutcome {
  /// An upstream response was accepted, whether or not policy schedules a
  /// subsequent retry from its status or contents.
  Response,
  Failed,
  Cancelled,
}

/// Explicit policy decision to retry after an attempt closes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryDecision {
  pub delay_ms: Option<u64>,
  pub reason: EventFailure,
}

/// Exactly one closing observation for every [`AttemptStarted`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptFinished {
  pub attempt: AttemptNo,
  pub outcome: AttemptOutcome,
  pub phase: RequestPhase,
  pub upstream_status: Option<u16>,
  pub failure: Option<EventFailure>,
  pub retry: Option<RetryDecision>,
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
  /// Number of [`AttemptStarted`] observations in this logical request.
  pub attempt_count: u32,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::CaptureOmission;

  #[test]
  fn body_parse_failure_requires_no_invented_routing_facts() {
    let request_id = RequestId::new("gateway-request").unwrap();
    let body_failure = EventFailure {
      code: SmolStr::new("invalid_json"),
      message: SmolStr::new("request body is not valid JSON"),
    };
    let body_event = TrafficEvent {
      request_id: request_id.clone(),
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
      sequence: 3,
      at_unix_ms: 10,
      elapsed_ms: 1,
      kind: TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Rejected,
        phase: RequestPhase::RequestBody,
        downstream_status: Some(400),
        failure: Some(body_failure),
        attempt_count: 0,
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

  #[test]
  fn attempt_numbers_are_one_based_and_request_sequence_does_not_reset() {
    assert_eq!(AttemptNo::new(0), None);
    assert_eq!(AttemptNo::FIRST.get(), 1);
    assert_eq!(AttemptNo::new(2).unwrap().get(), 2);

    let retry = RetryDecision {
      delay_ms: Some(250),
      reason: EventFailure {
        code: SmolStr::new("rate_limited"),
        message: SmolStr::new("the selected upstream requested a retry"),
      },
    };
    let finished = AttemptFinished {
      attempt: AttemptNo::FIRST,
      outcome: AttemptOutcome::Response,
      phase: RequestPhase::UpstreamResponse,
      upstream_status: Some(429),
      failure: None,
      retry: Some(retry),
    };

    assert_eq!(finished.attempt.get(), 1);
    assert_eq!(finished.retry.unwrap().delay_ms, Some(250));
  }
}

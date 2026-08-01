//! Public, pipeline-independent gateway lifecycle events.
//!
//! These contracts describe facts observed at stable traffic boundaries. They
//! deliberately do not expose router state, provider handles, database rows,
//! or internal pipeline stages. A CLI and an embedded library consumer receive
//! the same owned event values.
//!
//! # Lifecycle contract
//!
//! Every logical request starts with `TrafficEventKind::Started` at request
//! sequence 1 and closes with exactly one `TrafficEventKind::Finished`.
//! Request-wide admission, authentication, policy, and body failures therefore
//! remain observable even when no upstream attempt is opened. HTTP attempts
//! are one-based and contiguous; a later attempt is valid only after the
//! previous `AttemptFinished` carries an explicit retry decision. CONNECT uses
//! `ConnectReady`/`ConnectClosed` instead of synthetic HTTP attempts.
//!
//! `TrafficEvent.sequence` orders one request. `EventSeq` orders delivery across
//! all requests accepted by an event hub. Reliable boundaries use the awaited
//! publisher path; high-volume body progress may be coalesced, while terminal
//! delivery remains reliable. Body capture policy belongs to the producer and
//! is reported explicitly in `BodyCapture`; a persistence consumer may apply a
//! narrower storage policy without reducing what other consumers receive.

mod capture;
mod id;
mod runtime;
mod traffic;
mod usage;

pub use capture::{
  is_sensitive_header_name, BodyCapture, CaptureOmission, CapturedHeader, CapturedHeaderValue, CapturedHeaders,
  CapturedUri,
};
pub use id::{RequestId, RequestIdError, REQUEST_ID_MAX_BYTES};
pub use runtime::{
  ConsumerFailureKind, ConsumerOperation, ConsumerResult, DeliveryStats, EventConsumer, EventHub, EventSeq, FlushError,
  ForcedShutdown, HubBuildError, HubBuilder, HubFailure, HubStatus, PublishError, Publisher, ShutdownError,
  TerminalBatch, TerminalContext, TerminalGuard, TerminalRegistrationError, TerminalSubmitError, TryPublishError,
  WaitFailedError,
};
pub use traffic::{
  AttemptFinished, AttemptHttpRequest, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted,
  AttemptUsage, BodyFinished, BodyLeg, BodyOutcome, BodyProgress, BodyResult, ClientIdentity, ConnectAction,
  ConnectClosed, ConnectReady, Correlation, EventFailure, GatewayEvent, HttpFamily, HttpRequestSnapshot,
  HttpResponseHead, IngressKind, PolicySelection, RequestAdmitted, RequestBodyObservation, RequestFinished,
  RequestOutcome, RequestPhase, RequestSource, RequestStarted, RetryDecision, SelectedAction, TargetSelection,
  TrafficEvent, TrafficEventKind,
};
pub use usage::{TokenUsage, UsageKind};

//! Public, pipeline-independent gateway lifecycle events.
//!
//! These contracts describe facts observed at stable traffic boundaries. They
//! deliberately do not expose router state, provider handles, database rows,
//! or internal pipeline stages. A CLI and an embedded library consumer receive
//! the same owned event values.

mod capture;
mod id;
mod traffic;
mod usage;

pub use capture::{BodyCapture, CaptureOmission, CapturedHeader, CapturedHeaderValue, CapturedHeaders, CapturedUri};
pub use id::RequestId;
pub use traffic::{
  BodyFinished, BodyLeg, BodyOutcome, BodyProgress, BodyResult, ClientIdentity, ConnectAction, ConnectClosed,
  ConnectReady, Correlation, EventFailure, GatewayEvent, HttpFamily, HttpRequestSnapshot, HttpResponseHead,
  IngressKind, PolicySelection, RequestAdmitted, RequestBodyObservation, RequestFinished, RequestOutcome, RequestPhase,
  RequestSource, RequestStarted, SelectedAction, TargetSelection, TrafficEvent, TrafficEventKind,
};
pub use usage::{TokenUsage, UsageKind};

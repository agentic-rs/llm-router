//! Pipeline error type. Stages are responsible for constructing this with the
//! correct [`Stage`] tag and `recoverable` flag; the runner emits a matching
//! [`StageEvent::Error`] verbatim from these fields.
//!
//! The `stop` flag distinguishes a *requested* short-circuit (a stage chose
//! to halt the pipeline without producing a response — e.g. a dry-run Send
//! stub) from a *real* failure. The runner treats both identically (emits
//! `Error` + `Completed { success = false }` and short-circuits), but
//! callers can branch on `err.stop` to render a successful dry-run report
//! instead of a failure report. State accumulated up to the stop point is
//! available to subscribers on the [`EventBus`] — each per-stage event
//! carries that stage's own output.
//!
//! [`StageEvent::Error`]: crate::event::StageEvent::Error
//! [`EventBus`]: crate::event::EventBus

use crate::event::Stage;
use crate::utils::codec::CodecError;
use smol_str::SmolStr;
use snafu::Snafu;
use tokn_convert::error::ConvertError;
use tokn_core::provider::Endpoint;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum RequestsError {
  #[snafu(display("{source}"))]
  Resolve {
    source: tokn_accounts::routing::ResolveError,
  },

  #[snafu(display("session expired: {session_id}"))]
  SessionExpired { session_id: SmolStr },

  #[snafu(display("no account supports endpoint {endpoint} for model {model}"))]
  NoAccount { endpoint: Endpoint, model: SmolStr },

  #[snafu(display("no account configured for provider {provider_id}"))]
  NoProviderAccount { provider_id: SmolStr },

  #[snafu(display("API key does not allow the requested provider"))]
  ProviderAccessDenied,

  #[snafu(display("invalid API-key provider policy"))]
  InvalidAccessPolicy,

  #[snafu(display("invalid routed request: {message}"))]
  InvalidRouteRequest { message: SmolStr },

  #[snafu(display("invalid `{key}` endpoint `{value}`"))]
  InvalidConfiguredEndpoint { key: &'static str, value: SmolStr },

  #[snafu(display("missing resolved endpoint for request endpoint `{request_endpoint}`"))]
  MissingResolvedEndpoint { request_endpoint: SmolStr },

  #[snafu(display("missing upstream endpoint for request endpoint `{request_endpoint}`"))]
  MissingUpstreamEndpoint { request_endpoint: SmolStr },

  #[snafu(display("request conversion failed: {source}"))]
  RequestConversion { source: ConvertError },

  #[snafu(display("invalid generation options: {source}"))]
  InvalidGenerationOptions {
    source: tokn_core::generation::GenerationOptionsError,
  },

  #[snafu(display(
    "generation control `{control}` is not supported by provider `{provider_id}` on {endpoint}: {reason}"
  ))]
  UnsupportedGenerationControl {
    control: &'static str,
    provider_id: SmolStr,
    endpoint: Endpoint,
    reason: &'static str,
  },

  #[snafu(display("provider input_transformer failed: {source}"))]
  ProviderInputTransformer { source: tokn_core::provider::Error },

  #[snafu(display("serialize upstream body: {source}"))]
  SerializeUpstreamBody { source: serde_json::Error },

  #[snafu(display("re-encode outbound body: {source}"))]
  ReencodeOutboundBody { source: CodecError },

  #[snafu(display("upstream body not valid JSON: {source}"))]
  UpstreamBodyNotJson { source: serde_json::Error },

  #[snafu(display("response conversion failed: {source}"))]
  ResponseConversion { source: ConvertError },

  #[snafu(display("serializing translated response failed: {source}"))]
  SerializeTranslatedResponse { source: serde_json::Error },

  #[snafu(display("upstream {status}: failed to read body: {source}"))]
  UpstreamReadFailed { status: u16, source: reqwest::Error },

  #[snafu(display("upstream {status}: {body}"))]
  UpstreamStatus { status: u16, body: String },

  #[snafu(display("reading upstream body: {source}"))]
  ReadingUpstreamBody { source: reqwest::Error },

  #[snafu(display("{source}"))]
  Provider { source: ProviderError },

  #[snafu(display("dry-run profile stopped before contacting upstream"))]
  Stop,

  #[snafu(display("{source}"))]
  Other { source: BoxError },
}

/// Chain-formatted wrapper for [`tokn_core::provider::Error`]. Reqwest's
/// top-level `Display` hides the underlying transport cause (DNS failure,
/// TLS error, connection refused, etc.); this wrapper walks the full
/// `std::error::Error::source()` chain so the root cause is visible.
#[derive(Debug)]
pub struct ProviderError(tokn_core::provider::Error);

impl ProviderError {
  pub fn new(err: tokn_core::provider::Error) -> Self {
    Self(err)
  }

  pub fn inner(&self) -> &tokn_core::provider::Error {
    &self.0
  }
}

impl std::fmt::Display for ProviderError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut src: &dyn std::error::Error = &self.0;
    write!(f, "{}", src)?;
    while let Some(cause) = src.source() {
      write!(f, ": {cause}")?;
      src = cause;
    }
    Ok(())
  }
}

impl std::error::Error for ProviderError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.0)
  }
}

#[derive(Debug)]
pub struct PipelineError {
  pub stage: Stage,
  inner: RequestsError,
  /// `true` iff a retry-style decorators may sensibly re-invoke the stage.
  /// Permanent failures (bad request, 4xx, unknown model) set this to
  /// `false`. Always `false` when `stop == true`.
  pub recoverable: bool,
  /// `true` iff a stage deliberately halted the pipeline rather than
  /// failing. Used by dry-run Send stubs and other "stop here" stages.
  /// Callers should treat this as a successful early termination.
  pub stop: bool,
}

impl PipelineError {
  pub fn permanent(stage: Stage, inner: RequestsError) -> Self {
    Self {
      stage,
      inner,
      recoverable: false,
      stop: false,
    }
  }

  pub fn recoverable(stage: Stage, inner: RequestsError) -> Self {
    Self {
      stage,
      inner,
      recoverable: true,
      stop: false,
    }
  }

  /// A deliberate short-circuit: the stage chose to halt the pipeline
  /// without producing a response. Not a failure; callers should render
  /// whatever partial state they captured (typically via the event bus).
  pub fn stop(stage: Stage) -> Self {
    Self {
      stage,
      inner: RequestsError::Stop,
      recoverable: false,
      stop: true,
    }
  }

  pub fn inner(&self) -> &RequestsError {
    &self.inner
  }

  pub fn message(&self) -> std::borrow::Cow<'_, str> {
    std::borrow::Cow::Owned(self.inner.to_string())
  }
}

impl std::fmt::Display for PipelineError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "[{}] {}", self.stage, self.inner)
  }
}

impl std::error::Error for PipelineError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.inner)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[derive(Debug, Snafu)]
  #[snafu(display("boom"))]
  struct Boom;

  #[test]
  fn displays_stage_and_source_message() {
    let err = PipelineError::permanent(Stage::Resolve, RequestsError::Other { source: Box::new(Boom) });
    assert_eq!(err.to_string(), "[resolve] boom");
    assert!(matches!(err.inner(), RequestsError::Other { .. }));
  }
}

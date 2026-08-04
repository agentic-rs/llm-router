//! Transitional request-service boundary shared by pipeline and layered runtimes.
//!
//! Router and SDK callers depend on [`RequestService`] instead of the
//! concrete six-stage pipeline. The current [`PipelineRunner`]
//! implementation is adapted behind the service, while a later
//! [`tower::Layer`] stack can be supplied without changing those callers.
//! The current [`RawInbound`] request and [`ConvertedResponse`] response are
//! compatibility types, not the final low-level SDK contract.
//!
//! [`PipelineRunner`]: crate::PipelineRunner

use crate::pipeline::error::PipelineError;
use crate::pipeline::{ConvertedResponse, PipelineRunner, RawInbound, RunConfig};
use std::convert::Infallible;
use std::error::Error as StdError;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::util::BoxCloneSyncService;
use tower::{Service, ServiceExt};

/// One complete request submitted to a [`RequestService`].
///
/// Keeping the inbound payload and per-run configuration together prevents
/// adapters from accidentally dropping caller-owned execution context.
pub struct ExecutionRequest {
  inbound: RawInbound,
  config: RunConfig,
}

type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Error returned by the transitional request-service boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum RequestError {
  /// Failure produced by the compatibility pipeline implementation.
  Pipeline { source: PipelineError },
  /// Failure produced by service middleware or a non-pipeline executor.
  Service { source: BoxError },
}

impl RequestError {
  /// Wrap a non-pipeline service failure.
  pub fn service(source: impl StdError + Send + Sync + 'static) -> Self {
    Self::Service {
      source: Box::new(source),
    }
  }

  /// Return the compatibility pipeline failure, when this service uses one.
  pub fn pipeline(&self) -> Option<&PipelineError> {
    match self {
      Self::Pipeline { source } => Some(source),
      Self::Service { .. } => None,
    }
  }

  /// Recover the compatibility pipeline failure without discarding other errors.
  pub fn into_pipeline(self) -> Result<PipelineError, Self> {
    match self {
      Self::Pipeline { source } => Ok(source),
      service @ Self::Service { .. } => Err(service),
    }
  }
}

impl From<PipelineError> for RequestError {
  fn from(source: PipelineError) -> Self {
    Self::Pipeline { source }
  }
}

impl From<BoxError> for RequestError {
  fn from(source: BoxError) -> Self {
    Self::Service { source }
  }
}

impl From<Infallible> for RequestError {
  fn from(source: Infallible) -> Self {
    match source {}
  }
}

impl std::fmt::Display for RequestError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Pipeline { source } => source.fmt(formatter),
      Self::Service { source } => write!(formatter, "request service failed: {source}"),
    }
  }
}

impl StdError for RequestError {
  fn source(&self) -> Option<&(dyn StdError + 'static)> {
    match self {
      Self::Pipeline { source } => Some(source),
      Self::Service { source } => Some(source.as_ref()),
    }
  }
}

impl ExecutionRequest {
  /// Create a request with the default per-run configuration.
  pub fn new(inbound: RawInbound) -> Self {
    Self {
      inbound,
      config: RunConfig::default(),
    }
  }

  /// Attach caller-owned per-run configuration.
  #[must_use]
  pub fn with_config(mut self, config: RunConfig) -> Self {
    self.config = config;
    self
  }

  /// Return the inbound request payload.
  pub fn inbound(&self) -> &RawInbound {
    &self.inbound
  }

  /// Return the caller-owned per-run configuration.
  pub fn config(&self) -> &RunConfig {
    &self.config
  }

  /// Split the request into its inbound payload and configuration.
  pub fn into_parts(self) -> (RawInbound, RunConfig) {
    (self.inbound, self.config)
  }
}

/// Cloneable, type-erased request service used by router and embedded SDKs.
///
/// The concrete wrapper exposes Tower readiness without leaking the boxed
/// implementation type. [`RequestService::execute`] clones the service before
/// polling it, so shared backpressure depends on the wrapped service's clone
/// semantics. Tower-aware callers may poll the [`Service`] implementation
/// directly.
#[derive(Clone, Debug)]
pub struct RequestService {
  inner: BoxCloneSyncService<ExecutionRequest, ConvertedResponse, RequestError>,
}

impl RequestService {
  /// Erase a cloneable Tower service behind the request-service boundary.
  pub fn new<S>(service: S) -> Self
  where
    S: Service<ExecutionRequest, Response = ConvertedResponse> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Error: Into<RequestError>,
  {
    Self {
      inner: BoxCloneSyncService::new(service.map_err(Into::into)),
    }
  }

  /// Adapt the current six-stage pipeline into a request service.
  pub fn from_pipeline(pipeline: Arc<PipelineRunner>) -> Self {
    Self::new(tower::service_fn(move |request: ExecutionRequest| {
      let pipeline = pipeline.clone();
      async move {
        let (inbound, config) = request.into_parts();
        pipeline.run_with(inbound, config).await
      }
    }))
  }

  /// Wait for readiness and execute one logical request.
  pub async fn execute(&self, request: ExecutionRequest) -> Result<ConvertedResponse, RequestError> {
    self.clone().oneshot(request).await
  }
}

impl Service<ExecutionRequest> for RequestService {
  type Response = ConvertedResponse;
  type Error = RequestError;
  type Future =
    <BoxCloneSyncService<ExecutionRequest, ConvertedResponse, RequestError> as Service<ExecutionRequest>>::Future;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, request: ExecutionRequest) -> Self::Future {
    self.inner.call(request)
  }
}

impl From<Arc<PipelineRunner>> for RequestService {
  fn from(pipeline: Arc<PipelineRunner>) -> Self {
    Self::from_pipeline(pipeline)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use bytes::Bytes;
  use smol_str::SmolStr;
  use std::future::{ready, Ready};
  use std::sync::atomic::{AtomicUsize, Ordering};
  use tokn_core::provider::Endpoint;
  use tokn_core::request_event::RequestEndpoint;
  use tokn_headers::HeaderMap;

  fn request() -> ExecutionRequest {
    ExecutionRequest::new(RawInbound {
      request_endpoint: RequestEndpoint::from(Endpoint::ChatCompletions),
      headers: HeaderMap::new(),
      raw_body: Bytes::from_static(br#"{}"#),
      decoded_body: Bytes::from_static(br#"{}"#),
      body_json: serde_json::json!({}),
      request_id: Some(SmolStr::new("req-service-test")),
    })
  }

  #[tokio::test]
  async fn custom_service_receives_run_config() {
    let service = RequestService::new(tower::service_fn(|request: ExecutionRequest| async move {
      assert_eq!(request.config().get_str("custom.value"), Some("present"));
      Err(PipelineError::stop(crate::Stage::Send))
    }));
    let config = RunConfig::builder().with_str("custom.value", "present").build();

    let err = service
      .execute(request().with_config(config))
      .await
      .expect_err("fake service deliberately stops");

    assert!(err.pipeline().is_some_and(|source| source.stop));
  }

  #[derive(Clone)]
  struct ReadinessProbe {
    polls: Arc<AtomicUsize>,
  }

  impl Service<ExecutionRequest> for ReadinessProbe {
    type Response = ConvertedResponse;
    type Error = PipelineError;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
      self.polls.fetch_add(1, Ordering::Relaxed);
      Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: ExecutionRequest) -> Self::Future {
      assert!(self.polls.load(Ordering::Relaxed) > 0, "call must follow readiness");
      ready(Err(PipelineError::stop(crate::Stage::Send)))
    }
  }

  #[tokio::test]
  async fn execute_polls_service_readiness() {
    let polls = Arc::new(AtomicUsize::new(0));
    let service = RequestService::new(ReadinessProbe { polls: polls.clone() });

    let _ = service.execute(request()).await;

    assert_eq!(polls.load(Ordering::Relaxed), 1);
  }
}

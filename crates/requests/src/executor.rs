//! Transitional request-service boundary shared by pipeline and layered runtimes.
//!
//! SDK callers depend on [`RequestService`] instead of the concrete six-stage
//! pipeline. HTTP-facing callers use [`tokn_service::HttpService`], produced
//! by adapting this request-domain service through
//! [`RequestService::http_service`]. The current [`PipelineRunner`]
//! implementation remains behind both boundaries while the request-domain
//! contract evolves independently from the HTTP transport contract.
//! The current [`RawInbound`] request and [`ConvertedResponse`] response are
//! compatibility types, not the final low-level SDK contract.
//!
//! [`PipelineRunner`]: crate::PipelineRunner

use crate::pipeline::error::PipelineError;
use crate::pipeline::stages::{ConvertedBody, ConvertedResponseKind};
use crate::pipeline::{ConvertedResponse, PipelineRunner, RawInbound, RunConfig};
use bytes::Bytes;
use http::{Method, Uri};
use http_body_util::BodyExt;
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

/// Pipeline-specific context carried in native HTTP request extensions.
///
/// Low-level services do not know this type exists. High-level adapters use
/// it to retain endpoint identity, request ids, run configuration, and an
/// already-decoded inspection copy while the wire message stays ordinary
/// [`http::Request`].
#[derive(Debug, Clone)]
pub struct PipelineRequestContext {
  request_endpoint: tokn_core::request_event::RequestEndpoint,
  request_id: Option<smol_str::SmolStr>,
  config: RunConfig,
  prepared_body: Option<PreparedBody>,
}

#[derive(Debug, Clone)]
struct PreparedBody {
  decoded_body: Bytes,
  body_json: serde_json::Value,
}

/// Compatibility response-body classification retained in HTTP extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineResponseKind {
  /// Managed response whose downstream headers are rebuilt for JSON.
  Buffered,
  /// Opaque response whose upstream status, headers, and body stay aligned.
  Opaque,
  Stream,
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

  /// Convert this compatibility request into the native low-level HTTP form.
  ///
  /// The original wire body remains the HTTP body. Pipeline-only decoded
  /// state is attached as an extension and is invisible to arbitrary Tower
  /// layers that operate only on the HTTP message.
  pub fn into_http(self, method: Method, uri: Uri) -> Result<tokn_service::Request, http::Error> {
    let (inbound, config) = self.into_parts();
    let RawInbound {
      request_endpoint,
      headers,
      raw_body,
      decoded_body,
      body_json,
      request_id,
    } = inbound;
    let context = PipelineRequestContext {
      request_endpoint,
      request_id,
      config,
      prepared_body: Some(PreparedBody {
        decoded_body,
        body_json,
      }),
    };
    let mut request = http::Request::builder()
      .method(method)
      .uri(uri)
      .body(tokn_service::body::full(raw_body))?;
    *request.headers_mut() = headers.into();
    request.extensions_mut().insert(context);
    Ok(request)
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

  /// Adapt this request-domain service into the public native HTTP service.
  pub fn http_service(&self) -> tokn_service::HttpService {
    let service = self.clone();
    tokn_service::HttpService::new(tower::service_fn(move |request: tokn_service::Request| {
      let service = service.clone();
      async move {
        let request = execution_from_http(request).await?;
        let response = service.execute(request).await?;
        converted_to_http(response)
      }
    }))
  }

  /// Adapt the compatibility pipeline into the public native HTTP service.
  pub fn http_from_pipeline(pipeline: Arc<PipelineRunner>) -> tokn_service::HttpService {
    Self::from_pipeline(pipeline).http_service()
  }

  /// Wait for readiness and execute one logical request.
  pub async fn execute(&self, request: ExecutionRequest) -> Result<ConvertedResponse, RequestError> {
    self.clone().oneshot(request).await
  }
}

async fn execution_from_http(request: tokn_service::Request) -> Result<ExecutionRequest, RequestError> {
  let (mut parts, body) = request.into_parts();
  let context = parts.extensions.remove::<PipelineRequestContext>();
  let raw_body = body.collect().await.map_err(RequestError::service)?.to_bytes();
  let headers: tokn_headers::HeaderMap = (&parts.headers).into();
  let request_endpoint = context
    .as_ref()
    .map(|context| context.request_endpoint.clone())
    .unwrap_or_else(|| tokn_core::request_event::RequestEndpoint::infer_from_path(parts.uri.path()));
  let (decoded_body, body_json) = match context.as_ref().and_then(|context| context.prepared_body.clone()) {
    Some(prepared) => (prepared.decoded_body, prepared.body_json),
    None => {
      let decoded =
        crate::utils::codec::decode_json_request(&headers, raw_body.clone()).map_err(RequestError::service)?;
      (decoded.decoded_body, decoded.value)
    }
  };
  let request_id = context.as_ref().and_then(|context| context.request_id.clone());
  let config = context.map_or_else(RunConfig::default, |context| context.config);
  Ok(
    ExecutionRequest::new(RawInbound {
      request_endpoint,
      headers,
      raw_body,
      decoded_body,
      body_json,
      request_id,
    })
    .with_config(config),
  )
}

fn converted_to_http(response: ConvertedResponse) -> Result<tokn_service::Response, RequestError> {
  let ConvertedResponse {
    status,
    headers,
    kind,
    body,
  } = response;
  let (body, kind) = match (kind, body) {
    (ConvertedResponseKind::Managed, ConvertedBody::Buffered { body_bytes, .. }) => {
      (tokn_service::body::full(body_bytes), PipelineResponseKind::Buffered)
    }
    (ConvertedResponseKind::Managed, ConvertedBody::Stream { body }) => {
      (tokn_service::body::stream(body), PipelineResponseKind::Stream)
    }
    (ConvertedResponseKind::Opaque, ConvertedBody::Buffered { body_bytes, .. }) => {
      (tokn_service::body::full(body_bytes), PipelineResponseKind::Opaque)
    }
    (ConvertedResponseKind::Opaque, ConvertedBody::Stream { body }) => {
      (tokn_service::body::stream(body), PipelineResponseKind::Opaque)
    }
  };
  let mut response = http::Response::builder()
    .status(status)
    .body(body)
    .map_err(RequestError::service)?;
  *response.headers_mut() = headers.into();
  response.extensions_mut().insert(kind);
  Ok(response)
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

  #[tokio::test]
  async fn native_http_request_is_adapted_without_losing_duplicate_headers() {
    let mut request = http::Request::post("/v1/responses")
      .body(tokn_service::body::full(Bytes::from_static(br#"{"model":"test"}"#)))
      .unwrap();
    request
      .headers_mut()
      .append("x-duplicate", http::HeaderValue::from_static("first"));
    request
      .headers_mut()
      .append("x-duplicate", http::HeaderValue::from_static("second"));

    let execution = execution_from_http(request).await.unwrap();
    let (inbound, _) = execution.into_parts();

    assert_eq!(inbound.request_endpoint, Endpoint::Responses);
    assert_eq!(inbound.decoded_body, Bytes::from_static(br#"{"model":"test"}"#));
    assert_eq!(inbound.body_json["model"], "test");
    assert_eq!(
      inbound
        .headers
        .get_all("x-duplicate")
        .map(|value| value.as_str())
        .collect::<Vec<_>>(),
      ["first", "second"]
    );
  }

  #[tokio::test]
  async fn compatibility_request_round_trips_through_native_http_extensions() {
    let config = RunConfig::builder().with_str("custom.value", "present").build();
    let request = request()
      .with_config(config)
      .into_http(Method::POST, Uri::from_static("/v1/chat/completions"))
      .unwrap();

    let execution = execution_from_http(request).await.unwrap();

    assert_eq!(execution.config().get_str("custom.value"), Some("present"));
    assert_eq!(execution.inbound().request_id.as_deref(), Some("req-service-test"));
    assert_eq!(execution.inbound().body_json, serde_json::json!({}));
  }

  #[test]
  fn native_response_classification_is_explicit() {
    for (kind, body_json, expected) in [
      (
        ConvertedResponseKind::Managed,
        Some(Arc::new(serde_json::json!({"ok": true}))),
        PipelineResponseKind::Buffered,
      ),
      (ConvertedResponseKind::Managed, None, PipelineResponseKind::Buffered),
      (ConvertedResponseKind::Opaque, None, PipelineResponseKind::Opaque),
    ] {
      let response = converted_to_http(ConvertedResponse {
        status: 200,
        headers: HeaderMap::new(),
        kind,
        body: ConvertedBody::Buffered {
          body_json,
          body_bytes: Bytes::from_static(b"body"),
        },
      })
      .unwrap();
      assert_eq!(response.extensions().get::<PipelineResponseKind>(), Some(&expected));
    }
  }
}

//! Request-attempt event projection and pre-adaptation application-body
//! observation.
//!
//! The non-cloneable request lifecycle remains owned by the server adapter.
//! Live upstream bodies instead update this small shared observation record;
//! the outer downstream body owner drains progress in-order and closes the
//! attempt atomically with request termination.

use crate::runtime::observation::capture_headers;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use serde_json::Value;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use tokn_core::provider::{Endpoint, Error as ProviderError, OutboundRequestObserver};
use tokn_events::{
  AttemptFinished, AttemptHttpRequest, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted,
  AttemptUsage, BodyCapture, BodyFinished, BodyLeg, BodyProgress, BodyResult, CapturedUri, EventFailure,
  HttpRequestSnapshot, HttpResponseHead, RequestPhase, TargetSelection, TokenUsage, TrafficEventKind, UsageKind,
};
use tokn_requests::{BoundaryPublishError, RequestLifecycle, RequestTerminalEvent, RequestTermination};

const UPSTREAM_BODY_FAILURE_CODE: &str = "upstream_body_read_failed";
const UPSTREAM_BODY_FAILURE_MESSAGE: &str = "the upstream response body could not be read";
const REQUEST_OBSERVATION_FAILURE_MESSAGE: &str = "gateway request lifecycle publication failed";

pub(crate) async fn publish_attempt_started(
  lifecycle: &mut RequestLifecycle,
  target: TargetSelection,
) -> Result<(), BoundaryPublishError> {
  lifecycle
    .publish_boundary(TrafficEventKind::AttemptStarted(AttemptStarted {
      attempt: AttemptNo::FIRST,
      target,
    }))
    .await
    .map(|_| ())
}

pub(crate) async fn publish_response_head(
  lifecycle: &mut RequestLifecycle,
  response: &reqwest::Response,
) -> Result<(), BoundaryPublishError> {
  lifecycle
    .publish_boundary(TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
      attempt: AttemptNo::FIRST,
      response: HttpResponseHead {
        status: response.status().as_u16(),
        headers: capture_headers(response.headers()),
      },
    }))
    .await
    .map(|_| ())
}

pub(crate) async fn close_pre_head_failure(
  lifecycle: &mut RequestLifecycle,
  phase: RequestPhase,
) -> Result<(), BoundaryPublishError> {
  lifecycle
    .publish_boundary(TrafficEventKind::AttemptFinished(AttemptFinished {
      attempt: AttemptNo::FIRST,
      outcome: AttemptOutcome::Failed,
      phase,
      upstream_status: None,
      failure: Some(EventFailure {
        code: "upstream_request_failed".into(),
        message: "the upstream request could not be completed".into(),
      }),
      retry: None,
    }))
    .await
    .map(|_| ())
}

pub(crate) const fn endpoint_usage_kind(endpoint: Endpoint) -> UsageKind {
  match endpoint {
    Endpoint::ChatCompletions => UsageKind::ChatCompletions,
    Endpoint::Responses => UsageKind::Responses,
    Endpoint::Messages => UsageKind::Messages,
  }
}

/// Publishes the provider-prepared request immediately before transport I/O.
pub(crate) struct AttemptRequestObserver<'a> {
  lifecycle: &'a mut RequestLifecycle,
  attempt: AttemptNo,
  capture_limit: usize,
  publication_error: Option<BoundaryPublishError>,
}

impl<'a> AttemptRequestObserver<'a> {
  pub(crate) fn new(lifecycle: &'a mut RequestLifecycle, attempt: AttemptNo, capture_limit: usize) -> Self {
    Self {
      lifecycle,
      attempt,
      capture_limit,
      publication_error: None,
    }
  }

  pub(crate) fn take_publication_error(&mut self) -> Option<BoundaryPublishError> {
    self.publication_error.take()
  }
}

#[async_trait]
impl OutboundRequestObserver for AttemptRequestObserver<'_> {
  async fn observe(&mut self, request: &reqwest::Request) -> Result<(), ProviderError> {
    let body = match request.body().and_then(reqwest::Body::as_bytes) {
      Some(body) => capture_bytes(body, self.capture_limit),
      None if request.body().is_none() => BodyCapture::Absent,
      None => BodyCapture::Omitted {
        reason: tokn_events::CaptureOmission::Unavailable,
        bytes_seen: 0,
      },
    };
    let snapshot = AttemptHttpRequest {
      attempt: self.attempt,
      request: HttpRequestSnapshot {
        method: request.method().as_str().into(),
        uri: CapturedUri::exact(request.url().as_str()),
        headers: capture_headers(request.headers()),
        body,
      },
    };
    match self
      .lifecycle
      .publish_boundary(TrafficEventKind::AttemptRequest(snapshot))
      .await
    {
      Ok(_) => Ok(()),
      Err(source) => {
        tracing::error!(error = %source, "could not publish final upstream request observation");
        self.publication_error = Some(source);
        Err(ProviderError::RequestObservation {
          message: REQUEST_OBSERVATION_FAILURE_MESSAGE.to_string(),
        })
      }
    }
  }
}

/// Shared facts for one reqwest-exposed upstream response body.
#[derive(Clone)]
pub(crate) struct UpstreamBodyObservation {
  inner: Arc<Mutex<UpstreamBodyState>>,
}

/// Terminal ownership for a response whose pre-adaptation body may remain live.
#[derive(Clone)]
pub(crate) struct AttemptBodyPlan {
  observation: UpstreamBodyObservation,
  upstream_status: u16,
}

impl AttemptBodyPlan {
  pub(crate) fn new(observation: UpstreamBodyObservation, upstream_status: u16) -> Self {
    Self {
      observation,
      upstream_status,
    }
  }

  pub(crate) fn arm(&self, lifecycle: &mut RequestLifecycle) {
    lifecycle.arm_body(BodyLeg::Upstream {
      attempt: AttemptNo::FIRST,
    });
  }

  pub(crate) fn take_progress(&self) -> Option<BodyProgress> {
    self.observation.take_progress()
  }

  pub(crate) fn is_finished(&self) -> bool {
    self.observation.is_finished()
  }

  pub(crate) async fn publish_terminal(&self, lifecycle: &mut RequestLifecycle) -> Result<(), BoundaryPublishError> {
    let Some(events) = self.observation.take_terminal(self.upstream_status) else {
      return Ok(());
    };
    for event in events {
      if let Some(kind) = terminal_kind(event) {
        lifecycle.publish_boundary(kind).await?;
      }
    }
    Ok(())
  }

  pub(crate) fn append_terminal(&self, termination: &mut RequestTermination) {
    let Some(events) = self.observation.take_terminal(self.upstream_status) else {
      return;
    };
    for event in events {
      termination.push(event);
    }
  }
}

/// Wrap a received response before any adapter can poll its reqwest-exposed
/// application body.
pub(crate) fn observe_upstream_response(
  response: reqwest::Response,
  capture_limit: usize,
  usage_kind: Option<UsageKind>,
) -> (reqwest::Response, AttemptBodyPlan) {
  let status = response.status().as_u16();
  let is_sse = response_is_sse(response.headers());
  let observation = UpstreamBodyObservation::new(AttemptNo::FIRST, capture_limit, usage_kind, is_sse);
  let response: http::Response<reqwest::Body> = response.into();
  let (parts, body) = response.into_parts();
  let body = reqwest::Body::wrap(ObservedUpstreamBody::new(body, observation.clone()));
  let response = reqwest::Response::from(http::Response::from_parts(parts, body));
  (response, AttemptBodyPlan::new(observation, status))
}

fn terminal_kind(event: RequestTerminalEvent) -> Option<TrafficEventKind> {
  match event {
    RequestTerminalEvent::BodyFinished(event) => Some(TrafficEventKind::BodyFinished(event)),
    RequestTerminalEvent::AttemptUsage(event) => Some(TrafficEventKind::AttemptUsage(event)),
    RequestTerminalEvent::AttemptFinished(event) => Some(TrafficEventKind::AttemptFinished(event)),
    RequestTerminalEvent::ConnectClosed(_) => None,
    _ => None,
  }
}

impl UpstreamBodyObservation {
  pub(crate) fn new(attempt: AttemptNo, capture_limit: usize, usage_kind: Option<UsageKind>, is_sse: bool) -> Self {
    Self {
      inner: Arc::new(Mutex::new(UpstreamBodyState {
        attempt,
        capture: BytesMut::with_capacity(capture_limit.min(8 * 1024)),
        capture_limit,
        bytes_seen: 0,
        chunks: 0,
        published_bytes: 0,
        published_chunks: 0,
        result: None,
        usage: TokenUsage {
          kind: usage_kind,
          ..TokenUsage::default()
        },
        usage_observed: false,
        is_sse,
        sse_buffer: Vec::new(),
        terminalized: false,
      })),
    }
  }

  fn lock(&self) -> MutexGuard<'_, UpstreamBodyState> {
    self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn observe_data(&self, data: &Bytes) {
    self.lock().observe_data(data);
  }

  fn finish(&self, result: BodyResult) {
    self.lock().finish(result);
  }

  /// Return only newly observed cumulative progress.
  pub(crate) fn take_progress(&self) -> Option<BodyProgress> {
    let mut state = self.lock();
    if state.bytes_seen == state.published_bytes && state.chunks == state.published_chunks {
      return None;
    }
    state.published_bytes = state.bytes_seen;
    state.published_chunks = state.chunks;
    Some(BodyProgress {
      leg: BodyLeg::Upstream { attempt: state.attempt },
      bytes_seen: state.bytes_seen,
      chunks: state.chunks,
    })
  }

  pub(crate) fn is_finished(&self) -> bool {
    self.lock().result.is_some()
  }

  /// Materialize this attempt's terminal facts exactly once.
  ///
  /// An unfinished body is cancellation, which is truthful when the owning
  /// response or conversion pipeline is being dropped before reqwest body EOF.
  pub(crate) fn take_terminal(&self, upstream_status: u16) -> Option<Vec<RequestTerminalEvent>> {
    let mut state = self.lock();
    if state.terminalized {
      return None;
    }
    if state.result.is_none() {
      state.finish(BodyResult::Cancelled);
    }
    state.terminalized = true;
    Some(state.terminal_events(upstream_status))
  }
}

struct UpstreamBodyState {
  attempt: AttemptNo,
  capture: BytesMut,
  capture_limit: usize,
  bytes_seen: u64,
  chunks: u64,
  published_bytes: u64,
  published_chunks: u64,
  result: Option<BodyResult>,
  usage: TokenUsage,
  usage_observed: bool,
  is_sse: bool,
  sse_buffer: Vec<u8>,
  terminalized: bool,
}

impl UpstreamBodyState {
  fn observe_data(&mut self, data: &Bytes) {
    if self.result.is_some() {
      return;
    }
    self.bytes_seen = self
      .bytes_seen
      .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    self.chunks = self.chunks.saturating_add(1);
    let retained = self.capture_limit.saturating_sub(self.capture.len()).min(data.len());
    self.capture.extend_from_slice(&data[..retained]);
    if self.is_sse {
      self.observe_sse(data);
    }
  }

  fn observe_sse(&mut self, data: &[u8]) {
    self.sse_buffer.extend_from_slice(data);
    while let Some(newline) = self.sse_buffer.iter().position(|byte| *byte == b'\n') {
      let mut line = self.sse_buffer.drain(..=newline).collect::<Vec<_>>();
      while line.last().is_some_and(|byte| matches!(*byte, b'\n' | b'\r')) {
        line.pop();
      }
      self.observe_sse_line(&line);
    }
    // A malformed peer must not make telemetry retain an unbounded line.
    if self.sse_buffer.len() > self.capture_limit.max(64 * 1024) {
      self.sse_buffer.clear();
    }
  }

  fn finish(&mut self, result: BodyResult) {
    if self.result.is_some() {
      return;
    }
    if matches!(result, BodyResult::Complete) {
      if self.is_sse && !self.sse_buffer.is_empty() {
        let line = std::mem::take(&mut self.sse_buffer);
        self.observe_sse_line(&line);
      } else if !self.is_sse && self.bytes_seen == self.capture.len() as u64 {
        if let Ok(value) = serde_json::from_slice::<Value>(&self.capture) {
          self.observe_usage_value(&value);
        }
      }
    }
    self.result = Some(result);
  }

  fn observe_sse_line(&mut self, line: &[u8]) {
    let Some(payload) = line.strip_prefix(b"data:") else {
      return;
    };
    let payload = payload.strip_prefix(b" ").unwrap_or(payload);
    if payload == b"[DONE]" {
      return;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(payload) {
      self.observe_usage_value(&value);
    }
  }

  fn observe_usage_value(&mut self, value: &Value) {
    let Some(usage) = find_usage(value) else {
      return;
    };
    let update = token_usage(self.usage.kind, usage);
    if usage_has_values(&update) {
      self.usage.merge_from(&update);
      self.usage_observed = true;
    }
  }

  fn terminal_events(&self, upstream_status: u16) -> Vec<RequestTerminalEvent> {
    let result = self.result.clone().unwrap_or(BodyResult::Cancelled);
    let capture = if matches!(result, BodyResult::Complete) && self.bytes_seen == self.capture.len() as u64 {
      BodyCapture::Complete(Bytes::copy_from_slice(&self.capture))
    } else {
      BodyCapture::Truncated {
        prefix: Bytes::copy_from_slice(&self.capture),
        bytes_seen: self.bytes_seen,
      }
    };
    let failure = match &result {
      BodyResult::Failed(failure) => Some(failure.clone()),
      BodyResult::Complete | BodyResult::Cancelled => None,
      _ => None,
    };
    let outcome = match result {
      BodyResult::Complete => AttemptOutcome::Response,
      BodyResult::Failed(_) => AttemptOutcome::Failed,
      BodyResult::Cancelled => AttemptOutcome::Cancelled,
      _ => AttemptOutcome::Failed,
    };
    let mut events = vec![RequestTerminalEvent::BodyFinished(BodyFinished {
      leg: BodyLeg::Upstream { attempt: self.attempt },
      capture,
      result,
    })];
    if self.usage_observed {
      events.push(RequestTerminalEvent::AttemptUsage(AttemptUsage {
        attempt: self.attempt,
        usage: self.usage.clone(),
      }));
    }
    events.push(RequestTerminalEvent::AttemptFinished(AttemptFinished {
      attempt: self.attempt,
      outcome,
      phase: RequestPhase::UpstreamResponse,
      upstream_status: Some(upstream_status),
      failure,
      retry: None,
    }));
    events
  }
}

/// HTTP body wrapper that observes frames yielded by reqwest without changing
/// them.
pub(crate) struct ObservedUpstreamBody<B> {
  inner: Pin<Box<B>>,
  observation: UpstreamBodyObservation,
}

impl<B> ObservedUpstreamBody<B> {
  pub(crate) fn new(inner: B, observation: UpstreamBodyObservation) -> Self {
    Self {
      inner: Box::pin(inner),
      observation,
    }
  }
}

impl<B> HttpBody for ObservedUpstreamBody<B>
where
  B: HttpBody<Data = Bytes>,
  B::Error: fmt::Display,
{
  type Data = Bytes;
  type Error = B::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match self.inner.as_mut().poll_frame(context) {
      Poll::Ready(Some(Ok(frame))) => {
        if let Some(data) = frame.data_ref() {
          self.observation.observe_data(data);
        }
        Poll::Ready(Some(Ok(frame)))
      }
      Poll::Ready(Some(Err(error))) => {
        tracing::warn!(error = %error, "upstream response body read failed");
        self.observation.finish(BodyResult::Failed(EventFailure {
          code: UPSTREAM_BODY_FAILURE_CODE.into(),
          message: UPSTREAM_BODY_FAILURE_MESSAGE.into(),
        }));
        Poll::Ready(Some(Err(error)))
      }
      Poll::Ready(None) => {
        self.observation.finish(BodyResult::Complete);
        Poll::Ready(None)
      }
      Poll::Pending => Poll::Pending,
    }
  }

  fn is_end_stream(&self) -> bool {
    // Force one poll even when the inner size hint is exactly zero, otherwise
    // this observer cannot distinguish a completed empty body from a body
    // dropped before observation.
    self.observation.is_finished()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

impl<B> Drop for ObservedUpstreamBody<B> {
  fn drop(&mut self) {
    self.observation.finish(BodyResult::Cancelled);
  }
}

pub(crate) fn capture_bytes(body: &[u8], limit: usize) -> BodyCapture {
  if body.len() <= limit {
    BodyCapture::Complete(Bytes::copy_from_slice(body))
  } else {
    BodyCapture::Truncated {
      prefix: Bytes::copy_from_slice(&body[..limit]),
      bytes_seen: u64::try_from(body.len()).unwrap_or(u64::MAX),
    }
  }
}

fn find_usage(value: &Value) -> Option<&Value> {
  value
    .get("usage")
    .or_else(|| value.get("response").and_then(|response| response.get("usage")))
    .or_else(|| value.get("message").and_then(|message| message.get("usage")))
}

fn token_usage(kind: Option<UsageKind>, usage: &Value) -> TokenUsage {
  let input = u64_field(usage, &["input_tokens", "prompt_tokens"]);
  let output = u64_field(usage, &["output_tokens", "completion_tokens"]);
  TokenUsage {
    kind,
    input,
    output,
    total: u64_field(usage, &["total_tokens"]),
    cache_read: u64_field(usage, &["cache_read_input_tokens"])
      .or_else(|| nested_u64(usage, &["input_tokens_details", "cached_tokens"]))
      .or_else(|| nested_u64(usage, &["prompt_tokens_details", "cached_tokens"])),
    cache_write: u64_field(usage, &["cache_creation_input_tokens"]),
    reasoning: nested_u64(usage, &["output_tokens_details", "reasoning_tokens"])
      .or_else(|| nested_u64(usage, &["completion_tokens_details", "reasoning_tokens"])),
  }
}

fn usage_has_values(usage: &TokenUsage) -> bool {
  usage.input.is_some()
    || usage.output.is_some()
    || usage.total.is_some()
    || usage.cache_read.is_some()
    || usage.cache_write.is_some()
    || usage.reasoning.is_some()
}

fn u64_field(value: &Value, names: &[&str]) -> Option<u64> {
  names.iter().find_map(|name| value.get(*name).and_then(Value::as_u64))
}

fn nested_u64(value: &Value, path: &[&str]) -> Option<u64> {
  path
    .iter()
    .try_fold(value, |current, name| current.get(*name))
    .and_then(Value::as_u64)
}

pub(crate) fn response_is_sse(headers: &HeaderMap) -> bool {
  headers
    .get(http::header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.split(';').next())
    .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::VecDeque;
  use std::convert::Infallible;
  use std::task::Poll;

  enum TestFrame {
    Data(&'static [u8]),
    Pending,
  }

  struct TestBody {
    frames: VecDeque<TestFrame>,
  }

  impl TestBody {
    fn new(frames: impl IntoIterator<Item = TestFrame>) -> Self {
      Self {
        frames: frames.into_iter().collect(),
      }
    }
  }

  impl HttpBody for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
      mut self: Pin<&mut Self>,
      _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
      match self.frames.pop_front() {
        Some(TestFrame::Data(data)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(data))))),
        Some(TestFrame::Pending) => Poll::Pending,
        None => Poll::Ready(None),
      }
    }
  }

  async fn next_frame(body: &mut ObservedUpstreamBody<TestBody>) -> Option<Result<Frame<Bytes>, Infallible>> {
    std::future::poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await
  }

  #[tokio::test]
  async fn empty_upstream_body_is_polled_and_completed_without_a_retry() {
    let observation = UpstreamBodyObservation::new(AttemptNo::FIRST, 64, None, false);
    let mut body = ObservedUpstreamBody::new(TestBody::new([]), observation.clone());

    assert!(!body.is_end_stream());
    assert!(next_frame(&mut body).await.is_none());
    assert!(body.is_end_stream());

    let events = observation.take_terminal(204).unwrap();
    assert!(matches!(
      &events[0],
      RequestTerminalEvent::BodyFinished(BodyFinished {
        capture: BodyCapture::Complete(body),
        result: BodyResult::Complete,
        ..
      }) if body.is_empty()
    ));
    assert!(matches!(
      &events[1],
      RequestTerminalEvent::AttemptFinished(AttemptFinished {
        outcome: AttemptOutcome::Response,
        upstream_status: Some(204),
        retry: None,
        ..
      })
    ));
    assert!(observation.take_terminal(204).is_none());
  }

  #[test]
  fn dropping_a_pending_upstream_body_closes_the_attempt_once_as_cancelled() {
    let observation = UpstreamBodyObservation::new(AttemptNo::FIRST, 64, None, false);
    let body = ObservedUpstreamBody::new(TestBody::new([TestFrame::Pending]), observation.clone());

    drop(body);

    let events = observation.take_terminal(200).unwrap();
    assert_eq!(
      events
        .iter()
        .filter(|event| matches!(event, RequestTerminalEvent::AttemptFinished(_)))
        .count(),
      1
    );
    assert!(matches!(
      events.last(),
      Some(RequestTerminalEvent::AttemptFinished(AttemptFinished {
        outcome: AttemptOutcome::Cancelled,
        retry: None,
        ..
      }))
    ));
    assert!(observation.take_terminal(200).is_none());
  }

  #[tokio::test]
  async fn sse_usage_is_extracted_from_raw_upstream_bytes() {
    let observation = UpstreamBodyObservation::new(AttemptNo::FIRST, 1024, Some(UsageKind::Responses), true);
    let payload = b"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":5,\"total_tokens\":12,\"input_tokens_details\":{\"cached_tokens\":3},\"output_tokens_details\":{\"reasoning_tokens\":2}}}}";
    let mut body = ObservedUpstreamBody::new(TestBody::new([TestFrame::Data(payload)]), observation.clone());

    assert!(next_frame(&mut body).await.unwrap().is_ok());
    assert!(next_frame(&mut body).await.is_none());

    let events = observation.take_terminal(200).unwrap();
    assert!(events.iter().any(|event| matches!(
      event,
      RequestTerminalEvent::AttemptUsage(AttemptUsage {
        usage: TokenUsage {
          kind: Some(UsageKind::Responses),
          input: Some(7),
          output: Some(5),
          total: Some(12),
          cache_read: Some(3),
          reasoning: Some(2),
          ..
        },
        ..
      })
    )));
  }
}

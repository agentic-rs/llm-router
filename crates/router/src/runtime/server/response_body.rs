//! Downstream response-body lifecycle observation.
//!
//! The response head is published by the caller before it hands the lifecycle
//! to this module. The observer then owns that non-cloneable lifecycle until
//! the downstream body reaches EOF, fails, or is dropped by the client.

use crate::runtime::attempts::AttemptBodyPlan;
use axum::body::Body;
use axum::response::Response;
use bytes::{Bytes, BytesMut};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokn_events::{
  BodyCapture, BodyFinished, BodyLeg, BodyProgress, BodyResult, EventFailure, RequestOutcome, RequestPhase,
};
use tokn_requests::{RequestCompletion, RequestLifecycle, RequestTerminalEvent, RequestTermination};

const DOWNSTREAM_BODY_FAILURE_CODE: &str = "downstream_body_read_failed";
const DOWNSTREAM_BODY_FAILURE_MESSAGE: &str = "the downstream response body could not be read";

/// Move a request lifecycle into an observer for an already-materialized response.
///
/// The response head, extensions, and streaming body are preserved. `capture_limit`
/// bounds the retained downstream prefix without limiting bytes delivered to the
/// client. The caller must publish `DownstreamResponseHead` before calling this
/// function. Body completion is appended to `termination`. A failure or
/// cancellation replaces a provisional `Delivered` completion while preserving
/// already-classified local `Rejected` and `Failed` responses.
pub(super) fn observe_downstream_body(
  response: Response,
  lifecycle: RequestLifecycle,
  termination: RequestTermination,
  capture_limit: usize,
) -> Response {
  let (mut parts, body) = response.into_parts();
  let attempt = parts.extensions.remove::<AttemptBodyPlan>();
  let body = Body::new(DownstreamLifecycleBody::with_attempt(
    body,
    lifecycle,
    termination,
    capture_limit,
    attempt,
  ));
  Response::from_parts(parts, body)
}

/// A transparent frame observer that owns terminal request publication.
struct DownstreamLifecycleBody<B> {
  inner: Pin<Box<B>>,
  lifecycle: Option<RequestLifecycle>,
  termination: Option<RequestTermination>,
  capture: BytesMut,
  capture_limit: usize,
  bytes_seen: u64,
  chunks: u64,
  progress_available: bool,
  attempt_progress_available: bool,
  attempt: Option<AttemptBodyPlan>,
}

impl<B> DownstreamLifecycleBody<B> {
  #[cfg(test)]
  fn new(inner: B, lifecycle: RequestLifecycle, termination: RequestTermination, capture_limit: usize) -> Self {
    Self::with_attempt(inner, lifecycle, termination, capture_limit, None)
  }

  fn with_attempt(
    inner: B,
    mut lifecycle: RequestLifecycle,
    termination: RequestTermination,
    capture_limit: usize,
    attempt: Option<AttemptBodyPlan>,
  ) -> Self {
    if let Some(attempt) = &attempt {
      attempt.arm(&mut lifecycle);
    }
    lifecycle.arm_body(BodyLeg::Downstream);
    Self {
      inner: Box::pin(inner),
      lifecycle: Some(lifecycle),
      termination: Some(termination),
      capture: BytesMut::with_capacity(capture_limit.min(8 * 1024)),
      capture_limit,
      bytes_seen: 0,
      chunks: 0,
      progress_available: true,
      attempt_progress_available: true,
      attempt,
    }
  }

  fn publish_attempt_progress(&mut self) {
    if !self.attempt_progress_available {
      return;
    }
    let Some(progress) = self.attempt.as_ref().and_then(AttemptBodyPlan::take_progress) else {
      return;
    };
    let Some(lifecycle) = &mut self.lifecycle else {
      return;
    };
    if let Err(error) = lifecycle.try_publish_progress(progress) {
      self.attempt_progress_available = false;
      tracing::warn!(error = %error, "upstream body progress publication failed");
    }
  }

  fn observe_data(&mut self, data: &Bytes) {
    let chunk_bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
    self.bytes_seen = self.bytes_seen.saturating_add(chunk_bytes);
    self.chunks = self.chunks.saturating_add(1);

    let remaining = self.capture_limit.saturating_sub(self.capture.len());
    let retained = remaining.min(data.len());
    self.capture.extend_from_slice(&data[..retained]);

    if !self.progress_available {
      return;
    }
    let progress = BodyProgress {
      leg: BodyLeg::Downstream,
      bytes_seen: self.bytes_seen,
      chunks: self.chunks,
    };
    let Some(lifecycle) = &mut self.lifecycle else {
      return;
    };
    if let Err(error) = lifecycle.try_publish_progress(progress) {
      self.progress_available = false;
      tracing::warn!(error = %error, "downstream body progress publication failed");
    }
  }

  fn finish_complete(&mut self) {
    let capture = if self.bytes_seen == u64::try_from(self.capture.len()).unwrap_or(u64::MAX) {
      BodyCapture::Complete(self.capture.split().freeze())
    } else {
      self.incomplete_capture()
    };
    self.finish(capture, BodyResult::Complete);
  }

  fn finish_incomplete(&mut self, result: BodyResult) {
    let capture = self.incomplete_capture();
    self.finish(capture, result);
  }

  fn incomplete_capture(&mut self) -> BodyCapture {
    BodyCapture::Truncated {
      prefix: self.capture.split().freeze(),
      bytes_seen: self.bytes_seen,
    }
  }

  fn finish(&mut self, capture: BodyCapture, result: BodyResult) {
    let Some(lifecycle) = self.lifecycle.take() else {
      return;
    };
    let mut termination = self
      .termination
      .take()
      .expect("a live downstream lifecycle always has a terminal plan");
    if termination.completion().outcome == RequestOutcome::Delivered {
      match &result {
        BodyResult::Failed(failure) => termination.replace_completion(RequestCompletion::new(
          RequestOutcome::Failed,
          RequestPhase::DownstreamResponse,
          None,
          Some(failure.clone()),
        )),
        BodyResult::Cancelled => termination.replace_completion(RequestCompletion::new(
          RequestOutcome::Cancelled,
          RequestPhase::DownstreamResponse,
          None,
          None,
        )),
        BodyResult::Complete => {}
        _ => {}
      }
    }
    if let Some(attempt) = &self.attempt {
      attempt.append_terminal(&mut termination);
    }
    termination.push(RequestTerminalEvent::BodyFinished(BodyFinished {
      leg: BodyLeg::Downstream,
      capture,
      result,
    }));
    let request_id = lifecycle.request_id().clone();
    if let Err(error) = lifecycle.finish(termination) {
      tracing::warn!(%request_id, error = %error, "downstream body terminal publication failed");
    }
  }
}

impl<B> HttpBody for DownstreamLifecycleBody<B>
where
  B: HttpBody<Data = Bytes>,
  B::Error: fmt::Display,
{
  type Data = Bytes;
  type Error = B::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
    let this = &mut *self;
    if this.lifecycle.is_none() {
      return Poll::Ready(None);
    }

    match this.inner.as_mut().poll_frame(context) {
      Poll::Ready(Some(Ok(frame))) => {
        this.publish_attempt_progress();
        if let Some(data) = frame.data_ref() {
          this.observe_data(data);
        }
        Poll::Ready(Some(Ok(frame)))
      }
      Poll::Ready(Some(Err(error))) => {
        this.publish_attempt_progress();
        tracing::warn!(error = %error, "downstream response body read failed");
        let failure = EventFailure {
          code: DOWNSTREAM_BODY_FAILURE_CODE.into(),
          message: DOWNSTREAM_BODY_FAILURE_MESSAGE.into(),
        };
        this.finish_incomplete(BodyResult::Failed(failure));
        Poll::Ready(Some(Err(error)))
      }
      Poll::Ready(None) => {
        this.publish_attempt_progress();
        this.finish_complete();
        Poll::Ready(None)
      }
      Poll::Pending => {
        this.publish_attempt_progress();
        Poll::Pending
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    // Keep an empty inner body pollable until it can publish Complete. Once
    // terminalized, no more frames may be observed even if a broken upstream
    // body were to yield frames after an error.
    self.lifecycle.is_none()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

impl<B> Drop for DownstreamLifecycleBody<B> {
  fn drop(&mut self) {
    if self.lifecycle.is_some() {
      self.finish_incomplete(BodyResult::Cancelled);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::{HeaderMap, HeaderValue, StatusCode};
  use std::collections::VecDeque;
  use std::error::Error;
  use std::sync::{Arc, Mutex};
  use tokn_events::{
    AttemptFinished, AttemptHttpRequest, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted,
    CapturedHeaders, CapturedUri, ConsumerResult, Correlation, EventConsumer, EventSeq, GatewayEvent, HttpFamily,
    HttpRequestSnapshot, HttpResponseHead, HubBuilder, IngressKind, RequestOutcome, RequestPhase, RequestSource,
    RequestStarted, TargetSelection, TrafficEvent, TrafficEventKind,
  };
  use tokn_requests::{RequestCompletion, RequestLifecycleEmitter};

  #[derive(Debug)]
  struct TestBodyError(&'static str);

  impl fmt::Display for TestBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      formatter.write_str(self.0)
    }
  }

  impl Error for TestBodyError {}

  enum TestFrame {
    Data(&'static [u8]),
    Trailers(HeaderMap),
    Error(TestBodyError),
    Pending,
  }

  struct TestBody {
    frames: VecDeque<TestFrame>,
    size_hint: SizeHint,
  }

  impl TestBody {
    fn new(frames: impl IntoIterator<Item = TestFrame>) -> Self {
      Self {
        frames: frames.into_iter().collect(),
        size_hint: SizeHint::default(),
      }
    }

    fn with_exact_size(mut self, size: u64) -> Self {
      self.size_hint = SizeHint::with_exact(size);
      self
    }
  }

  impl HttpBody for TestBody {
    type Data = Bytes;
    type Error = TestBodyError;

    fn poll_frame(
      mut self: Pin<&mut Self>,
      _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
      match self.frames.pop_front() {
        Some(TestFrame::Data(data)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(data))))),
        Some(TestFrame::Trailers(trailers)) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
        Some(TestFrame::Error(error)) => Poll::Ready(Some(Err(error))),
        Some(TestFrame::Pending) => Poll::Pending,
        None => Poll::Ready(None),
      }
    }

    fn size_hint(&self) -> SizeHint {
      self.size_hint.clone()
    }
  }

  struct CaptureConsumer {
    events: Arc<Mutex<Vec<GatewayEvent>>>,
  }

  impl EventConsumer<GatewayEvent> for CaptureConsumer {
    fn name(&self) -> &str {
      "response-body-test"
    }

    fn handle(&mut self, _sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
      self.events.lock().unwrap().push(event.clone());
      Ok(())
    }
  }

  fn started() -> RequestStarted {
    RequestStarted {
      source: RequestSource::Listener {
        listener_id: "test".into(),
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
    }
  }

  fn termination(outcome: RequestOutcome, status: u16) -> RequestTermination {
    RequestTermination::new(RequestCompletion::new(
      outcome,
      RequestPhase::Complete,
      Some(status),
      None,
    ))
  }

  async fn lifecycle(
    events: &Arc<Mutex<Vec<GatewayEvent>>>,
    status: u16,
  ) -> (RequestLifecycle, tokn_events::EventHub<GatewayEvent>) {
    let (publisher, hub) = HubBuilder::new()
      .consumer(CaptureConsumer {
        events: Arc::clone(events),
      })
      .start()
      .unwrap();
    let emitter = RequestLifecycleEmitter::new(publisher);
    let mut lifecycle = emitter.begin(started()).await.unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status,
        headers: CapturedHeaders::default(),
      }))
      .await
      .unwrap();
    (lifecycle, hub)
  }

  async fn attempt_lifecycle(
    events: &Arc<Mutex<Vec<GatewayEvent>>>,
    status: u16,
  ) -> (RequestLifecycle, tokn_events::EventHub<GatewayEvent>) {
    let (publisher, hub) = HubBuilder::new()
      .consumer(CaptureConsumer {
        events: Arc::clone(events),
      })
      .start()
      .unwrap();
    let emitter = RequestLifecycleEmitter::new(publisher);
    let mut lifecycle = emitter.begin(started()).await.unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: TargetSelection {
          family: HttpFamily::Transparent,
          account_id: None,
          provider_id: None,
          upstream_id: None,
          requested_model: None,
          upstream_model: None,
          requested_operation: None,
          upstream_operation: None,
        },
      }))
      .await
      .unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::AttemptRequest(AttemptHttpRequest {
        attempt: AttemptNo::FIRST,
        request: HttpRequestSnapshot {
          method: "GET".into(),
          uri: CapturedUri::exact("https://upstream.example/"),
          headers: CapturedHeaders::default(),
          body: BodyCapture::Absent,
        },
      }))
      .await
      .unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
        attempt: AttemptNo::FIRST,
        response: HttpResponseHead {
          status,
          headers: CapturedHeaders::default(),
        },
      }))
      .await
      .unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status,
        headers: CapturedHeaders::default(),
      }))
      .await
      .unwrap();
    (lifecycle, hub)
  }

  fn traffic(events: &Arc<Mutex<Vec<GatewayEvent>>>) -> Vec<TrafficEvent> {
    events
      .lock()
      .unwrap()
      .iter()
      .filter_map(|event| match event {
        GatewayEvent::Traffic(event) => Some(event.clone()),
        _ => None,
      })
      .collect()
  }

  async fn next_frame(body: &mut DownstreamLifecycleBody<TestBody>) -> Option<Result<Frame<Bytes>, TestBodyError>> {
    std::future::poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await
  }

  async fn next_attempt_frame(
    body: &mut DownstreamLifecycleBody<crate::runtime::attempts::ObservedUpstreamBody<TestBody>>,
  ) -> Option<Result<Frame<Bytes>, TestBodyError>> {
    std::future::poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await
  }

  #[tokio::test]
  async fn preserves_data_trailers_and_size_hint_while_capturing_a_bounded_prefix() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (lifecycle, hub) = lifecycle(&events, 200).await;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", HeaderValue::from_static("ok"));
    let body = TestBody::new([
      TestFrame::Data(b"abc"),
      TestFrame::Data(b"defg"),
      TestFrame::Trailers(trailers),
    ])
    .with_exact_size(7);
    let mut observed = DownstreamLifecycleBody::new(body, lifecycle, termination(RequestOutcome::Delivered, 200), 4);

    assert_eq!(observed.size_hint().exact(), Some(7));
    assert_eq!(
      next_frame(&mut observed).await.unwrap().unwrap().data_ref().unwrap(),
      "abc"
    );
    assert_eq!(
      next_frame(&mut observed).await.unwrap().unwrap().data_ref().unwrap(),
      "defg"
    );
    let trailers = next_frame(&mut observed)
      .await
      .unwrap()
      .unwrap()
      .into_trailers()
      .unwrap();
    assert_eq!(trailers["x-checksum"], "ok");
    assert!(next_frame(&mut observed).await.is_none());
    drop(observed);
    hub.shutdown().await.unwrap();

    let traffic = traffic(&events);
    assert_eq!(
      traffic.iter().map(|event| event.sequence).collect::<Vec<_>>(),
      vec![1, 2, 3, 4, 5, 6]
    );
    assert!(matches!(
      &traffic[2].kind,
      TrafficEventKind::BodyProgress(BodyProgress {
        leg: BodyLeg::Downstream,
        bytes_seen: 3,
        chunks: 1,
      })
    ));
    assert!(matches!(
      &traffic[3].kind,
      TrafficEventKind::BodyProgress(BodyProgress {
        leg: BodyLeg::Downstream,
        bytes_seen: 7,
        chunks: 2,
      })
    ));
    assert!(matches!(
      &traffic[4].kind,
      TrafficEventKind::BodyFinished(BodyFinished {
        capture: BodyCapture::Truncated { prefix, bytes_seen: 7 },
        result: BodyResult::Complete,
        ..
      }) if prefix.as_ref() == b"abcd"
    ));
  }

  #[tokio::test]
  async fn complete_body_capture_is_emitted_at_eof() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (lifecycle, hub) = lifecycle(&events, 200).await;
    let mut observed = DownstreamLifecycleBody::new(
      TestBody::new([TestFrame::Data(b"complete")]),
      lifecycle,
      termination(RequestOutcome::Delivered, 200),
      32,
    );

    assert!(next_frame(&mut observed).await.unwrap().is_ok());
    assert!(next_frame(&mut observed).await.is_none());
    hub.shutdown().await.unwrap();

    assert!(traffic(&events).iter().any(|event| matches!(
      &event.kind,
      TrafficEventKind::BodyFinished(BodyFinished {
        capture: BodyCapture::Complete(body),
        result: BodyResult::Complete,
        ..
      }) if body.as_ref() == b"complete"
    )));
  }

  #[tokio::test]
  async fn known_empty_body_stays_pollable_until_complete_is_published() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (lifecycle, hub) = lifecycle(&events, 200).await;
    let mut observed = DownstreamLifecycleBody::new(
      TestBody::new([]),
      lifecycle,
      termination(RequestOutcome::Delivered, 200),
      0,
    );

    assert!(!observed.is_end_stream());
    assert!(next_frame(&mut observed).await.is_none());
    assert!(observed.is_end_stream());
    hub.shutdown().await.unwrap();

    assert!(traffic(&events).iter().any(|event| matches!(
      &event.kind,
      TrafficEventKind::BodyFinished(BodyFinished {
        capture: BodyCapture::Complete(body),
        result: BodyResult::Complete,
        ..
      }) if body.is_empty()
    )));
  }

  #[tokio::test]
  async fn body_error_is_forwarded_and_terminalized_with_the_retained_prefix() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (lifecycle, hub) = lifecycle(&events, 502).await;
    let mut observed = DownstreamLifecycleBody::new(
      TestBody::new([
        TestFrame::Data(b"abc"),
        TestFrame::Error(TestBodyError("upstream reset")),
      ]),
      lifecycle,
      termination(RequestOutcome::Failed, 502),
      8,
    );

    assert!(next_frame(&mut observed).await.unwrap().is_ok());
    let error = next_frame(&mut observed).await.unwrap().unwrap_err();
    assert_eq!(error.to_string(), "upstream reset");
    assert!(next_frame(&mut observed).await.is_none());
    hub.shutdown().await.unwrap();

    let traffic = traffic(&events);
    assert!(traffic.iter().any(|event| matches!(
      &event.kind,
      TrafficEventKind::BodyFinished(BodyFinished {
        capture: BodyCapture::Truncated { prefix, bytes_seen: 3 },
        result: BodyResult::Failed(EventFailure { code, message }),
        ..
      }) if prefix.as_ref() == b"abc"
        && code.as_str() == DOWNSTREAM_BODY_FAILURE_CODE
        && message.as_str() == DOWNSTREAM_BODY_FAILURE_MESSAGE
    )));
  }

  #[tokio::test]
  async fn drop_records_cancellation_without_rewriting_the_supplied_completion() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let status = StatusCode::IM_A_TEAPOT.as_u16();
    let (lifecycle, hub) = lifecycle(&events, status).await;
    let mut observed = DownstreamLifecycleBody::new(
      TestBody::new([TestFrame::Data(b"abc"), TestFrame::Pending]),
      lifecycle,
      termination(RequestOutcome::Rejected, status),
      8,
    );

    assert!(next_frame(&mut observed).await.unwrap().is_ok());
    drop(observed);
    hub.shutdown().await.unwrap();

    let traffic = traffic(&events);
    assert!(traffic.iter().any(|event| matches!(
      &event.kind,
      TrafficEventKind::BodyFinished(BodyFinished {
        capture: BodyCapture::Truncated { prefix, bytes_seen: 3 },
        result: BodyResult::Cancelled,
        ..
      }) if prefix.as_ref() == b"abc"
    )));
    assert!(matches!(
      traffic.last().map(|event| &event.kind),
      Some(TrafficEventKind::Finished(finished))
        if finished.outcome == RequestOutcome::Rejected
          && finished.downstream_status == Some(StatusCode::IM_A_TEAPOT.as_u16())
    ));
  }

  #[tokio::test]
  async fn dropping_a_buffered_delivered_body_replaces_the_provisional_success() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (lifecycle, hub) = lifecycle(&events, 200).await;
    let mut observed = DownstreamLifecycleBody::new(
      TestBody::new([TestFrame::Data(b"abc"), TestFrame::Pending]),
      lifecycle,
      termination(RequestOutcome::Delivered, 200),
      8,
    );

    assert!(next_frame(&mut observed).await.unwrap().is_ok());
    drop(observed);
    hub.shutdown().await.unwrap();

    assert!(matches!(
      traffic(&events).last().map(|event| &event.kind),
      Some(TrafficEventKind::Finished(finished)) if finished.outcome == RequestOutcome::Cancelled
    ));
  }

  #[tokio::test]
  async fn dropped_live_attempt_closes_once_before_request_cancellation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (lifecycle, hub) = attempt_lifecycle(&events, 200).await;
    let upstream = crate::runtime::attempts::UpstreamBodyObservation::new(AttemptNo::FIRST, 32, None, false);
    let raw = crate::runtime::attempts::ObservedUpstreamBody::new(
      TestBody::new([TestFrame::Data(b"abc"), TestFrame::Pending]),
      upstream.clone(),
    );
    let plan = AttemptBodyPlan::new(upstream, 200);
    let mut observed = DownstreamLifecycleBody::with_attempt(
      raw,
      lifecycle,
      termination(RequestOutcome::Delivered, 200),
      32,
      Some(plan),
    );

    assert!(next_attempt_frame(&mut observed).await.unwrap().is_ok());
    drop(observed);
    hub.shutdown().await.unwrap();

    let traffic = traffic(&events);
    let attempt_finishes = traffic
      .iter()
      .filter_map(|event| match &event.kind {
        TrafficEventKind::AttemptFinished(finished) => Some(finished),
        _ => None,
      })
      .collect::<Vec<_>>();
    assert_eq!(attempt_finishes.len(), 1);
    assert!(matches!(
      attempt_finishes[0],
      AttemptFinished {
        outcome: AttemptOutcome::Cancelled,
        retry: None,
        ..
      }
    ));
    let upstream_finished = traffic
      .iter()
      .position(|event| {
        matches!(
          event.kind,
          TrafficEventKind::BodyFinished(BodyFinished {
            leg: BodyLeg::Upstream { .. },
            ..
          })
        )
      })
      .unwrap();
    let attempt_finished = traffic
      .iter()
      .position(|event| matches!(event.kind, TrafficEventKind::AttemptFinished(_)))
      .unwrap();
    let downstream_finished = traffic
      .iter()
      .position(|event| {
        matches!(
          event.kind,
          TrafficEventKind::BodyFinished(BodyFinished {
            leg: BodyLeg::Downstream,
            ..
          })
        )
      })
      .unwrap();
    assert!(upstream_finished < attempt_finished);
    assert!(attempt_finished < downstream_finished);
    assert!(matches!(
      traffic.last().map(|event| &event.kind),
      Some(TrafficEventKind::Finished(finished)) if finished.outcome == RequestOutcome::Cancelled
    ));
  }

  #[tokio::test]
  async fn failed_live_attempt_replaces_delivered_request_outcome() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (lifecycle, hub) = attempt_lifecycle(&events, 200).await;
    let upstream = crate::runtime::attempts::UpstreamBodyObservation::new(AttemptNo::FIRST, 32, None, false);
    let raw = crate::runtime::attempts::ObservedUpstreamBody::new(
      TestBody::new([
        TestFrame::Data(b"abc"),
        TestFrame::Error(TestBodyError("upstream reset")),
      ]),
      upstream.clone(),
    );
    let plan = AttemptBodyPlan::new(upstream, 200);
    let mut observed = DownstreamLifecycleBody::with_attempt(
      raw,
      lifecycle,
      termination(RequestOutcome::Delivered, 200),
      32,
      Some(plan),
    );

    assert!(next_attempt_frame(&mut observed).await.unwrap().is_ok());
    assert_eq!(
      next_attempt_frame(&mut observed)
        .await
        .unwrap()
        .unwrap_err()
        .to_string(),
      "upstream reset"
    );
    hub.shutdown().await.unwrap();

    let traffic = traffic(&events);
    assert!(matches!(
      traffic.iter().find_map(|event| match &event.kind {
        TrafficEventKind::AttemptFinished(finished) => Some(finished),
        _ => None,
      }),
      Some(AttemptFinished {
        outcome: AttemptOutcome::Failed,
        retry: None,
        ..
      })
    ));
    assert!(matches!(
      traffic.last().map(|event| &event.kind),
      Some(TrafficEventKind::Finished(finished)) if finished.outcome == RequestOutcome::Failed
    ));
  }
}

//! Shared downstream body capture and request-terminal ownership.
//!
//! HTTP listener bodies and embedded managed streams use different polling
//! traits, but their lifecycle semantics must remain identical. This state
//! owns the common progress, bounded capture, attempt ordering, completion
//! rewrite, and drop-cancellation behavior.

use super::attempts::AttemptBodyPlan;
use bytes::{Bytes, BytesMut};
use tokn_events::{BodyCapture, BodyFinished, BodyLeg, BodyProgress, BodyResult, EventFailure, RequestOutcome};
use tokn_requests::{
  ProgressPublishError, RequestCompletion, RequestLifecycle, RequestTerminalEvent, RequestTermination,
};

pub(crate) const DOWNSTREAM_BODY_FAILURE_CODE: &str = "downstream_body_read_failed";
pub(crate) const DOWNSTREAM_BODY_FAILURE_MESSAGE: &str = "the downstream response body could not be read";

pub(crate) fn downstream_body_failure() -> EventFailure {
  EventFailure {
    code: DOWNSTREAM_BODY_FAILURE_CODE.into(),
    message: DOWNSTREAM_BODY_FAILURE_MESSAGE.into(),
  }
}

pub(crate) struct DownstreamLifecycle {
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

impl DownstreamLifecycle {
  pub(crate) fn new(
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

  pub(crate) fn is_active(&self) -> bool {
    self.lifecycle.is_some()
  }

  pub(crate) fn publish_attempt_progress(&mut self) -> Result<(), ProgressPublishError> {
    if !self.attempt_progress_available {
      return Ok(());
    }
    let Some(progress) = self.attempt.as_ref().and_then(AttemptBodyPlan::take_progress) else {
      return Ok(());
    };
    let Some(lifecycle) = &mut self.lifecycle else {
      return Ok(());
    };
    if let Err(error) = lifecycle.try_publish_progress(progress) {
      self.attempt_progress_available = false;
      return Err(error);
    }
    Ok(())
  }

  pub(crate) fn observe_data(&mut self, data: &Bytes) -> Result<(), ProgressPublishError> {
    let chunk_bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
    self.bytes_seen = self.bytes_seen.saturating_add(chunk_bytes);
    self.chunks = self.chunks.saturating_add(1);

    let retained = self.capture_limit.saturating_sub(self.capture.len()).min(data.len());
    self.capture.extend_from_slice(&data[..retained]);

    if !self.progress_available {
      return Ok(());
    }
    let progress = BodyProgress {
      leg: BodyLeg::Downstream,
      bytes_seen: self.bytes_seen,
      chunks: self.chunks,
    };
    let Some(lifecycle) = &mut self.lifecycle else {
      return Ok(());
    };
    if let Err(error) = lifecycle.try_publish_progress(progress) {
      self.progress_available = false;
      return Err(error);
    }
    Ok(())
  }

  pub(crate) fn finish_complete(&mut self) -> Result<(), tokn_events::TerminalSubmitError> {
    let capture = if self.bytes_seen == u64::try_from(self.capture.len()).unwrap_or(u64::MAX) {
      BodyCapture::Complete(self.capture.split().freeze())
    } else {
      self.incomplete_capture()
    };
    self.finish(capture, BodyResult::Complete)
  }

  pub(crate) fn finish_failed(&mut self, failure: EventFailure) -> Result<(), tokn_events::TerminalSubmitError> {
    let capture = self.incomplete_capture();
    self.finish(capture, BodyResult::Failed(failure))
  }

  pub(crate) fn finish_cancelled(&mut self) -> Result<(), tokn_events::TerminalSubmitError> {
    let capture = self.incomplete_capture();
    self.finish(capture, BodyResult::Cancelled)
  }

  pub(crate) fn finish_semantically_complete(&mut self) -> Result<(), tokn_events::TerminalSubmitError> {
    if let Some(attempt) = &self.attempt {
      attempt.mark_semantically_complete();
    }
    self.finish_complete()
  }

  fn incomplete_capture(&mut self) -> BodyCapture {
    BodyCapture::Truncated {
      prefix: self.capture.split().freeze(),
      bytes_seen: self.bytes_seen,
    }
  }

  fn finish(&mut self, capture: BodyCapture, result: BodyResult) -> Result<(), tokn_events::TerminalSubmitError> {
    let Some(lifecycle) = self.lifecycle.take() else {
      return Ok(());
    };
    let mut termination = self
      .termination
      .take()
      .expect("a live downstream lifecycle always has a terminal plan");
    if termination.completion().outcome == RequestOutcome::Delivered {
      match &result {
        BodyResult::Failed(failure) => termination.replace_completion(RequestCompletion::new(
          RequestOutcome::Failed,
          tokn_events::RequestPhase::DownstreamResponse,
          None,
          Some(failure.clone()),
        )),
        BodyResult::Cancelled => termination.replace_completion(RequestCompletion::new(
          RequestOutcome::Cancelled,
          tokn_events::RequestPhase::DownstreamResponse,
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
    lifecycle.finish(termination).map(|_| ())
  }
}

impl Drop for DownstreamLifecycle {
  fn drop(&mut self) {
    if self.is_active() {
      if let Err(error) = self.finish_cancelled() {
        tracing::warn!(error = %error, "downstream body cancellation publication failed");
      }
    }
  }
}

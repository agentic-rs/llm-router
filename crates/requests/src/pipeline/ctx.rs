//! Per-request mutable state threaded through every stage.
//!
//! `PipelineCtx` carries identifiers (request id, attempt counter), the
//! inbound [`RequestEndpoint`] (set by the runner from `RawInbound` before
//! any stage runs), and a handle to the [`EventBus`] so stages can publish
//! custom events without holding a separate reference to the bus. Stage
//! outputs are *not* stored here — they flow as function-typed return
//! values between stages — but the ctx is the right home for cross-cutting
//! state we add later (timings, cancellation tokens, etc.).

use crate::event::{CustomEvent, Event, EventBus, EventPayload, RecordEvent, StageEvent};
use crate::pipeline::config::RunConfig;
use smol_str::SmolStr;
use std::sync::Arc;
use tokn_core::event::Event as CoreEvent;
use tokn_core::request_event::RequestEndpoint;

pub struct PipelineCtx {
  pub request_id: SmolStr,
  pub attempt: u32,
  /// Inbound request identity as observed by the transport. Known router
  /// endpoints use `RequestEndpoint::Known`; opaque/custom paths may be
  /// `CustomPath`.
  pub request_endpoint: RequestEndpoint,
  pub events: Arc<EventBus>,
  /// Caller-supplied per-run config bag. Stages may read access, routing,
  /// and generation overrides from it. Empty for the default pipeline path
  /// that calls [`crate::Pipeline::run`].
  pub config: Arc<RunConfig>,
}

impl PipelineCtx {
  pub fn new(request_id: impl Into<SmolStr>, request_endpoint: RequestEndpoint, events: Arc<EventBus>) -> Self {
    Self::new_with_attempt_and_config(request_id, 0, request_endpoint, events, Arc::new(RunConfig::default()))
  }

  pub fn new_with_config(
    request_id: impl Into<SmolStr>,
    request_endpoint: RequestEndpoint,
    events: Arc<EventBus>,
    config: Arc<RunConfig>,
  ) -> Self {
    Self::new_with_attempt_and_config(request_id, 0, request_endpoint, events, config)
  }

  pub fn new_with_attempt_and_config(
    request_id: impl Into<SmolStr>,
    attempt: u32,
    request_endpoint: RequestEndpoint,
    events: Arc<EventBus>,
    config: Arc<RunConfig>,
  ) -> Self {
    Self {
      request_id: request_id.into(),
      attempt,
      request_endpoint,
      events,
      config,
    }
  }

  /// Publish a [`StageEvent`] tagged with the current request id and attempt.
  pub fn emit_stage(&self, payload: StageEvent) {
    self.events.emit(CoreEvent::Requests(Event {
      request_id: self.request_id.clone(),
      attempt: self.attempt,
      ts: tokn_core::util::now_unix_ms(),
      payload: EventPayload::Stage(payload),
    }));
  }

  /// Publish a [`RecordEvent`] tagged with the current request id and
  /// attempt. Used for transport-adjacent facts that live alongside the
  /// stage lifecycle, such as outbound wire-truth, inbound connection
  /// metadata, and parsed usage.
  pub fn emit_record(&self, payload: RecordEvent) {
    self.events.emit(CoreEvent::Requests(Event {
      request_id: self.request_id.clone(),
      attempt: self.attempt,
      ts: tokn_core::util::now_unix_ms(),
      payload: EventPayload::Record(payload),
    }));
  }

  /// Publish a [`CustomEvent`] from inside a stage or decorator.
  pub fn emit_custom(&self, kind: &'static str, value: impl std::any::Any + Send + Sync) {
    self.events.emit(CoreEvent::Requests(Event {
      request_id: self.request_id.clone(),
      attempt: self.attempt,
      ts: tokn_core::util::now_unix_ms(),
      payload: EventPayload::Custom(CustomEvent::new(kind, value)),
    }));
  }
}

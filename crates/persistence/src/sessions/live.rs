//! Live projection of public gateway events into the semantic sessions DB.

use super::semantic::{request_messages_from_json, response_messages_from_body};
use super::{Result, SessionsDb, TreeRequestRecord};
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::path::Path;
use tokn_events::{
  AttemptFinished, AttemptHttpRequest, AttemptNo, AttemptOutcome, AttemptStarted, BodyCapture, BodyFinished, BodyLeg,
  BodyOutcome, BodyProgress, BodyResult, ConnectAction, ConnectClosed, ConnectReady, ConsumerResult, EventConsumer,
  EventSeq, GatewayEvent, HttpResponseHead, PolicySelection, RequestAdmitted, RequestBodyObservation, RequestFinished,
  RequestId, RequestOutcome, RequestStarted, SelectedAction, TrafficEvent, TrafficEventKind,
};

const MAX_PENDING_SESSIONS: usize = 16_384;
const TERMINAL_TOMBSTONE_CAPACITY: usize = 4_096;

/// Builds semantic session trees from the public request lifecycle.
///
/// The consumer is deliberately independent from request-day persistence.
/// This preserves live sessions when raw request body storage is disabled and
/// keeps the semantic projection usable by embedded gateway runtimes.
pub struct SessionPersistenceConsumer {
  db: SessionsDb,
  pending: HashMap<RequestId, PendingSession>,
  terminal: HashMap<RequestId, u64>,
  terminal_order: VecDeque<RequestId>,
}

impl SessionPersistenceConsumer {
  /// Open the existing sessions database, applying its current migrations.
  pub fn open(path: impl AsRef<Path>) -> Result<Self> {
    Ok(Self {
      db: SessionsDb::open(path.as_ref())?,
      pending: HashMap::new(),
      terminal: HashMap::new(),
      terminal_order: VecDeque::new(),
    })
  }

  fn handle_traffic(&mut self, event: &TrafficEvent) -> SessionWriteResult {
    if event.request_id.as_str().contains(':') {
      return Err(SessionWriteError::lifecycle(
        &event.request_id,
        "base request IDs cannot contain `:` because it is reserved for persisted retry IDs",
      ));
    }
    if let Some(last_sequence) = self.terminal.get(&event.request_id).copied() {
      return if event.sequence <= last_sequence {
        Ok(())
      } else {
        Err(SessionWriteError::lifecycle(
          &event.request_id,
          format!(
            "received sequence {} after terminal sequence {last_sequence}",
            event.sequence
          ),
        ))
      };
    }

    if !self.pending.contains_key(&event.request_id) {
      let TrafficEventKind::Started(started) = &event.kind else {
        // Requests without session correlation are intentionally not retained.
        return Ok(());
      };
      return self.start_request(event, started);
    }

    if matches!(event.kind, TrafficEventKind::Finished(_)) {
      return self.finish_request(event);
    }

    let pending = self
      .pending
      .get_mut(&event.request_id)
      .expect("pending session was checked before borrowing");
    if !pending.validate_next(event)? {
      return Ok(());
    }
    if matches!(event.kind, TrafficEventKind::Started(_)) {
      return Err(SessionWriteError::lifecycle(
        &event.request_id,
        "received Started more than once",
      ));
    }
    pending.apply(event)?;
    pending.last_sequence = event.sequence;
    Ok(())
  }

  fn start_request(&mut self, event: &TrafficEvent, started: &RequestStarted) -> SessionWriteResult {
    if event.sequence != 1 {
      return Err(SessionWriteError::lifecycle(
        &event.request_id,
        format!("Started has sequence {}, expected 1", event.sequence),
      ));
    }
    let Some(session_id) = non_empty(started.correlation.session_id.as_deref()) else {
      return Ok(());
    };
    if self.pending.len() >= MAX_PENDING_SESSIONS {
      return Err(SessionWriteError::Capacity {
        limit: MAX_PENDING_SESSIONS,
      });
    }
    self.pending.insert(
      event.request_id.clone(),
      PendingSession::new(event.at_unix_ms, session_id, started),
    );
    Ok(())
  }

  fn finish_request(&mut self, event: &TrafficEvent) -> SessionWriteResult {
    let TrafficEventKind::Finished(finished) = &event.kind else {
      unreachable!("finish_request is only called for Finished events")
    };
    let record = {
      let pending = self
        .pending
        .get(&event.request_id)
        .expect("pending session was checked before terminal validation");
      if !pending.validate_next(event)? {
        return Ok(());
      }
      pending.validate_terminal(&event.request_id, finished)?;
      if finished.outcome == RequestOutcome::Delivered {
        pending.build_record(&event.request_id, finished)?
      } else {
        None
      }
    };

    if let Some(record) = record {
      self.db.record_tree(&record).map_err(SessionWriteError::Persistence)?;
    }
    let removed = self.pending.remove(&event.request_id);
    debug_assert!(removed.is_some(), "validated pending session disappeared before commit");
    self.remember_terminal(event.request_id.clone(), event.sequence);
    Ok(())
  }

  fn remember_terminal(&mut self, request_id: RequestId, sequence: u64) {
    self.terminal.insert(request_id.clone(), sequence);
    self.terminal_order.push_back(request_id);
    while self.terminal_order.len() > TERMINAL_TOMBSTONE_CAPACITY {
      if let Some(expired) = self.terminal_order.pop_front() {
        self.terminal.remove(&expired);
      }
    }
  }
}

impl EventConsumer<GatewayEvent> for SessionPersistenceConsumer {
  fn name(&self) -> &str {
    "session-persistence"
  }

  fn handle(&mut self, _sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
    let GatewayEvent::Traffic(event) = event else {
      return Ok(());
    };
    self
      .handle_traffic(event)
      .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
  }

  fn flush(&mut self) -> ConsumerResult {
    let incomplete = self.pending.len();
    self.pending.clear();
    self.terminal.clear();
    self.terminal_order.clear();
    if incomplete == 0 {
      Ok(())
    } else {
      Err(Box::new(SessionWriteError::Incomplete { count: incomplete }))
    }
  }
}

struct PendingSession {
  started_at_ms: i64,
  last_sequence: u64,
  session_id: String,
  thread_id: Option<String>,
  parent_thread_id: Option<String>,
  parent_session_id: Option<String>,
  endpoint: Option<String>,
  requested_model: Option<String>,
  request_body: SemanticRequestBody,
  admission_observed: bool,
  policy: Option<SelectedTransport>,
  request_body_observed: bool,
  attempts: BTreeMap<AttemptNo, PendingAttempt>,
  accepted_attempt: Option<AttemptNo>,
  transport: TransportState,
  connect_authority: Option<String>,
  downstream_status: Option<u16>,
  downstream_body: Option<Bytes>,
  downstream_body_observed: bool,
  downstream_body_progress_observed: bool,
}

impl PendingSession {
  fn new(started_at_ms: i64, session_id: String, started: &RequestStarted) -> Self {
    Self {
      started_at_ms,
      last_sequence: 1,
      session_id,
      thread_id: non_empty(started.correlation.thread_id.as_deref()),
      parent_thread_id: non_empty(started.correlation.parent_thread_id.as_deref()),
      parent_session_id: non_empty(started.correlation.parent_session_id.as_deref()),
      endpoint: None,
      requested_model: None,
      request_body: SemanticRequestBody::Unavailable,
      admission_observed: false,
      policy: None,
      request_body_observed: false,
      attempts: BTreeMap::new(),
      accepted_attempt: None,
      transport: TransportState::Unknown,
      connect_authority: None,
      downstream_status: None,
      downstream_body: None,
      downstream_body_observed: false,
      downstream_body_progress_observed: false,
    }
  }

  fn validate_next(&self, event: &TrafficEvent) -> SessionWriteResult<bool> {
    if event.sequence <= self.last_sequence {
      return Ok(false);
    }
    let expected = self.last_sequence.saturating_add(1);
    if event.sequence != expected {
      return Err(SessionWriteError::lifecycle(
        &event.request_id,
        format!("received sequence {}, expected {expected}", event.sequence),
      ));
    }
    Ok(true)
  }

  fn apply(&mut self, event: &TrafficEvent) -> SessionWriteResult {
    match &event.kind {
      TrafficEventKind::Admitted(admitted) => self.observe_admitted(&event.request_id, admitted)?,
      TrafficEventKind::PolicySelected(selection) => self.observe_policy(&event.request_id, selection)?,
      TrafficEventKind::RequestBody(observation) => {
        self.require_http(&event.request_id, "request body")?;
        self.observe_request_body(&event.request_id, observation)?;
      }
      TrafficEventKind::AttemptStarted(started) => self.start_attempt(&event.request_id, event.at_unix_ms, started)?,
      TrafficEventKind::AttemptRequest(request) => self.observe_attempt_request(&event.request_id, request)?,
      TrafficEventKind::AttemptResponseHead(response) => {
        self.observe_attempt_head(&event.request_id, response.attempt, response.response.status)?
      }
      TrafficEventKind::BodyProgress(progress) => self.observe_body_progress(&event.request_id, progress)?,
      TrafficEventKind::BodyFinished(finished) => self.observe_body(&event.request_id, finished)?,
      TrafficEventKind::DownstreamResponseHead(response) => {
        self.observe_downstream_head(&event.request_id, response)?;
      }
      TrafficEventKind::AttemptFinished(finished) => self.finish_attempt(&event.request_id, finished)?,
      TrafficEventKind::ConnectReady(ready) => self.observe_connect_ready(&event.request_id, ready)?,
      TrafficEventKind::ConnectClosed(closed) => self.observe_connect_closed(&event.request_id, closed)?,
      // Usage can arrive after AttemptFinished in a terminal batch. Sessions do
      // not project token accounting, so preserve that valid late boundary.
      TrafficEventKind::AttemptUsage(_) => {}
      TrafficEventKind::Started(_) | TrafficEventKind::Finished(_) => {
        return Err(SessionWriteError::lifecycle(
          &event.request_id,
          "dedicated lifecycle event reached the ordinary session projector",
        ));
      }
      _ => {}
    }
    Ok(())
  }

  fn observe_admitted(&mut self, request_id: &RequestId, admitted: &RequestAdmitted) -> SessionWriteResult {
    if self.admission_observed {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "request admission was observed more than once",
      ));
    }
    match admitted {
      RequestAdmitted::Http { operation, .. } => {
        if matches!(self.policy, Some(SelectedTransport::Connect(_))) {
          return Err(SessionWriteError::lifecycle(
            request_id,
            "HTTP admission followed a CONNECT policy",
          ));
        }
        self.require_http(request_id, "HTTP admission")?;
        if let Some(operation) = operation.as_ref() {
          self.endpoint = non_empty(Some(operation.as_str()));
        }
      }
      RequestAdmitted::Connect { authority } => {
        if matches!(self.policy, Some(SelectedTransport::Http)) {
          return Err(SessionWriteError::lifecycle(
            request_id,
            "CONNECT admission followed an HTTP policy",
          ));
        }
        self.transport = match self.transport {
          TransportState::Unknown => TransportState::Connect(ConnectState::Admitted),
          TransportState::Http => {
            return Err(SessionWriteError::lifecycle(
              request_id,
              "CONNECT admission followed an HTTP lifecycle",
            ));
          }
          TransportState::Connect(_) => {
            return Err(SessionWriteError::lifecycle(
              request_id,
              "CONNECT was admitted more than once",
            ));
          }
        };
        self.connect_authority = Some(authority.to_string());
      }
      _ => {}
    }
    self.admission_observed = true;
    Ok(())
  }

  fn observe_policy(&mut self, request_id: &RequestId, selection: &PolicySelection) -> SessionWriteResult {
    if self.policy.is_some() {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "request policy was selected more than once",
      ));
    }
    match (&selection.action, self.transport) {
      (SelectedAction::Http { .. }, TransportState::Connect(_)) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "HTTP policy followed CONNECT admission",
        ));
      }
      (SelectedAction::Connect { .. }, TransportState::Http) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT policy followed an HTTP lifecycle",
        ));
      }
      _ => {}
    }
    self.policy = Some(match &selection.action {
      SelectedAction::Reject => SelectedTransport::Reject,
      SelectedAction::Http { .. } => SelectedTransport::Http,
      SelectedAction::Connect { action } => SelectedTransport::Connect(*action),
      _ => SelectedTransport::Unknown,
    });
    Ok(())
  }

  fn require_http(&mut self, request_id: &RequestId, boundary: &str) -> SessionWriteResult {
    match self.transport {
      TransportState::Unknown => self.transport = TransportState::Http,
      TransportState::Http => {}
      TransportState::Connect(_) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          format!("{boundary} followed a CONNECT lifecycle"),
        ));
      }
    }
    Ok(())
  }

  fn observe_request_body(
    &mut self,
    request_id: &RequestId,
    observation: &RequestBodyObservation,
  ) -> SessionWriteResult {
    if self.request_body_observed {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "request body was observed more than once",
      ));
    }
    self.requested_model = observation.requested_model.as_ref().map(ToString::to_string);
    self.request_body = match &observation.outcome {
      BodyOutcome::Rejected(_) => SemanticRequestBody::Rejected,
      BodyOutcome::Accepted => complete_request_body(observation)
        .map(SemanticRequestBody::Complete)
        .unwrap_or(SemanticRequestBody::Unavailable),
      _ => SemanticRequestBody::Unavailable,
    };
    self.request_body_observed = true;
    Ok(())
  }

  fn start_attempt(&mut self, request_id: &RequestId, at_unix_ms: i64, started: &AttemptStarted) -> SessionWriteResult {
    if matches!(self.transport, TransportState::Connect(_))
      || matches!(
        self.policy,
        Some(SelectedTransport::Reject | SelectedTransport::Connect(_))
      )
    {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!(
          "attempt {} followed a non-HTTP policy or CONNECT lifecycle",
          started.attempt
        ),
      ));
    }
    let expected_attempt = u32::try_from(self.attempts.len()).unwrap_or(u32::MAX).saturating_add(1);
    if started.attempt.get() != expected_attempt {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!("opened attempt {}, expected {expected_attempt}", started.attempt),
      ));
    }
    if let Some((previous_no, previous)) = self.attempts.last_key_value() {
      if !previous.finished {
        return Err(SessionWriteError::lifecycle(
          request_id,
          format!(
            "opened attempt {} before attempt {previous_no} completed",
            started.attempt
          ),
        ));
      }
      if !previous.retry_planned {
        return Err(SessionWriteError::lifecycle(
          request_id,
          format!(
            "opened attempt {} without a retry decision from attempt {previous_no}",
            started.attempt
          ),
        ));
      }
    }
    if let Some(operation) = started.target.requested_operation.as_ref() {
      if self.endpoint.is_none() {
        self.endpoint = non_empty(Some(operation.as_str()));
      }
    }
    self.transport = TransportState::Http;
    self.attempts.insert(
      started.attempt,
      PendingAttempt {
        started_at_ms: at_unix_ms,
        account_id: started.target.account_id.as_ref().map(ToString::to_string),
        provider_id: started.target.provider_id.as_ref().map(ToString::to_string),
        requested_model: started.target.requested_model.as_ref().map(ToString::to_string),
        requested_operation: started.target.requested_operation.as_ref().map(ToString::to_string),
        request_observed: false,
        wire_status: None,
        terminal_status: None,
        upstream_body: None,
        upstream_body_observed: false,
        finished: false,
        retry_planned: false,
      },
    );
    Ok(())
  }

  fn observe_attempt_request(&mut self, request_id: &RequestId, request: &AttemptHttpRequest) -> SessionWriteResult {
    let attempt = self.open_attempt_mut(request_id, request.attempt, "request snapshot")?;
    if attempt.request_observed {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!("attempt {} request was observed more than once", request.attempt),
      ));
    }
    attempt.request_observed = true;
    Ok(())
  }

  fn observe_attempt_head(&mut self, request_id: &RequestId, attempt: AttemptNo, status: u16) -> SessionWriteResult {
    let attempt_state = self.open_attempt_mut(request_id, attempt, "response head")?;
    if attempt_state.wire_status.is_some() {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!("attempt {attempt} response head was observed more than once"),
      ));
    }
    attempt_state.wire_status = Some(status);
    Ok(())
  }

  fn observe_body_progress(&mut self, request_id: &RequestId, progress: &BodyProgress) -> SessionWriteResult {
    match progress.leg {
      BodyLeg::Upstream { attempt } => {
        let attempt_state = self.open_attempt_mut(request_id, attempt, "upstream body progress")?;
        if attempt_state.upstream_body_observed {
          return Err(SessionWriteError::lifecycle(
            request_id,
            format!("attempt {attempt} body progress followed body completion"),
          ));
        }
      }
      BodyLeg::Downstream => {
        self.require_http(request_id, "downstream body progress")?;
        if self.downstream_body_observed {
          return Err(SessionWriteError::lifecycle(
            request_id,
            "downstream body progress followed body completion",
          ));
        }
        self.downstream_body_progress_observed = true;
      }
      _ => {}
    }
    Ok(())
  }

  fn observe_body(&mut self, request_id: &RequestId, finished: &BodyFinished) -> SessionWriteResult {
    let body = if matches!(finished.result, BodyResult::Complete) {
      complete_response_body(&finished.capture)
    } else {
      None
    };
    match finished.leg {
      BodyLeg::Upstream { attempt } => {
        let attempt_state = self.open_attempt_mut(request_id, attempt, "upstream body")?;
        if attempt_state.upstream_body_observed {
          return Err(SessionWriteError::lifecycle(
            request_id,
            format!("attempt {attempt} body finished more than once"),
          ));
        }
        attempt_state.upstream_body = body;
        attempt_state.upstream_body_observed = true;
      }
      BodyLeg::Downstream => {
        self.require_http(request_id, "downstream body completion")?;
        if self.downstream_body_observed {
          return Err(SessionWriteError::lifecycle(
            request_id,
            "downstream body finished more than once",
          ));
        }
        self.downstream_body = body;
        self.downstream_body_observed = true;
      }
      _ => {}
    }
    Ok(())
  }

  fn observe_downstream_head(&mut self, request_id: &RequestId, response: &HttpResponseHead) -> SessionWriteResult {
    self.require_http(request_id, "downstream response head")?;
    if self.downstream_status.is_some() {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "downstream response head was observed more than once",
      ));
    }
    self.downstream_status = Some(response.status);
    Ok(())
  }

  fn finish_attempt(&mut self, request_id: &RequestId, finished: &AttemptFinished) -> SessionWriteResult {
    let attempt = self.attempt_mut(request_id, finished.attempt)?;
    if attempt.finished {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!("attempt {} finished more than once", finished.attempt),
      ));
    }
    if let (Some(observed), Some(summary)) = (attempt.wire_status, finished.upstream_status) {
      if observed != summary {
        return Err(SessionWriteError::lifecycle(
          request_id,
          format!(
            "attempt {} finished with status {summary} after observing {observed}",
            finished.attempt
          ),
        ));
      }
    }
    attempt.terminal_status = finished.upstream_status;
    attempt.finished = true;
    attempt.retry_planned = finished.retry.is_some();
    if finished.outcome == AttemptOutcome::Response && finished.retry.is_none() {
      self.accepted_attempt = Some(finished.attempt);
    }
    Ok(())
  }

  fn observe_connect_ready(&mut self, request_id: &RequestId, ready: &ConnectReady) -> SessionWriteResult {
    match self.transport {
      TransportState::Connect(ConnectState::Admitted) => {}
      TransportState::Unknown => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT became ready before CONNECT admission",
        ));
      }
      TransportState::Http => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT became ready after an HTTP lifecycle",
        ));
      }
      TransportState::Connect(ConnectState::Ready(_)) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT became ready more than once",
        ));
      }
      TransportState::Connect(ConnectState::Closed(_)) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT became ready after it closed",
        ));
      }
    }
    if ready.action == ConnectAction::Reject {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "rejected CONNECT cannot become ready",
      ));
    }
    match self.policy {
      Some(SelectedTransport::Connect(action)) if action == ready.action => {}
      Some(SelectedTransport::Connect(_)) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT ready action differs from the selected CONNECT policy",
        ));
      }
      Some(_) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT became ready after a non-CONNECT policy",
        ));
      }
      None => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT became ready before CONNECT policy selection",
        ));
      }
    }
    if self.connect_authority.as_deref() != Some(ready.authority.as_str()) {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "CONNECT ready authority differs from CONNECT admission",
      ));
    }
    if self.downstream_status.is_some() || self.downstream_body_observed || self.downstream_body_progress_observed {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "CONNECT became ready after an HTTP response boundary",
      ));
    }
    self.downstream_status = Some(200);
    self.transport = TransportState::Connect(ConnectState::Ready(ready.action));
    Ok(())
  }

  fn observe_connect_closed(&mut self, request_id: &RequestId, closed: &ConnectClosed) -> SessionWriteResult {
    self.transport = match self.transport {
      TransportState::Connect(ConnectState::Ready(action)) if action == closed.action => {
        TransportState::Connect(ConnectState::Closed(action))
      }
      TransportState::Connect(ConnectState::Ready(action)) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          format!(
            "CONNECT closed as {:?} after becoming ready as {action:?}",
            closed.action
          ),
        ));
      }
      TransportState::Unknown | TransportState::Connect(ConnectState::Admitted) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT closed before it became ready",
        ));
      }
      TransportState::Http => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT closed after an HTTP lifecycle",
        ));
      }
      TransportState::Connect(ConnectState::Closed(_)) => {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "CONNECT closed more than once",
        ));
      }
    };
    Ok(())
  }

  fn attempt_mut(&mut self, request_id: &RequestId, attempt: AttemptNo) -> SessionWriteResult<&mut PendingAttempt> {
    self
      .attempts
      .get_mut(&attempt)
      .ok_or_else(|| SessionWriteError::lifecycle(request_id, format!("event refers to unopened attempt {attempt}")))
  }

  fn open_attempt_mut(
    &mut self,
    request_id: &RequestId,
    attempt: AttemptNo,
    boundary: &str,
  ) -> SessionWriteResult<&mut PendingAttempt> {
    let attempt_state = self.attempt_mut(request_id, attempt)?;
    if attempt_state.finished {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!("attempt {attempt} received {boundary} after it finished"),
      ));
    }
    Ok(attempt_state)
  }

  fn validate_terminal(&self, request_id: &RequestId, finished: &RequestFinished) -> SessionWriteResult {
    if finished.attempt_count != self.attempts.len() as u32 {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!(
          "Finished reports {} attempts after {} AttemptStarted events",
          finished.attempt_count,
          self.attempts.len()
        ),
      ));
    }
    if let Some((attempt, _)) = self.attempts.iter().find(|(_, attempt)| !attempt.finished) {
      return Err(SessionWriteError::lifecycle(
        request_id,
        format!("attempt {attempt} remained open at Finished"),
      ));
    }
    if let TransportState::Connect(ConnectState::Ready(_)) = self.transport {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "request finished before CONNECT closed",
      ));
    }
    if matches!(self.transport, TransportState::Connect(ConnectState::Admitted))
      && finished.outcome == RequestOutcome::Delivered
    {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "CONNECT was delivered before it became ready and closed",
      ));
    }
    if let (Some(observed), Some(summary)) = (self.downstream_status, finished.downstream_status) {
      if observed != summary {
        return Err(SessionWriteError::lifecycle(
          request_id,
          format!("request finished with status {summary} after observing {observed}"),
        ));
      }
    }
    if finished.outcome == RequestOutcome::Delivered && finished.attempt_count > 0 && self.accepted_attempt.is_none() {
      return Err(SessionWriteError::lifecycle(
        request_id,
        "Delivered request has no final response attempt",
      ));
    }
    if finished.outcome == RequestOutcome::Delivered {
      let final_attempt = self.attempts.last_key_value().map(|(attempt, _)| *attempt);
      if self.accepted_attempt != final_attempt {
        return Err(SessionWriteError::lifecycle(
          request_id,
          "Delivered request accepted a response from a non-final attempt",
        ));
      }
    }
    Ok(())
  }

  fn build_record(
    &self,
    request_id: &RequestId,
    finished: &RequestFinished,
  ) -> SessionWriteResult<Option<TreeRequestRecord>> {
    if matches!(self.request_body, SemanticRequestBody::Rejected) {
      return Ok(None);
    }
    let Some(attempt_no) = self.accepted_attempt else {
      return Ok(None);
    };
    let attempt = self
      .attempts
      .get(&attempt_no)
      .ok_or_else(|| SessionWriteError::lifecycle(request_id, format!("accepted attempt {attempt_no} disappeared")))?;
    let Some(endpoint) = self.endpoint.as_ref().or(attempt.requested_operation.as_ref()).cloned() else {
      return Ok(None);
    };
    let request_messages = match &self.request_body {
      SemanticRequestBody::Complete(body) => {
        let Ok(body) = serde_json::from_slice(body) else {
          // A body parse failure must never create a partial semantic node.
          return Ok(None);
        };
        request_messages_from_json(&endpoint, &body)
      }
      SemanticRequestBody::Unavailable => Vec::new(),
      SemanticRequestBody::Rejected => unreachable!("rejected bodies return before semantic reduction"),
    };
    let response_body = self
      .downstream_body
      .as_ref()
      .or(attempt.upstream_body.as_ref())
      .map_or(&[][..], Bytes::as_ref);
    let response_messages = response_messages_from_body(response_body);
    if request_messages.is_empty() && response_messages.is_empty() {
      return Ok(None);
    }

    Ok(Some(TreeRequestRecord {
      ts: attempt.started_at_ms.max(self.started_at_ms),
      session_id: self.session_id.clone(),
      thread_id: self.thread_id.clone(),
      parent_thread_id: self.parent_thread_id.clone(),
      parent_session_id: self.parent_session_id.clone(),
      request_id: attempt_request_id(request_id, attempt_no),
      endpoint,
      status: self
        .downstream_status
        .or(finished.downstream_status)
        .or(attempt.wire_status)
        .or(attempt.terminal_status),
      account_id: attempt.account_id.clone(),
      provider_id: attempt.provider_id.clone(),
      model: attempt.requested_model.clone().or_else(|| self.requested_model.clone()),
      request_messages,
      response_messages,
    }))
  }
}

struct PendingAttempt {
  started_at_ms: i64,
  account_id: Option<String>,
  provider_id: Option<String>,
  requested_model: Option<String>,
  requested_operation: Option<String>,
  request_observed: bool,
  wire_status: Option<u16>,
  terminal_status: Option<u16>,
  upstream_body: Option<Bytes>,
  upstream_body_observed: bool,
  finished: bool,
  retry_planned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedTransport {
  Reject,
  Http,
  Connect(ConnectAction),
  Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportState {
  Unknown,
  Http,
  Connect(ConnectState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectState {
  Admitted,
  Ready(ConnectAction),
  Closed(ConnectAction),
}

enum SemanticRequestBody {
  Unavailable,
  Complete(Bytes),
  Rejected,
}

fn complete_request_body(observation: &RequestBodyObservation) -> Option<Bytes> {
  match observation.decoded.as_ref() {
    Some(BodyCapture::Complete(body)) => Some(body.clone()),
    Some(_) => None,
    None => match &observation.wire {
      BodyCapture::Complete(body) => Some(body.clone()),
      _ => None,
    },
  }
}

fn complete_response_body(capture: &BodyCapture) -> Option<Bytes> {
  match capture {
    BodyCapture::Absent => Some(Bytes::new()),
    BodyCapture::Complete(body) => Some(body.clone()),
    _ => None,
  }
}

fn attempt_request_id(request_id: &RequestId, attempt: AttemptNo) -> String {
  let suffix = attempt.get() - 1;
  if suffix == 0 {
    request_id.to_string()
  } else {
    format!("{request_id}:{suffix}")
  }
}

fn non_empty(value: Option<&str>) -> Option<String> {
  value
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_string)
}

type SessionWriteResult<T = ()> = std::result::Result<T, SessionWriteError>;

#[derive(Debug)]
enum SessionWriteError {
  Persistence(super::super::Error),
  Lifecycle { request_id: String, detail: String },
  Capacity { limit: usize },
  Incomplete { count: usize },
}

impl SessionWriteError {
  fn lifecycle(request_id: &RequestId, detail: impl Into<String>) -> Self {
    Self::Lifecycle {
      request_id: request_id.to_string(),
      detail: detail.into(),
    }
  }
}

impl fmt::Display for SessionWriteError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Persistence(source) => write!(formatter, "session persistence write failed: {source}"),
      Self::Lifecycle { request_id, detail } => {
        write!(
          formatter,
          "invalid session event lifecycle for `{request_id}`: {detail}"
        )
      }
      Self::Capacity { limit } => write!(
        formatter,
        "session persistence has reached its {limit} active-request limit"
      ),
      Self::Incomplete { count } => write!(
        formatter,
        "session persistence flushed with {count} incomplete requests"
      ),
    }
  }
}

impl Error for SessionWriteError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match self {
      Self::Persistence(source) => Some(source),
      Self::Lifecycle { .. } | Self::Capacity { .. } | Self::Incomplete { .. } => None,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;
  use tokn_events::{
    AttemptUsage, BodyOutcome, CapturedHeaders, CapturedUri, Correlation, EventFailure, HttpFamily,
    HttpRequestSnapshot, HttpResponseHead, IngressKind, RequestPhase, RequestSource, RetryDecision, TargetSelection,
    TokenUsage,
  };

  struct Harness {
    consumer: SessionPersistenceConsumer,
    request_id: RequestId,
    sequence: u64,
    at_unix_ms: i64,
  }

  impl Harness {
    fn new(request_id: &str, correlation: Correlation) -> Self {
      let mut harness = Self {
        consumer: SessionPersistenceConsumer::open(temp_db_path()).unwrap(),
        request_id: RequestId::new(request_id).unwrap(),
        sequence: 0,
        at_unix_ms: 1_000,
      };
      harness.emit(TrafficEventKind::Started(RequestStarted {
        source: RequestSource::Listener {
          listener_id: "test-listener".into(),
          ingress: IngressKind::LlmApi,
          local_addr: None,
          peer_addr: None,
        },
        http_version: Some("HTTP/1.1".into()),
        method: "POST".into(),
        target: CapturedUri::exact("/v1/responses"),
        headers: CapturedHeaders::default(),
        body_present: true,
        correlation,
      }));
      harness
    }

    fn emit(&mut self, kind: TrafficEventKind) {
      self.emit_result(kind).unwrap();
    }

    fn emit_result(&mut self, kind: TrafficEventKind) -> ConsumerResult {
      self.sequence += 1;
      self.emit_at_result(self.sequence, kind)
    }

    fn emit_at_result(&mut self, sequence: u64, kind: TrafficEventKind) -> ConsumerResult {
      self.at_unix_ms += 1;
      self.consumer.handle(
        EventSeq::ZERO,
        &GatewayEvent::Traffic(TrafficEvent {
          request_id: self.request_id.clone(),
          sequence,
          at_unix_ms: self.at_unix_ms,
          elapsed_ms: sequence,
          kind,
        }),
      )
    }

    fn admit(&mut self, operation: &str) {
      self.emit(TrafficEventKind::Admitted(RequestAdmitted::Http {
        scheme: "http".into(),
        authority: "localhost".into(),
        path_and_query: CapturedUri::exact(format!("/v1/{operation}")),
        operation: Some(operation.into()),
      }));
    }

    fn admit_connect(&mut self, authority: &str) {
      self.emit(TrafficEventKind::Admitted(RequestAdmitted::Connect {
        authority: authority.into(),
      }));
    }

    fn select_connect(&mut self, action: ConnectAction) {
      self.emit(TrafficEventKind::PolicySelected(PolicySelection {
        binding_id: Some("connect-binding".into()),
        action: SelectedAction::Connect { action },
      }));
    }

    fn ready_connect(&mut self, authority: &str, action: ConnectAction) {
      self.emit(TrafficEventKind::ConnectReady(ConnectReady {
        action,
        authority: authority.into(),
      }));
    }

    fn request_body(&mut self, body: serde_json::Value, model: &str) {
      self.request_body_result(body, model).unwrap();
    }

    fn request_body_result(&mut self, body: serde_json::Value, model: &str) -> ConsumerResult {
      let body = Bytes::from(serde_json::to_vec(&body).unwrap());
      self.emit_result(TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Complete(body.clone()),
        decoded: Some(BodyCapture::Complete(body)),
        requested_model: Some(model.into()),
        stream: Some(false),
        initiator: None,
        outcome: BodyOutcome::Accepted,
      }))
    }

    fn start_attempt(&mut self, attempt: AttemptNo, status_model: &str) {
      self.start_attempt_result(attempt, status_model).unwrap();
    }

    fn start_attempt_result(&mut self, attempt: AttemptNo, status_model: &str) -> ConsumerResult {
      self.emit_result(TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt,
        target: TargetSelection {
          family: HttpFamily::Managed,
          account_id: Some(format!("account-{}", attempt.get()).into()),
          provider_id: Some(format!("provider-{}", attempt.get()).into()),
          upstream_id: Some(format!("upstream-{}", attempt.get()).into()),
          requested_model: Some(status_model.into()),
          upstream_model: Some(format!("upstream-{status_model}").into()),
          requested_operation: Some("responses".into()),
          upstream_operation: Some("responses".into()),
        },
      }))
    }

    fn response_head(&mut self, attempt: AttemptNo, status: u16) {
      self.response_head_result(attempt, status).unwrap();
    }

    fn response_head_result(&mut self, attempt: AttemptNo, status: u16) -> ConsumerResult {
      self.emit_result(TrafficEventKind::AttemptResponseHead(
        tokn_events::AttemptHttpResponseHead {
          attempt,
          response: HttpResponseHead {
            status,
            headers: CapturedHeaders::default(),
          },
        },
      ))
    }

    fn finish_attempt(&mut self, attempt: AttemptNo, status: u16, retry: Option<RetryDecision>) {
      self.emit(TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(status),
        failure: None,
        retry,
      }));
    }

    fn finish(&mut self, outcome: RequestOutcome, status: Option<u16>, attempt_count: u32) {
      self.finish_result(outcome, status, attempt_count).unwrap();
    }

    fn finish_result(&mut self, outcome: RequestOutcome, status: Option<u16>, attempt_count: u32) -> ConsumerResult {
      self.emit_result(TrafficEventKind::Finished(RequestFinished {
        outcome,
        phase: RequestPhase::Complete,
        downstream_status: status,
        failure: None,
        attempt_count,
      }))
    }
  }

  fn ready_connect_harness(request_id: &str) -> Harness {
    let mut harness = Harness::new(
      request_id,
      Correlation {
        session_id: Some(format!("session-{request_id}").into()),
        ..Correlation::default()
      },
    );
    harness.admit_connect("example.com:443");
    harness.select_connect(ConnectAction::Tunnel);
    harness.ready_connect("example.com:443", ConnectAction::Tunnel);
    harness
  }

  #[test]
  fn delivered_four_xx_records_buffered_semantics_and_topology() {
    let mut harness = Harness::new(
      "request-buffered",
      Correlation {
        session_id: Some("session-buffered".into()),
        thread_id: Some("thread-child".into()),
        parent_thread_id: Some("thread-parent".into()),
        parent_session_id: Some("session-parent".into()),
        ..Correlation::default()
      },
    );
    harness.admit("responses");
    harness.request_body(
      json!({
        "instructions": "be concise",
        "input": [{"role": "user", "content": "hello"}]
      }),
      "model-requested",
    );
    harness.start_attempt(AttemptNo::FIRST, "model-requested");
    harness.response_head(AttemptNo::FIRST, 422);
    harness.emit(TrafficEventKind::BodyFinished(BodyFinished {
      leg: BodyLeg::Upstream {
        attempt: AttemptNo::FIRST,
      },
      capture: BodyCapture::Complete(Bytes::from_static(br#"{"output_text":"upstream"}"#)),
      result: BodyResult::Complete,
    }));
    harness.emit(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
      status: 422,
      headers: CapturedHeaders::default(),
    }));
    harness.emit(TrafficEventKind::BodyFinished(BodyFinished {
      leg: BodyLeg::Downstream,
      capture: BodyCapture::Complete(Bytes::from_static(br#"{"output_text":"downstream"}"#)),
      result: BodyResult::Complete,
    }));
    harness.finish_attempt(AttemptNo::FIRST, 422, None);
    harness.finish(RequestOutcome::Delivered, Some(422), 1);

    let node = harness
      .consumer
      .db
      .conn
      .query_row(
        "SELECT request_id, endpoint, status, account_id, provider_id, model, thread_id
         FROM session_nodes WHERE session_id = 'session-buffered'",
        [],
        |row| {
          Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
          ))
        },
      )
      .unwrap();
    assert_eq!(
      node,
      (
        "request-buffered".into(),
        "responses".into(),
        422,
        "account-1".into(),
        "provider-1".into(),
        "model-requested".into(),
        "thread-child".into(),
      )
    );
    let thread = harness
      .consumer
      .db
      .conn
      .query_row(
        "SELECT parent_thread_id, source FROM session_threads
         WHERE session_id = 'session-buffered' AND thread_id = 'thread-child'",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
      )
      .unwrap();
    assert_eq!(thread, ("thread-parent".into(), "thread-header".into()));
    let relation: String = harness
      .consumer
      .db
      .conn
      .query_row(
        "SELECT parent_session_id FROM session_relations WHERE child_session_id = 'session-buffered'",
        [],
        |row| row.get(0),
      )
      .unwrap();
    assert_eq!(relation, "session-parent");

    let request = harness
      .consumer
      .db
      .materialize_request_messages("request-buffered")
      .unwrap();
    assert_eq!(request.len(), 2);
    assert_eq!(request[1].parts[0].content.as_ref(), b"hello");
    let response = harness
      .consumer
      .db
      .materialize_response_messages("request-buffered")
      .unwrap();
    assert_eq!(response.len(), 1);
    assert_eq!(response[0].parts[0].content.as_ref(), b"downstream");
    assert!(harness.consumer.pending.is_empty());
  }

  #[test]
  fn retry_records_only_final_attempt_and_uses_upstream_sse_fallback() {
    let mut harness = Harness::new(
      "request-retry",
      Correlation {
        session_id: Some("session-retry".into()),
        ..Correlation::default()
      },
    );
    harness.admit("responses");
    harness.request_body(json!({"input": "retry me"}), "model-retry");
    harness.start_attempt(AttemptNo::FIRST, "model-retry");
    harness.response_head(AttemptNo::FIRST, 429);
    harness.finish_attempt(
      AttemptNo::FIRST,
      429,
      Some(RetryDecision {
        delay_ms: Some(10),
        reason: EventFailure {
          code: "rate_limited".into(),
          message: "retry another account".into(),
        },
      }),
    );

    let second = AttemptNo::new(2).unwrap();
    harness.start_attempt(second, "model-retry");
    harness.response_head(second, 200);
    harness.emit(TrafficEventKind::BodyFinished(BodyFinished {
      leg: BodyLeg::Upstream { attempt: second },
      capture: BodyCapture::Complete(Bytes::from_static(
        b"event: response.output_text.delta\ndata: {\"delta\":\"final answer\"}\n\n",
      )),
      result: BodyResult::Complete,
    }));
    harness.finish_attempt(second, 200, None);
    harness.finish(RequestOutcome::Delivered, Some(200), 2);

    let request_ids = harness
      .consumer
      .db
      .conn
      .prepare("SELECT request_id FROM session_nodes ORDER BY request_id")
      .unwrap()
      .query_map([], |row| row.get::<_, String>(0))
      .unwrap()
      .collect::<rusqlite::Result<Vec<_>>>()
      .unwrap();
    assert_eq!(request_ids, vec!["request-retry:1"]);
    let response = harness
      .consumer
      .db
      .materialize_response_messages("request-retry:1")
      .unwrap();
    assert_eq!(response[0].parts[0].content.as_ref(), b"final answer");
  }

  #[test]
  fn request_id_validation_reserves_the_retry_suffix_namespace() {
    let error = RequestId::new("logical-request:1").unwrap_err();
    assert!(error.to_string().contains("unsupported character at byte 15"));
  }

  #[test]
  fn attempts_must_start_at_one_and_remain_contiguous() {
    let mut harness = Harness::new(
      "request-gap",
      Correlation {
        session_id: Some("session-gap".into()),
        ..Correlation::default()
      },
    );
    let second = AttemptNo::new(2).unwrap();

    let error = harness.start_attempt_result(second, "model-gap").unwrap_err();
    assert!(error.to_string().contains("opened attempt 2, expected 1"));
    assert!(harness.consumer.pending[&harness.request_id].attempts.is_empty());
    assert_eq!(session_node_count(&harness.consumer), 0);
  }

  #[test]
  fn next_attempt_requires_the_previous_attempt_to_finish() {
    let mut harness = Harness::new(
      "request-overlap",
      Correlation {
        session_id: Some("session-overlap".into()),
        ..Correlation::default()
      },
    );
    harness.start_attempt(AttemptNo::FIRST, "model-overlap");
    let second = AttemptNo::new(2).unwrap();

    let error = harness.start_attempt_result(second, "model-overlap").unwrap_err();
    assert!(error
      .to_string()
      .contains("opened attempt 2 before attempt 1 completed"));
    assert_eq!(harness.consumer.pending[&harness.request_id].attempts.len(), 1);
    assert_eq!(session_node_count(&harness.consumer), 0);
  }

  #[test]
  fn next_attempt_requires_an_explicit_retry_decision() {
    let mut harness = Harness::new(
      "request-no-retry-decision",
      Correlation {
        session_id: Some("session-no-retry-decision".into()),
        ..Correlation::default()
      },
    );
    harness.start_attempt(AttemptNo::FIRST, "model-no-retry-decision");
    harness.finish_attempt(AttemptNo::FIRST, 503, None);
    let second = AttemptNo::new(2).unwrap();

    let error = harness
      .start_attempt_result(second, "model-no-retry-decision")
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("opened attempt 2 without a retry decision from attempt 1"));
    assert_eq!(harness.consumer.pending[&harness.request_id].attempts.len(), 1);
    assert_eq!(session_node_count(&harness.consumer), 0);
  }

  #[test]
  fn terminal_statuses_must_match_wire_observations_and_failed_validation_retains_state() {
    let mut upstream = Harness::new(
      "request-upstream-status-mismatch",
      Correlation {
        session_id: Some("session-upstream-status-mismatch".into()),
        ..Correlation::default()
      },
    );
    upstream.start_attempt(AttemptNo::FIRST, "model-status");
    upstream.response_head(AttemptNo::FIRST, 200);
    let error = upstream
      .emit_result(TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(503),
        failure: None,
        retry: None,
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 finished with status 503 after observing 200"));
    let attempt = &upstream.consumer.pending[&upstream.request_id].attempts[&AttemptNo::FIRST];
    assert_eq!(attempt.wire_status, Some(200));
    assert_eq!(attempt.terminal_status, None);
    assert!(!attempt.finished);

    let mut downstream = Harness::new(
      "request-downstream-status-mismatch",
      Correlation {
        session_id: Some("session-downstream-status-mismatch".into()),
        ..Correlation::default()
      },
    );
    downstream.admit("responses");
    downstream.request_body(json!({"input": "hello"}), "model-status");
    downstream.start_attempt(AttemptNo::FIRST, "model-status");
    downstream.response_head(AttemptNo::FIRST, 200);
    downstream.finish_attempt(AttemptNo::FIRST, 200, None);
    downstream.emit(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
      status: 200,
      headers: CapturedHeaders::default(),
    }));
    let terminal_sequence = downstream.sequence + 1;
    let error = downstream
      .emit_at_result(
        terminal_sequence,
        TrafficEventKind::Finished(RequestFinished {
          outcome: RequestOutcome::Delivered,
          phase: RequestPhase::Complete,
          downstream_status: Some(201),
          failure: None,
          attempt_count: 1,
        }),
      )
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("request finished with status 201 after observing 200"));
    assert!(downstream.consumer.pending.contains_key(&downstream.request_id));
    assert_eq!(session_node_count(&downstream.consumer), 0);

    downstream
      .emit_at_result(
        terminal_sequence,
        TrafficEventKind::Finished(RequestFinished {
          outcome: RequestOutcome::Delivered,
          phase: RequestPhase::Complete,
          downstream_status: Some(200),
          failure: None,
          attempt_count: 1,
        }),
      )
      .unwrap();
    assert!(!downstream.consumer.pending.contains_key(&downstream.request_id));
    let status: i64 = downstream
      .consumer
      .db
      .conn
      .query_row(
        "SELECT status FROM session_nodes WHERE request_id = 'request-downstream-status-mismatch'",
        [],
        |row| row.get(0),
      )
      .unwrap();
    assert_eq!(status, 200);
  }

  #[test]
  fn closed_attempt_rejects_late_response_head_and_upstream_body() {
    let mut head = Harness::new(
      "request-late-head",
      Correlation {
        session_id: Some("session-late-head".into()),
        ..Correlation::default()
      },
    );
    head.start_attempt(AttemptNo::FIRST, "model-late-head");
    head.finish_attempt(AttemptNo::FIRST, 200, None);
    let error = head
      .emit_result(TrafficEventKind::AttemptResponseHead(
        tokn_events::AttemptHttpResponseHead {
          attempt: AttemptNo::FIRST,
          response: HttpResponseHead {
            status: 200,
            headers: CapturedHeaders::default(),
          },
        },
      ))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 received response head after it finished"));

    let mut body = Harness::new(
      "request-late-body",
      Correlation {
        session_id: Some("session-late-body".into()),
        ..Correlation::default()
      },
    );
    body.start_attempt(AttemptNo::FIRST, "model-late-body");
    body.finish_attempt(AttemptNo::FIRST, 200, None);
    let error = body
      .emit_result(TrafficEventKind::BodyFinished(BodyFinished {
        leg: BodyLeg::Upstream {
          attempt: AttemptNo::FIRST,
        },
        capture: BodyCapture::Complete(Bytes::from_static(b"late")),
        result: BodyResult::Complete,
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 received upstream body after it finished"));

    let mut progress = Harness::new(
      "request-late-body-progress",
      Correlation {
        session_id: Some("session-late-body-progress".into()),
        ..Correlation::default()
      },
    );
    progress.start_attempt(AttemptNo::FIRST, "model-late-body-progress");
    progress.finish_attempt(AttemptNo::FIRST, 200, None);
    let error = progress
      .emit_result(TrafficEventKind::BodyProgress(tokn_events::BodyProgress {
        leg: BodyLeg::Upstream {
          attempt: AttemptNo::FIRST,
        },
        bytes_seen: 4,
        chunks: 1,
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 received upstream body progress after it finished"));
  }

  #[test]
  fn request_and_response_boundaries_are_one_shot() {
    let mut body = Harness::new(
      "request-duplicate-request-body",
      Correlation {
        session_id: Some("session-duplicate-request-body".into()),
        ..Correlation::default()
      },
    );
    body.admit("responses");
    body.request_body(json!({"input": "first"}), "model-first");
    let error = body
      .request_body_result(json!({"input": "second"}), "model-second")
      .unwrap_err();
    assert!(error.to_string().contains("request body was observed more than once"));
    assert_eq!(
      body.consumer.pending[&body.request_id].requested_model.as_deref(),
      Some("model-first")
    );

    let mut upstream = Harness::new(
      "request-duplicate-upstream-head",
      Correlation {
        session_id: Some("session-duplicate-upstream-head".into()),
        ..Correlation::default()
      },
    );
    upstream.start_attempt(AttemptNo::FIRST, "model-head");
    upstream.response_head(AttemptNo::FIRST, 200);
    let error = upstream.response_head_result(AttemptNo::FIRST, 200).unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 response head was observed more than once"));

    let mut downstream = Harness::new(
      "request-duplicate-downstream-head",
      Correlation {
        session_id: Some("session-duplicate-downstream-head".into()),
        ..Correlation::default()
      },
    );
    downstream.admit("responses");
    downstream.emit(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
      status: 200,
      headers: CapturedHeaders::default(),
    }));
    let error = downstream
      .emit_result(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("downstream response head was observed more than once"));
  }

  #[test]
  fn body_completion_is_one_shot_and_closes_progress() {
    let mut upstream = Harness::new(
      "request-duplicate-upstream-body",
      Correlation {
        session_id: Some("session-duplicate-upstream-body".into()),
        ..Correlation::default()
      },
    );
    upstream.start_attempt(AttemptNo::FIRST, "model-body");
    let completion = TrafficEventKind::BodyFinished(BodyFinished {
      leg: BodyLeg::Upstream {
        attempt: AttemptNo::FIRST,
      },
      capture: BodyCapture::Absent,
      result: BodyResult::Complete,
    });
    upstream.emit(completion.clone());
    let failed_sequence = upstream.sequence + 1;
    let error = upstream.emit_at_result(failed_sequence, completion).unwrap_err();
    assert!(error.to_string().contains("attempt 1 body finished more than once"));
    let error = upstream
      .emit_at_result(
        failed_sequence,
        TrafficEventKind::BodyProgress(BodyProgress {
          leg: BodyLeg::Upstream {
            attempt: AttemptNo::FIRST,
          },
          bytes_seen: 1,
          chunks: 1,
        }),
      )
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 body progress followed body completion"));

    let mut downstream = Harness::new(
      "request-duplicate-downstream-body",
      Correlation {
        session_id: Some("session-duplicate-downstream-body".into()),
        ..Correlation::default()
      },
    );
    downstream.admit("responses");
    let completion = TrafficEventKind::BodyFinished(BodyFinished {
      leg: BodyLeg::Downstream,
      capture: BodyCapture::Absent,
      result: BodyResult::Complete,
    });
    downstream.emit(completion.clone());
    let failed_sequence = downstream.sequence + 1;
    let error = downstream.emit_at_result(failed_sequence, completion).unwrap_err();
    assert!(error.to_string().contains("downstream body finished more than once"));
    let error = downstream
      .emit_at_result(
        failed_sequence,
        TrafficEventKind::BodyProgress(BodyProgress {
          leg: BodyLeg::Downstream,
          bytes_seen: 1,
          chunks: 1,
        }),
      )
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("downstream body progress followed body completion"));
  }

  #[test]
  fn attempt_request_is_one_shot_but_late_usage_remains_valid() {
    let mut request = Harness::new(
      "request-duplicate-attempt-request",
      Correlation {
        session_id: Some("session-duplicate-attempt-request".into()),
        ..Correlation::default()
      },
    );
    request.start_attempt(AttemptNo::FIRST, "model-request");
    let snapshot = TrafficEventKind::AttemptRequest(AttemptHttpRequest {
      attempt: AttemptNo::FIRST,
      request: HttpRequestSnapshot {
        method: "POST".into(),
        uri: CapturedUri::exact("https://example.com/v1/responses"),
        headers: CapturedHeaders::default(),
        body: BodyCapture::Absent,
      },
    });
    request.emit(snapshot.clone());
    let error = request.emit_result(snapshot).unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 request was observed more than once"));

    let mut usage = Harness::new(
      "request-late-session-usage",
      Correlation {
        session_id: Some("session-late-session-usage".into()),
        ..Correlation::default()
      },
    );
    usage.start_attempt(AttemptNo::FIRST, "model-usage");
    usage.finish_attempt(AttemptNo::FIRST, 200, None);
    usage.emit(TrafficEventKind::AttemptUsage(AttemptUsage {
      attempt: AttemptNo::FIRST,
      usage: TokenUsage {
        total: Some(7),
        ..TokenUsage::default()
      },
    }));
    usage.finish(RequestOutcome::Delivered, Some(200), 1);
    assert!(usage.consumer.pending.is_empty());
  }

  #[test]
  fn delivered_request_requires_a_response_from_the_final_attempt() {
    let mut harness = Harness::new(
      "request-stale-response",
      Correlation {
        session_id: Some("session-stale-response".into()),
        ..Correlation::default()
      },
    );
    harness.admit("responses");
    harness.request_body(json!({"input": "hello"}), "model-stale-response");
    harness.start_attempt(AttemptNo::FIRST, "model-stale-response");
    harness.finish_attempt(
      AttemptNo::FIRST,
      200,
      Some(RetryDecision {
        delay_ms: None,
        reason: EventFailure {
          code: "retry_selected".into(),
          message: "retry the response".into(),
        },
      }),
    );
    let second = AttemptNo::new(2).unwrap();
    harness.start_attempt(second, "model-stale-response");
    harness.emit(TrafficEventKind::AttemptFinished(AttemptFinished {
      attempt: second,
      outcome: AttemptOutcome::Failed,
      phase: RequestPhase::UpstreamResponse,
      upstream_status: None,
      failure: Some(EventFailure {
        code: "upstream_failed".into(),
        message: "the final attempt failed".into(),
      }),
      retry: None,
    }));

    let error = harness
      .finish_result(RequestOutcome::Delivered, Some(200), 2)
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("Delivered request has no final response attempt"));
    assert_eq!(session_node_count(&harness.consumer), 0);
  }

  #[test]
  fn rejected_body_and_other_non_delivered_requests_leave_no_nodes() {
    let mut rejected = Harness::new(
      "request-rejected",
      Correlation {
        session_id: Some("session-rejected".into()),
        ..Correlation::default()
      },
    );
    rejected.admit("responses");
    rejected.emit(TrafficEventKind::RequestBody(RequestBodyObservation {
      wire: BodyCapture::Complete(Bytes::from_static(b"{")),
      decoded: Some(BodyCapture::Complete(Bytes::from_static(b"{"))),
      requested_model: None,
      stream: None,
      initiator: None,
      outcome: BodyOutcome::Rejected(EventFailure {
        code: "invalid_json".into(),
        message: "request body is not valid JSON".into(),
      }),
    }));
    rejected.finish(RequestOutcome::Rejected, Some(400), 0);
    assert_eq!(session_node_count(&rejected.consumer), 0);
    assert!(rejected.consumer.pending.is_empty());

    for (request_id, outcome) in [
      ("request-failed", RequestOutcome::Failed),
      ("request-cancelled", RequestOutcome::Cancelled),
    ] {
      let mut harness = Harness::new(
        request_id,
        Correlation {
          session_id: Some(format!("session-{request_id}").into()),
          ..Correlation::default()
        },
      );
      harness.finish(outcome, None, 0);
      assert_eq!(session_node_count(&harness.consumer), 0);
      assert!(harness.consumer.pending.is_empty());
    }
  }

  #[test]
  fn connect_and_http_lifecycles_cannot_mix_and_closed_connect_leaves_no_node() {
    let mut connect_then_http = Harness::new(
      "request-connect-then-http",
      Correlation {
        session_id: Some("session-connect-then-http".into()),
        ..Correlation::default()
      },
    );
    connect_then_http.admit_connect("example.com:443");
    let error = connect_then_http
      .start_attempt_result(AttemptNo::FIRST, "model-connect")
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("attempt 1 followed a non-HTTP policy or CONNECT lifecycle"));

    let mut http_then_connect = Harness::new(
      "request-http-then-connect",
      Correlation {
        session_id: Some("session-http-then-connect".into()),
        ..Correlation::default()
      },
    );
    http_then_connect.start_attempt(AttemptNo::FIRST, "model-http");
    let error = http_then_connect
      .emit_result(TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "example.com:443".into(),
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("CONNECT became ready after an HTTP lifecycle"));

    let mut connect = Harness::new(
      "request-connect",
      Correlation {
        session_id: Some("session-connect".into()),
        ..Correlation::default()
      },
    );
    connect.admit_connect("example.com:443");
    connect.select_connect(ConnectAction::Tunnel);
    connect.ready_connect("example.com:443", ConnectAction::Tunnel);
    connect.emit(TrafficEventKind::ConnectClosed(ConnectClosed {
      action: ConnectAction::Tunnel,
      client_to_upstream_bytes: Some(10),
      upstream_to_client_bytes: Some(20),
      result: BodyResult::Complete,
    }));
    connect.finish(RequestOutcome::Delivered, Some(200), 0);
    assert!(connect.consumer.pending.is_empty());
    assert_eq!(session_node_count(&connect.consumer), 0);
  }

  #[test]
  fn connect_ready_requires_the_selected_action_and_admitted_authority() {
    let mut mismatch = Harness::new(
      "request-connect-action-mismatch",
      Correlation {
        session_id: Some("session-connect-action-mismatch".into()),
        ..Correlation::default()
      },
    );
    mismatch.admit_connect("example.com:443");
    mismatch.select_connect(ConnectAction::Intercept);
    let error = mismatch
      .emit_result(TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "example.com:443".into(),
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("CONNECT ready action differs from the selected CONNECT policy"));

    let mut rejected = Harness::new(
      "request-connect-reject-ready",
      Correlation {
        session_id: Some("session-connect-reject-ready".into()),
        ..Correlation::default()
      },
    );
    rejected.admit_connect("example.com:443");
    rejected.select_connect(ConnectAction::Reject);
    let error = rejected
      .emit_result(TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Reject,
        authority: "example.com:443".into(),
      }))
      .unwrap_err();
    assert!(error.to_string().contains("rejected CONNECT cannot become ready"));

    let mut authority = Harness::new(
      "request-connect-authority-mismatch",
      Correlation {
        session_id: Some("session-connect-authority-mismatch".into()),
        ..Correlation::default()
      },
    );
    authority.admit_connect("example.com:443");
    authority.select_connect(ConnectAction::Tunnel);
    let error = authority
      .emit_result(TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "other.example:443".into(),
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("CONNECT ready authority differs from CONNECT admission"));

    let mut generic_reject = Harness::new(
      "request-connect-generic-reject",
      Correlation {
        session_id: Some("session-connect-generic-reject".into()),
        ..Correlation::default()
      },
    );
    generic_reject.admit_connect("example.com:443");
    generic_reject.emit(TrafficEventKind::PolicySelected(PolicySelection {
      binding_id: None,
      action: SelectedAction::Reject,
    }));
    let error = generic_reject
      .emit_result(TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "example.com:443".into(),
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("CONNECT became ready after a non-CONNECT policy"));
  }

  #[test]
  fn ready_connect_rejects_http_response_facts() {
    let mut head = ready_connect_harness("request-connect-late-head");
    let error = head
      .emit_result(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("downstream response head followed a CONNECT lifecycle"));

    let mut progress = ready_connect_harness("request-connect-late-progress");
    let error = progress
      .emit_result(TrafficEventKind::BodyProgress(BodyProgress {
        leg: BodyLeg::Downstream,
        bytes_seen: 10,
        chunks: 1,
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("downstream body progress followed a CONNECT lifecycle"));

    let mut body = ready_connect_harness("request-connect-late-body");
    let error = body
      .emit_result(TrafficEventKind::BodyFinished(BodyFinished {
        leg: BodyLeg::Downstream,
        capture: BodyCapture::Absent,
        result: BodyResult::Complete,
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("downstream body completion followed a CONNECT lifecycle"));
  }

  #[test]
  fn admission_and_policy_selection_are_one_shot() {
    let mut admission = Harness::new(
      "request-duplicate-admission",
      Correlation {
        session_id: Some("session-duplicate-admission".into()),
        ..Correlation::default()
      },
    );
    admission.admit("responses");
    let error = admission
      .emit_result(TrafficEventKind::Admitted(RequestAdmitted::Http {
        scheme: "http".into(),
        authority: "localhost".into(),
        path_and_query: CapturedUri::exact("/v1/responses"),
        operation: Some("responses".into()),
      }))
      .unwrap_err();
    assert!(error
      .to_string()
      .contains("request admission was observed more than once"));

    let mut policy = Harness::new(
      "request-duplicate-policy",
      Correlation {
        session_id: Some("session-duplicate-policy".into()),
        ..Correlation::default()
      },
    );
    policy.admit_connect("example.com:443");
    policy.select_connect(ConnectAction::Tunnel);
    let error = policy
      .emit_result(TrafficEventKind::PolicySelected(PolicySelection {
        binding_id: None,
        action: SelectedAction::Connect {
          action: ConnectAction::Tunnel,
        },
      }))
      .unwrap_err();
    assert!(error.to_string().contains("request policy was selected more than once"));
  }

  #[test]
  fn sequence_gaps_duplicates_and_terminal_tombstones_are_handled() {
    let mut harness = Harness::new(
      "request-sequences",
      Correlation {
        session_id: Some("session-sequences".into()),
        ..Correlation::default()
      },
    );
    let terminal = TrafficEventKind::Finished(RequestFinished {
      outcome: RequestOutcome::Rejected,
      phase: RequestPhase::Admission,
      downstream_status: Some(400),
      failure: None,
      attempt_count: 0,
    });

    let error = harness.emit_at_result(3, terminal.clone()).unwrap_err();
    assert!(error.to_string().contains("received sequence 3, expected 2"));
    assert!(harness.consumer.pending.contains_key(&harness.request_id));
    assert_eq!(harness.consumer.pending[&harness.request_id].last_sequence, 1);

    let admitted = TrafficEventKind::Admitted(RequestAdmitted::Http {
      scheme: "http".into(),
      authority: "localhost".into(),
      path_and_query: CapturedUri::exact("/v1/responses"),
      operation: Some("responses".into()),
    });
    harness.emit_at_result(2, admitted).unwrap();
    harness
      .emit_at_result(
        2,
        TrafficEventKind::RequestBody(RequestBodyObservation {
          wire: BodyCapture::Complete(Bytes::from_static(b"different duplicate")),
          decoded: None,
          requested_model: None,
          stream: None,
          initiator: None,
          outcome: BodyOutcome::Accepted,
        }),
      )
      .unwrap();
    assert_eq!(harness.consumer.pending[&harness.request_id].last_sequence, 2);
    assert!(matches!(
      harness.consumer.pending[&harness.request_id].request_body,
      SemanticRequestBody::Unavailable
    ));

    harness.emit_at_result(3, terminal.clone()).unwrap();
    assert!(harness.consumer.pending.is_empty());
    harness.emit_at_result(3, terminal.clone()).unwrap();
    let error = harness.emit_at_result(4, terminal).unwrap_err();
    assert!(error
      .to_string()
      .contains("received sequence 4 after terminal sequence 3"));
  }

  #[test]
  fn incomplete_request_capture_is_not_parsed_but_real_response_is_recorded() {
    let mut harness = Harness::new(
      "request-truncated",
      Correlation {
        session_id: Some("session-truncated".into()),
        ..Correlation::default()
      },
    );
    harness.admit("responses");
    harness.emit(TrafficEventKind::RequestBody(RequestBodyObservation {
      wire: BodyCapture::Truncated {
        prefix: Bytes::from_static(b"{\"input\":"),
        bytes_seen: 100,
      },
      decoded: Some(BodyCapture::Truncated {
        prefix: Bytes::from_static(b"{\"input\":"),
        bytes_seen: 100,
      }),
      requested_model: Some("model-truncated".into()),
      stream: Some(false),
      initiator: None,
      outcome: BodyOutcome::Accepted,
    }));
    harness.start_attempt(AttemptNo::FIRST, "model-truncated");
    harness.response_head(AttemptNo::FIRST, 200);
    harness.emit(TrafficEventKind::BodyFinished(BodyFinished {
      leg: BodyLeg::Downstream,
      capture: BodyCapture::Complete(Bytes::from_static(br#"{"output_text":"visible"}"#)),
      result: BodyResult::Complete,
    }));
    harness.finish_attempt(AttemptNo::FIRST, 200, None);
    harness.finish(RequestOutcome::Delivered, Some(200), 1);

    let request = harness
      .consumer
      .db
      .materialize_request_messages("request-truncated")
      .unwrap();
    let response = harness
      .consumer
      .db
      .materialize_response_messages("request-truncated")
      .unwrap();
    assert!(request.is_empty());
    assert_eq!(response[0].parts[0].content.as_ref(), b"visible");
  }

  #[test]
  fn no_session_is_not_retained_and_incomplete_flush_is_reported() {
    let mut without_session = Harness::new("request-no-session", Correlation::default());
    without_session.admit("responses");
    without_session.finish(RequestOutcome::Rejected, Some(400), 0);
    assert!(without_session.consumer.pending.is_empty());
    without_session.consumer.flush().unwrap();

    let mut incomplete = Harness::new(
      "request-incomplete",
      Correlation {
        session_id: Some("session-incomplete".into()),
        ..Correlation::default()
      },
    );
    let error = incomplete.consumer.flush().unwrap_err();
    assert!(error.to_string().contains("1 incomplete requests"));
    assert!(incomplete.consumer.pending.is_empty());
  }

  #[test]
  fn database_write_errors_propagate_to_the_event_hub() {
    let mut harness = Harness::new(
      "request-db-error",
      Correlation {
        session_id: Some("session-db-error".into()),
        ..Correlation::default()
      },
    );
    harness.admit("responses");
    harness.request_body(json!({"input": "hello"}), "model-error");
    harness.start_attempt(AttemptNo::FIRST, "model-error");
    harness.response_head(AttemptNo::FIRST, 200);
    harness.finish_attempt(AttemptNo::FIRST, 200, None);
    harness
      .consumer
      .db
      .conn
      .execute("DROP TABLE session_heads", [])
      .unwrap();

    let error = harness
      .emit_result(TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Delivered,
        phase: RequestPhase::Complete,
        downstream_status: Some(200),
        failure: None,
        attempt_count: 1,
      }))
      .unwrap_err();
    assert!(error.to_string().contains("session persistence write failed"));
    assert!(harness.consumer.pending.contains_key(&harness.request_id));
  }

  fn session_node_count(consumer: &SessionPersistenceConsumer) -> i64 {
    consumer
      .db
      .conn
      .query_row("SELECT COUNT(*) FROM session_nodes", [], |row| row.get(0))
      .unwrap()
  }

  fn temp_db_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("tokn-live-session-events-{}.db", uuid::Uuid::new_v4()))
  }
}

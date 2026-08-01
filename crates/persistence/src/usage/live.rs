use super::{UsageDb, UsageRecord};
use crate::Result;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokn_events::{
  AttemptFinished, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted, AttemptUsage, BodyFinished,
  BodyLeg, BodyProgress, BodyResult, ClientIdentity, ConnectAction, ConnectClosed, ConnectReady, ConsumerResult,
  EventConsumer, EventFailure, EventSeq, GatewayEvent, HttpFamily, IngressKind, PolicySelection, RequestAdmitted,
  RequestBodyObservation, RequestFinished, RequestOutcome, RequestPhase, RequestSource, RequestStarted, SelectedAction,
  TargetSelection, TokenUsage, TrafficEvent, TrafficEventKind, UsageKind,
};

const TERMINAL_TOMBSTONE_CAPACITY: usize = 4_096;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Projects the ordered public request lifecycle into the existing `usage.db`
/// schema.
///
/// One row is written for every completed attempt with a real requested model.
/// The first attempt retains the logical request id; retries use the legacy
/// `request_id:{attempt - 1}` suffix. Request-wide failures that never open an
/// attempt, including body parsing failures, deliberately produce no usage row.
pub struct UsagePersistenceConsumer {
  db: UsageDb,
  gateway_version: Arc<str>,
  active: HashMap<String, LogicalUsageState>,
  terminal: HashMap<String, u64>,
  terminal_order: VecDeque<String>,
}

impl UsagePersistenceConsumer {
  /// Opens the current usage database and prepares an ordered lifecycle
  /// projection. `gateway_version` is copied into the existing `ver` column.
  pub fn open(usage_db: impl Into<PathBuf>, gateway_version: impl Into<Arc<str>>) -> Result<Self> {
    let db = UsageDb::open(&usage_db.into())?;
    db.conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
    Ok(Self {
      db,
      gateway_version: gateway_version.into(),
      active: HashMap::new(),
      terminal: HashMap::new(),
      terminal_order: VecDeque::new(),
    })
  }

  fn handle_traffic(&mut self, event: &TrafficEvent) -> UsageWriteResult {
    let request_id = event.request_id.as_str();
    if request_id.contains(':') {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "base request IDs cannot contain `:` because it is reserved for persisted retry IDs",
      ));
    }
    if let Some(last_sequence) = self.terminal.get(request_id).copied() {
      return if event.sequence <= last_sequence {
        Ok(())
      } else {
        Err(UsageWriteError::lifecycle(
          request_id,
          format!(
            "received sequence {} after terminal sequence {last_sequence}",
            event.sequence
          ),
        ))
      };
    }

    if !self.active.contains_key(request_id) {
      if event.sequence != 1 {
        return Err(UsageWriteError::lifecycle(
          request_id,
          format!("first event has sequence {}, expected 1", event.sequence),
        ));
      }
      let TrafficEventKind::Started(started) = &event.kind else {
        return Err(UsageWriteError::lifecycle(request_id, "first event is not Started"));
      };
      self.active.insert(
        request_id.to_string(),
        LogicalUsageState {
          last_sequence: 1,
          seed: UsageSeed::from_started(started),
          attempts: BTreeMap::new(),
          latest_attempt: None,
          http_admitted: false,
          policy_observed: false,
          selected_transport: None,
          downstream_status: None,
          downstream_body_observed: false,
          connect: ConnectState::None,
          connect_authority: None,
        },
      );
      return Ok(());
    }

    let mut state = self
      .active
      .remove(request_id)
      .expect("active request was checked before removal");
    if event.sequence <= state.last_sequence {
      self.active.insert(request_id.to_string(), state);
      return Ok(());
    }
    let expected_sequence = state.last_sequence.saturating_add(1);
    if event.sequence != expected_sequence {
      self.active.insert(request_id.to_string(), state);
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!("received sequence {}, expected {expected_sequence}", event.sequence),
      ));
    }
    if matches!(event.kind, TrafficEventKind::Started(_)) {
      self.active.insert(request_id.to_string(), state);
      return Err(UsageWriteError::lifecycle(
        request_id,
        "received Started more than once",
      ));
    }

    let terminal = match self.apply_event(request_id, event, &mut state) {
      Ok(terminal) => terminal,
      Err(error) => {
        self.active.insert(request_id.to_string(), state);
        return Err(error);
      }
    };
    state.last_sequence = event.sequence;
    if terminal {
      self.remember_terminal(request_id, event.sequence);
    } else {
      self.active.insert(request_id.to_string(), state);
    }
    Ok(())
  }

  fn apply_event(
    &mut self,
    request_id: &str,
    event: &TrafficEvent,
    state: &mut LogicalUsageState,
  ) -> UsageWriteResult<bool> {
    match &event.kind {
      TrafficEventKind::Admitted(admitted) => on_admitted(request_id, state, admitted)?,
      TrafficEventKind::Authenticated(identity) => on_authenticated(state, identity),
      TrafficEventKind::PolicySelected(selection) => on_policy_selected(request_id, state, selection)?,
      TrafficEventKind::RequestBody(observation) => on_request_body(request_id, state, observation)?,
      TrafficEventKind::AttemptStarted(started) => on_attempt_started(request_id, event, state, started)?,
      TrafficEventKind::AttemptResponseHead(response) => on_attempt_response_head(request_id, event, state, response)?,
      TrafficEventKind::BodyProgress(progress) => on_body_progress(request_id, state, progress)?,
      TrafficEventKind::BodyFinished(finished) => {
        self.on_body_finished(request_id, state, finished)?;
      }
      TrafficEventKind::DownstreamResponseHead(response) => {
        self.on_downstream_response_head(request_id, state, response.status)?;
      }
      TrafficEventKind::AttemptUsage(usage) => self.on_attempt_usage(request_id, state, usage)?,
      TrafficEventKind::AttemptFinished(finished) => {
        self.on_attempt_finished(request_id, event, state, finished)?;
      }
      TrafficEventKind::ConnectReady(ready) => on_connect_ready(request_id, state, ready)?,
      TrafficEventKind::ConnectClosed(closed) => on_connect_closed(request_id, state, closed)?,
      TrafficEventKind::Finished(finished) => {
        self.on_finished(request_id, event.elapsed_ms, state, finished)?;
        return Ok(true);
      }
      TrafficEventKind::Started(_) | TrafficEventKind::AttemptRequest(_) => {}
      _ => {}
    }
    Ok(false)
  }

  fn on_body_finished(
    &mut self,
    request_id: &str,
    state: &mut LogicalUsageState,
    finished: &BodyFinished,
  ) -> UsageWriteResult {
    if finished.leg == BodyLeg::Downstream {
      if matches!(state.connect, ConnectState::Ready(_) | ConnectState::Closed) {
        return Err(UsageWriteError::lifecycle(
          request_id,
          "downstream body completion followed a ready CONNECT lifecycle",
        ));
      }
      state.downstream_body_observed = true;
    }
    let (attempt, phase) = match finished.leg {
      BodyLeg::Upstream { attempt } => (attempt, RequestPhase::UpstreamResponse),
      BodyLeg::Downstream => match state.latest_attempt {
        Some(attempt) => (attempt, RequestPhase::DownstreamResponse),
        None => return Ok(()),
      },
      _ => return Ok(()),
    };
    let pending = state.attempts.get_mut(&attempt).ok_or_else(|| {
      UsageWriteError::lifecycle(request_id, format!("body event refers to unopened attempt {attempt}"))
    })?;
    if let Some(error) = body_result_error(phase, &finished.result) {
      pending.request_error = Some(error);
    }
    insert_literal(
      &mut pending.context,
      match finished.leg {
        BodyLeg::Upstream { .. } => "upstream_body_result",
        BodyLeg::Downstream => "downstream_body_result",
        _ => "body_result",
      },
      body_result_name(&finished.result),
    );
    if pending.completed {
      self.persist_attempt(state, attempt)?;
    }
    Ok(())
  }

  fn on_downstream_response_head(
    &mut self,
    request_id: &str,
    state: &mut LogicalUsageState,
    status: u16,
  ) -> UsageWriteResult {
    if matches!(state.connect, ConnectState::Ready(_) | ConnectState::Closed) {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "downstream response head followed a ready CONNECT lifecycle",
      ));
    }
    observe_downstream_status(request_id, state, status)?;
    let Some(attempt) = state.latest_attempt else {
      return Ok(());
    };
    let completed = state
      .attempts
      .get(&attempt)
      .ok_or_else(|| UsageWriteError::lifecycle(request_id, format!("latest attempt {attempt} is missing")))?
      .completed;
    if completed {
      self.persist_attempt(state, attempt)?;
    }
    Ok(())
  }

  fn on_attempt_usage(
    &mut self,
    request_id: &str,
    state: &mut LogicalUsageState,
    event: &AttemptUsage,
  ) -> UsageWriteResult {
    let pending = state.attempts.get_mut(&event.attempt).ok_or_else(|| {
      UsageWriteError::lifecycle(
        request_id,
        format!("usage event refers to unopened attempt {}", event.attempt),
      )
    })?;
    pending
      .usage
      .get_or_insert_with(TokenUsage::default)
      .merge_from(&event.usage);
    if pending.endpoint.is_none() {
      pending.endpoint = event.usage.kind.map(usage_kind_name).map(str::to_string);
    }
    if pending.completed {
      self.persist_attempt(state, event.attempt)?;
    }
    Ok(())
  }

  fn on_attempt_finished(
    &mut self,
    request_id: &str,
    event: &TrafficEvent,
    state: &mut LogicalUsageState,
    finished: &AttemptFinished,
  ) -> UsageWriteResult {
    let pending = state.attempts.get_mut(&finished.attempt).ok_or_else(|| {
      UsageWriteError::lifecycle(
        request_id,
        format!("attempt completion refers to unopened attempt {}", finished.attempt),
      )
    })?;
    if pending.completed {
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!("attempt {} finished more than once", finished.attempt),
      ));
    }
    if let (Some(observed), Some(summary)) = (pending.upstream_status, finished.upstream_status) {
      if observed != summary {
        return Err(UsageWriteError::lifecycle(
          request_id,
          format!(
            "attempt {} terminal status {summary} conflicts with observed response status {observed}",
            finished.attempt
          ),
        ));
      }
    }
    pending.completed = true;
    pending.retry_planned = finished.retry.is_some();
    pending.upstream_status = pending.upstream_status.or(finished.upstream_status);
    pending.context.insert(
      "latency_ms".to_string(),
      Value::from(event.elapsed_ms.saturating_sub(pending.started_elapsed_ms)),
    );
    insert_literal(
      &mut pending.context,
      "attempt_outcome",
      attempt_outcome_name(finished.outcome),
    );
    insert_literal(
      &mut pending.context,
      "attempt_phase",
      request_phase_name(finished.phase),
    );
    if let Some(error) = attempt_error(finished) {
      pending.request_error = Some(error);
    }
    self.persist_attempt(state, finished.attempt)
  }

  fn on_finished(
    &mut self,
    request_id: &str,
    elapsed_ms: u64,
    state: &mut LogicalUsageState,
    finished: &RequestFinished,
  ) -> UsageWriteResult {
    if finished.attempt_count != state.attempts.len() as u32 {
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!(
          "Finished reports {} attempts after {} AttemptStarted events",
          finished.attempt_count,
          state.attempts.len()
        ),
      ));
    }
    if let Some((attempt, _)) = state.attempts.iter().find(|(_, pending)| !pending.completed) {
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!("request finished before attempt {attempt} completed"),
      ));
    }
    if matches!(state.connect, ConnectState::Ready(_)) {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "request finished before CONNECT closed",
      ));
    }
    if state.connect == ConnectState::Admitted && finished.outcome == RequestOutcome::Delivered {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "CONNECT was delivered before it became ready and closed",
      ));
    }
    if let (Some(observed), Some(summary)) = (state.downstream_status, finished.downstream_status) {
      if observed != summary {
        return Err(UsageWriteError::lifecycle(
          request_id,
          format!("terminal status {summary} conflicts with observed downstream status {observed}"),
        ));
      }
    }
    state.downstream_status = state.downstream_status.or(finished.downstream_status);

    if let Some(attempt) = state.latest_attempt {
      let pending = state
        .attempts
        .get_mut(&attempt)
        .expect("latest attempt belongs to the request");
      pending
        .context
        .insert("request_latency_ms".to_string(), Value::from(elapsed_ms));
      pending
        .context
        .insert("attempt_count".to_string(), Value::from(finished.attempt_count));
      insert_literal(
        &mut pending.context,
        "request_outcome",
        request_outcome_name(finished.outcome),
      );
      insert_literal(
        &mut pending.context,
        "request_phase",
        request_phase_name(finished.phase),
      );
      if let Some(error) = terminal_error(finished) {
        pending.request_error = Some(error);
      }
      self.persist_attempt(state, attempt)?;
    }
    Ok(())
  }

  fn persist_attempt(&mut self, state: &LogicalUsageState, attempt: AttemptNo) -> UsageWriteResult {
    let pending = state
      .attempts
      .get(&attempt)
      .expect("attempt was validated before persistence");
    if !pending.completed {
      return Ok(());
    }
    let Some(model) = pending.model.as_deref().filter(|model| model_is_known(model)) else {
      return Ok(());
    };
    let params_json = optional_object_json(&pending.params)?;
    let usage_json = pending.usage.as_ref().map(usage_json).transpose()?.flatten();
    let context_json = optional_object_json(&pending.context)?;
    let status = if state.latest_attempt == Some(attempt) {
      state.downstream_status.or(pending.upstream_status)
    } else {
      pending.upstream_status
    };
    self.db.record(&UsageRecord {
      ts: pending.ts,
      session_id: pending.session_id.as_deref(),
      request_id: &pending.row_id,
      project_id: pending.project_id.as_deref(),
      version: &self.gateway_version,
      request_error: pending.request_error.as_deref(),
      user: pending.user.as_deref(),
      endpoint: pending.endpoint.as_deref(),
      account_id: pending.account_id.as_deref(),
      provider_id: pending.provider_id.as_deref(),
      model,
      params_json: params_json.as_deref(),
      usage_json: usage_json.as_deref(),
      context_json: context_json.as_deref(),
      status,
    })?;
    Ok(())
  }

  fn remember_terminal(&mut self, request_id: &str, sequence: u64) {
    self.terminal.insert(request_id.to_string(), sequence);
    self.terminal_order.push_back(request_id.to_string());
    while self.terminal_order.len() > TERMINAL_TOMBSTONE_CAPACITY {
      if let Some(expired) = self.terminal_order.pop_front() {
        self.terminal.remove(&expired);
      }
    }
  }
}

impl EventConsumer<GatewayEvent> for UsagePersistenceConsumer {
  fn name(&self) -> &str {
    "usage-persistence"
  }

  fn handle(&mut self, _sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
    let GatewayEvent::Traffic(event) = event else {
      return Ok(());
    };
    self
      .handle_traffic(event)
      .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
  }
}

struct LogicalUsageState {
  last_sequence: u64,
  seed: UsageSeed,
  attempts: BTreeMap<AttemptNo, PendingUsageRecord>,
  latest_attempt: Option<AttemptNo>,
  http_admitted: bool,
  policy_observed: bool,
  selected_transport: Option<SelectedTransport>,
  downstream_status: Option<u16>,
  downstream_body_observed: bool,
  connect: ConnectState,
  connect_authority: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectState {
  None,
  Admitted,
  Ready(ConnectAction),
  Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedTransport {
  Reject,
  Http,
  Connect(ConnectAction),
  Unknown,
}

#[derive(Clone)]
struct UsageSeed {
  session_id: Option<String>,
  project_id: Option<String>,
  user: Option<String>,
  endpoint: Option<String>,
  model: Option<String>,
  params: Map<String, Value>,
  context: Map<String, Value>,
}

impl UsageSeed {
  fn from_started(started: &RequestStarted) -> Self {
    Self {
      session_id: started.correlation.session_id.as_ref().map(ToString::to_string),
      project_id: started.correlation.project_id.as_ref().map(ToString::to_string),
      user: None,
      endpoint: None,
      model: None,
      params: Map::new(),
      context: started_context(started),
    }
  }
}

struct PendingUsageRecord {
  row_id: String,
  ts: i64,
  started_elapsed_ms: u64,
  session_id: Option<String>,
  project_id: Option<String>,
  request_error: Option<String>,
  user: Option<String>,
  endpoint: Option<String>,
  account_id: Option<String>,
  provider_id: Option<String>,
  model: Option<String>,
  params: Map<String, Value>,
  usage: Option<TokenUsage>,
  context: Map<String, Value>,
  upstream_status: Option<u16>,
  completed: bool,
  retry_planned: bool,
}

#[derive(Debug)]
enum UsageWriteError {
  Persistence(crate::Error),
  Json(serde_json::Error),
  Lifecycle { request_id: String, detail: String },
}

impl UsageWriteError {
  fn lifecycle(request_id: &str, detail: impl Into<String>) -> Self {
    Self::Lifecycle {
      request_id: request_id.to_string(),
      detail: detail.into(),
    }
  }
}

impl fmt::Display for UsageWriteError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Persistence(source) => write!(formatter, "usage persistence write failed: {source}"),
      Self::Json(source) => write!(formatter, "usage persistence JSON encoding failed: {source}"),
      Self::Lifecycle { request_id, detail } => {
        write!(formatter, "invalid usage event lifecycle for `{request_id}`: {detail}")
      }
    }
  }
}

impl Error for UsageWriteError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match self {
      Self::Persistence(source) => Some(source),
      Self::Json(source) => Some(source),
      Self::Lifecycle { .. } => None,
    }
  }
}

impl From<crate::Error> for UsageWriteError {
  fn from(source: crate::Error) -> Self {
    Self::Persistence(source)
  }
}

impl From<serde_json::Error> for UsageWriteError {
  fn from(source: serde_json::Error) -> Self {
    Self::Json(source)
  }
}

type UsageWriteResult<T = ()> = std::result::Result<T, UsageWriteError>;

fn on_admitted(request_id: &str, state: &mut LogicalUsageState, admitted: &RequestAdmitted) -> UsageWriteResult {
  if state.http_admitted || state.connect != ConnectState::None {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "request admission was observed more than once",
    ));
  }
  match admitted {
    RequestAdmitted::Http {
      scheme,
      authority,
      path_and_query,
      operation,
    } => {
      if matches!(state.selected_transport, Some(SelectedTransport::Connect(_))) {
        return Err(UsageWriteError::lifecycle(
          request_id,
          "HTTP admission followed CONNECT policy",
        ));
      }
      insert_string(&mut state.seed.context, "scheme", scheme);
      insert_string(&mut state.seed.context, "authority", authority);
      if state.seed.endpoint.is_none() {
        state.seed.endpoint = operation
          .as_ref()
          .map(ToString::to_string)
          .or_else(|| (!path_and_query.is_redacted()).then(|| endpoint_from_path(path_and_query.as_str())));
      }
      state.http_admitted = true;
    }
    RequestAdmitted::Connect { authority } => {
      if matches!(state.selected_transport, Some(SelectedTransport::Http)) {
        return Err(UsageWriteError::lifecycle(
          request_id,
          "CONNECT admission followed HTTP policy",
        ));
      }
      insert_string(&mut state.seed.context, "authority", authority);
      state.seed.endpoint.get_or_insert_with(|| "connect".to_string());
      state.connect = ConnectState::Admitted;
      state.connect_authority = Some(authority.to_string());
    }
    _ => {}
  }
  Ok(())
}

fn on_authenticated(state: &mut LogicalUsageState, identity: &ClientIdentity) {
  match identity {
    ClientIdentity::Anonymous => insert_literal(&mut state.seed.context, "client_identity", "anonymous"),
    ClientIdentity::LocalKey { key_id, key_name } => {
      insert_literal(&mut state.seed.context, "client_identity", "local_key");
      insert_string(&mut state.seed.context, "api_key_id", key_id);
      if state.seed.user.is_none() {
        state.seed.user = key_name.as_ref().map(ToString::to_string);
      }
    }
    ClientIdentity::Embedded => insert_literal(&mut state.seed.context, "client_identity", "embedded"),
    _ => {}
  }
}

fn on_policy_selected(
  request_id: &str,
  state: &mut LogicalUsageState,
  selection: &PolicySelection,
) -> UsageWriteResult {
  if state.policy_observed {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "request policy was selected more than once",
    ));
  }
  match &selection.action {
    SelectedAction::Http { .. } if state.connect != ConnectState::None => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "HTTP policy followed CONNECT admission",
      ));
    }
    SelectedAction::Connect { .. } if state.http_admitted => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "CONNECT policy followed HTTP admission",
      ));
    }
    _ => {}
  }
  insert_optional_string(&mut state.seed.context, "binding_id", selection.binding_id.as_ref());
  match &selection.action {
    SelectedAction::Reject => insert_literal(&mut state.seed.context, "selected_action", "reject"),
    SelectedAction::Http {
      profile_id,
      route_id,
      family,
    } => {
      insert_literal(&mut state.seed.context, "selected_action", "http");
      insert_string(&mut state.seed.context, "profile_id", profile_id);
      insert_string(&mut state.seed.context, "route_id", route_id);
      insert_literal(&mut state.seed.context, "http_family", http_family_name(*family));
    }
    SelectedAction::Connect { action } => {
      insert_literal(&mut state.seed.context, "selected_action", "connect");
      insert_literal(&mut state.seed.context, "connect_action", connect_action_name(*action));
    }
    _ => insert_literal(&mut state.seed.context, "selected_action", "unknown"),
  }
  state.policy_observed = true;
  state.selected_transport = Some(match &selection.action {
    SelectedAction::Reject => SelectedTransport::Reject,
    SelectedAction::Http { .. } => SelectedTransport::Http,
    SelectedAction::Connect { action } => SelectedTransport::Connect(*action),
    _ => SelectedTransport::Unknown,
  });
  Ok(())
}

fn on_request_body(
  request_id: &str,
  state: &mut LogicalUsageState,
  observation: &RequestBodyObservation,
) -> UsageWriteResult {
  if state.connect != ConnectState::None
    || matches!(
      state.selected_transport,
      Some(SelectedTransport::Reject | SelectedTransport::Connect(_))
    )
  {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "request body followed a non-HTTP policy or CONNECT lifecycle",
    ));
  }
  if state.seed.model.is_none() {
    state.seed.model = observation.requested_model.as_ref().map(ToString::to_string);
  }
  if let Some(stream) = observation.stream {
    state.seed.params.insert("stream".to_string(), Value::Bool(stream));
  }
  if let Some(initiator) = observation.initiator.as_ref() {
    insert_string(&mut state.seed.params, "initiator", initiator);
  }
  Ok(())
}

fn on_attempt_started(
  request_id: &str,
  event: &TrafficEvent,
  state: &mut LogicalUsageState,
  started: &AttemptStarted,
) -> UsageWriteResult {
  if state.connect != ConnectState::None
    || matches!(
      state.selected_transport,
      Some(SelectedTransport::Reject | SelectedTransport::Connect(_))
    )
  {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "HTTP attempt followed a non-HTTP policy or CONNECT lifecycle",
    ));
  }
  let expected_attempt = u32::try_from(state.attempts.len())
    .unwrap_or(u32::MAX)
    .saturating_add(1);
  if started.attempt.get() != expected_attempt {
    return Err(UsageWriteError::lifecycle(
      request_id,
      format!("opened attempt {}, expected {expected_attempt}", started.attempt),
    ));
  }
  if let Some(previous) = state.latest_attempt {
    let previous_state = state
      .attempts
      .get(&previous)
      .expect("latest attempt belongs to the request");
    if !previous_state.completed {
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!("opened attempt {} before attempt {previous} completed", started.attempt),
      ));
    }
    if !previous_state.retry_planned {
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!(
          "opened attempt {} without a retry decision for attempt {previous}",
          started.attempt
        ),
      ));
    }
  }

  let model = state
    .seed
    .model
    .as_deref()
    .filter(|model| model_is_known(model))
    .map(str::to_string)
    .or_else(|| {
      started
        .target
        .requested_model
        .as_ref()
        .map(ToString::to_string)
        .filter(|model| model_is_known(model))
    });
  let endpoint = state
    .seed
    .endpoint
    .clone()
    .or_else(|| started.target.requested_operation.as_ref().map(ToString::to_string));
  let mut context = state.seed.context.clone();
  context.insert("attempt".to_string(), Value::from(started.attempt.get()));
  insert_target_selection(&mut context, &started.target);
  let pending = PendingUsageRecord {
    row_id: attempt_row_id(request_id, started.attempt),
    ts: event.at_unix_ms,
    started_elapsed_ms: event.elapsed_ms,
    session_id: state.seed.session_id.clone(),
    project_id: state.seed.project_id.clone(),
    request_error: None,
    user: state.seed.user.clone(),
    endpoint,
    account_id: started.target.account_id.as_ref().map(ToString::to_string),
    provider_id: started.target.provider_id.as_ref().map(ToString::to_string),
    model,
    params: state.seed.params.clone(),
    usage: None,
    context,
    upstream_status: None,
    completed: false,
    retry_planned: false,
  };
  state.attempts.insert(started.attempt, pending);
  state.latest_attempt = Some(started.attempt);
  Ok(())
}

fn on_attempt_response_head(
  request_id: &str,
  event: &TrafficEvent,
  state: &mut LogicalUsageState,
  response: &AttemptHttpResponseHead,
) -> UsageWriteResult {
  let pending = state.attempts.get_mut(&response.attempt).ok_or_else(|| {
    UsageWriteError::lifecycle(
      request_id,
      format!("response head refers to unopened attempt {}", response.attempt),
    )
  })?;
  if pending.completed {
    return Err(UsageWriteError::lifecycle(
      request_id,
      format!("response head followed completion of attempt {}", response.attempt),
    ));
  }
  if let Some(observed) = pending.upstream_status {
    if observed != response.response.status {
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!(
          "attempt response status changed from {observed} to {}",
          response.response.status
        ),
      ));
    }
  } else {
    pending.upstream_status = Some(response.response.status);
  }
  pending.context.insert(
    "latency_header_ms".to_string(),
    Value::from(event.elapsed_ms.saturating_sub(pending.started_elapsed_ms)),
  );
  Ok(())
}

fn observe_downstream_status(request_id: &str, state: &mut LogicalUsageState, status: u16) -> UsageWriteResult {
  if let Some(observed) = state.downstream_status {
    if observed != status {
      return Err(UsageWriteError::lifecycle(
        request_id,
        format!("downstream response status changed from {observed} to {status}"),
      ));
    }
  } else {
    state.downstream_status = Some(status);
  }
  Ok(())
}

fn on_body_progress(request_id: &str, state: &mut LogicalUsageState, progress: &BodyProgress) -> UsageWriteResult {
  if progress.leg != BodyLeg::Downstream {
    return Ok(());
  }
  if matches!(state.connect, ConnectState::Ready(_) | ConnectState::Closed) {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "downstream body progress followed a ready CONNECT lifecycle",
    ));
  }
  state.downstream_body_observed = true;
  Ok(())
}

fn on_connect_ready(request_id: &str, state: &mut LogicalUsageState, ready: &ConnectReady) -> UsageWriteResult {
  if state.http_admitted || !state.attempts.is_empty() {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "ConnectReady followed an HTTP lifecycle",
    ));
  }
  match state.connect {
    ConnectState::Admitted => {}
    ConnectState::None => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectReady was emitted before CONNECT admission",
      ));
    }
    ConnectState::Ready(_) | ConnectState::Closed => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectReady was emitted more than once",
      ));
    }
  }
  if ready.action == ConnectAction::Reject {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "rejected CONNECT cannot become ready",
    ));
  }
  match state.selected_transport {
    Some(SelectedTransport::Connect(action)) if action == ready.action => {}
    Some(SelectedTransport::Connect(_)) => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectReady action differs from the selected CONNECT policy",
      ));
    }
    Some(_) => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectReady followed a non-CONNECT policy",
      ));
    }
    None => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectReady was emitted before CONNECT policy selection",
      ));
    }
  }
  if state.downstream_status.is_some() || state.downstream_body_observed {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "ConnectReady followed an HTTP response boundary",
    ));
  }
  if state.connect_authority.as_deref() != Some(ready.authority.as_str()) {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "ConnectReady authority differs from CONNECT admission",
    ));
  }
  observe_downstream_status(request_id, state, 200)?;
  state.connect = ConnectState::Ready(ready.action);
  Ok(())
}

fn on_connect_closed(request_id: &str, state: &mut LogicalUsageState, closed: &ConnectClosed) -> UsageWriteResult {
  if state.http_admitted || !state.attempts.is_empty() {
    return Err(UsageWriteError::lifecycle(
      request_id,
      "ConnectClosed followed an HTTP lifecycle",
    ));
  }
  match state.connect {
    ConnectState::None | ConnectState::Admitted => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectClosed was emitted before ConnectReady",
      ));
    }
    ConnectState::Ready(action) if action != closed.action => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectClosed action differs from ConnectReady",
      ));
    }
    ConnectState::Ready(_) => state.connect = ConnectState::Closed,
    ConnectState::Closed => {
      return Err(UsageWriteError::lifecycle(
        request_id,
        "ConnectClosed was emitted more than once",
      ));
    }
  }
  Ok(())
}

fn started_context(started: &RequestStarted) -> Map<String, Value> {
  let mut context = Map::new();
  insert_optional_string(&mut context, "http_version", started.http_version.as_ref());
  insert_string(&mut context, "inbound_method", &started.method);
  match &started.source {
    RequestSource::Listener {
      listener_id,
      ingress,
      local_addr,
      peer_addr,
    } => {
      insert_literal(&mut context, "request_source", "listener");
      insert_string(&mut context, "listener_id", listener_id);
      insert_literal(&mut context, "ingress", ingress_name(ingress));
      insert_literal(&mut context, "mode", ingress_mode(ingress));
      insert_literal(&mut context, "pipeline_id", ingress_pipeline(ingress));
      if let Some(local_addr) = local_addr {
        insert_literal(&mut context, "local_addr", &local_addr.to_string());
      }
      if let Some(peer_addr) = peer_addr {
        insert_literal(&mut context, "peer_addr", &peer_addr.to_string());
      }
      if let IngressKind::InterceptedHttps { parent_connect_id } = ingress {
        insert_string(&mut context, "parent_connect_id", parent_connect_id);
      }
    }
    RequestSource::Embedded { profile_id } => {
      insert_literal(&mut context, "request_source", "embedded");
      insert_string(&mut context, "source_profile_id", profile_id);
      insert_literal(&mut context, "mode", "embedded");
      insert_literal(&mut context, "pipeline_id", "embedded");
    }
    _ => insert_literal(&mut context, "request_source", "unknown"),
  }
  let correlation = &started.correlation;
  insert_optional_string(
    &mut context,
    "client_request_id",
    correlation.client_request_id.as_ref(),
  );
  insert_optional_string(&mut context, "thread_id", correlation.thread_id.as_ref());
  insert_optional_string(&mut context, "parent_thread_id", correlation.parent_thread_id.as_ref());
  insert_optional_string(
    &mut context,
    "parent_session_id",
    correlation.parent_session_id.as_ref(),
  );
  insert_optional_string(&mut context, "turn_id", correlation.turn_id.as_ref());
  context
}

fn insert_target_selection(context: &mut Map<String, Value>, target: &TargetSelection) {
  insert_literal(context, "http_family", http_family_name(target.family));
  insert_optional_string(context, "upstream_id", target.upstream_id.as_ref());
  insert_optional_string(context, "requested_model", target.requested_model.as_ref());
  insert_optional_string(context, "upstream_model", target.upstream_model.as_ref());
  insert_optional_string(context, "requested_operation", target.requested_operation.as_ref());
  insert_optional_string(context, "upstream_operation", target.upstream_operation.as_ref());
}

fn endpoint_from_path(path_and_query: &str) -> String {
  let path = path_and_query.split('?').next().unwrap_or(path_and_query);
  match path.trim_end_matches('/') {
    path if path.ends_with("/chat/completions") => "chat_completions".to_string(),
    path if path.ends_with("/responses") => "responses".to_string(),
    path if path.ends_with("/messages") => "messages".to_string(),
    path => path.to_string(),
  }
}

fn ingress_name(ingress: &IngressKind) -> &'static str {
  match ingress {
    IngressKind::LlmApi => "llm_api",
    IngressKind::ForwardProxy => "forward_proxy",
    IngressKind::InterceptedHttps { .. } => "intercepted_https",
    _ => "unknown",
  }
}

fn ingress_mode(ingress: &IngressKind) -> &'static str {
  match ingress {
    IngressKind::LlmApi => "route",
    IngressKind::ForwardProxy => "forward_proxy",
    IngressKind::InterceptedHttps { .. } => "intercept",
    _ => "unknown",
  }
}

fn ingress_pipeline(ingress: &IngressKind) -> &'static str {
  match ingress {
    IngressKind::LlmApi => "requests",
    IngressKind::ForwardProxy | IngressKind::InterceptedHttps { .. } => "proxy",
    _ => "unknown",
  }
}

fn http_family_name(family: HttpFamily) -> &'static str {
  match family {
    HttpFamily::Managed => "managed",
    HttpFamily::Relay => "relay",
    HttpFamily::Transparent => "transparent",
    _ => "unknown",
  }
}

fn connect_action_name(action: ConnectAction) -> &'static str {
  match action {
    ConnectAction::Intercept => "intercept",
    ConnectAction::Tunnel => "tunnel",
    ConnectAction::Reject => "reject",
    _ => "unknown",
  }
}

fn model_is_known(model: &str) -> bool {
  !model.is_empty() && model != "unknown"
}

fn attempt_row_id(request_id: &str, attempt: AttemptNo) -> String {
  let suffix = attempt.get() - 1;
  if suffix == 0 {
    request_id.to_string()
  } else {
    format!("{request_id}:{suffix}")
  }
}

fn optional_object_json(object: &Map<String, Value>) -> UsageWriteResult<Option<String>> {
  if object.is_empty() {
    Ok(None)
  } else {
    serde_json::to_string(object).map(Some).map_err(Into::into)
  }
}

fn usage_json(usage: &TokenUsage) -> UsageWriteResult<Option<String>> {
  let mut object = Map::new();
  if let Some(kind) = usage.kind {
    insert_literal(&mut object, "kind", usage_kind_name(kind));
  }
  for (key, value) in [
    ("input", usage.input),
    ("output", usage.output),
    ("total", usage.total),
    ("cache_read", usage.cache_read),
    ("cache_write", usage.cache_write),
    ("reasoning", usage.reasoning),
  ] {
    if let Some(value) = value {
      object.insert(key.to_string(), Value::from(value));
    }
  }
  optional_object_json(&object)
}

fn usage_kind_name(kind: UsageKind) -> &'static str {
  match kind {
    UsageKind::ChatCompletions => "chat_completions",
    UsageKind::Responses => "responses",
    UsageKind::Messages => "messages",
    _ => "unknown",
  }
}

fn attempt_error(finished: &AttemptFinished) -> Option<String> {
  if let Some(failure) = finished.failure.as_ref() {
    return Some(format_failure(finished.phase, failure));
  }
  if let Some(retry) = finished.retry.as_ref() {
    return Some(format_failure(finished.phase, &retry.reason));
  }
  match finished.outcome {
    AttemptOutcome::Response => None,
    AttemptOutcome::Failed => Some(format!("{}: failed", request_phase_name(finished.phase))),
    AttemptOutcome::Cancelled => Some(format!("{}: cancelled", request_phase_name(finished.phase))),
    _ => Some(format!(
      "{}: attempt did not complete",
      request_phase_name(finished.phase)
    )),
  }
}

fn terminal_error(finished: &RequestFinished) -> Option<String> {
  if let Some(failure) = finished.failure.as_ref() {
    return Some(format_failure(finished.phase, failure));
  }
  match finished.outcome {
    RequestOutcome::Delivered => None,
    RequestOutcome::Rejected => Some(format!("{}: rejected", request_phase_name(finished.phase))),
    RequestOutcome::Failed => Some(format!("{}: failed", request_phase_name(finished.phase))),
    RequestOutcome::Cancelled => Some(format!("{}: cancelled", request_phase_name(finished.phase))),
    _ => Some(format!(
      "{}: request did not complete",
      request_phase_name(finished.phase)
    )),
  }
}

fn body_result_error(phase: RequestPhase, result: &BodyResult) -> Option<String> {
  match result {
    BodyResult::Complete => None,
    BodyResult::Failed(failure) => Some(format_failure(phase, failure)),
    BodyResult::Cancelled => Some(format!("{}: cancelled", request_phase_name(phase))),
    _ => Some(format!("{}: body did not complete", request_phase_name(phase))),
  }
}

fn format_failure(phase: RequestPhase, failure: &EventFailure) -> String {
  format!("{}: {}", request_phase_name(phase), failure.message)
}

fn request_phase_name(phase: RequestPhase) -> &'static str {
  match phase {
    RequestPhase::Admission => "admission",
    RequestPhase::Authentication => "authentication",
    RequestPhase::Policy => "policy",
    RequestPhase::RequestBody => "request_body",
    RequestPhase::TargetSelection => "target_selection",
    RequestPhase::UpstreamRequest => "upstream_request",
    RequestPhase::UpstreamResponse => "upstream_response",
    RequestPhase::DownstreamResponse => "downstream_response",
    RequestPhase::Connect => "connect",
    RequestPhase::Complete => "complete",
    _ => "unknown",
  }
}

fn attempt_outcome_name(outcome: AttemptOutcome) -> &'static str {
  match outcome {
    AttemptOutcome::Response => "response",
    AttemptOutcome::Failed => "failed",
    AttemptOutcome::Cancelled => "cancelled",
    _ => "unknown",
  }
}

fn request_outcome_name(outcome: RequestOutcome) -> &'static str {
  match outcome {
    RequestOutcome::Delivered => "delivered",
    RequestOutcome::Rejected => "rejected",
    RequestOutcome::Failed => "failed",
    RequestOutcome::Cancelled => "cancelled",
    _ => "unknown",
  }
}

fn body_result_name(result: &BodyResult) -> &'static str {
  match result {
    BodyResult::Complete => "complete",
    BodyResult::Failed(_) => "failed",
    BodyResult::Cancelled => "cancelled",
    _ => "unknown",
  }
}

fn insert_optional_string<T: ToString>(context: &mut Map<String, Value>, key: &str, value: Option<&T>) {
  if let Some(value) = value {
    insert_string(context, key, value);
  }
}

fn insert_string(context: &mut Map<String, Value>, key: &str, value: &impl ToString) {
  insert_literal(context, key, &value.to_string());
}

fn insert_literal(context: &mut Map<String, Value>, key: &str, value: &str) {
  context.insert(key.to_string(), Value::String(value.to_string()));
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn usage_consumer_bounds_terminal_state() {
    let dir = std::env::temp_dir().join(format!("tokn-router-usage-state-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut consumer = UsagePersistenceConsumer::open(dir.join("usage.db"), "test-version").unwrap();

    for index in 0..=TERMINAL_TOMBSTONE_CAPACITY {
      consumer.remember_terminal(&format!("request-{index}"), 2);
    }

    assert!(consumer.active.is_empty());
    assert_eq!(consumer.terminal.len(), TERMINAL_TOMBSTONE_CAPACITY);
    assert!(!consumer.terminal.contains_key("request-0"));
    assert!(consumer
      .terminal
      .contains_key(&format!("request-{TERMINAL_TOMBSTONE_CAPACITY}")));
  }
}

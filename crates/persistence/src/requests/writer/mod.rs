//! Transactional projection of public gateway events into the requests DB.

mod encode;
mod projection;
mod store;

use self::encode::{
  attempt_outcome_name, attempt_row_id, body_result_error, body_result_name, connect_action_name, day_key,
  format_failure, headers_json, http_family_name, insert_failure, insert_literal, insert_optional_string,
  insert_string, insert_target_selection, object_json, optional_object_json, request_outcome_name, request_phase_name,
  started_context, terminal_error, usage_json,
};
use self::projection::{annotate_event_capture, project_body};
use self::store::RequestStore;
use crate::Result;
use bytes::Bytes;
use rusqlite::{params, Transaction};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokn_events::{
  AttemptFinished, AttemptHttpRequest, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted,
  AttemptUsage, BodyCapture, BodyFinished, BodyLeg, BodyOutcome, BodyProgress, BodyResult, ClientIdentity,
  ConnectAction, ConnectClosed, ConnectReady, ConsumerResult, EventConsumer, EventSeq, GatewayEvent, HttpResponseHead,
  PolicySelection, RequestAdmitted, RequestBodyObservation, RequestFinished, RequestPhase, RequestSource,
  RequestStarted, SelectedAction, TokenUsage, TrafficEvent, TrafficEventKind,
};

const TERMINAL_TOMBSTONE_CAPACITY: usize = 4_096;

/// Persists the public request lifecycle into the existing per-day requests
/// databases without exposing database concerns to event producers.
pub struct RequestPersistenceConsumer {
  store: RequestStore,
  gateway_version: Arc<str>,
  options: RequestPersistenceOptions,
  active: HashMap<String, LogicalState>,
  terminal: HashMap<String, u64>,
  terminal_order: VecDeque<String>,
}

/// Independent safety policy for projecting event body captures into SQLite.
///
/// The event stream remains unchanged and can retain more information than the
/// compatibility database projection. The projection never writes more than
/// [`Self::body_max_bytes`] to any body column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestPersistenceOptions {
  pub record_request_bodies: bool,
  pub body_max_bytes: usize,
}

impl Default for RequestPersistenceOptions {
  fn default() -> Self {
    Self {
      record_request_bodies: true,
      body_max_bytes: 10 * 1024 * 1024,
    }
  }
}

impl RequestPersistenceConsumer {
  /// Open a request projection with the current compatibility defaults: body
  /// recording enabled with a 10 MiB limit per stored body.
  pub fn open(requests_dir: impl Into<PathBuf>, gateway_version: impl Into<Arc<str>>) -> Result<Self> {
    Self::open_with_options(requests_dir, gateway_version, RequestPersistenceOptions::default())
  }

  /// Open a request projection with an explicit, independently enforced body
  /// persistence policy.
  pub fn open_with_options(
    requests_dir: impl Into<PathBuf>,
    gateway_version: impl Into<Arc<str>>,
    options: RequestPersistenceOptions,
  ) -> Result<Self> {
    Ok(Self {
      store: RequestStore::open(requests_dir.into())?,
      gateway_version: gateway_version.into(),
      options,
      active: HashMap::new(),
      terminal: HashMap::new(),
      terminal_order: VecDeque::new(),
    })
  }

  fn handle_traffic(&mut self, event: &TrafficEvent) -> WriteResult {
    let request_id = event.request_id.as_str();
    if request_id.contains(':') {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "base request IDs cannot contain `:` because it is reserved for persisted retry IDs",
      ));
    }
    if let Some(last_sequence) = self.terminal.get(request_id).copied() {
      return if event.sequence <= last_sequence {
        Ok(())
      } else {
        Err(RequestWriteError::lifecycle(
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
        return Err(RequestWriteError::lifecycle(
          request_id,
          format!("first event has sequence {}, expected 1", event.sequence),
        ));
      }
      let TrafficEventKind::Started(started) = &event.kind else {
        return Err(RequestWriteError::lifecycle(request_id, "first event is not Started"));
      };
      let state = self.start_request(request_id, event.at_unix_ms, started)?;
      self.active.insert(request_id.to_string(), state);
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
      return Err(RequestWriteError::lifecycle(
        request_id,
        format!("received sequence {}, expected {expected_sequence}", event.sequence),
      ));
    }
    if matches!(event.kind, TrafficEventKind::Started(_)) {
      self.active.insert(request_id.to_string(), state);
      return Err(RequestWriteError::lifecycle(
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

  fn start_request(
    &mut self,
    request_id: &str,
    at_unix_ms: i64,
    started: &RequestStarted,
  ) -> WriteResult<LogicalState> {
    let day = day_key(at_unix_ms)?;
    let context = started_context(started);
    let context_json = object_json(&context)?;
    let inbound_headers = Bytes::from(headers_json(&started.headers)?);
    let session_id = started.correlation.session_id.as_ref().map(ToString::to_string);
    let seed = RequestSeed {
      endpoint: None,
      user: None,
      context,
      session_id,
      model: None,
      params: Map::new(),
      inbound_method: started.method.to_string(),
      inbound_url: started.target.as_str().to_string(),
      inbound_headers,
      inbound_body: None,
    };
    let version = self.gateway_version.as_ref();
    self.store.transaction(&day, |transaction| {
      transaction.execute(
        "INSERT INTO request_connection (request_id, ts, ver, ctx_json)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(request_id) DO UPDATE SET
           ver = COALESCE(request_connection.ver, excluded.ver),
           ctx_json = COALESCE(request_connection.ctx_json, excluded.ctx_json)",
        params![request_id, at_unix_ms, version, context_json],
      )?;
      transaction.execute(
        "INSERT INTO request_metadata (request_id, session_id)
         VALUES (?1, ?2)
         ON CONFLICT(request_id) DO UPDATE SET
           session_id = COALESCE(request_metadata.session_id, excluded.session_id)",
        params![request_id, seed.session_id.as_deref()],
      )?;
      transaction.execute(
        "INSERT INTO request_downstream
           (request_id, inbound_req_method, inbound_req_url, inbound_req_headers)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(request_id) DO UPDATE SET
           inbound_req_method = COALESCE(request_downstream.inbound_req_method, excluded.inbound_req_method),
           inbound_req_url = COALESCE(request_downstream.inbound_req_url, excluded.inbound_req_url),
           inbound_req_headers = COALESCE(request_downstream.inbound_req_headers, excluded.inbound_req_headers)",
        params![
          request_id,
          seed.inbound_method,
          seed.inbound_url,
          seed.inbound_headers.as_ref()
        ],
      )?;
      Ok(())
    })?;

    Ok(LogicalState {
      base_day: day,
      last_sequence: 1,
      seed,
      embedded_source: matches!(&started.source, RequestSource::Embedded { .. }),
      attempts: BTreeMap::new(),
      latest_attempt: None,
      http_admitted: false,
      policy_observed: false,
      request_body_observed: false,
      downstream_status: None,
      downstream_body_finished: false,
      connect: ConnectState::None,
      connect_authority: None,
      selected_transport: None,
    })
  }

  fn apply_event(&mut self, request_id: &str, event: &TrafficEvent, state: &mut LogicalState) -> WriteResult<bool> {
    match &event.kind {
      TrafficEventKind::Admitted(admitted) => self.on_admitted(request_id, state, admitted)?,
      TrafficEventKind::Authenticated(identity) => self.on_authenticated(request_id, state, identity)?,
      TrafficEventKind::PolicySelected(selection) => self.on_policy_selected(request_id, state, selection)?,
      TrafficEventKind::RequestBody(observation) => self.on_request_body(request_id, state, observation)?,
      TrafficEventKind::AttemptStarted(started) => {
        self.on_attempt_started(request_id, event, state, started)?;
      }
      TrafficEventKind::AttemptRequest(request) => self.on_attempt_request(request_id, state, request)?,
      TrafficEventKind::AttemptResponseHead(response) => {
        self.on_attempt_response_head(request_id, event.elapsed_ms, state, response)?;
      }
      TrafficEventKind::BodyProgress(progress) => self.on_body_progress(request_id, state, progress)?,
      TrafficEventKind::BodyFinished(finished) => self.on_body_finished(request_id, state, finished)?,
      TrafficEventKind::DownstreamResponseHead(response) => {
        self.on_downstream_response_head(request_id, state, response)?;
      }
      TrafficEventKind::AttemptUsage(usage) => self.on_attempt_usage(request_id, state, usage)?,
      TrafficEventKind::AttemptFinished(finished) => {
        self.on_attempt_finished(request_id, event.elapsed_ms, state, finished)?;
      }
      TrafficEventKind::ConnectReady(ready) => self.on_connect_ready(request_id, state, ready)?,
      TrafficEventKind::ConnectClosed(closed) => self.on_connect_closed(request_id, state, closed)?,
      TrafficEventKind::Finished(finished) => {
        self.on_finished(request_id, event.elapsed_ms, state, finished)?;
        return Ok(true);
      }
      _ => {}
    }
    Ok(false)
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

impl EventConsumer<GatewayEvent> for RequestPersistenceConsumer {
  fn name(&self) -> &str {
    "request-persistence"
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

#[derive(Debug)]
enum RequestWriteError {
  Persistence(crate::Error),
  Sqlite(rusqlite::Error),
  Json(serde_json::Error),
  InvalidTimestamp(i64),
  Lifecycle { request_id: String, detail: String },
}

impl RequestWriteError {
  fn lifecycle(request_id: &str, detail: impl Into<String>) -> Self {
    Self::Lifecycle {
      request_id: request_id.to_string(),
      detail: detail.into(),
    }
  }
}

impl fmt::Display for RequestWriteError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Persistence(source) => write!(formatter, "request persistence setup failed: {source}"),
      Self::Sqlite(source) => write!(formatter, "request persistence write failed: {source}"),
      Self::Json(source) => write!(formatter, "request persistence JSON encoding failed: {source}"),
      Self::InvalidTimestamp(timestamp) => write!(formatter, "request event timestamp {timestamp} is out of range"),
      Self::Lifecycle { request_id, detail } => {
        write!(
          formatter,
          "invalid request event lifecycle for `{request_id}`: {detail}"
        )
      }
    }
  }
}

impl Error for RequestWriteError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match self {
      Self::Persistence(source) => Some(source),
      Self::Sqlite(source) => Some(source),
      Self::Json(source) => Some(source),
      Self::InvalidTimestamp(_) | Self::Lifecycle { .. } => None,
    }
  }
}

impl From<crate::Error> for RequestWriteError {
  fn from(source: crate::Error) -> Self {
    Self::Persistence(source)
  }
}

impl From<rusqlite::Error> for RequestWriteError {
  fn from(source: rusqlite::Error) -> Self {
    Self::Sqlite(source)
  }
}

impl From<serde_json::Error> for RequestWriteError {
  fn from(source: serde_json::Error) -> Self {
    Self::Json(source)
  }
}

type WriteResult<T = ()> = std::result::Result<T, RequestWriteError>;

struct LogicalState {
  base_day: String,
  last_sequence: u64,
  seed: RequestSeed,
  embedded_source: bool,
  attempts: BTreeMap<AttemptNo, AttemptState>,
  latest_attempt: Option<AttemptNo>,
  http_admitted: bool,
  policy_observed: bool,
  request_body_observed: bool,
  downstream_status: Option<u16>,
  downstream_body_finished: bool,
  connect: ConnectState,
  connect_authority: Option<String>,
  selected_transport: Option<SelectedTransport>,
}

#[derive(Clone)]
struct RequestSeed {
  endpoint: Option<String>,
  user: Option<String>,
  context: Map<String, Value>,
  session_id: Option<String>,
  model: Option<String>,
  params: Map<String, Value>,
  inbound_method: String,
  inbound_url: String,
  inbound_headers: Bytes,
  inbound_body: Option<Bytes>,
}

struct AttemptState {
  row_id: String,
  day: String,
  started_elapsed_ms: u64,
  context: Map<String, Value>,
  usage: TokenUsage,
  upstream_status: Option<u16>,
  request_observed: bool,
  upstream_body_finished: bool,
  finished: bool,
  retry_planned: bool,
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

struct RowTarget {
  attempt: Option<AttemptNo>,
  row_id: String,
  day: String,
  started_elapsed_ms: u64,
  context: Map<String, Value>,
}

impl RequestPersistenceConsumer {
  fn on_admitted(&mut self, request_id: &str, state: &mut LogicalState, admitted: &RequestAdmitted) -> WriteResult {
    if state.http_admitted || state.connect != ConnectState::None {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "request admission was observed more than once",
      ));
    }
    let mut context = state.seed.context.clone();
    let endpoint = match admitted {
      RequestAdmitted::Http {
        scheme,
        authority,
        path_and_query,
        operation,
      } => {
        insert_string(&mut context, "scheme", scheme);
        insert_string(&mut context, "authority", authority);
        if path_and_query.is_redacted() {
          context.insert("admitted_target_redacted".to_string(), Value::Bool(true));
        }
        operation
          .as_ref()
          .map(ToString::to_string)
          .or_else(|| Some(path_and_query.as_str().to_string()))
      }
      RequestAdmitted::Connect { authority } => {
        insert_string(&mut context, "authority", authority);
        Some("connect".to_string())
      }
      _ => None,
    };
    let context_json = object_json(&context)?;
    self.store.transaction(&state.base_day, |transaction| {
      require_connection_update(
        transaction,
        request_id,
        "UPDATE request_connection
         SET endpoint = COALESCE(endpoint, ?2), ctx_json = ?3
         WHERE request_id = ?1",
        params![request_id, endpoint.as_deref(), context_json],
      )
    })?;
    if state.seed.endpoint.is_none() {
      state.seed.endpoint = endpoint;
    }
    state.seed.context = context;
    match admitted {
      RequestAdmitted::Http { .. } => state.http_admitted = true,
      RequestAdmitted::Connect { authority } => {
        state.connect = ConnectState::Admitted;
        state.connect_authority = Some(authority.to_string());
      }
      _ => {}
    }
    Ok(())
  }

  fn on_authenticated(&mut self, request_id: &str, state: &mut LogicalState, identity: &ClientIdentity) -> WriteResult {
    let mut context = state.seed.context.clone();
    let user = match identity {
      ClientIdentity::Anonymous => {
        insert_literal(&mut context, "client_identity", "anonymous");
        None
      }
      ClientIdentity::LocalKey { key_id, key_name } => {
        insert_literal(&mut context, "client_identity", "local_key");
        insert_string(&mut context, "api_key_id", key_id);
        key_name.as_ref().map(ToString::to_string)
      }
      ClientIdentity::Embedded => {
        insert_literal(&mut context, "client_identity", "embedded");
        None
      }
      _ => None,
    };
    let context_json = object_json(&context)?;
    self.store.transaction(&state.base_day, |transaction| {
      require_connection_update(
        transaction,
        request_id,
        "UPDATE request_connection
         SET user = COALESCE(user, ?2), ctx_json = ?3
         WHERE request_id = ?1",
        params![request_id, user.as_deref(), context_json],
      )
    })?;
    if state.seed.user.is_none() {
      state.seed.user = user;
    }
    state.seed.context = context;
    Ok(())
  }

  fn on_policy_selected(
    &mut self,
    request_id: &str,
    state: &mut LogicalState,
    selection: &PolicySelection,
  ) -> WriteResult {
    if state.policy_observed {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "request policy was selected more than once",
      ));
    }
    match &selection.action {
      SelectedAction::Http { .. } if state.connect != ConnectState::None => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "HTTP policy followed CONNECT admission",
        ));
      }
      SelectedAction::Connect { .. } if state.http_admitted => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "CONNECT policy followed HTTP admission",
        ));
      }
      _ => {}
    }
    let mut context = state.seed.context.clone();
    insert_optional_string(&mut context, "binding_id", selection.binding_id.as_ref());
    // `mode` and `pipeline_id` are compatibility aliases for the request source.
    // Keep policy-specific detail in dedicated fields so early failures and routed
    // requests project the same ingress vocabulary.
    match &selection.action {
      SelectedAction::Reject => {
        insert_literal(&mut context, "selected_action", "reject");
      }
      SelectedAction::Http {
        profile_id,
        route_id,
        family,
      } => {
        insert_literal(&mut context, "selected_action", "http");
        insert_string(&mut context, "profile_id", profile_id);
        insert_string(&mut context, "route_id", route_id);
        insert_literal(&mut context, "http_family", http_family_name(*family));
      }
      SelectedAction::Connect { action } => {
        insert_literal(&mut context, "selected_action", "connect");
        insert_literal(&mut context, "connect_action", connect_action_name(*action));
      }
      _ => {
        insert_literal(&mut context, "selected_action", "unknown");
      }
    }
    let context_json = object_json(&context)?;
    self.store.transaction(&state.base_day, |transaction| {
      require_connection_update(
        transaction,
        request_id,
        "UPDATE request_connection SET ctx_json = ?2 WHERE request_id = ?1",
        params![request_id, context_json],
      )
    })?;
    state.seed.context = context;
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
    &mut self,
    request_id: &str,
    state: &mut LogicalState,
    observation: &RequestBodyObservation,
  ) -> WriteResult {
    if state.request_body_observed {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "request body was observed more than once",
      ));
    }
    if state.connect != ConnectState::None {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "request body followed CONNECT admission",
      ));
    }
    let mut context = state.seed.context.clone();
    let inbound_capture = if state.embedded_source && matches!(&observation.wire, BodyCapture::Absent) {
      observation.decoded.as_ref().unwrap_or(&observation.wire)
    } else {
      &observation.wire
    };
    let inbound_body = project_body(
      &mut context,
      "inbound_request_body_capture",
      inbound_capture,
      self.options,
    );
    if let Some(decoded) = observation.decoded.as_ref() {
      annotate_event_capture(&mut context, "decoded_request_body_capture", decoded);
    }
    let mut request_error = None;
    if let BodyOutcome::Rejected(failure) = &observation.outcome {
      request_error = Some(format_failure(RequestPhase::RequestBody, failure));
      insert_failure(&mut context, "request_body_failure", failure);
    }
    let model = observation
      .requested_model
      .as_ref()
      .map(ToString::to_string)
      .or_else(|| state.seed.model.clone());
    let mut request_params = state.seed.params.clone();
    if let Some(stream) = observation.stream {
      request_params.insert("stream".to_string(), Value::Bool(stream));
    }
    if let Some(initiator) = observation.initiator.as_ref() {
      insert_string(&mut request_params, "initiator", initiator);
    }
    let params_json = optional_object_json(&request_params)?;
    let context_json = object_json(&context)?;
    self.store.transaction(&state.base_day, |transaction| {
      require_connection_update(
        transaction,
        request_id,
        "UPDATE request_connection
         SET request_error = COALESCE(request_error, ?2), ctx_json = ?3
         WHERE request_id = ?1",
        params![request_id, request_error.as_deref(), context_json],
      )?;
      transaction.execute(
        "INSERT INTO request_metadata (request_id, model, params_json)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(request_id) DO UPDATE SET
           model = COALESCE(request_metadata.model, excluded.model),
           params_json = COALESCE(excluded.params_json, request_metadata.params_json)",
        params![request_id, model.as_deref(), params_json.as_deref()],
      )?;
      transaction.execute(
        "INSERT INTO request_downstream (request_id, inbound_req_body)
         VALUES (?1, ?2)
         ON CONFLICT(request_id) DO UPDATE SET inbound_req_body = excluded.inbound_req_body",
        params![request_id, inbound_body.as_deref()],
      )?;
      Ok(())
    })?;
    state.seed.context = context;
    state.seed.model = model;
    state.seed.params = request_params;
    state.seed.inbound_body = inbound_body;
    state.request_body_observed = true;
    Ok(())
  }

  fn on_attempt_started(
    &mut self,
    request_id: &str,
    event: &TrafficEvent,
    state: &mut LogicalState,
    started: &AttemptStarted,
  ) -> WriteResult {
    if state.connect != ConnectState::None
      || matches!(
        state.selected_transport,
        Some(SelectedTransport::Reject | SelectedTransport::Connect(_))
      )
    {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "HTTP attempt followed a non-HTTP policy or CONNECT lifecycle",
      ));
    }
    let expected_attempt = u32::try_from(state.attempts.len())
      .unwrap_or(u32::MAX)
      .saturating_add(1);
    if started.attempt.get() != expected_attempt {
      return Err(RequestWriteError::lifecycle(
        request_id,
        format!("opened attempt {}, expected {expected_attempt}", started.attempt),
      ));
    }
    if let Some(previous) = state.latest_attempt {
      let previous_state = state
        .attempts
        .get(&previous)
        .expect("latest attempt belongs to the request");
      if !previous_state.finished {
        return Err(RequestWriteError::lifecycle(
          request_id,
          format!("opened attempt {} before attempt {previous} finished", started.attempt),
        ));
      }
      if !previous_state.retry_planned {
        return Err(RequestWriteError::lifecycle(
          request_id,
          format!(
            "opened attempt {} without a retry decision for attempt {previous}",
            started.attempt
          ),
        ));
      }
    }

    let row_id = attempt_row_id(request_id, started.attempt);
    let day = if started.attempt == AttemptNo::FIRST {
      state.base_day.clone()
    } else {
      day_key(event.at_unix_ms)?
    };
    let mut context = state.seed.context.clone();
    context.insert("attempt".to_string(), Value::from(started.attempt.get()));
    insert_target_selection(&mut context, &started.target);
    let context_json = object_json(&context)?;
    let requested_model = state
      .seed
      .model
      .clone()
      .or_else(|| started.target.requested_model.as_ref().map(ToString::to_string));
    let endpoint = state
      .seed
      .endpoint
      .clone()
      .or_else(|| started.target.requested_operation.as_ref().map(ToString::to_string));
    let params_json = optional_object_json(&state.seed.params)?;
    let account_id = started.target.account_id.as_ref().map(ToString::to_string);
    let provider_id = started.target.provider_id.as_ref().map(ToString::to_string);

    if started.attempt == AttemptNo::FIRST {
      self.store.transaction(&day, |transaction| {
        require_connection_update(
          transaction,
          &row_id,
          "UPDATE request_connection
           SET endpoint = COALESCE(endpoint, ?2), ctx_json = ?3
           WHERE request_id = ?1",
          params![row_id, endpoint.as_deref(), context_json],
        )?;
        transaction.execute(
          "INSERT INTO request_metadata (request_id, account_id, provider_id, model, params_json)
           VALUES (?1, ?2, ?3, ?4, ?5)
           ON CONFLICT(request_id) DO UPDATE SET
             account_id = excluded.account_id,
             provider_id = excluded.provider_id,
             model = COALESCE(request_metadata.model, excluded.model),
             params_json = COALESCE(request_metadata.params_json, excluded.params_json)",
          params![
            row_id,
            account_id.as_deref(),
            provider_id.as_deref(),
            requested_model.as_deref(),
            params_json.as_deref()
          ],
        )?;
        Ok(())
      })?;
    } else {
      let version = self.gateway_version.as_ref();
      self.store.transaction(&day, |transaction| {
        transaction.execute(
          "INSERT INTO request_connection (request_id, ts, ver, endpoint, user, ctx_json)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)
           ON CONFLICT(request_id) DO UPDATE SET
             ver = COALESCE(request_connection.ver, excluded.ver),
             endpoint = COALESCE(request_connection.endpoint, excluded.endpoint),
             user = COALESCE(request_connection.user, excluded.user),
             ctx_json = excluded.ctx_json",
          params![
            row_id,
            event.at_unix_ms,
            version,
            endpoint.as_deref(),
            state.seed.user.as_deref(),
            context_json
          ],
        )?;
        transaction.execute(
          "INSERT INTO request_metadata
             (request_id, session_id, account_id, provider_id, model, params_json)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)
           ON CONFLICT(request_id) DO UPDATE SET
             session_id = COALESCE(request_metadata.session_id, excluded.session_id),
             account_id = excluded.account_id,
             provider_id = excluded.provider_id,
             model = COALESCE(request_metadata.model, excluded.model),
             params_json = COALESCE(request_metadata.params_json, excluded.params_json)",
          params![
            row_id,
            state.seed.session_id.as_deref(),
            account_id.as_deref(),
            provider_id.as_deref(),
            requested_model.as_deref(),
            params_json.as_deref()
          ],
        )?;
        transaction.execute(
          "INSERT INTO request_downstream
             (request_id, inbound_req_method, inbound_req_url, inbound_req_headers, inbound_req_body)
           VALUES (?1, ?2, ?3, ?4, ?5)
           ON CONFLICT(request_id) DO UPDATE SET
             inbound_req_method = excluded.inbound_req_method,
             inbound_req_url = excluded.inbound_req_url,
             inbound_req_headers = excluded.inbound_req_headers,
             inbound_req_body = excluded.inbound_req_body",
          params![
            row_id,
            state.seed.inbound_method,
            state.seed.inbound_url,
            state.seed.inbound_headers.as_ref(),
            state.seed.inbound_body.as_deref()
          ],
        )?;
        Ok(())
      })?;
    }

    if state.seed.model.is_none() {
      state.seed.model = requested_model;
    }
    if state.seed.endpoint.is_none() {
      state.seed.endpoint = endpoint;
    }
    state.attempts.insert(
      started.attempt,
      AttemptState {
        row_id,
        day,
        started_elapsed_ms: event.elapsed_ms,
        context,
        usage: TokenUsage::default(),
        upstream_status: None,
        request_observed: false,
        upstream_body_finished: false,
        finished: false,
        retry_planned: false,
      },
    );
    state.latest_attempt = Some(started.attempt);
    Ok(())
  }

  fn on_attempt_request(
    &mut self,
    request_id: &str,
    state: &mut LogicalState,
    event: &AttemptHttpRequest,
  ) -> WriteResult {
    let attempt = require_open_attempt(request_id, state, event.attempt, "request snapshot")?;
    if attempt.request_observed {
      return Err(RequestWriteError::lifecycle(
        request_id,
        format!("attempt {} request was observed more than once", event.attempt),
      ));
    }
    let target = row_target_for_attempt(request_id, state, event.attempt)?;
    let mut context = target.context.clone();
    let body = project_body(
      &mut context,
      "outbound_request_body_capture",
      &event.request.body,
      self.options,
    );
    let context_json = object_json(&context)?;
    let headers = headers_json(&event.request.headers)?;
    self.store.transaction(&target.day, |transaction| {
      require_connection_update(
        transaction,
        &target.row_id,
        "UPDATE request_connection SET ctx_json = ?2 WHERE request_id = ?1",
        params![target.row_id, context_json],
      )?;
      transaction.execute(
        "INSERT INTO request_upstream
           (request_id, outbound_req_method, outbound_req_url, outbound_req_headers, outbound_req_body)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(request_id) DO UPDATE SET
           outbound_req_method = excluded.outbound_req_method,
           outbound_req_url = excluded.outbound_req_url,
           outbound_req_headers = excluded.outbound_req_headers,
           outbound_req_body = excluded.outbound_req_body",
        params![
          target.row_id,
          event.request.method.as_str(),
          event.request.uri.as_str(),
          headers,
          body.as_deref()
        ],
      )?;
      Ok(())
    })?;
    let attempt = state
      .attempts
      .get_mut(&event.attempt)
      .expect("attempt was validated before request persistence");
    attempt.context = context;
    attempt.request_observed = true;
    Ok(())
  }

  fn on_attempt_response_head(
    &mut self,
    request_id: &str,
    elapsed_ms: u64,
    state: &mut LogicalState,
    event: &AttemptHttpResponseHead,
  ) -> WriteResult {
    let attempt = require_open_attempt(request_id, state, event.attempt, "response head")?;
    if attempt.upstream_status.is_some() {
      return Err(RequestWriteError::lifecycle(
        request_id,
        format!("attempt {} response head was observed more than once", event.attempt),
      ));
    }
    let target = row_target_for_attempt(request_id, state, event.attempt)?;
    let mut context = target.context.clone();
    context.insert(
      "latency_header_ms".to_string(),
      Value::from(elapsed_ms.saturating_sub(target.started_elapsed_ms)),
    );
    let context_json = object_json(&context)?;
    let headers = headers_json(&event.response.headers)?;
    self.store.transaction(&target.day, |transaction| {
      require_connection_update(
        transaction,
        &target.row_id,
        "UPDATE request_connection SET ctx_json = ?2 WHERE request_id = ?1",
        params![target.row_id, context_json],
      )?;
      transaction.execute(
        "INSERT INTO request_upstream (request_id, outbound_resp_status, outbound_resp_headers)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(request_id) DO UPDATE SET
           outbound_resp_status = excluded.outbound_resp_status,
           outbound_resp_headers = excluded.outbound_resp_headers",
        params![target.row_id, i64::from(event.response.status), headers],
      )?;
      Ok(())
    })?;
    let attempt = state.attempts.get_mut(&event.attempt).ok_or_else(|| {
      RequestWriteError::lifecycle(
        request_id,
        format!("attempt {} disappeared after persistence", event.attempt),
      )
    })?;
    attempt.context = context;
    attempt.upstream_status = Some(event.response.status);
    Ok(())
  }

  fn on_downstream_response_head(
    &mut self,
    request_id: &str,
    state: &mut LogicalState,
    response: &HttpResponseHead,
  ) -> WriteResult {
    if state.downstream_status.is_some() {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "downstream response head was observed more than once",
      ));
    }
    if matches!(state.connect, ConnectState::Ready(_) | ConnectState::Closed) {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "downstream response head followed a ready CONNECT lifecycle",
      ));
    }
    let target = downstream_target(request_id, state)?;
    let headers = headers_json(&response.headers)?;
    self.store.transaction(&target.day, |transaction| {
      require_connection_update(
        transaction,
        &target.row_id,
        "UPDATE request_connection SET status = ?2 WHERE request_id = ?1",
        params![target.row_id, i64::from(response.status)],
      )?;
      transaction.execute(
        "INSERT INTO request_downstream (request_id, inbound_resp_status, inbound_resp_headers)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(request_id) DO UPDATE SET
           inbound_resp_status = excluded.inbound_resp_status,
           inbound_resp_headers = excluded.inbound_resp_headers",
        params![target.row_id, i64::from(response.status), headers],
      )?;
      Ok(())
    })?;
    state.downstream_status = Some(response.status);
    Ok(())
  }

  fn on_attempt_usage(&mut self, request_id: &str, state: &mut LogicalState, event: &AttemptUsage) -> WriteResult {
    let target = row_target_for_attempt(request_id, state, event.attempt)?;
    let mut merged = state
      .attempts
      .get(&event.attempt)
      .ok_or_else(|| {
        RequestWriteError::lifecycle(
          request_id,
          format!("event refers to unopened attempt {}", event.attempt),
        )
      })?
      .usage
      .clone();
    merged.merge_from(&event.usage);
    let usage_json = usage_json(&merged)?;
    self.store.transaction(&target.day, |transaction| {
      require_connection_anchor(transaction, &target.row_id)?;
      transaction.execute(
        "INSERT INTO request_metadata (request_id, usage_json)
         VALUES (?1, ?2)
         ON CONFLICT(request_id) DO UPDATE SET
           usage_json = COALESCE(excluded.usage_json, request_metadata.usage_json)",
        params![target.row_id, usage_json.as_deref()],
      )?;
      Ok(())
    })?;
    state
      .attempts
      .get_mut(&event.attempt)
      .expect("attempt was validated before usage persistence")
      .usage = merged;
    Ok(())
  }

  fn on_attempt_finished(
    &mut self,
    request_id: &str,
    elapsed_ms: u64,
    state: &mut LogicalState,
    event: &AttemptFinished,
  ) -> WriteResult {
    let target = row_target_for_attempt(request_id, state, event.attempt)?;
    if state
      .attempts
      .get(&event.attempt)
      .is_some_and(|attempt| attempt.finished)
    {
      return Err(RequestWriteError::lifecycle(
        request_id,
        format!("attempt {} finished more than once", event.attempt),
      ));
    }
    let observed_status = state
      .attempts
      .get(&event.attempt)
      .and_then(|attempt| attempt.upstream_status);
    if let (Some(observed), Some(summary)) = (observed_status, event.upstream_status) {
      if observed != summary {
        return Err(RequestWriteError::lifecycle(
          request_id,
          format!(
            "attempt {} terminal status {summary} conflicts with observed response status {observed}",
            event.attempt
          ),
        ));
      }
    }
    let mut context = target.context.clone();
    insert_literal(&mut context, "attempt_outcome", attempt_outcome_name(event.outcome));
    insert_literal(&mut context, "attempt_phase", request_phase_name(event.phase));
    context.insert(
      "latency_ms".to_string(),
      Value::from(elapsed_ms.saturating_sub(target.started_elapsed_ms)),
    );
    let mut request_error = event
      .failure
      .as_ref()
      .map(|failure| format_failure(event.phase, failure));
    if let Some(failure) = event.failure.as_ref() {
      insert_failure(&mut context, "attempt_failure", failure);
    }
    if let Some(retry) = event.retry.as_ref() {
      if request_error.is_none() {
        request_error = Some(format_failure(event.phase, &retry.reason));
      }
      let mut retry_context = Map::new();
      if let Some(delay_ms) = retry.delay_ms {
        retry_context.insert("delay_ms".to_string(), Value::from(delay_ms));
      }
      insert_failure(&mut retry_context, "reason", &retry.reason);
      context.insert("retry".to_string(), Value::Object(retry_context));
    }
    if request_error.is_none() {
      request_error = match event.outcome {
        AttemptOutcome::Response => None,
        AttemptOutcome::Failed => Some(format!("{}: failed", request_phase_name(event.phase))),
        AttemptOutcome::Cancelled => Some(format!("{}: cancelled", request_phase_name(event.phase))),
        _ => Some(format!("{}: attempt did not complete", request_phase_name(event.phase))),
      };
    }
    let context_json = object_json(&context)?;
    self.store.transaction(&target.day, |transaction| {
      require_connection_update(
        transaction,
        &target.row_id,
        "UPDATE request_connection
         SET request_error = COALESCE(request_error, ?2), ctx_json = ?3
         WHERE request_id = ?1",
        params![target.row_id, request_error.as_deref(), context_json],
      )?;
      transaction.execute(
        "INSERT INTO request_upstream (request_id, outbound_resp_status)
         VALUES (?1, ?2)
         ON CONFLICT(request_id) DO UPDATE SET
           outbound_resp_status = COALESCE(request_upstream.outbound_resp_status, excluded.outbound_resp_status)",
        params![target.row_id, event.upstream_status.map(i64::from)],
      )?;
      Ok(())
    })?;
    let attempt = state.attempts.get_mut(&event.attempt).ok_or_else(|| {
      RequestWriteError::lifecycle(
        request_id,
        format!("attempt {} disappeared after persistence", event.attempt),
      )
    })?;
    attempt.context = context;
    attempt.finished = true;
    attempt.retry_planned = event.retry.is_some();
    Ok(())
  }

  fn on_body_progress(&mut self, request_id: &str, state: &mut LogicalState, event: &BodyProgress) -> WriteResult {
    match event.leg {
      BodyLeg::Upstream { attempt } => {
        let attempt_state = require_open_attempt(request_id, state, attempt, "body progress")?;
        if attempt_state.upstream_body_finished {
          return Err(RequestWriteError::lifecycle(
            request_id,
            format!("attempt {attempt} body progress followed body completion"),
          ));
        }
      }
      BodyLeg::Downstream => {
        if state.downstream_body_finished {
          return Err(RequestWriteError::lifecycle(
            request_id,
            "downstream body progress followed body completion",
          ));
        }
        if matches!(state.connect, ConnectState::Ready(_) | ConnectState::Closed) {
          return Err(RequestWriteError::lifecycle(
            request_id,
            "downstream body progress followed a ready CONNECT lifecycle",
          ));
        }
      }
      _ => {}
    }
    Ok(())
  }

  fn on_body_finished(&mut self, request_id: &str, state: &mut LogicalState, event: &BodyFinished) -> WriteResult {
    match event.leg {
      BodyLeg::Upstream { attempt } => {
        let attempt_state = require_open_attempt(request_id, state, attempt, "body completion")?;
        if attempt_state.upstream_body_finished {
          return Err(RequestWriteError::lifecycle(
            request_id,
            format!("attempt {attempt} body finished more than once"),
          ));
        }
      }
      BodyLeg::Downstream => {
        if state.downstream_body_finished {
          return Err(RequestWriteError::lifecycle(
            request_id,
            "downstream body finished more than once",
          ));
        }
        if matches!(state.connect, ConnectState::Ready(_) | ConnectState::Closed) {
          return Err(RequestWriteError::lifecycle(
            request_id,
            "downstream body completion followed a ready CONNECT lifecycle",
          ));
        }
      }
      _ => {}
    }
    let (target, context_key, phase, upstream) = match event.leg {
      BodyLeg::Upstream { attempt } => (
        row_target_for_attempt(request_id, state, attempt)?,
        "upstream_response_body_capture",
        RequestPhase::UpstreamResponse,
        true,
      ),
      BodyLeg::Downstream => (
        downstream_target(request_id, state)?,
        "downstream_response_body_capture",
        RequestPhase::DownstreamResponse,
        false,
      ),
      _ => return Ok(()),
    };
    let mut context = target.context.clone();
    let body = project_body(&mut context, context_key, &event.capture, self.options);
    insert_literal(
      &mut context,
      if upstream {
        "upstream_body_result"
      } else {
        "downstream_body_result"
      },
      body_result_name(&event.result),
    );
    let request_error = body_result_error(phase, &event.result);
    if let BodyResult::Failed(failure) = &event.result {
      insert_failure(
        &mut context,
        if upstream {
          "upstream_body_failure"
        } else {
          "downstream_body_failure"
        },
        failure,
      );
    }
    let context_json = object_json(&context)?;
    self.store.transaction(&target.day, |transaction| {
      require_connection_update(
        transaction,
        &target.row_id,
        "UPDATE request_connection
         SET request_error = COALESCE(request_error, ?2), ctx_json = ?3
         WHERE request_id = ?1",
        params![target.row_id, request_error.as_deref(), context_json],
      )?;
      if upstream {
        transaction.execute(
          "INSERT INTO request_upstream (request_id, outbound_resp_body)
           VALUES (?1, ?2)
           ON CONFLICT(request_id) DO UPDATE SET outbound_resp_body = excluded.outbound_resp_body",
          params![target.row_id, body.as_deref()],
        )?;
      } else {
        transaction.execute(
          "INSERT INTO request_downstream (request_id, inbound_resp_body)
           VALUES (?1, ?2)
           ON CONFLICT(request_id) DO UPDATE SET inbound_resp_body = excluded.inbound_resp_body",
          params![target.row_id, body.as_deref()],
        )?;
      }
      Ok(())
    })?;
    set_target_context(state, target.attempt, context)?;
    match event.leg {
      BodyLeg::Upstream { attempt } => {
        state
          .attempts
          .get_mut(&attempt)
          .expect("attempt was validated before body persistence")
          .upstream_body_finished = true;
      }
      BodyLeg::Downstream => state.downstream_body_finished = true,
      _ => {}
    }
    Ok(())
  }

  fn on_connect_ready(&mut self, request_id: &str, state: &mut LogicalState, event: &ConnectReady) -> WriteResult {
    if state.http_admitted || !state.attempts.is_empty() {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "ConnectReady followed an HTTP lifecycle",
      ));
    }
    match state.connect {
      ConnectState::Admitted => {}
      ConnectState::None => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectReady was emitted before CONNECT admission",
        ));
      }
      ConnectState::Ready(_) | ConnectState::Closed => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectReady was emitted more than once",
        ));
      }
    }
    if event.action == ConnectAction::Reject {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "rejected CONNECT cannot become ready",
      ));
    }
    match state.selected_transport {
      Some(SelectedTransport::Connect(action)) if action == event.action => {}
      Some(SelectedTransport::Connect(_)) => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectReady action differs from the selected CONNECT policy",
        ));
      }
      Some(_) => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectReady followed a non-CONNECT policy",
        ));
      }
      None => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectReady was emitted before CONNECT policy selection",
        ));
      }
    }
    if state.downstream_status.is_some() || state.downstream_body_finished {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "ConnectReady followed an HTTP response boundary",
      ));
    }
    if state.connect_authority.as_deref() != Some(event.authority.as_str()) {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "ConnectReady authority differs from CONNECT admission",
      ));
    }
    let mut context = state.seed.context.clone();
    insert_literal(&mut context, "connect_action", connect_action_name(event.action));
    insert_string(&mut context, "authority", &event.authority);
    let context_json = object_json(&context)?;
    self.store.transaction(&state.base_day, |transaction| {
      require_connection_update(
        transaction,
        request_id,
        "UPDATE request_connection SET status = 200, ctx_json = ?2 WHERE request_id = ?1",
        params![request_id, context_json],
      )?;
      transaction.execute(
        "INSERT INTO request_downstream (request_id, inbound_resp_status)
         VALUES (?1, 200)
         ON CONFLICT(request_id) DO UPDATE SET inbound_resp_status = 200",
        params![request_id],
      )?;
      Ok(())
    })?;
    state.seed.context = context;
    state.downstream_status = Some(200);
    state.connect = ConnectState::Ready(event.action);
    Ok(())
  }

  fn on_connect_closed(&mut self, request_id: &str, state: &mut LogicalState, event: &ConnectClosed) -> WriteResult {
    if !state.attempts.is_empty() {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "ConnectClosed followed an HTTP attempt",
      ));
    }
    match state.connect {
      ConnectState::None | ConnectState::Admitted => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectClosed was emitted before ConnectReady",
        ));
      }
      ConnectState::Ready(action) if action != event.action => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectClosed action differs from ConnectReady",
        ));
      }
      ConnectState::Ready(_) => {}
      ConnectState::Closed => {
        return Err(RequestWriteError::lifecycle(
          request_id,
          "ConnectClosed was emitted more than once",
        ));
      }
    }
    let mut context = state.seed.context.clone();
    insert_literal(&mut context, "connect_action", connect_action_name(event.action));
    if let Some(bytes) = event.client_to_upstream_bytes {
      context.insert("client_to_upstream_bytes".to_string(), Value::from(bytes));
    }
    if let Some(bytes) = event.upstream_to_client_bytes {
      context.insert("upstream_to_client_bytes".to_string(), Value::from(bytes));
    }
    insert_literal(&mut context, "connect_result", body_result_name(&event.result));
    let request_error = body_result_error(RequestPhase::Connect, &event.result);
    if let BodyResult::Failed(failure) = &event.result {
      insert_failure(&mut context, "connect_failure", failure);
    }
    let context_json = object_json(&context)?;
    self.store.transaction(&state.base_day, |transaction| {
      require_connection_update(
        transaction,
        request_id,
        "UPDATE request_connection
         SET request_error = COALESCE(request_error, ?2), ctx_json = ?3
         WHERE request_id = ?1",
        params![request_id, request_error.as_deref(), context_json],
      )
    })?;
    state.seed.context = context;
    state.connect = ConnectState::Closed;
    Ok(())
  }

  fn on_finished(
    &mut self,
    request_id: &str,
    elapsed_ms: u64,
    state: &mut LogicalState,
    finished: &RequestFinished,
  ) -> WriteResult {
    if finished.attempt_count != state.attempts.len() as u32 {
      return Err(RequestWriteError::lifecycle(
        request_id,
        format!(
          "Finished reports {} attempts after {} AttemptStarted events",
          finished.attempt_count,
          state.attempts.len()
        ),
      ));
    }
    if let Some((attempt, _)) = state.attempts.iter().find(|(_, attempt)| !attempt.finished) {
      return Err(RequestWriteError::lifecycle(
        request_id,
        format!("request finished before attempt {attempt} completed"),
      ));
    }
    if matches!(state.connect, ConnectState::Ready(_)) {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "request finished before CONNECT closed",
      ));
    }
    if state.connect == ConnectState::Admitted && finished.outcome == tokn_events::RequestOutcome::Delivered {
      return Err(RequestWriteError::lifecycle(
        request_id,
        "CONNECT was delivered before it became ready and closed",
      ));
    }
    if let (Some(observed), Some(summary)) = (state.downstream_status, finished.downstream_status) {
      if observed != summary {
        return Err(RequestWriteError::lifecycle(
          request_id,
          format!("terminal status {summary} conflicts with observed downstream status {observed}"),
        ));
      }
    }
    let target = downstream_target(request_id, state)?;
    let mut context = target.context.clone();
    context.insert(
      "latency_ms".to_string(),
      Value::from(elapsed_ms.saturating_sub(target.started_elapsed_ms)),
    );
    context.insert("request_latency_ms".to_string(), Value::from(elapsed_ms));
    insert_literal(&mut context, "request_outcome", request_outcome_name(finished.outcome));
    insert_literal(&mut context, "request_phase", request_phase_name(finished.phase));
    context.insert("attempt_count".to_string(), Value::from(finished.attempt_count));
    let request_error = terminal_error(finished);
    if let Some(failure) = finished.failure.as_ref() {
      insert_failure(&mut context, "request_failure", failure);
    }
    let context_json = object_json(&context)?;
    self.store.transaction(&target.day, |transaction| {
      require_connection_update(
        transaction,
        &target.row_id,
        "UPDATE request_connection
         SET status = COALESCE(status, ?2), request_error = COALESCE(request_error, ?3), ctx_json = ?4
         WHERE request_id = ?1",
        params![
          target.row_id,
          finished.downstream_status.map(i64::from),
          request_error.as_deref(),
          context_json
        ],
      )?;
      transaction.execute(
        "INSERT INTO request_downstream (request_id, inbound_resp_status)
         VALUES (?1, ?2)
         ON CONFLICT(request_id) DO UPDATE SET
           inbound_resp_status = COALESCE(request_downstream.inbound_resp_status, excluded.inbound_resp_status)",
        params![target.row_id, finished.downstream_status.map(i64::from)],
      )?;
      Ok(())
    })?;
    set_target_context(state, target.attempt, context)?;
    Ok(())
  }
}

fn require_connection_update(
  transaction: &Transaction<'_>,
  request_id: &str,
  sql: &str,
  values: impl rusqlite::Params,
) -> WriteResult {
  if transaction.execute(sql, values)? == 0 {
    return Err(RequestWriteError::lifecycle(
      request_id,
      "request_connection anchor disappeared during persistence",
    ));
  }
  Ok(())
}

fn require_connection_anchor(transaction: &Transaction<'_>, request_id: &str) -> WriteResult {
  let exists = transaction.query_row(
    "SELECT EXISTS(SELECT 1 FROM request_connection WHERE request_id = ?1)",
    params![request_id],
    |row| row.get::<_, bool>(0),
  )?;
  if !exists {
    return Err(RequestWriteError::lifecycle(
      request_id,
      "request_connection anchor disappeared during persistence",
    ));
  }
  Ok(())
}

fn downstream_target(request_id: &str, state: &LogicalState) -> WriteResult<RowTarget> {
  if let Some(attempt) = state.latest_attempt {
    return row_target_for_attempt(request_id, state, attempt);
  }
  Ok(RowTarget {
    attempt: None,
    row_id: request_id.to_string(),
    day: state.base_day.clone(),
    started_elapsed_ms: 0,
    context: state.seed.context.clone(),
  })
}

fn row_target_for_attempt(request_id: &str, state: &LogicalState, attempt: AttemptNo) -> WriteResult<RowTarget> {
  let attempt_state = state
    .attempts
    .get(&attempt)
    .ok_or_else(|| RequestWriteError::lifecycle(request_id, format!("event refers to unopened attempt {attempt}")))?;
  Ok(RowTarget {
    attempt: Some(attempt),
    row_id: attempt_state.row_id.clone(),
    day: attempt_state.day.clone(),
    started_elapsed_ms: attempt_state.started_elapsed_ms,
    context: attempt_state.context.clone(),
  })
}

fn require_open_attempt<'a>(
  request_id: &str,
  state: &'a LogicalState,
  attempt: AttemptNo,
  boundary: &str,
) -> WriteResult<&'a AttemptState> {
  let attempt_state = state
    .attempts
    .get(&attempt)
    .ok_or_else(|| RequestWriteError::lifecycle(request_id, format!("event refers to unopened attempt {attempt}")))?;
  if attempt_state.finished {
    return Err(RequestWriteError::lifecycle(
      request_id,
      format!("attempt {attempt} received {boundary} after it finished"),
    ));
  }
  Ok(attempt_state)
}

fn set_target_context(
  state: &mut LogicalState,
  attempt: Option<AttemptNo>,
  context: Map<String, Value>,
) -> WriteResult {
  if let Some(attempt) = attempt {
    let attempt_state = state.attempts.get_mut(&attempt).ok_or_else(|| {
      RequestWriteError::lifecycle("unknown", format!("attempt {attempt} disappeared after persistence"))
    })?;
    attempt_state.context = context;
  } else {
    state.seed.context = context;
  }
  Ok(())
}

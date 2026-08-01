use bytes::Bytes;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use tokn_events::{
  AttemptFinished, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted, AttemptUsage, BodyCapture,
  BodyOutcome, BodyResult, CapturedHeaders, CapturedUri, ClientIdentity, ConnectAction, ConnectClosed, ConnectReady,
  ConsumerResult, Correlation, EventConsumer, EventFailure, EventSeq, GatewayEvent, HttpFamily, HttpResponseHead,
  IngressKind, RequestAdmitted, RequestBodyObservation, RequestFinished, RequestId, RequestOutcome, RequestPhase,
  RequestSource, RequestStarted, RetryDecision, TargetSelection, TokenUsage, TrafficEvent, TrafficEventKind, UsageKind,
};
use tokn_persistence::usage::{UsageDb, UsagePersistenceConsumer};

const START_MS: i64 = 1_783_987_200_000;

#[test]
fn successful_attempt_preserves_current_usage_row_shape() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("successful");

  events
    .emit(&mut consumer, 0, TrafficEventKind::Started(started()))
    .unwrap();
  events
    .emit(
      &mut consumer,
      1,
      TrafficEventKind::Admitted(RequestAdmitted::Http {
        scheme: "http".into(),
        authority: "gateway.test".into(),
        path_and_query: CapturedUri::exact("/v1/responses"),
        operation: Some("responses".into()),
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      2,
      TrafficEventKind::Authenticated(ClientIdentity::LocalKey {
        key_id: "key-1".into(),
        key_name: Some("client-a".into()),
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      3,
      TrafficEventKind::RequestBody(accepted_body("client-model")),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      10,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account-1", "provider-1"),
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
        attempt: AttemptNo::FIRST,
        response: HttpResponseHead {
          status: 202,
          headers: CapturedHeaders::default(),
        },
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      21,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: usage(),
      }),
    )
    .unwrap();

  assert_eq!(row_count(&path), 0, "usage is not persisted before attempt completion");

  events
    .emit(
      &mut consumer,
      30,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 202)),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      31,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }),
    )
    .unwrap();
  events
    .emit(&mut consumer, 40, TrafficEventKind::Finished(delivered(1)))
    .unwrap();

  let connection = Connection::open(&path).unwrap();
  let row = connection
    .query_row(
      "SELECT ts, session_id, project_id, ver, request_error, user, endpoint, account_id,
              provider_id, model, params_json, usage_json, ctx_json, status
       FROM requests WHERE request_id = 'successful'",
      [],
      |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, Option<String>>(1)?,
          row.get::<_, Option<String>>(2)?,
          row.get::<_, Option<String>>(3)?,
          row.get::<_, Option<String>>(4)?,
          row.get::<_, Option<String>>(5)?,
          row.get::<_, Option<String>>(6)?,
          row.get::<_, Option<String>>(7)?,
          row.get::<_, Option<String>>(8)?,
          row.get::<_, String>(9)?,
          row.get::<_, Option<String>>(10)?,
          row.get::<_, Option<String>>(11)?,
          row.get::<_, Option<String>>(12)?,
          row.get::<_, Option<i64>>(13)?,
        ))
      },
    )
    .unwrap();
  assert_eq!(row.0, START_MS + 10);
  assert_eq!(row.1.as_deref(), Some("session-1"));
  assert_eq!(row.2.as_deref(), Some("project-1"));
  assert_eq!(row.3.as_deref(), Some("test-version"));
  assert_eq!(row.4, None);
  assert_eq!(row.5.as_deref(), Some("client-a"));
  assert_eq!(row.6.as_deref(), Some("responses"));
  assert_eq!(row.7.as_deref(), Some("account-1"));
  assert_eq!(row.8.as_deref(), Some("provider-1"));
  assert_eq!(row.9, "client-model");
  assert_eq!(
    parse_json(row.10.as_deref()),
    Some(serde_json::json!({"initiator": "user", "stream": true}))
  );
  assert_eq!(
    parse_json(row.11.as_deref()),
    Some(serde_json::json!({
      "kind": "responses",
      "input": 12,
      "output": 5,
      "total": 17,
      "cache_read": 3,
      "reasoning": 2
    }))
  );
  let context = parse_json(row.12.as_deref()).unwrap();
  assert_eq!(context["api_key_id"], "key-1");
  assert_eq!(context["local_addr"], "127.0.0.1:4141");
  assert_eq!(context["peer_addr"], "127.0.0.1:9999");
  assert_eq!(context["mode"], "route");
  assert_eq!(context["pipeline_id"], "requests");
  assert_eq!(context["latency_header_ms"], 10);
  assert_eq!(context["latency_ms"], 20);
  assert_eq!(context["request_latency_ms"], 40);
  assert_eq!(row.13, Some(200));
}

#[test]
fn completion_without_usage_still_writes_a_row() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("no-usage");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 200)),
    )
    .unwrap();
  events
    .emit(&mut consumer, 30, TrafficEventKind::Finished(delivered(1)))
    .unwrap();

  let connection = Connection::open(path).unwrap();
  let row: (String, Option<String>, Option<i64>) = connection
    .query_row(
      "SELECT model, usage_json, status FROM requests WHERE request_id = 'no-usage'",
      [],
      |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap();
  assert_eq!(row, ("client-model".to_string(), None, Some(200)));
}

#[test]
fn terminal_batch_can_report_usage_after_attempt_completion() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("late-usage");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 200)),
    )
    .unwrap();
  assert_eq!(read_usage(&path, "late-usage"), None);

  events
    .emit(
      &mut consumer,
      21,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: usage(),
      }),
    )
    .unwrap();
  events
    .emit(&mut consumer, 22, TrafficEventKind::Finished(delivered(1)))
    .unwrap();

  let usage = parse_json(read_usage(&path, "late-usage").as_deref()).unwrap();
  assert_eq!(usage["input"], 12);
  assert_eq!(usage["output"], 5);
  assert_eq!(row_count(&path), 1);
}

#[test]
fn sparse_usage_updates_merge_without_erasing_reported_fields() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("sparse-usage");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  events
    .emit(
      &mut consumer,
      15,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          kind: Some(UsageKind::Responses),
          input: Some(12),
          cache_read: Some(3),
          ..TokenUsage::default()
        },
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 200)),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      21,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          output: Some(5),
          total: Some(17),
          cache_write: Some(2),
          reasoning: Some(1),
          ..TokenUsage::default()
        },
      }),
    )
    .unwrap();
  events
    .emit(&mut consumer, 22, TrafficEventKind::Finished(delivered(1)))
    .unwrap();

  assert_eq!(
    parse_json(read_usage(&path, "sparse-usage").as_deref()),
    Some(serde_json::json!({
      "kind": "responses",
      "input": 12,
      "output": 5,
      "total": 17,
      "cache_read": 3,
      "cache_write": 2,
      "reasoning": 1
    }))
  );
}

#[test]
fn usage_summary_labels_accountless_targets_without_changing_the_schema() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("accountless");
  events
    .emit(&mut consumer, 0, TrafficEventKind::Started(started()))
    .unwrap();
  events
    .emit(
      &mut consumer,
      1,
      TrafficEventKind::RequestBody(accepted_body("client-model")),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      10,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: TargetSelection {
          family: HttpFamily::Transparent,
          account_id: None,
          provider_id: None,
          upstream_id: None,
          requested_model: Some("client-model".into()),
          upstream_model: Some("client-model".into()),
          requested_operation: Some("responses".into()),
          upstream_operation: Some("responses".into()),
        },
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: usage(),
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      30,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 200)),
    )
    .unwrap();
  events
    .emit(&mut consumer, 31, TrafficEventKind::Finished(delivered(1)))
    .unwrap();

  let db = UsageDb::open(&path).unwrap();
  let rows = db.summary(0, None, None).unwrap();
  assert_eq!(rows.len(), 1);
  assert_eq!(rows[0].account, "unknown");
  assert_eq!(rows[0].provider, "unknown");

  let filtered = db.summary(0, Some("unknown"), Some("unknown")).unwrap();
  assert_eq!(filtered.len(), 1);
  assert_eq!(filtered[0].model, "client-model");
}

#[test]
fn retries_keep_legacy_request_ids() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("retry");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  let retry_failure = failure("rate_limited", "try the next account");
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(429),
        failure: None,
        retry: Some(RetryDecision {
          delay_ms: Some(25),
          reason: retry_failure,
        }),
      }),
    )
    .unwrap();
  let second = AttemptNo::new(2).unwrap();
  events
    .emit(
      &mut consumer,
      30,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: second,
        target: target("account-2", "provider-2"),
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      40,
      TrafficEventKind::AttemptFinished(completed_attempt(second, 200)),
    )
    .unwrap();
  events
    .emit(&mut consumer, 45, TrafficEventKind::Finished(delivered(2)))
    .unwrap();

  let connection = Connection::open(path).unwrap();
  let rows = connection
    .prepare("SELECT request_id, account_id, provider_id, request_error FROM requests ORDER BY id")
    .unwrap()
    .query_map([], |row| {
      Ok((
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, String>(2)?,
        row.get::<_, Option<String>>(3)?,
      ))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap();
  assert_eq!(rows.len(), 2);
  assert_eq!(
    (rows[0].0.as_str(), rows[0].1.as_str(), rows[0].2.as_str()),
    ("retry", "account-1", "provider-1")
  );
  assert_eq!(rows[0].3.as_deref(), Some("upstream_response: try the next account"));
  assert_eq!(
    (rows[1].0.as_str(), rows[1].1.as_str(), rows[1].2.as_str()),
    ("retry:1", "account-2", "provider-2")
  );
  assert_eq!(rows[1].3, None);
}

#[test]
fn retry_attempt_requires_the_previous_terminal_retry_decision() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("retry-without-decision");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 200)),
    )
    .unwrap();

  let second = AttemptNo::new(2).unwrap();
  let error = events
    .emit(
      &mut consumer,
      30,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: second,
        target: target("account-2", "provider-2"),
      }),
    )
    .unwrap_err();
  assert!(error
    .to_string()
    .contains("opened attempt 2 without a retry decision for attempt 1"));

  events
    .emit(&mut consumer, 31, TrafficEventKind::Finished(delivered(1)))
    .unwrap();
  assert_eq!(row_count(&path), 1);
}

#[test]
fn response_head_status_is_preserved_and_must_match_attempt_terminal_summary() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("upstream-status");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptResponseHead(response_head(AttemptNo::FIRST, 202)),
    )
    .unwrap();

  let error = events
    .emit(
      &mut consumer,
      25,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 503)),
    )
    .unwrap_err();
  assert!(error
    .to_string()
    .contains("attempt 1 terminal status 503 conflicts with observed response status 202"));
  assert_eq!(row_count(&path), 0);

  events
    .emit(
      &mut consumer,
      26,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 202)),
    )
    .unwrap();
  assert_eq!(read_status(&path, "upstream-status"), Some(202));
  events
    .emit(
      &mut consumer,
      27,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }),
    )
    .unwrap();
  events
    .emit(&mut consumer, 30, TrafficEventKind::Finished(delivered(1)))
    .unwrap();
  assert_eq!(read_status(&path, "upstream-status"), Some(200));
}

#[test]
fn downstream_wire_status_wins_and_rejects_conflicting_heads_or_terminal_summary() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("downstream-status");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptFinished(completed_attempt(AttemptNo::FIRST, 202)),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      21,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 201,
        headers: CapturedHeaders::default(),
      }),
    )
    .unwrap();
  assert_eq!(read_status(&path, "downstream-status"), Some(201));

  let changed_head = events
    .emit(
      &mut consumer,
      22,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 202,
        headers: CapturedHeaders::default(),
      }),
    )
    .unwrap_err();
  assert!(changed_head
    .to_string()
    .contains("downstream response status changed from 201 to 202"));
  assert_eq!(read_status(&path, "downstream-status"), Some(201));

  let mismatch = events
    .emit(
      &mut consumer,
      23,
      TrafficEventKind::Finished(RequestFinished {
        downstream_status: Some(200),
        ..delivered(1)
      }),
    )
    .unwrap_err();
  assert!(mismatch
    .to_string()
    .contains("terminal status 200 conflicts with observed downstream status 201"));
  assert_eq!(read_status(&path, "downstream-status"), Some(201));

  events
    .emit(
      &mut consumer,
      24,
      TrafficEventKind::Finished(RequestFinished {
        downstream_status: Some(201),
        ..delivered(1)
      }),
    )
    .unwrap();
  assert_eq!(read_status(&path, "downstream-status"), Some(201));
}

#[test]
fn connect_lifecycle_rejects_http_attempts_and_requires_close_before_finish() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("connect");
  events
    .emit(&mut consumer, 0, TrafficEventKind::Started(started()))
    .unwrap();
  events
    .emit(
      &mut consumer,
      1,
      TrafficEventKind::Admitted(RequestAdmitted::Connect {
        authority: "upstream.test:443".into(),
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      2,
      TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "upstream.test:443".into(),
      }),
    )
    .unwrap();

  let attempt_error = events
    .emit(
      &mut consumer,
      3,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account-1", "provider-1"),
      }),
    )
    .unwrap_err();
  assert!(attempt_error
    .to_string()
    .contains("HTTP attempt followed a CONNECT lifecycle"));

  let unfinished = events
    .emit(
      &mut consumer,
      4,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Delivered,
        phase: RequestPhase::Connect,
        downstream_status: Some(200),
        failure: None,
        attempt_count: 0,
      }),
    )
    .unwrap_err();
  assert!(unfinished
    .to_string()
    .contains("request finished before CONNECT closed"));

  events
    .emit(
      &mut consumer,
      5,
      TrafficEventKind::ConnectClosed(ConnectClosed {
        action: ConnectAction::Tunnel,
        client_to_upstream_bytes: Some(12),
        upstream_to_client_bytes: Some(34),
        result: BodyResult::Complete,
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      6,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Delivered,
        phase: RequestPhase::Connect,
        downstream_status: Some(200),
        failure: None,
        attempt_count: 0,
      }),
    )
    .unwrap();
  assert_eq!(row_count(&path), 0);
}

#[test]
fn early_body_failure_does_not_invent_a_usage_row() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("parse-failure");
  events
    .emit(&mut consumer, 0, TrafficEventKind::Started(started()))
    .unwrap();
  let parse_failure = failure("invalid_json", "request body is not valid JSON");
  events
    .emit(
      &mut consumer,
      1,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Complete(Bytes::from_static(b"{")),
        decoded: Some(BodyCapture::Complete(Bytes::from_static(b"{"))),
        requested_model: None,
        stream: None,
        initiator: None,
        outcome: BodyOutcome::Rejected(parse_failure.clone()),
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      2,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Rejected,
        phase: RequestPhase::RequestBody,
        downstream_status: Some(400),
        failure: Some(parse_failure),
        attempt_count: 0,
      }),
    )
    .unwrap();

  assert_eq!(row_count(&path), 0);
}

#[test]
fn attempt_errors_are_persisted_and_lifecycle_errors_propagate() {
  let path = temp_usage_db();
  let mut consumer = UsagePersistenceConsumer::open(&path, "test-version").unwrap();
  let mut events = Events::new("failed");
  start_attempt(&mut events, &mut consumer, AttemptNo::FIRST, "account-1", "provider-1");
  let timeout = failure("timeout", "upstream timed out");
  events
    .emit(
      &mut consumer,
      20,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Failed,
        phase: RequestPhase::UpstreamRequest,
        upstream_status: None,
        failure: Some(timeout.clone()),
        retry: None,
      }),
    )
    .unwrap();
  events
    .emit(
      &mut consumer,
      25,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Failed,
        phase: RequestPhase::UpstreamRequest,
        downstream_status: Some(502),
        failure: Some(timeout),
        attempt_count: 1,
      }),
    )
    .unwrap();
  let connection = Connection::open(&path).unwrap();
  let row: (String, Option<i64>) = connection
    .query_row(
      "SELECT request_error, status FROM requests WHERE request_id = 'failed'",
      [],
      |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap();
  assert_eq!(row.0, "upstream_request: upstream timed out");
  assert_eq!(row.1, Some(502));

  let mut malformed = Events::new("malformed");
  malformed
    .emit(&mut consumer, 0, TrafficEventKind::Started(started()))
    .unwrap();
  let error = malformed
    .emit(
      &mut consumer,
      1,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: usage(),
      }),
    )
    .unwrap_err();
  assert!(error.to_string().contains("usage event refers to unopened attempt 1"));
}

struct Events {
  request_id: &'static str,
  sequence: u64,
}

impl Events {
  fn new(request_id: &'static str) -> Self {
    Self {
      request_id,
      sequence: 1,
    }
  }

  fn emit(
    &mut self,
    consumer: &mut UsagePersistenceConsumer,
    elapsed_ms: u64,
    kind: TrafficEventKind,
  ) -> ConsumerResult {
    let event = GatewayEvent::Traffic(TrafficEvent {
      request_id: RequestId::new(self.request_id).expect("test request IDs satisfy the public grammar"),
      sequence: self.sequence,
      at_unix_ms: START_MS + i64::try_from(elapsed_ms).unwrap(),
      elapsed_ms,
      kind,
    });
    let result = consumer.handle(EventSeq::ZERO, &event);
    if result.is_ok() {
      self.sequence += 1;
    }
    result
  }
}

fn start_attempt(
  events: &mut Events,
  consumer: &mut UsagePersistenceConsumer,
  attempt: AttemptNo,
  account: &str,
  provider: &str,
) {
  if attempt == AttemptNo::FIRST {
    events.emit(consumer, 0, TrafficEventKind::Started(started())).unwrap();
    events
      .emit(
        consumer,
        1,
        TrafficEventKind::Admitted(RequestAdmitted::Http {
          scheme: "http".into(),
          authority: "gateway.test".into(),
          path_and_query: CapturedUri::exact("/v1/responses"),
          operation: Some("responses".into()),
        }),
      )
      .unwrap();
    events
      .emit(
        consumer,
        2,
        TrafficEventKind::RequestBody(accepted_body("client-model")),
      )
      .unwrap();
  }
  events
    .emit(
      consumer,
      10,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt,
        target: target(account, provider),
      }),
    )
    .unwrap();
}

fn started() -> RequestStarted {
  RequestStarted {
    source: RequestSource::Listener {
      listener_id: "listener".into(),
      ingress: IngressKind::LlmApi,
      local_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4141)),
      peer_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)),
    },
    http_version: Some("HTTP/1.1".into()),
    method: "POST".into(),
    target: CapturedUri::exact("/v1/responses"),
    headers: CapturedHeaders::default(),
    body_present: true,
    correlation: Correlation {
      session_id: Some("session-1".into()),
      project_id: Some("project-1".into()),
      ..Correlation::default()
    },
  }
}

fn accepted_body(model: &str) -> RequestBodyObservation {
  RequestBodyObservation {
    wire: BodyCapture::Complete(Bytes::from_static(br#"{"model":"client-model"}"#)),
    decoded: Some(BodyCapture::Complete(Bytes::from_static(
      br#"{"model":"client-model"}"#,
    ))),
    requested_model: Some(model.into()),
    stream: Some(true),
    initiator: Some("user".into()),
    outcome: BodyOutcome::Accepted,
  }
}

fn target(account: &str, provider: &str) -> TargetSelection {
  TargetSelection {
    family: HttpFamily::Managed,
    account_id: Some(account.into()),
    provider_id: Some(provider.into()),
    upstream_id: Some("upstream".into()),
    requested_model: Some("client-model".into()),
    upstream_model: Some("upstream-model".into()),
    requested_operation: Some("responses".into()),
    upstream_operation: Some("responses".into()),
  }
}

fn usage() -> TokenUsage {
  TokenUsage {
    kind: Some(UsageKind::Responses),
    input: Some(12),
    output: Some(5),
    total: Some(17),
    cache_read: Some(3),
    cache_write: None,
    reasoning: Some(2),
  }
}

fn completed_attempt(attempt: AttemptNo, status: u16) -> AttemptFinished {
  AttemptFinished {
    attempt,
    outcome: AttemptOutcome::Response,
    phase: RequestPhase::UpstreamResponse,
    upstream_status: Some(status),
    failure: None,
    retry: None,
  }
}

fn response_head(attempt: AttemptNo, status: u16) -> AttemptHttpResponseHead {
  AttemptHttpResponseHead {
    attempt,
    response: HttpResponseHead {
      status,
      headers: CapturedHeaders::default(),
    },
  }
}

fn delivered(attempt_count: u32) -> RequestFinished {
  RequestFinished {
    outcome: RequestOutcome::Delivered,
    phase: RequestPhase::Complete,
    downstream_status: Some(200),
    failure: None,
    attempt_count,
  }
}

fn failure(code: &str, message: &str) -> EventFailure {
  EventFailure {
    code: code.into(),
    message: message.into(),
  }
}

fn row_count(path: &Path) -> i64 {
  Connection::open(path)
    .unwrap()
    .query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))
    .unwrap()
}

fn read_usage(path: &Path, request_id: &str) -> Option<String> {
  Connection::open(path)
    .unwrap()
    .query_row(
      "SELECT usage_json FROM requests WHERE request_id = ?1",
      params![request_id],
      |row| row.get(0),
    )
    .unwrap()
}

fn read_status(path: &Path, request_id: &str) -> Option<i64> {
  Connection::open(path)
    .unwrap()
    .query_row(
      "SELECT status FROM requests WHERE request_id = ?1",
      params![request_id],
      |row| row.get(0),
    )
    .unwrap()
}

fn parse_json(value: Option<&str>) -> Option<Value> {
  value.and_then(|value| serde_json::from_str(value).ok())
}

fn temp_usage_db() -> PathBuf {
  let dir = std::env::temp_dir().join(format!("tokn-usage-events-{}", uuid::Uuid::new_v4()));
  std::fs::create_dir_all(&dir).unwrap();
  dir.join("usage.db")
}

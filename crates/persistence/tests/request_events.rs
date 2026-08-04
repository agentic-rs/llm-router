use bytes::Bytes;
use rusqlite::Connection;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokn_events::{
  AttemptFinished, AttemptHttpRequest, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted,
  AttemptUsage, BodyCapture, BodyFinished, BodyLeg, BodyOutcome, BodyProgress, BodyResult, CapturedHeader,
  CapturedHeaders, CapturedUri, ClientIdentity, ConnectAction, ConnectClosed, ConnectReady, Correlation, EventConsumer,
  EventFailure, EventSeq, GatewayEvent, HttpFamily, HttpRequestSnapshot, HttpResponseHead, IngressKind,
  PolicySelection, RequestAdmitted, RequestBodyObservation, RequestFinished, RequestOutcome, RequestPhase,
  RequestSource, RequestStarted, RetryDecision, SelectedAction, TargetSelection, TokenUsage, TrafficEvent,
  TrafficEventKind, UsageKind,
};
use tokn_persistence::{RequestPersistenceConsumer, RequestPersistenceOptions};

const DAY: &str = "2026-07-14";
const START_MS: i64 = 1_783_987_200_000;

#[test]
fn parsing_failure_keeps_the_started_row_without_inventing_routing_facts() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("parse-failure", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();

  let connection = open_day(&dir, DAY);
  let anchored = connection
    .query_row(
      "SELECT ts, ver, endpoint, status, request_error, account_id, provider_id, model,
              inbound_req_method, inbound_req_url, inbound_req_headers
       FROM requests WHERE request_id = 'parse-failure'",
      [],
      |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, String>(1)?,
          row.get::<_, Option<String>>(2)?,
          row.get::<_, Option<i64>>(3)?,
          row.get::<_, Option<String>>(4)?,
          row.get::<_, Option<String>>(5)?,
          row.get::<_, Option<String>>(6)?,
          row.get::<_, Option<String>>(7)?,
          row.get::<_, String>(8)?,
          row.get::<_, String>(9)?,
          row.get::<_, Vec<u8>>(10)?,
        ))
      },
    )
    .unwrap();
  assert_eq!(anchored.0, START_MS);
  assert_eq!(anchored.1, "test-version");
  assert_eq!((&anchored.2, &anchored.3, &anchored.4), (&None, &None, &None));
  assert_eq!((&anchored.5, &anchored.6, &anchored.7), (&None, &None, &None));
  assert_eq!(anchored.8, "POST");
  assert_eq!(anchored.9, "/v1/responses");
  assert_eq!(
    serde_json::from_slice::<Value>(&anchored.10).unwrap(),
    serde_json::json!({"authorization": "<redacted>", "x-test": "second"})
  );

  let failure = failure("invalid_request_body", "the body is not valid JSON");
  emit(
    &mut consumer,
    event(
      "parse-failure",
      2,
      5,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Complete(Bytes::from_static(b"{")),
        decoded: Some(BodyCapture::Complete(Bytes::from_static(b"{"))),
        requested_model: None,
        stream: None,
        initiator: None,
        outcome: BodyOutcome::Rejected(failure.clone()),
      }),
    ),
  )
  .unwrap();
  let terminal = event(
    "parse-failure",
    3,
    7,
    TrafficEventKind::Finished(RequestFinished {
      outcome: RequestOutcome::Rejected,
      phase: RequestPhase::RequestBody,
      downstream_status: Some(400),
      failure: Some(failure),
      attempt_count: 0,
    }),
  );
  emit(&mut consumer, terminal.clone()).unwrap();
  emit(&mut consumer, terminal).unwrap();

  let persisted = connection
    .query_row(
      "SELECT status, request_error, model, account_id, provider_id, inbound_req_body,
              inbound_resp_status, ctx_json
       FROM requests WHERE request_id = 'parse-failure'",
      [],
      |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, String>(1)?,
          row.get::<_, Option<String>>(2)?,
          row.get::<_, Option<String>>(3)?,
          row.get::<_, Option<String>>(4)?,
          row.get::<_, Vec<u8>>(5)?,
          row.get::<_, i64>(6)?,
          row.get::<_, String>(7)?,
        ))
      },
    )
    .unwrap();
  assert_eq!(persisted.0, 400);
  assert_eq!(persisted.1, "request_body: the body is not valid JSON");
  assert_eq!((&persisted.2, &persisted.3, &persisted.4), (&None, &None, &None));
  assert_eq!(persisted.5, b"{");
  assert_eq!(persisted.6, 400);
  let context: Value = serde_json::from_str(&persisted.7).unwrap();
  assert_eq!(context["mode"], "route");
  assert_eq!(context["pipeline_id"], "requests");
  assert!(context.get("selected_action").is_none());
  assert!(context.get("http_family").is_none());
  assert_eq!(context["attempt_count"], 0);
  assert_eq!(context["request_failure"]["code"], "invalid_request_body");

  let after_terminal = event(
    "parse-failure",
    4,
    8,
    TrafficEventKind::RequestBody(RequestBodyObservation {
      wire: BodyCapture::Absent,
      decoded: None,
      requested_model: None,
      stream: None,
      initiator: None,
      outcome: BodyOutcome::Accepted,
    }),
  );
  assert!(emit(&mut consumer, after_terminal)
    .unwrap_err()
    .to_string()
    .contains("after terminal"));
}

#[test]
fn embedded_accepted_body_uses_decoded_capture_when_wire_is_absent() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("embedded-accepted", 1, 0, TrafficEventKind::Started(embedded_started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "embedded-accepted",
      2,
      1,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Absent,
        decoded: Some(BodyCapture::Complete(Bytes::from_static(
          br#"{"model":"requested","stream":false}"#,
        ))),
        requested_model: Some("requested".into()),
        stream: Some(false),
        initiator: None,
        outcome: BodyOutcome::Accepted,
      }),
    ),
  )
  .unwrap();

  let (body, request_error, context) = open_day(&dir, DAY)
    .query_row(
      "SELECT inbound_req_body, request_error, ctx_json
       FROM requests WHERE request_id = 'embedded-accepted'",
      [],
      |row| {
        Ok((
          row.get::<_, Option<Vec<u8>>>(0)?,
          row.get::<_, Option<String>>(1)?,
          row.get::<_, String>(2)?,
        ))
      },
    )
    .map(|(body, request_error, context)| (body, request_error, serde_json::from_str::<Value>(&context).unwrap()))
    .unwrap();

  assert_eq!(body, Some(br#"{"model":"requested","stream":false}"#.to_vec()));
  assert_eq!(request_error, None);
  assert_eq!(context["request_source"], "embedded");
  assert_eq!(context["source_profile_id"], "default");
}

#[test]
fn embedded_rejected_body_preserves_decoded_capture_metadata_when_wire_is_absent() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("embedded-rejected", 1, 0, TrafficEventKind::Started(embedded_started())),
  )
  .unwrap();
  let decoded_prefix = Bytes::from_static(br#"{"model":"requested"#);
  emit(
    &mut consumer,
    event(
      "embedded-rejected",
      2,
      1,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Absent,
        decoded: Some(BodyCapture::Truncated {
          prefix: decoded_prefix.clone(),
          bytes_seen: 64,
        }),
        requested_model: Some("requested".into()),
        stream: None,
        initiator: None,
        outcome: BodyOutcome::Rejected(failure("invalid_request_body", "invalid embedded body")),
      }),
    ),
  )
  .unwrap();

  let (body, request_error, context) = open_day(&dir, DAY)
    .query_row(
      "SELECT inbound_req_body, request_error, ctx_json
       FROM requests WHERE request_id = 'embedded-rejected'",
      [],
      |row| {
        Ok((
          row.get::<_, Option<Vec<u8>>>(0)?,
          row.get::<_, String>(1)?,
          row.get::<_, String>(2)?,
        ))
      },
    )
    .map(|(body, request_error, context)| (body, request_error, serde_json::from_str::<Value>(&context).unwrap()))
    .unwrap();

  assert_eq!(body, Some(decoded_prefix.to_vec()));
  assert_eq!(request_error, "request_body: invalid embedded body");
  for key in ["inbound_request_body_capture", "decoded_request_body_capture"] {
    assert_eq!(context[key]["state"], "truncated", "{key}");
    assert_eq!(context[key]["bytes_seen"], 64, "{key}");
    assert_eq!(context[key]["bytes_captured"], decoded_prefix.len(), "{key}");
  }
}

#[test]
fn listener_request_body_keeps_wire_precedence_over_decoded_capture() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("listener-wire", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "listener-wire",
      2,
      1,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Complete(Bytes::from_static(b"wire-body")),
        decoded: Some(BodyCapture::Truncated {
          prefix: Bytes::from_static(b"decoded-prefix"),
          bytes_seen: 128,
        }),
        requested_model: Some("requested".into()),
        stream: Some(false),
        initiator: None,
        outcome: BodyOutcome::Accepted,
      }),
    ),
  )
  .unwrap();

  let (body, context) = open_day(&dir, DAY)
    .query_row(
      "SELECT inbound_req_body, ctx_json FROM requests WHERE request_id = 'listener-wire'",
      [],
      |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
    )
    .map(|(body, context)| (body, serde_json::from_str::<Value>(&context).unwrap()))
    .unwrap();

  assert_eq!(body, b"wire-body");
  assert!(context.get("inbound_request_body_capture").is_none());
  assert_eq!(context["decoded_request_body_capture"]["state"], "truncated");
  assert_eq!(context["decoded_request_body_capture"]["bytes_seen"], 128);
}

#[test]
fn retries_keep_legacy_ids_and_clone_only_request_wide_facts() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("retry", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      2,
      1,
      TrafficEventKind::Admitted(RequestAdmitted::Http {
        scheme: "http".into(),
        authority: "gateway.local".into(),
        path_and_query: CapturedUri::exact("/v1/responses"),
        operation: Some("responses".into()),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      3,
      2,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Complete(Bytes::from_static(br#"{"model":"requested"}"#)),
        decoded: Some(BodyCapture::Complete(Bytes::from_static(br#"{"model":"requested"}"#))),
        requested_model: Some("requested".into()),
        stream: Some(false),
        initiator: Some("cli".into()),
        outcome: BodyOutcome::Accepted,
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      4,
      3,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account-1", "provider-1", "upstream-1"),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      5,
      4,
      TrafficEventKind::AttemptRequest(AttemptHttpRequest {
        attempt: AttemptNo::FIRST,
        request: HttpRequestSnapshot {
          method: "POST".into(),
          uri: CapturedUri::exact("https://first.example/v1/responses"),
          headers: CapturedHeaders::new([CapturedHeader::redacted("authorization")]),
          body: BodyCapture::Complete(Bytes::from_static(b"first-upstream")),
        },
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      6,
      10,
      TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
        attempt: AttemptNo::FIRST,
        response: HttpResponseHead {
          status: 503,
          headers: CapturedHeaders::default(),
        },
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      7,
      11,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          kind: Some(UsageKind::Responses),
          input: Some(4),
          output: Some(2),
          total: None,
          ..TokenUsage::default()
        },
      }),
    ),
  )
  .unwrap();
  let retry_reason = failure("upstream_unavailable", "try another account");
  emit(
    &mut consumer,
    event(
      "retry",
      8,
      12,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(503),
        failure: None,
        retry: Some(RetryDecision {
          delay_ms: Some(10),
          reason: retry_reason,
        }),
      }),
    ),
  )
  .unwrap();
  let second = AttemptNo::new(2).unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      9,
      20,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: second,
        target: target("account-2", "provider-2", "upstream-2"),
      }),
    ),
  )
  .unwrap();

  let connection = open_day(&dir, DAY);
  let ids = connection
    .prepare("SELECT request_id FROM requests ORDER BY idx")
    .unwrap()
    .query_map([], |row| row.get::<_, String>(0))
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap();
  assert_eq!(ids, ["retry", "retry:1"]);
  let retry_row = connection
    .query_row(
      "SELECT endpoint, account_id, provider_id, model, params_json, request_error, status,
              inbound_req_body, outbound_req_method, outbound_resp_status, usage_json
       FROM requests WHERE request_id = 'retry:1'",
      [],
      |row| {
        Ok((
          row.get::<_, String>(0)?,
          row.get::<_, String>(1)?,
          row.get::<_, String>(2)?,
          row.get::<_, String>(3)?,
          row.get::<_, String>(4)?,
          row.get::<_, Option<String>>(5)?,
          row.get::<_, Option<i64>>(6)?,
          row.get::<_, Vec<u8>>(7)?,
          row.get::<_, Option<String>>(8)?,
          row.get::<_, Option<i64>>(9)?,
          row.get::<_, Option<String>>(10)?,
        ))
      },
    )
    .unwrap();
  assert_eq!(
    (
      retry_row.0.as_str(),
      retry_row.1.as_str(),
      retry_row.2.as_str(),
      retry_row.3.as_str()
    ),
    ("responses", "account-2", "provider-2", "requested")
  );
  assert_eq!(
    serde_json::from_str::<Value>(&retry_row.4).unwrap(),
    serde_json::json!({"initiator": "cli", "stream": false})
  );
  assert_eq!((&retry_row.5, &retry_row.6), (&None, &None));
  assert_eq!(retry_row.7, br#"{"model":"requested"}"#);
  assert_eq!((&retry_row.8, &retry_row.9, &retry_row.10), (&None, &None, &None));

  let first_usage: Value = connection
    .query_row(
      "SELECT usage_json FROM requests WHERE request_id = 'retry'",
      [],
      |row| row.get::<_, String>(0),
    )
    .map(|json| serde_json::from_str(&json).unwrap())
    .unwrap();
  assert_eq!(first_usage["input"], 4);
  assert_eq!(first_usage["output"], 2);
  assert!(first_usage.get("total").is_none());

  emit(
    &mut consumer,
    event(
      "retry",
      10,
      21,
      TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
        attempt: second,
        response: HttpResponseHead {
          status: 200,
          headers: CapturedHeaders::default(),
        },
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      11,
      22,
      TrafficEventKind::BodyFinished(BodyFinished {
        leg: BodyLeg::Upstream { attempt: second },
        capture: BodyCapture::Complete(Bytes::from_static(br#"{"upstream":true}"#)),
        result: BodyResult::Complete,
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      12,
      23,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      13,
      24,
      TrafficEventKind::BodyFinished(BodyFinished {
        leg: BodyLeg::Downstream,
        capture: BodyCapture::Truncated {
          prefix: Bytes::from_static(b"data: partial"),
          bytes_seen: 100,
        },
        result: BodyResult::Complete,
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      14,
      25,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: second,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(200),
        failure: None,
        retry: None,
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "retry",
      15,
      30,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Delivered,
        phase: RequestPhase::Complete,
        downstream_status: Some(200),
        failure: None,
        attempt_count: 2,
      }),
    ),
  )
  .unwrap();

  let final_retry = connection
    .query_row(
      "SELECT status, inbound_resp_status, outbound_resp_status, request_error, ctx_json,
              outbound_resp_body, inbound_resp_body
       FROM requests WHERE request_id = 'retry:1'",
      [],
      |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, i64>(1)?,
          row.get::<_, i64>(2)?,
          row.get::<_, Option<String>>(3)?,
          row.get::<_, String>(4)?,
          row.get::<_, Vec<u8>>(5)?,
          row.get::<_, Vec<u8>>(6)?,
        ))
      },
    )
    .unwrap();
  assert_eq!((final_retry.0, final_retry.1, final_retry.2), (200, 200, 200));
  assert_eq!(final_retry.3, None);
  let context: Value = serde_json::from_str(&final_retry.4).unwrap();
  assert_eq!(context["attempt"], 2);
  assert_eq!(context["latency_ms"], 10);
  assert_eq!(context["request_latency_ms"], 30);
  assert_eq!(context["downstream_response_body_capture"]["state"], "truncated");
  assert_eq!(context["downstream_response_body_capture"]["bytes_seen"], 100);
  assert_eq!(final_retry.5, br#"{"upstream":true}"#);
  assert_eq!(final_retry.6, b"data: partial");
}

#[test]
fn lifecycle_order_errors_are_returned_to_the_event_hub() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  let error = emit(
    &mut consumer,
    event(
      "out-of-order",
      2,
      0,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Absent,
        decoded: None,
        requested_model: None,
        stream: None,
        initiator: None,
        outcome: BodyOutcome::Accepted,
      }),
    ),
  )
  .unwrap_err();

  assert!(error.to_string().contains("first event has sequence 2"));
  assert!(!dir.join(format!("{DAY}.db")).exists());
}

#[test]
fn sparse_attempt_usage_updates_are_merged_before_persistence() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("sparse-usage", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "sparse-usage",
      2,
      1,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account", "provider", "upstream"),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "sparse-usage",
      3,
      2,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          kind: Some(UsageKind::Responses),
          input: Some(13),
          cache_read: Some(5),
          ..TokenUsage::default()
        },
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "sparse-usage",
      4,
      3,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          output: Some(8),
          total: Some(21),
          ..TokenUsage::default()
        },
      }),
    ),
  )
  .unwrap();

  let usage: Value = open_day(&dir, DAY)
    .query_row(
      "SELECT usage_json FROM requests WHERE request_id = 'sparse-usage'",
      [],
      |row| row.get::<_, String>(0),
    )
    .map(|json| serde_json::from_str(&json).unwrap())
    .unwrap();
  assert_eq!(usage["kind"], "responses");
  assert_eq!(usage["input"], 13);
  assert_eq!(usage["output"], 8);
  assert_eq!(usage["total"], 21);
  assert_eq!(usage["cache_read"], 5);
}

#[test]
fn terminal_statuses_cannot_replace_observed_wire_statuses() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("attempt-status", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "attempt-status",
      2,
      1,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account", "provider", "upstream"),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "attempt-status",
      3,
      2,
      TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
        attempt: AttemptNo::FIRST,
        response: HttpResponseHead {
          status: 200,
          headers: CapturedHeaders::default(),
        },
      }),
    ),
  )
  .unwrap();
  let error = emit(
    &mut consumer,
    event(
      "attempt-status",
      4,
      3,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(503),
        failure: None,
        retry: None,
      }),
    ),
  )
  .unwrap_err();
  assert!(error
    .to_string()
    .contains("conflicts with observed response status 200"));
  assert_eq!(
    open_day(&dir, DAY)
      .query_row(
        "SELECT outbound_resp_status FROM requests WHERE request_id = 'attempt-status'",
        [],
        |row| row.get::<_, i64>(0),
      )
      .unwrap(),
    200
  );

  emit(
    &mut consumer,
    event("downstream-status", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "downstream-status",
      2,
      1,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }),
    ),
  )
  .unwrap();
  let error = emit(
    &mut consumer,
    event(
      "downstream-status",
      3,
      2,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Delivered,
        phase: RequestPhase::Complete,
        downstream_status: Some(500),
        failure: None,
        attempt_count: 0,
      }),
    ),
  )
  .unwrap_err();
  assert!(error
    .to_string()
    .contains("conflicts with observed downstream status 200"));
  assert_eq!(
    open_day(&dir, DAY)
      .query_row(
        "SELECT status FROM requests WHERE request_id = 'downstream-status'",
        [],
        |row| row.get::<_, i64>(0),
      )
      .unwrap(),
    200
  );
}

#[test]
fn one_shot_wire_boundaries_cannot_rewrite_closed_attempts() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("one-shot", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "one-shot",
      2,
      1,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account", "provider", "upstream"),
      }),
    ),
  )
  .unwrap();

  let request = TrafficEventKind::AttemptRequest(AttemptHttpRequest {
    attempt: AttemptNo::FIRST,
    request: HttpRequestSnapshot {
      method: "POST".into(),
      uri: CapturedUri::exact("https://upstream.example/v1/responses"),
      headers: CapturedHeaders::default(),
      body: BodyCapture::Complete(Bytes::from_static(b"request")),
    },
  });
  emit(&mut consumer, event("one-shot", 3, 2, request.clone())).unwrap();
  assert!(emit(&mut consumer, event("one-shot", 4, 3, request.clone()))
    .unwrap_err()
    .to_string()
    .contains("request was observed more than once"));

  let head = TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
    attempt: AttemptNo::FIRST,
    response: HttpResponseHead {
      status: 200,
      headers: CapturedHeaders::default(),
    },
  });
  emit(&mut consumer, event("one-shot", 4, 3, head.clone())).unwrap();
  assert!(emit(&mut consumer, event("one-shot", 5, 4, head.clone()))
    .unwrap_err()
    .to_string()
    .contains("response head was observed more than once"));

  let body = TrafficEventKind::BodyFinished(BodyFinished {
    leg: BodyLeg::Upstream {
      attempt: AttemptNo::FIRST,
    },
    capture: BodyCapture::Complete(Bytes::from_static(b"response")),
    result: BodyResult::Complete,
  });
  emit(&mut consumer, event("one-shot", 5, 4, body.clone())).unwrap();
  assert!(emit(&mut consumer, event("one-shot", 6, 5, body.clone()))
    .unwrap_err()
    .to_string()
    .contains("body finished more than once"));

  emit(
    &mut consumer,
    event(
      "one-shot",
      6,
      5,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(200),
        failure: None,
        retry: None,
      }),
    ),
  )
  .unwrap();

  for late in [
    request,
    head,
    body,
    TrafficEventKind::BodyProgress(BodyProgress {
      leg: BodyLeg::Upstream {
        attempt: AttemptNo::FIRST,
      },
      bytes_seen: 9,
      chunks: 1,
    }),
  ] {
    assert!(emit(&mut consumer, event("one-shot", 7, 6, late))
      .unwrap_err()
      .to_string()
      .contains("after it finished"));
  }

  // Provider usage may be reported late by the terminal batch, before the
  // request-wide Finished event.
  emit(
    &mut consumer,
    event(
      "one-shot",
      7,
      6,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          input: Some(3),
          output: Some(2),
          ..TokenUsage::default()
        },
      }),
    ),
  )
  .unwrap();

  let downstream = TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
    status: 200,
    headers: CapturedHeaders::default(),
  });
  emit(&mut consumer, event("one-shot", 8, 7, downstream.clone())).unwrap();
  assert!(emit(&mut consumer, event("one-shot", 9, 8, downstream))
    .unwrap_err()
    .to_string()
    .contains("downstream response head was observed more than once"));
}

#[test]
fn request_and_downstream_bodies_are_one_shot() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("body-one-shot", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  let request_body = TrafficEventKind::RequestBody(RequestBodyObservation {
    wire: BodyCapture::Complete(Bytes::from_static(b"request")),
    decoded: None,
    requested_model: None,
    stream: None,
    initiator: None,
    outcome: BodyOutcome::Accepted,
  });
  emit(&mut consumer, event("body-one-shot", 2, 1, request_body.clone())).unwrap();
  assert!(emit(&mut consumer, event("body-one-shot", 3, 2, request_body))
    .unwrap_err()
    .to_string()
    .contains("request body was observed more than once"));

  let downstream_body = TrafficEventKind::BodyFinished(BodyFinished {
    leg: BodyLeg::Downstream,
    capture: BodyCapture::Complete(Bytes::from_static(b"response")),
    result: BodyResult::Complete,
  });
  emit(&mut consumer, event("body-one-shot", 3, 2, downstream_body.clone())).unwrap();
  assert!(emit(&mut consumer, event("body-one-shot", 4, 3, downstream_body))
    .unwrap_err()
    .to_string()
    .contains("downstream body finished more than once"));
}

#[test]
fn requests_require_closed_attempts_and_explicit_retry_decisions() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  for request_id in ["open-attempt", "overlapping-retry", "unannounced-retry"] {
    emit(
      &mut consumer,
      event(request_id, 1, 0, TrafficEventKind::Started(started())),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        2,
        1,
        TrafficEventKind::AttemptStarted(AttemptStarted {
          attempt: AttemptNo::FIRST,
          target: target("account", "provider", "upstream"),
        }),
      ),
    )
    .unwrap();
  }

  let error = emit(
    &mut consumer,
    event(
      "open-attempt",
      3,
      2,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Failed,
        phase: RequestPhase::UpstreamRequest,
        downstream_status: Some(502),
        failure: Some(failure("upstream_failed", "attempt still open")),
        attempt_count: 1,
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("before attempt 1 completed"));

  let error = emit(
    &mut consumer,
    event(
      "overlapping-retry",
      3,
      2,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::new(2).unwrap(),
        target: target("account-2", "provider-2", "upstream-2"),
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("before attempt 1 finished"));

  emit(
    &mut consumer,
    event(
      "unannounced-retry",
      3,
      2,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Response,
        phase: RequestPhase::UpstreamResponse,
        upstream_status: Some(200),
        failure: None,
        retry: None,
      }),
    ),
  )
  .unwrap();
  let error = emit(
    &mut consumer,
    event(
      "unannounced-retry",
      4,
      3,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::new(2).unwrap(),
        target: target("account-2", "provider-2", "upstream-2"),
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("without a retry decision for attempt 1"));
}

#[test]
fn retry_rows_are_pinned_to_the_day_the_attempt_started() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  let before_midnight = START_MS + 86_399_995;
  emit(
    &mut consumer,
    event_at("midnight", 1, before_midnight, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event_at(
      "midnight",
      2,
      before_midnight + 1,
      1,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account-1", "provider-1", "upstream-1"),
      }),
    ),
  )
  .unwrap();
  let failure = failure("temporary", "retry after midnight");
  emit(
    &mut consumer,
    event_at(
      "midnight",
      3,
      before_midnight + 2,
      2,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Failed,
        phase: RequestPhase::UpstreamRequest,
        upstream_status: None,
        failure: Some(failure.clone()),
        retry: Some(RetryDecision {
          delay_ms: None,
          reason: failure,
        }),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event_at(
      "midnight",
      4,
      before_midnight + 10,
      10,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::new(2).unwrap(),
        target: target("account-2", "provider-2", "upstream-2"),
      }),
    ),
  )
  .unwrap();

  let first_day = open_day(&dir, "2026-07-14");
  let second_day = open_day(&dir, "2026-07-15");
  assert_eq!(
    first_day
      .query_row("SELECT request_id FROM requests", [], |row| row.get::<_, String>(0))
      .unwrap(),
    "midnight"
  );
  assert_eq!(
    second_day
      .query_row("SELECT request_id FROM requests", [], |row| row.get::<_, String>(0))
      .unwrap(),
    "midnight:1"
  );
}

#[test]
fn authentication_and_v2_routing_keep_legacy_inspector_aliases() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("aliases", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "aliases",
      2,
      1,
      TrafficEventKind::Authenticated(ClientIdentity::LocalKey {
        key_id: "key-id".into(),
        key_name: Some("developer".into()),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "aliases",
      3,
      2,
      TrafficEventKind::PolicySelected(PolicySelection {
        binding_id: Some("binding".into()),
        action: SelectedAction::Http {
          profile_id: "profile".into(),
          route_id: "route".into(),
          family: HttpFamily::Relay,
        },
      }),
    ),
  )
  .unwrap();

  let (user, context) = open_day(&dir, DAY)
    .query_row(
      "SELECT user, ctx_json FROM requests WHERE request_id = 'aliases'",
      [],
      |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .unwrap();
  let context: Value = serde_json::from_str(&context).unwrap();
  assert_eq!(user, "developer");
  assert_eq!(context["client_identity"], "local_key");
  assert_eq!(context["api_key_id"], "key-id");
  assert_eq!(context["ingress"], "llm_api");
  assert_eq!(context["pipeline_id"], "requests");
  assert_eq!(context["http_family"], "relay");
  assert_eq!(context["mode"], "route");
}

#[test]
fn ingress_and_http_policy_keep_exact_legacy_context_aliases() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  let parent_connect_id = tokn_events::RequestId::new("parent-connect").unwrap();
  let cases = [
    (
      "direct-managed",
      IngressKind::LlmApi,
      "llm_api",
      "route",
      "requests",
      HttpFamily::Managed,
      "managed",
      None,
    ),
    (
      "forward-relay",
      IngressKind::ForwardProxy,
      "forward_proxy",
      "forward_proxy",
      "proxy",
      HttpFamily::Relay,
      "relay",
      None,
    ),
    (
      "forward-transparent",
      IngressKind::ForwardProxy,
      "forward_proxy",
      "forward_proxy",
      "proxy",
      HttpFamily::Transparent,
      "transparent",
      None,
    ),
    (
      "intercepted-managed",
      IngressKind::InterceptedHttps {
        parent_connect_id: parent_connect_id.clone(),
      },
      "intercepted_https",
      "intercept",
      "proxy",
      HttpFamily::Managed,
      "managed",
      Some(parent_connect_id.as_str()),
    ),
  ];

  for (request_id, ingress, ingress_name, mode, pipeline_id, family, family_name, parent_id) in cases {
    emit(
      &mut consumer,
      event(
        request_id,
        1,
        0,
        TrafficEventKind::Started(started_for_ingress(ingress)),
      ),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        2,
        1,
        TrafficEventKind::Admitted(RequestAdmitted::Http {
          scheme: "https".into(),
          authority: "gateway.local".into(),
          path_and_query: CapturedUri::exact("/v1/responses"),
          operation: Some("responses".into()),
        }),
      ),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        3,
        2,
        TrafficEventKind::PolicySelected(PolicySelection {
          binding_id: Some(format!("{request_id}-binding").into()),
          action: SelectedAction::Http {
            profile_id: "profile".into(),
            route_id: "route".into(),
            family,
          },
        }),
      ),
    )
    .unwrap();

    let context = request_context(&dir, request_id);
    assert_eq!(context["ingress"], ingress_name, "{request_id}");
    assert_eq!(context["mode"], mode, "{request_id}");
    assert_eq!(context["pipeline_id"], pipeline_id, "{request_id}");
    assert_eq!(context["selected_action"], "http", "{request_id}");
    assert_eq!(context["http_family"], family_name, "{request_id}");
    match parent_id {
      Some(parent_id) => assert_eq!(context["parent_connect_id"], parent_id, "{request_id}"),
      None => assert!(context.get("parent_connect_id").is_none(), "{request_id}"),
    }
  }
}

#[test]
fn pre_policy_admission_failures_keep_ingress_context_aliases() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  let cases = [
    ("early-direct", IngressKind::LlmApi, "llm_api", "route", "requests"),
    (
      "early-forward",
      IngressKind::ForwardProxy,
      "forward_proxy",
      "forward_proxy",
      "proxy",
    ),
    (
      "early-intercepted",
      IngressKind::InterceptedHttps {
        parent_connect_id: tokn_events::RequestId::new("early-parent").unwrap(),
      },
      "intercepted_https",
      "intercept",
      "proxy",
    ),
  ];

  for (request_id, ingress, ingress_name, mode, pipeline_id) in cases {
    emit(
      &mut consumer,
      event(
        request_id,
        1,
        0,
        TrafficEventKind::Started(started_for_ingress(ingress)),
      ),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        2,
        1,
        TrafficEventKind::Finished(RequestFinished {
          outcome: RequestOutcome::Rejected,
          phase: RequestPhase::Admission,
          downstream_status: Some(400),
          failure: Some(failure("invalid_request", "request admission failed")),
          attempt_count: 0,
        }),
      ),
    )
    .unwrap();

    let context = request_context(&dir, request_id);
    assert_eq!(context["ingress"], ingress_name, "{request_id}");
    assert_eq!(context["mode"], mode, "{request_id}");
    assert_eq!(context["pipeline_id"], pipeline_id, "{request_id}");
    assert!(context.get("selected_action").is_none(), "{request_id}");
    assert!(context.get("http_family").is_none(), "{request_id}");
    assert_eq!(context["request_phase"], "admission", "{request_id}");
  }
}

#[test]
fn disabled_body_projection_omits_every_db_body_and_records_why() {
  let dir = persist_body_captures(
    "disabled-bodies",
    RequestPersistenceOptions {
      record_request_bodies: false,
      body_max_bytes: usize::MAX,
    },
  );
  let (bodies, context) = read_body_projection(&dir, "disabled-bodies");

  assert_eq!(bodies, (None, None, None, None));
  for key in BODY_CAPTURE_KEYS {
    assert_eq!(context[key]["state"], "omitted");
    assert_eq!(context[key]["reason"], "disabled");
    assert!(context[key]["bytes_seen"].as_u64().is_some_and(|bytes| bytes > 0));
  }
}

#[test]
fn bounded_body_projection_truncates_every_db_body_and_records_the_limit() {
  let dir = persist_body_captures(
    "bounded-bodies",
    RequestPersistenceOptions {
      record_request_bodies: true,
      body_max_bytes: 3,
    },
  );
  let (bodies, context) = read_body_projection(&dir, "bounded-bodies");

  assert_eq!(
    bodies,
    (
      Some(b"inb".to_vec()),
      Some(b"out".to_vec()),
      Some(b"ups".to_vec()),
      Some(b"dow".to_vec()),
    )
  );
  for key in BODY_CAPTURE_KEYS {
    assert_eq!(context[key]["state"], "truncated");
    assert_eq!(context[key]["bytes_captured"], 3);
    assert_eq!(context[key]["limit_bytes"], 3);
  }
}

#[test]
fn validated_request_ids_cannot_overlap_persisted_retry_rows() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("collision", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "collision",
      2,
      1,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account-1", "provider-1", "upstream-1"),
      }),
    ),
  )
  .unwrap();
  let retry_failure = failure("temporary", "retry");
  emit(
    &mut consumer,
    event(
      "collision",
      3,
      2,
      TrafficEventKind::AttemptFinished(AttemptFinished {
        attempt: AttemptNo::FIRST,
        outcome: AttemptOutcome::Failed,
        phase: RequestPhase::UpstreamRequest,
        upstream_status: None,
        failure: Some(retry_failure.clone()),
        retry: Some(RetryDecision {
          delay_ms: None,
          reason: retry_failure,
        }),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "collision",
      4,
      3,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::new(2).unwrap(),
        target: target("account-2", "provider-2", "upstream-2"),
      }),
    ),
  )
  .unwrap();

  let connection = open_day(&dir, DAY);
  let before = connection
    .query_row(
      "SELECT ts, ver, account_id FROM requests WHERE request_id = 'collision:1'",
      [],
      |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, String>(1)?,
          row.get::<_, String>(2)?,
        ))
      },
    )
    .unwrap();
  let error = tokn_events::RequestId::new("collision:1").unwrap_err();
  assert!(error.to_string().contains("unsupported character at byte 9"));
  let after = connection
    .query_row(
      "SELECT ts, ver, account_id FROM requests WHERE request_id = 'collision:1'",
      [],
      |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, String>(1)?,
          row.get::<_, String>(2)?,
        ))
      },
    )
    .unwrap();
  assert_eq!(after, before);
  assert_eq!(
    connection
      .query_row("SELECT COUNT(*) FROM requests", [], |row| row.get::<_, i64>(0))
      .unwrap(),
    2
  );
}

#[test]
fn attempt_usage_requires_the_connection_anchor_in_the_same_transaction() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("usage-anchor", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "usage-anchor",
      2,
      1,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account", "provider", "upstream"),
      }),
    ),
  )
  .unwrap();

  let connection = open_day(&dir, DAY);
  connection
    .execute("DELETE FROM request_connection WHERE request_id = 'usage-anchor'", [])
    .unwrap();
  let error = emit(
    &mut consumer,
    event(
      "usage-anchor",
      3,
      2,
      TrafficEventKind::AttemptUsage(AttemptUsage {
        attempt: AttemptNo::FIRST,
        usage: TokenUsage {
          input: Some(10),
          ..TokenUsage::default()
        },
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("anchor disappeared"));
  assert_eq!(
    connection
      .query_row(
        "SELECT usage_json FROM request_metadata WHERE request_id = 'usage-anchor'",
        [],
        |row| row.get::<_, Option<String>>(0),
      )
      .unwrap(),
    None
  );
}

#[test]
fn connect_lifecycle_preserves_proxy_context_and_byte_counts() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("connect", 1, 0, TrafficEventKind::Started(connect_started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "connect",
      2,
      1,
      TrafficEventKind::Admitted(RequestAdmitted::Connect {
        authority: "example.com:443".into(),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "connect",
      3,
      2,
      TrafficEventKind::PolicySelected(PolicySelection {
        binding_id: Some("proxy-binding".into()),
        action: SelectedAction::Connect {
          action: ConnectAction::Tunnel,
        },
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "connect",
      4,
      3,
      TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "example.com:443".into(),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "connect",
      5,
      4,
      TrafficEventKind::ConnectClosed(ConnectClosed {
        action: ConnectAction::Tunnel,
        client_to_upstream_bytes: Some(111),
        upstream_to_client_bytes: Some(222),
        result: BodyResult::Complete,
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "connect",
      6,
      5,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Delivered,
        phase: RequestPhase::Complete,
        downstream_status: Some(200),
        failure: None,
        attempt_count: 0,
      }),
    ),
  )
  .unwrap();

  let (endpoint, status, context) = open_day(&dir, DAY)
    .query_row(
      "SELECT endpoint, status, ctx_json FROM requests WHERE request_id = 'connect'",
      [],
      |row| {
        Ok((
          row.get::<_, String>(0)?,
          row.get::<_, i64>(1)?,
          row.get::<_, String>(2)?,
        ))
      },
    )
    .unwrap();
  let context: Value = serde_json::from_str(&context).unwrap();
  assert_eq!(endpoint, "connect");
  assert_eq!(status, 200);
  assert_eq!(context["pipeline_id"], "proxy");
  assert_eq!(context["mode"], "forward_proxy");
  assert_eq!(context["connect_action"], "tunnel");
  assert_eq!(context["client_to_upstream_bytes"], 111);
  assert_eq!(context["upstream_to_client_bytes"], 222);
  assert_eq!(context["attempt_count"], 0);
}

#[test]
fn connect_lifecycle_requires_ready_close_order_and_excludes_http_attempts() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();

  emit(
    &mut consumer,
    event("close-before-ready", 1, 0, TrafficEventKind::Started(connect_started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "close-before-ready",
      2,
      1,
      TrafficEventKind::Admitted(RequestAdmitted::Connect {
        authority: "example.com:443".into(),
      }),
    ),
  )
  .unwrap();
  let error = emit(
    &mut consumer,
    event(
      "close-before-ready",
      3,
      2,
      TrafficEventKind::ConnectClosed(ConnectClosed {
        action: ConnectAction::Tunnel,
        client_to_upstream_bytes: None,
        upstream_to_client_bytes: None,
        result: BodyResult::Complete,
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("before ConnectReady"));

  for request_id in ["open-connect", "duplicate-close", "http-after-connect"] {
    emit(
      &mut consumer,
      event(request_id, 1, 0, TrafficEventKind::Started(connect_started())),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        2,
        1,
        TrafficEventKind::Admitted(RequestAdmitted::Connect {
          authority: "example.com:443".into(),
        }),
      ),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        3,
        2,
        TrafficEventKind::PolicySelected(PolicySelection {
          binding_id: Some("proxy-binding".into()),
          action: SelectedAction::Connect {
            action: ConnectAction::Tunnel,
          },
        }),
      ),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        4,
        3,
        TrafficEventKind::ConnectReady(ConnectReady {
          action: ConnectAction::Tunnel,
          authority: "example.com:443".into(),
        }),
      ),
    )
    .unwrap();
  }

  let error = emit(
    &mut consumer,
    event(
      "open-connect",
      5,
      4,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Delivered,
        phase: RequestPhase::Complete,
        downstream_status: Some(200),
        failure: None,
        attempt_count: 0,
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("before CONNECT closed"));

  let closed = TrafficEventKind::ConnectClosed(ConnectClosed {
    action: ConnectAction::Tunnel,
    client_to_upstream_bytes: Some(1),
    upstream_to_client_bytes: Some(2),
    result: BodyResult::Complete,
  });
  emit(&mut consumer, event("duplicate-close", 5, 4, closed.clone())).unwrap();
  let error = emit(&mut consumer, event("duplicate-close", 6, 5, closed)).unwrap_err();
  assert!(error.to_string().contains("more than once"));

  let error = emit(
    &mut consumer,
    event(
      "http-after-connect",
      5,
      4,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account", "provider", "upstream"),
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("HTTP attempt followed a non-HTTP policy"));
}

#[test]
fn connect_ready_requires_matching_non_reject_policy_and_no_http_response() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();

  for (request_id, action) in [
    ("connect-mismatch", ConnectAction::Tunnel),
    ("connect-reject", ConnectAction::Reject),
    ("connect-after-response", ConnectAction::Tunnel),
  ] {
    emit(
      &mut consumer,
      event(request_id, 1, 0, TrafficEventKind::Started(connect_started())),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        2,
        1,
        TrafficEventKind::Admitted(RequestAdmitted::Connect {
          authority: "example.com:443".into(),
        }),
      ),
    )
    .unwrap();
    emit(
      &mut consumer,
      event(
        request_id,
        3,
        2,
        TrafficEventKind::PolicySelected(PolicySelection {
          binding_id: None,
          action: SelectedAction::Connect { action },
        }),
      ),
    )
    .unwrap();
  }

  let error = emit(
    &mut consumer,
    event(
      "connect-mismatch",
      4,
      3,
      TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Intercept,
        authority: "example.com:443".into(),
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("differs from the selected CONNECT policy"));

  let error = emit(
    &mut consumer,
    event(
      "connect-reject",
      4,
      3,
      TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Reject,
        authority: "example.com:443".into(),
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("rejected CONNECT cannot become ready"));
  assert_eq!(
    open_day(&dir, DAY)
      .query_row(
        "SELECT status FROM requests WHERE request_id = 'connect-reject'",
        [],
        |row| row.get::<_, Option<i64>>(0),
      )
      .unwrap(),
    None
  );

  emit(
    &mut consumer,
    event(
      "connect-after-response",
      4,
      3,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 502,
        headers: CapturedHeaders::default(),
      }),
    ),
  )
  .unwrap();
  let error = emit(
    &mut consumer,
    event(
      "connect-after-response",
      5,
      4,
      TrafficEventKind::ConnectReady(ConnectReady {
        action: ConnectAction::Tunnel,
        authority: "example.com:443".into(),
      }),
    ),
  )
  .unwrap_err();
  assert!(error.to_string().contains("followed an HTTP response boundary"));
}

#[test]
fn terminal_summary_does_not_replace_a_specific_body_failure() {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open(&dir, "test-version").unwrap();
  emit(
    &mut consumer,
    event("specific-error", 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "specific-error",
      2,
      1,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Truncated {
          prefix: Bytes::from_static(b"{"),
          bytes_seen: 2,
        },
        decoded: None,
        requested_model: None,
        stream: None,
        initiator: None,
        outcome: BodyOutcome::Rejected(failure("invalid_json", "expected an object key")),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      "specific-error",
      3,
      2,
      TrafficEventKind::Finished(RequestFinished {
        outcome: RequestOutcome::Rejected,
        phase: RequestPhase::RequestBody,
        downstream_status: Some(400),
        failure: None,
        attempt_count: 0,
      }),
    ),
  )
  .unwrap();

  let request_error = open_day(&dir, DAY)
    .query_row(
      "SELECT request_error FROM requests WHERE request_id = 'specific-error'",
      [],
      |row| row.get::<_, String>(0),
    )
    .unwrap();
  assert_eq!(request_error, "request_body: expected an object key");
}

const BODY_CAPTURE_KEYS: [&str; 4] = [
  "inbound_request_body_capture",
  "outbound_request_body_capture",
  "upstream_response_body_capture",
  "downstream_response_body_capture",
];

type StoredBodies = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

fn persist_body_captures(request_id: &str, options: RequestPersistenceOptions) -> PathBuf {
  let dir = tempdir();
  let mut consumer = RequestPersistenceConsumer::open_with_options(&dir, "test-version", options).unwrap();
  emit(
    &mut consumer,
    event(request_id, 1, 0, TrafficEventKind::Started(started())),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      request_id,
      2,
      1,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Complete(Bytes::from_static(b"inbound")),
        decoded: None,
        requested_model: Some("model".into()),
        stream: Some(false),
        initiator: None,
        outcome: BodyOutcome::Accepted,
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      request_id,
      3,
      2,
      TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: target("account", "provider", "upstream"),
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      request_id,
      4,
      3,
      TrafficEventKind::AttemptRequest(AttemptHttpRequest {
        attempt: AttemptNo::FIRST,
        request: HttpRequestSnapshot {
          method: "POST".into(),
          uri: CapturedUri::exact("https://upstream.example/v1/responses"),
          headers: CapturedHeaders::default(),
          body: BodyCapture::Complete(Bytes::from_static(b"outbound")),
        },
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      request_id,
      5,
      4,
      TrafficEventKind::BodyFinished(BodyFinished {
        leg: BodyLeg::Upstream {
          attempt: AttemptNo::FIRST,
        },
        capture: BodyCapture::Complete(Bytes::from_static(b"upstream")),
        result: BodyResult::Complete,
      }),
    ),
  )
  .unwrap();
  emit(
    &mut consumer,
    event(
      request_id,
      6,
      5,
      TrafficEventKind::BodyFinished(BodyFinished {
        leg: BodyLeg::Downstream,
        capture: BodyCapture::Complete(Bytes::from_static(b"downstream")),
        result: BodyResult::Complete,
      }),
    ),
  )
  .unwrap();
  dir
}

fn read_body_projection(dir: &Path, request_id: &str) -> (StoredBodies, Value) {
  let connection = open_day(dir, DAY);
  let row = connection
    .query_row(
      "SELECT inbound_req_body, outbound_req_body, outbound_resp_body, inbound_resp_body, ctx_json
       FROM requests WHERE request_id = ?1",
      [request_id],
      |row| {
        Ok((
          row.get::<_, Option<Vec<u8>>>(0)?,
          row.get::<_, Option<Vec<u8>>>(1)?,
          row.get::<_, Option<Vec<u8>>>(2)?,
          row.get::<_, Option<Vec<u8>>>(3)?,
          row.get::<_, String>(4)?,
        ))
      },
    )
    .unwrap();
  ((row.0, row.1, row.2, row.3), serde_json::from_str(&row.4).unwrap())
}

fn emit(consumer: &mut RequestPersistenceConsumer, event: GatewayEvent) -> tokn_events::ConsumerResult {
  consumer.handle(EventSeq::ZERO, &event)
}

fn event(request_id: &str, sequence: u64, elapsed_ms: u64, kind: TrafficEventKind) -> GatewayEvent {
  event_at(
    request_id,
    sequence,
    START_MS + i64::try_from(elapsed_ms).unwrap(),
    elapsed_ms,
    kind,
  )
}

fn event_at(request_id: &str, sequence: u64, at_unix_ms: i64, elapsed_ms: u64, kind: TrafficEventKind) -> GatewayEvent {
  GatewayEvent::Traffic(TrafficEvent {
    request_id: tokn_events::RequestId::new(request_id).unwrap(),
    sequence,
    at_unix_ms,
    elapsed_ms,
    kind,
  })
}

fn started() -> RequestStarted {
  RequestStarted {
    source: RequestSource::Listener {
      listener_id: "listener".into(),
      ingress: IngressKind::LlmApi,
      local_addr: None,
      peer_addr: None,
    },
    http_version: Some("HTTP/1.1".into()),
    method: "POST".into(),
    target: CapturedUri::exact("/v1/responses"),
    headers: CapturedHeaders::new([
      CapturedHeader::value("X-Test", "first"),
      CapturedHeader::redacted("Authorization"),
      CapturedHeader::value("x-test", "second"),
    ]),
    body_present: true,
    correlation: Correlation {
      session_id: Some("session".into()),
      ..Correlation::default()
    },
  }
}

fn embedded_started() -> RequestStarted {
  let mut started = started();
  started.source = RequestSource::Embedded {
    profile_id: "default".into(),
  };
  started.http_version = None;
  started
}

fn started_for_ingress(ingress: IngressKind) -> RequestStarted {
  let listener_id = match &ingress {
    IngressKind::LlmApi => "direct",
    IngressKind::ForwardProxy => "forward",
    IngressKind::InterceptedHttps { .. } => "intercepted",
    _ => "unknown",
  };
  let mut started = started();
  started.source = RequestSource::Listener {
    listener_id: listener_id.into(),
    ingress,
    local_addr: None,
    peer_addr: None,
  };
  started
}

fn connect_started() -> RequestStarted {
  RequestStarted {
    source: RequestSource::Listener {
      listener_id: "proxy".into(),
      ingress: IngressKind::ForwardProxy,
      local_addr: None,
      peer_addr: None,
    },
    http_version: Some("HTTP/1.1".into()),
    method: "CONNECT".into(),
    target: CapturedUri::exact("example.com:443"),
    headers: CapturedHeaders::default(),
    body_present: false,
    correlation: Correlation::default(),
  }
}

fn target(account_id: &str, provider_id: &str, upstream_id: &str) -> TargetSelection {
  TargetSelection {
    family: HttpFamily::Managed,
    account_id: Some(account_id.into()),
    provider_id: Some(provider_id.into()),
    upstream_id: Some(upstream_id.into()),
    requested_model: Some("requested".into()),
    upstream_model: Some("upstream-model".into()),
    requested_operation: Some("responses".into()),
    upstream_operation: Some("responses".into()),
  }
}

fn request_context(dir: &Path, request_id: &str) -> Value {
  let context = open_day(dir, DAY)
    .query_row(
      "SELECT ctx_json FROM requests WHERE request_id = ?1",
      [request_id],
      |row| row.get::<_, String>(0),
    )
    .unwrap();
  serde_json::from_str(&context).unwrap()
}

fn failure(code: &str, message: &str) -> EventFailure {
  EventFailure {
    code: code.into(),
    message: message.into(),
  }
}

fn open_day(dir: &Path, day: &str) -> Connection {
  Connection::open(dir.join(format!("{day}.db"))).unwrap()
}

fn tempdir() -> PathBuf {
  let path = std::env::temp_dir().join(format!("tokn-request-events-{}", uuid::Uuid::new_v4()));
  std::fs::create_dir_all(&path).unwrap();
  path
}

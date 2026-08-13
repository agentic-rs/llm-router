//! Integration tests for the requests event-driven persistence handler.

use bytes::Bytes;
use rusqlite::{params, Connection};
use serde_json::Value;
use smol_str::SmolStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokn_core::db::{Usage, UsageDetails, UsageType};
use tokn_core::event::{Event, EventHandler};
use tokn_core::provider::Endpoint;
use tokn_core::request_event::stage::{
  BuiltHeadersSummary, ConvertedRequestSummary, ConvertedResponseSummary, ExtractedSummary, ResolvedSummary,
  SentSummary, Stage, StageEvent,
};
use tokn_core::request_event::RecordEvent;
use tokn_core::request_event::{RequestEndpoint, RequestEvent, RequestEventPayload};
use tokn_headers::{HeaderMap, TemplateVars};
use tokn_persistence::{RequestEventHandler, RequestPersistenceOptions};

fn tempdir() -> PathBuf {
  let p = std::env::temp_dir().join(format!("tokn-router-r2-evt-{}", uuid::Uuid::new_v4()));
  std::fs::create_dir_all(&p).unwrap();
  p
}

fn r2(request_id: &str, attempt: u32, payload: StageEvent) -> Event {
  Event::Requests(RequestEvent {
    request_id: SmolStr::new(request_id),
    attempt,
    ts: tokn_core::util::now_unix_ms(),
    payload: RequestEventPayload::Stage(payload),
  })
}

fn rr(request_id: &str, attempt: u32, payload: RecordEvent) -> Event {
  Event::Requests(RequestEvent {
    request_id: SmolStr::new(request_id),
    attempt,
    ts: tokn_core::util::now_unix_ms(),
    payload: RequestEventPayload::Record(payload),
  })
}

fn extracted(model: &str, stream: bool, session: Option<&str>, body: &[u8]) -> StageEvent {
  extracted_with_initiator(model, stream, session, Some("user"), body)
}

fn extracted_with_initiator(
  model: &str,
  stream: bool,
  session: Option<&str>,
  initiator: Option<&str>,
  body: &[u8],
) -> StageEvent {
  let mut headers = HeaderMap::new();
  headers.insert("x-test", "1");
  StageEvent::Extract(ExtractedSummary {
    agent_id: None,
    model: SmolStr::new(model),
    stream,
    session_id: session.map(SmolStr::new),
    project_id: None,
    initiator: initiator.map(SmolStr::new),
    header_initiator: None,
    route_mode_hint: None,
    headers,
    raw_body: Bytes::copy_from_slice(body),
    decoded_body: Bytes::copy_from_slice(body),
    body_json: Arc::new(Value::Null),
  })
}

fn resolved(account: &str, provider: &str) -> StageEvent {
  StageEvent::Resolve(ResolvedSummary {
    agent_id: None,
    model: SmolStr::new("client-model"),
    resolved_endpoint: Some(Endpoint::Responses),
    upstream_model: SmolStr::new("upstream-model"),
    upstream_endpoint: Some(Endpoint::Responses),
    account_id: SmolStr::new(account),
    provider_id: SmolStr::new(provider),
  })
}

fn built_headers() -> StageEvent {
  let mut h = HeaderMap::new();
  h.insert("authorization", "Bearer secret");
  StageEvent::BuildHeaders(BuiltHeadersSummary {
    headers: h,
    vars: TemplateVars::default(),
    agent_id: Default::default(),
  })
}

fn converted_request(body: &[u8]) -> StageEvent {
  StageEvent::ConvertRequest(ConvertedRequestSummary {
    upstream_body: Arc::new(Value::Null),
    upstream_wire_body: Bytes::copy_from_slice(body),
    debug_outbound_body: Bytes::copy_from_slice(body),
    content_encoding: None,
  })
}

fn sent(status: u16) -> StageEvent {
  let mut h = HeaderMap::new();
  h.insert("x-upstream", "yes");
  StageEvent::Send(SentSummary {
    status,
    headers: h,
    upstream_endpoint: Some(Endpoint::Responses),
    stream: false,
  })
}

fn converted_response(status: u16, body: Option<Value>) -> StageEvent {
  let mut h = HeaderMap::new();
  h.insert("content-type", "application/json");
  StageEvent::ConvertResponse(ConvertedResponseSummary {
    status,
    headers: h,
    body: body.map(Arc::new),
  })
}

fn completed(success: bool, attempts: u32) -> StageEvent {
  StageEvent::Completed { success, attempts }
}

fn error(stage: Stage, msg: &str) -> StageEvent {
  StageEvent::Error {
    stage,
    message: SmolStr::new(msg),
    recoverable: false,
    stop: true,
  }
}

fn fetch_row(dir: &Path, request_id: &str) -> std::collections::HashMap<String, rusqlite::types::Value> {
  use rusqlite::types::Value;
  for entry in std::fs::read_dir(dir).unwrap() {
    let p = entry.unwrap().path();
    if p.extension().and_then(|e| e.to_str()) != Some("db") {
      continue;
    }
    let conn = Connection::open(&p).unwrap();
    let mut stmt = conn.prepare("SELECT * FROM requests WHERE request_id = ?1").unwrap();
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt.query(params![request_id]).unwrap();
    if let Some(row) = rows.next().unwrap() {
      let mut m = std::collections::HashMap::new();
      for (i, name) in col_names.iter().enumerate() {
        let v: Value = row.get(i).unwrap();
        m.insert(name.clone(), v);
      }
      return m;
    }
  }
  panic!("no row found for request_id={request_id}");
}

fn count_rows(dir: &Path) -> usize {
  let mut n = 0;
  for entry in std::fs::read_dir(dir).unwrap() {
    let p = entry.unwrap().path();
    if p.extension().and_then(|e| e.to_str()) != Some("db") {
      continue;
    }
    let conn = Connection::open(&p).unwrap();
    n += conn
      .query_row("SELECT COUNT(*) FROM requests", [], |r| r.get::<_, i64>(0))
      .unwrap() as usize;
  }
  n
}

fn first_db_path(dir: &Path) -> PathBuf {
  std::fs::read_dir(dir)
    .unwrap()
    .map(|entry| entry.unwrap().path())
    .find(|p| p.extension().and_then(|e| e.to_str()) == Some("db"))
    .unwrap()
}

fn as_text(v: &rusqlite::types::Value) -> Option<String> {
  use rusqlite::types::Value;
  match v {
    Value::Text(s) => Some(s.clone()),
    Value::Blob(b) => Some(String::from_utf8_lossy(b).to_string()),
    _ => None,
  }
}
fn as_json(v: &rusqlite::types::Value) -> Option<Value> {
  as_text(v).and_then(|text| serde_json::from_str(&text).ok())
}
fn ctx(row: &std::collections::HashMap<String, rusqlite::types::Value>) -> Value {
  as_json(&row["ctx_json"]).unwrap_or_else(|| serde_json::json!({}))
}
fn as_int(v: &rusqlite::types::Value) -> Option<i64> {
  match v {
    rusqlite::types::Value::Integer(i) => Some(*i),
    _ => None,
  }
}
fn is_null(v: &rusqlite::types::Value) -> bool {
  matches!(v, rusqlite::types::Value::Null)
}

#[test]
fn happy_path_persists_all_stages() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-happy";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(
    req,
    0,
    extracted("client-model", true, Some("sess-1"), b"{\"in\":1}"),
  ));
  h.handle(&r2(req, 0, resolved("acct-1", "prov-1")));
  h.handle(&r2(req, 0, built_headers()));
  h.handle(&r2(req, 0, converted_request(b"{\"out\":2}")));
  h.handle(&r2(req, 0, sent(200)));
  h.handle(&r2(
    req,
    0,
    converted_response(200, Some(serde_json::json!({"ok": true}))),
  ));
  h.handle(&r2(req, 0, completed(true, 1)));

  let row = fetch_row(&dir, req);
  assert_eq!(as_text(&row["ver"]).as_deref(), Some(tokn_core::util::version::full()));
  assert_eq!(as_text(&row["endpoint"]).as_deref(), Some("responses"));
  assert_eq!(as_text(&row["model"]).as_deref(), Some("client-model"));
  assert_eq!(
    as_json(&row["params_json"]),
    Some(serde_json::json!({"initiator": "user", "stream": true}))
  );
  assert_eq!(as_text(&row["session_id"]).as_deref(), Some("sess-1"));
  assert_eq!(as_text(&row["account_id"]).as_deref(), Some("acct-1"));
  assert_eq!(as_text(&row["provider_id"]).as_deref(), Some("prov-1"));
  assert!(as_text(&row["inbound_req_headers"])
    .unwrap()
    .contains("\"x-test\":\"1\""));
  assert_eq!(as_text(&row["inbound_req_body"]).as_deref(), Some("{\"in\":1}"));
  assert!(as_text(&row["outbound_req_headers"])
    .unwrap()
    .contains("\"authorization\":\"<redacted>\""));
  assert_eq!(as_text(&row["outbound_req_body"]).as_deref(), Some("{\"out\":2}"));
  assert_eq!(as_int(&row["outbound_resp_status"]), Some(200));
  assert_eq!(as_int(&row["status"]), Some(200));
  assert!(as_text(&row["outbound_resp_headers"])
    .unwrap()
    .contains("\"x-upstream\":\"yes\""));
  assert_eq!(as_int(&row["inbound_resp_status"]), Some(200));
  assert_eq!(as_text(&row["inbound_resp_body"]).as_deref(), Some("{\"ok\":true}"));
  assert!(ctx(&row)["latency_header_ms"].as_i64().is_some());
  assert!(ctx(&row)["latency_ms"].as_i64().is_some());
  assert!(is_null(&row["request_error"]));
}

#[test]
fn body_recording_can_be_disabled() {
  let dir = tempdir();
  let mut h = RequestEventHandler::with_options(
    dir.clone(),
    RequestPersistenceOptions {
      record_request_bodies: false,
      body_max_bytes: 4,
    },
  )
  .unwrap();
  let req = "req-no-bodies";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(req, 0, extracted("model", false, None, b"inbound")));
  h.handle(&r2(req, 0, converted_request(b"outbound")));
  h.handle(&r2(
    req,
    0,
    converted_response(200, Some(serde_json::json!({"response": true}))),
  ));

  let row = fetch_row(&dir, req);
  assert!(is_null(&row["inbound_req_body"]));
  assert!(is_null(&row["outbound_req_body"]));
  assert!(is_null(&row["inbound_resp_body"]));
}

#[test]
fn recorded_bodies_are_bounded() {
  let dir = tempdir();
  let mut h = RequestEventHandler::with_options(
    dir.clone(),
    RequestPersistenceOptions {
      record_request_bodies: true,
      body_max_bytes: 4,
    },
  )
  .unwrap();
  let req = "req-bounded-bodies";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(req, 0, extracted("model", false, None, b"inbound")));
  h.handle(&r2(req, 0, converted_request(b"outbound")));
  h.handle(&rr(
    req,
    0,
    RecordEvent::UpstreamBody {
      body: Bytes::from_static(b"upstream"),
      error: None,
    },
  ));
  h.handle(&rr(
    req,
    0,
    RecordEvent::ConvertedBody {
      body: Bytes::from_static(b"converted"),
      error: None,
    },
  ));

  let row = fetch_row(&dir, req);
  assert_eq!(as_text(&row["inbound_req_body"]).as_deref(), Some("inbo"));
  assert_eq!(as_text(&row["outbound_req_body"]).as_deref(), Some("outb"));
  assert_eq!(as_text(&row["outbound_resp_body"]).as_deref(), Some("upst"));
  assert_eq!(as_text(&row["inbound_resp_body"]).as_deref(), Some("conv"));
}

#[test]
fn extract_omits_initiator_when_unknown() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-no-initiator";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(
    req,
    0,
    extracted_with_initiator("client-model", true, Some("sess-1"), None, b"{\"in\":1}"),
  ));

  let row = fetch_row(&dir, req);
  assert_eq!(as_json(&row["params_json"]), Some(serde_json::json!({"stream": true})));
}

#[test]
fn extract_merges_params_json_with_existing_keys() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-params-merge";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(
    req,
    0,
    extracted("client-model", true, Some("sess-1"), b"{\"in\":1}"),
  ));

  let conn = Connection::open(first_db_path(&dir)).unwrap();
  conn
    .execute(
      "UPDATE request_metadata
       SET params_json = json_set(params_json, '$.temperature', 0.7)
       WHERE request_id = ?1",
      params![req],
    )
    .unwrap();
  drop(conn);

  h.handle(&r2(req, 0, extracted("client-model-2", false, None, b"{\"in\":2}")));

  let row = fetch_row(&dir, req);
  assert_eq!(as_text(&row["model"]).as_deref(), Some("client-model-2"));
  assert_eq!(
    as_json(&row["params_json"]),
    Some(serde_json::json!({
      "initiator": "user",
      "stream": false,
      "temperature": 0.7
    }))
  );
}

#[test]
fn resolve_does_not_overwrite_started_request_endpoint_with_upstream_endpoint() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-endpoint-stability";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::custom("/v1/experimental/agents"),
    },
  ));
  h.handle(&r2(
    req,
    0,
    StageEvent::Resolve(ResolvedSummary {
      agent_id: None,
      model: SmolStr::new("client-model"),
      resolved_endpoint: None,
      upstream_model: SmolStr::new("upstream-model"),
      upstream_endpoint: Some(Endpoint::ChatCompletions),
      account_id: SmolStr::new("acct-1"),
      provider_id: SmolStr::new("prov-1"),
    }),
  ));

  let row = fetch_row(&dir, req);
  assert_eq!(as_text(&row["endpoint"]).as_deref(), Some("/v1/experimental/agents"));
}

#[test]
fn error_before_send_leaves_status_null_and_records_error() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-err";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Messages),
    },
  ));
  h.handle(&r2(req, 0, extracted("m", false, None, b"")));
  h.handle(&r2(req, 0, error(Stage::Resolve, "no account")));
  h.handle(&r2(req, 0, completed(false, 1)));

  let row = fetch_row(&dir, req);
  assert!(is_null(&row["status"]));
  assert!(is_null(&row["outbound_resp_status"]));
  assert_eq!(as_text(&row["request_error"]).as_deref(), Some("resolve: no account"));
  assert!(ctx(&row)["latency_ms"].as_i64().is_some());
}

#[test]
fn upstream_error_status_persists_response_snapshot_and_error() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-upstream-err";
  let mut headers = HeaderMap::new();
  headers.insert("content-type", "application/json");

  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(req, 0, extracted("m", false, None, b"{\"in\":1}")));
  h.handle(&r2(req, 0, resolved("acct", "prov")));
  h.handle(&r2(req, 0, built_headers()));
  h.handle(&r2(req, 0, converted_request(b"{\"out\":2}")));
  h.handle(&rr(
    req,
    0,
    RecordEvent::UpstreamResp {
      status: 502,
      headers: headers.clone(),
    },
  ));
  h.handle(&rr(
    req,
    0,
    RecordEvent::UpstreamBody {
      body: Bytes::copy_from_slice(br#"{"error":"boom"}"#),
      error: None,
    },
  ));
  h.handle(&r2(req, 0, error(Stage::Send, "upstream 502: {\"error\":\"boom\"}")));
  h.handle(&r2(req, 0, completed(false, 1)));

  let row = fetch_row(&dir, req);
  assert!(is_null(&row["status"]));
  assert_eq!(as_int(&row["outbound_resp_status"]), Some(502));
  assert!(as_text(&row["outbound_resp_headers"])
    .unwrap()
    .contains("\"content-type\":\"application/json\""));
  assert_eq!(
    as_text(&row["outbound_resp_body"]).as_deref(),
    Some("{\"error\":\"boom\"}")
  );
  assert_eq!(
    as_text(&row["request_error"]).as_deref(),
    Some("send: upstream 502: {\"error\":\"boom\"}")
  );
  assert!(ctx(&row)["latency_header_ms"].as_i64().is_some());
  assert!(ctx(&row)["latency_ms"].as_i64().is_some());
}

#[test]
fn retry_produces_two_independent_rows() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-retry";
  // attempt 0: fails at Send
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(req, 0, extracted("m", false, None, b"a")));
  h.handle(&r2(req, 0, resolved("acct", "prov")));
  h.handle(&r2(req, 0, built_headers()));
  h.handle(&r2(req, 0, converted_request(b"o0")));
  h.handle(&r2(req, 0, error(Stage::Send, "500")));
  h.handle(&r2(req, 0, completed(false, 1)));
  // attempt 1: succeeds
  h.handle(&r2(
    req,
    1,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&r2(req, 1, extracted("m", false, None, b"a")));
  h.handle(&r2(req, 1, resolved("acct", "prov")));
  h.handle(&r2(req, 1, built_headers()));
  h.handle(&r2(req, 1, converted_request(b"o1")));
  h.handle(&r2(req, 1, sent(200)));
  h.handle(&r2(req, 1, converted_response(200, Some(serde_json::json!({})))));
  h.handle(&r2(req, 1, completed(true, 2)));

  assert_eq!(count_rows(&dir), 2);
  let row0 = fetch_row(&dir, "req-retry");
  let row1 = fetch_row(&dir, "req-retry:1");
  assert!(is_null(&row0["status"]));
  assert_eq!(as_text(&row0["request_error"]).as_deref(), Some("send: 500"));
  assert_eq!(as_int(&row1["status"]), Some(200));
  assert!(is_null(&row1["request_error"]));
}

#[test]
fn stage_event_without_started_is_dropped_with_warning() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-orphan";
  h.handle(&r2(req, 0, extracted("m", false, None, b"")));
  h.handle(&r2(req, 0, completed(false, 1)));
  assert_eq!(count_rows(&dir), 0);
}

#[test]
fn inbound_connection_record_updates_connection_fields() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-conn";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&rr(
    req,
    0,
    RecordEvent::InboundConnection {
      user: Some(SmolStr::new("client-a")),
      api_key_id: Some(SmolStr::new("key-a")),
      local_addr: Some(SmolStr::new("127.0.0.1:4141")),
      peer_addr: Some(SmolStr::new("127.0.0.1:4142")),
      mode: SmolStr::new("route"),
      method: SmolStr::new("requests"),
      inbound_method: SmolStr::new("POST"),
      url: Some(SmolStr::new("https://example.test/v1/responses")),
    },
  ));

  let row = fetch_row(&dir, req);
  let ctx = ctx(&row);
  assert_eq!(as_text(&row["user"]).as_deref(), Some("client-a"));
  assert_eq!(ctx["api_key_id"], serde_json::json!("key-a"));
  assert_eq!(ctx["local_addr"], serde_json::json!("127.0.0.1:4141"));
  assert_eq!(ctx["peer_addr"], serde_json::json!("127.0.0.1:4142"));
  assert_eq!(ctx["mode"], serde_json::json!("route"));
  assert_eq!(ctx["pipeline_id"], serde_json::json!("requests"));
  assert_eq!(as_text(&row["inbound_req_method"]).as_deref(), Some("POST"));
  assert_eq!(
    as_text(&row["inbound_req_url"]).as_deref(),
    Some("https://example.test/v1/responses")
  );
}

#[test]
fn record_without_started_bootstraps_row() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-bootstrap";
  h.handle(&rr(
    req,
    0,
    RecordEvent::InboundConnection {
      user: None,
      api_key_id: None,
      local_addr: Some(SmolStr::new("127.0.0.1:4141")),
      peer_addr: Some(SmolStr::new("127.0.0.1:4142")),
      mode: SmolStr::new("route"),
      method: SmolStr::new("requests"),
      inbound_method: SmolStr::new("POST"),
      url: Some(SmolStr::new("https://example.test/v1/responses")),
    },
  ));

  let row = fetch_row(&dir, req);
  let ctx = ctx(&row);
  assert_eq!(ctx["local_addr"], serde_json::json!("127.0.0.1:4141"));
  assert_eq!(ctx["peer_addr"], serde_json::json!("127.0.0.1:4142"));
  assert_eq!(ctx["mode"], serde_json::json!("route"));
  assert_eq!(ctx["pipeline_id"], serde_json::json!("requests"));
  assert_eq!(as_text(&row["inbound_req_method"]).as_deref(), Some("POST"));
  assert_eq!(
    as_text(&row["inbound_req_url"]).as_deref(),
    Some("https://example.test/v1/responses")
  );
  assert!(is_null(&row["endpoint"]));
}

#[test]
fn resolve_without_upstream_endpoint_keeps_started_request_endpoint() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-auto-endpoint";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::custom("/v1/unknown"),
    },
  ));
  h.handle(&r2(
    req,
    0,
    StageEvent::Resolve(ResolvedSummary {
      agent_id: None,
      model: SmolStr::new("client-model"),
      resolved_endpoint: None,
      upstream_model: SmolStr::new("upstream-model"),
      upstream_endpoint: None,
      account_id: SmolStr::new("acct"),
      provider_id: SmolStr::new("prov"),
    }),
  ));

  let row = fetch_row(&dir, req);
  assert_eq!(as_text(&row["endpoint"]).as_deref(), Some("/v1/unknown"));
}

#[test]
fn custom_request_endpoint_persists_verbatim() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-custom-endpoint";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::custom("/v1/custom-endpoint"),
    },
  ));
  h.handle(&r2(req, 0, completed(true, 1)));

  let row = fetch_row(&dir, req);
  assert_eq!(as_text(&row["endpoint"]).as_deref(), Some("/v1/custom-endpoint"));
}

#[test]
fn usage_record_updates_token_columns() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-usage";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&rr(
    req,
    0,
    RecordEvent::Usage(Usage {
      input_tokens: Some(11),
      output_tokens: Some(22),
      total_tokens: Some(40),
      usage_type: Some(UsageType::Responses),
      details: UsageDetails {
        cache_read: Some(3),
        cache_write: Some(5),
        reasoning: Some(4),
      },
    }),
  ));

  let row = fetch_row(&dir, req);
  assert_eq!(
    as_json(&row["usage_json"]),
    Some(serde_json::json!({
      "kind": "responses",
      "input": 11,
      "output": 22,
      "cache_read": 3,
      "cache_write": 5,
      "reasoning": 4,
      "total": 40
    }))
  );
}

#[test]
fn usage_json_omits_missing_token_keys_and_does_not_calculate_total() {
  let dir = tempdir();
  let mut h = RequestEventHandler::new(dir.clone()).unwrap();
  let req = "req-usage-partial";
  h.handle(&r2(
    req,
    0,
    StageEvent::Started {
      request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
    },
  ));
  h.handle(&rr(
    req,
    0,
    RecordEvent::Usage(Usage {
      input_tokens: Some(11),
      output_tokens: Some(13),
      total_tokens: None,
      usage_type: Some(UsageType::Messages),
      details: UsageDetails {
        cache_read: None,
        cache_write: None,
        reasoning: None,
      },
    }),
  ));

  let row = fetch_row(&dir, req);
  assert_eq!(
    as_json(&row["usage_json"]),
    Some(serde_json::json!({
      "kind": "messages",
      "input": 11,
      "output": 13
    }))
  );
}

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use common::{body_json, body_text, cfg_for, ctx, int, json_obj, missing_or_null, text, zai_account, RequestsHarness};
use serde_json::{json, Map, Value};
use tokn_config::{ProfileConfig, RouteMode};
use tokn_mock_server::{MockLlmConfig, MockLlmServer, MockRoute};
use tokn_router::api::{build_state, router};
use tower::ServiceExt;

#[derive(Clone, Copy)]
struct RouterCase {
  name: &'static str,
  mode: &'static str,
  model: &'static str,
  expected_status: StatusCode,
  expected_upstream_model: Option<&'static str>,
  expected_error: Option<&'static str>,
}

fn assert_router_row(row: &Map<String, Value>, case: RouterCase) {
  let ctx = ctx(row);
  assert_eq!(
    ctx.get("mode").and_then(Value::as_str),
    Some(case.mode),
    "{}",
    case.name
  );
  assert_eq!(
    ctx.get("pipeline_id").and_then(Value::as_str),
    Some("requests"),
    "{}",
    case.name
  );
  assert_eq!(
    text(row, "inbound_req_method").as_deref(),
    Some("POST"),
    "{}",
    case.name
  );
  assert_eq!(
    text(row, "endpoint").as_deref(),
    Some("chat_completions"),
    "{}",
    case.name
  );
  assert_eq!(text(row, "model").as_deref(), Some(case.model), "{}", case.name);
  assert_eq!(
    text(row, "session_id").as_deref(),
    Some("sess-router-1"),
    "{}",
    case.name
  );

  if let Some(expected_error) = case.expected_error {
    let error = text(row, "request_error").unwrap_or_default();
    assert!(
      error.contains(expected_error),
      "{} persisted error {error:?} did not contain {expected_error:?}",
      case.name
    );
    assert!(
      int(row, "status").is_none(),
      "{} should not persist a success status",
      case.name
    );
    return;
  }

  assert_eq!(int(row, "status"), Some(200), "{}", case.name);
  assert_eq!(int(row, "outbound_resp_status"), Some(200), "{}", case.name);
  assert!(missing_or_null(row, "request_error"), "{}", case.name);
  assert_eq!(
    text(row, "account_id").as_deref(),
    Some("zai-test-acct"),
    "{}",
    case.name
  );
  assert_eq!(
    text(row, "provider_id").as_deref(),
    Some("zai-coding-plan"),
    "{}",
    case.name
  );
  let outbound = body_json(row, "outbound_req_body");
  assert_eq!(
    outbound["model"],
    Value::String(case.expected_upstream_model.unwrap().into()),
    "{}",
    case.name
  );
}

#[tokio::test]
async fn router_modes_return_expected_results_and_persist_request_rows() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let mut harness = RequestsHarness::new();
  let mut cfg = cfg_for(&harness.requests_dir, RouteMode::Route);
  for mode in [
    RouteMode::Route,
    RouteMode::Fuzzy,
    RouteMode::Exact,
    RouteMode::Passthrough,
  ] {
    cfg.profiles.insert(
      mode_name(mode).into(),
      ProfileConfig {
        mode: Some(mode),
        default_provider_id: matches!(mode, RouteMode::Passthrough).then_some("zai-coding-plan".into()),
        ..Default::default()
      },
    );
  }
  let state = build_state(&cfg, &[zai_account(mock.base_url())], harness.events.clone()).unwrap();
  let app = router(state);

  let cases = [
    RouterCase {
      name: "route_success",
      mode: "route",
      model: "glm-4.7",
      expected_status: StatusCode::OK,
      expected_upstream_model: Some("glm-4.7"),
      expected_error: None,
    },
    RouterCase {
      name: "fuzzy_success",
      mode: "fuzzy",
      model: "glm-family",
      expected_status: StatusCode::OK,
      expected_upstream_model: Some("glm-family"),
      expected_error: None,
    },
    RouterCase {
      name: "exact_success",
      mode: "exact",
      model: "zai-coding-plan/glm-4.7",
      expected_status: StatusCode::OK,
      expected_upstream_model: Some("glm-4.7"),
      expected_error: None,
    },
    RouterCase {
      name: "passthrough_success",
      mode: "passthrough",
      model: "glm-4.7",
      expected_status: StatusCode::OK,
      expected_upstream_model: Some("glm-4.7"),
      expected_error: None,
    },
    RouterCase {
      name: "exact_failure",
      mode: "exact",
      model: "glm-4.7",
      expected_status: StatusCode::BAD_REQUEST,
      expected_upstream_model: None,
      expected_error: Some("exact mode requires model in 'provider/model' form"),
    },
  ];

  for case in cases {
    let request_id = format!("router-{}", case.name);
    let inbound_body = json!({
      "model": case.model,
      "messages": [{"role": "user", "content": "hello"}],
      "stream": false
    });
    let raw_body = serde_json::to_vec(&inbound_body).unwrap();
    let response = app
      .clone()
      .oneshot(
        Request::builder()
          .method(Method::POST)
          .uri(format!("/{}/v1/chat/completions", case.mode))
          .header("content-type", "application/json")
          .header("x-request-id", &request_id)
          .header("x-session-id", "sess-router-1")
          .body(Body::from(raw_body.clone()))
          .unwrap(),
      )
      .await
      .unwrap();

    assert_eq!(response.status(), case.expected_status, "{}", case.name);
    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  }

  assert_eq!(
    mock.requests().len(),
    4,
    "only successful router cases should hit upstream"
  );
  harness.shutdown().await;
  for case in cases {
    let request_id = format!("router-{}", case.name);
    let row = harness.row(&request_id).await;
    assert_router_row(&row, case);
  }
  mock.shutdown().await;
}

fn mode_name(mode: RouteMode) -> &'static str {
  match mode {
    RouteMode::Passthrough => "passthrough",
    RouteMode::Switch => "switch",
    RouteMode::Exact => "exact",
    RouteMode::Route => "route",
    RouteMode::Fuzzy => "fuzzy",
  }
}

#[tokio::test]
async fn router_stream_returns_sse_and_persists_drained_stream_row() {
  let mock = MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::chat_completions_stream())).await;
  let mut harness = RequestsHarness::new();
  let cfg = cfg_for(&harness.requests_dir, RouteMode::Route);
  let state = build_state(&cfg, &[zai_account(mock.base_url())], harness.events.clone()).unwrap();
  let app = router(state);
  let request_id = "router-stream-success";
  let inbound_body = json!({
    "model": "glm-4.7",
    "messages": [{"role": "user", "content": "stream please"}],
    "stream": true
  });
  let raw_body = serde_json::to_vec(&inbound_body).unwrap();

  let response = app
    .oneshot(
      Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header("accept", "text/event-stream")
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .header(
          "x-codex-turn-metadata",
          r#"{"session_id":"sess-stream-meta","thread_id":"thread-stream-meta","turn_id":"turn-stream-meta"}"#,
        )
        .body(Body::from(raw_body.clone()))
        .unwrap(),
    )
    .await
    .unwrap();

  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    response
      .headers()
      .get("content-type")
      .and_then(|value| value.to_str().ok())
      .map(|value| value.starts_with("text/event-stream")),
    Some(true)
  );
  let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  let body = std::str::from_utf8(&body).unwrap();
  assert!(body.contains("\"content\":\"hel\""), "{body}");
  assert!(body.contains("\"content\":\"lo\""), "{body}");
  assert!(body.contains("\"completion_tokens\":2"), "{body}");
  assert!(body.contains("data: [DONE]"), "{body}");

  let captured = mock.last_request().expect("upstream request captured");
  assert_eq!(captured.header("accept"), Some("text/event-stream"));
  let outbound: Value = serde_json::from_slice(&captured.body).unwrap();
  assert_eq!(outbound["model"], "glm-4.7");
  assert_eq!(outbound["stream"], true);

  harness.shutdown().await;

  let row = harness.row(request_id).await;
  let ctx = ctx(&row);
  assert_eq!(ctx.get("mode").and_then(Value::as_str), Some("route"));
  assert_eq!(ctx.get("pipeline_id").and_then(Value::as_str), Some("requests"));
  let params = json_obj(&row, "params_json");
  let usage = json_obj(&row, "usage_json");
  assert_eq!(text(&row, "endpoint").as_deref(), Some("chat_completions"));
  assert_eq!(text(&row, "model").as_deref(), Some("glm-4.7"));
  assert_eq!(text(&row, "session_id").as_deref(), Some("sess-stream-meta"));
  assert_eq!(
    harness.usage_session_id(request_id).as_deref(),
    Some("sess-stream-meta")
  );
  assert_eq!(params.get("stream").and_then(Value::as_bool), Some(true));
  assert_eq!(int(&row, "status"), Some(200));
  assert_eq!(int(&row, "outbound_resp_status"), Some(200));
  assert_eq!(int(&row, "inbound_resp_status"), Some(200));
  assert_eq!(usage.get("input").and_then(Value::as_i64), Some(3));
  assert_eq!(usage.get("output").and_then(Value::as_i64), Some(2));
  let persisted_outbound = body_json(&row, "outbound_req_body");
  assert_eq!(persisted_outbound["model"], "glm-4.7");
  assert_eq!(persisted_outbound["stream"], true);
  assert!(body_text(&row, "outbound_resp_body").contains("\"completion_tokens\":2"));
  assert!(body_text(&row, "inbound_resp_body").contains("\"completion_tokens\":2"));
  assert!(body_text(&row, "inbound_resp_body").contains("data: [DONE]"));
  assert!(missing_or_null(&row, "request_error"));

  mock.shutdown().await;
}

#[tokio::test]
async fn malformed_body_returns_bad_request_and_persists_completed_row() {
  let mut harness = RequestsHarness::new();
  let cfg = cfg_for(&harness.requests_dir, RouteMode::Route);
  let state = build_state(&cfg, &[zai_account("http://127.0.0.1:9")], harness.events.clone()).unwrap();
  let app = router(state);
  let request_id = "router-malformed-body";

  let response = app
    .oneshot(
      Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .body(Body::from(r#"{"model":"#))
        .unwrap(),
    )
    .await
    .unwrap();

  assert_eq!(response.status(), StatusCode::BAD_REQUEST);
  let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  assert!(std::str::from_utf8(&response_body)
    .unwrap()
    .contains("invalid JSON request body"));

  harness.shutdown().await;
  let row = harness.row(request_id).await;
  assert_eq!(text(&row, "inbound_req_method").as_deref(), Some("POST"));
  assert_eq!(text(&row, "endpoint").as_deref(), Some("chat_completions"));
  assert_eq!(int(&row, "status"), Some(400));
  assert_eq!(int(&row, "inbound_resp_status"), Some(400));
  assert!(text(&row, "request_error")
    .unwrap_or_default()
    .contains("invalid JSON request body"));
  assert!(body_json(&row, "inbound_resp_body")["error"]["message"]
    .as_str()
    .unwrap_or_default()
    .contains("invalid JSON request body"));
}

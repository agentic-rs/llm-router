mod support;

use smol_str::SmolStr;
use std::sync::Arc;
use support::*;
use tokn_requests::event::{EventPayload, RecordEvent, Stage, StageEvent};
use tokn_requests::pipeline::stages::ConvertedBody;
use tokn_requests::stages::{
  DefaultBuildHeaders, DefaultConvertRequest, DefaultConvertResponse, DefaultExtract, DefaultSend, NoopBuildHeaders,
  NoopConvertRequest, PoolResolve,
};
use tokn_requests::{ExecutionRequest, PipelineRunner, Profile, RequestService};

#[tokio::test]
async fn pre_send_happy_path_emits_expected_event_sequence() {
  let (bus, log) = capture_bus();
  let profile = Arc::new(Profile::without_send(
    "smoke",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(Arc::new(OkSelector))),
    Arc::new(NoopBuildHeaders),
    Arc::new(NoopConvertRequest),
  ));
  let service = RequestService::from_pipeline(Arc::new(PipelineRunner::new(profile, bus)));

  let err = service
    .execute(ExecutionRequest::new(raw_chat("input-model")))
    .await
    .expect_err("without_send must return Err(stop) at Send");
  let source = err.pipeline().expect("pipeline adapter must retain its source");
  assert!(source.stop, "expected a stop error, got {source:?}");
  assert_eq!(source.stage, Stage::Send);

  let events = drain_until_completed(&log).await;
  let kinds = known_kinds(&events);
  assert_eq!(
    kinds,
    [
      "started",
      "extract",
      "resolve",
      "build_headers",
      "convert_request",
      "error",
      "completed",
    ]
  );

  let (err_stage, stop_flag) = events
    .iter()
    .find_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Error { stage, stop, .. }) => Some((*stage, *stop)),
      _ => None,
    })
    .expect("Error event must be present");
  assert_eq!(err_stage, Stage::Send);
  assert!(stop_flag);

  let resolve = events.iter().find_map(|e| match &e.payload {
    EventPayload::Stage(StageEvent::Resolve(r)) => Some((
      r.upstream_model.clone(),
      r.provider_id.clone(),
      r.account_id.clone(),
      r.agent_id.clone(),
    )),
    _ => None,
  });
  let (upstream, provider, account, client) = resolve.expect("Resolve event must be present");
  assert_eq!(upstream, "glm-4");
  assert_eq!(provider, "zai-coding-plan");
  assert_eq!(account, "acct-1");
  assert!(client.is_none());
}

#[tokio::test]
async fn pre_send_no_account_emits_error_then_completed_failure() {
  let (bus, log) = capture_bus();
  let profile = Arc::new(Profile::without_send(
    "smoke",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(Arc::new(EmptySelector))),
    Arc::new(NoopBuildHeaders),
    Arc::new(NoopConvertRequest),
  ));
  let runner = PipelineRunner::new(profile, bus);

  let err = runner
    .run(raw_chat("nope"))
    .await
    .expect_err("empty selector must fail at Resolve");
  assert_eq!(err.stage, Stage::Resolve);
  assert!(!err.recoverable);
  assert!(!err.stop, "no-account is a real failure, not a stop");

  let events = drain_until_completed(&log).await;
  let kinds = known_kinds(&events);
  assert_eq!(kinds, ["started", "extract", "error", "completed"]);

  let (stage, recoverable, stop) = events
    .iter()
    .find_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Error {
        stage,
        recoverable,
        stop,
        ..
      }) => Some((*stage, *recoverable, *stop)),
      _ => None,
    })
    .expect("Error event must be present");
  assert_eq!(stage, Stage::Resolve);
  assert!(!recoverable);
  assert!(!stop);

  let success = events.iter().find_map(|e| match &e.payload {
    EventPayload::Stage(StageEvent::Completed { success, .. }) => Some(*success),
    _ => None,
  });
  assert_eq!(success, Some(false));
}

#[tokio::test]
async fn full_pipeline_buffered_happy_path() {
  let (bus, log) = capture_bus();

  let resp = ok_response(
    200,
    r#"{"id":"resp-1","choices":[{"message":{"role":"assistant","content":"hi"}}]}"#,
  );
  let handle = responding_handle("zai-coding-plan", "acct-1", resp);
  let selector = Arc::new(CannedSelector { handle });

  let profile = Arc::new(Profile::full(
    "smoke-full",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(reqwest::Client::new())),
    Arc::new(DefaultConvertResponse::new()),
  ));
  let runner = PipelineRunner::new(profile, bus);

  let converted = runner
    .run(raw_chat("glm-4"))
    .await
    .expect("happy-path pipeline must succeed");

  let events = drain_until_completed(&log).await;
  let kinds = known_kinds(&events);
  assert_eq!(
    kinds,
    [
      "started",
      "extract",
      "resolve",
      "build_headers",
      "convert_request",
      "record",
      "send",
      "record",
      "convert_response",
      "record",
      "completed",
    ]
  );

  let (success, attempts) = events
    .iter()
    .find_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Completed { success, attempts }) => Some((*success, *attempts)),
      _ => None,
    })
    .expect("Completed event must be present");
  assert!(success);
  assert_eq!(attempts, 1);

  assert_eq!(converted.status, 200);
  match converted.body {
    ConvertedBody::Buffered { body_json, .. } => {
      let body_json = body_json.unwrap();
      assert_eq!(body_json["id"], "resp-1");
      assert_eq!(body_json["choices"][0]["message"]["content"], "hi");
    }
    other => panic!("expected Buffered, got {other:?}"),
  }
}

#[tokio::test]
async fn cancelled_attempt_after_upstream_req_emits_terminal_events() {
  let (bus, log) = capture_bus();
  let selector = Arc::new(OkSelector);
  let profile = Arc::new(Profile::full(
    "smoke-cancelled-at-send",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(NoopBuildHeaders),
    Arc::new(NoopConvertRequest),
    Arc::new(PendingSend),
    Arc::new(DefaultConvertResponse::new()),
  ));
  let runner = PipelineRunner::new(profile, bus);

  let task = tokio::spawn(async move { runner.run(raw_chat("glm-4")).await });
  drain_until_upstream_req(&log).await;
  task.abort();
  let _ = task.await;

  let events = drain_until_completed(&log).await;
  let saw_cancel_error = events.iter().any(|e| {
    matches!(
      &e.payload,
      EventPayload::Stage(StageEvent::Error {
        stage: Stage::Send,
        message,
        ..
      }) if message.as_str().contains("cancelled")
    )
  });
  assert!(saw_cancel_error, "cancelled send must emit a terminal error");

  let completed = events.iter().find_map(|e| match &e.payload {
    EventPayload::Stage(StageEvent::Completed { success, attempts }) => Some((*success, *attempts)),
    _ => None,
  });
  assert_eq!(completed, Some((false, 1)));

  let request = events.iter().find_map(|e| match &e.payload {
    EventPayload::Record(RecordEvent::UpstreamReq { method, url, .. }) => Some((method, url)),
    _ => None,
  });
  assert_eq!(
    request,
    Some((&SmolStr::new("POST"), &SmolStr::new("https://example.test/pending")))
  );
}

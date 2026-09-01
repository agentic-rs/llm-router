mod support;

use http::Method;
use std::sync::Arc;
use std::time::Duration;
use support::*;
use tokn_core::request_event::RecordEvent;
use tokn_requests::event::{EventPayload, Stage, StageEvent};
use tokn_requests::pipeline::stages::ConvertedBody;
use tokn_requests::stages::{
  DefaultBuildHeaders, DefaultConvertRequest, DefaultConvertResponse, DefaultExtract, DefaultSend, PoolResolve,
};
use tokn_requests::{PipelineRunner, Profile, RetryPolicy, RunConfig};

#[tokio::test]
async fn pipeline_send_failure_preserves_partial_outcome() {
  let (bus, log) = capture_bus();

  let handle = failing_handle("zai-coding-plan", "acct-1");
  let selector = Arc::new(CannedSelector { handle });

  let profile = Arc::new(Profile::full(
    "smoke-fail",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(reqwest::Client::new())),
    Arc::new(DefaultConvertResponse::new()),
  ));
  let runner = PipelineRunner::new(profile, bus);

  let err = runner
    .run(raw_chat("glm-4"))
    .await
    .expect_err("upstream 401 must surface as Err");

  assert_eq!(err.stage, Stage::Send);
  assert!(
    err.message().contains("401"),
    "error message should mention upstream status: {}",
    err.message()
  );
  assert!(!err.stop, "401 is a real failure, not a stop");

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
      "record",
      "error",
      "completed",
    ]
  );

  let mut saw_upstream_resp = false;
  let mut saw_upstream_body = false;
  for event in &*events {
    match &event.payload {
      EventPayload::Record(RecordEvent::UpstreamResp { status, .. }) => {
        saw_upstream_resp = true;
        assert_eq!(*status, 401);
      }
      EventPayload::Record(RecordEvent::UpstreamBody { body, error }) => {
        saw_upstream_body = true;
        assert_eq!(
          std::str::from_utf8(body.as_ref()).unwrap(),
          r#"{"error":"unauthorized"}"#
        );
        assert!(error.is_none());
      }
      _ => {}
    }
  }
  assert!(saw_upstream_resp, "expected UpstreamResp record on send failure");
  assert!(saw_upstream_body, "expected UpstreamBody record on send failure");

  let resolved_seen = events
    .iter()
    .any(|e| matches!(&e.payload, EventPayload::Stage(StageEvent::Resolve(_))));
  let headers_seen = events
    .iter()
    .any(|e| matches!(&e.payload, EventPayload::Stage(StageEvent::BuildHeaders(_))));
  let req_seen = events
    .iter()
    .any(|e| matches!(&e.payload, EventPayload::Stage(StageEvent::ConvertRequest(_))));
  assert!(resolved_seen, "Resolve event must precede the Send failure");
  assert!(headers_seen, "BuildHeaders event must precede the Send failure");
  assert!(req_seen, "ConvertRequest event must precede the Send failure");

  let (err_stage, err_stop) = events
    .iter()
    .find_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Error { stage, stop, .. }) => Some((*stage, *stop)),
      _ => None,
    })
    .expect("Error event must be present");
  assert_eq!(err_stage, Stage::Send);
  assert!(!err_stop);
  let completed_success = events.iter().find_map(|e| match &e.payload {
    EventPayload::Stage(StageEvent::Completed { success, .. }) => Some(*success),
    _ => None,
  });
  assert_eq!(completed_success, Some(false));
}

#[tokio::test]
async fn pipeline_retries_recoverable_send_failures_and_succeeds() {
  let (bus, log) = capture_bus();

  let handle = sequenced_handle(
    "zai-coding-plan",
    "acct-1",
    vec![
      ScriptedResponse::Http {
        status: 503,
        body: "retry me",
      },
      ScriptedResponse::Http {
        status: 200,
        body: r#"{"id":"resp-retry","choices":[{"message":{"role":"assistant","content":"ok"}}]}"#,
      },
    ],
  );
  let selector = Arc::new(CannedSelector { handle });

  let profile = Arc::new(Profile::full(
    "smoke-retry-success",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(reqwest::Client::new())),
    Arc::new(DefaultConvertResponse::new()),
  ));
  let runner = PipelineRunner::new_with_retry(profile, bus, RetryPolicy::new(2, Duration::from_millis(1)));

  let converted = runner
    .run(raw_chat("glm-4"))
    .await
    .expect("second attempt should succeed");
  let events = drain_until_completed_attempts(&log, 2).await;
  let error_attempts: Vec<u32> = events
    .iter()
    .filter_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Error {
        stage: Stage::Send,
        recoverable,
        ..
      }) if *recoverable => Some(e.attempt),
      _ => None,
    })
    .collect();
  assert_eq!(error_attempts, vec![0]);

  let completed = events
    .iter()
    .filter_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Completed { success, attempts }) => Some((e.attempt, *success, *attempts)),
      _ => None,
    })
    .collect::<Vec<_>>();
  let started_attempts: Vec<u32> = events
    .iter()
    .filter_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Started { .. }) => Some(e.attempt),
      _ => None,
    })
    .collect();
  assert_eq!(started_attempts, vec![0, 1]);
  assert_eq!(completed, vec![(0, false, 1), (1, true, 2)]);

  match converted.body {
    ConvertedBody::Buffered { body_json, .. } => {
      let body_json = body_json.unwrap();
      assert_eq!(body_json["id"], "resp-retry");
    }
    other => panic!("expected Buffered, got {other:?}"),
  }
}

#[tokio::test]
async fn pipeline_stops_after_retry_budget_exhausted() {
  let (bus, log) = capture_bus();

  let handle = sequenced_handle(
    "zai-coding-plan",
    "acct-1",
    vec![
      ScriptedResponse::Http {
        status: 503,
        body: "one",
      },
      ScriptedResponse::Http {
        status: 503,
        body: "two",
      },
      ScriptedResponse::Http {
        status: 503,
        body: "three",
      },
    ],
  );
  let selector = Arc::new(CannedSelector { handle });

  let profile = Arc::new(Profile::full(
    "smoke-retry-exhausted",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(reqwest::Client::new())),
    Arc::new(DefaultConvertResponse::new()),
  ));
  let runner = PipelineRunner::new_with_retry(profile, bus, RetryPolicy::new(2, Duration::from_millis(1)));

  let err = runner
    .run(raw_chat("glm-4"))
    .await
    .expect_err("retry budget should exhaust");
  assert_eq!(err.stage, Stage::Send);
  assert!(err.recoverable);

  let events = drain_until_completed_attempts(&log, 3).await;
  let completed = events
    .iter()
    .filter_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Completed { success, attempts }) => Some((e.attempt, *success, *attempts)),
      _ => None,
    })
    .collect::<Vec<_>>();
  let started_attempts: Vec<u32> = events
    .iter()
    .filter_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Started { .. }) => Some(e.attempt),
      _ => None,
    })
    .collect();
  assert_eq!(started_attempts, vec![0, 1, 2]);
  assert_eq!(completed, vec![(0, false, 1), (1, false, 2), (2, false, 3)]);
}

#[tokio::test]
async fn pipeline_does_not_retry_permanent_send_failures() {
  let (bus, log) = capture_bus();

  let handle = sequenced_handle(
    "zai-coding-plan",
    "acct-1",
    vec![ScriptedResponse::Http {
      status: 401,
      body: "nope",
    }],
  );
  let selector = Arc::new(CannedSelector { handle });

  let profile = Arc::new(Profile::full(
    "smoke-retry-permanent",
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(reqwest::Client::new())),
    Arc::new(DefaultConvertResponse::new()),
  ));
  let runner = PipelineRunner::new_with_retry(profile, bus, RetryPolicy::new(2, Duration::from_millis(1)));

  let err = runner
    .run(raw_chat("glm-4"))
    .await
    .expect_err("401 should remain permanent");
  assert_eq!(err.stage, Stage::Send);
  assert!(!err.recoverable);

  let events = drain_until_completed(&log).await;
  let started_attempts: Vec<u32> = events
    .iter()
    .filter_map(|e| match &e.payload {
      EventPayload::Stage(StageEvent::Started { .. }) => Some(e.attempt),
      _ => None,
    })
    .collect();
  assert_eq!(started_attempts, vec![0]);
}

#[tokio::test]
async fn safe_method_policy_retries_get_requests() {
  let (bus, log) = capture_bus();
  let handle = sequenced_handle(
    "zai-coding-plan",
    "acct-1",
    vec![
      ScriptedResponse::Http {
        status: 503,
        body: "retry me",
      },
      ScriptedResponse::Http {
        status: 200,
        body: r#"{"id":"resp-safe","choices":[{"message":{"role":"assistant","content":"ok"}}]}"#,
      },
    ],
  );
  let runner = retry_runner(
    "safe-method-get",
    handle,
    bus,
    RetryPolicy::safe_methods(1, Duration::ZERO),
  );

  let response = runner
    .run_with(raw_chat("glm-4"), RunConfig::new().with_request_method(Method::GET))
    .await
    .expect("safe GET should be retried");
  assert!(matches!(response.body, ConvertedBody::Buffered { .. }));

  let events = drain_until_completed_attempts(&log, 2).await;
  assert_eq!(started_attempts(&events), vec![0, 1]);
}

#[tokio::test]
async fn safe_method_policy_does_not_retry_post_or_unknown_methods() {
  for (label, method) in [("post", Some(Method::POST)), ("unknown", None)] {
    let bus = Arc::new(tokn_requests::EventBus::new(256));
    let mut events = bus.subscribe();
    let handle = sequenced_handle(
      "zai-coding-plan",
      "acct-1",
      vec![ScriptedResponse::Http {
        status: 503,
        body: "do not replay",
      }],
    );
    let runner = retry_runner(
      &format!("safe-method-{label}"),
      handle,
      bus,
      RetryPolicy::safe_methods(1, Duration::ZERO),
    );
    let config = method.map_or_else(RunConfig::new, |method| RunConfig::new().with_request_method(method));

    let error = runner
      .run_with(raw_chat("glm-4"), config)
      .await
      .expect_err("unsafe or unknown methods must not be replayed");
    assert!(error.recoverable);

    let events = drain_received_events(&mut events);
    assert_eq!(started_attempts(&events), vec![0], "method case: {label}");
  }
}

fn retry_runner(
  name: &str,
  handle: Arc<tokn_accounts::AccountHandle>,
  events: Arc<tokn_requests::EventBus>,
  retry_policy: RetryPolicy,
) -> PipelineRunner {
  let profile = Arc::new(Profile::full(
    name,
    Arc::new(DefaultExtract),
    Arc::new(PoolResolve::new(Arc::new(CannedSelector { handle }))),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(reqwest::Client::new())),
    Arc::new(DefaultConvertResponse::new()),
  ));
  PipelineRunner::new_with_retry(profile, events, retry_policy)
}

fn started_attempts(events: &[tokn_requests::Event]) -> Vec<u32> {
  events
    .iter()
    .filter_map(|event| match &event.payload {
      EventPayload::Stage(StageEvent::Started { .. }) => Some(event.attempt),
      _ => None,
    })
    .collect()
}

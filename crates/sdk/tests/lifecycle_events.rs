use serde_json::json;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokn_mock_server::{MockLlmConfig, MockLlmServer, MockRoute};
use tokn_sdk::chat_completions::ChatRequest;
use tokn_sdk::events::{
  BodyCapture, BodyLeg, BodyOutcome, BodyResult, RequestOutcome, RequestSource, TrafficEvent, TrafficEventKind,
};
use tokn_sdk::{
  Client, ConsumerResult, Endpoint, Error, EventConsumer, EventSeq, GatewayEvent, HubBuilder, HubStatus, Publisher,
  RequestOptions,
};

struct Fixture {
  _root: TempDir,
  config_path: std::path::PathBuf,
  auth_path: std::path::PathBuf,
}

impl Fixture {
  fn new(base_url: &str) -> Self {
    let root = tempfile::tempdir().expect("create SDK event fixture directory");
    let config_path = root.path().join("config.toml");
    let auth_path = root.path().join("auth.yaml");
    fs::write(&config_path, config(base_url)).expect("write SDK event config");
    fs::write(
      &auth_path,
      "version: 1\naccounts:\n  - id: local\n    provider: llama-cpp\n",
    )
    .expect("write SDK event credentials");
    Self {
      _root: root,
      config_path,
      auth_path,
    }
  }

  fn client(&self, publisher: Publisher<GatewayEvent>) -> Client {
    Client::builder()
      .config_path(&self.config_path)
      .auth_path(&self.auth_path)
      .event_publisher(publisher)
      .build()
      .expect("build event-enabled SDK client")
  }
}

fn config(base_url: &str) -> String {
  format!(
    r#"schema_version = 2

[profiles.default]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "fixed", upstream = "local" }}
model = {{ kind = "qualified", namespace = "provider" }}
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["llama-cpp"]

[upstreams.local]
provider = "llama-cpp"
base_url = "{base_url}"
accounts = ["local"]
"#,
  )
}

fn chat_request() -> ChatRequest {
  serde_json::from_value(json!({
    "model": "llama-cpp/mock-model",
    "messages": [{"role": "user", "content": "hello"}]
  }))
  .expect("deserialize chat request fixture")
}

#[derive(Clone)]
struct Capture {
  inner: Arc<CaptureInner>,
}

struct CaptureInner {
  events: Mutex<Vec<(EventSeq, GatewayEvent)>>,
  changed: Notify,
}

impl Capture {
  fn new() -> Self {
    Self {
      inner: Arc::new(CaptureInner {
        events: Mutex::new(Vec::new()),
        changed: Notify::new(),
      }),
    }
  }

  fn consumer(&self) -> CaptureConsumer {
    CaptureConsumer { capture: self.clone() }
  }

  fn traffic(&self, client_request_id: &str) -> Vec<TrafficEvent> {
    let events = self.inner.events.lock().expect("capture lock poisoned");
    let request_id = events.iter().find_map(|(_, event)| match event {
      GatewayEvent::Traffic(event) => match &event.kind {
        TrafficEventKind::Started(started)
          if started.correlation.client_request_id.as_deref() == Some(client_request_id) =>
        {
          Some(event.request_id.clone())
        }
        _ => None,
      },
      _ => None,
    });
    let Some(request_id) = request_id else {
      return Vec::new();
    };
    events
      .iter()
      .filter_map(|(_, event)| match event {
        GatewayEvent::Traffic(event) if event.request_id == request_id => Some(event.clone()),
        _ => None,
      })
      .collect()
  }

  fn has_finished(&self, client_request_id: &str) -> bool {
    self
      .traffic(client_request_id)
      .iter()
      .any(|event| matches!(event.kind, TrafficEventKind::Finished(_)))
  }

  fn hub_sequences(&self) -> Vec<u64> {
    self
      .inner
      .events
      .lock()
      .expect("capture lock poisoned")
      .iter()
      .map(|(sequence, _)| sequence.get())
      .collect()
  }

  async fn wait_for_finished(&self, client_request_ids: &[&str]) {
    tokio::time::timeout(Duration::from_secs(5), async {
      loop {
        let changed = self.inner.changed.notified();
        if client_request_ids
          .iter()
          .all(|request_id| self.has_finished(request_id))
        {
          break;
        }
        changed.await;
      }
    })
    .await
    .expect("timed out waiting for request lifecycle completion");
  }
}

struct CaptureConsumer {
  capture: Capture,
}

impl EventConsumer<GatewayEvent> for CaptureConsumer {
  fn name(&self) -> &str {
    "sdk-lifecycle-capture"
  }

  fn handle(&mut self, sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
    self
      .capture
      .inner
      .events
      .lock()
      .expect("capture lock poisoned")
      .push((sequence, event.clone()));
    self.capture.inner.changed.notify_one();
    Ok(())
  }
}

fn event_hub() -> (Capture, Publisher<GatewayEvent>, tokn_sdk::EventHub<GatewayEvent>) {
  let capture = Capture::new();
  let (publisher, hub) = HubBuilder::new()
    .consumer(capture.consumer())
    .start()
    .expect("start caller-owned event hub");
  (capture, publisher, hub)
}

fn assert_contiguous_request_sequence(events: &[TrafficEvent]) {
  assert!(!events.is_empty());
  assert_eq!(events[0].sequence, 1);
  for window in events.windows(2) {
    assert_eq!(window[1].sequence, window[0].sequence + 1);
  }
}

#[tokio::test]
async fn buffered_success_and_body_validation_failure_are_comprehensive() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let (capture, publisher, hub) = event_hub();
  let client = fixture.client(publisher);

  let response = client
    .chat_completions()
    .create_with(
      &chat_request(),
      RequestOptions::default().with_request_id("sdk-buffered-events"),
    )
    .await
    .expect("execute buffered request");
  assert_eq!(response.status, 200);

  let error = client
    .execute(
      Endpoint::ChatCompletions,
      json!({"messages": []}),
      RequestOptions::default().with_request_id("sdk-invalid-body-events"),
    )
    .await
    .expect_err("missing model should fail body validation");
  assert!(matches!(error, Error::ManagedRequest { .. }));

  capture
    .wait_for_finished(&["sdk-buffered-events", "sdk-invalid-body-events"])
    .await;

  let success = capture.traffic("sdk-buffered-events");
  assert_contiguous_request_sequence(&success);
  assert_ne!(success[0].request_id.as_str(), "sdk-buffered-events");
  assert!(success.iter().all(|event| event.request_id == success[0].request_id));
  assert!(success.iter().any(|event| {
    matches!(
      &event.kind,
      TrafficEventKind::Started(started)
        if matches!(&started.source, RequestSource::Embedded { profile_id } if profile_id == "default")
          && started.correlation.client_request_id.as_deref() == Some("sdk-buffered-events")
    )
  }));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::Authenticated(_))));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::PolicySelected(_))));
  assert!(success.iter().any(|event| {
    matches!(
      &event.kind,
      TrafficEventKind::RequestBody(body)
        if matches!(&body.wire, BodyCapture::Absent)
          && matches!(&body.decoded, Some(BodyCapture::Complete(_)))
          && matches!(&body.outcome, BodyOutcome::Accepted)
    )
  }));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::AttemptStarted(_))));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::AttemptRequest(_))));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::AttemptResponseHead(_))));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::DownstreamResponseHead(_))));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::BodyFinished(_))));
  assert!(success
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::AttemptFinished(_))));
  assert!(success.iter().any(|event| {
    matches!(
      &event.kind,
      TrafficEventKind::Finished(finished)
        if finished.outcome == RequestOutcome::Delivered && finished.attempt_count == 1
    )
  }));

  let invalid = capture.traffic("sdk-invalid-body-events");
  assert_contiguous_request_sequence(&invalid);
  assert_ne!(invalid[0].request_id.as_str(), "sdk-invalid-body-events");
  assert!(invalid.iter().any(|event| {
    matches!(
      &event.kind,
      TrafficEventKind::RequestBody(body)
        if matches!(&body.wire, BodyCapture::Absent)
          && matches!(&body.decoded, Some(BodyCapture::Complete(_)))
          && matches!(&body.outcome, BodyOutcome::Rejected(_))
    )
  }));
  assert!(invalid
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::Authenticated(_))));
  assert!(invalid
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::PolicySelected(_))));
  assert!(!invalid
    .iter()
    .any(|event| matches!(&event.kind, TrafficEventKind::AttemptStarted(_))));
  assert!(invalid.iter().any(|event| {
    matches!(
      &event.kind,
      TrafficEventKind::Finished(finished)
        if finished.outcome == RequestOutcome::Rejected && finished.attempt_count == 0
    )
  }));
  assert_eq!(mock.requests().len(), 1);

  drop(client);
  hub.shutdown().await.expect("shut down caller-owned event hub");
  mock.shutdown().await;
}

#[tokio::test]
async fn raw_stream_eof_and_drop_publish_truthful_terminal_facts() {
  let mock = MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::chat_completions_stream())).await;
  let fixture = Fixture::new(mock.base_url());
  let (capture, publisher, hub) = event_hub();
  let client = fixture.client(publisher);

  let response = client
    .chat_completions()
    .stream_with(
      &chat_request(),
      RequestOptions::default().with_request_id("sdk-raw-eof"),
    )
    .await
    .expect("start raw stream for EOF");
  response.bytes().await.expect("drain raw stream through EOF");

  let response = client
    .chat_completions()
    .stream_with(
      &chat_request(),
      RequestOptions::default().with_request_id("sdk-raw-drop"),
    )
    .await
    .expect("start raw stream for drop");
  drop(response);

  capture.wait_for_finished(&["sdk-raw-eof", "sdk-raw-drop"]).await;

  let complete = capture.traffic("sdk-raw-eof");
  assert!(complete.iter().any(|event| match &event.kind {
    TrafficEventKind::BodyFinished(body) => {
      matches!(body.leg, BodyLeg::Upstream { .. }) && body.result == BodyResult::Complete
    }
    _ => false,
  }));
  assert!(!complete.iter().any(|event| match &event.kind {
    TrafficEventKind::BodyFinished(body) => body.result == BodyResult::Cancelled,
    _ => false,
  }));
  assert!(complete.iter().any(|event| {
    matches!(
      &event.kind,
      TrafficEventKind::Finished(finished) if finished.outcome == RequestOutcome::Delivered
    )
  }));

  let dropped = capture.traffic("sdk-raw-drop");
  assert!(dropped.iter().any(|event| match &event.kind {
    TrafficEventKind::BodyFinished(body) => {
      matches!(body.leg, BodyLeg::Upstream { .. }) && body.result == BodyResult::Cancelled
    }
    _ => false,
  }));
  assert!(dropped.iter().any(|event| {
    matches!(
      &event.kind,
      TrafficEventKind::Finished(finished) if finished.outcome == RequestOutcome::Cancelled
    )
  }));

  drop(client);
  hub.shutdown().await.expect("shut down caller-owned event hub");
  mock.shutdown().await;
}

#[tokio::test]
async fn successful_and_failed_reloads_keep_using_the_same_event_hub() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let (capture, publisher, hub) = event_hub();
  let client = fixture.client(publisher);

  client
    .chat_completions()
    .create_with(
      &chat_request(),
      RequestOptions::default().with_request_id("sdk-before-reload"),
    )
    .await
    .expect("execute before reload");

  client.reload().expect("successful reload");
  client
    .chat_completions()
    .create_with(
      &chat_request(),
      RequestOptions::default().with_request_id("sdk-after-reload"),
    )
    .await
    .expect("execute after reload");

  fs::write(
    &fixture.config_path,
    "schema_version = 2\n[profiles.default]\nroute = \"missing\"\n",
  )
  .expect("replace config with invalid generation");
  assert!(matches!(client.reload(), Err(Error::LoadConfig { .. })));
  client
    .chat_completions()
    .create_with(
      &chat_request(),
      RequestOptions::default().with_request_id("sdk-after-failed-reload"),
    )
    .await
    .expect("previous runtime and publisher survive failed reload");

  capture
    .wait_for_finished(&["sdk-before-reload", "sdk-after-reload", "sdk-after-failed-reload"])
    .await;
  for request_id in ["sdk-before-reload", "sdk-after-reload", "sdk-after-failed-reload"] {
    let events = capture.traffic(request_id);
    assert_contiguous_request_sequence(&events);
    assert!(events
      .iter()
      .any(|event| matches!(&event.kind, TrafficEventKind::Finished(_))));
  }
  let sequences = capture.hub_sequences();
  assert!(sequences.windows(2).all(|window| window[1] == window[0] + 1));
  assert_eq!(mock.requests().len(), 3);

  drop(client);
  hub.shutdown().await.expect("shut down caller-owned event hub");
  mock.shutdown().await;
}

#[tokio::test]
async fn dropping_client_does_not_close_the_caller_owned_hub() {
  let fixture = Fixture::new("http://127.0.0.1:1");
  let (_capture, publisher, hub) = event_hub();
  let client = fixture.client(publisher.clone());

  drop(client);

  assert!(matches!(publisher.status(), HubStatus::Running));
  publisher.flush().await.expect("event hub remains flushable");
  hub.shutdown().await.expect("caller shuts down its event hub");
}

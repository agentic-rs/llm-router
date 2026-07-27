use serde_json::json;
use std::fs;
use tempfile::TempDir;
use tokn_mock_server::{MockLlmConfig, MockLlmServer, MockRoute};
use tokn_sdk::chat_completions::{ChatRequest, ChatResponse};
use tokn_sdk::{Client, Error, RequestOptions};

struct Fixture {
  _root: TempDir,
  config_path: std::path::PathBuf,
  auth_path: std::path::PathBuf,
}

impl Fixture {
  fn new(base_url: &str) -> Self {
    let root = tempfile::tempdir().expect("create SDK fixture directory");
    let config_path = root.path().join("config.toml");
    let auth_path = root.path().join("auth.yaml");
    fs::write(&config_path, "[defaults]\nmode = \"exact\"\n").expect("write SDK config");
    fs::write(
      &auth_path,
      format!("version: 1\naccounts:\n  - id: local\n    provider: llama-cpp\n    base_url: {base_url}\n"),
    )
    .expect("write SDK credentials");
    Self {
      _root: root,
      config_path,
      auth_path,
    }
  }

  fn client(&self) -> Client {
    Client::builder()
      .config_path(&self.config_path)
      .auth_path(&self.auth_path)
      .build()
      .expect("build SDK client")
  }
}

fn chat_request() -> ChatRequest {
  serde_json::from_value(json!({
    "model": "llama-cpp/mock-model",
    "messages": [{"role": "user", "content": "hello"}]
  }))
  .expect("deserialize chat request fixture")
}

#[tokio::test]
async fn typed_request_uses_configured_provider_and_returns_typed_response() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let response = client
    .chat_completions()
    .create_with(
      &chat_request(),
      RequestOptions::default()
        .with_request_id("sdk-buffered")
        .with_session_id("session-1")
        .with_header("x-sdk-test", "buffered"),
    )
    .await
    .expect("execute typed SDK request");

  assert_eq!(response.status, 200);
  assert_eq!(response.data.id.as_deref(), Some("chatcmpl-mock"));
  let captured = mock.last_request().expect("upstream request captured");
  assert_eq!(captured.path, "/chat/completions");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["model"], "mock-model");
  assert_eq!(outbound["stream"], false);

  mock.shutdown().await;
}

#[tokio::test]
async fn raw_request_and_client_lifecycle_use_explicit_paths() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  assert_eq!(client.config_path(), fixture.config_path);
  assert_eq!(client.auth_path(), fixture.auth_path);
  client.reload().expect("reload SDK client");
  let _ = client.responses();
  let _ = client.messages();

  let options = RequestOptions::default()
    .with_profile("default")
    .with_request_id("sdk-raw")
    .with_session_id("session-raw")
    .with_project_id("/tmp/sdk-project")
    .with_initiator("sdk-test")
    .with_header("x-sdk-test", "raw");
  let error = client
    .execute(
      tokn_core::provider::Endpoint::ChatCompletions,
      serde_json::to_value(chat_request()).expect("serialize chat request"),
      options,
    )
    .await
    .expect_err("unknown request profile should fail");
  assert!(matches!(error, Error::UnknownProfile { profile } if profile == "default"));

  mock.shutdown().await;
}

#[tokio::test]
async fn streaming_request_remains_a_live_byte_stream() {
  let mock = MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::chat_completions_stream())).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let response = client
    .chat_completions()
    .stream(&chat_request())
    .await
    .expect("execute streaming SDK request");
  assert_eq!(response.status, 200);
  let body = response.bytes().await.expect("consume SDK stream");
  let body = std::str::from_utf8(&body).expect("stream is UTF-8");
  assert!(body.contains("\"content\":\"hel\""), "{body}");
  assert!(body.contains("data: [DONE]"), "{body}");

  let captured = mock.last_request().expect("upstream request captured");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["stream"], true);

  mock.shutdown().await;
}

#[test]
fn invalid_default_profile_is_rejected_during_construction() {
  let fixture = Fixture::new("http://127.0.0.1:1");
  let error = Client::builder()
    .config_path(&fixture.config_path)
    .auth_path(&fixture.auth_path)
    .profile("missing")
    .build()
    .err()
    .expect("unknown profile should fail");

  assert!(matches!(error, Error::UnknownProfile { profile } if profile == "missing"));
}

#[test]
fn response_types_remain_publicly_deserializable() {
  let response: ChatResponse = serde_json::from_value(json!({
    "id": "chatcmpl-test",
    "choices": []
  }))
  .expect("deserialize public SDK response type");
  assert_eq!(response.id.as_deref(), Some("chatcmpl-test"));
}

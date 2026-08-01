use futures_util::TryStreamExt;
use serde_json::json;
use std::fs;
use tempfile::TempDir;
use tokn_mock_server::{MockEndpoint, MockLlmConfig, MockLlmServer, MockResponse, MockRoute};
use tokn_sdk::chat_completions::{ChatRequest, ChatResponse};
use tokn_sdk::{
  Client, Endpoint, Error, GenerateEvent, GenerateRequest, Message, ReasoningEffort, ReasoningSummary, RequestOptions,
  Tool, ToolCall, ToolChoice,
};

struct Fixture {
  _root: TempDir,
  config_path: std::path::PathBuf,
  auth_path: std::path::PathBuf,
}

impl Fixture {
  fn new(base_url: &str) -> Self {
    Self::with_account(base_url, "llama-cpp", "")
  }

  fn openai(base_url: &str) -> Self {
    Self::with_account(base_url, "openai", "    api_key: test-key\n")
  }

  fn with_account(base_url: &str, provider: &str, credentials: &str) -> Self {
    let root = tempfile::tempdir().expect("create SDK fixture directory");
    let config_path = root.path().join("config.toml");
    let auth_path = root.path().join("auth.yaml");
    fs::write(
      &config_path,
      format!(
        r#"schema_version = 2

[profiles.default]
route = "managed"

[profiles.alternate]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "fixed", upstream = "local" }}
model = {{ kind = "qualified", namespace = "provider" }}
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["{provider}"]

[upstreams.local]
provider = "{provider}"
base_url = "{base_url}"
accounts = ["local"]
"#,
      ),
    )
    .expect("write SDK config");
    fs::write(
      &auth_path,
      format!("version: 1\naccounts:\n  - id: local\n    provider: {provider}\n{credentials}"),
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
  assert_eq!(captured.header("x-session-affinity"), Some("session-1"));
  assert_eq!(captured.header("x-sdk-test"), None);
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["model"], "mock-model");
  assert_eq!(outbound["stream"], false);

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_request_uses_native_responses_provider_when_available() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::openai(mock.base_url());
  let client = fixture.client();

  let response = client
    .generate("openai/gpt-5")
    .prompt("use the native responses endpoint")
    .max_tokens(1024)
    .reasoning_effort(ReasoningEffort::High)
    .reasoning_summary(ReasoningSummary::Auto)
    .tool(
      Tool::function(
        "lookup",
        json!({"type": "object", "properties": {"query": {"type": "string"}}}),
      )
      .description("Look up a value"),
    )
    .tool_choice("lookup")
    .send()
    .await
    .expect("send native Responses request");

  assert_eq!(response.text, "mock response");
  let captured = mock.last_request().expect("upstream request captured");
  assert_eq!(captured.path, "/responses");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["model"], "gpt-5");
  assert_eq!(outbound["input"][0]["role"], "user");
  assert_eq!(outbound["max_output_tokens"], 1024);
  assert_eq!(outbound["reasoning"]["effort"], "high");
  assert_eq!(outbound["reasoning"]["summary"], "auto");
  assert_eq!(outbound["tool_choice"], json!({"type": "function", "name": "lookup"}));

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_reasoning_rejects_known_non_reasoning_model_locally() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::openai(mock.base_url());
  let client = fixture.client();

  let error = client
    .generate("openai/gpt-4o")
    .prompt("Do not send an unsupported reasoning control.")
    .reasoning_effort(ReasoningEffort::High)
    .send()
    .await
    .expect_err("known non-reasoning model should fail locally");

  assert!(
    matches!(error, Error::InvalidGenerateRequest { message } if message.contains("known not to support reasoning"))
  );
  assert!(mock.last_request().is_none());

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_unsupported_top_k_is_an_invalid_request() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::openai(mock.base_url());
  let client = fixture.client();

  let error = client
    .generate("openai/gpt-5")
    .prompt("Do not send unsupported top-k sampling.")
    .top_k(40)
    .send()
    .await
    .expect_err("unsupported top_k should fail locally");

  assert!(matches!(error, Error::InvalidGenerateRequest { message } if message.contains("top_k")));
  assert!(mock.last_request().is_none());

  mock.shutdown().await;
}

#[tokio::test]
async fn detached_generation_request_round_trips_transforms_and_uses_mock_provider() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let request = GenerateRequest::builder("llama-cpp/mock-model")
    .system("Answer briefly.")
    .prompt("hello from a detached request")
    .temperature(0.2)
    .request_id("sdk-detached")
    .build()
    .expect("build detached request");
  let serialized = serde_json::to_string(&request).expect("serialize detached request");
  let request: GenerateRequest = serde_json::from_str(&serialized).expect("deserialize detached request");
  let request = request
    .into_builder()
    .top_k(40)
    .max_output_tokens(64)
    .build()
    .expect("transform detached request");

  let response = client.send(&request).await.expect("send detached request");

  assert_eq!(response.http_status, 200);
  assert_eq!(response.text, "mock response");
  assert_eq!(response.status.as_deref(), Some("completed"));
  assert_eq!(response.finish_reason.as_deref(), Some("stop"));
  let captured = mock.last_request().expect("upstream request captured");
  assert_eq!(captured.path, "/chat/completions");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["model"], "mock-model");
  assert_eq!(
    outbound["messages"][0],
    json!({"role": "system", "content": "Answer briefly."})
  );
  assert_eq!(
    outbound["messages"][1],
    json!({"role": "user", "content": "hello from a detached request"})
  );
  assert_eq!(outbound["temperature"], 0.2);
  assert_eq!(outbound["top_k"], 40);
  assert_eq!(outbound["max_tokens"], 64);
  assert!(!outbound
    .get("stream")
    .and_then(serde_json::Value::as_bool)
    .unwrap_or(false));

  mock.shutdown().await;
}

#[tokio::test]
async fn detached_request_preserves_assistant_tool_call_history() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let request = GenerateRequest::builder("llama-cpp/mock-model")
    .prompt("look up rust")
    .message(Message::assistant_with_tool_calls(
      "",
      [ToolCall::new("lookup", json!({"query": "rust"})).id("call_1")],
    ))
    .tool_result("call_1", "Rust is a systems language.")
    .build()
    .expect("build tool follow-up request");

  client.send(&request).await.expect("send tool follow-up request");

  let captured = mock.last_request().expect("upstream request captured");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(
    outbound["messages"][0],
    json!({"role": "user", "content": "look up rust"})
  );
  assert_eq!(outbound["messages"][1]["role"], "assistant");
  assert_eq!(outbound["messages"][1]["tool_calls"][0]["id"], "call_1");
  assert_eq!(outbound["messages"][1]["tool_calls"][0]["function"]["name"], "lookup");
  assert_eq!(
    outbound["messages"][1]["tool_calls"][0]["function"]["arguments"],
    r#"{"query":"rust"}"#
  );
  assert_eq!(
    outbound["messages"][2],
    json!({
      "role": "tool",
      "content": "Rust is a systems language.",
      "tool_call_id": "call_1"
    })
  );

  mock.shutdown().await;
}

#[tokio::test]
async fn client_bound_generation_builder_uses_same_owned_request_model() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let response = client
    .generate("llama-cpp/mock-model")
    .prompt("hello from a bound request")
    .tool(
      Tool::function(
        "lookup",
        json!({
          "type": "object",
          "properties": {"query": {"type": "string"}},
          "required": ["query"]
        }),
      )
      .description("Look up a value")
      .strict(true),
    )
    .tool_choice(ToolChoice::named("lookup"))
    .send()
    .await
    .expect("send client-bound request");

  assert_eq!(response.text, "mock response");
  let captured = mock.last_request().expect("upstream request captured");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["messages"][0]["content"], "hello from a bound request");
  assert_eq!(outbound["tools"][0]["type"], "function");
  assert_eq!(outbound["tools"][0]["function"]["name"], "lookup");
  assert_eq!(outbound["tools"][0]["function"]["description"], "Look up a value");
  assert_eq!(outbound["tools"][0]["function"]["strict"], true);
  assert_eq!(
    outbound["tool_choice"],
    json!({"type": "function", "function": {"name": "lookup"}})
  );

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_response_normalizes_reasoning_tools_and_usage_from_mock_provider() {
  let mock = MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::new(
    MockEndpoint::ChatCompletions,
    MockResponse::json(json!({
      "id": "chatcmpl-friendly",
      "model": "mock-model",
      "choices": [{
        "index": 0,
        "message": {
          "role": "assistant",
          "content": "mock answer",
          "reasoning_content": "mock reasoning",
          "tool_calls": [{
            "id": "call_1",
            "type": "function",
            "function": {"name": "lookup", "arguments": "{\"query\":\"rust\"}"}
          }]
        },
        "finish_reason": "tool_calls"
      }],
      "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8}
    })),
  )))
  .await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let response = client
    .generate("llama-cpp/mock-model")
    .prompt("use a tool")
    .send()
    .await
    .expect("send generation request");

  assert_eq!(response.text, "mock answer");
  assert_eq!(response.reasoning.as_deref(), Some("mock reasoning"));
  assert_eq!(response.tool_calls.len(), 1);
  assert_eq!(response.tool_calls[0].id.as_deref(), Some("call_1"));
  assert_eq!(response.tool_calls[0].name, "lookup");
  assert_eq!(response.tool_calls[0].arguments, json!({"query": "rust"}));
  assert_eq!(response.finish_reason.as_deref(), Some("tool_calls"));
  let usage = response.usage.expect("normalized usage");
  assert_eq!(usage.input_tokens, Some(3));
  assert_eq!(usage.output_tokens, Some(5));
  assert_eq!(usage.total_tokens, Some(8));

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_response_preserves_length_finish_reason() {
  let mock = MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::new(
    MockEndpoint::ChatCompletions,
    MockResponse::json(json!({
      "id": "chatcmpl-length",
      "model": "mock-model",
      "choices": [{
        "index": 0,
        "message": {"role": "assistant", "content": "partial"},
        "finish_reason": "length"
      }]
    })),
  )))
  .await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let response = client
    .generate("llama-cpp/mock-model")
    .prompt("write a long answer")
    .send()
    .await
    .expect("send generation request");

  assert_eq!(response.text, "partial");
  assert_eq!(response.status.as_deref(), Some("incomplete"));
  assert_eq!(response.finish_reason.as_deref(), Some("length"));
  assert_eq!(response.raw["incomplete_details"]["reason"], "max_output_tokens");

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_request_turns_non_success_status_into_sdk_error() {
  let mut failure = MockResponse::json(json!({"error": {"message": "mock failure"}}));
  failure.status = "502".parse().expect("valid mock status");
  let mock =
    MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::new(MockEndpoint::ChatCompletions, failure)))
      .await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let error = client
    .generate("llama-cpp/mock-model")
    .prompt("fail this request")
    .send()
    .await
    .expect_err("non-success status should fail");

  assert!(matches!(
    error,
    Error::GenerateResponseStatus { status: 502, body } if body.contains("mock failure")
  ));

  mock.shutdown().await;
}

#[tokio::test]
async fn detached_request_can_bind_to_client_before_execution() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let request = GenerateRequest::builder("llama-cpp/mock-model")
    .prompt("bind this request")
    .build()
    .expect("build detached request");
  let response = request
    .bind(&client)
    .send()
    .await
    .expect("send explicitly bound request");

  assert_eq!(response.text, "mock response");
  assert_eq!(
    mock.last_request().expect("upstream request captured").path,
    "/chat/completions"
  );

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_text_stream_parses_mock_provider_sse() {
  let mock = MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::chat_completions_stream())).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let text: Vec<String> = client
    .generate("llama-cpp/mock-model")
    .prompt("stream this request")
    .stream_text()
    .await
    .expect("start text stream")
    .try_collect()
    .await
    .expect("collect text stream");

  assert_eq!(text, vec!["hel", "lo"]);
  let captured = mock.last_request().expect("upstream request captured");
  assert_eq!(captured.path, "/chat/completions");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["stream"], true);

  mock.shutdown().await;
}

#[tokio::test]
async fn friendly_stream_preserves_tool_call_identity_and_finish_reason() {
  let mock = MockLlmServer::start(
    MockLlmConfig::default().with_route(MockRoute::new(
      MockEndpoint::ChatCompletions,
      MockResponse::sse_data([
        json!({
          "id": "chatcmpl-tool-stream",
          "model": "mock-model",
          "choices": [{
            "index": 0,
            "delta": {
              "role": "assistant",
              "tool_calls": [{
                "index": 0,
                "id": "call_stream",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{\"query\":"}
              }]
            },
            "finish_reason": null
          }]
        })
        .to_string(),
        json!({
          "id": "chatcmpl-tool-stream",
          "model": "mock-model",
          "choices": [{
            "index": 0,
            "delta": {
              "tool_calls": [{
                "index": 0,
                "function": {"arguments": "\"rust\"}"}
              }]
            },
            "finish_reason": null
          }]
        })
        .to_string(),
        json!({
          "id": "chatcmpl-tool-stream",
          "model": "mock-model",
          "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]
        })
        .to_string(),
        "[DONE]".into(),
      ]),
    )),
  )
  .await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  let events: Vec<GenerateEvent> = client
    .generate("llama-cpp/mock-model")
    .prompt("use a tool")
    .stream()
    .await
    .expect("start semantic stream")
    .try_collect()
    .await
    .expect("collect semantic stream");

  let tool_events: Vec<_> = events
    .iter()
    .filter_map(|event| match event {
      GenerateEvent::ToolCallDelta {
        id,
        name,
        arguments_delta,
        ..
      } => Some((id.as_deref(), name.as_deref(), arguments_delta.as_str())),
      _ => None,
    })
    .collect();
  assert!(!tool_events.is_empty());
  assert!(tool_events
    .iter()
    .all(|(id, name, _)| *id == Some("call_stream") && *name == Some("lookup")));
  assert_eq!(
    tool_events.iter().map(|(_, _, delta)| *delta).collect::<String>(),
    r#"{"query":"rust"}"#
  );
  assert!(events.iter().any(|event| {
    matches!(
      event,
      GenerateEvent::Completed {
        finish_reason: Some(reason)
      } if reason == "tool_calls"
    )
  }));

  mock.shutdown().await;
}

#[tokio::test]
async fn raw_request_and_client_lifecycle_use_explicit_paths() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();

  assert_eq!(client.config_path(), fixture.config_path);
  assert_eq!(client.auth_path(), fixture.auth_path);
  assert_eq!(client.profile(), "default");
  client.reload().expect("reload SDK client");
  let _ = client.responses();
  let _ = client.messages();

  let options = RequestOptions::default()
    .with_request_id("sdk-raw")
    .with_session_id("session-raw")
    .with_project_id("/tmp/sdk-project")
    .with_initiator("agent")
    .with_header("x-sdk-test", "raw");
  let response = client
    .execute(
      Endpoint::ChatCompletions,
      serde_json::to_value(chat_request()).expect("serialize chat request"),
      options,
    )
    .await
    .expect("execute raw request through the bound default profile");
  assert_eq!(response.status, 200);
  let captured = mock.last_request().expect("upstream request captured");
  assert_eq!(captured.path, "/chat/completions");
  assert_eq!(captured.header("x-session-affinity"), Some("session-raw"));
  assert_eq!(captured.header("x-sdk-test"), None);

  mock.shutdown().await;
}

#[tokio::test]
async fn failed_reload_keeps_the_previous_runtime_snapshot() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = fixture.client();
  fs::write(
    &fixture.config_path,
    "schema_version = 2\n[profiles.default]\nroute = \"missing\"\n",
  )
  .expect("replace config with an invalid generation");

  assert!(matches!(client.reload(), Err(Error::LoadConfig { .. })));
  let response = client
    .chat_completions()
    .create(&chat_request())
    .await
    .expect("previous runtime remains usable after failed reload");
  assert_eq!(response.status, 200);
  assert_eq!(mock.requests().len(), 1);

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
fn missing_builder_bound_profile_is_rejected_during_construction() {
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

#[tokio::test]
async fn explicit_alternate_profile_executes_the_same_managed_route() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let fixture = Fixture::new(mock.base_url());
  let client = Client::builder()
    .config_path(&fixture.config_path)
    .auth_path(&fixture.auth_path)
    .profile("alternate")
    .build()
    .expect("build alternate-profile SDK client");

  assert_eq!(client.profile(), "alternate");
  let response = client
    .chat_completions()
    .create(&chat_request())
    .await
    .expect("execute through alternate profile");
  assert_eq!(response.status, 200);
  let captured = mock.last_request().expect("upstream request captured");
  let outbound: serde_json::Value = serde_json::from_slice(&captured.body).expect("parse upstream body");
  assert_eq!(outbound["model"], "mock-model");

  mock.shutdown().await;
}

#[test]
fn legacy_config_is_rejected_instead_of_implicitly_migrated() {
  let fixture = Fixture::new("http://127.0.0.1:1");
  fs::write(&fixture.config_path, "[defaults]\nmode = \"exact\"\n").expect("replace fixture with legacy config");

  let error = Client::builder()
    .config_path(&fixture.config_path)
    .auth_path(&fixture.auth_path)
    .build()
    .err()
    .expect("legacy config should fail strict v2 loading");

  assert!(matches!(error, Error::LoadConfig { .. }));
}

#[test]
fn non_managed_profile_is_rejected_during_construction() {
  let fixture = Fixture::new("http://127.0.0.1:1");
  fs::write(
    &fixture.config_path,
    r#"schema_version = 2

[profiles.default]
route = "relay"

[routes.relay]
kind = "relay"
target = { kind = "fixed_upstream", upstream = "local", account_pool = "default" }

[account_pools.default]
active_accounts = ["*"]
providers = ["llama-cpp"]

[upstreams.local]
provider = "llama-cpp"
base_url = "http://127.0.0.1:1"
accounts = ["local"]
"#,
  )
  .expect("write relay config");

  let error = Client::builder()
    .config_path(&fixture.config_path)
    .auth_path(&fixture.auth_path)
    .build()
    .err()
    .expect("relay profile should fail embedded SDK construction");

  assert!(matches!(
    error,
    Error::NonManagedProfile { profile, route, .. } if profile == "default" && route == "relay"
  ));
}

#[tokio::test]
async fn invalid_request_header_is_rejected_before_transport() {
  let fixture = Fixture::new("http://127.0.0.1:1");
  let client = fixture.client();

  let error = client
    .execute(
      Endpoint::ChatCompletions,
      serde_json::to_value(chat_request()).expect("serialize chat request"),
      RequestOptions::default().with_header("invalid header", "value"),
    )
    .await
    .expect_err("invalid header name should fail locally");

  assert!(matches!(error, Error::InvalidHeaderName { name, .. } if name == "invalid header"));
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

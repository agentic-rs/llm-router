use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use tokn_accounts::link::{
  build_account_pool_runtimes, link_account_pools, link_provider_graph, link_routes, resolve_managed_target,
  LinkedRouteKind, SelectionOutcome, TargetResolution,
};
use tokn_accounts::registry::Registry;
use tokn_core::account::{AccountConfig, Secret};
use tokn_core::provider::{Endpoint, ID_CODEX, ID_LLAMA_CPP};
use tokn_core::util::http::{build_managed_client, HttpClientOptions};
use tokn_headers::HeaderMap;
use tokn_mock_server::{MockAuthConfig, MockEndpoint, MockLlmConfig, MockLlmServer, MockResponse, MockRoute};
use tokn_requests::execution::{
  ManagedClientBody, ManagedExecutionTarget, ManagedHttpAttempt, ManagedHttpExecutor, ManagedResponseAdapter,
};
use tokn_requests::utils::codec::{decode_body_bytes, encode_body_bytes, ContentEncodingKind};

const REQUESTED_MODEL: &str = "client-alias";
const UPSTREAM_MODEL: &str = "selected-backend-model";
const CODEX_MODEL: &str = "gpt-5.3-codex";

#[tokio::test]
async fn managed_executor_uses_the_exact_v2_selected_target_and_reencodes_conversion() {
  let selected_server = MockLlmServer::start(
    MockLlmConfig {
      routes: vec![MockRoute::chat_completions()],
      ..Default::default()
    }
    .with_auth(MockAuthConfig::bearer(["selected-key"])),
  )
  .await;
  let decoy_server = MockLlmServer::start(
    MockLlmConfig {
      routes: vec![MockRoute::chat_completions()],
      ..Default::default()
    }
    .with_auth(MockAuthConfig::bearer(["decoy-key"])),
  )
  .await;

  let config = format!(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "default" }}

[profiles.default]
route = "default"

[routes.default]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "any" }}
model = {{ kind = "fallback", selector = {{ kind = "fixed", group = "fixture" }} }}
operation = "translate_compatible"

[account_pools.default]
accounts = ["*"]
providers = ["*"]
strategy = "round_robin"

[upstreams.decoy]
provider = "llama-cpp"
base_url = "{}"
accounts = ["decoy-account"]

[upstreams.selected]
provider = "llama-cpp"
base_url = "{}"
accounts = ["selected-account"]

[[model_groups.fixture]]
model = "{UPSTREAM_MODEL}"
upstream = "selected"
"#,
    decoy_server.base_url(),
    selected_server.base_url(),
  );
  let plan = tokn_config::v2::parse(&config, Path::new("managed-execution.toml")).unwrap();
  let accounts = [
    llama_account("decoy-account", "decoy-key"),
    llama_account("selected-account", "selected-key"),
  ];
  let registry = Registry::builtin();
  let providers = link_provider_graph(&plan, &accounts, &registry).unwrap();
  let pools = link_account_pools(&plan, &providers, &registry).unwrap();
  let runtimes = build_account_pool_runtimes(&pools);
  let reachable = plan.routes().keys().cloned().collect::<BTreeSet<_>>();
  let linked_routes = link_routes(&plan, &reachable, &providers, &runtimes).unwrap();
  let (_, linked_route) = linked_routes.routes().next().expect("one linked route");
  let LinkedRouteKind::Managed(managed_route) = linked_route.kind() else {
    panic!("expected a managed route");
  };
  let selected =
    match resolve_managed_target(managed_route, REQUESTED_MODEL, Endpoint::Responses, None, |_| true).unwrap() {
      TargetResolution::Selected(selected) => selected,
      other => panic!("expected a selected managed target, got {other:?}"),
    };

  assert_eq!(selected.binding().upstream_id().as_str(), "selected");
  assert_eq!(selected.binding().account_id(), "selected-account");
  assert_eq!(selected.model(), UPSTREAM_MODEL);
  assert_eq!(selected.operation(), Endpoint::ChatCompletions);

  let inbound_json = json!({
    "model": REQUESTED_MODEL,
    "input": [{
      "role": "user",
      "content": [{"type": "input_text", "text": "hello from responses"}]
    }],
    "stream": false
  });
  let inbound_json_bytes = serde_json::to_vec(&inbound_json).unwrap();
  let inbound_body = encode_body_bytes(&inbound_json_bytes, Some(ContentEncodingKind::Gzip)).unwrap();
  let mut inbound_headers = HeaderMap::new();
  inbound_headers.insert("content-type", "application/json");
  inbound_headers.insert("content-encoding", "gzip");

  let target = ManagedExecutionTarget::new(REQUESTED_MODEL, Endpoint::Responses, &selected, None);
  let attempt = ManagedHttpAttempt::new(target, &inbound_headers, &inbound_body);
  let http = build_managed_client(&HttpClientOptions::default()).unwrap();
  let result = ManagedHttpExecutor::new(http).execute(attempt).await.unwrap();

  assert_eq!(result.response().status(), reqwest::StatusCode::OK);
  assert_eq!(result.selection_outcome(), SelectionOutcome::Healthy);
  assert_eq!(result.metadata().requested_operation(), Endpoint::Responses);
  assert_eq!(result.metadata().upstream_operation(), Endpoint::ChatCompletions);
  assert!(!result.metadata().requested_stream());
  assert!(!result.metadata().upstream_stream());

  let (response, metadata) = result.into_parts();
  assert_eq!(metadata.upstream_operation(), Endpoint::ChatCompletions);
  let response_body = response.bytes().await.unwrap();
  let response_json: Value = serde_json::from_slice(&response_body).unwrap();
  assert_eq!(response_json["id"], "chatcmpl-mock");
  assert!(response_json.get("choices").is_some());
  assert!(response_json.get("output").is_none());

  let selected_requests = selected_server.requests();
  assert_eq!(selected_requests.len(), 1);
  let captured = &selected_requests[0];
  assert_eq!(captured.method, reqwest::Method::POST);
  assert_eq!(captured.path, "/chat/completions");
  assert_eq!(captured.header("authorization"), Some("Bearer selected-key"));
  assert_eq!(captured.header("content-encoding"), Some("gzip"));
  assert_ne!(captured.body, inbound_body);

  let decoded = decode_body_bytes(captured.body.clone(), Some(ContentEncodingKind::Gzip)).unwrap();
  let upstream_json: Value = serde_json::from_slice(&decoded).unwrap();
  assert_eq!(upstream_json["model"], UPSTREAM_MODEL);
  assert_eq!(upstream_json["messages"][0]["role"], "user");
  assert_eq!(upstream_json["messages"][0]["content"], "hello from responses");
  assert!(upstream_json.get("input").is_none());

  assert!(decoy_server.requests().is_empty());
}

#[tokio::test]
async fn managed_executor_buffers_codex_sse_without_a_wire_identity() {
  let server = MockLlmServer::start(
    MockLlmConfig {
      routes: vec![MockRoute::new(
        MockEndpoint::Responses,
        MockResponse::sse_data([
          json!({
            "type": "response.output_text.delta",
            "response_id": "resp-codex",
            "output_index": 0,
            "content_index": 0,
            "delta": "hello from codex"
          })
          .to_string(),
          json!({
            "type": "response.completed",
            "response": {
              "id": "resp-codex",
              "object": "response",
              "status": "completed",
              "model": CODEX_MODEL,
              "output": [],
              "usage": {
                "input_tokens": 3,
                "output_tokens": 3,
                "total_tokens": 6
              }
            }
          })
          .to_string(),
          "[DONE]".to_string(),
        ]),
      )],
      ..Default::default()
    }
    .with_auth(MockAuthConfig::bearer(["codex-token"])),
  )
  .await;

  let config = format!(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "default" }}

[profiles.default]
route = "default"
wire_identity = "none"

[routes.default]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "fixed", upstream = "codex" }}
model = {{ kind = "capability" }}
operation = "preserve"

[account_pools.default]
accounts = ["codex-account"]
providers = ["codex"]
strategy = "round_robin"

[upstreams.codex]
provider = "codex"
base_url = "{}"
accounts = ["codex-account"]
"#,
    server.base_url(),
  );
  let plan = tokn_config::v2::parse(&config, Path::new("managed-codex-execution.toml")).unwrap();
  let accounts = [codex_account("codex-account", "codex-token", "codex-provider-account")];
  let registry = Registry::builtin();
  let providers = link_provider_graph(&plan, &accounts, &registry).unwrap();
  let pools = link_account_pools(&plan, &providers, &registry).unwrap();
  let runtimes = build_account_pool_runtimes(&pools);
  let reachable = plan.routes().keys().cloned().collect::<BTreeSet<_>>();
  let linked_routes = link_routes(&plan, &reachable, &providers, &runtimes).unwrap();
  let (_, linked_route) = linked_routes.routes().next().expect("one linked route");
  let LinkedRouteKind::Managed(managed_route) = linked_route.kind() else {
    panic!("expected a managed route");
  };
  let selected = match resolve_managed_target(managed_route, CODEX_MODEL, Endpoint::Responses, None, |_| true).unwrap()
  {
    TargetResolution::Selected(selected) => selected,
    other => panic!("expected a selected managed target, got {other:?}"),
  };

  assert_eq!(selected.binding().upstream_id().as_str(), "codex");
  assert_eq!(selected.binding().account_id(), "codex-account");
  assert_eq!(selected.model(), CODEX_MODEL);
  assert_eq!(selected.operation(), Endpoint::Responses);

  let inbound_json = json!({
    "model": CODEX_MODEL,
    "input": "hello",
    "stream": false
  });
  let inbound_body = serde_json::to_vec(&inbound_json).unwrap().into();
  let mut inbound_headers = HeaderMap::new();
  inbound_headers.insert("content-type", "application/json");
  inbound_headers.insert("originator", "client-originator");
  inbound_headers.insert("version", "client-version");
  inbound_headers.insert("user-agent", "client-agent/1.0");
  inbound_headers.insert("session_id", "client-session");
  inbound_headers.insert("x-codex-turn-metadata", r#"{"cwd":"/client"}"#);

  let target = ManagedExecutionTarget::new(CODEX_MODEL, Endpoint::Responses, &selected, None);
  assert!(target.wire_identity().is_none());
  let attempt = ManagedHttpAttempt::new(target, &inbound_headers, &inbound_body);
  let http = build_managed_client(&HttpClientOptions::default()).unwrap();
  let result = ManagedHttpExecutor::new(http).execute(attempt).await.unwrap();

  assert_eq!(result.response().status(), reqwest::StatusCode::OK);
  assert_eq!(result.selection_outcome(), SelectionOutcome::Healthy);
  assert_eq!(result.metadata().requested_operation(), Endpoint::Responses);
  assert_eq!(result.metadata().upstream_operation(), Endpoint::Responses);
  assert!(!result.metadata().requested_stream());
  assert!(result.metadata().upstream_stream());

  let captured_requests = server.requests();
  assert_eq!(captured_requests.len(), 1);
  let captured = &captured_requests[0];
  assert_eq!(captured.method, reqwest::Method::POST);
  assert_eq!(captured.path, "/responses");
  assert_eq!(captured.header("authorization"), Some("Bearer codex-token"));
  assert_eq!(captured.header("chatgpt-account-id"), Some("codex-provider-account"));
  assert_eq!(captured.header("accept"), Some("text/event-stream"));
  assert_eq!(captured.header("content-type"), Some("application/json"));
  assert_eq!(captured.header("openai-beta"), Some("responses=experimental"));
  for persona_header in [
    "originator",
    "version",
    "user-agent",
    "session_id",
    "x-codex-turn-metadata",
  ] {
    assert!(captured.header(persona_header).is_none(), "unexpected {persona_header}");
  }

  let upstream_json: Value = serde_json::from_slice(&captured.body).unwrap();
  assert_eq!(upstream_json["model"], CODEX_MODEL);
  assert_eq!(upstream_json["input"][0]["role"], "user");
  assert_eq!(upstream_json["input"][0]["content"][0]["text"], "hello");
  assert_eq!(upstream_json["instructions"], "");
  assert_eq!(upstream_json["store"], false);
  assert_eq!(upstream_json["stream"], true);

  let adapted = ManagedResponseAdapter::new().adapt(result).await.unwrap();
  let (status, headers, body) = adapted.into_parts();
  assert_eq!(status, reqwest::StatusCode::OK);
  assert_eq!(headers.get("content-type").unwrap(), "application/json");
  let ManagedClientBody::Buffered(body) = body else {
    panic!("expected a buffered client response");
  };
  let response_json: Value = serde_json::from_slice(&body).unwrap();
  assert_eq!(response_json["object"], "response");
  assert_eq!(response_json["status"], "completed");
  assert_eq!(response_json["output_text"], "hello from codex");
}

fn llama_account(id: &str, api_key: &str) -> AccountConfig {
  AccountConfig {
    id: id.to_string(),
    provider: ID_LLAMA_CPP.to_string(),
    enabled: true,
    tier: Default::default(),
    tags: Vec::new(),
    label: None,
    // V2 upstreams are authoritative; a legacy constructor must not use this.
    base_url: Some("not a valid legacy account URL".into()),
    headers: Default::default(),
    auth_type: None,
    username: None,
    api_key: Some(Secret::new(api_key.to_string())),
    api_key_expires_at: None,
    access_token: None,
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: Default::default(),
  }
}

fn codex_account(id: &str, access_token: &str, provider_account_id: &str) -> AccountConfig {
  AccountConfig {
    id: id.to_string(),
    provider: ID_CODEX.to_string(),
    enabled: true,
    tier: Default::default(),
    tags: Vec::new(),
    label: None,
    // V2 upstreams are authoritative; a legacy constructor must not use this.
    base_url: Some("not a valid legacy account URL".into()),
    headers: Default::default(),
    auth_type: None,
    username: None,
    api_key: None,
    api_key_expires_at: None,
    access_token: Some(Secret::new(access_token.to_string())),
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: Some(provider_account_id.to_string()),
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: Default::default(),
  }
}

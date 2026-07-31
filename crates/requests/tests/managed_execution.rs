use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;
use tokn_accounts::link::{
  build_account_pool_runtimes, link_account_pools, link_provider_graph, link_routes, resolve_managed_target,
  LinkedRouteKind, SelectionOutcome, TargetResolution,
};
use tokn_accounts::registry::Registry;
use tokn_core::account::{AccountConfig, Secret};
use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
use tokn_core::util::http::{build_managed_client, HttpClientOptions};
use tokn_headers::HeaderMap;
use tokn_mock_server::{MockAuthConfig, MockLlmConfig, MockLlmServer, MockRoute};
use tokn_requests::execution::{ManagedExecutionTarget, ManagedHttpAttempt, ManagedHttpExecutor};
use tokn_requests::utils::codec::{decode_body_bytes, encode_body_bytes, ContentEncodingKind};

const REQUESTED_MODEL: &str = "client-alias";
const UPSTREAM_MODEL: &str = "selected-backend-model";

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

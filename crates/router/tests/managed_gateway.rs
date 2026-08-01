use http::header::{HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH};
use http::HeaderMap;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use tokn_access::ProviderAccess;
use tokn_accounts::link::NoEligibleReason;
use tokn_core::account::{AccountConfig, Secret};
use tokn_core::generation::GenerationOptions;
use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
use tokn_core::util::http::HttpClientOptions;
use tokn_mock_server::{MockAuthConfig, MockLlmConfig, MockLlmServer, MockRoute};
use tokn_policy::ProfileId;
use tokn_requests::execution::ManagedClientBody;
use tokn_router::runtime::{
  link_builtin_gateway_runtime_with_profile_roots, EmbeddedProfileRoots, ManagedGatewayError, ManagedGatewayExecutor,
  ManagedGatewayOutcome, ManagedGatewayRequest, ManagedRequestBodyError,
};

const PROFILE: &str = "embedded";
const REQUESTED_MODEL: &str = "client-alias";
const UPSTREAM_MODEL: &str = "selected-backend-model";

#[tokio::test]
async fn embedded_gateway_executes_one_v2_profile_without_a_listener() {
  let server = MockLlmServer::start(
    MockLlmConfig {
      routes: vec![MockRoute::chat_completions()],
      ..Default::default()
    }
    .with_auth(MockAuthConfig::bearer(["selected-key"])),
  )
  .await;
  let (profile, runtime) = runtime(server.base_url());
  assert!(runtime.listeners().is_empty());
  let gateway = ManagedGatewayExecutor::build(runtime, &HttpClientOptions::default()).unwrap();
  let mut headers = HeaderMap::new();
  headers.insert("x-session-id", HeaderValue::from_static("stale-header-session"));
  headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("999"));
  let request = ManagedGatewayRequest::new(
    Endpoint::Responses,
    json!({
      "model": REQUESTED_MODEL,
      "input": [{
        "role": "user",
        "content": [{"type": "input_text", "text": "hello from embedded"}]
      }],
      "stream": false
    }),
  )
  .with_headers(headers)
  .with_session_id("explicit-session")
  .with_generation_options(GenerationOptions::new().with_top_k(40));

  let outcome = gateway.execute(&profile, request).await.unwrap();
  let ManagedGatewayOutcome::Response {
    site,
    selection,
    response,
  } = outcome
  else {
    panic!("expected one managed response")
  };
  assert_eq!(site.profile_id(), &profile);
  assert_eq!(site.route_id().as_str(), "managed");
  assert_eq!(selection.account_id(), "selected-account");
  assert_eq!(selection.provider_id().as_str(), ID_LLAMA_CPP);
  assert_eq!(selection.upstream_id().as_str(), "selected");
  assert_eq!(selection.requested_model(), REQUESTED_MODEL);
  assert_eq!(selection.upstream_model(), UPSTREAM_MODEL);
  assert_eq!(selection.requested_operation(), Endpoint::Responses);
  assert_eq!(selection.upstream_operation(), Endpoint::ChatCompletions);

  let (status, _, body) = response.into_parts();
  assert_eq!(status, http::StatusCode::OK);
  let ManagedClientBody::Buffered(body) = body else {
    panic!("expected a buffered converted response")
  };
  let response_json: Value = serde_json::from_slice(&body).unwrap();
  assert_eq!(response_json["object"], "response");
  assert!(response_json["output"].is_array());

  let requests = server.requests();
  assert_eq!(requests.len(), 1);
  let captured = &requests[0];
  assert_eq!(captured.path, "/chat/completions");
  assert_eq!(captured.header("authorization"), Some("Bearer selected-key"));
  assert_eq!(captured.header("x-session-affinity"), Some("explicit-session"));
  assert_eq!(captured.header("content-encoding"), None);
  let upstream_json: Value = serde_json::from_slice(&captured.body).unwrap();
  assert_eq!(upstream_json["model"], UPSTREAM_MODEL);
  assert_eq!(upstream_json["messages"][0]["content"], "hello from embedded");
  assert_eq!(upstream_json["top_k"], 40);
  assert!(upstream_json.get("input").is_none());
}

#[tokio::test]
async fn embedded_gateway_keeps_lookup_validation_and_eligibility_distinct() {
  let (profile, runtime) = runtime("http://127.0.0.1:9");
  let gateway = ManagedGatewayExecutor::build(runtime, &HttpClientOptions::default()).unwrap();

  let unknown = ProfileId::new("unknown").unwrap();
  let error = gateway
    .execute(
      &unknown,
      ManagedGatewayRequest::new(Endpoint::Responses, json!({"model": REQUESTED_MODEL})),
    )
    .await
    .unwrap_err();
  assert!(matches!(
    error,
    ManagedGatewayError::ProfileNotLinked { profile: actual } if actual == unknown
  ));

  let error = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(Endpoint::Responses, json!({"model": " "})),
    )
    .await
    .unwrap_err();
  assert!(matches!(
    error,
    ManagedGatewayError::InvalidBody {
      site,
      source: ManagedRequestBodyError::ModelEmpty,
    } if site.profile_id() == &profile
  ));

  let denied = ProviderAccess::from_provider_ids(vec!["openai".to_owned()]).unwrap();
  let outcome = gateway
    .execute(
      &profile,
      ManagedGatewayRequest::new(Endpoint::Responses, json!({"model": REQUESTED_MODEL})).with_provider_access(denied),
    )
    .await
    .unwrap();
  assert!(matches!(
    outcome,
    ManagedGatewayOutcome::NoEligible {
      site,
      reason: NoEligibleReason::ProviderAccessDenied,
    } if site.profile_id() == &profile
  ));
}

fn runtime(base_url: &str) -> (ProfileId, Arc<tokn_router::runtime::LinkedGatewayRuntime>) {
  let config = format!(
    r#"
schema_version = 2

[profiles.{PROFILE}]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "fixed", upstream = "selected" }}
model = {{ kind = "fallback", selector = {{ kind = "fixed", group = "fixture" }} }}
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["*"]
strategy = "round_robin"

[upstreams.selected]
provider = "llama-cpp"
base_url = "{base_url}"
accounts = ["selected-account"]

[[model_groups.fixture]]
model = "{UPSTREAM_MODEL}"
upstream = "selected"
"#,
  );
  let compiled = tokn_config::v2::parse(&config, Path::new("embedded-managed.toml")).unwrap();
  let profile = ProfileId::new(PROFILE).unwrap();
  let runtime = link_builtin_gateway_runtime_with_profile_roots(
    compiled.gateway(),
    &[llama_account("selected-account", "selected-key")],
    &EmbeddedProfileRoots::one(profile.clone()),
  )
  .unwrap();
  (profile, Arc::new(runtime))
}

fn llama_account(id: &str, api_key: &str) -> AccountConfig {
  AccountConfig {
    id: id.to_owned(),
    provider: ID_LLAMA_CPP.to_owned(),
    enabled: true,
    tier: Default::default(),
    tags: Vec::new(),
    label: None,
    base_url: None,
    headers: Default::default(),
    auth_type: None,
    username: None,
    api_key: Some(Secret::new(api_key.to_owned())),
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

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, Uri};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use std::path::Path;
use std::sync::Arc;
use tokn_access::AccessStore;
use tokn_core::account::{AccountConfig, AccountTier, AuthType, Secret};
use tokn_core::event::EventBus;
use tower::ServiceExt;

struct CapturedRequest {
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
}

#[tokio::test]
async fn v2_listener_selects_managed_and_relay_six_stage_pipelines() {
  let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(2);
  let upstream = Router::new()
    .route(
      "/{*path}",
      any(
        |State(capture_tx): State<tokio::sync::mpsc::Sender<CapturedRequest>>,
         uri: Uri,
         headers: HeaderMap,
         body: Bytes| async move {
          let is_responses = uri.path().ends_with("/responses");
          capture_tx.send(CapturedRequest { uri, headers, body }).await.unwrap();
          if is_responses {
            Response::builder()
              .header("content-type", "application/json")
              .body(Body::from(r#"{"relay":"unchanged"}"#))
              .unwrap()
          } else {
            Response::builder()
              .header("content-type", "application/json")
              .body(Body::from(
                r#"{"id":"chatcmpl-v2","choices":[{"message":{"role":"assistant","content":"hello"}}]}"#,
              ))
              .unwrap()
          }
        },
      ),
    )
    .with_state(capture_tx);
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let upstream_addr = listener.local_addr().unwrap();
  let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

  let config = format!(
    r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "managed" }}

[[bindings]]
id = "relay-responses"
listener = "api"
action = {{ kind = "route", profile = "relay" }}
operations = ["responses"]

[profiles.managed]
route = "managed"

[profiles.relay]
route = "relay"

[routes.managed]
kind = "managed"
account_pool = "primary"
upstream = {{ kind = "fixed", upstream = "local" }}
model = {{ kind = "capability" }}
operation = "preserve"

[routes.relay]
kind = "relay"
target = {{ kind = "fixed_upstream", upstream = "local", account_pool = "primary" }}

[account_pools.primary]
accounts = ["acct"]
providers = ["openai"]

[upstreams.local]
provider = "openai"
accounts = ["acct"]
base_url = "http://{upstream_addr}/v1"
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-test.toml")).unwrap();
  let states = tokn_router::v2::build_states(
    plan,
    &[account()],
    Arc::new(AccessStore::disabled()),
    Arc::new(EventBus::noop()),
  )
  .unwrap();
  let app = tokn_router::v2::router(states.into_iter().next().unwrap());

  let managed_body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
  let managed = app
    .clone()
    .oneshot(
      Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(managed_body.as_slice()))
        .unwrap(),
    )
    .await
    .unwrap();
  let managed_status = managed.status();
  let managed_response = to_bytes(managed.into_body(), usize::MAX).await.unwrap();
  assert_eq!(
    managed_status,
    StatusCode::OK,
    "managed response: {}",
    String::from_utf8_lossy(&managed_response)
  );
  assert_eq!(
    serde_json::from_slice::<serde_json::Value>(&managed_response).unwrap()["id"],
    "chatcmpl-v2"
  );

  let captured_managed = capture_rx.recv().await.unwrap();
  assert_eq!(captured_managed.uri.path(), "/v1/chat/completions");
  assert_eq!(captured_managed.headers["authorization"], "Bearer sk-v2-test");
  assert_eq!(
    serde_json::from_slice::<serde_json::Value>(&captured_managed.body).unwrap()["model"],
    "gpt-4o"
  );

  let relay_body = Bytes::from_static(br#"{"input":"hi","model":"gpt-4o","unusual_order":true}"#);
  let relay = app
    .oneshot(
      Request::post("/v1/responses")
        .header("content-type", "application/json")
        .header("authorization", "Bearer client-secret")
        .body(Body::from(relay_body.clone()))
        .unwrap(),
    )
    .await
    .unwrap();
  let relay_status = relay.status();
  let relay_response = to_bytes(relay.into_body(), usize::MAX).await.unwrap();
  assert_eq!(
    relay_status,
    StatusCode::OK,
    "relay response: {}",
    String::from_utf8_lossy(&relay_response)
  );
  assert_eq!(relay_response.as_ref(), br#"{"relay":"unchanged"}"#);

  let captured_relay = capture_rx.recv().await.unwrap();
  assert_eq!(captured_relay.uri.path(), "/v1/responses");
  assert_eq!(captured_relay.headers["authorization"], "Bearer sk-v2-test");
  assert_eq!(captured_relay.body, relay_body);
  assert!(!String::from_utf8_lossy(&captured_relay.body).contains("client-secret"));

  server.abort();
}

fn account() -> AccountConfig {
  AccountConfig {
    id: "acct".into(),
    provider: "openai".into(),
    enabled: true,
    tier: AccountTier::Active,
    tags: Vec::new(),
    label: None,
    base_url: None,
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: Some(Secret::new("sk-v2-test".into())),
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

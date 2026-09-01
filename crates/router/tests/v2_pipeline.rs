use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Extension, State};
use axum::http::{HeaderMap, Request, StatusCode, Uri};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use std::path::Path;
use std::sync::Arc;
use tokn_access::AccessStore;
use tokn_core::account::{AccountConfig, AccountTier, AuthType, Secret};
use tokn_core::event::{Event, EventBus};
use tokn_core::request_event::{RecordEvent, RequestEventPayload};
use tower::ServiceExt;

struct CapturedRequest {
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
}

#[tokio::test]
async fn fixed_provider_client_relay_preserves_client_credentials_without_accounts() {
  let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(1);
  let upstream = Router::new()
    .route(
      "/{*path}",
      any(
        |State(capture_tx): State<tokio::sync::mpsc::Sender<CapturedRequest>>,
         uri: Uri,
         headers: HeaderMap,
         body: Bytes| async move {
          capture_tx.send(CapturedRequest { uri, headers, body }).await.unwrap();
          Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(r#"{"client_relay":"unchanged"}"#))
            .unwrap()
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
client_auth = "local_keys"
default_http_action = {{ kind = "route", profile = "client-relay" }}

[profiles.client-relay]
route = "client-relay"

[routes.client-relay]
kind = "relay"
destination = {{ kind = "fixed_provider", provider = "local" }}
credentials = {{ kind = "client" }}

[providers.local]
driver = "openai"
base_url = "http://{upstream_addr}/v1"
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-client-relay.toml")).unwrap();
  let events = Arc::new(EventBus::new(64));
  let mut event_rx = events.subscribe();
  let states = tokn_router::v2::build_states(plan, &[], Arc::new(AccessStore::disabled()), events).unwrap();
  let local_addr = "127.0.0.1:4141".parse::<std::net::SocketAddr>().unwrap();
  let peer_addr = "127.0.0.1:5151".parse::<std::net::SocketAddr>().unwrap();
  let app = tokn_router::v2::router(states.into_iter().next().unwrap()).layer(Extension(local_addr));
  let body = Bytes::from_static(br#"{"model":"gpt-4o","input":"hello","opaque":true}"#);

  let mut request = Request::post("/v1/responses")
    .header("host", "gateway.example")
    .header("x-tokn-router-local-addr", "spoofed.example")
    .header("content-type", "application/json")
    .header("authorization", "Bearer client-secret")
    .header("x-api-key", "client-key")
    .body(Body::from(body.clone()))
    .unwrap();
  request.extensions_mut().insert(ConnectInfo(peer_addr));
  let response = app.oneshot(request).await.unwrap();
  let request_id = response
    .headers()
    .get("x-request-id")
    .expect("v2 response missing request id")
    .to_str()
    .unwrap()
    .to_string();
  let status = response.status();
  let response_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  assert_eq!(
    status,
    StatusCode::OK,
    "client relay response: {}",
    String::from_utf8_lossy(&response_body)
  );
  assert_eq!(response_body.as_ref(), br#"{"client_relay":"unchanged"}"#);

  let captured = capture_rx.recv().await.unwrap();
  assert_eq!(captured.uri.path(), "/v1/responses");
  assert_eq!(captured.headers["authorization"], "Bearer client-secret");
  assert_eq!(captured.headers["x-api-key"], "client-key");
  assert_ne!(captured.headers["host"], "gateway.example");
  assert_eq!(captured.body, body);

  let inbound = std::iter::from_fn(|| event_rx.try_recv().ok()).find_map(|event| {
    let Event::Requests(request) = &*event else {
      return None;
    };
    match &request.payload {
      RequestEventPayload::Record(RecordEvent::InboundConnection {
        user,
        api_key_id,
        local_addr,
        peer_addr,
        mode,
        method,
        inbound_method,
        url,
      }) => Some((
        request.request_id.clone(),
        user.clone(),
        api_key_id.clone(),
        local_addr.clone(),
        peer_addr.clone(),
        mode.clone(),
        method.clone(),
        inbound_method.clone(),
        url.clone(),
      )),
      _ => None,
    }
  });
  let (event_request_id, user, api_key_id, local_addr, peer_addr, mode, pipeline_id, inbound_method, url) =
    inbound.expect("v2 API request did not emit an inbound connection event");
  assert_eq!(event_request_id.as_str(), request_id);
  assert!(user.is_none());
  assert!(api_key_id.is_none());
  assert_eq!(local_addr.as_deref(), Some("127.0.0.1:4141"));
  assert_eq!(peer_addr.as_deref(), Some("127.0.0.1:5151"));
  assert_eq!(mode.as_str(), "passthrough");
  assert_eq!(pipeline_id.as_str(), "requests");
  assert_eq!(inbound_method.as_str(), "POST");
  assert!(url.is_none());

  server.abort();
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
client_auth = "local_keys"
default_http_action = {{ kind = "route", profile = "managed" }}

[[bindings]]
id = "relay-responses"
listener = "api"
action = {{ kind = "route", profile = "relay" }}
operations = ["responses"]

[[bindings]]
id = "reject-messages"
listener = "api"
action = {{ kind = "reject" }}
operations = ["messages"]

[profiles.managed]
route = "managed"

[profiles.relay]
route = "relay"

[routes.managed]
kind = "managed"
account_pool = "primary"
provider = {{ kind = "fixed", provider = "local" }}
model = {{ kind = "family", families = {{ smart = ["not-an-openai-model", "gpt-4o"] }} }}
operation = "preserve"

[routes.relay]
kind = "relay"
destination = {{ kind = "fixed_provider", provider = "local" }}
credentials = {{ kind = "account_pool", account_pool = "primary" }}

[account_pools.primary]
accounts = ["acct"]
providers = ["local"]

[providers.local]
driver = "openai"
base_url = "http://{upstream_addr}/v1"
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-test.toml")).unwrap();
  let access = Arc::new(AccessStore::disabled());
  let allowed_key = access.create_key("local provider", vec!["local".into()]).unwrap();
  let driver_only_key = access.create_key("driver only", vec!["openai".into()]).unwrap();
  let states = tokn_router::v2::build_states(plan, &[account()], access, Arc::new(EventBus::noop())).unwrap();
  let app = tokn_router::v2::router(states.into_iter().next().unwrap());

  let managed_body = br#"{"model":"smart","messages":[{"role":"user","content":"hi"}]}"#;
  let missing_key = app
    .clone()
    .oneshot(
      Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(managed_body.as_slice()))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(missing_key.status(), StatusCode::UNAUTHORIZED);

  let rejected = app
    .clone()
    .oneshot(
      Request::post("/v1/messages")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", allowed_key.token))
        .body(Body::from(br#"{"model":"gpt-4o","messages":[]}"#.as_slice()))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

  let denied = app
    .clone()
    .oneshot(
      Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", driver_only_key.token))
        .body(Body::from(managed_body.as_slice()))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(denied.status(), StatusCode::FORBIDDEN);

  let managed = app
    .clone()
    .oneshot(
      Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", allowed_key.token))
        .body(Body::from(managed_body.as_slice()))
        .unwrap(),
    )
    .await
    .unwrap();
  let managed_request_id = managed
    .headers()
    .get("x-request-id")
    .expect("managed response missing generated request id")
    .to_str()
    .unwrap()
    .to_string();
  let managed_uuid = managed_request_id
    .strip_prefix("req-")
    .expect("managed request id missing req- prefix");
  assert!(uuid::Uuid::parse_str(managed_uuid).is_ok());
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
  assert_eq!(captured_managed.headers["x-request-id"], managed_request_id);
  assert_eq!(
    serde_json::from_slice::<serde_json::Value>(&captured_managed.body).unwrap()["model"],
    "gpt-4o"
  );

  let relay_body = Bytes::from_static(br#"{"input":"hi","model":"gpt-4o","unusual_order":true}"#);
  let relay = app
    .oneshot(
      Request::post("/v1/responses")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", allowed_key.token))
        .header("x-request-id", "client-v2-request")
        .body(Body::from(relay_body.clone()))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(relay.headers()["x-request-id"], "client-v2-request");
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
  assert_eq!(captured_relay.headers["x-request-id"], "client-v2-request");
  assert_eq!(captured_relay.body, relay_body);

  server.abort();
}

#[tokio::test]
async fn managed_retry_reselects_after_a_recoverable_account_failure() {
  let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(2);
  let upstream = Router::new()
    .route(
      "/{*path}",
      any(
        |State(capture_tx): State<tokio::sync::mpsc::Sender<String>>, headers: HeaderMap| async move {
          let authorization = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
          capture_tx.send(authorization.clone()).await.unwrap();
          if authorization == "Bearer sk-primary" {
            Response::builder()
              .status(StatusCode::SERVICE_UNAVAILABLE)
              .header("content-type", "application/json")
              .body(Body::from(r#"{"error":"try another account"}"#))
              .unwrap()
          } else {
            Response::builder()
              .header("content-type", "application/json")
              .body(Body::from(
                r#"{"id":"chatcmpl-failover","choices":[{"message":{"role":"assistant","content":"ok"}}]}"#,
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

[profiles.managed]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "primary"
provider = {{ kind = "fixed", provider = "local" }}
model = {{ kind = "capability" }}
operation = "preserve"
retry = {{ kind = "recoverable", policy = "failover" }}

[retry_policies.failover]
max_retries = 1
initial_backoff_ms = 0

[account_pools.primary]
accounts = ["a-primary", "b-secondary"]
providers = ["local"]
failure_cooldown_secs = 60

[providers.local]
driver = "openai"
base_url = "http://{upstream_addr}/v1"
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-retry.toml")).unwrap();
  let accounts = [
    account_with_credentials("a-primary", "sk-primary"),
    account_with_credentials("b-secondary", "sk-secondary"),
  ];
  let states = tokn_router::v2::build_states(
    plan,
    &accounts,
    Arc::new(AccessStore::disabled()),
    Arc::new(EventBus::noop()),
  )
  .unwrap();
  let app = tokn_router::v2::router(states.into_iter().next().unwrap());

  let response = app
    .oneshot(
      Request::post("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(br#"{"model":"gpt-4o","messages":[]}"#.as_slice()))
        .unwrap(),
    )
    .await
    .unwrap();
  let status = response.status();
  let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  assert_eq!(
    status,
    StatusCode::OK,
    "retry response: {}",
    String::from_utf8_lossy(&body)
  );
  assert_eq!(
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["id"],
    "chatcmpl-failover"
  );
  assert_eq!(capture_rx.recv().await.as_deref(), Some("Bearer sk-primary"));
  assert_eq!(capture_rx.recv().await.as_deref(), Some("Bearer sk-secondary"));

  server.abort();
}

fn account() -> AccountConfig {
  account_with_credentials("acct", "sk-v2-test")
}

fn account_with_credentials(id: &str, api_key: &str) -> AccountConfig {
  AccountConfig {
    id: id.into(),
    provider: "local".into(),
    enabled: true,
    tier: AccountTier::Active,
    tags: Vec::new(),
    label: None,
    base_url: None,
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: Some(Secret::new(api_key.into())),
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

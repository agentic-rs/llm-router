use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, Uri};
use axum::routing::any;
use axum::Router;
use std::path::Path;
use std::sync::Arc;
use tokn_access::AccessStore;
use tokn_core::event::EventBus;
use tower::ServiceExt;

#[tokio::test]
async fn custom_mount_dispatches_all_generation_operations_without_forwarding_the_mount_path() {
  let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
  let upstream = Router::new()
    .fallback(any(
      |State(sender): State<tokio::sync::mpsc::Sender<(Uri, HeaderMap, Bytes)>>,
       uri: Uri,
       headers: HeaderMap,
       body: Bytes| async move {
        sender.send((uri, headers, body.clone())).await.unwrap();
        body
      },
    ))
    .with_state(sender);
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
  let config = format!(
    r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "local_keys"
[profiles.relay]
route = "relay"
binding = {{ path = "/custom/team/api" }}
[routes.relay]
kind = "relay"
destination = {{ kind = "fixed_provider", provider = "local" }}
credentials = {{ kind = "client" }}
providers = ["local"]
[providers.local]
driver = "github-copilot"
base_url = "http://{address}"
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("mounts.toml")).unwrap();
  let state = tokn_router::v2::build_states(plan, &[], Arc::new(AccessStore::disabled()), Arc::new(EventBus::noop()))
    .unwrap()
    .pop()
    .unwrap();
  let app = tokn_router::v2::router(state);
  for suffix in ["chat/completions", "responses", "messages"] {
    let payload = r#"{"model":"test","opaque":true}"#;
    let response = app
      .clone()
      .oneshot(
        Request::post(format!("/custom/team/api/{suffix}"))
          .header("authorization", "Bearer client-secret")
          .body(Body::from(payload))
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{suffix}");
    assert_eq!(to_bytes(response.into_body(), usize::MAX).await.unwrap(), payload);
    let (uri, headers, body) = receiver.recv().await.unwrap();
    let upstream_path = if suffix == "messages" {
      "/v1/messages".to_string()
    } else {
      format!("/{suffix}")
    };
    assert_eq!(uri.path(), upstream_path);
    assert_eq!(headers["authorization"], "Bearer client-secret");
    assert_eq!(body, payload);
  }
  let response = app
    .oneshot(Request::post("/relay/v1/responses").body(Body::from("{}")).unwrap())
    .await
    .unwrap();
  assert!(!response.status().is_success());
  assert!(receiver.try_recv().is_err());
  server.abort();
}

#[tokio::test]
async fn generation_and_discovery_both_intersect_route_and_profile_filters() {
  let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
  let upstream = Router::new()
    .fallback(any(
      |State(sender): State<tokio::sync::mpsc::Sender<String>>, headers: HeaderMap, uri: Uri| async move {
        sender
          .send(headers["authorization"].to_str().unwrap().to_string())
          .await
          .unwrap();
        axum::Json(if uri.path().ends_with("/models") {
          serde_json::json!({"data": [{"id":"gpt-4o","object":"model"}]})
        } else {
          serde_json::json!({"id":"chatcmpl-test","choices":[{"message":{"role":"assistant","content":"hello"}}]})
        })
      },
    ))
    .with_state(sender);
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
  let config = format!(
    r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
[profiles.work]
route = "coding"
account_pool = {{ accounts = ["work", "excluded-provider"] }}
binding = {{ path = "/custom/work", endpoints = ["chat_completions"] }}
[routes.coding]
kind = "managed"
provider = {{ kind = "any" }}
providers = ["local"]
model = {{ kind = "capability" }}
operation = "translate_compatible"
[providers.local]
driver = "openai"
base_url = "http://{address}/v1"
[providers.other]
driver = "openai"
base_url = "http://{address}/v1"
"#
  );
  let accounts = [
    ("excluded-account", "local"),
    ("excluded-provider", "other"),
    ("work", "local"),
  ]
  .map(|(id, provider)| {
    toml::from_str(&format!(
      "id = {id:?}\nprovider = {provider:?}\napi_key = {id:?}\nenabled = true"
    ))
    .unwrap()
  });
  let plan = tokn_config::v2::parse(&config, Path::new("mounts.toml")).unwrap();
  let state = tokn_router::v2::build_states(
    plan,
    &accounts,
    Arc::new(AccessStore::disabled()),
    Arc::new(EventBus::noop()),
  )
  .unwrap()
  .pop()
  .unwrap();
  let app = tokn_router::v2::router(state);
  let response = app
    .clone()
    .oneshot(Request::get("/custom/work/providers").body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  let body: serde_json::Value =
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
  assert_eq!(body["data"].as_array().unwrap().len(), 1);
  assert_eq!(body["data"][0]["id"], "local");
  assert_eq!(body["data"][0]["accounts"], 1);
  let response = app
    .clone()
    .oneshot(Request::get("/custom/work/models").body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(receiver.recv().await.unwrap(), "Bearer work");
  let response = app
    .clone()
    .oneshot(
      Request::post("/custom/work/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(
          r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
        ))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(receiver.recv().await.unwrap(), "Bearer work");
  let response = app
    .oneshot(Request::post("/custom/work/responses").body(Body::from("{}")).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::NOT_FOUND);
  assert!(receiver.try_recv().is_err());
  server.abort();
}

use super::*;
use axum::body::{to_bytes, Body};
use std::path::Path;
use tokn_accounts::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph, PoolAcquire};
use tower::ServiceExt;

fn config(path: &str, endpoints: &str) -> String {
  format!(
    r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "default" }}
[listeners.second]
kind = "llm_api"
bind = "127.0.0.1:4142"
client_auth = "none"
[profiles.default]
route = "shared"
[profiles.work]
route = "shared"
binding = {{ path = {path:?}, endpoints = {endpoints} }}
[routes.shared]
kind = "managed"
provider = {{ kind = "any" }}
providers = ["openai"]
model = {{ kind = "capability" }}
operation = "translate_compatible"
"#
  )
}

fn plan(path: &str, endpoints: &str) -> GatewayPlan {
  tokn_config::v2::parse(&config(path, endpoints), Path::new("mounts.toml")).unwrap()
}

fn states(path: &str, endpoints: &str) -> RuntimeStates {
  build_runtime_states(
    plan(path, endpoints),
    &[],
    Arc::new(tokn_access::AccessStore::disabled()),
    Arc::new(EventBus::noop()),
  )
  .unwrap()
}

#[tokio::test]
async fn mounts_are_global_disabled_endpoints_never_fall_through_and_discovery_stays_available() {
  let states = states("/teams/work/api", "[]");
  assert!(Arc::ptr_eq(&states.llm_api[0].profiles, &states.llm_api[1].profiles));
  assert!(Arc::ptr_eq(&states.llm_api[0].mounts, &states.llm_api[1].mounts));
  for state in states.llm_api {
    let app = router(state);
    for suffix in ["chat/completions", "responses", "messages"] {
      let response = app
        .clone()
        .oneshot(
          Request::post(format!("/teams/work/api/{suffix}"))
            .body(Body::from("{}"))
            .unwrap(),
        )
        .await
        .unwrap();
      assert_eq!(response.status(), StatusCode::NOT_FOUND, "{suffix}");
    }
    for suffix in ["providers", "models"] {
      let response = app
        .clone()
        .oneshot(
          Request::get(format!("/teams/work/api/{suffix}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
      assert_eq!(response.status(), StatusCode::OK, "{suffix}");
      let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
      assert_eq!(body["data"], serde_json::json!([]));
    }
    let head = app
      .clone()
      .oneshot(Request::head("/teams/work/api/providers").body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert!(to_bytes(head.into_body(), usize::MAX).await.unwrap().is_empty());
    let wrong_method = app
      .clone()
      .oneshot(Request::post("/teams/work/api/providers").body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong_method.headers()[axum::http::header::ALLOW], "GET, HEAD");
    for path in [
      "/work/v1/responses",
      "/unknown/v1/responses",
      "/teams/work/api/responses/extra",
    ] {
      let response = app
        .clone()
        .oneshot(Request::post(path).body(Body::from("{}")).unwrap())
        .await
        .unwrap();
      assert!(
        matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::FORBIDDEN),
        "{path}"
      );
    }
  }
}

#[tokio::test]
async fn reload_updates_custom_mounts_and_endpoint_selection_without_rebuilding_router() {
  let live = LiveRuntime::new(states("/custom/old", "[\"responses\"]"), 0);
  let state = live
    .llm_api_listeners()
    .into_iter()
    .find(|state| state.current().listener_id.as_str() == "api")
    .unwrap();
  let old_generation = state.current();
  let app = router_live(state.clone());
  assert!(old_generation.mounts.get("/custom/old/responses").unwrap().enabled);
  live.replace(states("/custom/new", "[\"messages\"]"), 0).unwrap();
  assert!(old_generation.mounts.get("/custom/old/responses").is_some());
  assert!(state.current().mounts.get("/custom/old/responses").is_none());
  assert!(state.current().mounts.get("/custom/new/messages").unwrap().enabled);
  for path in ["/custom/old/responses", "/custom/new/responses"] {
    let response = app
      .clone()
      .oneshot(Request::post(path).body(Body::from("{}")).unwrap())
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
  }
  let response = app
    .oneshot(
      Request::post("/custom/new/messages")
        .body(Body::from("not-json"))
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn canonical_paths_do_not_decode_slashes_or_change_namespace() {
  let mounts = ApiMounts::new(&plan("/custom/team%2fblue", "[\"responses\"]")).unwrap();
  for path in ["/custom/team%2fblue/responses", "/custom/team%2Fblue/responses"] {
    assert!(mounts.get(path).unwrap().enabled);
  }
  assert!(mounts.get("/custom/team/blue/responses").is_none());
}

#[test]
fn reused_route_does_not_share_round_robin_cooldown_or_session_affinity() {
  let plan = plan("/work/v1", "[]");
  let accounts = ["one", "two"].map(|id| {
    toml::from_str(&format!(
      "id = {id:?}\nprovider = 'openai'\napi_key = 'test'\nenabled = true"
    ))
    .unwrap()
  });
  let providers = link_provider_graph(&plan, &accounts, &Registry::builtin()).unwrap();
  let pools = build_account_pool_runtimes(&link_account_pools(&plan, &providers).unwrap());
  let default = pools
    .runtime(plan.profiles()["default"].account_pool().unwrap())
    .unwrap();
  let work = pools.runtime(plan.profiles()["work"].account_pool().unwrap()).unwrap();
  assert!(!Arc::ptr_eq(default, work));
  let select = |pool: &tokn_accounts::link::AccountPoolRuntime, session| {
    let PoolAcquire::Selected(binding) = pool.acquire(session, |_| true) else {
      panic!("expected account")
    };
    binding
  };
  let first = select(default, None);
  let second = select(default, None);
  assert_ne!(first.key(), second.key());
  assert_eq!(select(work, None).key(), first.key());
  default.record_success(Some("session"), first.key()).unwrap();
  work.record_success(Some("session"), second.key()).unwrap();
  assert_eq!(select(default, Some("session")).key(), first.key());
  assert_eq!(select(work, Some("session")).key(), second.key());
  default.record_failure(first.key()).unwrap();
  assert_eq!(select(default, Some("session")).key(), second.key());
  work.record_success(Some("another"), first.key()).unwrap();
  assert_eq!(select(work, Some("another")).key(), first.key());
}

#[tokio::test]
async fn custom_mount_keeps_authentication_cors_and_request_limits() {
  let directory = tempfile::tempdir().unwrap();
  let access = tokn_access::AccessStore::open(directory.path().join("access.db")).unwrap();
  let token = access.create_key("client", Vec::new()).unwrap().token;
  let config = format!("{}\n[listeners.api.cors]\nenabled = true\nallowed_origins = ['https://app.example.com']\n[service.request_limits]\nmax_wire_bytes = 16", config("/custom/api", "[\"responses\"]").replace("client_auth = \"none\"", "client_auth = \"local_keys\""));
  let config = tokn_config::v2::parse_config(&config, Path::new("mounts.toml")).unwrap();
  let states = build_runtime_states_with_service(
    config.gateway().clone(),
    config.service().clone(),
    &[],
    Arc::new(access),
    Arc::new(EventBus::noop()),
  )
  .unwrap();
  let state = states
    .llm_api
    .into_iter()
    .find(|state| state.listener_id.as_str() == "api")
    .unwrap();
  let app = router(state);
  let preflight = app
    .clone()
    .oneshot(
      Request::builder()
        .method(Method::OPTIONS)
        .uri("/custom/api/responses")
        .header("origin", "https://app.example.com")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(preflight.status(), StatusCode::OK);
  for (key, expected) in [
    (None, StatusCode::UNAUTHORIZED),
    (Some(token), StatusCode::PAYLOAD_TOO_LARGE),
  ] {
    let mut request = Request::post("/custom/api/responses").header("origin", "https://app.example.com");
    if let Some(key) = key {
      request = request.header("authorization", format!("Bearer {key}"));
    }
    let response = app
      .clone()
      .oneshot(request.body(Body::from("x".repeat(32))).unwrap())
      .await
      .unwrap();
    assert_eq!(response.status(), expected);
    assert_eq!(
      response.headers()["access-control-allow-origin"],
      "https://app.example.com"
    );
  }
}

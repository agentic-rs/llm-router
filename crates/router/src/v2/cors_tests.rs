use super::*;
use axum::body::Body;
use axum::http::{header, HeaderValue, Request};
use std::path::Path;
use tower::ServiceExt;

const ORIGIN: &str = "https://app.example.com";
const CLIENT_PATHS: &[(&str, &str)] = &[
  ("/v1/chat/completions", "POST"),
  ("/v1/responses", "POST"),
  ("/v1/messages", "POST"),
  ("/v1/models", "GET"),
  ("/v1/providers", "GET"),
  ("/work/v1/chat/completions", "POST"),
  ("/work/v1/responses", "POST"),
  ("/work/v1/messages", "POST"),
  ("/work/v1/models", "GET"),
  ("/work/v1/providers", "GET"),
];

fn plan(settings: &str) -> GatewayPlan {
  tokn_config::v2::parse(
    &format!(
      r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "local_keys"
default_http_action = {{ kind = "reject" }}
[listeners.api.cors]
{settings}
"#
    ),
    Path::new("cors.toml"),
  )
  .unwrap()
}

fn states(plan: GatewayPlan, access: Arc<tokn_access::AccessStore>) -> RuntimeStates {
  build_runtime_states(plan, &[], access, Arc::new(EventBus::noop())).unwrap()
}

fn app(settings: &str) -> Router {
  let live = LiveRuntime::new(
    states(plan(settings), Arc::new(tokn_access::AccessStore::disabled())),
    0,
  );
  router_live(live.llm_api_listeners().pop().unwrap())
}

fn preflight(path: &str, method: &str, origin: &str) -> Request<Body> {
  Request::builder()
    .method(Method::OPTIONS)
    .uri(path)
    .header(header::ORIGIN, origin)
    .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
    .header(
      header::ACCESS_CONTROL_REQUEST_HEADERS,
      "authorization,x-api-key,x-future-client-metadata",
    )
    .body(Body::empty())
    .unwrap()
}

#[tokio::test]
async fn preflight_precedes_authentication_on_all_client_endpoints() {
  let app = app(&format!("enabled = true\nallowed_origins = [{ORIGIN:?}]"));
  for (path, method) in CLIENT_PATHS {
    let response = app.clone().oneshot(preflight(path, method, ORIGIN)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    assert_eq!(
      response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
      ORIGIN,
      "{path}"
    );
    assert!(response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS]
      .to_str()
      .unwrap()
      .contains(method));
    assert_eq!(
      response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
      "authorization,x-api-key,x-future-client-metadata"
    );
    assert_eq!(response.headers()[header::ACCESS_CONTROL_MAX_AGE], "600");
    assert!(!response
      .headers()
      .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
    assert!(response.headers()[header::VARY].to_str().unwrap().contains("origin"));
  }
}

#[tokio::test]
async fn actual_requests_keep_authentication_and_cors_headers_on_errors() {
  let directory = tempfile::tempdir().unwrap();
  let access = tokn_access::AccessStore::open(directory.path().join("access.db")).unwrap();
  let token = access.create_key("cors-client", Vec::new()).unwrap().token;
  let live = LiveRuntime::new(
    states(
      plan(&format!("enabled = true\nallowed_origins = [{ORIGIN:?}]")),
      Arc::new(access),
    ),
    0,
  );
  let app = router_live(live.llm_api_listeners().pop().unwrap());
  for (auth, expected) in [
    (None, StatusCode::UNAUTHORIZED),
    (Some("invalid"), StatusCode::UNAUTHORIZED),
    (Some(token.as_str()), StatusCode::BAD_REQUEST),
  ] {
    let mut request = Request::get("/v1/models").header(header::ORIGIN, ORIGIN);
    if let Some(auth) = auth {
      request = request.header(header::AUTHORIZATION, format!("Bearer {auth}"));
    }
    let response = app.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
    // A valid key reaches discovery's missing-profile error; CORS does not
    // grant routing access or bypass client authentication.
    assert_eq!(response.status(), expected);
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], ORIGIN);
    assert_eq!(
      response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
      REQUEST_ID_HEADER
    );
    assert!(response.headers().contains_key(REQUEST_ID_HEADER));
  }
}

#[tokio::test]
async fn successful_discovery_responses_include_cors_and_request_ids() {
  let source = format!(
    r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "default" }}
cors = {{ enabled = true, allowed_origins = [{ORIGIN:?}] }}
[profiles.default]
route = "default"
[routes.default]
kind = "managed"
account_pool = "default"
provider = {{ kind = "any" }}
model = {{ kind = "capability" }}
operation = "translate_compatible"
[account_pools.default]
accounts = ["*"]
providers = ["*"]
"#
  );
  let plan = tokn_config::v2::parse(&source, Path::new("cors.toml")).unwrap();
  let live = LiveRuntime::new(states(plan, Arc::new(tokn_access::AccessStore::disabled())), 0);
  let app = router_live(live.llm_api_listeners().pop().unwrap());
  for path in ["/v1/providers", "/v1/models"] {
    let response = app
      .clone()
      .oneshot(
        Request::get(path)
          .header(header::ORIGIN, ORIGIN)
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], ORIGIN);
    assert_eq!(
      response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
      REQUEST_ID_HEADER
    );
    assert!(response.headers().contains_key(REQUEST_ID_HEADER));
  }
}

#[tokio::test]
async fn cors_never_covers_admin_health_or_unknown_paths() {
  let app = app(&format!("enabled = true\nallowed_origins = [{ORIGIN:?}]"));
  for path in ["/admin/config/reload", "/healthz", "/unknown"] {
    let response = app.clone().oneshot(preflight(path, "POST", ORIGIN)).await.unwrap();
    assert!(
      !response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
      "{path}"
    );
    let response = app
      .clone()
      .oneshot(
        Request::get(path)
          .header(header::ORIGIN, ORIGIN)
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert!(
      !response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
      "{path}"
    );
  }
  let admin = app
    .oneshot(
      Request::post("/admin/config/reload")
        .header(header::ORIGIN, ORIGIN)
        .header(ADMIN_ACTION_HEADER, ADMIN_RELOAD_ACTION)
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  // Non-browser callers keep the explicit-action contract; this runtime has
  // no reloader. Browsers cannot pass the custom-header preflight above.
  assert_eq!(admin.status(), StatusCode::NOT_FOUND);
  assert!(!admin.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn disabled_and_unlisted_origins_never_receive_access_permission() {
  for settings in [
    "".to_string(),
    format!("allowed_origins = [{ORIGIN:?}]\nallow_localhost = true"),
    "enabled = true\nallowed_origins = ['https://other.example']".into(),
    "enabled = true\nallowed_origins = ['https://*.example.com']".into(),
  ] {
    let app = app(&settings);
    for origin in [ORIGIN, "http://localhost:3000"] {
      let response = app
        .clone()
        .oneshot(preflight("/v1/models", "GET", origin))
        .await
        .unwrap();
      assert!(!response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
      let response = app
        .clone()
        .oneshot(
          Request::get("/v1/models")
            .header(header::ORIGIN, origin)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
      assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
      assert!(!response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }
  }
}

#[tokio::test]
async fn localhost_policy_rejects_lookalikes_and_non_origins() {
  let app = app("enabled = true\nallow_localhost = true");
  for origin in [
    "http://localhost",
    "https://localhost:8443",
    "http://app.localhost:3000",
    "https://nested.app.localhost",
    "http://127.0.0.1:5173",
    "https://[::1]:9443",
  ] {
    let response = app
      .clone()
      .oneshot(preflight("/v1/models", "GET", origin))
      .await
      .unwrap();
    assert_eq!(
      response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
      Some(&HeaderValue::try_from(origin).unwrap()),
      "{origin}"
    );
  }
  for origin in [
    "null",
    "http://localhost.example.com",
    "http://examplelocalhost",
    "http://127.0.0.2:5173",
    "http://192.168.1.10",
    "https://example.com",
    "ftp://localhost",
    "http://user:secret@localhost",
    "http://localhost/path",
    "http://localhost/?query=yes",
    "http://localhost/#fragment",
  ] {
    let response = app
      .clone()
      .oneshot(preflight("/v1/models", "GET", origin))
      .await
      .unwrap();
    assert!(
      !response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
      "{origin}"
    );
  }
}

#[tokio::test]
async fn cors_permissions_follow_live_reload_without_rebuilding_router() {
  let access = Arc::new(tokn_access::AccessStore::disabled());
  let live = LiveRuntime::new(states(plan(""), access.clone()), 0);
  let app = router_live(live.llm_api_listeners().pop().unwrap());
  let settings = [
    format!("enabled = true\nallowed_origins = [{ORIGIN:?}]"),
    "enabled = true\nallow_localhost = true".into(),
    "enabled = false\nallow_localhost = true".into(),
  ];
  for (index, settings) in settings.iter().enumerate() {
    let replacement = plan(settings);
    live.validate_reload(&replacement).unwrap();
    live.replace(states(replacement, access.clone()), 0).unwrap();
    assert_eq!(live.generation(), index as u64 + 2);
    for (origin, expected) in [(ORIGIN, index == 0), ("http://localhost:3000", index == 1)] {
      let response = app
        .clone()
        .oneshot(preflight("/v1/models", "GET", origin))
        .await
        .unwrap();
      assert_eq!(
        response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        expected,
        "{settings}: {origin}"
      );
    }
  }
}

#[tokio::test]
async fn cors_permissions_are_isolated_between_api_listeners() {
  let source = format!(
    r#"
schema_version = 2
[listeners.first]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
cors = {{ enabled = true, allowed_origins = [{ORIGIN:?}] }}
[listeners.second]
kind = "llm_api"
bind = "127.0.0.1:4142"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
"#
  );
  let plan = tokn_config::v2::parse(&source, Path::new("cors.toml")).unwrap();
  let live = LiveRuntime::new(states(plan, Arc::new(tokn_access::AccessStore::disabled())), 0);
  for state in live.llm_api_listeners() {
    let expected = state.listener_id().as_str() == "first";
    let response = router_live(state)
      .oneshot(preflight("/v1/models", "GET", ORIGIN))
      .await
      .unwrap();
    assert_eq!(
      response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
      expected
    );
  }
}

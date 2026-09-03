use super::*;
use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use std::path::Path;
use tower::ServiceExt;

const FIRST: &str = "https://first.example.com";
const SECOND: &str = "https://second.example.com";

/// Write equivalent disk configs to exercise both runtime-source reload paths.
fn write_config(path: &Path, legacy: bool, cors: &tokn_config::CorsConfig) {
  if legacy {
    let mut config = Config::default();
    config.server.cors = cors.clone();
    config.save(path).unwrap();
  } else {
    let mut raw = tokn_config::v2::decode(
      r#"
schema_version = 2
[defaults]
[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
"#,
      path,
    )
    .unwrap();
    let tokn_config::v2::RawListener::LlmApi { cors: target, .. } = raw.listeners.get_mut("api").unwrap() else {
      panic!("expected API listener");
    };
    *target = cors.into();
    std::fs::write(path, toml::to_string(&raw).unwrap()).unwrap();
  }
}

async fn preflight_allowed(app: &axum::Router, origin: &str) -> bool {
  app
    .clone()
    .oneshot(
      Request::builder()
        .method(Method::OPTIONS)
        .uri("/v1/models")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap()
    .headers()
    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
}

async fn reload(app: &axum::Router) -> (StatusCode, serde_json::Value) {
  let response = app
    .clone()
    .oneshot(
      Request::post("/admin/config/reload")
        .header("x-tokn-admin", "reload")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  let status = response.status();
  let body = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
  (status, body)
}

#[tokio::test]
async fn cors_reload_reads_both_schemas_and_preserves_permissions_after_invalid_edits() {
  for legacy in [false, true] {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    let mut auth = tokn_auth::AuthStore::load(Some(&auth_path), None).unwrap();
    auth.upsert(toml::from_str("id = 'primary'\nprovider = 'openai'\nenabled = true\napi_key = 'test-key'").unwrap());
    auth.save().unwrap();
    let mut cors = tokn_config::CorsConfig {
      enabled: true,
      allow_localhost: false,
      allowed_origins: vec![FIRST.into()],
    };
    write_config(&config_path, legacy, &cors);
    let args = ServeArgs {
      host: None,
      port: None,
      with_proxy: false,
      proxy_route_mode: None,
      insecure_allow_remote: false,
      no_proxy: false,
    };
    let source = if legacy {
      RuntimeSource::ProjectedLegacy {
        config_path: config_path.clone(),
        auth_path,
        args,
      }
    } else {
      RuntimeSource::NativeV2 {
        config_path: config_path.clone(),
        auth_path,
        args,
      }
    };
    let loaded = source.load().unwrap();
    let initial_service = loaded.compiled.service().clone();
    let (plan, service) = loaded.compiled.into_parts();
    let access = Arc::new(tokn_access::AccessStore::disabled());
    let events = Arc::new(EventBus::noop());
    let states = tokn_router::v2::build_runtime_states_with_service(
      plan,
      service,
      &loaded.accounts,
      access.clone(),
      events.clone(),
    )
    .unwrap();
    let live = tokn_router::v2::LiveRuntime::new(states, loaded.accounts.len());
    install_admin_reloader(&live, source, initial_service, access, events).unwrap();
    let app = tokn_router::v2::router_live(live.llm_api_listeners().pop().unwrap());
    assert!(preflight_allowed(&app, FIRST).await);
    assert!(!preflight_allowed(&app, SECOND).await);

    cors.allowed_origins = vec![SECOND.into()];
    write_config(&config_path, legacy, &cors);
    let (status, body) = reload(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["generation"], 2);
    assert!(!preflight_allowed(&app, FIRST).await);
    assert!(preflight_allowed(&app, SECOND).await);

    // Bypass config writers' validation to simulate an invalid manual edit.
    let valid = std::fs::read_to_string(&config_path).unwrap();
    let invalid = valid.replace(SECOND, "https://second.example.com/not-an-origin");
    std::fs::write(&config_path, invalid).unwrap();
    let (status, body) = reload(&app).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["type"], "reload_failed");
    assert_eq!(live.generation(), 2);
    assert!(!preflight_allowed(&app, FIRST).await);
    assert!(preflight_allowed(&app, SECOND).await);

    cors.enabled = false;
    write_config(&config_path, legacy, &cors);
    assert_eq!(reload(&app).await.0, StatusCode::OK);
    assert_eq!(live.generation(), 3);
    assert!(!preflight_allowed(&app, SECOND).await);

    cors.enabled = true;
    cors.allowed_origins.clear();
    cors.allow_localhost = true;
    write_config(&config_path, legacy, &cors);
    assert_eq!(reload(&app).await.0, StatusCode::OK);
    assert_eq!(live.generation(), 4);
    assert!(!preflight_allowed(&app, SECOND).await);
    assert!(preflight_allowed(&app, "http://localhost:3000").await);
  }
}

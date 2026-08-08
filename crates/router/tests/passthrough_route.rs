//! Integration test for the passthrough pipeline served by `router(state)`.
//!
//! Drives a real `POST /passthrough/v1/chat/completions` through the axum router →
//! `endpoints::handle` (which dispatches to `state.passthrough_service`)
//! → mock upstream TCP server. Asserts:
//!
//! * The upstream receives the inbound body **verbatim** (no
//!   re-serialization).
//! * Router-owned `x-route-mode` / `x-tokn-router-*` / `x-behave-as`
//!   headers are dropped before forwarding.
//! * The upstream `Authorization: Bearer ...` is injected by the
//!   provider (not the original inbound auth).
//! * The downstream response body matches upstream exactly for the
//!   non-SSE buffered branch.
//!
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokn_core::account::{AccountConfig, AccountTier, AuthType};
use tokn_core::event::EventBus;
use tokn_router::api::build_state;
use tokn_router::api::router;
use tokn_router::config::{Account as AccountCfg, Config, ProfileConfig, RouteMode};
use tokn_router::util::secret::Secret;
use tower::ServiceExt;

fn test_account(base_url: String) -> AccountCfg {
  AccountCfg {
    id: "passthrough-acct".into(),
    provider: "zai-coding-plan".into(),
    enabled: true,
    tier: AccountTier::Active,
    tags: Vec::new(),
    label: None,
    base_url: Some(base_url),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: Some(Secret::new("sk-upstream-injected".into())),
    api_key_expires_at: None,
    access_token: None,
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: toml::Table::new(),
  }
}

fn _account_config(cfg: AccountCfg) -> AccountConfig {
  // Construct via TOML round-trip — `AccountCfg` is the router's
  // local TOML alias; `build_state` accepts `&[AccountConfig]`.
  // The two types share fields by name. We round-trip through serde
  // to avoid pinning to whichever conversion currently exists.
  let toml_str = toml::to_string(&cfg).expect("serialize AccountCfg");
  toml::from_str(&toml_str).expect("parse AccountConfig")
}

#[tokio::test]
async fn passthrough_route_forwards_body_verbatim_and_injects_auth() {
  // Mock upstream: accepts one request, captures it for assertion,
  // returns a buffered JSON response.
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let upstream_url = format!("http://{addr}");

  let (req_tx, req_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
  let upstream_body =
    br#"{"id":"resp-1","choices":[{"message":{"content":"hello"}}],"usage":{"prompt_tokens":3,"completion_tokens":5}}"#;
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut buf = vec![0_u8; 16384];
    let n = stream.read(&mut buf).await.unwrap();
    buf.truncate(n);
    // Send response while body is still being read so write doesn't block.
    let resp = format!(
      "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
      upstream_body.len()
    );
    stream.write_all(resp.as_bytes()).await.unwrap();
    stream.write_all(upstream_body).await.unwrap();
    stream.flush().await.unwrap();
    let _ = req_tx.send(buf);
  });

  // Build router state with our mock upstream as the account base_url.
  let mut cfg = Config::default();
  cfg.api_key.enabled = true;
  cfg.profiles.insert(
    "passthrough".into(),
    ProfileConfig {
      mode: Some(RouteMode::Passthrough),
      default_provider_id: Some("zai-coding-plan".into()),
      ..Default::default()
    },
  );
  let acct_router = test_account(upstream_url.clone());
  // Convert router-local AccountCfg → tokn_core::AccountConfig via TOML
  // round-trip. `build_state` reads `AccountConfig`.
  let acct_core: AccountConfig = {
    let s = toml::to_string(&acct_router).unwrap();
    toml::from_str(&s).unwrap()
  };
  let state = build_state(&cfg, &[acct_core], Arc::new(EventBus::noop())).unwrap();
  let app = router(state);

  // Inbound request body — note the unusual key order to prove no
  // re-serialization happens (a JSON re-encode would canonicalize).
  let inbound_body =
    Bytes::from_static(br#"{"stream":false,"messages":[{"role":"user","content":"hi"}],"model":"glm-4.6"}"#);

  let req = Request::builder()
    .method(Method::POST)
    .uri("/passthrough/v1/chat/completions")
    .header("content-type", "application/json")
    // This is deliberately not a tokn API key. Passthrough bypasses client
    // authentication even when the global API-key switch is enabled.
    .header("authorization", "Bearer client-side-secret-must-not-leak")
    .header("x-tokn-router-local-addr", "127.0.0.1:9999")
    .header("x-behave-as", "codex")
    .body(Body::from(inbound_body.clone()))
    .unwrap();

  let resp = app.oneshot(req).await.unwrap();
  assert_eq!(resp.status(), StatusCode::OK, "passthrough should succeed");
  let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
  assert_eq!(
    resp_body.as_ref(),
    upstream_body,
    "downstream body must be upstream body verbatim"
  );

  // Verify what the upstream received.
  server.await.unwrap();
  let raw_req = req_rx.await.unwrap();
  let raw_req_str = String::from_utf8_lossy(&raw_req);

  // Body bytes appear verbatim in the raw HTTP request.
  assert!(
    raw_req_str.contains(std::str::from_utf8(&inbound_body).unwrap()),
    "upstream request must contain inbound body verbatim, got:\n{raw_req_str}"
  );

  // Router-owned headers are stripped.
  let lower = raw_req_str.to_ascii_lowercase();
  assert!(
    !lower.contains("x-tokn-router-local-addr"),
    "x-tokn-router-* must be stripped"
  );
  assert!(!lower.contains("x-route-mode"), "x-route-mode must be stripped");
  assert!(!lower.contains("x-behave-as"), "x-behave-as must be stripped");

  // The provider injects upstream auth, replacing the client's bearer.
  assert!(
    lower.contains("authorization: bearer sk-upstream-injected"),
    "upstream must see provider-injected auth, got:\n{raw_req_str}"
  );
  assert!(
    !raw_req_str.contains("client-side-secret-must-not-leak"),
    "client-supplied auth must NOT leak to upstream"
  );
}

/// SSE branch: upstream emits `text/event-stream`; we expect:
/// * The downstream client receives the raw SSE frames byte-for-byte.
/// * The background SSE tap parses the per-frame usage and emits
///   `RecordEvent::Usage` on the event bus.
/// * The Content-Type header is preserved end-to-end.
#[tokio::test]
async fn passthrough_route_streams_sse_verbatim_and_emits_usage() {
  use tokn_core::event::Event as CoreEvent;
  use tokn_core::request_event::{RecordEvent, RequestEventPayload};

  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let upstream_url = format!("http://{addr}");

  // SSE body: a content delta, a usage frame, and [DONE].
  let sse_body = concat!(
    "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
    "data: {\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":13}}\n\n",
    "data: [DONE]\n\n",
  );

  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut buf = vec![0_u8; 16384];
    let _ = stream.read(&mut buf).await.unwrap();
    let head =
      "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\n\r\n".to_string();
    stream.write_all(head.as_bytes()).await.unwrap();
    // Write the SSE body as a single chunked-encoded frame followed
    // by the terminator. Using one chunk keeps this test focused on
    // the passthrough behaviour, not chunked-encoding edge cases.
    let chunk_header = format!("{:x}\r\n", sse_body.len());
    stream.write_all(chunk_header.as_bytes()).await.unwrap();
    stream.write_all(sse_body.as_bytes()).await.unwrap();
    stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
    stream.flush().await.unwrap();
  });

  let mut cfg = Config::default();
  cfg.profiles.insert(
    "passthrough".into(),
    ProfileConfig {
      mode: Some(RouteMode::Passthrough),
      default_provider_id: Some("zai-coding-plan".into()),
      ..Default::default()
    },
  );
  let acct_router = test_account(upstream_url.clone());
  let acct_core: AccountConfig = {
    let s = toml::to_string(&acct_router).unwrap();
    toml::from_str(&s).unwrap()
  };

  // Use a real bounded EventBus so we can subscribe and observe the
  // background tap's RecordEvent::Usage. `EventBus::noop()` would
  // silently drop everything.
  let events = Arc::new(EventBus::new(256));
  let mut rx = events.subscribe();
  let state = build_state(&cfg, &[acct_core], events.clone()).unwrap();
  let app = router(state);

  let inbound_body =
    Bytes::from_static(br#"{"model":"glm-4.6","messages":[{"role":"user","content":"hi"}],"stream":true}"#);
  let req = Request::builder()
    .method(Method::POST)
    .uri("/passthrough/v1/chat/completions")
    .header("content-type", "application/json")
    .header("accept", "text/event-stream")
    .body(Body::from(inbound_body.clone()))
    .unwrap();

  let resp = app.oneshot(req).await.unwrap();
  assert_eq!(resp.status(), StatusCode::OK);
  let ct = resp
    .headers()
    .get(axum::http::header::CONTENT_TYPE)
    .and_then(|v| v.to_str().ok())
    .unwrap_or("");
  assert!(
    ct.starts_with("text/event-stream"),
    "downstream Content-Type must be SSE, got {ct:?}"
  );

  let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
  assert_eq!(
    std::str::from_utf8(&resp_body).unwrap(),
    sse_body,
    "downstream SSE body must equal upstream verbatim"
  );

  server.await.unwrap();

  // Drain events until we see RecordEvent::Usage from the background tap.
  let mut saw_usage = false;
  for _ in 0..64 {
    let ev = tokio::time::timeout(std::time::Duration::from_millis(250), rx.recv()).await;
    let Ok(Ok(ev)) = ev else { break };
    if let CoreEvent::Requests(req) = &*ev {
      if let RequestEventPayload::Record(RecordEvent::Usage(u)) = &req.payload {
        // The parsers map prompt/completion_tokens → input/output_tokens.
        assert_eq!(u.input_tokens, Some(11), "expected input_tokens=11, got {u:?}");
        assert_eq!(u.output_tokens, Some(13), "expected output_tokens=13, got {u:?}");
        saw_usage = true;
        break;
      }
    }
  }
  assert!(
    saw_usage,
    "background SSE tap must emit RecordEvent::Usage with parsed token counts"
  );
}

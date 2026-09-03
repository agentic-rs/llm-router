use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokn_access::AccessStore;
use tokn_core::event::{Event, EventBus};
use tokn_core::request_event::{RecordEvent, RequestEventPayload, StageEvent};

#[tokio::test]
async fn v2_forward_proxy_authenticates_and_applies_connect_policy() {
  let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let upstream_addr = upstream.local_addr().unwrap();
  let upstream_task = tokio::spawn(async move {
    let (mut stream, _) = upstream.accept().await.unwrap();
    let mut request = [0_u8; 4];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    stream.write_all(b"pong").await.unwrap();
  });

  let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_addr = probe.local_addr().unwrap();
  drop(probe);
  let config = format!(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "local_keys"
default_http_action = {{ kind = "reject" }}
default_connect = "tunnel"

[[connect_rules]]
id = "reject-blocked"
listener = "proxy"
action = "reject"
hosts = ["blocked.example"]
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-forward-proxy.toml")).unwrap();
  let access = Arc::new(AccessStore::disabled());
  let key = access.create_key("proxy test", vec!["*".into()]).unwrap();
  assert!(
    tokn_router::v2::build_states(plan.clone(), &[], access.clone(), Arc::new(EventBus::noop()))
      .unwrap()
      .is_empty()
  );
  let state = tokn_router::v2::build_runtime_states(plan, &[], access, Arc::new(EventBus::noop()))
    .unwrap()
    .forward_proxy
    .pop()
    .unwrap();
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut unauthenticated_get = TcpStream::connect(proxy_addr).await.unwrap();
  unauthenticated_get
    .write_all(b"GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
    .await
    .unwrap();
  assert!(read_response_head(&mut unauthenticated_get)
    .await
    .starts_with("HTTP/1.1 407 Proxy Authentication Required"));

  let unauthenticated = connect(proxy_addr, "blocked.example:443", None).await;
  assert!(unauthenticated.starts_with("HTTP/1.1 407 Proxy Authentication Required"));

  let invalid = connect(proxy_addr, "blocked.example:443", Some("not-a-key")).await;
  assert!(invalid.starts_with("HTTP/1.1 407 Proxy Authentication Required"));

  let malformed = connect_with_authorization(proxy_addr, "blocked.example:443", &["Basic invalid"]).await;
  assert!(malformed.starts_with("HTTP/1.1 407 Proxy Authentication Required"));

  let duplicate = connect_with_authorization(
    proxy_addr,
    "blocked.example:443",
    &["Bearer duplicate-one", "Bearer duplicate-two"],
  )
  .await;
  assert!(duplicate.starts_with("HTTP/1.1 407 Proxy Authentication Required"));

  let rejected = connect(proxy_addr, "blocked.example:443", Some(&key.token)).await;
  assert!(rejected.starts_with("HTTP/1.1 403 Forbidden"));

  let mut tunnel = TcpStream::connect(proxy_addr).await.unwrap();
  tunnel
    .write_all(
      format!(
        "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: Bearer {}\r\nX-Request-Id: outer-connect\r\n\r\n",
        key.token
      )
      .as_bytes(),
    )
    .await
    .unwrap();
  let response = read_response_head(&mut tunnel).await;
  assert!(
    response.starts_with("HTTP/1.1 200"),
    "unexpected CONNECT response: {response:?}"
  );
  assert!(!response.to_ascii_lowercase().contains("x-request-id:"));
  tunnel.write_all(b"ping").await.unwrap();
  let mut reply = [0_u8; 4];
  tunnel.read_exact(&mut reply).await.unwrap();
  assert_eq!(&reply, b"pong");

  upstream_task.await.unwrap();
  shutdown_tx.send(()).unwrap();
  proxy_task.await.unwrap().unwrap();
}

#[test]
fn v2_forward_proxy_materializes_interception_ca() {
  let ca = tempfile::tempdir().unwrap();
  let ca_dir = toml_string(&ca.path().to_string_lossy());
  let plan = tokn_config::v2::parse(
    &format!(
      r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
default_connect = "intercept"
ca_dir = {ca_dir}
"#
    ),
    Path::new("v2-forward-proxy.toml"),
  )
  .unwrap();
  let state =
    tokn_router::v2::build_runtime_states(plan, &[], Arc::new(AccessStore::disabled()), Arc::new(EventBus::noop()))
      .unwrap()
      .forward_proxy
      .pop()
      .unwrap();
  assert_eq!(state.listener_id().as_str(), "proxy");
  assert!(ca.path().join("ca.crt").exists());
}

#[tokio::test]
async fn v2_forward_proxy_routes_absolute_http_transparently() {
  let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let upstream_addr = upstream.local_addr().unwrap();
  let received = tokio::spawn(async move {
    let (mut stream, _) = upstream.accept().await.unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
      let read = stream.read(&mut buffer).await.unwrap();
      assert!(read > 0);
      request.extend_from_slice(&buffer[..read]);
      if request.windows(4).any(|window| window == b"\r\n\r\n") && request.ends_with(b"hello") {
        break;
      }
    }
    stream
      .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld")
      .await
      .unwrap();
    request
  });

  let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_addr = probe.local_addr().unwrap();
  drop(probe);
  let config = format!(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "transparent" }}
default_connect = "reject"

[profiles.transparent]
route = "transparent"

[routes.transparent]
kind = "relay"
destination = {{ kind = "original" }}
credentials = {{ kind = "client" }}

[providers.codex]
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-forward-proxy.toml")).unwrap();
  let account = toml::from_str(
    r#"
id = "codex-primary"
provider = "codex"
access_token = "codex-client-token"
"#,
  )
  .unwrap();
  let events = Arc::new(EventBus::new(64));
  let mut event_rx = events.subscribe();
  let state = tokn_router::v2::build_runtime_states(plan, &[account], Arc::new(AccessStore::disabled()), events)
    .unwrap()
    .forward_proxy
    .pop()
    .unwrap();
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  let client_addr = client.local_addr().unwrap();
  client
    .write_all(
      format!(
        "POST http://{upstream_addr}/opaque?x=1 HTTP/1.1\r\nHost: {upstream_addr}\r\nAuthorization: Bearer codex-client-token\r\nContent-Length: 5\r\nConnection: close, x-hop\r\nKeep-Alive: timeout=5\r\nX-Hop: remove-me\r\n\r\nhello"
      )
      .as_bytes(),
    )
    .await
    .unwrap();
  let mut response = Vec::new();
  client.read_to_end(&mut response).await.unwrap();
  assert!(
    response.starts_with(b"HTTP/1.1 201 Created"),
    "unexpected response: {}",
    String::from_utf8_lossy(&response)
  );
  assert!(String::from_utf8_lossy(&response)
    .to_ascii_lowercase()
    .contains("content-length: 5\r\n"));
  assert!(response.windows(5).any(|window| window == b"world"));

  let response_text = String::from_utf8_lossy(&response);
  let generated_request_id = response_text
    .lines()
    .find_map(|line| {
      line
        .split_once(':')
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
    })
    .map(|(_, value)| value.trim())
    .expect("proxy response missing generated request id");
  let generated_uuid = generated_request_id
    .strip_prefix("req-")
    .expect("proxy request id missing req- prefix");
  assert!(uuid::Uuid::parse_str(generated_uuid).is_ok());

  let request = String::from_utf8(received.await.unwrap()).unwrap();
  assert!(request.starts_with("POST /opaque?x=1 HTTP/1.1\r\n"));
  assert!(request.contains("authorization: Bearer codex-client-token\r\n"));
  let request_lower = request.to_ascii_lowercase();
  assert!(request_lower.contains(&format!("x-request-id: {}\r\n", generated_request_id)));
  for removed in ["proxy-authorization", "connection:", "keep-alive:", "x-hop:"] {
    assert!(!request_lower.contains(removed), "forwarded request retained {removed}");
  }
  assert!(request.ends_with("hello"));

  let events = std::iter::from_fn(|| event_rx.try_recv().ok()).collect::<Vec<_>>();
  let inbound = events.iter().find_map(|event| {
    let Event::Requests(request) = &**event else {
      return None;
    };
    match &request.payload {
      RequestEventPayload::Record(RecordEvent::InboundConnection {
        local_addr,
        peer_addr,
        mode,
        method,
        inbound_method,
        url,
        ..
      }) => Some((
        request.request_id.clone(),
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
  let (request_id, local_addr, peer_addr, mode, pipeline_id, inbound_method, inbound_url) =
    inbound.expect("proxy request did not emit an inbound connection event");
  assert_eq!(request_id.as_str(), generated_request_id);
  assert_eq!(local_addr.as_deref(), Some(proxy_addr.to_string().as_str()));
  assert_eq!(peer_addr.as_deref(), Some(client_addr.to_string().as_str()));
  assert_eq!(mode.as_str(), "passthrough");
  assert_eq!(pipeline_id.as_str(), "proxy");
  assert_eq!(inbound_method.as_str(), "POST");
  assert_eq!(
    inbound_url.as_deref(),
    Some(format!("http://{upstream_addr}/opaque?x=1").as_str())
  );

  let resolved = events.iter().find_map(|event| {
    let Event::Requests(request) = &**event else {
      return None;
    };
    match &request.payload {
      RequestEventPayload::Stage(StageEvent::Resolve(summary)) => Some(summary.clone()),
      _ => None,
    }
  });
  let resolved = resolved.expect("proxy request did not emit a resolve event");
  assert_eq!(resolved.provider_id.as_str(), "codex");
  assert_eq!(resolved.account_id.as_str(), "codex-primary");

  shutdown_tx.send(()).unwrap();
  proxy_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn v2_forward_proxy_rejects_bodies_over_the_configured_limit() {
  let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_addr = probe.local_addr().unwrap();
  drop(probe);
  let config = format!(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
request_body_max_bytes = 4
default_http_action = {{ kind = "route", profile = "transparent" }}
default_connect = "reject"

[profiles.transparent]
route = "transparent"

[routes.transparent]
kind = "relay"
destination = {{ kind = "original" }}
credentials = {{ kind = "client" }}
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-forward-proxy.toml")).unwrap();
  let state =
    tokn_router::v2::build_runtime_states(plan, &[], Arc::new(AccessStore::disabled()), Arc::new(EventBus::noop()))
      .unwrap()
      .forward_proxy
      .pop()
      .unwrap();
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(
      b"POST http://127.0.0.1:1/opaque HTTP/1.1\r\nHost: 127.0.0.1:1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await
    .unwrap();
  let mut response = Vec::new();
  client.read_to_end(&mut response).await.unwrap();
  assert!(
    response.starts_with(b"HTTP/1.1 413 Payload Too Large"),
    "unexpected response: {}",
    String::from_utf8_lossy(&response)
  );

  shutdown_tx.send(()).unwrap();
  proxy_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn v2_forward_proxy_intercepts_tls_and_reuses_http_policy() {
  let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_addr = probe.local_addr().unwrap();
  drop(probe);
  let ca = tempfile::tempdir().unwrap();
  let ca_dir = toml_string(&ca.path().to_string_lossy());
  let config = format!(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
default_connect = "intercept"
ca_dir = {ca_dir}
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-forward-proxy.toml")).unwrap();
  let state =
    tokn_router::v2::build_runtime_states(plan, &[], Arc::new(AccessStore::disabled()), Arc::new(EventBus::noop()))
      .unwrap()
      .forward_proxy
      .pop()
      .unwrap();
  let cert_path = ca.path().join("ca.crt");
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut tls = connect_intercepted_tls(proxy_addr, "api.example.test", &cert_path).await;
  tls
    .write_all(
      b"POST /v1/responses HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
  let mut response = Vec::new();
  tls.read_to_end(&mut response).await.unwrap();
  assert!(response.starts_with(b"HTTP/1.1 403 Forbidden"));
  let response = String::from_utf8(response).unwrap();
  let generated_request_id = response
    .lines()
    .find_map(|line| {
      line
        .split_once(':')
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-request-id"))
    })
    .map(|(_, value)| value.trim())
    .expect("intercepted response missing generated request id");
  assert!(generated_request_id.starts_with("req-"));
  assert!(uuid::Uuid::parse_str(&generated_request_id[4..]).is_ok());

  shutdown_tx.send(()).unwrap();
  proxy_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn v2_forward_proxy_rejects_intercepted_websocket_before_dispatch() {
  let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let upstream_addr = upstream.local_addr().unwrap();
  let (upstream_tx, mut upstream_rx) = tokio::sync::mpsc::channel(1);
  let upstream_task = tokio::spawn(async move {
    let (mut stream, _) = upstream.accept().await.unwrap();
    upstream_tx.send(()).await.unwrap();
    stream
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      .await
      .unwrap();
  });

  let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_addr = probe.local_addr().unwrap();
  drop(probe);
  let ca = tempfile::tempdir().unwrap();
  let ca_dir = toml_string(&ca.path().to_string_lossy());
  let config = format!(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "transparent" }}
default_connect = "intercept"
ca_dir = {ca_dir}

[profiles.transparent]
route = "transparent"

[routes.transparent]
kind = "relay"
destination = {{ kind = "fixed_provider", provider = "local" }}
credentials = {{ kind = "client" }}

[providers.local]
driver = "openai"
base_url = "http://{upstream_addr}/v1"
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-forward-proxy.toml")).unwrap();
  let events = Arc::new(EventBus::new(16));
  let mut event_rx = events.subscribe();
  let state = tokn_router::v2::build_runtime_states(plan, &[], Arc::new(AccessStore::disabled()), events)
    .unwrap()
    .forward_proxy
    .pop()
    .unwrap();
  let cert_path = ca.path().join("ca.crt");
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut tls = connect_intercepted_tls(proxy_addr, "api.example.test", &cert_path).await;
  tls
    .write_all(
      b"GET /backend-api/wham/remote/control/server HTTP/1.1\r\nHost: api.example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
  let response = read_response_head(&mut tls).await;
  assert!(
    response.starts_with("HTTP/1.1 426 Upgrade Required"),
    "unexpected response: {response:?}"
  );
  let response_lower = response.to_ascii_lowercase();
  assert!(response_lower.contains("connection: upgrade\r\n"));
  assert!(response_lower.contains("upgrade: websocket\r\n"));
  assert!(upstream_rx.try_recv().is_err(), "websocket request reached upstream");
  assert!(event_rx.try_recv().is_err(), "websocket request entered the pipeline");

  shutdown_tx.send(()).unwrap();
  proxy_task.await.unwrap().unwrap();
  upstream_task.abort();
}

#[tokio::test]
async fn v2_forward_proxy_relay_selects_provider_from_original_origin() {
  let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let upstream_addr = upstream.local_addr().unwrap();
  let received = tokio::spawn(async move {
    let (mut stream, _) = upstream.accept().await.unwrap();
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
      let read = stream.read(&mut buffer).await.unwrap();
      assert!(read > 0);
      request.extend_from_slice(&buffer[..read]);
      if request.windows(4).any(|window| window == b"\r\n\r\n") && request.ends_with(b"hello") {
        break;
      }
    }
    stream
      .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 5\r\nConnection: close\r\n\r\nretry")
      .await
      .unwrap();
    request
  });

  let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_addr = probe.local_addr().unwrap();
  drop(probe);
  let config = format!(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "relay" }}
default_connect = "reject"

[profiles.relay]
route = "relay"

[profiles.relay.account_pool]
accounts = ["acct"]

[routes.relay]
kind = "relay"
providers = ["*"]
destination = {{ kind = "original" }}
credentials = {{ kind = "account_pool" }}

[providers.local]
driver = "llama-cpp"
base_url = "http://{upstream_addr}/v1"
"#
  );
  let plan = tokn_config::v2::parse(&config, Path::new("v2-forward-proxy.toml")).unwrap();
  let account = toml::from_str(
    r#"
id = "acct"
provider = "local"
api_key = "router-secret"
"#,
  )
  .unwrap();
  let state = tokn_router::v2::build_runtime_states(
    plan,
    &[account],
    Arc::new(AccessStore::disabled()),
    Arc::new(EventBus::noop()),
  )
  .unwrap()
  .forward_proxy
  .pop()
  .unwrap();
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(
      format!(
        "POST http://{upstream_addr}/custom?x=1 HTTP/1.1\r\nHost: {upstream_addr}\r\nAuthorization: Bearer client-secret\r\nX-Request-Id: client-proxy-request\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
      )
      .as_bytes(),
    )
    .await
    .unwrap();
  let mut response = Vec::new();
  client.read_to_end(&mut response).await.unwrap();
  assert!(
    response.starts_with(b"HTTP/1.1 503 Service Unavailable"),
    "unexpected response: {}",
    String::from_utf8_lossy(&response)
  );
  assert!(response.windows(5).any(|window| window == b"retry"));
  assert!(String::from_utf8_lossy(&response)
    .to_ascii_lowercase()
    .contains("x-request-id: client-proxy-request\r\n"));

  let request = String::from_utf8(received.await.unwrap()).unwrap();
  assert!(request.starts_with("POST /custom?x=1 HTTP/1.1\r\n"));
  assert!(!request.contains("client-secret"));
  assert!(request
    .to_ascii_lowercase()
    .contains("authorization: bearer router-secret"));
  assert!(request
    .to_ascii_lowercase()
    .contains("x-request-id: client-proxy-request\r\n"));
  assert!(request.ends_with("hello"));

  shutdown_tx.send(()).unwrap();
  proxy_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn v2_forward_proxy_shutdown_cancels_an_active_tunnel() {
  let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let upstream_addr = upstream.local_addr().unwrap();
  let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy_addr = probe.local_addr().unwrap();
  drop(probe);
  let plan = tokn_config::v2::parse(
    &format!(
      r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
default_connect = "tunnel"
"#
    ),
    Path::new("v2-forward-proxy.toml"),
  )
  .unwrap();
  let state =
    tokn_router::v2::build_runtime_states(plan, &[], Arc::new(AccessStore::disabled()), Arc::new(EventBus::noop()))
      .unwrap()
      .forward_proxy
      .pop()
      .unwrap();
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n").as_bytes())
    .await
    .unwrap();
  assert!(read_response_head(&mut client).await.starts_with("HTTP/1.1 200"));
  let (mut upstream_stream, _) = upstream.accept().await.unwrap();

  shutdown_tx.send(()).unwrap();
  tokio::time::timeout(std::time::Duration::from_secs(1), proxy_task)
    .await
    .unwrap()
    .unwrap()
    .unwrap();
  let mut byte = [0_u8; 1];
  assert_eq!(
    tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
      .await
      .unwrap()
      .unwrap(),
    0
  );
  assert_eq!(
    tokio::time::timeout(std::time::Duration::from_secs(1), upstream_stream.read(&mut byte))
      .await
      .unwrap()
      .unwrap(),
    0
  );
}

#[tokio::test]
async fn profile_owned_proxy_pools_and_client_relays_enforce_route_provider_restrictions() {
  let allowed = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let allowed_addr = allowed.local_addr().unwrap();
  let blocked = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let blocked_addr = blocked.local_addr().unwrap();
  let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(2);
  let upstream = tokio::spawn(async move {
    for _ in 0..2 {
      let (mut stream, _) = allowed.accept().await.unwrap();
      let request = read_response_head(&mut stream).await;
      capture_tx.send(request).await.unwrap();
      stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .unwrap();
    }
  });
  for credentials in ["account_pool", "client"] {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = probe.local_addr().unwrap();
    drop(probe);
    let pool = if credentials == "account_pool" {
      "account_pool = { accounts = ['allowed-account', 'blocked-account'] }"
    } else {
      ""
    };
    let config = format!(
      r#"
schema_version = 2
[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
default_http_action = {{ kind = "route", profile = "relay" }}
default_connect = "reject"
[profiles.relay]
route = "relay"
{pool}
[routes.relay]
kind = "relay"
providers = ["allowed"]
destination = {{ kind = "original" }}
credentials = {{ kind = "{credentials}" }}
[providers.allowed]
driver = "llama-cpp"
base_url = "http://{allowed_addr}/v1"
[providers.blocked]
driver = "llama-cpp"
base_url = "http://{blocked_addr}/v1"
"#
    );
    let accounts = ["allowed", "blocked"].map(|provider| {
      toml::from_str(&format!(
        "id = '{provider}-account'\nprovider = '{provider}'\napi_key = 'router-secret'\nenabled = true"
      ))
      .unwrap()
    });
    let plan = tokn_config::v2::parse(&config, Path::new("proxy-profile.toml")).unwrap();
    assert!(plan.profiles()["relay"].api_binding().is_none());
    let state = tokn_router::v2::build_runtime_states(
      plan,
      &accounts,
      Arc::new(AccessStore::disabled()),
      Arc::new(EventBus::noop()),
    )
    .unwrap()
    .forward_proxy
    .pop()
    .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
      let _ = shutdown_rx.await;
    }));
    wait_for_listener(proxy_addr).await;
    // Account relays preserve the existing unowned-origin 400 response;
    // restricted client relays report a provider-policy denial.
    let denied = if credentials == "account_pool" {
      "HTTP/1.1 400"
    } else {
      "HTTP/1.1 403"
    };
    for (destination, expected) in [(blocked_addr, denied), (allowed_addr, "HTTP/1.1 200")] {
      let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
      stream.write_all(format!("GET http://{destination}/custom HTTP/1.1\r\nHost: {destination}\r\nAuthorization: Bearer client-secret\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
      let response = read_response_head(&mut stream).await;
      assert!(response.starts_with(expected), "{credentials}: {response}");
    }
    let captured = capture_rx.recv().await.unwrap().to_ascii_lowercase();
    assert!(captured.starts_with("get /custom http/1.1"));
    let key = if credentials == "client" {
      "client-secret"
    } else {
      "router-secret"
    };
    assert!(captured.contains(&format!("authorization: bearer {key}")));
    assert!(
      tokio::time::timeout(std::time::Duration::from_millis(20), blocked.accept())
        .await
        .is_err()
    );
    shutdown_tx.send(()).unwrap();
    proxy.await.unwrap().unwrap();
  }
  upstream.await.unwrap();
}

async fn connect(proxy_addr: std::net::SocketAddr, authority: &str, token: Option<&str>) -> String {
  let authorization = token.map(|token| format!("Bearer {token}"));
  let authorization = authorization.iter().map(String::as_str).collect::<Vec<_>>();
  connect_with_authorization(proxy_addr, authority, &authorization).await
}

async fn connect_with_authorization(
  proxy_addr: std::net::SocketAddr,
  authority: &str,
  authorization: &[&str],
) -> String {
  let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
  let authorization = authorization
    .iter()
    .map(|value| format!("Proxy-Authorization: {value}\r\n"))
    .collect::<String>();
  stream
    .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{authorization}\r\n").as_bytes())
    .await
    .unwrap();
  read_response_head(&mut stream).await
}

async fn read_response_head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
  let mut response = Vec::new();
  let mut byte = [0_u8; 1];
  while !response.ends_with(b"\r\n\r\n") {
    stream.read_exact(&mut byte).await.unwrap();
    response.push(byte[0]);
  }
  String::from_utf8(response).unwrap()
}

async fn connect_intercepted_tls(
  proxy_addr: std::net::SocketAddr,
  host: &str,
  cert_path: &Path,
) -> tokio_rustls::client::TlsStream<TcpStream> {
  let mut client = TcpStream::connect(proxy_addr).await.unwrap();
  client
    .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
    .await
    .unwrap();
  let head = read_response_head(&mut client).await;
  assert!(
    head.starts_with("HTTP/1.1 200"),
    "unexpected CONNECT response: {head:?}"
  );

  let cert_file = std::fs::File::open(cert_path).unwrap();
  let mut cert_reader = std::io::BufReader::new(cert_file);
  let certs = rustls_pemfile::certs(&mut cert_reader)
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(certs[0].clone()).unwrap();
  let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
  let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
  tokio_rustls::TlsConnector::from(Arc::new(tls))
    .connect(server_name, client)
    .await
    .unwrap()
}

async fn wait_for_listener(addr: std::net::SocketAddr) {
  for _ in 0..50 {
    if TcpStream::connect(addr).await.is_ok() {
      return;
    }
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
  }
  panic!("proxy listener did not start at {addr}");
}

fn toml_string(value: &str) -> String {
  toml::Value::String(value.to_string()).to_string()
}

#[test]
fn proxy_test_config_escapes_windows_paths() {
  let path = r"C:\Users\runneradmin\AppData\Local\Temp\.tmp-ca";
  let parsed = toml::from_str::<toml::Value>(&format!("ca_dir = {}", toml_string(path))).unwrap();
  assert_eq!(parsed["ca_dir"].as_str(), Some(path));
}

use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokn_access::AccessStore;
use tokn_core::event::EventBus;

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
  let state = tokn_router::v2::build_forward_proxy_states(&plan, access)
    .unwrap()
    .pop()
    .unwrap();
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
  let proxy_task = tokio::spawn(tokn_router::v2::serve_forward_proxy(state, proxy_addr, async {
    let _ = shutdown_rx.await;
  }));
  wait_for_listener(proxy_addr).await;

  let mut unauthenticated_get = TcpStream::connect(proxy_addr).await.unwrap();
  unauthenticated_get
    .write_all(b"GET / HTTP/1.1\r\nHost: proxy\r\n\r\n")
    .await
    .unwrap();
  assert!(read_response_head(&mut unauthenticated_get)
    .await
    .starts_with("HTTP/1.1 407 Proxy Authentication Required"));

  let unauthenticated = connect(proxy_addr, "blocked.example:443", None).await;
  assert!(unauthenticated.starts_with("HTTP/1.1 407 Proxy Authentication Required"));

  let rejected = connect(proxy_addr, "blocked.example:443", Some(&key.token)).await;
  assert!(rejected.starts_with("HTTP/1.1 403 Forbidden"));

  let mut tunnel = TcpStream::connect(proxy_addr).await.unwrap();
  tunnel
    .write_all(
      format!(
        "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        key.token
      )
      .as_bytes(),
    )
    .await
    .unwrap();
  let response = read_response_head(&mut tunnel).await;
  assert!(response.starts_with("HTTP/1.1 200 Connection Established"));
  tunnel.write_all(b"ping").await.unwrap();
  let mut reply = [0_u8; 4];
  tunnel.read_exact(&mut reply).await.unwrap();
  assert_eq!(&reply, b"pong");

  upstream_task.await.unwrap();
  shutdown_tx.send(()).unwrap();
  proxy_task.await.unwrap().unwrap();
}

#[test]
fn v2_forward_proxy_rejects_interception_until_http_dispatch_is_adapted() {
  let plan = tokn_config::v2::parse(
    r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "127.0.0.1:8080"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "intercept"
ca_dir = "certificates"
"#,
    Path::new("v2-forward-proxy.toml"),
  )
  .unwrap();
  let error = tokn_router::v2::build_forward_proxy_states(&plan, Arc::new(AccessStore::disabled()))
    .err()
    .unwrap();
  assert!(error.to_string().contains("CONNECT interception"));
}

async fn connect(proxy_addr: std::net::SocketAddr, authority: &str, token: Option<&str>) -> String {
  let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
  let authorization = token
    .map(|token| format!("Proxy-Authorization: Bearer {token}\r\n"))
    .unwrap_or_default();
  stream
    .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{authorization}\r\n").as_bytes())
    .await
    .unwrap();
  read_response_head(&mut stream).await
}

async fn read_response_head(stream: &mut TcpStream) -> String {
  let mut response = Vec::new();
  let mut byte = [0_u8; 1];
  while !response.ends_with(b"\r\n\r\n") {
    stream.read_exact(&mut byte).await.unwrap();
    response.push(byte[0]);
  }
  String::from_utf8(response).unwrap()
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

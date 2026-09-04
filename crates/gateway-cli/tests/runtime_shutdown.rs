//! Real process signals, isolated config/auth homes, and real persistence.
#![cfg(unix)]

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokn_config::v2;

const WAIT: Duration = Duration::from_secs(10);

fn free_address() -> SocketAddr {
  std::net::TcpListener::bind("127.0.0.1:0")
    .unwrap()
    .local_addr()
    .unwrap()
}

fn start(home: &Path, config: &Path) -> Child {
  let stderr = fs::File::create(home.join("stderr.log")).unwrap();
  Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
    .arg("--config")
    .arg(config)
    .arg("serve")
    // Only the child gets an isolated home; never read or mutate user auth.
    .env("HOME", home)
    .env_remove("RUST_LOG")
    .env_remove("HTTP_PROXY")
    .env_remove("HTTPS_PROXY")
    .env_remove("ALL_PROXY")
    .stdout(Stdio::null())
    .stderr(stderr)
    .kill_on_drop(true)
    .spawn()
    .unwrap()
}

async fn ready(child: &mut Child, address: SocketAddr, home: &Path) {
  let client = reqwest::Client::builder().no_proxy().build().unwrap();
  tokio::time::timeout(WAIT, async {
    loop {
      assert!(
        child.try_wait().unwrap().is_none(),
        "gateway exited: {}",
        fs::read_to_string(home.join("stderr.log")).unwrap()
      );
      if client.get(format!("http://{address}/health")).send().await.is_ok() {
        return;
      }
      tokio::time::sleep(Duration::from_millis(20)).await;
    }
  })
  .await
  .expect("gateway ready deadline");
}

fn signal(child: &Child, signal: &str) {
  assert!(std::process::Command::new("kill")
    .arg(signal)
    .arg(child.id().expect("running child").to_string())
    .status()
    .unwrap()
    .success());
}

async fn wait_for_closed_listener(address: SocketAddr) {
  tokio::time::timeout(WAIT, async {
    while TcpStream::connect(address).await.is_ok() {
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .expect("accept socket must close before streams finish");
}

async fn assert_clean_exit(child: &mut Child, home: &Path) {
  let status = tokio::time::timeout(WAIT, child.wait())
    .await
    .expect("shutdown deadline")
    .unwrap();
  let log = fs::read_to_string(home.join("stderr.log")).unwrap();
  assert!(status.success(), "{status}: {log}");
  assert!(log.contains("shutdown persistence cleanup complete"), "{log}");
}

#[tokio::test]
async fn sigint_and_sigterm_drain_streams_and_flush_request_records() {
  for signal_name in ["-INT", "-TERM"] {
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("config.toml");
    let requests_dir = home.path().join("requests");
    let address = free_address();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (release, released) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
      let (mut stream, _) = upstream.accept().await.unwrap();
      let mut header = Vec::new();
      while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
      }
      let header = String::from_utf8(header).unwrap();
      let length = header
        .lines()
        .find_map(|line| {
          let (name, value) = line.split_once(':')?;
          name
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
      stream.read_exact(&mut vec![0; length]).await.unwrap();
      let first = "data: {\"id\":\"fixture\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n";
      let last = "data: [DONE]\n\n";
      stream
        .write_all(
          format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{first}",
        first.len() + last.len()
      )
          .as_bytes(),
        )
        .await
        .unwrap();
      released.await.unwrap();
      stream.write_all(last.as_bytes()).await.unwrap();
    });
    let source = format!(
      r#"
schema_version = 2
[listeners.api]
kind = "llm_api"
bind = "{address}"
client_auth = "none"
[profiles.default]
route = "relay"
[routes.relay]
kind = "relay"
destination = {{ kind = "fixed_provider", provider = "local" }}
credentials = {{ kind = "client" }}
[providers.local]
driver = "openai"
base_url = "http://{upstream_address}/v1"
"#
    );
    let mut raw = v2::decode(&source, &config_path).unwrap();
    raw.service.logging.target = tokn_config::LogTarget::Stderr;
    raw.service.persistence.requests_dir = Some(requests_dir.clone());
    raw.service.persistence.usage_db_path = Some(home.path().join("usage.db"));
    raw.service.persistence.sessions_db_path = Some(home.path().join("sessions.db"));
    fs::write(&config_path, toml::to_string(&raw).unwrap()).unwrap();
    let mut child = start(home.path(), &config_path);
    ready(&mut child, address, home.path()).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut response = tokio::time::timeout(
      WAIT,
      client
        .post(format!("http://{address}/v1/chat/completions"))
        .header("x-request-id", "shutdown-fixture")
        .json(&serde_json::json!({"model": "fixture", "messages": [], "stream": true}))
        .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), 200);
    assert!(tokio::time::timeout(WAIT, response.chunk())
      .await
      .unwrap()
      .unwrap()
      .is_some());
    signal(&child, signal_name);
    wait_for_closed_listener(address).await;
    assert!(child.try_wait().unwrap().is_none(), "must wait for the admitted stream");
    release.send(()).unwrap();
    let remaining = tokio::time::timeout(WAIT, response.bytes()).await.unwrap().unwrap();
    assert!(remaining.ends_with(b"data: [DONE]\n\n"));
    upstream_task.await.unwrap();
    assert_clean_exit(&mut child, home.path()).await;
    let row = tokn_persistence::read_request_row(&requests_dir, "shutdown-fixture")
      .unwrap()
      .expect("flushed request row");
    assert_eq!(row["inbound_req_method"], "POST");
    assert!(row["ctx_json"]["latency_ms"].is_number(), "{row:?}");
  }
}

#[tokio::test]
async fn projected_v1_also_shuts_down_cleanly_on_sigterm() {
  let home = tempfile::tempdir().unwrap();
  let path = home.path().join("config.toml");
  let address = free_address();
  let source = format!(
    r#"
[server]
host = "127.0.0.1"
port = {}
[logging]
target = "stderr"
[db]
enabled = false
"#,
    address.port()
  );
  fs::write(&path, source).unwrap();
  let auth_path = home.path().join(".tokn/router/auth.yaml");
  let mut auth = tokn_auth::AuthStore::load(Some(&auth_path), None).unwrap();
  auth.upsert(toml::from_str("id = 'fixture'\nprovider = 'openai'\napi_key = 'not-a-real-key'").unwrap());
  auth.save().unwrap();
  let mut child = start(home.path(), &path);
  ready(&mut child, address, home.path()).await;
  signal(&child, "-TERM");
  assert_clean_exit(&mut child, home.path()).await;
}

#[tokio::test]
async fn bind_failure_closes_sibling_listener_and_flushes_before_exiting() {
  let home = tempfile::tempdir().unwrap();
  let path = home.path().join("config.toml");
  let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let occupied_address = occupied.local_addr().unwrap();
  let sibling = free_address();
  let source = format!(
    r#"
schema_version = 2
[service.logging]
target = "stderr"
[service.persistence]
enabled = false
[listeners.a]
kind = "llm_api"
bind = "{sibling}"
client_auth = "none"
[listeners.z]
kind = "llm_api"
bind = "{occupied_address}"
client_auth = "none"
"#
  );
  fs::write(&path, source).unwrap();
  let mut child = start(home.path(), &path);
  let status = tokio::time::timeout(WAIT, child.wait()).await.unwrap().unwrap();
  assert!(!status.success());
  let log = fs::read_to_string(home.path().join("stderr.log")).unwrap();
  assert!(log.contains("shutdown persistence cleanup complete"), "{log}");
  assert!(TcpStream::connect(sibling).await.is_err());
}

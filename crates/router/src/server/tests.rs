use super::*;
use axum::routing::get;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Notify};

#[tokio::test]
async fn shutdown_drains_an_admitted_response_and_keeps_connection_metadata() {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let started = Arc::new(Notify::new());
  let release = Arc::new(Notify::new());
  let app = Router::new().route(
    "/work",
    get({
      let started = started.clone();
      let release = release.clone();
      move |ConnectInfo(peer): ConnectInfo<SocketAddr>, Extension(local): Extension<SocketAddr>| {
        let started = started.clone();
        let release = release.clone();
        async move {
          assert_eq!(local, address);
          assert!(peer.ip().is_loopback());
          started.notify_one();
          release.notified().await;
          "finished"
        }
      }
    }),
  );
  let (stop, stopped) = oneshot::channel();
  let server = tokio::spawn(serve_http(app, listener, async { stopped.await.unwrap() }));
  let mut client = TcpStream::connect(address).await.unwrap();
  client
    .write_all(b"GET /work HTTP/1.1\r\nHost: localhost\r\n\r\n")
    .await
    .unwrap();
  tokio::time::timeout(Duration::from_secs(2), started.notified())
    .await
    .unwrap();
  stop.send(()).unwrap();
  // A refused TCP connect can itself take several seconds on Windows. Keep
  // checking actual closure, but budget OS refusal latency, not only scheduling.
  tokio::time::timeout(Duration::from_secs(10), async {
    loop {
      match TcpStream::connect(address).await {
        Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        Err(error) => {
          assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
          break;
        }
      }
    }
  })
  .await
  .expect("accept socket must close while the admitted response is still active");
  assert!(!server.is_finished());
  release.notify_one();
  let mut response = String::new();
  tokio::time::timeout(Duration::from_secs(2), client.read_to_string(&mut response))
    .await
    .unwrap()
    .unwrap();
  assert!(response.starts_with("HTTP/1.1 200"));
  assert!(response.ends_with("finished"));
  server.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_closes_idle_keepalive_connections() {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let (stop, stopped) = oneshot::channel();
  let server = tokio::spawn(serve_http(Router::new(), listener, async { stopped.await.unwrap() }));
  let mut client = TcpStream::connect(address).await.unwrap();
  client
    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    .await
    .unwrap();
  let mut head = Vec::new();
  while !head.ends_with(b"\r\n\r\n") {
    head.push(client.read_u8().await.unwrap());
  }
  stop.send(()).unwrap();
  tokio::time::timeout(Duration::from_secs(2), server)
    .await
    .unwrap()
    .unwrap()
    .unwrap();
  assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}

struct Dropped(Arc<AtomicBool>);

impl Drop for Dropped {
  fn drop(&mut self) {
    self.0.store(true, Ordering::SeqCst);
  }
}

#[tokio::test]
async fn grace_deadline_cancels_and_joins_stalled_connections() {
  let dropped = Arc::new(AtomicBool::new(false));
  let guard = Dropped(dropped.clone());
  let mut connections = JoinSet::new();
  connections.spawn(async move {
    let _guard = guard;
    std::future::pending::<()>().await;
  });
  let error = drain_connections(&mut connections, Duration::from_millis(20))
    .await
    .unwrap_err();
  assert!(error.to_string().contains("grace period expired"));
  assert!(connections.is_empty());
  assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn completed_and_empty_connection_sets_drain_successfully() {
  let mut connections = JoinSet::new();
  drain_connections(&mut connections, Duration::from_secs(1))
    .await
    .unwrap();
  connections.spawn(async {});
  drain_connections(&mut connections, Duration::from_secs(1))
    .await
    .unwrap();
  assert!(connections.is_empty());
}

#[tokio::test]
async fn failed_connection_tasks_are_joined_without_stalling_other_connections() {
  let mut connections = JoinSet::new();
  connections.spawn(async { panic!("fixture connection panic") });
  connections.spawn(async {});
  drain_connections(&mut connections, Duration::from_secs(2))
    .await
    .unwrap();
  assert!(connections.is_empty());
}

#[tokio::test]
async fn shutdown_watch_handles_existing_signal_and_dropped_sender() {
  let (sender, mut receiver) = watch::channel(true);
  tokio::time::timeout(Duration::from_secs(2), shutdown_requested(&mut receiver))
    .await
    .unwrap();
  sender.send(false).unwrap();
  drop(sender);
  tokio::time::timeout(Duration::from_secs(2), shutdown_requested(&mut receiver))
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_http_does_not_stop_the_listener() {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let (stop, stopped) = oneshot::channel();
  let server = tokio::spawn(serve_http(Router::new(), listener, async { stopped.await.unwrap() }));
  for (request, expected) in [
    ("not http\r\n\r\n", "HTTP/1.1 400"),
    (
      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
      "HTTP/1.1 404",
    ),
  ] {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
      .await
      .unwrap()
      .unwrap();
    assert!(response.starts_with(expected), "{response:?}");
  }
  stop.send(()).unwrap();
  tokio::time::timeout(Duration::from_secs(5), server)
    .await
    .unwrap()
    .unwrap()
    .unwrap();
}

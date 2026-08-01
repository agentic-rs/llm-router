//! HTTP/1 connection ownership and coordinated listener shutdown.
//!
//! Every listener and client connection is owned by a tracked `JoinSet`.
//! Shutdown stops new accepts, cancels HTTP connections and raw tunnels at a
//! well-defined boundary, and waits for every task to release its generation.

use super::adapter::{handle_forward_proxy_request, handle_intercepted_https_request, handle_llm_api_request};
use super::connect::{
  connect_upgrade_channel, ConnectRunError, ConnectRunOutcome, ConnectRunReport, ConnectRunResult, ConnectTransport,
  ConnectUpgrade,
};
use super::{BoundGatewayListeners, BoundListener, ListenerServerState};
use axum::body::Body;
use http::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use snafu::Snafu;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokn_policy::{ListenerId, ListenerKind};

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Serve every pre-bound listener until the supplied shutdown future resolves.
///
/// Sockets are already bound atomically. This phase starts one tracked accept
/// loop per listener and one tracked task per connection. Shutdown is a
/// cancellation boundary for active requests and tunnels, so an idle CONNECT
/// cannot keep an old runtime generation alive indefinitely.
pub async fn serve_gateway_listeners<F>(bound: BoundGatewayListeners, shutdown: F) -> GatewayServeResult<()>
where
  F: Future<Output = ()> + Send,
{
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let mut listeners = JoinSet::new();
  for (listener_id, listener) in bound.into_listeners() {
    let listener_shutdown = shutdown_rx.clone();
    listeners.spawn(async move {
      serve_bound_listener(listener_id.clone(), listener, listener_shutdown).await;
      listener_id
    });
  }
  drop(shutdown_rx);

  tokio::pin!(shutdown);
  if listeners.is_empty() {
    shutdown.await;
    return Ok(());
  }

  let mut failure = tokio::select! {
    _ = &mut shutdown => None,
    joined = listeners.join_next() => {
      Some(unexpected_listener_exit(joined.expect("a nonempty listener set has one task to join")))
    }
  };

  let _ = shutdown_tx.send(true);
  while let Some(joined) = listeners.join_next().await {
    if let Err(source) = joined {
      failure.get_or_insert(GatewayServeError::ListenerTask { source });
    }
  }

  match failure {
    Some(error) => Err(error),
    None => Ok(()),
  }
}

fn unexpected_listener_exit(joined: Result<ListenerId, JoinError>) -> GatewayServeError {
  match joined {
    Ok(listener) => GatewayServeError::UnexpectedListenerExit { listener },
    Err(source) => GatewayServeError::ListenerTask { source },
  }
}

async fn serve_bound_listener(listener_id: ListenerId, listener: BoundListener, mut shutdown: watch::Receiver<bool>) {
  let (socket, state) = listener.into_parts();
  let address = socket.local_addr().unwrap_or_else(|error| {
    tracing::warn!(listener = %listener_id, %error, "failed to inspect bound listener address");
    state.listener().bind()
  });
  let kind = state.listener().kind();
  tracing::info!(listener = %listener_id, ?kind, %address, "gateway listener started");

  let mut connections = JoinSet::new();
  loop {
    if *shutdown.borrow() {
      break;
    }

    tokio::select! {
      biased;
      _ = shutdown_requested(&mut shutdown) => break,
      joined = connections.join_next(), if !connections.is_empty() => {
        log_connection_result(&listener_id, joined.expect("a nonempty connection set has one task to join"));
      }
      accepted = socket.accept() => match accepted {
        Ok((stream, peer)) => {
          let state = state.clone();
          let connection_shutdown = shutdown.clone();
          connections.spawn(async move {
            let result = serve_connection(stream, state, connection_shutdown).await;
            (peer, result)
          });
        }
        Err(source) => {
          let retry_immediately = matches!(
            source.kind(),
            io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
          );
          if retry_immediately {
            tracing::debug!(listener = %listener_id, ?kind, %address, %source, "listener accept was interrupted");
            continue;
          }

          tracing::error!(
            listener = %listener_id,
            ?kind,
            %address,
            %source,
            retry_after_seconds = ACCEPT_ERROR_BACKOFF.as_secs(),
            "listener accept failed"
          );
          tokio::select! {
            _ = shutdown_requested(&mut shutdown) => break,
            _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
          }
        }
      }
    }
  }

  while let Some(joined) = connections.join_next().await {
    log_connection_result(&listener_id, joined);
  }
  tracing::info!(listener = %listener_id, ?kind, %address, "gateway listener stopped");
}

async fn serve_connection(
  stream: TcpStream,
  state: Arc<ListenerServerState>,
  shutdown: watch::Receiver<bool>,
) -> ConnectionServeResult<ConnectionOutcome> {
  match state.listener().kind() {
    ListenerKind::LlmApi => {
      serve_llm_api_connection(stream, state, shutdown).await?;
      Ok(ConnectionOutcome::Http)
    }
    ListenerKind::ForwardProxy => match serve_forward_proxy_connection(stream, state, shutdown).await? {
      Some(report) => Ok(ConnectionOutcome::Connect(report)),
      None => Ok(ConnectionOutcome::Http),
    },
  }
}

async fn serve_llm_api_connection(
  stream: TcpStream,
  state: Arc<ListenerServerState>,
  mut shutdown: watch::Receiver<bool>,
) -> ConnectionServeResult<()> {
  let service = service_fn(move |request: Request<Incoming>| {
    let state = state.clone();
    async move {
      let response = handle_llm_api_request(&state, request.map(Body::new)).await;
      Ok::<_, Infallible>(response)
    }
  });
  let builder = http1_builder();
  let connection = builder.serve_connection(TokioIo::new(stream), service);
  tokio::pin!(connection);

  tokio::select! {
    result = &mut connection => result.map_err(|source| ConnectionServeError::Http { source }),
    _ = shutdown_requested(&mut shutdown) => Ok(()),
  }
}

async fn serve_forward_proxy_connection(
  stream: TcpStream,
  state: Arc<ListenerServerState>,
  mut shutdown: watch::Receiver<bool>,
) -> ConnectionServeResult<Option<ConnectRunReport>> {
  let (upgrades, mut upgrade_receiver) = connect_upgrade_channel();
  let upgrade_state = state.clone();
  let service = service_fn(move |request: Request<Incoming>| {
    let state = state.clone();
    let upgrades = upgrades.clone();
    async move {
      let response = handle_forward_proxy_request(&state, request.map(Body::new), &upgrades).await;
      Ok::<_, Infallible>(response)
    }
  });

  let connection_result = {
    let builder = http1_builder();
    let connection = builder.serve_connection(TokioIo::new(stream), service).with_upgrades();
    tokio::pin!(connection);
    tokio::select! {
      result = &mut connection => result,
      _ = shutdown_requested(&mut shutdown) => return Ok(None),
    }
  };
  let upgrade = upgrade_receiver.recv().await;
  connection_result.map_err(|source| ConnectionServeError::Http { source })?;

  let Some(upgrade) = upgrade else {
    return Ok(None);
  };
  tokio::select! {
    result = run_connect_upgrade(upgrade, upgrade_state) => {
      result.map(Some).map_err(|source| ConnectionServeError::Connect { source })
    },
    _ = shutdown_requested(&mut shutdown) => Ok(None),
  }
}

async fn run_connect_upgrade(
  upgrade: ConnectUpgrade,
  state: Arc<ListenerServerState>,
) -> ConnectRunResult<ConnectRunReport> {
  let (session, on_upgrade, transport) = upgrade.into_parts();
  let site = session.dispatch().site().clone();
  let upgraded = on_upgrade.await.map_err(|source| ConnectRunError::DownstreamUpgrade {
    site: site.clone(),
    source,
  })?;
  let downstream = TokioIo::new(upgraded);

  match transport {
    ConnectTransport::Tunnel { mut upstream } => {
      let mut downstream = downstream;
      let (client_to_upstream, upstream_to_client) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
        .await
        .map_err(|source| ConnectRunError::TunnelPump { site, source })?;
      Ok(ConnectRunReport::tunnel(
        session,
        client_to_upstream,
        upstream_to_client,
      ))
    }
    ConnectTransport::Intercept { prepared } => {
      let tls = tokio::time::timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(prepared.into_config()).accept(downstream),
      )
      .await
      .map_err(|_| ConnectRunError::TlsHandshakeTimeout { site: site.clone() })?
      .map_err(|source| ConnectRunError::TlsHandshake {
        site: site.clone(),
        source,
      })?;

      let request_session = session.clone();
      let service = service_fn(move |request: Request<Incoming>| {
        let state = state.clone();
        let session = request_session.clone();
        async move {
          let response = handle_intercepted_https_request(&state, &session, request.map(Body::new)).await;
          Ok::<_, Infallible>(response)
        }
      });
      let builder = http1_builder();
      builder
        .serve_connection(TokioIo::new(tls), service)
        .await
        .map_err(|source| ConnectRunError::InterceptHttp { site, source })?;
      Ok(ConnectRunReport::intercepted(session))
    }
  }
}

fn http1_builder() -> http1::Builder {
  let mut builder = http1::Builder::new();
  builder
    .half_close(true)
    .keep_alive(true)
    .timer(TokioTimer::new())
    .header_read_timeout(HTTP_HEADER_READ_TIMEOUT);
  builder
}

async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
  if *shutdown.borrow() {
    return;
  }
  let _ = shutdown.changed().await;
}

fn log_connection_result(
  listener: &ListenerId,
  joined: Result<(SocketAddr, ConnectionServeResult<ConnectionOutcome>), JoinError>,
) {
  match joined {
    Ok((peer, Ok(ConnectionOutcome::Http))) => {
      tracing::trace!(%listener, %peer, "HTTP connection completed");
    }
    Ok((peer, Ok(ConnectionOutcome::Connect(report)))) => match report.outcome() {
      ConnectRunOutcome::Tunnel {
        client_to_upstream,
        upstream_to_client,
      } => {
        tracing::debug!(
          %listener,
          %peer,
          site = %report.session().dispatch().site(),
          client_key_id = report.session().access().key_id.as_deref(),
          client_to_upstream,
          upstream_to_client,
          "CONNECT tunnel completed"
        );
      }
      ConnectRunOutcome::Intercept => {
        tracing::debug!(
          %listener,
          %peer,
          site = %report.session().dispatch().site(),
          client_key_id = report.session().access().key_id.as_deref(),
          "intercepted HTTPS connection completed"
        );
      }
    },
    Ok((peer, Err(ConnectionServeError::Http { source }))) => {
      tracing::debug!(%listener, %peer, error = %source, "HTTP connection failed");
    }
    Ok((peer, Err(ConnectionServeError::Connect { source }))) => {
      tracing::warn!(%listener, %peer, site = %source.site(), error = %source, "CONNECT session failed");
    }
    Err(error) => {
      tracing::error!(%listener, error = %error, "connection task failed");
    }
  }
}

enum ConnectionOutcome {
  Http,
  Connect(ConnectRunReport),
}

#[derive(Debug, Snafu)]
enum ConnectionServeError {
  #[snafu(display("HTTP/1 connection failed: {source}"))]
  Http { source: hyper::Error },

  #[snafu(display("CONNECT session failed: {source}"))]
  Connect { source: ConnectRunError },
}

type ConnectionServeResult<T> = std::result::Result<T, ConnectionServeError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum GatewayServeError {
  #[snafu(display("gateway listener task failed: {source}"))]
  ListenerTask { source: JoinError },

  #[snafu(display("gateway listener '{listener}' stopped before shutdown"))]
  UnexpectedListenerExit { listener: ListenerId },
}

pub type GatewayServeResult<T> = std::result::Result<T, GatewayServeError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{
    bind_gateway_listeners, link_gateway_runtime, materialize_listeners, GatewayServerState, GatewayServingDefaults,
    LinkedGatewayRuntime, RequestBodyLimits, RuntimeNameRegistry,
  };
  use rustls::pki_types::ServerName;
  use rustls::{ClientConfig, ClientConnection, RootCertStore};
  use std::collections::BTreeMap;
  use std::io::{BufReader, Read as _, Write as _};
  use std::net::Ipv4Addr;
  use std::path::{Path, PathBuf};
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;
  use tokio::sync::oneshot;
  use tokio::time::timeout;
  use tokio_rustls::TlsConnector;
  use tokn_access::AccessContext;
  use tokn_accounts::registry::Registry;
  use tokn_core::util::http::HttpClientOptions;
  use tokn_policy::{
    ClientAuthPlan, ConnectAction, ForwardProxyListenerPlan, GatewayPlan, HttpAction, ListenerPlan, LlmApiListenerPlan,
    TlsPlan,
  };

  const TEST_TIMEOUT: Duration = Duration::from_secs(2);
  const EARLY: &[u8] = b"\x16\x03\x01early";
  const READY: &[u8] = b"ready";
  const LATER: &[u8] = b"later";
  const REPLY: &[u8] = b"reply";
  const FINAL: &[u8] = b"final";

  fn listener_id() -> ListenerId {
    ListenerId::new("proxy").unwrap()
  }

  fn proxy_plan(bind: SocketAddr) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::from([(
        listener_id(),
        ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
          bind,
          ClientAuthPlan::None,
          Box::default(),
          HttpAction::Reject,
          Box::default(),
          ConnectAction::Tunnel,
          None,
        )),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    )
  }

  fn intercept_plan(bind: SocketAddr, ca_dir: PathBuf) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::from([(
        listener_id(),
        ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
          bind,
          ClientAuthPlan::None,
          Box::default(),
          HttpAction::Reject,
          Box::default(),
          ConnectAction::Intercept,
          Some(TlsPlan::new(ca_dir)),
        )),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    )
  }

  fn linked_runtime(plan: &GatewayPlan) -> Arc<LinkedGatewayRuntime> {
    Arc::new(link_gateway_runtime(plan, &[], &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap())
  }

  fn serving_generation(runtime: Arc<LinkedGatewayRuntime>) -> Arc<GatewayServerState> {
    Arc::new(
      GatewayServerState::build(
        runtime,
        &HttpClientOptions {
          system: false,
          ..HttpClientOptions::default()
        },
        GatewayServingDefaults::new(RequestBodyLimits::new(1024, 1024)),
      )
      .unwrap(),
    )
  }

  fn listener_state(plan: &GatewayPlan) -> Arc<ListenerServerState> {
    let runtime = linked_runtime(plan);
    let resources = materialize_listeners(runtime.listeners(), None).unwrap();
    let resource = resources.listener(&listener_id()).unwrap().clone();
    Arc::new(ListenerServerState::new(serving_generation(runtime), resource))
  }

  fn intercept_state(bind: SocketAddr) -> (tempfile::TempDir, Arc<ListenerServerState>, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let plan = intercept_plan(bind, temp.path().join("ca"));
    let runtime = linked_runtime(&plan);
    let resources = materialize_listeners(runtime.listeners(), None).unwrap();
    let resource = resources.listener(&listener_id()).unwrap().clone();
    let ca_cert = resource.kind().proxy_ca().unwrap().cert_path();
    let state = Arc::new(ListenerServerState::new(serving_generation(runtime), resource));
    (temp, state, ca_cert)
  }

  fn tls_client_config(ca_cert: &Path) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(std::fs::File::open(ca_cert).unwrap());
    for certificate in rustls_pemfile::certs(&mut reader) {
      roots.add(certificate.unwrap()).unwrap();
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_root_certificates(roots)
      .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
  }

  fn trusted_tls_client(ca_cert: &Path, host: &str) -> ClientConnection {
    ClientConnection::new(
      tls_client_config(ca_cert),
      ServerName::try_from(host.to_owned()).unwrap(),
    )
    .unwrap()
  }

  fn take_tls_output(tls: &mut ClientConnection) -> Vec<u8> {
    let mut output = Vec::new();
    while tls.wants_write() {
      let written = tls.write_tls(&mut output).unwrap();
      assert_ne!(written, 0, "rustls made no write progress");
    }
    output
  }

  fn feed_tls_input(tls: &mut ClientConnection, mut encrypted: &[u8]) {
    while !encrypted.is_empty() {
      let read = tls.read_tls(&mut encrypted).unwrap();
      assert_ne!(read, 0, "rustls made no read progress");
    }
    tls.process_new_packets().unwrap();
  }

  async fn flush_tls_output(stream: &mut TcpStream, tls: &mut ClientConnection) {
    let encrypted = take_tls_output(tls);
    if !encrypted.is_empty() {
      stream.write_all(&encrypted).await.unwrap();
      stream.flush().await.unwrap();
    }
  }

  async fn read_tls_input(stream: &mut TcpStream, tls: &mut ClientConnection) {
    let mut encrypted = [0u8; 32 * 1024];
    let read = stream.read(&mut encrypted).await.unwrap();
    assert_ne!(read, 0, "TLS peer closed unexpectedly");
    feed_tls_input(tls, &encrypted[..read]);
  }

  async fn finish_tls_handshake(stream: &mut TcpStream, tls: &mut ClientConnection, outer_read_ahead: &[u8]) {
    feed_tls_input(tls, outer_read_ahead);
    while tls.is_handshaking() {
      flush_tls_output(stream, tls).await;
      if tls.is_handshaking() {
        assert!(tls.wants_read(), "TLS handshake stalled");
        read_tls_input(stream, tls).await;
      }
    }
    // TLS 1.3 can finish while the client Finished record is still queued.
    flush_tls_output(stream, tls).await;
    assert_eq!(tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
  }

  fn drain_tls_plaintext(tls: &mut ClientConnection, output: &mut Vec<u8>) {
    let mut chunk = [0u8; 4096];
    loop {
      match tls.reader().read(&mut chunk) {
        Ok(0) => return,
        Ok(read) => output.extend_from_slice(&chunk[..read]),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
        Err(error) => panic!("read TLS plaintext: {error}"),
      }
    }
  }

  async fn read_tls_plaintext_until(stream: &mut TcpStream, tls: &mut ClientConnection, needle: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::new();
    loop {
      drain_tls_plaintext(tls, &mut plaintext);
      if plaintext.windows(needle.len()).any(|window| window == needle) {
        return plaintext;
      }
      flush_tls_output(stream, tls).await;
      read_tls_input(stream, tls).await;
    }
  }

  async fn bound_generation() -> (BoundGatewayListeners, SocketAddr, std::sync::Weak<GatewayServerState>) {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let reserved_address = reservation.local_addr().unwrap();
    let plan = proxy_plan(reserved_address);
    let runtime = linked_runtime(&plan);
    let resources = materialize_listeners(runtime.listeners(), None).unwrap();
    let gateway = serving_generation(runtime);
    let weak = Arc::downgrade(&gateway);
    drop(reservation);
    let bound = bind_gateway_listeners(gateway, resources).await.unwrap();
    let address = bound.listener(&listener_id()).unwrap().local_addr().unwrap();
    (bound, address, weak)
  }

  async fn read_response_head<S>(stream: &mut S) -> (Vec<u8>, Vec<u8>)
  where
    S: tokio::io::AsyncRead + Unpin,
  {
    let mut received = Vec::new();
    loop {
      if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") {
        let body = received.split_off(index + 4);
        return (received, body);
      }
      assert!(received.len() < 64 * 1024, "HTTP response head exceeded test bound");
      let mut chunk = [0u8; 256];
      let count = stream.read(&mut chunk).await.unwrap();
      assert_ne!(count, 0, "connection closed before an HTTP response head");
      received.extend_from_slice(&chunk[..count]);
    }
  }

  async fn fill_to<S>(stream: &mut S, bytes: &mut Vec<u8>, length: usize)
  where
    S: tokio::io::AsyncRead + Unpin,
  {
    while bytes.len() < length {
      let mut chunk = [0u8; 64];
      let count = stream.read(&mut chunk).await.unwrap();
      assert_ne!(count, 0, "tunnel closed before the expected bytes arrived");
      bytes.extend_from_slice(&chunk[..count]);
    }
  }

  fn response_content_length(head: &[u8]) -> usize {
    std::str::from_utf8(head)
      .unwrap()
      .lines()
      .find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name
          .eq_ignore_ascii_case("content-length")
          .then(|| value.trim().parse().unwrap())
      })
      .expect("test response has a content length")
  }

  #[tokio::test]
  async fn direct_listener_serves_the_shared_http_adapter() {
    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let plan = GatewayPlan::new(
      BTreeMap::from([(
        listener_id(),
        ListenerPlan::LlmApi(LlmApiListenerPlan::new(
          address,
          ClientAuthPlan::None,
          Box::default(),
          HttpAction::Reject,
        )),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let state = listener_state(&plan);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection = tokio::spawn(async move {
      let (stream, _) = socket.accept().await.unwrap();
      serve_llm_api_connection(stream, state, shutdown_rx).await
    });

    let mut client = TcpStream::connect(address).await.unwrap();
    client
      .write_all(b"GET /v1/models HTTP/1.1\r\nHost: client.example\r\nConnection: close\r\n\r\n")
      .await
      .unwrap();
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
      .await
      .unwrap()
      .unwrap();
    let response = std::str::from_utf8(&response).unwrap();
    assert!(
      response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
      "unexpected response: {response:?}"
    );
    assert!(response.contains("\"code\":\"route_rejected\""));

    timeout(TEST_TIMEOUT, connection).await.unwrap().unwrap().unwrap();
    drop(shutdown_tx);
  }

  #[tokio::test]
  async fn forward_proxy_connect_preserves_read_ahead_and_half_close() {
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let plan = proxy_plan(SocketAddr::from((Ipv4Addr::LOCALHOST, 42_502)));
    let state = listener_state(&plan);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let connection = tokio::spawn(async move {
      let (stream, _) = proxy_listener.accept().await.unwrap();
      serve_forward_proxy_connection(stream, state, shutdown_rx).await
    });
    let upstream = tokio::spawn(async move {
      let (mut stream, _) = upstream_listener.accept().await.unwrap();
      let mut early = vec![0u8; EARLY.len()];
      stream.read_exact(&mut early).await.unwrap();
      assert_eq!(early, EARLY);
      stream.write_all(READY).await.unwrap();

      let mut later = vec![0u8; LATER.len()];
      stream.read_exact(&mut later).await.unwrap();
      assert_eq!(later, LATER);
      stream.write_all(REPLY).await.unwrap();

      let mut byte = [0u8; 1];
      assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
      stream.write_all(FINAL).await.unwrap();
      stream.shutdown().await.unwrap();
    });

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    let mut connect = format!("CONNECT {upstream_address} HTTP/1.1\r\nHost: {upstream_address}\r\n\r\n").into_bytes();
    connect.extend_from_slice(EARLY);
    client.write_all(&connect).await.unwrap();

    let (head, mut tunneled) = timeout(TEST_TIMEOUT, read_response_head(&mut client)).await.unwrap();
    let head = std::str::from_utf8(&head).unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "unexpected response: {head:?}");
    let lower_head = head.to_ascii_lowercase();
    assert!(!lower_head.contains("content-length:"));
    assert!(!lower_head.contains("transfer-encoding:"));

    timeout(TEST_TIMEOUT, fill_to(&mut client, &mut tunneled, READY.len()))
      .await
      .unwrap();
    assert_eq!(tunneled, READY);
    client.write_all(LATER).await.unwrap();
    let mut reply = vec![0u8; REPLY.len()];
    timeout(TEST_TIMEOUT, client.read_exact(&mut reply))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(reply, REPLY);

    client.shutdown().await.unwrap();
    let mut final_bytes = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut final_bytes))
      .await
      .unwrap()
      .unwrap();
    assert_eq!(final_bytes, FINAL);

    timeout(TEST_TIMEOUT, upstream).await.unwrap().unwrap();
    let report = timeout(TEST_TIMEOUT, connection)
      .await
      .unwrap()
      .unwrap()
      .unwrap()
      .expect("a successful CONNECT returns one report");
    assert_eq!(
      report.outcome(),
      ConnectRunOutcome::Tunnel {
        client_to_upstream: (EARLY.len() + LATER.len()) as u64,
        upstream_to_client: (READY.len() + REPLY.len() + FINAL.len()) as u64,
      }
    );
    assert_eq!(report.session().access(), &AccessContext::unrestricted());
    assert_eq!(
      report.session().dispatch().authority().authority().to_string(),
      upstream_address.to_string()
    );
    assert_eq!(report.session().dispatch().site().listener_id(), &listener_id());
    assert!(report.session().dispatch().site().rule_id().is_none());
    drop(shutdown_tx);
  }

  #[tokio::test]
  async fn intercepted_connect_serves_https_with_the_connect_identity() {
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let (_temp, state, ca_cert) = intercept_state(SocketAddr::from((Ipv4Addr::LOCALHOST, 42_503)));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection = tokio::spawn(async move {
      let (stream, _) = proxy_listener.accept().await.unwrap();
      serve_forward_proxy_connection(stream, state, shutdown_rx).await
    });

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client
      .write_all(b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n")
      .await
      .unwrap();
    let (head, read_ahead) = timeout(TEST_TIMEOUT, read_response_head(&mut client)).await.unwrap();
    let head = std::str::from_utf8(&head).unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "unexpected response: {head:?}");
    assert!(read_ahead.is_empty());

    let server_name = ServerName::try_from("api.example.test").unwrap().to_owned();
    let mut tls = timeout(
      TEST_TIMEOUT,
      TlsConnector::from(tls_client_config(&ca_cert)).connect(server_name, client),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
    tls
      .write_all(b"GET /v1/models HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
      .await
      .unwrap();
    let (head, mut body) = timeout(TEST_TIMEOUT, read_response_head(&mut tls)).await.unwrap();
    assert!(std::str::from_utf8(&head)
      .unwrap()
      .starts_with("HTTP/1.1 403 Forbidden\r\n"));
    let content_length = response_content_length(&head);
    timeout(TEST_TIMEOUT, fill_to(&mut tls, &mut body, content_length))
      .await
      .unwrap();
    assert_eq!(body.len(), content_length);
    assert!(std::str::from_utf8(&body)
      .unwrap()
      .contains("\"code\":\"route_rejected\""));

    let report = timeout(TEST_TIMEOUT, connection)
      .await
      .unwrap()
      .unwrap()
      .unwrap()
      .expect("a successful intercepted CONNECT returns one report");
    assert_eq!(report.outcome(), ConnectRunOutcome::Intercept);
    assert_eq!(
      report.session().dispatch().authority().authority().to_string(),
      "api.example.test:443"
    );
    drop(shutdown_tx);
  }

  #[tokio::test]
  async fn intercepted_connect_preserves_coalesced_client_hello_read_ahead() {
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let (_temp, state, ca_cert) = intercept_state(SocketAddr::from((Ipv4Addr::LOCALHOST, 42_504)));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection = tokio::spawn(async move {
      let (stream, _) = proxy_listener.accept().await.unwrap();
      serve_forward_proxy_connection(stream, state, shutdown_rx).await
    });

    let mut tls = trusted_tls_client(&ca_cert, "api.example.test");
    let client_hello = take_tls_output(&mut tls);
    assert_eq!(client_hello.first(), Some(&0x16));
    let mut coalesced = b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n".to_vec();
    coalesced.extend_from_slice(&client_hello);

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client.write_all(&coalesced).await.unwrap();
    let (head, tls_read_ahead) = timeout(TEST_TIMEOUT, read_response_head(&mut client)).await.unwrap();
    assert!(std::str::from_utf8(&head).unwrap().starts_with("HTTP/1.1 200 OK\r\n"));
    timeout(
      TEST_TIMEOUT,
      finish_tls_handshake(&mut client, &mut tls, &tls_read_ahead),
    )
    .await
    .unwrap();

    tls
      .writer()
      .write_all(b"GET /v1/models HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
      .unwrap();
    flush_tls_output(&mut client, &mut tls).await;
    let inner = timeout(
      TEST_TIMEOUT,
      read_tls_plaintext_until(&mut client, &mut tls, b"route_rejected"),
    )
    .await
    .unwrap();
    assert!(inner.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

    let report = timeout(TEST_TIMEOUT, connection)
      .await
      .unwrap()
      .unwrap()
      .unwrap()
      .expect("a successful intercepted CONNECT returns one report");
    assert_eq!(report.outcome(), ConnectRunOutcome::Intercept);
    drop(shutdown_tx);
  }

  #[tokio::test]
  async fn gateway_shutdown_cancels_active_tunnels_and_releases_generation() {
    let (bound, proxy_address, weak_gateway) = bound_generation().await;
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
      serve_gateway_listeners(bound, async {
        let _ = shutdown_rx.await;
      })
      .await
    });

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client
      .write_all(format!("CONNECT {upstream_address} HTTP/1.1\r\nHost: {upstream_address}\r\n\r\n").as_bytes())
      .await
      .unwrap();
    let (head, tunneled) = timeout(TEST_TIMEOUT, read_response_head(&mut client)).await.unwrap();
    assert!(std::str::from_utf8(&head).unwrap().starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(tunneled.is_empty());
    let (mut upstream, _) = timeout(TEST_TIMEOUT, upstream_listener.accept())
      .await
      .unwrap()
      .unwrap();

    shutdown_tx.send(()).unwrap();
    timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().unwrap();

    let mut byte = [0u8; 1];
    assert_eq!(timeout(TEST_TIMEOUT, client.read(&mut byte)).await.unwrap().unwrap(), 0);
    assert_eq!(
      timeout(TEST_TIMEOUT, upstream.read(&mut byte)).await.unwrap().unwrap(),
      0
    );
    assert!(weak_gateway.upgrade().is_none());
  }
}

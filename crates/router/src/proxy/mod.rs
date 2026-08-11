mod ca;
mod connect_proxy;
pub mod passthrough_pipeline;
mod transport;

use crate::api::{AppState, LiveAppState};
use anyhow::{Context, Result};
use axum::http::Method;
use axum::Router;
pub use ca::{load_or_generate_ca, ProxyCa};
use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokn_accounts::registry::Registry;
use tokn_auth::descriptor::RewriteTarget;
use tokn_core::util::http::HttpClientOptions;
use tokn_policy::{CanonicalHost, ConnectAction};
use transport::handle_client;

fn is_benign_disconnect(err: &anyhow::Error) -> bool {
  let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err.as_ref());
  while let Some(source) = current {
    if let Some(io_err) = source.downcast_ref::<std::io::Error>() {
      if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
        return true;
      }
    }
    let message = source.to_string();
    if message.contains("peer closed connection without sending TLS close_notify")
      || message.contains("unexpected eof")
      || message.contains("UnexpectedEof")
    {
      return true;
    }
    current = source.source();
  }
  false
}

/// Full built-in intercept set. Keep this explicit so default interception
/// does not shrink when a provider crate is conditionally unavailable.
pub(crate) const INTERCEPT_HOSTS: &[&str] = &[
  "api.openai.com",
  "api.githubcopilot.com",
  "api.z.ai",
  "open.bigmodel.cn",
  "chatgpt.com",
  // "ab.chatgpt.com",
  "api.deepseek.com",
];

/// Hosts the proxy intercepts even though no provider claims them.
const EXTRA_INTERCEPT_HOSTS: &[&str] = &["openrouter.ai", "api.anthropic.com", "opencode.ai"];

#[derive(Clone)]
pub struct ProxyOptions {
  pub addr: SocketAddr,
  pub ca_dir: PathBuf,
  pub intercept_hosts: Vec<String>,
  pub passthrough_hosts: Vec<String>,
  pub outbound_proxy: HttpClientOptions,
  pub plain_http_handler: Option<ProxyPlainHttpHandler>,
}

pub type ProxyPlainHttpHandler =
  Arc<dyn Fn(ProxyPlainHttpRequest) -> Option<ProxyPlainHttpResponse> + Send + Sync + 'static>;

pub(crate) type ProxyConnectPolicy = Arc<dyn Fn(&CanonicalHost, u16) -> ConnectAction + Send + Sync + 'static>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyPlainHttpRequest {
  pub method: String,
  pub target: String,
  pub host: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyPlainHttpResponse {
  pub status: &'static str,
  pub content_type: &'static str,
  pub body: String,
}

pub async fn serve<F>(state: AppState, options: ProxyOptions, shutdown: F) -> Result<()>
where
  F: Future<Output = ()> + Send,
{
  serve_live(LiveAppState::new(state), options, shutdown).await
}

pub async fn serve_live<F>(state: LiveAppState, options: ProxyOptions, shutdown: F) -> Result<()>
where
  F: Future<Output = ()> + Send,
{
  let listener = TcpListener::bind(options.addr)
    .await
    .with_context(|| format!("bind {}", options.addr))?;
  let ca = Arc::new(load_or_generate_ca(&options.ca_dir, false)?);
  let state = Arc::new(state);
  let router = proxy_router((*state).clone());
  let host_policy = HostPolicy::new(&options);
  let runtime = transport::ProxyRuntime::Legacy {
    state,
    router,
    ca,
    host_policy,
  };
  let outbound_proxy = Arc::new(connect_proxy::ConnectProxy::from_options(&options.outbound_proxy));
  let plain_http_handler = options.plain_http_handler.clone();

  tracing::info!(addr = %options.addr, ca_dir = %options.ca_dir.display(), "tokn-router proxy listening");

  tokio::pin!(shutdown);

  loop {
    tokio::select! {
      _ = &mut shutdown => break,
      accept = listener.accept() => {
        let (stream, peer) = accept?;
        let runtime = runtime.clone();
        let outbound_proxy = outbound_proxy.clone();
        let plain_http_handler = plain_http_handler.clone();
        tokio::spawn(async move {
          if let Err(err) = handle_client(stream, peer, runtime, outbound_proxy, plain_http_handler).await {
            if is_benign_disconnect(&err) {
              tracing::debug!(%peer, error = %err, "proxy connection closed by peer");
            } else {
              tracing::warn!(%peer, error = %err, "proxy connection failed");
            }
          }
        });
      }
    }
  }

  Ok(())
}

pub(crate) async fn serve_connect_policy<F>(
  addr: SocketAddr,
  outbound_proxy: HttpClientOptions,
  connect_policy: ProxyConnectPolicy,
  client_auth: Option<Arc<tokn_access::AccessStore>>,
  shutdown: F,
) -> Result<()>
where
  F: Future<Output = ()> + Send,
{
  serve_policy_runtime(
    addr,
    outbound_proxy,
    transport::ProxyRuntime::Policy {
      connect_policy,
      client_auth,
    },
    shutdown,
  )
  .await
}

async fn serve_policy_runtime<F>(
  addr: SocketAddr,
  outbound_proxy: HttpClientOptions,
  runtime: transport::ProxyRuntime,
  shutdown: F,
) -> Result<()>
where
  F: Future<Output = ()> + Send,
{
  let listener = TcpListener::bind(addr).await.with_context(|| format!("bind {addr}"))?;
  let outbound_proxy = Arc::new(connect_proxy::ConnectProxy::from_options(&outbound_proxy));

  tracing::info!(%addr, "tokn-router proxy listening");

  tokio::pin!(shutdown);

  loop {
    tokio::select! {
      _ = &mut shutdown => break,
      accept = listener.accept() => {
        let (stream, peer) = accept?;
        let runtime = runtime.clone();
        let outbound_proxy = outbound_proxy.clone();
        tokio::spawn(async move {
          if let Err(err) = handle_client(stream, peer, runtime, outbound_proxy, None).await {
            if is_benign_disconnect(&err) {
              tracing::debug!(%peer, error = %err, "proxy connection closed by peer");
            } else {
              tracing::warn!(%peer, error = %err, "proxy connection failed");
            }
          }
        });
      }
    }
  }

  Ok(())
}

#[derive(Clone)]
pub(super) struct HostPolicy {
  intercept: Arc<HashSet<String>>,
}

impl HostPolicy {
  fn new(options: &ProxyOptions) -> Self {
    let mut intercept = INTERCEPT_HOSTS.iter().map(|s| s.to_string()).collect::<HashSet<_>>();
    intercept.extend(EXTRA_INTERCEPT_HOSTS.iter().map(|s| s.to_string()));
    intercept.extend(options.intercept_hosts.iter().map(|s| s.to_ascii_lowercase()));
    for host in &options.passthrough_hosts {
      intercept.remove(&host.to_ascii_lowercase());
    }
    Self {
      intercept: Arc::new(intercept),
    }
  }

  pub(super) fn should_intercept(&self, host: &str) -> bool {
    self.intercept.contains(&host.to_ascii_lowercase())
  }
}

/// Extract route mode from Proxy-Authorization Basic header username.
/// Format: `Proxy-Authorization: Basic <base64(username:password)>`
/// The username is parsed as a route mode; password is ignored.
pub(super) fn extract_proxy_auth_mode(header_value: &str) -> Option<String> {
  let encoded = header_value
    .strip_prefix("Basic ")
    .or_else(|| header_value.strip_prefix("basic "))?;
  let decoded = String::from_utf8(base64_decode(encoded.trim())?).ok()?;
  let username = decoded.split(':').next().unwrap_or("");
  if username.is_empty() {
    return None;
  }
  // Validate it's a known mode
  match username {
    "route" | "passthrough" | "switch" | "exact" | "fuzzy" => Some(username.to_string()),
    _ => None,
  }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
  use base64::Engine;
  base64::engine::general_purpose::STANDARD.decode(input).ok()
}

/// Look up the canonical path for an inbound `(host, method, path)` by
/// consulting the registry's descriptor table. Falls back to a single
/// global rule for `GET /v1/models` (which every provider serves at the
/// same path).
pub(crate) fn rewrite_target(host: &str, path: &str, method: &Method) -> Option<RewriteTarget> {
  if method == Method::GET && path == "/v1/models" {
    return Some(RewriteTarget::Path("/v1/models"));
  }
  Registry::builtin().rewrite_target(host, method.as_str(), path)
}

fn proxy_router(state: LiveAppState) -> Router {
  crate::api::router_live(state)
}

fn split_authority(authority: &str) -> Result<(String, u16)> {
  let (host, port) = authority
    .rsplit_once(':')
    .with_context(|| format!("invalid CONNECT authority '{authority}'"))?;
  Ok((
    host.to_ascii_lowercase(),
    port
      .parse()
      .with_context(|| format!("invalid CONNECT port in '{authority}'"))?,
  ))
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  #[test]
  fn benign_disconnect_matches_unexpected_eof() {
    let err = anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "stream ended"));
    assert!(is_benign_disconnect(&err));
  }

  #[test]
  fn benign_disconnect_matches_rustls_close_notify_message() {
    let err = anyhow::anyhow!("TLS handshake failed: peer closed connection without sending TLS close_notify");
    assert!(is_benign_disconnect(&err));
  }

  #[test]
  fn benign_disconnect_rejects_other_errors() {
    let err = anyhow::anyhow!("invalid CONNECT authority");
    assert!(!is_benign_disconnect(&err));
  }

  #[tokio::test]
  async fn policy_transport_refuses_unadapted_interception() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_connect_policy(
      addr,
      HttpClientOptions::default(),
      Arc::new(|_, _| ConnectAction::Intercept),
      None,
      async {
        let _ = shutdown_rx.await;
      },
    ));
    let mut stream = None;
    for _ in 0..50 {
      match tokio::net::TcpStream::connect(addr).await {
        Ok(connected) => {
          stream = Some(connected);
          break;
        }
        Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
      }
    }
    let mut stream = stream.expect("policy proxy listener should start");

    stream
      .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
      .await
      .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 501 Not Implemented"));

    shutdown_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
  }
}

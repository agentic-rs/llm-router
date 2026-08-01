//! Bounded outbound transport for v2 CONNECT tunnels.
//!
//! The connector freezes proxy and no-proxy environment state when a serving
//! generation is built. Every returned stream retains any bytes read past an
//! HTTP proxy response head, and HTTPS proxy tunnels remain wrapped in their
//! authenticated TLS transport for the complete tunnel lifetime.

use anyhow::{anyhow, Context};
use http::{HeaderValue, Uri};
use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use rustls::pki_types::ServerName;
use snafu::Snafu;
use std::env;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokn_core::util::http::HttpClientOptions;
use tokn_policy::ResolvedAuthority;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PROXY_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
const HTTP_1_1_ALPN: &[u8] = b"http/1.1";

/// Async byte stream returned after the selected tunnel transport is ready.
pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxTunnelIo = Box<dyn TunnelIo>;

/// Immutable outbound CONNECT transport policy for one serving generation.
pub struct TunnelConnector {
  proxy_matcher: Matcher,
  proxy_tls: Option<Arc<rustls::ClientConfig>>,
}

impl TunnelConnector {
  /// Validate and freeze the configured outbound proxy policy.
  pub fn build(options: &HttpClientOptions) -> TunnelConnectorBuildResult<Self> {
    let frozen = FrozenProxySettings::capture(options)?;
    let proxy_tls = frozen.requires_tls.then(build_proxy_tls_config).transpose()?;
    Ok(Self {
      proxy_matcher: frozen.matcher,
      proxy_tls,
    })
  }

  /// Open one direct or proxied byte tunnel within a bounded setup deadline.
  pub async fn connect(&self, target: &ResolvedAuthority) -> TunnelConnectResult<BoxTunnelIo> {
    let result = tokio::time::timeout(CONNECT_TIMEOUT, self.connect_inner(target)).await;
    match result {
      Err(_) => Err(TunnelConnectError::Timeout { target: target.clone() }),
      Ok(Err(OpenTunnelError::ProxyRejected { status })) => Err(TunnelConnectError::ProxyRejected {
        target: target.clone(),
        status,
      }),
      Ok(Err(OpenTunnelError::Transport(source))) => Err(TunnelConnectError::Transport {
        target: target.clone(),
        source,
      }),
      Ok(Ok(stream)) => Ok(stream),
    }
  }

  async fn connect_inner(&self, target: &ResolvedAuthority) -> Result<BoxTunnelIo, OpenTunnelError> {
    let target_uri = target_uri(target);
    let Some(intercept) = self.proxy_matcher.intercept(&target_uri) else {
      return connect_tcp(target.host().as_str(), target.port())
        .await
        .map(|stream| Box::new(stream) as BoxTunnelIo)
        .map_err(OpenTunnelError::transport);
    };
    let endpoint = ProxyEndpoint::from_intercept(&intercept).map_err(OpenTunnelError::transport)?;

    match endpoint.kind {
      ProxyKind::Http => connect_via_http_proxy(endpoint, target).await,
      ProxyKind::Https => {
        let tls = self.proxy_tls.as_ref().ok_or_else(|| {
          OpenTunnelError::transport(anyhow!("HTTPS proxy selected without a generation TLS configuration"))
        })?;
        connect_via_https_proxy(endpoint, target, tls.clone()).await
      }
      ProxyKind::Socks5 { remote_dns } => connect_via_socks5_proxy(endpoint, target, remote_dns).await,
    }
  }
}

impl fmt::Debug for TunnelConnector {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TunnelConnector")
      .field("proxy_matcher", &self.proxy_matcher)
      .field("proxy_tls", &self.proxy_tls.as_ref().map(|_| "configured"))
      .finish()
  }
}

struct FrozenProxySettings {
  matcher: Matcher,
  requires_tls: bool,
}

impl FrozenProxySettings {
  fn capture(options: &HttpClientOptions) -> TunnelConnectorBuildResult<Self> {
    if let Some(proxy) = options.url.as_deref() {
      let scheme = validate_proxy_url(proxy)?;
      let mut matcher = Matcher::builder().all(proxy.to_owned());
      if !options.no_proxy.is_empty() {
        matcher = matcher.no(options.no_proxy.join(","));
      }
      return Ok(Self {
        matcher: matcher.build(),
        requires_tls: scheme == ProxyKind::Https,
      });
    }

    if !options.system {
      return Ok(Self {
        matcher: Matcher::builder().build(),
        requires_tls: false,
      });
    }

    // CONNECT targets use an HTTPS-shaped URI for conventional proxy
    // selection, so HTTPS_PROXY wins and ALL_PROXY is the fallback. Preserve
    // the legacy HTTP_PROXY fallback when neither is configured. Capture
    // values now; later environment mutations cannot change this generation.
    let all_proxy = first_environment_value(&["ALL_PROXY", "all_proxy"])
      .or_else(|| first_environment_value(&["HTTP_PROXY", "http_proxy"]));
    let https_proxy = first_environment_value(&["HTTPS_PROXY", "https_proxy"]);
    let mut requires_tls = false;
    for value in [all_proxy.as_deref(), https_proxy.as_deref()].into_iter().flatten() {
      requires_tls |= validate_proxy_url(value)? == ProxyKind::Https;
    }

    let mut matcher = Matcher::builder();
    if let Some(value) = all_proxy {
      matcher = matcher.all(value);
    }
    if let Some(value) = https_proxy {
      matcher = matcher.https(value);
    }
    let mut no_proxy = first_environment_value(&["NO_PROXY", "no_proxy"])
      .into_iter()
      .collect::<Vec<_>>();
    no_proxy.extend(options.no_proxy.iter().cloned());
    if !no_proxy.is_empty() {
      matcher = matcher.no(no_proxy.join(","));
    }

    Ok(Self {
      matcher: matcher.build(),
      requires_tls,
    })
  }
}

fn first_environment_value(names: &[&str]) -> Option<String> {
  names.iter().find_map(|name| env::var(name).ok())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyKind {
  Http,
  Https,
  Socks5 { remote_dns: bool },
}

fn validate_proxy_url(value: &str) -> TunnelConnectorBuildResult<ProxyKind> {
  let url = reqwest::Url::parse(value)
    .map_err(|source| TunnelConnectorBuildError::InvalidProxyUrl { source: source.into() })?;
  if url.host_str().is_none()
    || url.cannot_be_a_base()
    || !matches!(url.path(), "" | "/")
    || url.query().is_some()
    || url.fragment().is_some()
  {
    return Err(TunnelConnectorBuildError::InvalidProxyUrl {
      source: anyhow!("proxy URL must contain only an authority"),
    });
  }
  match url.scheme() {
    "http" => Ok(ProxyKind::Http),
    "https" => Ok(ProxyKind::Https),
    "socks5" => Ok(ProxyKind::Socks5 { remote_dns: false }),
    "socks5h" => Ok(ProxyKind::Socks5 { remote_dns: true }),
    scheme => Err(TunnelConnectorBuildError::UnsupportedProxyScheme {
      scheme: scheme.to_owned(),
    }),
  }
}

#[derive(Clone, Debug)]
struct ProxyEndpoint {
  kind: ProxyKind,
  host: String,
  port: u16,
  basic_auth: Option<HeaderValue>,
  raw_auth: Option<(String, String)>,
}

impl ProxyEndpoint {
  fn from_intercept(intercept: &Intercept) -> anyhow::Result<Self> {
    let uri = intercept.uri();
    let scheme = uri
      .scheme_str()
      .ok_or_else(|| anyhow!("matched outbound proxy has no scheme"))?;
    let kind = match scheme {
      "http" => ProxyKind::Http,
      "https" => ProxyKind::Https,
      "socks5" => ProxyKind::Socks5 { remote_dns: false },
      "socks5h" => ProxyKind::Socks5 { remote_dns: true },
      _ => return Err(anyhow!("matched outbound proxy has unsupported scheme")),
    };
    let host = uri
      .host()
      .ok_or_else(|| anyhow!("matched outbound proxy has no host"))?
      .to_owned();
    let port = uri.port_u16().unwrap_or(match kind {
      ProxyKind::Http => 80,
      ProxyKind::Https => 443,
      ProxyKind::Socks5 { .. } => 1080,
    });
    Ok(Self {
      kind,
      host,
      port,
      basic_auth: intercept.basic_auth().cloned(),
      raw_auth: intercept
        .raw_auth()
        .map(|(username, password)| (username.to_owned(), password.to_owned())),
    })
  }
}

async fn connect_via_http_proxy(
  endpoint: ProxyEndpoint,
  target: &ResolvedAuthority,
) -> Result<BoxTunnelIo, OpenTunnelError> {
  let stream = connect_tcp(&endpoint.host, endpoint.port)
    .await
    .with_context(|| format!("connect outbound HTTP proxy {}:{}", endpoint.host, endpoint.port))
    .map_err(OpenTunnelError::transport)?;
  establish_http_connect(stream, endpoint.basic_auth.as_ref(), target).await
}

async fn connect_via_https_proxy(
  endpoint: ProxyEndpoint,
  target: &ResolvedAuthority,
  tls_config: Arc<rustls::ClientConfig>,
) -> Result<BoxTunnelIo, OpenTunnelError> {
  let stream = connect_tcp(&endpoint.host, endpoint.port)
    .await
    .with_context(|| format!("connect outbound HTTPS proxy {}:{}", endpoint.host, endpoint.port))
    .map_err(OpenTunnelError::transport)?;
  let server_name = ServerName::try_from(endpoint.host.clone())
    .map_err(|_| OpenTunnelError::transport(anyhow!("outbound HTTPS proxy host is not a valid TLS server name")))?;
  let stream = TlsConnector::from(tls_config)
    .connect(server_name, stream)
    .await
    .with_context(|| format!("TLS handshake with outbound proxy {}:{}", endpoint.host, endpoint.port))
    .map_err(OpenTunnelError::transport)?;
  establish_http_connect(stream, endpoint.basic_auth.as_ref(), target).await
}

async fn establish_http_connect<S>(
  stream: S,
  authorization: Option<&HeaderValue>,
  target: &ResolvedAuthority,
) -> Result<BoxTunnelIo, OpenTunnelError>
where
  S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let authority = target.to_string();
  let mut request = Vec::with_capacity(128);
  request.extend_from_slice(b"CONNECT ");
  request.extend_from_slice(authority.as_bytes());
  request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
  request.extend_from_slice(authority.as_bytes());
  request.extend_from_slice(b"\r\n");
  if let Some(value) = authorization {
    request.extend_from_slice(b"Proxy-Authorization: ");
    request.extend_from_slice(value.as_bytes());
    request.extend_from_slice(b"\r\n");
  }
  request.extend_from_slice(b"\r\n");

  let mut stream = BufReader::new(stream);
  stream
    .write_all(&request)
    .await
    .context("write outbound proxy CONNECT request")
    .map_err(OpenTunnelError::transport)?;
  stream
    .flush()
    .await
    .context("flush outbound proxy CONNECT request")
    .map_err(OpenTunnelError::transport)?;

  let mut remaining = MAX_PROXY_RESPONSE_HEAD_BYTES;
  loop {
    let head = read_http_head(&mut stream, &mut remaining)
      .await
      .map_err(OpenTunnelError::transport)?;
    let status = parse_proxy_status(&head).map_err(OpenTunnelError::transport)?;
    if (100..200).contains(&status) && status != 101 {
      continue;
    }
    if (200..300).contains(&status) {
      return Ok(Box::new(stream));
    }
    return Err(OpenTunnelError::ProxyRejected { status });
  }
}

async fn read_http_head<R>(reader: &mut BufReader<R>, remaining: &mut usize) -> anyhow::Result<Vec<u8>>
where
  R: AsyncRead + Unpin,
{
  let mut head = Vec::new();
  loop {
    let available = reader.fill_buf().await.context("read outbound proxy response")?;
    if available.is_empty() {
      return Err(anyhow!("outbound proxy closed before completing its response head"));
    }
    let mut consumed = 0usize;
    let mut complete = false;
    for byte in available {
      if *remaining == 0 {
        return Err(anyhow!("outbound proxy response head exceeds the configured limit"));
      }
      head.push(*byte);
      *remaining -= 1;
      consumed += 1;
      if head.ends_with(b"\r\n\r\n") {
        complete = true;
        break;
      }
    }
    reader.consume(consumed);
    if complete {
      return Ok(head);
    }
  }
}

fn parse_proxy_status(head: &[u8]) -> anyhow::Result<u16> {
  let line_end = head
    .windows(2)
    .position(|window| window == b"\r\n")
    .or_else(|| head.iter().position(|byte| *byte == b'\n'))
    .ok_or_else(|| anyhow!("outbound proxy response has no status line"))?;
  let line = std::str::from_utf8(&head[..line_end]).context("outbound proxy status line is not UTF-8")?;
  let mut parts = line.split_ascii_whitespace();
  let version = parts.next().unwrap_or_default();
  let status = parts.next().unwrap_or_default();
  if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    || status.len() != 3
    || !status.bytes().all(|byte| byte.is_ascii_digit())
  {
    return Err(anyhow!("outbound proxy returned an invalid HTTP status line"));
  }
  status
    .parse()
    .context("outbound proxy returned an invalid HTTP status code")
}

async fn connect_via_socks5_proxy(
  endpoint: ProxyEndpoint,
  target: &ResolvedAuthority,
  remote_dns: bool,
) -> Result<BoxTunnelIo, OpenTunnelError> {
  let mut stream = connect_tcp(&endpoint.host, endpoint.port)
    .await
    .with_context(|| format!("connect outbound SOCKS5 proxy {}:{}", endpoint.host, endpoint.port))
    .map_err(OpenTunnelError::transport)?;
  socks5_authenticate(&mut stream, endpoint.raw_auth.as_ref())
    .await
    .map_err(OpenTunnelError::transport)?;
  let address = socks5_target(target, remote_dns)
    .await
    .map_err(OpenTunnelError::transport)?;
  send_socks5_connect(&mut stream, address, target.port())
    .await
    .map_err(OpenTunnelError::transport)?;
  Ok(Box::new(stream))
}

async fn socks5_authenticate(stream: &mut TcpStream, credentials: Option<&(String, String)>) -> anyhow::Result<()> {
  if credentials.is_some() {
    stream.write_all(&[0x05, 0x01, 0x02]).await?;
  } else {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
  }
  stream.flush().await?;
  let mut selected = [0u8; 2];
  stream.read_exact(&mut selected).await?;
  let expected = if credentials.is_some() {
    [0x05, 0x02]
  } else {
    [0x05, 0x00]
  };
  if selected != expected {
    return Err(anyhow!(
      "outbound SOCKS5 proxy rejected the offered authentication method"
    ));
  }

  let Some((username, password)) = credentials else {
    return Ok(());
  };
  let username = username.as_bytes();
  let password = password.as_bytes();
  if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
    return Err(anyhow!("outbound SOCKS5 credentials exceed protocol limits"));
  }
  let mut request = Vec::with_capacity(3 + username.len() + password.len());
  request.extend_from_slice(&[0x01, username.len() as u8]);
  request.extend_from_slice(username);
  request.push(password.len() as u8);
  request.extend_from_slice(password);
  stream.write_all(&request).await?;
  stream.flush().await?;
  let mut response = [0u8; 2];
  stream.read_exact(&mut response).await?;
  if response != [0x01, 0x00] {
    return Err(anyhow!("outbound SOCKS5 proxy rejected its credentials"));
  }
  Ok(())
}

enum Socks5Target {
  Ip(IpAddr),
  Domain(String),
}

async fn socks5_target(target: &ResolvedAuthority, remote_dns: bool) -> anyhow::Result<Socks5Target> {
  if let Ok(address) = target.host().as_str().parse::<IpAddr>() {
    return Ok(Socks5Target::Ip(address));
  }
  if remote_dns {
    return Ok(Socks5Target::Domain(target.host().as_str().to_owned()));
  }
  let mut addresses = tokio::net::lookup_host((target.host().as_str(), target.port()))
    .await
    .context("resolve SOCKS5 tunnel target locally")?;
  addresses
    .next()
    .map(|address| Socks5Target::Ip(address.ip()))
    .ok_or_else(|| anyhow!("SOCKS5 tunnel target resolved to no addresses"))
}

async fn send_socks5_connect(stream: &mut TcpStream, target: Socks5Target, port: u16) -> anyhow::Result<()> {
  let mut request = vec![0x05, 0x01, 0x00];
  match target {
    Socks5Target::Ip(IpAddr::V4(address)) => {
      request.push(0x01);
      request.extend_from_slice(&address.octets());
    }
    Socks5Target::Ip(IpAddr::V6(address)) => {
      request.push(0x04);
      request.extend_from_slice(&address.octets());
    }
    Socks5Target::Domain(host) => {
      let host = host.as_bytes();
      if host.len() > u8::MAX as usize {
        return Err(anyhow!("SOCKS5 tunnel target hostname exceeds protocol limits"));
      }
      request.extend_from_slice(&[0x03, host.len() as u8]);
      request.extend_from_slice(host);
    }
  }
  request.extend_from_slice(&port.to_be_bytes());
  stream.write_all(&request).await?;
  stream.flush().await?;

  let mut response = [0u8; 4];
  stream.read_exact(&mut response).await?;
  if response[0] != 0x05 || response[2] != 0x00 {
    return Err(anyhow!("outbound SOCKS5 proxy returned an invalid response"));
  }
  if response[1] != 0x00 {
    return Err(anyhow!("outbound SOCKS5 proxy rejected the CONNECT request"));
  }
  let address_bytes = match response[3] {
    0x01 => 4,
    0x04 => 16,
    0x03 => {
      let mut length = [0u8; 1];
      stream.read_exact(&mut length).await?;
      usize::from(length[0])
    }
    _ => return Err(anyhow!("outbound SOCKS5 proxy returned an unsupported address type")),
  };
  let mut ignored = vec![0u8; address_bytes + 2];
  stream.read_exact(&mut ignored).await?;
  Ok(())
}

async fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
  TcpStream::connect((host, port)).await
}

fn target_uri(target: &ResolvedAuthority) -> Uri {
  format!("https://{target}/")
    .parse()
    .expect("a canonical resolved authority always forms a valid HTTPS URI")
}

fn build_proxy_tls_config() -> TunnelConnectorBuildResult<Arc<rustls::ClientConfig>> {
  let loaded = rustls_native_certs::load_native_certs();
  let mut roots = rustls::RootCertStore::empty();
  for certificate in loaded.certs {
    let _ = roots.add(certificate);
  }
  if roots.is_empty() {
    let detail = loaded
      .errors
      .into_iter()
      .next()
      .map(|error| error.to_string())
      .unwrap_or_else(|| "no certificates were discovered".to_owned());
    return Err(TunnelConnectorBuildError::NativeRoots { detail });
  }
  for error in loaded.errors {
    tracing::warn!(%error, "failed to load one native root certificate for outbound HTTPS proxying");
  }
  let mut config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  config.alpn_protocols = vec![HTTP_1_1_ALPN.to_vec()];
  Ok(Arc::new(config))
}

enum OpenTunnelError {
  Transport(anyhow::Error),
  ProxyRejected { status: u16 },
}

impl OpenTunnelError {
  fn transport(source: impl Into<anyhow::Error>) -> Self {
    Self::Transport(source.into())
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum TunnelConnectorBuildError {
  #[snafu(display("configured outbound proxy URL is invalid: {source}"))]
  InvalidProxyUrl { source: anyhow::Error },

  #[snafu(display("configured outbound proxy scheme '{scheme}' is unsupported for CONNECT tunnels"))]
  UnsupportedProxyScheme { scheme: String },

  #[snafu(display("failed to build outbound HTTPS proxy trust roots: {detail}"))]
  NativeRoots { detail: String },
}

pub type TunnelConnectorBuildResult<T> = std::result::Result<T, TunnelConnectorBuildError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum TunnelConnectError {
  #[snafu(display("timed out opening a tunnel to '{target}'"))]
  Timeout { target: ResolvedAuthority },

  #[snafu(display("failed to open a tunnel to '{target}': {source}"))]
  Transport {
    target: ResolvedAuthority,
    source: anyhow::Error,
  },

  #[snafu(display("outbound proxy rejected the tunnel to '{target}' with status {status}"))]
  ProxyRejected { target: ResolvedAuthority, status: u16 },
}

pub type TunnelConnectResult<T> = std::result::Result<T, TunnelConnectError>;

#[cfg(test)]
mod tests {
  use super::*;
  use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
  use std::net::SocketAddr;
  use std::num::NonZeroU16;
  use tokio::net::TcpListener;
  use tokio_rustls::TlsAcceptor;
  use tokn_policy::CanonicalHost;

  fn target(host: &str, port: u16) -> ResolvedAuthority {
    ResolvedAuthority::new(CanonicalHost::parse(host).unwrap(), NonZeroU16::new(port).unwrap())
  }

  fn proxy_options(address: SocketAddr) -> HttpClientOptions {
    HttpClientOptions {
      url: Some(format!("http://{address}")),
      no_proxy: Vec::new(),
      system: false,
    }
  }

  async fn read_request_head<S>(stream: &mut S) -> Vec<u8>
  where
    S: AsyncRead + Unpin,
  {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
      stream.read_exact(&mut byte).await.unwrap();
      head.push(byte[0]);
      assert!(head.len() < 4096);
    }
    head
  }

  #[test]
  fn invalid_and_unsupported_proxy_urls_fail_generation_build() {
    let invalid = TunnelConnector::build(&HttpClientOptions {
      url: Some("http://[invalid".to_owned()),
      no_proxy: Vec::new(),
      system: false,
    });
    assert!(matches!(
      invalid,
      Err(TunnelConnectorBuildError::InvalidProxyUrl { .. })
    ));

    let unsupported = TunnelConnector::build(&HttpClientOptions {
      url: Some("ftp://proxy.example".to_owned()),
      no_proxy: Vec::new(),
      system: false,
    });
    assert!(matches!(
      unsupported,
      Err(TunnelConnectorBuildError::UnsupportedProxyScheme { .. })
    ));
  }

  #[tokio::test]
  async fn http_proxy_preserves_bytes_read_ahead_after_a_final_2xx() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let request = read_request_head(&mut stream).await;
      assert!(request.starts_with(b"CONNECT api.example:443 HTTP/1.1\r\n"));
      stream
        .write_all(b"HTTP/1.1 204 No Content\r\nX-Test: yes\r\n\r\nimmediate")
        .await
        .unwrap();
    });

    let connector = TunnelConnector::build(&proxy_options(address)).unwrap();
    let mut stream = connector.connect(&target("api.example", 443)).await.unwrap();
    let mut immediate = [0u8; 9];
    stream.read_exact(&mut immediate).await.unwrap();
    assert_eq!(&immediate, b"immediate");
    proxy.await.unwrap();
  }

  #[tokio::test]
  async fn http_proxy_uses_canonical_bracketed_ipv6_authorities() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let request = read_request_head(&mut stream).await;
      let request = std::str::from_utf8(&request).unwrap();
      assert!(request.starts_with("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n"));
      assert!(request.contains("\r\nHost: [2001:db8::1]:8443\r\n"));
      stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    });

    let connector = TunnelConnector::build(&proxy_options(address)).unwrap();
    let _stream = connector.connect(&target("2001:db8::1", 8443)).await.unwrap();
    proxy.await.unwrap();
  }

  #[tokio::test]
  async fn https_proxy_tunnel_remains_inside_tls_after_connect() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let certificate = generated.cert.der().clone();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()));
    let mut server_config = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(vec![certificate.clone()], private_key)
      .unwrap();
    server_config.alpn_protocols = vec![HTTP_1_1_ALPN.to_vec()];

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let mut client_config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth();
    client_config.alpn_protocols = vec![HTTP_1_1_ALPN.to_vec()];

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
      let (stream, _) = listener.accept().await.unwrap();
      let mut stream = TlsAcceptor::from(Arc::new(server_config)).accept(stream).await.unwrap();
      let request = read_request_head(&mut stream).await;
      assert!(request.starts_with(b"CONNECT api.example:443 HTTP/1.1\r\n"));
      stream.write_all(b"HTTP/1.1 200 OK\r\n\r\ntls-ready").await.unwrap();
      let mut tunneled = [0u8; 1];
      stream.read_exact(&mut tunneled).await.unwrap();
      assert_eq!(tunneled, [b'x']);
    });

    let connector = TunnelConnector {
      proxy_matcher: Matcher::builder().all(format!("https://{address}")).build(),
      proxy_tls: Some(Arc::new(client_config)),
    };
    let mut stream = connector.connect(&target("api.example", 443)).await.unwrap();
    let mut ready = [0u8; 9];
    stream.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"tls-ready");
    stream.write_all(b"x").await.unwrap();
    stream.flush().await.unwrap();
    proxy.await.unwrap();
  }

  #[tokio::test]
  async fn socks5h_proxy_receives_the_canonical_domain_and_preserves_tunnel_bytes() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut greeting = [0u8; 3];
      stream.read_exact(&mut greeting).await.unwrap();
      assert_eq!(greeting, [0x05, 0x01, 0x00]);
      stream.write_all(&[0x05, 0x00]).await.unwrap();

      let mut request = [0u8; 5];
      stream.read_exact(&mut request).await.unwrap();
      assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x03]);
      let mut host = vec![0u8; usize::from(request[4])];
      stream.read_exact(&mut host).await.unwrap();
      assert_eq!(&host, b"api.example");
      let mut port = [0u8; 2];
      stream.read_exact(&mut port).await.unwrap();
      assert_eq!(u16::from_be_bytes(port), 8443);
      stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
        .await
        .unwrap();
      stream.write_all(b"ready").await.unwrap();
    });

    let connector = TunnelConnector::build(&HttpClientOptions {
      url: Some(format!("socks5h://{address}")),
      no_proxy: Vec::new(),
      system: false,
    })
    .unwrap();
    let mut stream = connector.connect(&target("api.example", 8443)).await.unwrap();
    let mut ready = [0u8; 5];
    stream.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"ready");
    proxy.await.unwrap();
  }

  #[tokio::test]
  async fn http_proxy_rejection_remains_typed() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let _ = read_request_head(&mut stream).await;
      stream
        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        .await
        .unwrap();
    });

    let connector = TunnelConnector::build(&proxy_options(address)).unwrap();
    let Err(error) = connector.connect(&target("api.example", 443)).await else {
      panic!("expected the outbound proxy rejection")
    };
    assert!(matches!(error, TunnelConnectError::ProxyRejected { status: 407, .. }));
    proxy.await.unwrap();
  }
}

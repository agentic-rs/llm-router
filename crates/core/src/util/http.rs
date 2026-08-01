use anyhow::Result;
use bytes::Bytes;
use http::HeaderMap as NativeHeaderMap;
use reqwest::Method;
use serde::de::DeserializeOwned;
use snafu::ResultExt;
use std::time::Duration;
use tokn_headers::HeaderMap;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CONTROL_PLANE_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientKind {
  Control,
  Managed,
  Opaque,
}

impl ClientKind {
  fn total_timeout(self) -> Option<Duration> {
    match self {
      Self::Control => Some(CONTROL_PLANE_TOTAL_TIMEOUT),
      Self::Managed | Self::Opaque => None,
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct HttpClientOptions {
  pub url: Option<String>,
  pub no_proxy: Vec<String>,
  pub system: bool,
}

/// Build the bounded client used by control-plane and legacy call sites.
pub fn build_client(options: &HttpClientOptions) -> Result<reqwest::Client> {
  build_client_with_options(control_plane_client_builder(), options)
}

/// Build a client for one selected managed upstream attempt.
///
/// Redirects are returned to the caller so execution cannot drift away from
/// the selected upstream. Response decompression remains enabled because
/// managed JSON and SSE conversion operate on decoded bytes. No total request
/// timeout is installed: reqwest applies that deadline through the complete
/// response body, which would terminate long-lived SSE streams.
pub fn build_managed_client(options: &HttpClientOptions) -> Result<reqwest::Client> {
  build_client_with_options(managed_client_builder(), options)
}

/// Build a client for opaque relay and transparent traffic.
///
/// Redirects are returned to the caller instead of being followed, and
/// response content codings remain untouched so the caller can forward the
/// original response headers and bytes together. No total request timeout is
/// installed because opaque response bodies may be arbitrarily long-lived.
pub fn build_opaque_client(options: &HttpClientOptions) -> Result<reqwest::Client> {
  build_client_with_options(opaque_client_builder(), options)
}

/// Common connection and pooling policy.
///
/// [`ClientKind`] determines whether to add a total request timeout. Reqwest's
/// default is no total timeout, which the data-plane kinds retain.
fn transport_client_builder(kind: ClientKind) -> reqwest::ClientBuilder {
  let builder = reqwest::Client::builder()
    .connect_timeout(CONNECT_TIMEOUT)
    .pool_idle_timeout(Some(POOL_IDLE_TIMEOUT));
  match kind.total_timeout() {
    Some(timeout) => builder.timeout(timeout),
    None => builder,
  }
}

fn control_plane_client_builder() -> reqwest::ClientBuilder {
  with_decompression(transport_client_builder(ClientKind::Control))
}

fn managed_client_builder() -> reqwest::ClientBuilder {
  with_decompression(transport_client_builder(ClientKind::Managed)).redirect(reqwest::redirect::Policy::none())
}

fn opaque_client_builder() -> reqwest::ClientBuilder {
  transport_client_builder(ClientKind::Opaque)
    .redirect(reqwest::redirect::Policy::none())
    .gzip(false)
    .brotli(false)
    .deflate(false)
    .zstd(false)
}

fn with_decompression(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
  builder
    // Personas advertise `Accept-Encoding: gzip, deflate, br, zstd` (from
    // real-world captures), and providers honor it (zai → gzip). Without
    // these toggles reqwest hands compressed bytes to managed response
    // conversion, which then fails to parse JSON or SSE. Reqwest also removes
    // `Content-Encoding` and `Content-Length` after decoding so headers remain
    // consistent with the returned body.
    .gzip(true)
    .brotli(true)
    .deflate(true)
    .zstd(true)
}

fn build_client_with_options(
  mut builder: reqwest::ClientBuilder,
  options: &HttpClientOptions,
) -> Result<reqwest::Client> {
  builder = apply_proxy_options(builder, options)?;
  Ok(builder.build()?)
}

fn apply_proxy_options(
  mut builder: reqwest::ClientBuilder,
  options: &HttpClientOptions,
) -> Result<reqwest::ClientBuilder> {
  if let Some(url) = &options.url {
    let mut p = reqwest::Proxy::all(url).map_err(|e| anyhow::anyhow!("invalid proxy url: {url}: {e}"))?;
    if !options.no_proxy.is_empty() {
      let joined = options.no_proxy.join(",");
      if let Some(np) = reqwest::NoProxy::from_string(&joined) {
        p = p.no_proxy(Some(np));
      }
    }
    builder = builder.proxy(p);
    tracing::info!(scheme = %scheme_of(url), "outbound proxy enabled");
  } else if options.system {
    // Defer to reqwest defaults (env vars).
    tracing::info!("outbound proxy: deferring to system env vars");
  } else {
    // Explicitly disable any ambient HTTP_PROXY/HTTPS_PROXY.
    builder = builder.no_proxy();
  }
  Ok(builder)
}

pub async fn send(
  client: &reqwest::Client,
  method: Method,
  url: &str,
  mut headers: HeaderMap,
  body: Option<Bytes>,
  what: &'static str,
) -> crate::provider::Result<reqwest::Response> {
  // Strip transport-derived headers before handing off to reqwest:
  //   - `Host`     : MUST be derived from `url` (SNI + HTTP Host must agree
  //                  or upstream WAFs reject; e.g. zai returns 403 when a
  //                  stale persona-default `Host: api.deepseek.com` survives
  //                  to a request actually sent to `api.z.ai`).
  //   - `Content-Length` : reqwest computes the correct value from `body`;
  //                  a stale persona-supplied value will not match the
  //                  serialized payload.
  // Persona builders may inject these from inbound captures or from defaults
  // derived from real-world traffic; that's fine for diagnostics but must
  // not reach the wire.
  let stripped_host = headers.remove(&tokn_headers::keys::HOST);
  let stripped_clen = headers.remove(&tokn_headers::keys::CONTENT_LENGTH);
  if stripped_host > 0 || stripped_clen > 0 {
    tracing::trace!(
      what,
      stripped_host,
      stripped_clen,
      "stripped transport headers before reqwest dispatch"
    );
  }
  send_native(client, method, url, headers.into(), body, what).await
}

/// Send one request from a native HTTP header map without a lossy conversion.
///
/// This boundary is intended for opaque v2 transport, where duplicate values
/// and non-UTF-8 header bytes must reach reqwest unchanged. `Host` and
/// `Content-Length` are always discarded so reqwest derives connection and
/// framing metadata from the selected URL and actual body.
pub async fn send_native(
  client: &reqwest::Client,
  method: Method,
  url: &str,
  headers: NativeHeaderMap,
  body: Option<Bytes>,
  what: &'static str,
) -> crate::provider::Result<reqwest::Response> {
  build_native_request(client, method, url, headers, body, what)
    .send()
    .await
    .context(crate::provider::error::HttpSnafu { what })
}

fn build_native_request(
  client: &reqwest::Client,
  method: Method,
  url: &str,
  mut headers: NativeHeaderMap,
  body: Option<Bytes>,
  what: &'static str,
) -> reqwest::RequestBuilder {
  let stripped_host = headers.remove(http::header::HOST).is_some();
  let stripped_content_length = headers.remove(http::header::CONTENT_LENGTH).is_some();
  if stripped_host || stripped_content_length {
    tracing::trace!(
      what,
      stripped_host,
      stripped_content_length,
      "stripped native transport headers before reqwest dispatch"
    );
  }

  let request = client.request(method, url).headers(headers);
  match body {
    Some(body) => request.body(body),
    None => request,
  }
}

pub async fn read_json<T>(resp: reqwest::Response, what: &'static str) -> crate::provider::Result<T>
where
  T: DeserializeOwned,
{
  let status = resp.status();
  let body = resp.text().await.unwrap_or_default();
  if !status.is_success() {
    return crate::provider::error::HttpStatusSnafu { what, status, body }.fail();
  }
  snafu::ResultExt::context(
    serde_json::from_str(&body),
    crate::provider::error::JsonSnafu {
      what,
      body: body.clone(),
    },
  )
}

fn scheme_of(url: &str) -> &str {
  url.split("://").next().unwrap_or("?")
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::SocketAddr;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  #[test]
  fn total_timeout_is_bounded_only_for_control_plane_clients() {
    assert_eq!(ClientKind::Control.total_timeout(), Some(CONTROL_PLANE_TOTAL_TIMEOUT));
    assert_eq!(ClientKind::Managed.total_timeout(), None);
    assert_eq!(ClientKind::Opaque.total_timeout(), None);
  }

  #[test]
  fn control_plane_client_builds_without_proxy() {
    build_client(&HttpClientOptions::default()).expect("control-plane client should build");
  }

  #[test]
  fn opaque_client_builds_without_proxy() {
    build_opaque_client(&HttpClientOptions::default()).expect("opaque client should build");
  }

  #[test]
  fn managed_client_builds_without_proxy() {
    build_managed_client(&HttpClientOptions::default()).expect("managed client should build");
  }

  #[test]
  fn native_request_preserves_duplicate_and_raw_header_values() {
    let client = build_opaque_client(&HttpClientOptions::default()).unwrap();
    let mut headers = NativeHeaderMap::new();
    headers.append("x-duplicate", reqwest::header::HeaderValue::from_static("first"));
    headers.append("x-duplicate", reqwest::header::HeaderValue::from_static("second"));
    headers.insert(
      "x-raw",
      reqwest::header::HeaderValue::from_bytes(&[0x80, 0xff]).unwrap(),
    );
    headers.insert(
      http::header::HOST,
      reqwest::header::HeaderValue::from_static("wrong.invalid"),
    );
    headers.insert(
      http::header::CONTENT_LENGTH,
      reqwest::header::HeaderValue::from_static("999"),
    );
    let body = Bytes::from_static(b"payload");

    let request = build_native_request(
      &client,
      Method::POST,
      "https://upstream.invalid/v1/raw",
      headers,
      Some(body.clone()),
      "native header test",
    )
    .build()
    .unwrap();

    assert_eq!(
      request
        .headers()
        .get_all("x-duplicate")
        .iter()
        .map(|value| value.as_bytes())
        .collect::<Vec<_>>(),
      [b"first".as_slice(), b"second".as_slice()]
    );
    assert_eq!(request.headers()["x-raw"].as_bytes(), [0x80, 0xff]);
    assert!(!request.headers().contains_key(http::header::HOST));
    assert!(!request.headers().contains_key(http::header::CONTENT_LENGTH));
    assert_eq!(request.body().and_then(reqwest::Body::as_bytes), Some(body.as_ref()));
  }

  #[tokio::test]
  async fn managed_client_does_not_follow_redirects() {
    let address = serve_redirect_then_ok().await;
    let client = build_managed_client(&HttpClientOptions::default()).unwrap();
    let response = client.get(format!("http://{address}/start")).send().await.unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
  }

  #[tokio::test]
  async fn managed_client_decodes_encoded_response_bytes() {
    const GZIP_BODY: &[u8] = &[
      31, 139, 8, 0, 0, 0, 0, 0, 2, 19, 203, 77, 204, 75, 76, 79, 77, 81, 72, 73, 77, 206, 79, 1, 210, 73, 149, 37,
      169, 197, 0, 77, 154, 181, 35, 21, 0, 0, 0,
    ];

    let address = serve_once("gzip", GZIP_BODY).await;
    let client = build_managed_client(&HttpClientOptions::default()).unwrap();
    let response = client.get(format!("http://{address}/encoded")).send().await.unwrap();

    assert!(!response.headers().contains_key(reqwest::header::CONTENT_ENCODING));
    assert!(!response.headers().contains_key(reqwest::header::CONTENT_LENGTH));
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"managed decoded bytes");
  }

  #[tokio::test]
  async fn opaque_client_does_not_follow_redirects() {
    let address = serve_redirect_then_ok().await;
    let client = build_opaque_client(&HttpClientOptions::default()).unwrap();
    let response = client.get(format!("http://{address}/start")).send().await.unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
  }

  #[tokio::test]
  async fn opaque_client_preserves_encoded_response_bytes() {
    let client = build_opaque_client(&HttpClientOptions::default()).unwrap();
    let encoded = b"opaque encoded bytes";

    for encoding in ["gzip", "br", "deflate", "zstd"] {
      let address = serve_once(encoding, encoded).await;
      let response = client.get(format!("http://{address}/encoded")).send().await.unwrap();

      assert_eq!(response.headers()[reqwest::header::CONTENT_ENCODING], encoding);
      assert_eq!(response.bytes().await.unwrap().as_ref(), encoded);
    }
  }

  async fn serve_redirect_then_ok() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
      for response in [
        format!(
          "HTTP/1.1 302 Found\r\nlocation: http://{address}/followed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        ),
        "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string(),
      ] {
        let Ok(Ok((mut socket, _))) = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await else {
          return;
        };
        read_request_head(&mut socket).await;
        socket.write_all(response.as_bytes()).await.unwrap();
      }
    });
    address
  }

  async fn serve_once(content_encoding: &'static str, body: &'static [u8]) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
      let (mut socket, _) = listener.accept().await.unwrap();
      read_request_head(&mut socket).await;
      let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-encoding: {content_encoding}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
      );
      socket.write_all(head.as_bytes()).await.unwrap();
      socket.write_all(body).await.unwrap();
    });
    address
  }

  async fn read_request_head(socket: &mut tokio::net::TcpStream) {
    let mut request = [0_u8; 4096];
    let read = socket.read(&mut request).await.unwrap();
    assert!(read > 0, "client closed before sending a request head");
  }
}

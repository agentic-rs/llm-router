use super::connect_proxy::{connect_upstream, ConnectProxy};
use crate::api::error::ApiError;
use crate::v2::{InboundConnectionInfo, LiveForwardProxyState, ProxyAuthenticationError};
use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, Method, Request, Response, StatusCode};
use axum::response::IntoResponse;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tokn_access::AccessContext;
use tokn_policy::{CanonicalAuthority, ConnectAction, IngressAuthority};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

enum PreparedConnect {
  Tunnel(TcpStream),
  Intercept(Arc<rustls::ServerConfig>),
}

struct ConnectUpgrade {
  ingress: IngressAuthority,
  access: AccessContext,
  connection: InboundConnectionInfo,
  on_upgrade: hyper::upgrade::OnUpgrade,
  transport: PreparedConnect,
}

pub(super) async fn handle_v2_client(
  stream: TcpStream,
  peer: SocketAddr,
  state: LiveForwardProxyState,
  outbound_proxy: Arc<ConnectProxy>,
  mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
  let connection = InboundConnectionInfo::new(stream.local_addr().ok(), peer);
  let (upgrades, mut upgrade_receiver) = mpsc::channel(1);
  let service_state = state.clone();
  let service_proxy = outbound_proxy.clone();
  let service = service_fn(move |request| {
    let state = service_state.clone();
    let outbound_proxy = service_proxy.clone();
    let upgrades = upgrades.clone();
    async move { Ok::<_, Infallible>(handle_request(state, outbound_proxy, upgrades, connection, request).await) }
  });
  let builder = http1_builder();
  let connection = builder.serve_connection(TokioIo::new(stream), service).with_upgrades();
  tokio::pin!(connection);
  tokio::select! {
    result = &mut connection => result.context("serve v2 proxy HTTP connection")?,
    _ = shutdown_requested(&mut shutdown) => return Ok(()),
  }
  let upgrade = tokio::select! {
    upgrade = upgrade_receiver.recv() => upgrade,
    _ = shutdown_requested(&mut shutdown) => return Ok(()),
  };
  if let Some(upgrade) = upgrade {
    tokio::select! {
      result = run_connect(upgrade, state) => {
        result.with_context(|| format!("run v2 CONNECT session from {peer}"))?;
      }
      _ = shutdown_requested(&mut shutdown) => {}
    }
  }
  Ok(())
}

async fn handle_request(
  state: LiveForwardProxyState,
  outbound_proxy: Arc<ConnectProxy>,
  upgrades: mpsc::Sender<ConnectUpgrade>,
  connection: InboundConnectionInfo,
  mut request: Request<hyper::body::Incoming>,
) -> Response<Body> {
  if request.method() != Method::CONNECT {
    let request_id = crate::request_id::ensure_request_id(request.headers_mut());
    let mut response = handle_request_inner(state, outbound_proxy, upgrades, connection, request).await;
    crate::request_id::set_response_request_id(&mut response, request_id);
    return response;
  }

  handle_request_inner(state, outbound_proxy, upgrades, connection, request).await
}

async fn handle_request_inner(
  live: LiveForwardProxyState,
  outbound_proxy: Arc<ConnectProxy>,
  upgrades: mpsc::Sender<ConnectUpgrade>,
  connection: InboundConnectionInfo,
  mut request: Request<hyper::body::Incoming>,
) -> Response<Body> {
  if is_websocket_upgrade(request.headers()) {
    return websocket_upgrade_response();
  }
  if request.method() == Method::CONNECT && request_body_present(&request) {
    return ApiError::bad_request("CONNECT requests must not contain a body representation").into_response();
  }
  let admission = if request.method() == Method::CONNECT {
    admit_connect(&request).map(Admission::Connect)
  } else {
    admit_direct_http(&request).map(Admission::Http)
  };
  let admission = match admission {
    Ok(admission) => admission,
    Err(error) => return ApiError::bad_request(error.to_string()).into_response(),
  };
  let state = live.current();
  let access = match state.authenticate_proxy(request.headers_mut()).await {
    Ok(access) => access,
    Err(ProxyAuthenticationError::Rejected) => return proxy_auth_required(),
    Err(ProxyAuthenticationError::Unavailable) => {
      return response(StatusCode::INTERNAL_SERVER_ERROR, "proxy authentication unavailable");
    }
  };

  match admission {
    Admission::Http(ingress) => {
      if let Err(error) = strip_hop_by_hop_headers(request.headers_mut()) {
        return ApiError::bad_request(error.to_string()).into_response();
      }
      state.dispatch_http(&ingress, "http", access, connection, request).await
    }
    Admission::Connect(ingress) => {
      let transport = match state.connect_action_for(&ingress) {
        ConnectAction::Reject => return response(StatusCode::FORBIDDEN, "CONNECT rejected by listener policy"),
        ConnectAction::Tunnel => match connect_upstream(ingress.host().as_str(), ingress.port(), &outbound_proxy).await
        {
          Ok(upstream) => PreparedConnect::Tunnel(upstream),
          Err(error) => return ApiError::bad_gateway(error.to_string()).into_response(),
        },
        ConnectAction::Intercept => match state.pinned_tls_config(&ingress) {
          Ok(config) => PreparedConnect::Intercept(config),
          Err(error) => return ApiError::bad_gateway(error.to_string()).into_response(),
        },
      };
      let on_upgrade = hyper::upgrade::on(&mut request);
      let upgrade = ConnectUpgrade {
        ingress,
        access,
        connection,
        on_upgrade,
        transport,
      };
      if upgrades.send(upgrade).await.is_err() {
        return response(StatusCode::INTERNAL_SERVER_ERROR, "CONNECT upgrade unavailable");
      }
      response(StatusCode::OK, "")
    }
  }
}

enum Admission {
  Http(IngressAuthority),
  Connect(IngressAuthority),
}

fn admit_connect(request: &Request<hyper::body::Incoming>) -> Result<IngressAuthority> {
  if request.uri().scheme().is_some() || request.uri().path_and_query().is_some() {
    anyhow::bail!("CONNECT requires an authority-form request target");
  }
  let authority = request
    .uri()
    .authority()
    .ok_or_else(|| anyhow::anyhow!("CONNECT request target has no authority"))?;
  let ingress = IngressAuthority::from_connect_authority(CanonicalAuthority::parse(authority.as_str())?)?;
  if let Some(host) = single_host(request.headers())? {
    ingress
      .validate_inner(host, std::num::NonZeroU16::new(443).expect("HTTPS port is nonzero"))
      .context("CONNECT Host header does not match request target")?;
  }
  Ok(ingress)
}

fn admit_direct_http(request: &Request<hyper::body::Incoming>) -> Result<IngressAuthority> {
  if request.uri().scheme_str() != Some("http") || request.uri().authority().is_none() {
    anyhow::bail!("forward proxy requests require an absolute http:// request target");
  }
  let authority = CanonicalAuthority::parse(
    request
      .uri()
      .authority()
      .expect("absolute request target has an authority")
      .as_str(),
  )?;
  let ingress = IngressAuthority::from_http(authority, std::num::NonZeroU16::new(80).expect("HTTP port is nonzero"));
  if let Some(host) = single_host(request.headers())? {
    ingress
      .validate_inner(host, std::num::NonZeroU16::new(80).expect("HTTP port is nonzero"))
      .context("Host header does not match request target")?;
  }
  Ok(ingress)
}

async fn run_connect(upgrade: ConnectUpgrade, state: LiveForwardProxyState) -> Result<()> {
  let upgraded = upgrade.on_upgrade.await.context("upgrade downstream CONNECT")?;
  let downstream = TokioIo::new(upgraded);
  match upgrade.transport {
    PreparedConnect::Tunnel(mut upstream) => {
      let mut downstream = downstream;
      tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
        .await
        .context("pump CONNECT tunnel")?;
    }
    PreparedConnect::Intercept(config) => {
      let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, TlsAcceptor::from(config).accept(downstream))
        .await
        .context("intercepted TLS handshake timed out")?
        .context("intercepted TLS handshake failed")?;
      let ingress = upgrade.ingress;
      let access = upgrade.access;
      let connection = upgrade.connection;
      let service = service_fn(move |mut request| {
        let state = state.current();
        let ingress = ingress.clone();
        let access = access.clone();
        async move {
          let request_id = crate::request_id::ensure_request_id(request.headers_mut());
          let mut response = if is_websocket_upgrade(request.headers()) {
            websocket_upgrade_response()
          } else {
            match admit_intercepted(&request, &ingress) {
              Ok(()) => {
                request.headers_mut().remove(header::PROXY_AUTHORIZATION);
                match strip_hop_by_hop_headers(request.headers_mut()) {
                  Ok(()) => {
                    state
                      .dispatch_http(&ingress, "https", access, connection, request)
                      .await
                  }
                  Err(error) => ApiError::bad_request(error.to_string()).into_response(),
                }
              }
              Err(error) => ApiError::bad_request(error.to_string()).into_response(),
            }
          };
          crate::request_id::set_response_request_id(&mut response, request_id);
          Ok::<_, Infallible>(response)
        }
      });
      let builder = http1_builder();
      builder
        .serve_connection(TokioIo::new(tls), service)
        .await
        .context("serve intercepted HTTPS connection")?;
    }
  }
  Ok(())
}

fn admit_intercepted(request: &Request<hyper::body::Incoming>, ingress: &IngressAuthority) -> Result<()> {
  if request.method() == Method::CONNECT {
    anyhow::bail!("nested CONNECT is not supported");
  }
  let authority = match (request.uri().scheme_str(), request.uri().authority()) {
    (None, None) => {
      single_host(request.headers())?.ok_or_else(|| anyhow::anyhow!("intercepted request has no Host"))?
    }
    (Some("https"), Some(authority)) => {
      let authority = CanonicalAuthority::parse(authority.as_str())?;
      if let Some(host) = single_host(request.headers())? {
        ingress
          .validate_inner(host, std::num::NonZeroU16::new(443).expect("HTTPS port is nonzero"))
          .context("intercepted Host header does not match CONNECT authority")?;
      }
      authority
    }
    _ => anyhow::bail!("intercepted request requires origin-form or an absolute https:// target"),
  };
  ingress
    .validate_inner(
      authority,
      std::num::NonZeroU16::new(443).expect("HTTPS port is nonzero"),
    )
    .context("intercepted request authority does not match CONNECT authority")
}

fn single_host(headers: &HeaderMap) -> Result<Option<CanonicalAuthority>> {
  let mut values = headers.get_all(header::HOST).iter();
  let Some(value) = values.next() else {
    return Ok(None);
  };
  if values.next().is_some() {
    anyhow::bail!("request contains multiple Host headers");
  }
  let value = value.to_str().context("Host header is not UTF-8")?;
  CanonicalAuthority::parse(value).map(Some).map_err(Into::into)
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
  let connection_upgrade = headers
    .get_all(header::CONNECTION)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .any(|value| value.trim().eq_ignore_ascii_case("upgrade"));
  connection_upgrade
    && headers
      .get(header::UPGRADE)
      .and_then(|value| value.to_str().ok())
      .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
}

fn request_body_present(request: &Request<hyper::body::Incoming>) -> bool {
  request.headers().contains_key(header::CONTENT_LENGTH)
    || request.headers().contains_key(header::TRANSFER_ENCODING)
    || !hyper::body::Body::is_end_stream(request.body())
}

fn strip_hop_by_hop_headers(headers: &mut HeaderMap) -> Result<()> {
  let nominated = headers
    .get_all(header::CONNECTION)
    .iter()
    .map(|value| value.to_str().context("Connection header is not UTF-8"))
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .filter(|name| !name.is_empty())
    .map(|name| HeaderName::from_bytes(name.as_bytes()).context("Connection header names an invalid header"))
    .collect::<Result<Vec<_>>>()?;

  for name in [
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ] {
    headers.remove(name);
  }
  for name in nominated {
    headers.remove(name);
  }
  Ok(())
}

fn http1_builder() -> http1::Builder {
  let mut builder = http1::Builder::new();
  builder
    .half_close(true)
    .keep_alive(true)
    .title_case_headers(true)
    .timer(TokioTimer::new())
    .header_read_timeout(HTTP_HEADER_READ_TIMEOUT);
  builder
}

fn proxy_auth_required() -> Response<Body> {
  let mut response = response(
    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
    "proxy authentication required",
  );
  response
    .headers_mut()
    .insert(header::PROXY_AUTHENTICATE, header::HeaderValue::from_static("Bearer"));
  response
}

fn websocket_upgrade_response() -> Response<Body> {
  let mut response = response(StatusCode::UPGRADE_REQUIRED, "");
  response
    .headers_mut()
    .insert(header::CONNECTION, header::HeaderValue::from_static("Upgrade"));
  response
    .headers_mut()
    .insert(header::UPGRADE, header::HeaderValue::from_static("websocket"));
  response
}

fn response(status: StatusCode, message: &str) -> Response<Body> {
  let mut response = Response::new(Body::from(message.to_string()));
  *response.status_mut() = status;
  response
}

async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
  if *shutdown.borrow() {
    return;
  }
  let _ = shutdown.changed().await;
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::http::HeaderValue;

  #[test]
  fn strips_fixed_and_connection_nominated_hop_by_hop_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive, x-remove-me"));
    headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    headers.insert(header::TE, HeaderValue::from_static("trailers"));
    headers.insert(header::TRAILER, HeaderValue::from_static("x-checksum"));
    headers.insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("h2c"));
    headers.insert("x-remove-me", HeaderValue::from_static("secret"));
    headers.insert("x-keep-me", HeaderValue::from_static("value"));

    strip_hop_by_hop_headers(&mut headers).unwrap();

    assert_eq!(headers.len(), 1);
    assert_eq!(headers["x-keep-me"], "value");
  }

  #[test]
  fn identifies_complete_websocket_upgrade_requests() {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("WebSocket"));
    assert!(is_websocket_upgrade(&headers));

    headers.remove(header::CONNECTION);
    assert!(!is_websocket_upgrade(&headers));
    headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    assert!(!is_websocket_upgrade(&headers));
  }
}

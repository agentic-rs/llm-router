use super::connect_proxy::{connect_upstream, ConnectProxy};

use super::{
  extract_proxy_auth_mode, rewrite_target, split_authority, HostPolicy, ProxyCa, ProxyPlainHttpHandler,
  ProxyPlainHttpRequest, ProxyPlainHttpResponse,
};
use crate::api::{error::ApiError, AppState, LiveAppState};
use crate::pipeline::request_header_extract;
use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Response, Uri};
use axum::response::IntoResponse;
use axum::Router;
use http::header::{HeaderValue, CONNECTION, HOST, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use smol_str::SmolStr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokn_accounts::registry::Registry;
use tokn_accounts::routing::{route_mode_as_str, RouteResolver};
use tokn_auth::descriptor::RewriteTarget;
use tokn_config::RouteMode;
use tokn_core::event::Event as CoreEvent;
use tokn_core::request_event::{RecordEvent, RequestEndpoint, RequestEvent, RequestEventPayload, Stage, StageEvent};
use tokn_policy::{CanonicalHost, ConnectAction};

const CONNECT_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BAD_CONNECT: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n";
const CONNECT_FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
const UPGRADE_REQUIRED_WEBSOCKET: &[u8] =
  b"HTTP/1.1 426 Upgrade Required\r\nconnection: Upgrade\r\nupgrade: websocket\r\ncontent-length: 0\r\n\r\n";
const PROXY_GET_HELP: &str = "tokn-router proxy is running. Configure HTTP_PROXY/HTTPS_PROXY to this address.\n";

#[derive(Clone)]
pub(super) enum ProxyRuntime {
  Legacy {
    state: Arc<LiveAppState>,
    router: Router,
    ca: Arc<ProxyCa>,
    host_policy: HostPolicy,
  },
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_client(
  stream: TcpStream,
  peer: SocketAddr,
  runtime: ProxyRuntime,
  outbound_proxy: Arc<ConnectProxy>,
  plain_http_handler: Option<ProxyPlainHttpHandler>,
) -> Result<()> {
  let mut reader = BufReader::new(stream);
  let mut request_line = String::new();
  if reader.read_line(&mut request_line).await? == 0 {
    return Ok(());
  }
  let request_line = request_line.trim_end_matches(['\r', '\n']);
  let mut parts = request_line.split_whitespace();
  let method = parts.next().unwrap_or_default();
  let authority = parts.next().unwrap_or_default();
  let _version = parts.next().unwrap_or_default();

  let mut proxy_route_mode: Option<String> = None;
  let mut host_header: Option<String> = None;
  let mut websocket_upgrade = false;
  loop {
    let mut header_line = String::new();
    if reader.read_line(&mut header_line).await? == 0 {
      break;
    }
    if header_line == "\r\n" || header_line == "\n" {
      break;
    }
    if let Some(value) = header_line
      .strip_prefix("Proxy-Authorization:")
      .or_else(|| header_line.strip_prefix("proxy-authorization:"))
    {
      let value = value.trim().trim_end_matches(['\r', '\n']);
      if let Some(mode) = extract_proxy_auth_mode(value) {
        proxy_route_mode = Some(mode);
      }
    }
    if let Some(value) = header_line
      .strip_prefix("Host:")
      .or_else(|| header_line.strip_prefix("host:"))
    {
      host_header = Some(value.trim().trim_end_matches(['\r', '\n']).to_string());
    }
    if let Some(value) = header_line
      .strip_prefix("Upgrade:")
      .or_else(|| header_line.strip_prefix("upgrade:"))
    {
      websocket_upgrade = value
        .trim()
        .trim_end_matches(['\r', '\n'])
        .eq_ignore_ascii_case("websocket");
    }
  }

  let mut stream = reader.into_inner();
  let local = stream
    .local_addr()
    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
  if websocket_upgrade {
    tracing::debug!("rejecting websocket upgrade request from {}", peer);
    stream.write_all(UPGRADE_REQUIRED_WEBSOCKET).await?;
    return Ok(());
  }
  if method == Method::GET.as_str() {
    let response = response_for_plain_get(authority, host_header, plain_http_handler);
    stream.write_all(&response).await?;
    tracing::debug!(%peer, target = authority, "served proxy listener get");
    return Ok(());
  }
  if method != Method::CONNECT.as_str() {
    stream.write_all(BAD_CONNECT).await?;
    tracing::warn!(%peer, method, "unsupported proxy method");
    return Ok(());
  }

  let (host, port) = split_authority(authority)?;
  let canonical_host = CanonicalHost::parse(&host).context("canonicalize CONNECT host")?;
  let action = match &runtime {
    ProxyRuntime::Legacy { host_policy, .. }
      if port == 443 && host_policy.should_intercept(canonical_host.as_str()) =>
    {
      ConnectAction::Intercept
    }
    ProxyRuntime::Legacy { .. } => ConnectAction::Tunnel,
  };
  tracing::debug!(%peer, host = %canonical_host, port, ?action, proxy_route_mode = ?proxy_route_mode, "proxy_connect");

  match action {
    ConnectAction::Tunnel => tunnel(stream, canonical_host.as_str(), port, outbound_proxy.as_ref()).await,
    ConnectAction::Reject => {
      stream.write_all(CONNECT_FORBIDDEN).await?;
      Ok(())
    }
    ConnectAction::Intercept => {
      let ProxyRuntime::Legacy { state, router, ca, .. } = runtime;
      let tls_config = ca.pinned_server_config(&canonical_host)?;
      stream.write_all(CONNECT_OK).await?;
      stream.flush().await?;
      intercept_tls(
        stream,
        peer,
        local,
        canonical_host.as_str(),
        port,
        state,
        router,
        tls_config,
        proxy_route_mode,
      )
      .await
    }
  }
}

fn response_for_plain_get(target: &str, host: Option<String>, handler: Option<ProxyPlainHttpHandler>) -> Vec<u8> {
  if let Some(handler) = handler {
    let request = ProxyPlainHttpRequest {
      method: Method::GET.as_str().to_string(),
      target: target.to_string(),
      host,
    };
    if let Some(response) = handler(request) {
      return serialize_plain_http_response(response);
    }
  }
  serialize_plain_http_response(ProxyPlainHttpResponse {
    status: "200 OK",
    content_type: "text/plain; charset=utf-8",
    body: PROXY_GET_HELP.to_string(),
  })
}

fn serialize_plain_http_response(response: ProxyPlainHttpResponse) -> Vec<u8> {
  let body = response.body.into_bytes();
  let mut head = format!(
    "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
    response.status,
    response.content_type,
    body.len()
  )
  .into_bytes();
  head.extend(body);
  head
}

async fn tunnel(mut client: TcpStream, host: &str, port: u16, outbound_proxy: &ConnectProxy) -> Result<()> {
  let mut upstream = connect_upstream(host, port, outbound_proxy).await?;
  client.write_all(CONNECT_OK).await?;
  client.flush().await?;
  tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn intercept_tls(
  stream: TcpStream,
  peer: SocketAddr,
  local: SocketAddr,
  host: &str,
  port: u16,
  state: Arc<LiveAppState>,
  router: Router,
  tls_config: Arc<rustls::ServerConfig>,
  proxy_route_mode: Option<String>,
) -> Result<()> {
  let tls = TlsAcceptor::from(tls_config);
  let tls_stream = tls.accept(stream).await.context("TLS handshake failed")?;
  let mut http1_builder = http1::Builder::new();
  http1_builder.keep_alive(true).title_case_headers(true);

  let host = host.to_string();
  let service = service_fn(move |req| {
    route_intercepted_request(
      state.clone(),
      router.clone(),
      peer,
      local,
      host.clone(),
      port,
      req,
      proxy_route_mode.clone(),
    )
  });
  http1_builder
    .serve_connection(TokioIo::new(tls_stream), service)
    .await
    .context("serve intercepted HTTP connection")?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn route_intercepted_request(
  live_state: Arc<LiveAppState>,
  router: Router,
  peer: SocketAddr,
  local: SocketAddr,
  intercepted_host: String,
  intercepted_port: u16,
  mut req: Request<hyper::body::Incoming>,
  proxy_route_mode: Option<String>,
) -> Result<Response<Body>, std::convert::Infallible> {
  let state = live_state.current();

  // WebSocket connections are not supported by this proxy. Detect them early and return an error response.
  if is_websocket_upgrade_headers(req.headers()) {
    return Ok(websocket_upgrade_response());
  }

  if let Some(ref mode) = proxy_route_mode {
    if !req
      .headers()
      .contains_key(tokn_accounts::routing::RouteResolver::mode_header())
    {
      if let Ok(val) = HeaderValue::from_str(mode) {
        req
          .headers_mut()
          .insert(http::header::HeaderName::from_static("x-route-mode"), val);
      }
    }
  }

  // Bare host (no port) — used by the route-rewrite branch below to
  // look up endpoints and to set the outbound `Host` header. The
  // passthrough branch ignores this and resolves its own authoritative
  // host[:port] inside `proxy_passthrough_via_pipeline`.
  let host = req
    .headers()
    .get(HOST)
    .and_then(|v| v.to_str().ok())
    .map(|s| s.split(':').next().unwrap_or(s).to_string())
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| intercepted_host.clone());
  let path = req.uri().path().to_string();
  let method = req.method().clone();

  let route_mode = resolve_proxy_route_mode(
    &state,
    state.route.as_ref(),
    req.headers(),
    &host,
    req.uri().path_and_query().map(|v| v.as_str()).unwrap_or(&path),
  );
  tracing::trace!(%host, path = %path, method = %method, resolved_mode = ?route_mode, "resolved route mode for intercepted request");
  let resolved_mode = match route_mode {
    Ok(mode) => mode,
    Err(error) => return Ok(ApiError::bad_request(error.to_string()).into_response()),
  };

  if should_authenticate_proxy_request(&state, resolved_mode) {
    if let Err(error) = crate::api::access::authenticate_managed_request(&state, &mut req).await {
      let mut response = crate::api::access::authentication_error_response(error);
      close_intercepted_connection_on_error(&mut response);
      return Ok(response);
    }
  }

  if resolved_mode.is_verbatim() {
    let response = match resolved_mode {
      RouteMode::Passthrough => {
        super::passthrough_pipeline::proxy_passthrough_via_pipeline(
          &state,
          &intercepted_host,
          intercepted_port,
          "https",
          Some(peer.to_string()),
          Some(local.to_string()),
          req,
        )
        .await
      }
      RouteMode::Switch => {
        super::passthrough_pipeline::proxy_switch_via_pipeline(
          &state,
          &intercepted_host,
          intercepted_port,
          "https",
          Some(peer.to_string()),
          Some(local.to_string()),
          req,
        )
        .await
      }
      _ => unreachable!(),
    };
    let mut response = response
      .inspect(|b| {
        if !b.status().is_success() {
          tracing::warn!(%host, path = %path, method = %method, status = %b.status(), "proxy mode request failed");
        }
      })
      .inspect_err(|err| tracing::warn!(%host, error = %err, "proxy mode failed"))
      .unwrap_or_else(|err| ApiError::bad_gateway(err.to_string()).into_response());
    close_intercepted_connection_on_error(&mut response);
    return Ok(response);
  }
  let rewritten = if let Some(rewritten) = rewrite_target(&host, &path, &method) {
    rewritten
  } else {
    emit_router_not_implemented(&state, &req, &host, peer, local, Some(resolved_mode));
    return Ok(ApiError::not_implemented(path, host).into_response());
  };

  let rewritten_path = match rewritten {
    RewriteTarget::Endpoint(endpoint) => Registry::builtin().endpoint_path(endpoint).unwrap_or(path.as_str()),
    RewriteTarget::Path(path) => path,
  };

  let path_and_query = req.uri().path_and_query().map(|v| v.as_str()).unwrap_or(&path);
  let rewritten_path_and_query = path_and_query.replacen(&path, rewritten_path, 1);
  let uri = Uri::builder()
    .path_and_query(rewritten_path_and_query.as_str())
    .build()
    .unwrap_or_else(|_| Uri::from_static("/"));

  let (parts, body) = req.into_parts();
  let extensions = parts.extensions;
  let mut builder = Request::builder().method(method).uri(uri).version(parts.version);
  for (key, value) in &parts.headers {
    if key != HOST {
      builder = builder.header(key, value);
    }
  }
  builder = builder.header(
    HOST,
    HeaderValue::from_str(&host).unwrap_or_else(|_| HeaderValue::from_static("localhost")),
  );
  builder = builder.header("x-tokn-router-local-addr", local.to_string());
  let body = Body::new(body);
  let mut request = builder.body(body).unwrap_or_else(|_| Request::new(Body::empty()));
  *request.extensions_mut() = extensions;

  use tower::ServiceExt;
  let response = router
    .oneshot(request)
    .await
    .unwrap_or_else(|err| ApiError::bad_gateway(err.to_string()).into_response());
  Ok(response)
}

fn should_authenticate_proxy_request(state: &AppState, mode: RouteMode) -> bool {
  state.api_key_enabled && mode != RouteMode::Passthrough
}

fn default_proxy_provider_mode(
  state: &AppState,
  headers: &HeaderMap,
  intercepted_host: &str,
  path_and_query: &str,
) -> Option<RouteMode> {
  let host = headers
    .get(HOST)
    .and_then(|v| v.to_str().ok())
    .map(|s| s.split(':').next().unwrap_or(s).trim())
    .filter(|s| !s.is_empty())
    .unwrap_or(intercepted_host);
  let full_url = format!("https://{host}{path_and_query}");
  let provider_id = state.provider_registry.provider_id_for_url(&full_url)?;
  state
    .proxy_provider_modes
    .get(provider_id)
    .copied()
    .map(|mode| mode.as_route_mode())
}

fn resolve_proxy_route_mode(
  state: &AppState,
  route_resolver: &RouteResolver,
  headers: &HeaderMap,
  intercepted_host: &str,
  path_and_query: &str,
) -> std::result::Result<RouteMode, tokn_accounts::routing::ResolveError> {
  let route_mode = headers
    .get(RouteResolver::mode_header())
    .and_then(|v| v.to_str().ok())
    .map(str::to_string)
    .or_else(|| {
      default_proxy_provider_mode(state, headers, intercepted_host, path_and_query)
        .map(|mode| route_mode_as_str(mode).to_string())
    });
  route_resolver.resolve_mode(route_mode.as_deref())
}

fn emit_router_not_implemented(
  state: &AppState,
  req: &Request<hyper::body::Incoming>,
  host: &str,
  peer: SocketAddr,
  local: SocketAddr,
  mode: Option<RouteMode>,
) {
  let ts = tokn_core::util::now_unix_ms();
  let path_and_query = req
    .uri()
    .path_and_query()
    .map(|v| v.as_str().to_string())
    .unwrap_or_else(|| req.uri().path().to_string());
  let path = req.uri().path().to_string();
  let url = format!("https://{host}{path_and_query}");
  let hx = request_header_extract(req.headers());
  let request_id = SmolStr::new(&hx.request_id);
  let api_err = ApiError::not_implemented(path.clone(), host.to_string());
  let response_body = serde_json::from_slice(&api_err.body_bytes()).unwrap_or(serde_json::Value::Null);
  let mut response_headers = tokn_headers::HeaderMap::new();
  response_headers.insert("content-type", "application/json");
  let access = req.extensions().get::<tokn_access::AccessContext>();

  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id: request_id.clone(),
    attempt: 0,
    ts,
    payload: RequestEventPayload::Stage(StageEvent::Started {
      request_endpoint: RequestEndpoint::CustomPath(path.into()),
    }),
  }));
  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id: request_id.clone(),
    attempt: 0,
    ts,
    payload: RequestEventPayload::Record(RecordEvent::InboundConnection {
      user: access.and_then(|access| access.key_name.clone()).map(SmolStr::from),
      api_key_id: access.and_then(|access| access.key_id.clone()).map(SmolStr::from),
      local_addr: Some(SmolStr::new(local.to_string())),
      peer_addr: Some(SmolStr::new(peer.to_string())),
      mode: SmolStr::new(route_mode_as_str(mode.unwrap_or(RouteMode::Route))),
      method: SmolStr::new("requests"),
      inbound_method: SmolStr::new(req.method().as_str()),
      url: Some(SmolStr::new(url)),
    }),
  }));
  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id: request_id.clone(),
    attempt: 0,
    ts,
    payload: RequestEventPayload::Stage(StageEvent::Error {
      stage: Stage::Resolve,
      message: SmolStr::new(api_err.to_string()),
      recoverable: false,
      stop: true,
    }),
  }));
  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id: request_id.clone(),
    attempt: 0,
    ts,
    payload: RequestEventPayload::Stage(StageEvent::ConvertResponse(
      tokn_core::request_event::ConvertedResponseSummary {
        status: api_err.status().as_u16(),
        headers: response_headers,
        body: Some(std::sync::Arc::new(response_body)),
      },
    )),
  }));
  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id,
    attempt: 0,
    ts,
    payload: RequestEventPayload::Stage(StageEvent::Completed {
      success: false,
      attempts: 1,
    }),
  }));
}

fn is_websocket_upgrade_headers(headers: &HeaderMap) -> bool {
  let has_upgrade_connection = headers
    .get(CONNECTION)
    .and_then(|v| v.to_str().ok())
    .map(|v| v.split(',').any(|part| part.trim().eq_ignore_ascii_case("upgrade")))
    .unwrap_or(false);
  if !has_upgrade_connection {
    return false;
  }
  headers
    .get(UPGRADE)
    .and_then(|v| v.to_str().ok())
    .map(|v| v.trim().eq_ignore_ascii_case("websocket"))
    .unwrap_or(false)
}

fn close_intercepted_connection_on_error(response: &mut Response<Body>) {
  if response.status().is_success() {
    return;
  }
  response
    .headers_mut()
    .insert(CONNECTION, HeaderValue::from_static("close"));
}

fn websocket_upgrade_response() -> Response<Body> {
  let mut resp = Response::new(Body::empty());
  *resp.status_mut() = axum::http::StatusCode::UPGRADE_REQUIRED;
  resp
    .headers_mut()
    .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
  resp
    .headers_mut()
    .insert(UPGRADE, HeaderValue::from_static("websocket"));
  resp
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::http::StatusCode;
  use std::collections::BTreeMap;
  use std::sync::Arc;
  use tokn_config::Config;
  use tokn_config::ProxyProviderMode;
  use tokn_core::event::EventBus;

  fn state_with_provider_modes(provider_modes: &[(&str, ProxyProviderMode)]) -> AppState {
    let mut cfg = Config::default();
    cfg.server.route_mode = RouteMode::Passthrough;
    cfg.proxy_mode.provider_modes = provider_modes
      .iter()
      .map(|(provider_id, mode)| ((*provider_id).to_string(), *mode))
      .collect::<BTreeMap<_, _>>();
    crate::api::build_proxy_state(&cfg, &[], Arc::new(EventBus::new(8))).expect("state")
  }

  #[test]
  fn api_keys_apply_only_to_enabled_managed_proxy_modes() {
    let mut disabled = state_with_provider_modes(&[]);
    disabled.api_key_enabled = false;
    for mode in [
      RouteMode::Route,
      RouteMode::Exact,
      RouteMode::Fuzzy,
      RouteMode::Switch,
      RouteMode::Passthrough,
    ] {
      assert!(!should_authenticate_proxy_request(&disabled, mode));
    }

    let mut enabled = disabled;
    enabled.api_key_enabled = true;
    assert!(!should_authenticate_proxy_request(&enabled, RouteMode::Passthrough));
    for mode in [RouteMode::Route, RouteMode::Exact, RouteMode::Fuzzy, RouteMode::Switch] {
      assert!(should_authenticate_proxy_request(&enabled, mode));
    }
  }

  #[test]
  fn error_responses_close_intercepted_connection() {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::FORBIDDEN;

    close_intercepted_connection_on_error(&mut resp);

    assert_eq!(
      resp.headers().get(CONNECTION).and_then(|v| v.to_str().ok()),
      Some("close")
    );
  }

  #[test]
  fn success_responses_keep_existing_connection_policy() {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;

    close_intercepted_connection_on_error(&mut resp);

    assert!(resp.headers().get(CONNECTION).is_none());
  }

  #[test]
  fn plain_get_without_handler_returns_proxy_help() {
    let response = response_for_plain_get("/", Some("127.0.0.1:4142".into()), None);
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/plain; charset=utf-8\r\n"));
    assert!(response.contains(PROXY_GET_HELP));
  }

  #[test]
  fn plain_get_handler_can_serve_custom_response() {
    let handler: ProxyPlainHttpHandler = Arc::new(|request| {
      assert_eq!(request.target, "/-/lan/bootstrap.json");
      assert_eq!(request.host.as_deref(), Some("lan.local:4142"));
      Some(ProxyPlainHttpResponse {
        status: "200 OK",
        content_type: "application/json; charset=utf-8",
        body: "{\"ok\":true}".into(),
      })
    });

    let response = response_for_plain_get("/-/lan/bootstrap.json", Some("lan.local:4142".into()), Some(handler));
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json; charset=utf-8\r\n"));
    assert!(response.ends_with("{\"ok\":true}"));
  }

  #[test]
  fn provider_mode_uses_recognized_provider_url() {
    let state = state_with_provider_modes(&[("openai", ProxyProviderMode::Switch)]);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("api.openai.com"));

    assert_eq!(
      default_proxy_provider_mode(&state, &headers, "api.openai.com", "/v1/chat/completions"),
      Some(RouteMode::Switch)
    );
  }

  #[test]
  fn provider_mode_uses_intercepted_host_when_host_header_missing() {
    let state = state_with_provider_modes(&[("codex", ProxyProviderMode::Passthrough)]);
    let headers = HeaderMap::new();

    assert_eq!(
      default_proxy_provider_mode(&state, &headers, "chatgpt.com", "/backend-api/codex/responses"),
      Some(RouteMode::Passthrough)
    );
  }

  #[test]
  fn provider_mode_ignores_unknown_provider_urls() {
    let state = state_with_provider_modes(&[("openai", ProxyProviderMode::Switch)]);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("api.anthropic.com"));

    assert_eq!(
      default_proxy_provider_mode(&state, &headers, "api.anthropic.com", "/v1/messages"),
      None
    );
  }

  #[test]
  fn explicit_route_mode_overrides_provider_policy() {
    let state = state_with_provider_modes(&[("openai", ProxyProviderMode::Switch)]);
    let route = RouteResolver::new(RouteMode::Passthrough, &[]);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("api.openai.com"));
    headers.insert(RouteResolver::mode_header(), HeaderValue::from_static("route"));

    assert_eq!(
      resolve_proxy_route_mode(&state, &route, &headers, "api.openai.com", "/v1/chat/completions"),
      Ok(RouteMode::Route)
    );
  }

  #[test]
  fn provider_policy_overrides_global_proxy_mode() {
    let state = state_with_provider_modes(&[("openai", ProxyProviderMode::Switch)]);
    let route = RouteResolver::new(RouteMode::Passthrough, &[]);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("api.openai.com"));

    assert_eq!(
      resolve_proxy_route_mode(&state, &route, &headers, "api.openai.com", "/v1/chat/completions"),
      Ok(RouteMode::Switch)
    );
  }

  #[test]
  fn proxied_request_snapshot_keeps_old_policy_while_new_request_uses_reloaded_policy() {
    let live = LiveAppState::new(state_with_provider_modes(&[("openai", ProxyProviderMode::Passthrough)]));
    let old_request_state = live.current();
    live.swap(state_with_provider_modes(&[("openai", ProxyProviderMode::Switch)]));

    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("api.openai.com"));

    assert_eq!(
      resolve_proxy_route_mode(
        &old_request_state,
        old_request_state.route.as_ref(),
        &headers,
        "api.openai.com",
        "/v1/chat/completions"
      ),
      Ok(RouteMode::Passthrough),
      "already-captured proxy request state should keep old provider policy"
    );

    let new_request_state = live.current();
    assert_eq!(
      resolve_proxy_route_mode(
        &new_request_state,
        new_request_state.route.as_ref(),
        &headers,
        "api.openai.com",
        "/v1/chat/completions"
      ),
      Ok(RouteMode::Switch),
      "new proxy request state should use reloaded provider policy"
    );
  }

  #[test]
  fn unknown_provider_falls_back_to_global_proxy_mode() {
    let state = state_with_provider_modes(&[("openai", ProxyProviderMode::Switch)]);
    let route = RouteResolver::new(RouteMode::Passthrough, &[]);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("api.anthropic.com"));

    assert_eq!(
      resolve_proxy_route_mode(&state, &route, &headers, "api.anthropic.com", "/v1/messages"),
      Ok(RouteMode::Passthrough)
    );
  }
}

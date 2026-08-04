//! Proxy MITM passthrough dispatch via the shared `tokn-requests`
//! [`Pipeline`].
//!
//! This is the pipeline-based replacement for [`super::passthrough::proxy_passthrough`].
//! It builds a [`tokn_requests::RawInbound`] from the intercepted request,
//! supplies a [`tokn_requests::RunConfig`] populated with the resolved
//! authority / method / path / scheme under the `proxy.*` keys, and
//! invokes [`AppState::proxy_passthrough_service`].
//!
//! Host/port resolution lives in this module — see
//! [`resolve_host_with_port`]. The resolved value is used as the
//! upstream authority (URL host) **and** as the outbound `Host` header
//! (preserved verbatim by
//! [`PassthroughBuildHeaders::preserve_host`](tokn_requests::stages::PassthroughBuildHeaders::preserve_host)).
//!
//! The pipeline itself ([`ProxyResolve`] + [`ProxySend`]) reads those
//! keys, dispatches the request to `{scheme}://{host}{path}` preserving
//! the client's own `Authorization`, and emits the standard
//! `RecordEvent::*` observability stream — no legacy `LegacyRequest`
//! events are produced here.
//!
//! [`ProxyResolve`]: tokn_requests::stages::ProxyResolve
//! [`ProxySend`]: tokn_requests::stages::ProxySend
//! [`AppState::proxy_passthrough_service`]: crate::api::AppState::proxy_passthrough_service

use crate::api::error::ApiError;
use crate::api::AppState;
use crate::pipeline::request_header_extract;
use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::request::Parts;
use axum::http::{HeaderValue, Request, Response};
use axum::response::IntoResponse;
use bytes::Bytes;
use http::header::HOST;
use smol_str::SmolStr;
use tokn_access::AccessContext;
use tokn_accounts::routing::ResolveError;
use tokn_core::event::Event as CoreEvent;
use tokn_core::request_event::{
  ConvertedResponseSummary, RecordEvent, RequestEndpoint, RequestEvent, RequestEventPayload, Stage, StageEvent,
};
use tokn_requests::pipeline::error::RequestsError;

/// Dispatch an intercepted MITM request through the proxy-passthrough
/// pipeline.
///
/// * `intercepted_host` — bare host (no port) from the CONNECT
///   authority. Used as the **fallback** authority and as the bare-host
///   fallback for `provider_id` when identity resolution returns
///   `None`.
/// * `intercepted_port` — port from the CONNECT authority. Used as the
///   **fallback** port when neither `req.uri()` nor the `Host` header
///   carry one.
/// * `scheme` — `"http"` or `"https"`. Production always passes
///   `"https"` (the MITM only runs for port 443); tests may pass
///   `"http"`.
/// * `peer_addr` / `local_addr` — inbound TCP connection endpoints,
///   forwarded into `RecordEvent::InboundConnection` for persistence.
pub(super) async fn proxy_passthrough_via_pipeline(
  state: &AppState,
  intercepted_host: &str,
  intercepted_port: u16,
  scheme: &str,
  peer_addr: Option<String>,
  local_addr: Option<String>,
  req: Request<hyper::body::Incoming>,
) -> Result<Response<Body>> {
  let (parts, body) = req.into_parts();
  let raw_body = axum::body::to_bytes(Body::new(body), usize::MAX)
    .await
    .context("read proxy passthrough request body")?;
  Ok(
    proxy_passthrough_via_pipeline_inner(
      state,
      intercepted_host,
      intercepted_port,
      scheme,
      peer_addr,
      local_addr,
      parts,
      raw_body,
    )
    .await,
  )
}

pub(super) async fn proxy_switch_via_pipeline(
  state: &AppState,
  intercepted_host: &str,
  intercepted_port: u16,
  scheme: &str,
  peer_addr: Option<String>,
  local_addr: Option<String>,
  req: Request<hyper::body::Incoming>,
) -> Result<Response<Body>> {
  let (parts, body) = req.into_parts();
  let raw_body = axum::body::to_bytes(Body::new(body), usize::MAX)
    .await
    .context("read proxy switch request body")?;
  Ok(
    proxy_via_pipeline_inner(
      state,
      intercepted_host,
      intercepted_port,
      scheme,
      peer_addr,
      local_addr,
      parts,
      raw_body,
      ProxyPipelineMode::Switch,
    )
    .await,
  )
}

/// Inner core that does identity resolution, `RunConfig` construction,
/// pipeline invocation, and response conversion. Split from the public
/// wrapper so integration tests (which can't construct a real
/// `hyper::body::Incoming`) can drive the pipeline with pre-read body
/// bytes and a custom `scheme` (e.g. `"http"` to point at a plain mock
/// upstream).
#[allow(clippy::too_many_arguments)]
pub async fn proxy_passthrough_via_pipeline_inner(
  state: &AppState,
  intercepted_host: &str,
  intercepted_port: u16,
  scheme: &str,
  peer_addr: Option<String>,
  local_addr: Option<String>,
  parts: Parts,
  raw_body: Bytes,
) -> Response<Body> {
  proxy_via_pipeline_inner(
    state,
    intercepted_host,
    intercepted_port,
    scheme,
    peer_addr,
    local_addr,
    parts,
    raw_body,
    ProxyPipelineMode::Passthrough,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub async fn proxy_switch_via_pipeline_inner(
  state: &AppState,
  intercepted_host: &str,
  intercepted_port: u16,
  scheme: &str,
  peer_addr: Option<String>,
  local_addr: Option<String>,
  parts: Parts,
  raw_body: Bytes,
) -> Response<Body> {
  proxy_via_pipeline_inner(
    state,
    intercepted_host,
    intercepted_port,
    scheme,
    peer_addr,
    local_addr,
    parts,
    raw_body,
    ProxyPipelineMode::Switch,
  )
  .await
}

#[derive(Clone, Copy)]
enum ProxyPipelineMode {
  Passthrough,
  Switch,
}

#[allow(clippy::too_many_arguments)]
async fn proxy_via_pipeline_inner(
  state: &AppState,
  intercepted_host: &str,
  intercepted_port: u16,
  scheme: &str,
  peer_addr: Option<String>,
  local_addr: Option<String>,
  mut parts: Parts,
  raw_body: Bytes,
  mode: ProxyPipelineMode,
) -> Response<Body> {
  let path_and_query = parts
    .uri
    .path_and_query()
    .map(|v| v.as_str().to_string())
    .unwrap_or_else(|| "/".to_string());
  let path_only = parts.uri.path();
  let method = parts.method.clone();

  // Resolve the authoritative host[:port] using the precedence:
  //   req.uri authority → Host header → intercepted host:port.
  // The result has default ports (`:443` for https, `:80` for http)
  // normalized out.
  let host_with_port = resolve_host_with_port(&parts, intercepted_host, intercepted_port, scheme);

  // Rewrite the inbound `Host` header to the resolved authority so
  // `PassthroughBuildHeaders::preserve_host()` forwards the correct
  // value to the upstream.
  if let Ok(hv) = HeaderValue::from_str(&host_with_port) {
    parts.headers.insert(HOST, hv);
  }

  let request_endpoint = RequestEndpoint::infer_from_path(path_only);

  // Keep the wire body verbatim for passthrough forwarding, but decode a
  // side-copy for best-effort model/stream peeking and event summaries.
  let inbound_headers: tokn_headers::HeaderMap = (&parts.headers).into();
  let decoded_body = decode_proxy_body(&inbound_headers, raw_body.clone());
  let body_json = serde_json::Value::Null;

  // Reconstruct the full URL the client targeted post-CONNECT.
  // Identity resolution gets it (path helps providers like
  // `matches_url` disambiguate shared-host scenarios — see
  // `Registry::provider_id_for_url`); `RecordEvent::InboundConnection`
  // persists it for the `requests.inbound_req_url` column.
  let full_url = format!("{scheme}://{host_with_port}{path_and_query}");
  let mode_name = match mode {
    ProxyPipelineMode::Passthrough => "passthrough",
    ProxyPipelineMode::Switch => "switch",
  };
  let hx = request_header_extract(&parts.headers);
  let request_id = SmolStr::new(&hx.request_id);
  let access = parts.extensions.get::<AccessContext>();

  emit_proxy_inbound(
    state,
    request_id.clone(),
    access,
    local_addr.as_deref(),
    peer_addr.as_deref(),
    mode_name,
    method.as_str(),
    &full_url,
  );

  let mut cfg_builder = tokn_requests::RunConfig::builder()
    .with_str(tokn_requests::stages::resolve::proxy::keys::HOST, &host_with_port)
    .with_str(tokn_requests::stages::resolve::proxy::keys::PATH, &path_and_query)
    .with_str(tokn_requests::stages::send::proxy::send_keys::PATH, &path_and_query)
    .with_str(tokn_requests::stages::send::proxy::send_keys::METHOD, method.as_str())
    .with_str(tokn_requests::stages::send::proxy::send_keys::SCHEME, scheme);
  let service = match mode {
    ProxyPipelineMode::Passthrough => {
      // Identity resolution — fingerprint the inbound bearer against
      // locally-known accounts so DB rows / events attribute the
      // intercepted request to a concrete `account_id` + `provider_id`.
      // Pass the full URL so descriptors with path-based `matches_url`
      // discriminate correctly. Registry strips the port internally.
      let identity_url = if is_default_intercept_host(&host_with_port) {
        full_url.as_str()
      } else {
        ""
      };
      let identity = state
        .identity
        .resolve(&parts.headers, identity_url, &state.provider_registry);
      // Fallback to the bare intercepted host (not host:port and not the
      // full URL) so the synthetic provider_id stays stable across
      // requests to different paths/ports on the same upstream.
      let resolved_provider_id = identity.provider_id.unwrap_or_else(|| intercepted_host.to_string());
      cfg_builder = cfg_builder.with_str(
        tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID,
        &resolved_provider_id,
      );
      if let Some(account_id) = identity.account_id.as_deref() {
        cfg_builder = cfg_builder.with_str(tokn_requests::stages::resolve::proxy::keys::ACCOUNT_ID, account_id);
      }
      &state.proxy_passthrough_service
    }
    ProxyPipelineMode::Switch => {
      let Some(provider_id) = state.provider_registry.provider_id_for_url(&full_url) else {
        let api_err = ApiError::bad_request(format!(
          "switch mode requires a recognized provider URL, got '{full_url}'"
        ));
        emit_proxy_terminal_error(state, request_id, request_endpoint.clone(), &api_err);
        return api_err.into_response();
      };
      cfg_builder = cfg_builder
        .with_str(tokn_requests::stages::resolve::proxy::keys::PROVIDER_ID, provider_id)
        .with(tokn_requests::stages::send::proxy::send_keys::INJECT_AUTH, true);
      if let Some(providers) = parts
        .extensions
        .get::<AccessContext>()
        .and_then(|access| access.providers.provider_ids())
      {
        cfg_builder = cfg_builder.with(
          tokn_requests::stages::ACCESS_ALLOWED_PROVIDERS_KEY,
          serde_json::Value::Array(providers.iter().cloned().map(serde_json::Value::String).collect()),
        );
      }
      &state.proxy_switch_service
    }
  };

  let cfg = cfg_builder.build();

  let raw = tokn_requests::RawInbound {
    request_endpoint,
    headers: inbound_headers,
    raw_body,
    decoded_body,
    body_json,
    request_id: Some(request_id),
  };

  match service
    .execute(tokn_requests::ExecutionRequest::new(raw).with_config(cfg))
    .await
  {
    Ok(converted) => crate::api::response::converted_to_axum(converted),
    Err(err) => proxy_request_error_to_api_error(&err, &host_with_port).into_response(),
  }
}

fn decode_proxy_body(headers: &tokn_headers::HeaderMap, raw_body: Bytes) -> Bytes {
  let encoding = match tokn_requests::utils::codec::request_content_encoding(headers) {
    Ok(encoding) => encoding,
    Err(err) => {
      tracing::warn!(error = %err, "could not parse proxy request content-encoding; using raw body for inspection");
      return raw_body;
    }
  };
  match tokn_requests::utils::codec::decode_body_bytes(raw_body.clone(), encoding) {
    Ok(decoded) => decoded,
    Err(err) => {
      tracing::warn!(error = %err, "could not decode proxy request body; using raw body for inspection");
      raw_body
    }
  }
}

#[allow(clippy::too_many_arguments)]
fn emit_proxy_inbound(
  state: &AppState,
  request_id: SmolStr,
  access: Option<&AccessContext>,
  local_addr: Option<&str>,
  peer_addr: Option<&str>,
  mode: &str,
  inbound_method: &str,
  url: &str,
) {
  let ts = tokn_core::util::now_unix_ms();
  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id,
    attempt: 0,
    ts,
    payload: RequestEventPayload::Record(RecordEvent::InboundConnection {
      user: access.and_then(|access| access.key_name.clone()).map(SmolStr::from),
      api_key_id: access.and_then(|access| access.key_id.clone()).map(SmolStr::from),
      local_addr: local_addr.map(SmolStr::new),
      peer_addr: peer_addr.map(SmolStr::new),
      mode: SmolStr::new(mode),
      method: SmolStr::new("proxy"),
      inbound_method: SmolStr::new(inbound_method),
      url: Some(SmolStr::new(url)),
    }),
  }));
}

fn emit_proxy_terminal_error(
  state: &AppState,
  request_id: SmolStr,
  request_endpoint: RequestEndpoint,
  api_err: &ApiError,
) {
  let ts = tokn_core::util::now_unix_ms();
  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id: request_id.clone(),
    attempt: 0,
    ts,
    payload: RequestEventPayload::Stage(StageEvent::Started { request_endpoint }),
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

  let response_body = serde_json::from_slice(&api_err.body_bytes()).unwrap_or(serde_json::Value::Null);
  let mut response_headers = tokn_headers::HeaderMap::new();
  response_headers.insert("content-type", "application/json");
  state.events.emit(CoreEvent::Requests(RequestEvent {
    request_id: request_id.clone(),
    attempt: 0,
    ts,
    payload: RequestEventPayload::Stage(StageEvent::ConvertResponse(ConvertedResponseSummary {
      status: api_err.status().as_u16(),
      headers: response_headers,
      body: Some(std::sync::Arc::new(response_body)),
    })),
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

fn is_default_intercept_host(host_with_port: &str) -> bool {
  let (host, _) = split_host_port(host_with_port);
  let host = host.trim_matches(['[', ']']);
  super::INTERCEPT_HOSTS.contains(&host)
}

fn proxy_request_error_to_api_error(err: &tokn_requests::RequestError, host_with_port: &str) -> ApiError {
  let Some(err) = err.pipeline() else {
    tracing::warn!(host = %host_with_port, error = %err, "proxy request service failed");
    return ApiError::bad_gateway(err.to_string());
  };
  proxy_pipeline_error_to_api_error(err, host_with_port)
}

fn proxy_pipeline_error_to_api_error(err: &tokn_requests::PipelineError, host_with_port: &str) -> ApiError {
  tracing::warn!(host = %host_with_port, error = %err.message(), "proxy pipeline failed");
  match err.inner() {
    RequestsError::Resolve {
      source: ResolveError::InvalidRouteMode { .. },
    }
    | RequestsError::Resolve {
      source: ResolveError::InvalidExactModel { .. },
    } => ApiError::bad_request(err.message().into_owned()),
    RequestsError::SessionExpired { session_id } => ApiError::session_expired(session_id.to_string()),
    RequestsError::ProviderAccessDenied => ApiError::forbidden("API key does not allow the requested provider"),
    RequestsError::InvalidAccessPolicy => ApiError::internal("invalid API-key provider policy"),
    RequestsError::NoAccount { endpoint, model } => ApiError::not_implemented(endpoint.to_string(), model.to_string()),
    RequestsError::NoProviderAccount { provider_id } => ApiError::bad_request(format!(
      "switch mode requires a recognized provider URL with a configured account, got provider '{provider_id}'"
    )),
    RequestsError::UpstreamStatus { status, body } => match http::StatusCode::from_u16(*status) {
      Ok(status) => ApiError::upstream(status, body.clone()),
      Err(_) => ApiError::bad_gateway(body.clone()),
    },
    _ => ApiError::bad_gateway(err.message().into_owned()),
  }
}

/// Resolve the authoritative `host[:port]` for the upstream URL with
/// the precedence:
///
/// 1. `parts.uri().authority()` (set when the request line was
///    absolute-form — `req.uri()` port wins over the `Host` header
///    per the original CONNECT proxy contract).
/// 2. The inbound `Host` header.
/// 3. The intercepted CONNECT authority (`intercepted_host:intercepted_port`).
///
/// The result has the default port stripped when it matches the scheme
/// (`:443` for `https`, `:80` for `http`).
fn resolve_host_with_port(parts: &Parts, intercepted_host: &str, intercepted_port: u16, scheme: &str) -> String {
  let (host, port) = if let Some(auth) = parts.uri.authority() {
    (auth.host().to_string(), auth.port_u16())
  } else if let Some((h, p)) = parts
    .headers
    .get(HOST)
    .and_then(|v| v.to_str().ok())
    .map(split_host_port)
  {
    (h, p)
  } else {
    (intercepted_host.to_string(), Some(intercepted_port))
  };
  normalize_authority(&host, port, scheme)
}

/// Split `host` or `host:port` into `(host, Option<port>)`. Invalid
/// port digits yield `None` — falls through to the intercepted port
/// (the only other source). IPv6 literals (`[::1]:443`) are handled
/// by splitting on the last `:` outside the brackets.
fn split_host_port(value: &str) -> (String, Option<u16>) {
  let trimmed = value.trim();
  // IPv6 literal in brackets.
  if let Some(rest) = trimmed.strip_prefix('[') {
    if let Some(end) = rest.find(']') {
      let host = format!("[{}]", &rest[..end]);
      let after = &rest[end + 1..];
      let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
      return (host, port);
    }
  }
  match trimmed.rsplit_once(':') {
    Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.parse().ok()),
    _ => (trimmed.to_string(), None),
  }
}

/// Format `host` + optional `port` into a canonical authority,
/// dropping the port when it equals the scheme's default.
fn normalize_authority(host: &str, port: Option<u16>, scheme: &str) -> String {
  let default = match scheme {
    "https" => Some(443),
    "http" => Some(80),
    _ => None,
  };
  match port {
    Some(p) if Some(p) != default => format!("{host}:{p}"),
    _ => host.to_string(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::http::{HeaderMap, Method, Uri, Version};

  fn parts_with(uri: &str, host_header: Option<&str>) -> Parts {
    let req = Request::builder()
      .method(Method::POST)
      .uri(Uri::try_from(uri).unwrap())
      .version(Version::HTTP_11)
      .body(())
      .unwrap();
    let (mut parts, _) = req.into_parts();
    if let Some(h) = host_header {
      parts.headers.insert(HOST, HeaderValue::from_str(h).unwrap());
    } else {
      // Builder may auto-add Host from the URI authority; clear it so
      // the test exercises the no-Host-header branch deterministically.
      parts.headers.remove(HOST);
    }
    parts
  }

  #[test]
  fn uri_authority_wins_over_host_header() {
    let p = parts_with("http://api.example.com:8443/v1/x", Some("other.com"));
    let _ = HeaderMap::new();
    assert_eq!(
      resolve_host_with_port(&p, "intercepted.example", 443, "https"),
      "api.example.com:8443"
    );
  }

  #[test]
  fn host_header_default_port_stripped_https() {
    let p = parts_with("/v1/x", Some("api.example.com:443"));
    assert_eq!(
      resolve_host_with_port(&p, "intercepted", 443, "https"),
      "api.example.com"
    );
  }

  #[test]
  fn host_header_nondefault_port_kept_http() {
    let p = parts_with("/v1/x", Some("api.example.com:8080"));
    assert_eq!(
      resolve_host_with_port(&p, "intercepted", 80, "http"),
      "api.example.com:8080"
    );
  }

  #[test]
  fn intercepted_default_port_stripped() {
    let p = parts_with("/v1/x", None);
    assert_eq!(
      resolve_host_with_port(&p, "api.example.com", 443, "https"),
      "api.example.com"
    );
  }

  #[test]
  fn intercepted_nondefault_port_kept() {
    let p = parts_with("/v1/x", None);
    assert_eq!(
      resolve_host_with_port(&p, "api.example.com", 8443, "https"),
      "api.example.com:8443"
    );
  }

  #[test]
  fn ipv6_host_header_with_port() {
    let p = parts_with("/v1/x", Some("[::1]:8443"));
    assert_eq!(resolve_host_with_port(&p, "intercepted", 443, "https"), "[::1]:8443");
  }

  #[test]
  fn ipv6_host_header_default_port_stripped() {
    let p = parts_with("/v1/x", Some("[::1]:443"));
    assert_eq!(resolve_host_with_port(&p, "intercepted", 443, "https"), "[::1]");
  }
}

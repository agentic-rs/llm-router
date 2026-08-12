//! Send stage for the MITM proxy passthrough pipeline.
//!
//! Unlike [`DefaultSend`](super::DefaultSend), the proxy variant **does
//! not delegate to `Provider::chat / responses / messages`**. The
//! upstream URL is `https://{proxy.host}{proxy.path}` (taken straight
//! from [`PipelineCtx::config`]), the HTTP method is the inbound method
//! (also in the bag), and the headers are the pre-pruned [`BuiltHeaders`]
//! from [`PassthroughBuildHeaders`](super::super::build_headers::PassthroughBuildHeaders)
//! — including the client's own `Authorization`, which we preserve
//! verbatim. No auth injection, no URL rewriting, no provider hooks.
//!
//! The body sent on the wire is `ConvertedRequest::upstream_wire_body`,
//! which for the passthrough variant is the inbound raw bytes
//! ([`PassthroughConvertRequest`](super::super::convert_request::PassthroughConvertRequest)
//! returns them verbatim).
//!
//! By default, 5xx responses remain recoverable pipeline errors for legacy
//! retry behavior. V2 account-pool callers opt into forwarding every received
//! response verbatim and classify its status separately.

use crate::event::Stage;
use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::{PipelineError, ProviderError, RequestsError};
use crate::pipeline::stages::{
  provider_request_kind, resolved_upstream_endpoint, BuiltHeaders, ConvertedRequest, Extracted, Resolved, SendStage,
  SentResponse,
};
use async_trait::async_trait;
use bytes::Bytes;
use smol_str::SmolStr;
use tokn_core::provider::HeaderPatchCtx;
use tokn_headers::HeaderMap;
use tracing::{debug, instrument, warn};

use crate::stages::resolve::proxy::keys;

fn proxy_send_error_hint(err_text: &str, has_inner_source: bool) -> &'static str {
  if err_text.contains("with no inner error")
    || (!has_inner_source && err_text.contains("error sending request for url"))
  {
    " (upstream/network details were not exposed by reqwest; this is often a TLS shutdown or connection reset by the upstream)"
  } else {
    ""
  }
}

fn format_proxy_send_error(url: &str, err: &reqwest::Error) -> String {
  let err_text = err.to_string();
  let hint = proxy_send_error_hint(&err_text, std::error::Error::source(err).is_some());
  format!("proxy upstream `{url}` failed: {err_text}{hint}")
}

/// Config keys consumed by [`ProxySend`]. These complement the keys
/// read by [`ProxyResolve`](crate::stages::ProxyResolve) and must be
/// populated by the proxy transport layer before executing the request
/// service.
pub mod send_keys {
  /// HTTP method as an upper-case string, e.g. `"POST"`. When absent,
  /// `POST` is used as the default (matches the common LLM API case).
  pub const METHOD: &str = "proxy.method";
  /// Request path + query, e.g. `"/v1/chat/completions?foo=bar"`. Must
  /// start with `/`. Defaults to `/` when absent.
  pub const PATH: &str = "proxy.path";
  /// URL scheme, either `"https"` (production / MITM-intercepted TLS) or
  /// `"http"` (test fixtures pointing at plain HTTP mock servers).
  /// Defaults to `"https"` when absent.
  pub const SCHEME: &str = "proxy.scheme";
  /// When true, the selected provider patches auth onto the outbound
  /// request before proxy dispatch.
  pub const INJECT_AUTH: &str = "proxy.inject_auth";
}

pub struct ProxySend {
  http: reqwest::Client,
  forward_server_errors: bool,
}

impl ProxySend {
  pub fn new(http: reqwest::Client) -> Self {
    Self {
      http,
      forward_server_errors: false,
    }
  }

  pub fn forward_all_statuses(http: reqwest::Client) -> Self {
    Self {
      http,
      forward_server_errors: true,
    }
  }
}

#[async_trait]
impl SendStage for ProxySend {
  #[instrument(name = "proxy_send", skip_all, fields(
    account = %resolved.account_id,
    provider = %resolved.provider_id,
    endpoint = ?resolved.route.upstream_endpoint(),
    stream = extracted.stream,
  ))]
  async fn send(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
    headers: &BuiltHeaders,
    body: &ConvertedRequest,
  ) -> Result<SentResponse, PipelineError> {
    let upstream_endpoint = resolved_upstream_endpoint(ctx, resolved, Stage::Send)?;
    let host = ctx
      .config
      .get_str(keys::HOST)
      .ok_or_else(|| missing_config(keys::HOST))?;
    let path = ctx.config.get_str(send_keys::PATH).unwrap_or("/");
    let method_str = ctx.config.get_str(send_keys::METHOD).unwrap_or("POST");
    let method = reqwest::Method::from_bytes(method_str.as_bytes()).map_err(|e| {
      PipelineError::permanent(
        Stage::Send,
        RequestsError::Other {
          source: format!("invalid proxy method `{method_str}`: {e}").into(),
        },
      )
    })?;
    let scheme = ctx.config.get_str(send_keys::SCHEME).unwrap_or("https");
    let url = format!("{scheme}://{host}{path}");
    debug!(%url, %method, "proxy upstream dispatch");

    let inject_auth = ctx
      .config
      .get(send_keys::INJECT_AUTH)
      .and_then(|v| v.as_bool())
      .unwrap_or(false);
    let mut outbound_headers = headers.headers.clone();
    if inject_auth {
      resolved
        .account_handle
        .provider
        .patch_headers(
          &mut outbound_headers,
          &HeaderPatchCtx {
            request_kind: provider_request_kind(ctx, resolved, Stage::Send)?,
            body: body.upstream_body.as_ref(),
            bearer_token: None,
            content_encoding: body.content_encoding.map(|e| e.as_str()),
            stream: extracted.stream,
            initiator: extracted.initiator.as_deref().unwrap_or("user"),
            inbound_headers: &HeaderMap::new(),
            vars: &headers.vars,
            agent_id: &headers.agent_id,
          },
        )
        .map_err(|err| {
          PipelineError::permanent(
            Stage::Send,
            RequestsError::Provider {
              source: ProviderError::new(err),
            },
          )
        })?;
    }

    // The proxy build-header stage preserves Host so the request record
    // reflects the intercepted authority. Do not forward that copy through
    // reqwest and then append another Host below: duplicate Host is invalid
    // HTTP/1.1 and strict upstream CDNs may close the connection without
    // returning a response.
    outbound_headers.remove(&tokn_headers::keys::HOST);

    let mut req = self.http.request(method.clone(), &url);
    for (name, value) in outbound_headers.iter() {
      req = req.header(name.as_str(), value.as_str());
    }
    // Always set HOST to the intercepted host so virtual-hosted upstreams
    // (most LLM APIs are behind a CDN that vhosts by Host) route us to
    // the right backend.
    req = req.header(reqwest::header::HOST, host);
    req = req.body(body.upstream_wire_body.clone());

    // Emit the request-side record so the persistence handler can write
    // wire-accurate values into the row, mirroring DefaultSend.
    ctx.emit_record(tokn_core::request_event::RecordEvent::UpstreamReq {
      method: SmolStr::new(method.as_str()),
      url: SmolStr::new(&url),
      headers: outbound_headers.clone(),
      body: body.upstream_wire_body.clone(),
    });

    let resp = match req.send().await {
      Ok(r) => r,
      Err(err) => {
        let recoverable = err.is_connect() || err.is_timeout() || err.is_request();
        let source = RequestsError::Other {
          source: format_proxy_send_error(&url, &err).into(),
        };
        return Err(if recoverable {
          PipelineError::recoverable(Stage::Send, source)
        } else {
          PipelineError::permanent(Stage::Send, source)
        });
      }
    };

    let status = resp.status().as_u16();
    let resp_headers = HeaderMap::from(resp.headers());
    debug!(%status, "proxy upstream responded");

    ctx.emit_record(tokn_core::request_event::RecordEvent::UpstreamResp {
      status,
      headers: resp_headers.clone(),
    });

    if status >= 500 && !self.forward_server_errors {
      let body_text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
          return Err(PipelineError::recoverable(
            Stage::Send,
            RequestsError::UpstreamReadFailed { status, source: e },
          ));
        }
      };
      ctx.emit_record(tokn_core::request_event::RecordEvent::UpstreamBody {
        body: Bytes::copy_from_slice(body_text.as_bytes()),
        error: None,
      });
      return Err(PipelineError::recoverable(
        Stage::Send,
        RequestsError::UpstreamStatus {
          status,
          body: truncate(&body_text, 512),
        },
      ));
    }
    if status >= 400 {
      warn!(%status, "proxy upstream error response — forwarding verbatim");
    }

    Ok(SentResponse {
      status,
      headers: resp_headers,
      stream: extracted.stream,
      upstream_endpoint,
      response: resp,
    })
  }
}

fn missing_config(key: &str) -> PipelineError {
  PipelineError::permanent(
    Stage::Send,
    RequestsError::Other {
      source: format!("proxy passthrough pipeline requires `{key}` in RunConfig").into(),
    },
  )
}

fn truncate(s: &str, max: usize) -> String {
  if s.len() <= max {
    s.to_string()
  } else {
    format!("{}…", &s[..max])
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::EventBus;
  use crate::pipeline::config::RunConfig;
  use crate::pipeline::stages::ResolveStage;
  use crate::pipeline::stages::{BuiltHeaders, ConvertedRequest, Extracted, Resolved, ResolvedRoute};
  use crate::stages::resolve::proxy::ProxyResolve;
  use crate::test_support::{mock_handle_with_provider, MockProvider};
  use bytes::Bytes;
  use serde_json::Value;
  use std::sync::Arc;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokn_core::provider::{Endpoint, ProviderRequestKind};
  use tokn_headers::{HeaderName, HeaderValue};

  #[test]
  fn proxy_send_error_hint_matches_no_inner_error_text() {
    let hint = proxy_send_error_hint(
      "error sending request for url (https://api.z.ai/api/coding/paas/v4/chat/completions) with no inner error",
      false,
    );
    assert!(hint.contains("TLS shutdown or connection reset"));
  }

  #[test]
  fn proxy_send_error_hint_omits_regular_transport_errors() {
    let hint = proxy_send_error_hint(
      "error sending request for url (http://127.0.0.1:1): tcp connect error",
      true,
    );
    assert!(hint.is_empty());
  }

  fn ctx_with(config: RunConfig) -> PipelineCtx {
    PipelineCtx::new_with_config(
      "req-px-send",
      Endpoint::ChatCompletions.into(),
      Arc::new(EventBus::new(64)),
      Arc::new(config),
    )
  }

  fn fake_extracted() -> Extracted {
    Extracted {
      agent_id: None,
      model: SmolStr::new("gpt-4"),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: None,
      header_initiator: None,
      route_mode_hint: None,
      headers: HeaderMap::new(),
      raw_body: Bytes::new(),
      decoded_body: Bytes::new(),
      body_json: Arc::new(Value::Null),
      content_encoding: None,
    }
  }

  async fn fake_resolved(ctx: &PipelineCtx) -> Resolved {
    ProxyResolve.resolve(ctx, &fake_extracted()).await.unwrap()
  }

  fn fake_body() -> ConvertedRequest {
    let bytes = Bytes::from_static(b"hello world");
    ConvertedRequest {
      upstream_body: Arc::new(Value::Null),
      upstream_wire_body: bytes.clone(),
      debug_outbound_body: bytes,
      content_encoding: None,
    }
  }

  fn fake_headers() -> BuiltHeaders {
    let mut h = HeaderMap::new();
    h.insert(
      HeaderName::new("authorization"),
      HeaderValue::from_static("Bearer client-token"),
    );
    h.insert(HeaderName::new("user-agent"), HeaderValue::from_static("test"));
    BuiltHeaders {
      headers: h,
      vars: Default::default(),
      agent_id: Default::default(),
    }
  }

  async fn one_shot_raw_http_server() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buf = vec![0_u8; 8192];
      let n = stream.read(&mut buf).await.unwrap();
      buf.truncate(n);
      stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
        .await
        .unwrap();
      stream.flush().await.unwrap();
      let _ = tx.send(buf);
    });
    (addr, rx)
  }

  #[tokio::test]
  async fn missing_host_is_permanent_error() {
    let ctx = ctx_with(RunConfig::default());
    let resolved = Resolved {
      agent_id: None,
      model: SmolStr::new("m"),
      upstream_model: SmolStr::new("m"),
      route: ResolvedRoute::operation(Endpoint::ChatCompletions, Endpoint::ChatCompletions),
      account_id: SmolStr::new("proxy"),
      provider_id: SmolStr::new("none"),
      account_handle: crate::stages::resolve::proxy::stub_handle("proxy", "none"),
    };
    let send = ProxySend::new(reqwest::Client::new());
    let err = send
      .send(&ctx, &fake_extracted(), &resolved, &fake_headers(), &fake_body())
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::Send);
    assert!(err.message().contains("proxy.host"));
  }

  #[tokio::test]
  async fn invalid_method_is_permanent_error() {
    let cfg = RunConfig::builder()
      .with_str(keys::HOST, "127.0.0.1:1")
      .with_str(send_keys::METHOD, "TOTALLY BAD METHOD")
      .build();
    let ctx = ctx_with(cfg);
    let resolved = fake_resolved(&ctx).await;
    let send = ProxySend::new(reqwest::Client::new());
    let err = send
      .send(&ctx, &fake_extracted(), &resolved, &fake_headers(), &fake_body())
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::Send);
    assert!(err.message().contains("invalid proxy method"));
  }

  #[tokio::test]
  async fn injects_router_managed_auth_when_enabled() {
    let (addr, rx) = one_shot_raw_http_server().await;

    let ctx = ctx_with(
      RunConfig::builder()
        .with_str(keys::HOST, addr.to_string())
        .with_str(send_keys::PATH, "/v1/chat/completions")
        .with_str(send_keys::METHOD, "POST")
        .with_str(send_keys::SCHEME, "http")
        .with(send_keys::INJECT_AUTH, true)
        .build(),
    );
    let resolved = Resolved {
      agent_id: None,
      model: SmolStr::new("gpt-4"),
      upstream_model: SmolStr::new("gpt-4"),
      route: ResolvedRoute::operation(Endpoint::ChatCompletions, Endpoint::ChatCompletions),
      account_id: SmolStr::new("acct"),
      provider_id: SmolStr::new("mock"),
      account_handle: mock_handle_with_provider(
        "acct",
        MockProvider::new("mock").with_header("authorization", "Bearer router-token"),
      ),
    };

    let send = ProxySend::new(reqwest::Client::new());
    let sent = send
      .send(&ctx, &fake_extracted(), &resolved, &fake_headers(), &fake_body())
      .await
      .unwrap();
    assert_eq!(sent.status, 200);

    let raw_req = String::from_utf8_lossy(&rx.await.unwrap()).to_ascii_lowercase();
    assert!(raw_req.contains("authorization: bearer router-token"));
    assert!(!raw_req.contains("authorization: bearer client-token"));
  }

  #[tokio::test]
  async fn injects_router_managed_auth_for_custom_paths() {
    let (addr, rx) = one_shot_raw_http_server().await;

    let ctx = ctx_with(
      RunConfig::builder()
        .with_str(keys::HOST, addr.to_string())
        .with_str(send_keys::PATH, "/models")
        .with_str(send_keys::METHOD, "GET")
        .with_str(send_keys::SCHEME, "http")
        .with(send_keys::INJECT_AUTH, true)
        .build(),
    );
    let resolved = Resolved {
      agent_id: None,
      model: SmolStr::new("unknown"),
      upstream_model: SmolStr::new("unknown"),
      route: ResolvedRoute::provider_traffic(ProviderRequestKind::Models),
      account_id: SmolStr::new("acct"),
      provider_id: SmolStr::new("mock"),
      account_handle: mock_handle_with_provider(
        "acct",
        MockProvider::new("mock").with_header("authorization", "Bearer router-token"),
      ),
    };

    let send = ProxySend::new(reqwest::Client::new());
    let sent = send
      .send(&ctx, &fake_extracted(), &resolved, &fake_headers(), &fake_body())
      .await
      .unwrap();
    assert_eq!(sent.status, 200);

    let raw_req = String::from_utf8_lossy(&rx.await.unwrap()).to_ascii_lowercase();
    assert!(raw_req.starts_with("get /models "));
    assert!(raw_req.contains("authorization: bearer router-token"));
    assert!(!raw_req.contains("authorization: bearer client-token"));
  }

  #[test]
  fn classifies_provider_traffic_paths_for_header_patching() {
    assert_eq!(
      ProviderRequestKind::from_provider_path("/models"),
      ProviderRequestKind::Models
    );
    assert_eq!(
      ProviderRequestKind::from_provider_path("/v1/models?client_version=test"),
      ProviderRequestKind::Models
    );
    assert_eq!(
      ProviderRequestKind::from_provider_path("/v1/experimental/agents"),
      ProviderRequestKind::Opaque
    );
  }

  #[tokio::test]
  async fn sends_single_authoritative_host_header() {
    let (addr, rx) = one_shot_raw_http_server().await;
    let ctx = ctx_with(
      RunConfig::builder()
        .with_str(keys::HOST, addr.to_string())
        .with_str(send_keys::PATH, "/v1/chat/completions")
        .with_str(send_keys::METHOD, "POST")
        .with_str(send_keys::SCHEME, "http")
        .build(),
    );
    let resolved = fake_resolved(&ctx).await;
    let mut headers = fake_headers();
    headers
      .headers
      .insert(HeaderName::new("host"), HeaderValue::from_static("stale.example.test"));

    let send = ProxySend::new(reqwest::Client::new());
    let sent = send
      .send(&ctx, &fake_extracted(), &resolved, &headers, &fake_body())
      .await
      .unwrap();
    assert_eq!(sent.status, 200);

    let raw_req = String::from_utf8_lossy(&rx.await.unwrap()).to_ascii_lowercase();
    assert_eq!(raw_req.matches("\r\nhost: ").count(), 1);
    assert!(raw_req.contains(&format!("\r\nhost: {addr}\r\n").to_ascii_lowercase()));
    assert!(!raw_req.contains("stale.example.test"));
  }
}

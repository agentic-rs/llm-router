//! Pass-through BuildHeaders stage.
//!
//! The outbound request carries the **inbound** headers as-is, with two
//! categories stripped:
//!
//! 1. **Router-owned** — anything matching `is_router_owned_header` (i.e.
//!    `x-tokn-router-*`, `x-route-mode`, `x-behave-as`). These are internal
//!    transport metadata that must never leave the router.
//! 2. **Hop-by-hop** — `host`, `proxy-authorization`, `proxy-connection`,
//!    `te`, `trailer`, `transfer-encoding`, `upgrade`. We intentionally keep
//!    `connection` / `keep-alive` for replay debugging even though they are
//!    hop-by-hop per RFC 7230 §6.1.
//!
//! Upstream auth is **not** injected here — the provider's `patch_headers`
//! (called from inside `DefaultSend` via `provider.chat/responses/messages`)
//! still adds `Authorization` based on `Resolved.account_handle`.
//!
//! `TemplateVars` still mirrors the inbound correlation headers so downstream
//! consumers see the same request metadata contract as the default path.

use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::PipelineError;
use crate::pipeline::stages::{BuildHeadersStage, BuiltHeaders, Extracted, Resolved};
use async_trait::async_trait;
use tokn_core::AgentId;
use tokn_headers::inbound::build_template_vars;
use tokn_headers::HeaderMap;

/// Hop-by-hop header names (lowercase) that must not be forwarded
/// verbatim to the upstream. `connection` / `keep-alive` are intentionally
/// omitted so replay flows can pass them through unchanged.
const HOP_BY_HOP_HEADERS: &[&str] = &[
  "host",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

/// Router-owned header names (lowercase) that must never leak upstream.
/// Mirrors `tokn_router::api::is_router_owned_header` — duplicated here
/// to keep `tokn-requests` free of any dependency on the legacy router
/// crate.
fn is_router_owned(name: &str) -> bool {
  name.starts_with("x-tokn-router-") || name == "x-route-mode" || name == "x-behave-as"
}

pub struct PassthroughBuildHeaders {
  preserve_client_auth: bool,
}

impl Default for PassthroughBuildHeaders {
  fn default() -> Self {
    Self::new()
  }
}

impl PassthroughBuildHeaders {
  /// Default: strip `Host` along with the other hop-by-hop headers. Suitable
  /// for the JSON `/v1` passthrough path, where the upstream URL is dictated
  /// by the provider and reqwest sets `Host` from that URL.
  pub fn new() -> Self {
    Self {
      preserve_client_auth: true,
    }
  }

  /// Strip inbound auth while letting reqwest derive `Host` from the
  /// provider URL. Used by API switch mode: bytes stay verbatim, but
  /// credentials come from the selected router account.
  pub fn router_auth() -> Self {
    Self {
      preserve_client_auth: false,
    }
  }
}

#[async_trait]
impl BuildHeadersStage for PassthroughBuildHeaders {
  async fn build_headers(
    &self,
    _ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
  ) -> Result<BuiltHeaders, PipelineError> {
    let mut out = HeaderMap::new();
    for (name, value) in extracted.headers.iter() {
      let lower = name.as_str().to_ascii_lowercase();
      if is_router_owned(&lower) {
        continue;
      }
      if !self.preserve_client_auth && matches!(lower.as_str(), "authorization" | "x-api-key") {
        continue;
      }
      if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
        continue;
      }
      out.insert(name.clone(), value.clone());
    }
    Ok(BuiltHeaders {
      headers: out,
      vars: build_template_vars(&extracted.headers),
      agent_id: resolved
        .agent_id
        .clone()
        .or_else(|| extracted.agent_id.clone())
        .or_else(|| AgentId::provider_default(resolved.provider_id.as_str()))
        .unwrap_or_default(),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::EventBus;
  use crate::pipeline::ctx::PipelineCtx;
  use bytes::Bytes;
  use serde_json::json;
  use smol_str::SmolStr;
  use std::sync::Arc;
  use tokn_core::provider::Endpoint;
  use tokn_headers::{HeaderName, HeaderValue};

  fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
      m.insert(HeaderName::new(*k), HeaderValue::from_string((*v).to_string()));
    }
    m
  }

  fn extracted(headers: HeaderMap) -> Extracted {
    Extracted {
      agent_id: None,
      model: SmolStr::new("m"),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: None,
      header_initiator: None,
      route_mode_hint: None,
      headers,
      raw_body: Bytes::new(),
      decoded_body: Bytes::new(),
      body_json: Arc::new(json!(null)),
      content_encoding: None,
    }
  }

  fn resolved(provider_id: &str) -> Resolved {
    Resolved {
      agent_id: None,
      model: SmolStr::new("m"),
      upstream_model: SmolStr::new("m"),
      route: crate::pipeline::stages::ResolvedRoute::operation(Endpoint::ChatCompletions, Endpoint::ChatCompletions),
      account_id: SmolStr::new("acct-1"),
      provider_id: SmolStr::new(provider_id),
      account_handle: crate::test_support::mock_handle("acct-1", provider_id),
    }
  }

  fn ctx() -> PipelineCtx {
    PipelineCtx::new("req-pbh", Endpoint::ChatCompletions.into(), Arc::new(EventBus::new(64)))
  }

  #[tokio::test]
  async fn forwards_inbound_minus_denylist() {
    let h = header_map(&[
      ("user-agent", "opencode/1.0"),
      ("authorization", "Bearer client-token"),
      ("accept", "application/json"),
      ("host", "api.openai.com"),
      ("connection", "keep-alive"),
      ("x-tokn-router-local-addr", "127.0.0.1:8080"),
      ("x-route-mode", "passthrough"),
      ("x-behave-as", "codex"),
      ("x-custom-thing", "hello"),
    ]);
    let out = PassthroughBuildHeaders::new()
      .build_headers(&ctx(), &extracted(h), &resolved("openai"))
      .await
      .unwrap();
    assert!(out.headers.contains_key("user-agent"));
    assert!(out.headers.contains_key("authorization"));
    assert!(out.headers.contains_key("accept"));
    assert!(out.headers.contains_key("x-custom-thing"));
    assert!(!out.headers.contains_key("host"), "host stripped");
    assert_eq!(out.headers.get("connection").map(|v| v.as_str()), Some("keep-alive"));
    assert!(
      !out.headers.contains_key("x-tokn-router-local-addr"),
      "router-owned stripped"
    );
    assert!(!out.headers.contains_key("x-route-mode"));
    assert!(!out.headers.contains_key("x-behave-as"));
  }

  #[tokio::test]
  async fn passthrough_vars_preserve_correlation_metadata() {
    let headers = header_map(&[
      ("x-session-id", "ses_abc"),
      ("x-request-id", "req_123"),
      ("x-opencode-project", "/worktree"),
      ("x-interaction-id", "int_9"),
      ("chatgpt-account-id", "acct_1"),
    ]);
    let out = PassthroughBuildHeaders::new()
      .build_headers(&ctx(), &extracted(headers), &resolved("openai"))
      .await
      .unwrap();
    assert_eq!(out.vars.session_id.as_deref(), Some("ses_abc"));
    assert_eq!(out.vars.request_id.as_deref(), Some("req_123"));
    assert_eq!(out.vars.project_cwd.as_deref(), Some("/worktree"));
    assert_eq!(out.vars.interaction_id.as_deref(), Some("int_9"));
    assert_eq!(out.vars.account_id.as_deref(), Some("acct_1"));
  }

  #[tokio::test]
  async fn router_auth_strips_client_credentials_and_host() {
    let h = header_map(&[
      ("host", "api.example.com"),
      ("authorization", "Bearer tok"),
      ("x-api-key", "client-key"),
      ("accept", "application/json"),
    ]);
    let out = PassthroughBuildHeaders::router_auth()
      .build_headers(&ctx(), &extracted(h), &resolved("openai"))
      .await
      .unwrap();
    assert!(!out.headers.contains_key("host"));
    assert!(!out.headers.contains_key("authorization"));
    assert!(!out.headers.contains_key("x-api-key"));
    assert!(out.headers.contains_key("accept"));
  }
}

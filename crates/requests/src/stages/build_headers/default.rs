//! Default BuildHeaders stage.
//!
//! Composes the outbound HeaderMap from the inbound request using the
//! [`tokn_headers`] schema + overlay registry. The flow is:
//!
//! 1. Resolve an effective [`tokn_core::AgentId`] — `extracted.agent_id`
//!    wins if set, else the stage's per-provider default mapping is used, else
//!    a stage-wide fallback.
//! 2. Build template variables from the inbound headers using the same scan
//!    behavior as the legacy router's `api::first_header`.
//! 3. Delegate wire identity composition to
//!    [`build_wire_identity_headers`]. The shared registry helper combines
//!    the selected agent schema with the provider overlay, or falls back to
//!    agent-only headers for an unknown provider.
//!
//! Output: [`BuiltHeaders { headers, vars }`]. `vars` is retained so later
//! stages can splice correlation values into bodies without re-parsing the
//! inbound map.

use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::PipelineError;
use crate::pipeline::stages::{BuildHeadersStage, BuiltHeaders, Extracted, Resolved};
use async_trait::async_trait;
use smol_str::SmolStr;
use std::collections::HashMap;
use tokn_core::AgentId;
use tokn_headers::inbound::build_template_vars;
use tokn_headers::registry::build_wire_identity_headers;

/// Default BuildHeaders stage. See module docs for the resolution
/// algorithm.
pub struct DefaultBuildHeaders {
  /// Per-provider fallback agent id. Indexed by `provider_id`.
  agent_defaults: HashMap<SmolStr, AgentId>,
  /// Stage-wide fallback agent id used when no explicit or provider default
  /// exists.
  unknown_agent_id_default: AgentId,
}

impl DefaultBuildHeaders {
  pub fn new(agent_defaults: HashMap<SmolStr, AgentId>, unknown_agent_id_default: AgentId) -> Self {
    Self {
      agent_defaults,
      unknown_agent_id_default,
    }
  }

  /// Convenience constructor with built-in provider defaults and an Opencode
  /// fallback for unknown providers.
  pub fn with_provider_defaults() -> Self {
    let mut agent_defaults = HashMap::new();
    for provider_id in [
      "openai",
      "deepseek",
      "zai",
      "zai-coding-plan",
      "zhipuai",
      "zhipuai-coding-plan",
    ] {
      agent_defaults.insert(SmolStr::new(provider_id), AgentId::Opencode);
    }
    agent_defaults.insert(SmolStr::new("codex"), AgentId::CodexCli);
    agent_defaults.insert(SmolStr::new("copilot"), AgentId::CopilotCli);
    agent_defaults.insert(SmolStr::new("github-copilot"), AgentId::CopilotCli);
    Self::new(agent_defaults, AgentId::Opencode)
  }

  fn effective_agent_id(&self, extracted: &Extracted, resolved: &Resolved) -> AgentId {
    resolved
      .agent_id
      .clone()
      .or_else(|| extracted.agent_id.clone())
      .or_else(|| self.agent_defaults.get(resolved.provider_id.as_str()).cloned())
      .unwrap_or_else(|| self.unknown_agent_id_default.clone())
  }
}

#[async_trait]
impl BuildHeadersStage for DefaultBuildHeaders {
  async fn build_headers(
    &self,
    _ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
  ) -> Result<BuiltHeaders, PipelineError> {
    let inbound = &extracted.headers;
    let vars = build_template_vars(inbound);
    let agent_id = self.effective_agent_id(extracted, resolved);

    let headers = build_wire_identity_headers(resolved.provider_id.as_str(), agent_id.as_str(), &vars, inbound);

    Ok(BuiltHeaders {
      headers,
      vars,
      agent_id,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::EventBus;
  use bytes::Bytes;
  use serde_json::json;
  use std::sync::Arc;
  use tokn_core::provider::Endpoint;
  use tokn_headers::{keys, HeaderMap, HeaderValue};

  fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
      m.insert(*k, HeaderValue::from_string((*v).to_string()));
    }
    m
  }

  fn extracted(headers: HeaderMap, agent_id: Option<AgentId>) -> Extracted {
    Extracted {
      agent_id,
      model: "gpt-4o".into(),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: None,
      header_initiator: None,
      route_mode_hint: None,
      headers,
      raw_body: Bytes::new(),
      decoded_body: Bytes::new(),
      body_json: Arc::new(json!({})),
      content_encoding: None,
    }
  }

  fn resolved(provider_id: &str) -> Resolved {
    Resolved {
      agent_id: None,
      model: "gpt-4o".into(),
      upstream_model: "gpt-4o".into(),
      route: crate::pipeline::stages::ResolvedRoute::operation(Endpoint::ChatCompletions, Endpoint::ChatCompletions),
      account_id: "acct-1".into(),
      provider_id: provider_id.into(),
      account_handle: crate::test_support::mock_handle("acct-1", provider_id),
    }
  }

  fn ctx() -> PipelineCtx {
    PipelineCtx::new("req-bh", Endpoint::ChatCompletions.into(), Arc::new(EventBus::new(64)))
  }

  #[tokio::test]
  async fn provider_default_with_overlay_composes_both() {
    let stage = DefaultBuildHeaders::with_provider_defaults();
    let out = stage
      .build_headers(&ctx(), &extracted(HeaderMap::new(), None), &resolved("copilot"))
      .await
      .unwrap();
    assert!(out.headers.contains_key(&keys::EDITOR_VERSION));
    assert!(out.headers.contains_key(&keys::COPILOT_INTEGRATION_ID));
  }

  #[tokio::test]
  async fn provider_default_without_overlay_uses_agent_id_only() {
    let stage = DefaultBuildHeaders::with_provider_defaults();
    let out = stage
      .build_headers(&ctx(), &extracted(HeaderMap::new(), None), &resolved("deepseek"))
      .await
      .unwrap();
    assert!(!out.headers.is_empty(), "agent header map should be non-empty");
    assert!(!out.headers.contains_key(&keys::COPILOT_INTEGRATION_ID));
  }

  #[tokio::test]
  async fn missing_agent_id_falls_back_to_custom_provider_default() {
    let mut defaults = HashMap::new();
    defaults.insert(SmolStr::new("copilot"), AgentId::CopilotCli);
    let stage = DefaultBuildHeaders::new(defaults, AgentId::Opencode);
    let out = stage
      .build_headers(&ctx(), &extracted(HeaderMap::new(), None), &resolved("copilot"))
      .await
      .unwrap();
    assert!(out.headers.contains_key(&keys::EDITOR_VERSION));
  }

  #[tokio::test]
  async fn missing_agent_id_falls_back_to_global_default() {
    let stage = DefaultBuildHeaders::new(HashMap::new(), AgentId::Opencode);
    let out = stage
      .build_headers(&ctx(), &extracted(HeaderMap::new(), None), &resolved("nonesuch"))
      .await
      .unwrap();
    assert!(!out.headers.is_empty());
  }

  #[tokio::test]
  async fn explicit_agent_id_overrides_provider_default() {
    let stage = DefaultBuildHeaders::with_provider_defaults();
    let out = stage
      .build_headers(
        &ctx(),
        &extracted(HeaderMap::new(), Some(AgentId::CodexCli)),
        &resolved("openai"),
      )
      .await
      .unwrap();
    assert!(
      out.headers.contains_key(&keys::ORIGINATOR),
      "Codex overlay's `originator` header missing — explicit agent_id was ignored"
    );
  }

  #[tokio::test]
  async fn resolved_agent_id_overrides_extracted_agent_id() {
    let stage = DefaultBuildHeaders::with_provider_defaults();
    let mut resolved = resolved("openai");
    resolved.agent_id = Some(AgentId::CodexCli);
    let out = stage
      .build_headers(&ctx(), &extracted(HeaderMap::new(), Some(AgentId::Opencode)), &resolved)
      .await
      .unwrap();
    assert!(
      out.headers.contains_key(&keys::ORIGINATOR),
      "Codex overlay should win when Resolve supplied the effective agent_id"
    );
  }

  #[tokio::test]
  async fn template_vars_populated_from_inbound() {
    let headers = header_map(&[
      ("x-session-id", "ses_abc"),
      ("x-request-id", "req_xyz"),
      ("x-opencode-project", "/home/me/proj"),
      ("chatgpt-account-id", "acct_42"),
    ]);
    let stage = DefaultBuildHeaders::with_provider_defaults();
    let out = stage
      .build_headers(&ctx(), &extracted(headers, None), &resolved("deepseek"))
      .await
      .unwrap();
    assert_eq!(out.vars.session_id.as_deref(), Some("ses_abc"));
    assert_eq!(out.vars.request_id.as_deref(), Some("req_xyz"));
    assert_eq!(out.vars.project_cwd.as_deref(), Some("/home/me/proj"));
    assert_eq!(out.vars.account_id.as_deref(), Some("acct_42"));
  }
}

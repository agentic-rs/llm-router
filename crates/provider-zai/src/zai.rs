//! Z.ai (a.k.a. Zhipu AI / bigmodel.cn) provider.
//!
//! Targets Z.ai's OpenAI-compatible coding-plan endpoint
//! (`https://api.z.ai/api/coding/paas/v4`). The same backend implementation is
//! exposed under four provider identifiers that share one implementation:
//!   - `zai-coding-plan` (canonical)
//!   - `zai`
//!   - `zhipuai-coding-plan`
//!   - `zhipuai`
//!
//! Authentication is a single static `Authorization: Bearer <api_key>` header;
//! no token exchange. For models flagged `capabilities.reasoning = true` we
//! inject a `thinking: { type: "enabled", clear_thinking: false }` block into
//! the outgoing request body, mirroring the contract upstream coding tools
//! (Claude Code, opencode) rely on.

pub use crate::{models, quota, transform};

use crate::util::secret::Secret;
use async_trait::async_trait;
use reqwest::Method;
use serde_json::Value;
use tokn_core::account::AccountConfig;
use tokn_core::pipeline::InputTransformer;
use tokn_core::provider::ProviderTarget;
use tokn_core::upstream_url::CleartextHttpPolicy;
use tokn_headers::keys::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use tokn_headers::{HeaderMap, HeaderValue};
use tracing::{debug, instrument, warn};

use crate::{
  error, AuthKind, CredentialPatchCtx, HeaderPatchCtx, ModelInfo, Provider, ProviderInfo, ProviderRequestKind,
  RequestCtx, Result, ID_ZAI, ID_ZAI_CODING_PLAN, ID_ZHIPUAI, ID_ZHIPUAI_CODING_PLAN, ZAI_PROVIDERS,
};

/// Canonical upstreams for the four Z.ai provider identities. Legacy account
/// URLs may override these until destination ownership moves fully to v2
/// upstream resources.
pub const ZAI_BASE_URL: &str = "https://api.z.ai/api/paas/v4";
pub const ZAI_CODING_PLAN_BASE_URL: &str = "https://api.z.ai/api/coding/paas/v4";
pub const ZHIPUAI_BASE_URL: &str = "https://open.bigmodel.cn/api/paas/v4";
pub const ZHIPUAI_CODING_PLAN_BASE_URL: &str = "https://open.bigmodel.cn/api/coding/paas/v4";

pub struct ZaiProvider {
  pub id: String,
  api_key: Secret<String>,
  target: ProviderTarget,
  info: ProviderInfo,
}

impl std::fmt::Debug for ZaiProvider {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    // Deliberately omit `api_key` so it never lands in logs or test
    // panic output.
    f.debug_struct("ZaiProvider")
      .field("id", &self.id)
      .field("base_url", &self.target.base_url())
      .field("provider", &self.info.id)
      .finish()
  }
}

impl ZaiProvider {
  pub fn validate_account(a: &AccountConfig) -> Result<()> {
    if !ZAI_PROVIDERS.contains(&a.provider.as_str()) {
      return error::ProviderMismatchSnafu {
        expected: "zai|zai-coding-plan|zhipuai|zhipuai-coding-plan",
        got: a.provider.clone(),
      }
      .fail();
    }
    let _ = a
      .api_key
      .clone()
      .filter(|s| !s.expose().trim().is_empty())
      .ok_or(error::Error::MissingCredential {
        account: a.id.clone(),
        what: "api_key",
      })?;
    Ok(())
  }

  pub fn from_account(a: std::sync::Arc<AccountConfig>) -> Result<Self> {
    Self::validate_account(&a)?;
    let base_url = a.base_url.clone().unwrap_or_else(|| {
      default_base_url(&a.provider)
        .expect("validated Z.ai provider id")
        .to_string()
    });
    let target = ProviderTarget::parse(&base_url, CleartextHttpPolicy::Allow).map_err(|source| {
      error::Error::InvalidUpstreamUrl {
        account: a.id.clone(),
        source,
      }
    })?;
    Ok(Self::from_validated_account_at(a, target))
  }

  pub fn from_account_at(a: std::sync::Arc<AccountConfig>, target: ProviderTarget) -> Result<Self> {
    Self::validate_account(&a)?;
    Ok(Self::from_validated_account_at(a, target))
  }

  fn from_validated_account_at(a: std::sync::Arc<AccountConfig>, target: ProviderTarget) -> Self {
    let key = a.api_key.clone().expect("validated api_key");
    let upstream_url = target.base_url().to_string();

    let info = ProviderInfo {
      id: a.provider.clone(),
      aliases: &[],
      display_name: "Z.ai (GLM Coding Plan)",
      upstream_url,
      auth_kind: AuthKind::StaticApiKey,
      default_models: models::catalogue_for(&a.provider),
      default_endpoints: crate::DEFAULT_ENDPOINTS,
      model_cache: target.model_cache().clone(),
    };
    Self {
      id: format!("{}:{}", a.provider, a.id),
      api_key: key,
      target,
      info,
    }
  }

  fn auth_headers(&self, streaming: bool) -> Result<HeaderMap> {
    let mut m = HeaderMap::new();
    m.insert(
      &AUTHORIZATION,
      HeaderValue::from_string(format!("Bearer {}", self.api_key.expose())),
    );
    m.insert(
      &ACCEPT,
      HeaderValue::from_static(if streaming {
        "text/event-stream"
      } else {
        "application/json"
      }),
    );
    m.insert(&CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(m)
  }
}

impl InputTransformer for ZaiProvider {
  fn transform_input(&self, _endpoint: crate::Endpoint, body: Value) -> Result<Value> {
    let model_id = body.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let reasoning = self
      .model_info(model_id)
      .map(|m| m.capabilities.reasoning)
      .unwrap_or_else(|| model_id.starts_with("glm-"));
    Ok(transform::shape_request(&body, reasoning))
  }
}

pub fn default_base_url(provider: &str) -> Option<&'static str> {
  match provider {
    ID_ZAI => Some(ZAI_BASE_URL),
    ID_ZAI_CODING_PLAN => Some(ZAI_CODING_PLAN_BASE_URL),
    ID_ZHIPUAI => Some(ZHIPUAI_BASE_URL),
    ID_ZHIPUAI_CODING_PLAN => Some(ZHIPUAI_CODING_PLAN_BASE_URL),
    _ => None,
  }
}

#[async_trait]
impl Provider for ZaiProvider {
  fn id(&self) -> &str {
    &self.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  fn input_transformer(&self) -> Option<&dyn InputTransformer> {
    Some(self)
  }

  fn model_info(&self, model: &str) -> Option<&ModelInfo> {
    self.info.default_models.iter().find(|m| m.id == model)
  }

  fn inject_credentials(&self, headers: &mut HeaderMap, _ctx: &CredentialPatchCtx<'_>) -> Result<()> {
    headers.insert(
      &AUTHORIZATION,
      HeaderValue::from_string(format!("Bearer {}", self.api_key.expose())),
    );
    Ok(())
  }

  fn normalize_headers(&self, headers: &mut HeaderMap, ctx: &HeaderPatchCtx<'_>) -> Result<Option<HeaderMap>> {
    headers.insert(
      &ACCEPT,
      HeaderValue::from_static(if ctx.stream {
        "text/event-stream"
      } else {
        "application/json"
      }),
    );
    headers.insert(&CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(encoding) = ctx.content_encoding {
      headers.insert(&CONTENT_ENCODING, HeaderValue::from_string(encoding.to_string()));
    }
    Ok(None)
  }

  #[instrument(
    name = "zai_list_models",
    skip_all,
    fields(account = %self.id, key_fp = %self.api_key.fingerprint(), status = tracing::field::Empty, count = tracing::field::Empty),
  )]
  async fn list_models(&self, http: &reqwest::Client) -> Result<Value> {
    let url = self.target.base_url().operation_url(["models"])?;
    debug!(%url, "GET zai models");
    let resp = crate::util::http::send(
      http,
      Method::GET,
      url.as_str(),
      self.auth_headers(false)?,
      None,
      None,
      "zai /models",
    )
    .await?;
    let status = resp.status();
    tracing::Span::current().record("status", status.as_u16());
    let v: Value = crate::util::http::read_json(resp, "zai /models").await?;
    let data: Vec<Value> = match &v {
      Value::Object(_) => v.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default(),
      Value::Array(a) => a.clone(),
      _ => Vec::new(),
    };
    tracing::Span::current().record("count", data.len());
    Ok(serde_json::json!({ "object": "list", "data": data }))
  }

  #[instrument(
    name = "zai_chat",
    skip_all,
    fields(
      account = %self.id,
      key_fp = %self.api_key.fingerprint(),
      stream = ctx.stream,
      model = tracing::field::Empty,
      reasoning = tracing::field::Empty,
      status = tracing::field::Empty,
    ),
  )]
  async fn chat(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    let model_id = ctx.body.get("model").and_then(|v| v.as_str()).unwrap_or("");
    // Reasoning gating: known models drive it explicitly; unknown GLM
    // models default to enabled (matches Z.ai's own clients).
    let reasoning = self
      .model_info(model_id)
      .map(|m| m.capabilities.reasoning)
      .unwrap_or_else(|| model_id.starts_with("glm-"));
    let span = tracing::Span::current();
    span.record("model", model_id);
    span.record("reasoning", reasoning);

    let url = self.target.base_url().operation_url(["chat", "completions"])?;
    debug!(%url, "POST zai chat");
    let mut headers = ctx.client_headers.clone().unwrap_or_default();
    self.patch_headers(
      &mut headers,
      &HeaderPatchCtx {
        request_kind: ProviderRequestKind::Operation(ctx.endpoint),
        body: ctx.body,
        bearer_token: None,
        content_encoding: ctx.content_encoding,
        stream: ctx.stream,
        initiator: ctx.initiator,
        inbound_headers: ctx.inbound_headers,
        vars: &ctx.vars,
        wire_identity: ctx.wire_identity.as_ref(),
      },
    )?;
    let body_bytes = ctx.request_body_bytes();
    let resp = crate::util::http::send(
      ctx.http,
      Method::POST,
      url.as_str(),
      headers,
      Some(body_bytes),
      ctx.outbound.as_ref(),
      "zai chat",
    )
    .await?;
    span.record("status", resp.status().as_u16());
    Ok(resp)
  }

  fn on_unauthorized(&self) {
    // Static API keys cannot be silently refreshed; the operator must
    // rotate. We log loudly so they notice.
    warn!(
      account = %self.id,
      key_fp = %self.api_key.fingerprint(),
      "zai upstream returned 401: api_key likely revoked or expired"
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::Account as AcctCfg;
  use crate::provider::{new_outbound_capture, Endpoint, RequestCtx, ZAI_PROVIDERS};
  use crate::TemplateVars;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  fn acct(provider: &str, key: Option<&str>) -> AcctCfg {
    AcctCfg {
      id: "test".into(),
      provider: provider.into(),
      enabled: true,
      tier: tokn_core::account::AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: None,
      username: None,
      api_key: key.map(|s| Secret::new(s.into())),
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: toml::Table::new(),
    }
  }

  #[test]
  fn rejects_missing_api_key() {
    let err = ZaiProvider::from_account(std::sync::Arc::new(acct("zai-coding-plan", None))).unwrap_err();
    assert!(err.to_string().contains("api_key"), "{err}");
  }

  #[test]
  fn rejects_blank_api_key() {
    let err = ZaiProvider::from_account(std::sync::Arc::new(acct("zai-coding-plan", Some("   ")))).unwrap_err();
    assert!(err.to_string().contains("api_key"), "{err}");
  }

  #[test]
  fn rejects_non_zai_provider_id() {
    let err = ZaiProvider::from_account(std::sync::Arc::new(acct("github-copilot", Some("sk-x")))).unwrap_err();
    assert!(err.to_string().contains("provider mismatch"), "{err}");
  }

  #[test]
  fn all_four_aliases_construct_and_preserve_canonical_id() {
    for provider in ZAI_PROVIDERS {
      let p = ZaiProvider::from_account(std::sync::Arc::new(acct(provider, Some("sk-x")))).unwrap();
      assert_eq!(p.info().id, *provider, "info().id should preserve provider id");
      assert_eq!(p.info().display_name, "Z.ai (GLM Coding Plan)");
      assert_eq!(p.info().auth_kind, AuthKind::StaticApiKey);
      assert!(!p.info().default_models.is_empty());
    }
  }

  #[test]
  fn each_alias_defaults_to_its_descriptor_endpoint() {
    for (provider, expected) in [
      (ID_ZAI, ZAI_BASE_URL),
      (ID_ZAI_CODING_PLAN, ZAI_CODING_PLAN_BASE_URL),
      (ID_ZHIPUAI, ZHIPUAI_BASE_URL),
      (ID_ZHIPUAI_CODING_PLAN, ZHIPUAI_CODING_PLAN_BASE_URL),
    ] {
      let provider = ZaiProvider::from_account(std::sync::Arc::new(acct(provider, Some("sk-x")))).unwrap();
      assert_eq!(provider.target.base_url().as_str(), format!("{expected}/"));
    }
  }

  #[test]
  fn respects_base_url_override() {
    let mut a = acct("zhipuai", Some("sk-x"));
    a.base_url = Some("https://open.bigmodel.cn/api/paas/v4".into());
    let p = ZaiProvider::from_account(std::sync::Arc::new(a)).unwrap();
    assert_eq!(p.target.base_url().as_str(), "https://open.bigmodel.cn/api/paas/v4/");
  }

  #[test]
  fn explicit_target_owns_the_destination_and_cache() {
    let mut account = acct("zai", Some("sk-x"));
    account.base_url = Some("https://ignored.example/v1".into());
    let target = ProviderTarget::parse("https://gateway.example/zai", CleartextHttpPolicy::Allow).unwrap();
    let cache = target.model_cache().clone();

    let provider = ZaiProvider::from_account_at(std::sync::Arc::new(account), target).unwrap();

    assert_eq!(provider.target.base_url().as_str(), "https://gateway.example/zai/");
    assert_eq!(
      provider
        .target
        .base_url()
        .operation_url(["chat", "completions"])
        .unwrap()
        .as_str(),
      "https://gateway.example/zai/chat/completions"
    );
    assert_eq!(provider.info().upstream_url, "https://gateway.example/zai/");
    assert!(std::sync::Arc::ptr_eq(&provider.info().model_cache, &cache));
  }

  #[test]
  fn input_transformer_injects_thinking_once() {
    let provider = ZaiProvider::from_account(std::sync::Arc::new(acct("zai-coding-plan", Some("sk-test")))).unwrap();
    let body = serde_json::json!({
      "model": "glm-4.6",
      "messages": [{ "role": "user", "content": "hi" }]
    });

    let once = provider.transform_input(Endpoint::ChatCompletions, body).unwrap();
    let twice = provider
      .transform_input(Endpoint::ChatCompletions, once.clone())
      .unwrap();

    assert_eq!(once, twice);
    assert_eq!(
      once
        .get("thinking")
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str()),
      Some("enabled")
    );
  }

  #[tokio::test]
  async fn captures_transformed_outbound_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      let mut buf = vec![0_u8; 8192];
      let n = stream.read(&mut buf).await.unwrap();
      assert!(String::from_utf8_lossy(&buf[..n]).contains("POST /chat/completions"));
      stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
        .await
        .unwrap();
    });

    let mut cfg = acct("zai-coding-plan", Some("sk-test"));
    cfg.base_url = Some(format!("http://{addr}"));
    let provider = ZaiProvider::from_account(std::sync::Arc::new(cfg)).unwrap();
    let http = reqwest::Client::new();
    let body = provider
      .transform_input(
        Endpoint::ChatCompletions,
        serde_json::json!({ "model": "glm-4.6", "messages": [{ "role": "user", "content": "hi" }] }),
      )
      .unwrap();
    let inbound = HeaderMap::new();
    let capture = new_outbound_capture();
    let ctx = RequestCtx {
      endpoint: Endpoint::ChatCompletions,
      http: &http,
      body: &body,
      body_bytes: None,
      content_encoding: None,
      stream: false,
      initiator: "user",
      inbound_headers: &inbound,
      client_headers: None,
      outbound: Some(capture.clone()),
      vars: TemplateVars::default(),
      wire_identity: Some(tokn_core::AgentId::Opencode),
    };
    let resp = provider.chat(ctx).await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    server.await.unwrap();
    let captured = capture.get().expect("captured outbound");
    let captured_body: Value = serde_json::from_slice(captured.req_body.as_ref()).unwrap();
    assert_eq!(captured.method.as_deref(), Some("POST"));
    assert!(
      captured_body.get("thinking").is_some(),
      "body was not transformed: {captured_body}"
    );
  }

  // ---------- header stability tests ----------
  // All four ZAI_PROVIDERS share the same patch_headers impl, so we exercise
  // one canonical id (zai-coding-plan) and rely on the existing aliases test
  // for ID coverage.

  fn patch_ctx(stream: bool, content_encoding: Option<&'static str>) -> HeaderPatchCtx<'static> {
    HeaderPatchCtx {
      request_kind: ProviderRequestKind::Operation(Endpoint::ChatCompletions),
      body: &Value::Null,
      bearer_token: None,
      content_encoding,
      stream,
      initiator: "user",
      inbound_headers: Box::leak(Box::new(HeaderMap::new())),
      vars: Box::leak(Box::new(TemplateVars::default())),
      wire_identity: Some(Box::leak(Box::new(tokn_core::AgentId::Opencode))),
    }
  }

  fn provider() -> ZaiProvider {
    ZaiProvider::from_account(std::sync::Arc::new(acct("zai-coding-plan", Some("sk-test-fixture")))).unwrap()
  }

  #[test]
  fn zai_patch_headers_streaming() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(true, None)).unwrap();
    assert_eq!(h.get("authorization").unwrap().as_str(), "Bearer sk-test-fixture");
    assert_eq!(h.get("accept").unwrap().as_str(), "text/event-stream");
    assert_eq!(h.get("content-type").unwrap().as_str(), "application/json");
    assert!(h.get("content-encoding").is_none());
    let names: Vec<_> = h.iter().map(|(n, _)| n.as_str().to_string()).collect();
    assert_eq!(names.len(), 3, "unexpected extra headers: {names:?}");
  }

  #[test]
  fn zai_patch_headers_non_streaming() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(false, None)).unwrap();
    assert_eq!(h.get("accept").unwrap().as_str(), "application/json");
    assert_eq!(h.get("content-type").unwrap().as_str(), "application/json");
  }

  #[test]
  fn zai_patch_headers_round_trips_content_encoding() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(false, Some("gzip"))).unwrap();
    assert_eq!(h.get("content-encoding").unwrap().as_str(), "gzip");
  }
}

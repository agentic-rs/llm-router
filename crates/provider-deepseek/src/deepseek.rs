use crate::util::secret::Secret;
use async_trait::async_trait;
use reqwest::Method;
use serde_json::{json, Value};
use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::pipeline::InputTransformer;
use tokn_core::provider::ProviderTarget;
use tokn_core::upstream_url::CleartextHttpPolicy;
use tokn_headers::keys::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use tokn_headers::{HeaderMap, HeaderValue};
use tracing::{debug, instrument, warn};

use crate::{
  error, AuthKind, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx, Result, TemplateVars,
  ID_DEEPSEEK,
};

pub const DEFAULT_BASE_URL: &str = "https://api.deepseek.com";

pub struct DeepSeekProvider {
  pub id: String,
  api_key: Secret<String>,
  target: ProviderTarget,
  info: ProviderInfo,
}

impl DeepSeekProvider {
  pub fn validate_account(a: &AccountConfig) -> Result<()> {
    if a.provider != ID_DEEPSEEK {
      return error::ProviderMismatchSnafu {
        expected: ID_DEEPSEEK,
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

  pub fn from_account(a: Arc<AccountConfig>) -> Result<Self> {
    let base_url = a.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL);
    let target = ProviderTarget::parse(base_url, CleartextHttpPolicy::Allow).map_err(|source| {
      error::Error::InvalidUpstreamUrl {
        account: a.id.clone(),
        source,
      }
    })?;
    Self::from_account_at(a, target)
  }

  pub fn from_account_at(a: Arc<AccountConfig>, target: ProviderTarget) -> Result<Self> {
    Self::validate_account(&a)?;
    let key = a.api_key.clone().expect("validated api_key");
    let upstream_url = target.base_url().to_string();
    Ok(Self {
      id: format!("deepseek:{}", a.id),
      api_key: key,
      info: ProviderInfo {
        id: ID_DEEPSEEK.to_string(),
        aliases: &[ID_DEEPSEEK],
        display_name: "DeepSeek",
        upstream_url,
        auth_kind: AuthKind::StaticApiKey,
        default_models: crate::catalogue::default_models_for(ID_DEEPSEEK),
        default_endpoints: crate::DEFAULT_ENDPOINTS,
        model_cache: Arc::clone(target.model_cache()),
      },
      target,
    })
  }

  fn operation_url(&self, segments: &[&str]) -> Result<reqwest::Url> {
    Ok(self.target.base_url().operation_url(segments.iter().copied())?)
  }

  fn messages_url(&self) -> Result<reqwest::Url> {
    if self
      .target
      .base_url()
      .as_str()
      .trim_end_matches('/')
      .ends_with("/anthropic")
    {
      self.operation_url(&["v1", "messages"])
    } else {
      self.operation_url(&["anthropic", "v1", "messages"])
    }
  }

  async fn upstream_post(
    &self,
    ctx: RequestCtx<'_>,
    url: reqwest::Url,
    what: &'static str,
  ) -> Result<reqwest::Response> {
    debug!(%url, "POST deepseek upstream");
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
        agent_id: &ctx.agent_id,
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
      what,
    )
    .await?;
    Ok(resp)
  }
}

impl InputTransformer for DeepSeekProvider {
  fn transform_input(&self, endpoint: crate::Endpoint, body: Value) -> Result<Value> {
    Ok(shape_request(endpoint, body))
  }
}

#[async_trait]
impl Provider for DeepSeekProvider {
  fn id(&self) -> &str {
    &self.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  fn input_transformer(&self) -> Option<&dyn InputTransformer> {
    Some(self)
  }

  fn inject_credentials(&self, headers: &mut HeaderMap, _ctx: &HeaderPatchCtx<'_>) -> Result<()> {
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

  async fn list_models(&self, http: &reqwest::Client) -> Result<Value> {
    let mut headers = HeaderMap::new();
    self.patch_headers(
      &mut headers,
      &HeaderPatchCtx {
        request_kind: ProviderRequestKind::Models,
        body: &Value::Null,
        bearer_token: None,
        content_encoding: None,
        stream: false,
        initiator: "user",
        inbound_headers: &HeaderMap::new(),
        vars: &TemplateVars::default(),
        agent_id: &tokn_core::AgentId::Opencode,
      },
    )?;
    let url = self.operation_url(&["models"])?;
    let resp =
      crate::util::http::send(http, Method::GET, url.as_str(), headers, None, None, "deepseek /models").await?;
    crate::util::http::read_json(resp, "deepseek /models").await
  }

  #[instrument(name = "deepseek_chat", skip_all, fields(account = %self.id, stream = ctx.stream))]
  async fn chat(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    let url = self.operation_url(&["chat", "completions"])?;
    self.upstream_post(ctx, url, "deepseek chat").await
  }

  #[instrument(name = "deepseek_messages", skip_all, fields(account = %self.id, stream = ctx.stream))]
  async fn messages(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    let url = self.messages_url()?;
    self.upstream_post(ctx, url, "deepseek messages").await
  }

  fn on_unauthorized(&self) {
    warn!(account = %self.id, key_fp = %self.api_key.fingerprint(), "deepseek upstream returned 401: api_key likely revoked or expired");
  }
}

fn shape_request(endpoint: crate::Endpoint, body: Value) -> Value {
  let mut out = body;
  let Some(obj) = out.as_object_mut() else {
    return out;
  };

  let effort = extract_effort(obj.get("thinking")).or_else(|| extract_effort(obj.get("reasoning")));
  let thinking_mode = extract_thinking_mode(obj.get("thinking"), obj.get("reasoning"));
  obj.insert("thinking".into(), json!({ "type": thinking_mode }));
  obj.remove("reasoning");

  match endpoint {
    crate::Endpoint::ChatCompletions => {
      obj.remove("output_config");
      if let Some(effort) = effort {
        obj.insert("reasoning_effort".into(), Value::String(effort));
      } else {
        obj.remove("reasoning_effort");
      }
    }
    crate::Endpoint::Messages => {
      obj.remove("reasoning_effort");
      if let Some(effort) = effort {
        obj.insert("output_config".into(), json!({ "effort": effort }));
      } else {
        obj.remove("output_config");
      }
    }
    crate::Endpoint::Responses => {}
  }

  out
}

fn extract_thinking_mode(thinking: Option<&Value>, reasoning: Option<&Value>) -> &'static str {
  match thinking
    .and_then(explicit_thinking_mode)
    .or_else(|| reasoning.and_then(explicit_thinking_mode))
  {
    Some(mode) => mode,
    None if thinking.is_some() || reasoning.is_some() => "enabled",
    None => "disabled",
  }
}

fn explicit_thinking_mode(value: &Value) -> Option<&'static str> {
  match value {
    Value::Bool(true) => Some("enabled"),
    Value::Bool(false) => Some("disabled"),
    Value::String(s) if s.eq_ignore_ascii_case("enabled") => Some("enabled"),
    Value::String(s) if s.eq_ignore_ascii_case("disabled") => Some("disabled"),
    Value::Object(map) => match map.get("type").and_then(Value::as_str) {
      Some("enabled") => Some("enabled"),
      Some("disabled") => Some("disabled"),
      _ => None,
    },
    _ => None,
  }
}

fn extract_effort(value: Option<&Value>) -> Option<String> {
  match value {
    Some(Value::Object(map)) => map.get("effort").and_then(Value::as_str).map(str::to_string),
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::account::AccountTier;
  use tokn_core::provider::Endpoint;

  fn acct(key: Option<&str>) -> AccountConfig {
    AccountConfig {
      id: "test".into(),
      provider: ID_DEEPSEEK.into(),
      enabled: true,
      tier: AccountTier::Active,
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
    let err = DeepSeekProvider::from_account(Arc::new(acct(None))).err().unwrap();
    assert!(err.to_string().contains("api_key"));
  }

  #[test]
  fn constructs_with_default_url() {
    let p = DeepSeekProvider::from_account(Arc::new(acct(Some("sk-test")))).unwrap();
    assert_eq!(p.info().id, ID_DEEPSEEK);
    assert_eq!(p.info().upstream_url, format!("{DEFAULT_BASE_URL}/"));
  }

  #[test]
  fn explicit_target_owns_destination_and_model_cache() {
    let mut account = acct(Some("sk-test"));
    account.base_url = Some("https://ignored.example".into());
    let target = ProviderTarget::parse("https://proxy.example/deepseek", CleartextHttpPolicy::Allow).unwrap();
    let model_cache = Arc::clone(target.model_cache());

    let p = DeepSeekProvider::from_account_at(Arc::new(account), target).unwrap();

    assert_eq!(p.info().upstream_url, "https://proxy.example/deepseek/");
    assert_eq!(
      p.operation_url(&["models"]).unwrap().as_str(),
      "https://proxy.example/deepseek/models"
    );
    assert!(Arc::ptr_eq(&p.info().model_cache, &model_cache));
  }

  #[test]
  fn supports_messages_endpoint() {
    let p = DeepSeekProvider::from_account(Arc::new(acct(Some("sk-test")))).unwrap();
    assert!(p.supports("", crate::Endpoint::ChatCompletions));
    assert!(p.supports("", crate::Endpoint::Messages));
  }

  #[test]
  fn chat_shape_uses_thinking_and_reasoning_effort() {
    let body = json!({
      "model": "deepseek-v4-flash",
      "messages": [{"role": "user", "content": "hi"}],
      "reasoning": {"effort": "high"}
    });

    let out = shape_request(Endpoint::ChatCompletions, body);

    assert_eq!(out.get("thinking"), Some(&json!({"type": "enabled"})));
    assert_eq!(out.get("reasoning_effort"), Some(&json!("high")));
    assert!(out.get("reasoning").is_none());
    assert!(out.get("output_config").is_none());
  }

  #[test]
  fn messages_shape_uses_thinking_and_output_config_effort() {
    let body = json!({
      "model": "deepseek-v4-flash",
      "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
      "thinking": {"effort": "max"}
    });

    let out = shape_request(Endpoint::Messages, body);

    assert_eq!(out.get("thinking"), Some(&json!({"type": "enabled"})));
    assert_eq!(out.get("output_config"), Some(&json!({"effort": "max"})));
    assert!(out.get("reasoning").is_none());
    assert!(out.get("reasoning_effort").is_none());
  }

  #[test]
  fn defaults_thinking_to_disabled_without_reasoning() {
    let body = json!({
      "model": "deepseek-v4-flash",
      "messages": [{"role": "user", "content": "hi"}]
    });

    let out = shape_request(Endpoint::ChatCompletions, body);

    assert_eq!(out.get("thinking"), Some(&json!({"type": "disabled"})));
    assert!(out.get("reasoning_effort").is_none());
  }

  #[test]
  fn messages_url_adds_the_anthropic_prefix() {
    let p = DeepSeekProvider::from_account(Arc::new(acct(Some("sk-test")))).unwrap();
    assert_eq!(
      p.messages_url().unwrap().as_str(),
      "https://api.deepseek.com/anthropic/v1/messages"
    );
  }

  #[test]
  fn messages_url_does_not_duplicate_an_anthropic_prefix() {
    let mut account = acct(Some("sk-test"));
    account.base_url = Some("https://api.deepseek.com/anthropic".into());
    let p = DeepSeekProvider::from_account(Arc::new(account)).unwrap();
    assert_eq!(
      p.messages_url().unwrap().as_str(),
      "https://api.deepseek.com/anthropic/v1/messages"
    );
  }

  fn patch_ctx(endpoint: Endpoint, stream: bool, content_encoding: Option<&'static str>) -> HeaderPatchCtx<'static> {
    HeaderPatchCtx {
      request_kind: ProviderRequestKind::Operation(endpoint),
      body: &Value::Null,
      bearer_token: None,
      content_encoding,
      stream,
      initiator: "user",
      inbound_headers: Box::leak(Box::new(HeaderMap::new())),
      vars: Box::leak(Box::new(TemplateVars::default())),
      agent_id: Box::leak(Box::new(tokn_core::AgentId::Opencode)),
    }
  }

  fn provider() -> DeepSeekProvider {
    DeepSeekProvider::from_account(Arc::new(acct(Some("sk-test-fixture")))).unwrap()
  }

  #[test]
  fn deepseek_patch_headers_chat_streaming() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::ChatCompletions, true, None))
      .unwrap();
    assert_eq!(h.get("authorization").unwrap().as_str(), "Bearer sk-test-fixture");
    assert_eq!(h.get("accept").unwrap().as_str(), "text/event-stream");
    assert_eq!(h.get("content-type").unwrap().as_str(), "application/json");
    assert!(h.get("content-encoding").is_none());
    let names: Vec<_> = h.iter().map(|(n, _)| n.as_str().to_string()).collect();
    assert_eq!(names.len(), 3, "unexpected extra headers: {names:?}");
  }

  #[test]
  fn deepseek_patch_headers_chat_non_streaming() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::ChatCompletions, false, None))
      .unwrap();
    assert_eq!(h.get("authorization").unwrap().as_str(), "Bearer sk-test-fixture");
    assert_eq!(h.get("accept").unwrap().as_str(), "application/json");
    assert_eq!(h.get("content-type").unwrap().as_str(), "application/json");
    assert!(h.get("content-encoding").is_none());
  }

  #[test]
  fn deepseek_patch_headers_messages_streaming_matches_chat_shape() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::Messages, true, None))
      .unwrap();
    assert_eq!(h.get("authorization").unwrap().as_str(), "Bearer sk-test-fixture");
    assert_eq!(h.get("accept").unwrap().as_str(), "text/event-stream");
    assert_eq!(h.get("content-type").unwrap().as_str(), "application/json");
  }

  #[test]
  fn deepseek_patch_headers_round_trips_content_encoding() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::ChatCompletions, false, Some("gzip")))
      .unwrap();
    assert_eq!(h.get("content-encoding").unwrap().as_str(), "gzip");
  }
}

use crate::common::{self, Credential};
use async_trait::async_trait;
use reqwest::Method;
use serde_json::Value;
use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::pipeline::InputTransformer;
use tokn_core::provider::ProviderTarget;
use tokn_core::upstream_url::CleartextHttpPolicy;
use tokn_headers::HeaderMap;
use tracing::{debug, instrument, warn};

use crate::{
  error, AuthKind, Endpoint, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx, Result,
  TemplateVars, ID_CODEX,
};

pub const CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
pub const CODEX_CLIENT_VERSION: &str = "0.130.0";
const CODEX_MODELS_PATH: &str = "/models?client_version=0.130.0";

pub struct CodexProvider {
  pub id: String,
  credential: Credential,
  target: ProviderTarget,
  provider_account_id: Option<String>,
  info: ProviderInfo,
}

impl CodexProvider {
  pub fn from_account(a: Arc<AccountConfig>) -> Result<Self> {
    let base_url = a.base_url.as_deref().unwrap_or(CODEX_BASE_URL);
    let target = ProviderTarget::parse(base_url, CleartextHttpPolicy::Allow).map_err(|source| {
      error::Error::InvalidUpstreamUrl {
        account: a.id.clone(),
        source,
      }
    })?;
    Self::from_account_at(a, target)
  }

  pub fn from_account_at(a: Arc<AccountConfig>, target: ProviderTarget) -> Result<Self> {
    validate(a.as_ref())?;
    let credential = Credential::AccessToken(
      a.access_token
        .clone()
        .or_else(|| a.api_key.clone())
        .expect("validated access token"),
    );
    let upstream_url = target.base_url().to_string();
    let model_cache = target.model_cache().clone();
    Ok(Self {
      id: format!("{}:{}", a.provider, a.id),
      credential,
      target,
      provider_account_id: a.provider_account_id.clone(),
      info: ProviderInfo {
        id: a.provider.clone(),
        aliases: &[],
        display_name: "ChatGPT Codex",
        upstream_url,
        auth_kind: AuthKind::OAuthDeviceFlow,
        default_models: crate::catalogue::default_models_for(crate::ID_OPENAI),
        default_endpoints: crate::DEFAULT_ENDPOINTS_CODEX,
        model_cache,
      },
    })
  }

  fn url(&self, path: &str) -> String {
    common::url(self.target.base_url().as_str(), path)
  }

  async fn upstream_post(&self, ctx: RequestCtx<'_>, path: &str, what: &'static str) -> Result<reqwest::Response> {
    let url = self.url(path);
    debug!(%url, "POST upstream");
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
    crate::util::http::send(
      ctx.http,
      Method::POST,
      &url,
      headers,
      Some(body_bytes),
      ctx.outbound.as_ref(),
      what,
    )
    .await
  }
}

impl InputTransformer for CodexProvider {
  fn transform_input(&self, endpoint: Endpoint, mut body: Value) -> Result<Value> {
    if endpoint == Endpoint::Responses {
      if let Some(obj) = body.as_object_mut() {
        obj.remove("max_output_tokens");
        obj.insert("store".into(), Value::Bool(false));
        obj.insert("stream".into(), Value::Bool(true));
        normalize_verbosity(obj);
        if let Some(input) = obj.get_mut("input") {
          normalize_codex_input(input);
        }
        if !obj.get("instructions").map(Value::is_string).unwrap_or(false) {
          obj.insert("instructions".into(), Value::String(String::new()));
        }
        normalize_reasoning_effort(obj);
      }
    }
    Ok(body)
  }
}

fn normalize_reasoning_effort(obj: &mut serde_json::Map<String, Value>) {
  let Some(effort) = obj
    .remove("reasoning_effort")
    .and_then(|v| v.as_str().map(str::to_string))
  else {
    return;
  };

  match obj.get_mut("reasoning") {
    Some(Value::Object(reasoning)) => {
      reasoning.entry("effort").or_insert_with(|| Value::String(effort));
    }
    Some(_) => {}
    None => {
      obj.insert("reasoning".into(), serde_json::json!({ "effort": effort }));
    }
  }
}

fn normalize_verbosity(obj: &mut serde_json::Map<String, Value>) {
  let Some(verbosity) = obj.remove("verbosity") else {
    return;
  };

  match obj.get_mut("text") {
    Some(Value::Object(text)) => {
      text.entry("verbosity").or_insert(verbosity);
    }
    Some(_) => {}
    None => {
      obj.insert("text".into(), serde_json::json!({ "verbosity": verbosity }));
    }
  }
}

fn normalize_codex_input(input: &mut Value) {
  let replacement = match input.clone() {
    Value::Array(_) => return,
    Value::String(text) => {
      serde_json::json!([{"role": "user", "content": [{"type": "input_text", "text": text.clone()}]}])
    }
    Value::Null => Value::Array(Vec::new()),
    other => Value::Array(vec![other]),
  };
  *input = replacement;
}

pub fn validate(account: &AccountConfig) -> Result<()> {
  if account.provider != ID_CODEX {
    return error::ProviderMismatchSnafu {
      expected: ID_CODEX,
      got: account.provider.clone(),
    }
    .fail();
  }
  let _ = account
    .access_token
    .clone()
    .or_else(|| account.api_key.clone())
    .filter(|s| !s.expose().trim().is_empty())
    .ok_or(error::Error::MissingCredential {
      account: account.id.clone(),
      what: "access_token",
    })?;
  Ok(())
}

pub fn build(account: Arc<AccountConfig>) -> Result<Arc<dyn Provider>> {
  Ok(Arc::new(CodexProvider::from_account(account)?))
}

#[async_trait]
impl Provider for CodexProvider {
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
    common::inject_codex_credentials(headers, self.credential.expose(), self.provider_account_id.as_deref());
    Ok(())
  }

  fn normalize_headers(&self, headers: &mut HeaderMap, ctx: &HeaderPatchCtx<'_>) -> Result<Option<HeaderMap>> {
    Ok(Some(common::normalize_codex_headers(headers, ctx)))
  }

  async fn list_models(&self, http: &reqwest::Client) -> Result<Value> {
    let headers = self.models_headers()?;
    let resp = crate::util::http::send(
      http,
      Method::GET,
      &self.url(CODEX_MODELS_PATH),
      headers,
      None,
      None,
      "codex /models",
    )
    .await?;
    let value: Value = crate::util::http::read_json(resp, "codex /models").await?;
    Ok(normalize_models_response(value))
  }

  #[instrument(name = "codex_responses", skip_all, fields(account = %self.id, stream = ctx.stream))]
  async fn responses(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    self.upstream_post(ctx, "/responses", "codex responses").await
  }

  async fn chat(&self, _ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    error::UnsupportedEndpointSnafu {
      provider: self.info.id.clone(),
      endpoint: "/v1/chat/completions",
    }
    .fail()
  }

  fn on_unauthorized(&self) {
    warn!(account = %self.id, "codex upstream returned 401: credential likely revoked or expired");
  }
}

impl CodexProvider {
  fn models_headers(&self) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    self.patch_headers(
      &mut headers,
      &HeaderPatchCtx {
        request_kind: ProviderRequestKind::Operation(Endpoint::Responses),
        body: &Value::Null,
        bearer_token: None,
        content_encoding: None,
        stream: false,
        initiator: "user",
        inbound_headers: &HeaderMap::new(),
        vars: &TemplateVars::default(),
        agent_id: &tokn_core::AgentId::CodexCli,
      },
    )?;
    Ok(headers)
  }
}

fn normalize_models_response(value: Value) -> Value {
  if value.get("data").and_then(|v| v.as_array()).is_some() {
    return value;
  }
  let models = find_models_array(&value).cloned().unwrap_or_default();
  let data = models.into_iter().filter_map(normalize_model_entry).collect::<Vec<_>>();
  serde_json::json!({ "object": "list", "data": data })
}

fn find_models_array(value: &Value) -> Option<&Vec<Value>> {
  if let Some(arr) = value.as_array() {
    return Some(arr);
  }
  if let Some(arr) = value.get("models").and_then(|v| v.as_array()) {
    return Some(arr);
  }
  value
    .as_object()
    .and_then(|obj| obj.values().find_map(|v| v.get("models").and_then(|m| m.as_array())))
}

fn normalize_model_entry(entry: Value) -> Option<Value> {
  if let Some(id) = entry.as_str().filter(|id| !id.trim().is_empty()) {
    return Some(serde_json::json!({ "id": id, "object": "model" }));
  }
  let obj = entry.as_object()?;
  let id = ["id", "model", "slug", "name"]
    .iter()
    .find_map(|key| obj.get(*key).and_then(|v| v.as_str()))?
    .trim();
  if id.is_empty() {
    return None;
  }
  Some(serde_json::json!({
    "id": id,
    "object": "model",
    "x_codex": entry,
  }))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::util::secret::Secret;
  use tokn_core::account::AccountTier;

  fn acct(access: Option<&str>) -> AccountConfig {
    AccountConfig {
      id: "test".into(),
      provider: ID_CODEX.into(),
      enabled: true,
      tier: AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: None,
      username: None,
      api_key: None,
      api_key_expires_at: None,
      access_token: access.map(|s| Secret::new(s.into())),
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

  fn patch_ctx() -> HeaderPatchCtx<'static> {
    HeaderPatchCtx {
      request_kind: ProviderRequestKind::Operation(Endpoint::Responses),
      body: &Value::Null,
      bearer_token: None,
      content_encoding: None,
      stream: false,
      initiator: "user",
      inbound_headers: Box::leak(Box::new(HeaderMap::new())),
      vars: Box::leak(Box::new(TemplateVars::default())),
      agent_id: Box::leak(Box::new(tokn_core::AgentId::Opencode)),
    }
  }

  fn request_body() -> Value {
    serde_json::json!({
      "model": "gpt-5.4-mini",
      "input": [{"role": "user", "content": "hi"}],
      "max_output_tokens": 1024,
    })
  }

  #[test]
  fn codex_requires_access_token() {
    let err = CodexProvider::from_account(Arc::new(acct(None))).err().unwrap();
    assert!(err.to_string().contains("access_token"));
  }

  #[test]
  fn codex_patch_headers_injects_account_id_when_present() {
    let mut a = acct(Some("atk-test"));
    a.provider_account_id = Some("acc-77".into());
    let codex = CodexProvider::from_account(Arc::new(a)).unwrap();
    let mut h = HeaderMap::new();
    h.insert("originator", "Codex Desktop");
    h.insert("session_id", "sess-1");
    h.insert("x-api-key", "wrong");
    codex.patch_headers(&mut h, &patch_ctx()).unwrap();
    assert_eq!(h.get("authorization").unwrap().as_str(), "Bearer atk-test");
    assert_eq!(h.get("accept").unwrap().as_str(), "application/json");
    assert_eq!(h.get("content-type").unwrap().as_str(), "application/json");
    assert_eq!(h.get("OpenAI-Beta").unwrap().as_str(), "responses=experimental");
    assert_eq!(h.get("originator").unwrap().as_str(), "opencode");
    assert!(h.get("version").is_none());
    assert_eq!(
      h.get("user-agent").unwrap().as_str(),
      "opencode/1.14.28 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13"
    );
    assert_eq!(h.get("session_id").unwrap().as_str(), "sess-1");
    assert_eq!(h.get("x-session-affinity").unwrap().as_str(), "sess-1");
    assert_eq!(h.get("chatgpt-account-id").unwrap().as_str(), "acc-77");
    assert!(h.get("x-api-key").is_none());
  }

  #[test]
  fn codex_patch_headers_defaults_originator_and_stream_accept() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut h = HeaderMap::new();
    let mut ctx = patch_ctx();
    ctx.stream = true;
    codex.patch_headers(&mut h, &ctx).unwrap();
    assert_eq!(h.get("accept").unwrap().as_str(), "text/event-stream");
    assert_eq!(h.get("originator").unwrap().as_str(), "opencode");
    assert_eq!(
      h.get("user-agent").unwrap().as_str(),
      "opencode/1.14.28 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13"
    );
    assert_eq!(h.get("OpenAI-Beta").unwrap().as_str(), "responses=experimental");
  }

  #[test]
  fn codex_patch_headers_omits_account_id_when_absent_or_blank() {
    for blank in [None, Some(String::new())] {
      let mut a = acct(Some("atk-test"));
      a.provider_account_id = blank;
      let codex = CodexProvider::from_account(Arc::new(a)).unwrap();
      let mut h = HeaderMap::new();
      codex.patch_headers(&mut h, &patch_ctx()).unwrap();
      assert!(h.get("chatgpt-account-id").is_none());
    }
  }

  #[test]
  fn codex_constructs() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    assert_eq!(codex.info().upstream_url, format!("{CODEX_BASE_URL}/"));
    assert!(codex.supports("", Endpoint::Responses));
    assert!(!codex.supports("", Endpoint::ChatCompletions));
  }

  #[test]
  fn codex_target_overrides_legacy_account_url_and_shares_cache() {
    let mut account = acct(Some("atk-test"));
    account.base_url = Some("https://ignored.example/codex".into());
    let target = ProviderTarget::parse(
      "https://gateway.example/backend-api/codex",
      CleartextHttpPolicy::LoopbackOnly,
    )
    .unwrap();
    let target_cache = target.model_cache().clone();

    let codex = CodexProvider::from_account_at(Arc::new(account), target).unwrap();

    assert_eq!(
      codex.url(CODEX_MODELS_PATH),
      "https://gateway.example/backend-api/codex/models?client_version=0.130.0"
    );
    assert_eq!(codex.info().upstream_url, "https://gateway.example/backend-api/codex/");
    assert!(Arc::ptr_eq(&codex.info().model_cache, &target_cache));
  }

  #[test]
  fn codex_legacy_constructor_reports_invalid_account_url() {
    let mut account = acct(Some("atk-test"));
    account.base_url = Some("not-a-url".into());

    let err = CodexProvider::from_account(Arc::new(account)).err().unwrap();

    assert!(matches!(
      err,
      error::Error::InvalidUpstreamUrl { account, .. } if account == "test"
    ));
  }

  #[test]
  fn codex_transform_removes_max_output_tokens_and_adds_instructions() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let out = codex.transform_input(Endpoint::Responses, request_body()).unwrap();

    assert!(out.get("max_output_tokens").is_none());
    assert_eq!(out.get("instructions").and_then(Value::as_str), Some(""));
  }

  #[test]
  fn codex_transform_preserves_existing_instructions() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut body = request_body();
    body["instructions"] = Value::String("be terse".into());

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert_eq!(out.get("instructions").and_then(Value::as_str), Some("be terse"));
  }

  #[test]
  fn codex_transform_forces_store_false() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut body = request_body();
    body["store"] = Value::Bool(true);

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert_eq!(out.get("store"), Some(&Value::Bool(false)));
  }

  #[test]
  fn codex_transform_forces_stream_true() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut body = request_body();
    body["stream"] = Value::Bool(false);

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert_eq!(out.get("stream"), Some(&Value::Bool(true)));
  }

  #[test]
  fn codex_transform_moves_top_level_verbosity_into_text() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut body = request_body();
    body["verbosity"] = Value::String("low".into());

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert!(out.get("verbosity").is_none());
    assert_eq!(out.get("text"), Some(&serde_json::json!({ "verbosity": "low" })));
  }

  #[test]
  fn codex_transform_preserves_existing_text_verbosity() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut body = request_body();
    body["verbosity"] = Value::String("low".into());
    body["text"] = serde_json::json!({ "verbosity": "high", "format": { "type": "text" } });

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert!(out.get("verbosity").is_none());
    assert_eq!(
      out.get("text"),
      Some(&serde_json::json!({ "verbosity": "high", "format": { "type": "text" } }))
    );
  }

  #[test]
  fn codex_transform_promotes_reasoning_effort_into_reasoning() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut body = request_body();
    body["reasoning_effort"] = Value::String("high".into());

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert!(out.get("reasoning_effort").is_none());
    assert_eq!(out.get("reasoning"), Some(&serde_json::json!({ "effort": "high" })));
  }

  #[test]
  fn codex_transform_preserves_existing_reasoning_effort_field() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let mut body = request_body();
    body["reasoning_effort"] = Value::String("high".into());
    body["reasoning"] = serde_json::json!({ "effort": "low", "summary": "auto" });

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert!(out.get("reasoning_effort").is_none());
    assert_eq!(
      out.get("reasoning"),
      Some(&serde_json::json!({ "effort": "low", "summary": "auto" }))
    );
  }

  #[test]
  fn codex_transform_wraps_single_input_object() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let body = serde_json::json!({
      "model": "gpt-5.4-mini",
      "input": {"role": "user", "content": "hi"}
    });

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert_eq!(out["input"], serde_json::json!([{"role": "user", "content": "hi"}]));
  }

  #[test]
  fn codex_transform_wraps_string_input_as_user_message() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    let body = serde_json::json!({
      "model": "gpt-5.4-mini",
      "input": "hi"
    });

    let out = codex.transform_input(Endpoint::Responses, body).unwrap();

    assert_eq!(
      out["input"],
      serde_json::json!([
        {"role": "user", "content": [{"type": "input_text", "text": "hi"}]}
      ])
    );
  }

  #[test]
  fn codex_models_url_uses_backend_api_path() {
    let codex = CodexProvider::from_account(Arc::new(acct(Some("atk-test")))).unwrap();
    assert_eq!(codex.url("/models"), "https://chatgpt.com/backend-api/codex/models");
    assert_eq!(
      codex.url(CODEX_MODELS_PATH),
      "https://chatgpt.com/backend-api/codex/models?client_version=0.130.0"
    );
  }

  #[test]
  fn normalizes_models_array_response() {
    let out = normalize_models_response(serde_json::json!({ "models": [{ "slug": "gpt-5" }, "o3"] }));
    let data = out.get("data").and_then(|v| v.as_array()).unwrap();
    assert_eq!(data[0].get("id").and_then(|v| v.as_str()), Some("gpt-5"));
    assert_eq!(data[1].get("id").and_then(|v| v.as_str()), Some("o3"));
  }

  #[test]
  fn normalizes_nested_models_array_response() {
    let out = normalize_models_response(serde_json::json!({ "app": { "models": [{ "model": "codex-mini" }] } }));
    let data = out.get("data").and_then(|v| v.as_array()).unwrap();
    assert_eq!(data[0].get("id").and_then(|v| v.as_str()), Some("codex-mini"));
  }

  #[test]
  fn leaves_openai_data_response_unchanged() {
    let input = serde_json::json!({ "object": "list", "data": [{ "id": "x" }] });
    assert_eq!(normalize_models_response(input.clone()), input);
  }
}

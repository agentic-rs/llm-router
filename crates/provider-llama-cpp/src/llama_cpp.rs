use crate::util::secret::Secret;
use async_trait::async_trait;
use reqwest::Method;
use serde_json::Value;
use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::provider::ProviderTarget;
use tokn_core::upstream_url::CleartextHttpPolicy;
use tokn_headers::keys::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use tokn_headers::{HeaderMap, HeaderValue};
use tracing::{debug, instrument, warn};

use crate::{
  error, AuthKind, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx, Result, TemplateVars,
  ID_LLAMA_CPP,
};

pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080/v1";

pub struct LlamaCppProvider {
  pub id: String,
  api_key: Option<Secret<String>>,
  target: ProviderTarget,
  info: ProviderInfo,
}

impl LlamaCppProvider {
  pub fn validate_account(a: &AccountConfig) -> Result<()> {
    if a.provider != ID_LLAMA_CPP {
      return error::ProviderMismatchSnafu {
        expected: ID_LLAMA_CPP,
        got: a.provider.clone(),
      }
      .fail();
    }
    if let Some(key) = &a.api_key {
      if key.expose().trim().is_empty() {
        return Err(error::Error::MissingCredential {
          account: a.id.clone(),
          what: "api_key",
        });
      }
    }
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
    let api_key = a.api_key.clone();
    let upstream_url = target.base_url().to_string();
    let model_cache = target.model_cache().clone();
    Ok(Self {
      id: format!("{}:{}", a.provider, a.id),
      api_key: api_key.clone(),
      target,
      info: ProviderInfo {
        id: ID_LLAMA_CPP.to_string(),
        aliases: &[ID_LLAMA_CPP],
        display_name: "llama.cpp",
        upstream_url,
        auth_kind: if api_key.is_some() {
          AuthKind::StaticApiKey
        } else {
          AuthKind::None
        },
        default_models: crate::catalogue::default_models_for(ID_LLAMA_CPP),
        default_endpoints: crate::DEFAULT_ENDPOINTS,
        model_cache,
      },
    })
  }

  fn operation_url(&self, segments: &[&str]) -> Result<reqwest::Url> {
    Ok(self.target.base_url().operation_url(segments.iter().copied())?)
  }
}

#[async_trait]
impl Provider for LlamaCppProvider {
  fn id(&self) -> &str {
    &self.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  fn has_model(&self, model: &str) -> bool {
    if model.is_empty() {
      return true;
    }
    if self.info.model_cache.is_warm() {
      return self.info.model_cache.contains(model);
    }
    self.info.default_models.is_empty() || self.info.default_models.iter().any(|m| m.id == model)
  }

  fn inject_credentials(&self, headers: &mut HeaderMap, _ctx: &HeaderPatchCtx<'_>) -> Result<()> {
    if let Some(key) = &self.api_key {
      headers.insert(
        &AUTHORIZATION,
        HeaderValue::from_string(format!("Bearer {}", key.expose())),
      );
    }
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
    debug!(%url, "GET llama.cpp models");
    let resp = crate::util::http::send(
      http,
      Method::GET,
      url.as_str(),
      headers,
      None,
      None,
      "llama.cpp /models",
    )
    .await?;
    crate::util::http::read_json(resp, "llama.cpp /models").await
  }

  #[instrument(name = "llama_cpp_chat", skip_all, fields(account = %self.id, stream = ctx.stream))]
  async fn chat(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    let url = crate::operation_url(&self.target, ctx.endpoint)?;
    debug!(%url, "POST llama.cpp chat");
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
      url.as_str(),
      headers,
      Some(body_bytes),
      ctx.outbound.as_ref(),
      "llama.cpp chat",
    )
    .await
  }

  fn on_unauthorized(&self) {
    warn!(account = %self.id, "llama.cpp upstream returned 401: api_key may be missing or invalid");
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Endpoint;
  use tokn_core::account::AccountTier;
  use tokn_mock_server::{HeaderExpectation, MockAuthConfig, MockLlmConfig, MockLlmServer, MockRoute};

  fn acct(key: Option<&str>) -> AccountConfig {
    AccountConfig {
      id: "test".into(),
      provider: ID_LLAMA_CPP.into(),
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

  fn patch_ctx() -> HeaderPatchCtx<'static> {
    HeaderPatchCtx {
      request_kind: ProviderRequestKind::Operation(Endpoint::ChatCompletions),
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

  #[test]
  fn constructs_without_api_key() {
    let provider = LlamaCppProvider::from_account(Arc::new(acct(None))).unwrap();
    assert_eq!(provider.info().id, ID_LLAMA_CPP);
    assert_eq!(provider.info().upstream_url, format!("{DEFAULT_BASE_URL}/"));
    assert_eq!(provider.info().auth_kind, AuthKind::None);
    assert!(provider.supports("local-model", Endpoint::ChatCompletions));
  }

  #[test]
  fn target_overrides_legacy_account_url_and_owns_the_model_cache() {
    let mut account = acct(None);
    account.base_url = Some("https://ignored.example/v1".into());
    let target = ProviderTarget::parse("https://selected.example/api/v1", CleartextHttpPolicy::Allow).unwrap();
    let expected_cache = target.model_cache().clone();

    let provider = LlamaCppProvider::from_account_at(Arc::new(account), target).unwrap();

    assert_eq!(provider.info().upstream_url, "https://selected.example/api/v1/");
    assert_eq!(
      provider.operation_url(&["models"]).unwrap().as_str(),
      "https://selected.example/api/v1/models"
    );
    assert!(Arc::ptr_eq(&provider.info().model_cache, &expected_cache));
  }

  #[test]
  fn legacy_constructor_reports_invalid_account_url() {
    let mut account = acct(None);
    account.base_url = Some("not a URL".into());

    let error = LlamaCppProvider::from_account(Arc::new(account)).err().unwrap();

    assert!(matches!(
      error,
      error::Error::InvalidUpstreamUrl { ref account, .. } if account == "test"
    ));
  }

  #[test]
  fn rejects_blank_api_key() {
    let err = LlamaCppProvider::from_account(Arc::new(acct(Some("   "))))
      .err()
      .unwrap();
    assert!(err.to_string().contains("api_key"));
  }

  #[test]
  fn patch_headers_omits_authorization_without_api_key() {
    let provider = LlamaCppProvider::from_account(Arc::new(acct(None))).unwrap();
    let mut headers = HeaderMap::new();
    provider.patch_headers(&mut headers, &patch_ctx()).unwrap();
    assert!(headers.get("authorization").is_none());
    assert_eq!(headers.get("accept").map(|v| v.as_str()), Some("application/json"));
  }

  #[test]
  fn patch_headers_sets_authorization_with_api_key() {
    let provider = LlamaCppProvider::from_account(Arc::new(acct(Some("sk-test")))).unwrap();
    let mut headers = HeaderMap::new();
    provider.patch_headers(&mut headers, &patch_ctx()).unwrap();
    assert_eq!(headers.get("authorization").map(|v| v.as_str()), Some("Bearer sk-test"));
    assert_eq!(provider.info().auth_kind, AuthKind::StaticApiKey);
  }

  #[tokio::test]
  async fn list_models_works_with_mock_server() {
    let server = MockLlmServer::start(MockLlmConfig {
      routes: vec![MockRoute::models(["local-model"])],
      ..Default::default()
    })
    .await;

    let mut account = acct(None);
    account.base_url = Some(server.base_url().to_string());
    let provider = LlamaCppProvider::from_account(Arc::new(account)).unwrap();

    let models = provider.list_models(&reqwest::Client::new()).await.unwrap();
    let ids: Vec<&str> = models["data"]
      .as_array()
      .unwrap()
      .iter()
      .filter_map(|model| model["id"].as_str())
      .collect();

    assert_eq!(ids, vec!["local-model"]);
    let captured = server.last_request().expect("captured models request");
    assert_eq!(captured.method, reqwest::Method::GET);
    assert_eq!(captured.path, "/models");
    assert_eq!(captured.header("authorization"), None);
  }

  #[tokio::test]
  async fn chat_works_with_optional_api_key() {
    let server = MockLlmServer::start(
      MockLlmConfig {
        routes: vec![MockRoute::chat_completions()],
        ..Default::default()
      }
      .with_auth(MockAuthConfig::bearer(["sk-test"]))
      .require_header(HeaderExpectation::equals("accept", "application/json")),
    )
    .await;

    let mut account = acct(Some("sk-test"));
    account.base_url = Some(server.base_url().to_string());
    let provider = LlamaCppProvider::from_account(Arc::new(account)).unwrap();

    let http = reqwest::Client::new();
    let body = serde_json::json!({
      "model": "local-model",
      "messages": [{"role": "user", "content": "hi"}]
    });
    let inbound = HeaderMap::new();
    let response = provider
      .chat(RequestCtx {
        endpoint: Endpoint::ChatCompletions,
        http: &http,
        body: &body,
        body_bytes: None,
        content_encoding: None,
        stream: false,
        initiator: "user",
        inbound_headers: &inbound,
        client_headers: None,
        outbound: None,
        vars: TemplateVars::default(),
        agent_id: tokn_core::AgentId::Opencode,
      })
      .await
      .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let captured = server.last_request().expect("captured chat request");
    assert_eq!(captured.method, reqwest::Method::POST);
    assert_eq!(captured.path, "/chat/completions");
    assert_eq!(captured.header("authorization"), Some("Bearer sk-test"));
  }

  #[tokio::test]
  #[ignore = "requires LLAMA_CPP_LIVE_BASE_URL"]
  async fn live_server_lists_models_and_accepts_chat() {
    let base_url = std::env::var("LLAMA_CPP_LIVE_BASE_URL").expect("LLAMA_CPP_LIVE_BASE_URL must be set");
    let mut account = acct(None);
    account.base_url = Some(base_url);
    let provider = LlamaCppProvider::from_account(Arc::new(account)).unwrap();
    let http = reqwest::Client::new();

    let models = provider.list_models(&http).await.unwrap();
    let model = models["data"]
      .as_array()
      .and_then(|models| models.first())
      .and_then(|model| model["id"].as_str())
      .expect("live llama.cpp server should expose at least one model");

    let body = serde_json::json!({
      "model": model,
      "messages": [{"role": "user", "content": "Reply with exactly: llama live ok"}],
      "stream": false,
      "max_tokens": 16,
      "temperature": 0
    });
    let inbound = HeaderMap::new();
    let response = provider
      .chat(RequestCtx {
        endpoint: Endpoint::ChatCompletions,
        http: &http,
        body: &body,
        body_bytes: None,
        content_encoding: None,
        stream: false,
        initiator: "user",
        inbound_headers: &inbound,
        client_headers: None,
        outbound: None,
        vars: TemplateVars::default(),
        agent_id: tokn_core::AgentId::Opencode,
      })
      .await
      .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let payload: Value = response.json().await.unwrap();
    assert!(payload["choices"].as_array().is_some_and(|choices| !choices.is_empty()));
    assert_eq!(payload["model"].as_str(), Some(model));
  }
}

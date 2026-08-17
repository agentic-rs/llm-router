//! GitHub Copilot provider.

pub use crate::{headers, models, oauth, token, user};

use crate::config::{CopilotHeaders, InitiatorMode};
use crate::util::secret::Secret;
use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::Method;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tokn_core::account::AccountConfig;
use tokn_core::pipeline::InputTransformer;
use tokn_core::provider::ProviderTarget;
use tokn_core::upstream_url::CleartextHttpPolicy;
use tokn_headers::keys::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use tokn_headers::{HeaderMap, HeaderName, HeaderValue};
use tracing::{debug, instrument};

use crate::{
  error, AuthKind, Endpoint, EndpointRule, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx,
  Result, ID_GITHUB_COPILOT,
};

#[allow(dead_code)]
pub const GITHUB_API: &str = "https://api.github.com";
pub const COPILOT_API: &str = "https://api.githubcopilot.com";
/// Cached short-lived API token state.
struct ApiToken {
  token: Option<Secret<String>>,
  expires_at: Option<i64>,
}

pub struct CopilotProvider {
  #[allow(dead_code)]
  pub id: String,
  pub refresh_token: Secret<String>,
  pub headers: CopilotHeaders,
  refresh_lock: AsyncMutex<()>,
  cache: RwLock<ApiToken>,
  target: ProviderTarget,
  info: ProviderInfo,
}

impl CopilotProvider {
  pub fn validate_account(a: &AccountConfig) -> Result<()> {
    let _ = a.refresh_token.clone().ok_or(error::Error::MissingCredential {
      account: a.id.clone(),
      what: "refresh_token",
    })?;
    let headers = headers_from_settings(a)?;
    headers.validate()?;
    Ok(())
  }

  pub fn from_account(a: Arc<AccountConfig>) -> Result<Self> {
    Self::validate_account(&a)?;
    let base_url = a.base_url.as_deref().unwrap_or(COPILOT_API);
    let target = ProviderTarget::parse(base_url, CleartextHttpPolicy::Allow).map_err(|source| {
      error::Error::InvalidUpstreamUrl {
        account: a.id.clone(),
        source,
      }
    })?;
    Self::from_validated_account_at(a, target)
  }

  pub fn from_account_at(a: Arc<AccountConfig>, target: ProviderTarget) -> Result<Self> {
    Self::validate_account(&a)?;
    Self::from_validated_account_at(a, target)
  }

  fn from_validated_account_at(a: Arc<AccountConfig>, target: ProviderTarget) -> Result<Self> {
    let gh = a.refresh_token.clone().expect("validated refresh_token");
    let headers = headers_from_settings(&a)?;
    let upstream_url = target.base_url().to_string();
    let model_cache = target.model_cache().clone();
    Ok(Self {
      id: format!("github-copilot:{}", a.id),
      refresh_token: gh,
      headers,
      refresh_lock: AsyncMutex::new(()),
      cache: RwLock::new(ApiToken {
        token: a.access_token.clone(),
        expires_at: a.access_token_expires_at,
      }),
      target,
      info: ProviderInfo {
        id: ID_GITHUB_COPILOT.to_string(),
        aliases: &[ID_GITHUB_COPILOT],
        display_name: "GitHub Copilot",
        upstream_url,
        auth_kind: AuthKind::OAuthDeviceFlow,
        // Copilot's `/models` upstream is the source of truth for model
        // *identity*; the catalogue below provides metadata overlay for the
        // ids that models.dev tracks. Unknown ids still pass through
        // `/v1/models` — they just lack the `x_tokn_router` enrichment block.
        default_models: crate::catalogue::default_models_for(ID_GITHUB_COPILOT),
        default_endpoints: crate::DEFAULT_ENDPOINTS,
        model_cache,
      },
    })
  }

  fn snapshot(&self) -> (Option<Secret<String>>, Option<i64>) {
    let g = self.cache.read();
    (g.token.clone(), g.expires_at)
  }

  /// Ensure we have a non-expired Copilot API token; refresh if needed.
  #[instrument(name = "ensure_api_token", skip_all, fields(account = %self.id, refreshed = tracing::field::Empty, fp = tracing::field::Empty))]
  pub async fn ensure_api_token(&self, http: &reqwest::Client) -> Result<Secret<String>> {
    const SKEW_SECS: i64 = 300;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if let (Some(tok), Some(exp)) = self.snapshot() {
      if exp - SKEW_SECS > now {
        let span = tracing::Span::current();
        span.record("refreshed", false);
        span.record("fp", tracing::field::display(tok.fingerprint()));
        return Ok(tok);
      }
    }
    let _g = self.refresh_lock.lock().await;
    if let (Some(tok), Some(exp)) = self.snapshot() {
      if exp - SKEW_SECS > now {
        let span = tracing::Span::current();
        span.record("refreshed", false);
        span.record("fp", tracing::field::display(tok.fingerprint()));
        return Ok(tok);
      }
    }
    debug!("api token expired or missing; refreshing");
    let resp = token::exchange(http, self.refresh_token.expose(), &self.headers).await?;
    let token = Secret::new(resp.token);
    {
      let mut g = self.cache.write();
      g.token = Some(token.clone());
      g.expires_at = Some(resp.expires_at);
    }
    let span = tracing::Span::current();
    span.record("refreshed", true);
    span.record("fp", tracing::field::display(token.fingerprint()));
    Ok(token)
  }

  fn invalidate_api_token(&self) {
    debug!(account = %self.id, "invalidating cached copilot api token");
    let mut g = self.cache.write();
    g.token = None;
    g.expires_at = None;
  }

  /// Resolve the X-Initiator value to send.
  /// Precedence: inbound `X-Initiator` header > config mode > auto-classify.
  fn resolve_initiator(&self, body: &Value, inbound: &HeaderMap, fallback: &str) -> String {
    if let Some(v) = inbound.get("x-initiator") {
      let v = v.as_str().trim().to_ascii_lowercase();
      if v == "user" || v == "agent" {
        return v;
      }
    }
    match self.headers.initiator_mode {
      InitiatorMode::AlwaysUser => "user".into(),
      InitiatorMode::AlwaysAgent => "agent".into(),
      InitiatorMode::Auto => {
        // If caller already classified, trust it.
        if fallback == "user" || fallback == "agent" {
          return fallback.into();
        }
        crate::util::initiator::classify_initiator(body)
          .unwrap_or("user")
          .into()
      }
    }
  }
}

impl InputTransformer for CopilotProvider {
  fn transform_input(&self, _endpoint: Endpoint, body: Value) -> Result<Value> {
    Ok(body)
  }
}

#[async_trait]
impl Provider for CopilotProvider {
  fn id(&self) -> &str {
    &self.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  fn input_transformer(&self) -> Option<&dyn InputTransformer> {
    Some(self)
  }

  fn endpoint_rules(&self) -> Option<&'static [EndpointRule]> {
    crate::DESCRIPTOR.model_endpoint_rules
  }

  fn inject_credentials(&self, headers: &mut HeaderMap, ctx: &HeaderPatchCtx<'_>) -> Result<()> {
    let token = ctx.bearer_token.ok_or_else(|| error::Error::Profiles {
      message: "missing copilot bearer token for header patch".to_string(),
    })?;
    headers.insert(&AUTHORIZATION, HeaderValue::from_string(format!("Bearer {token}")));
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
    headers.insert(
      HeaderName::new("x-initiator"),
      HeaderValue::from_string(ctx.initiator.to_string()),
    );
    if let Some(encoding) = ctx.content_encoding {
      headers.insert(&CONTENT_ENCODING, HeaderValue::from_string(encoding.to_string()));
    }
    Ok(None)
  }

  async fn list_models(&self, http: &reqwest::Client) -> Result<Value> {
    let token = self.ensure_api_token(http).await?;
    models::list(http, self.target.base_url(), token.expose(), &self.headers).await
  }

  async fn chat(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    self.upstream_post(ctx, "chat").await
  }

  async fn responses(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    self.upstream_post(ctx, "responses").await
  }

  async fn messages(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    self.upstream_post(ctx, "messages").await
  }

  fn on_unauthorized(&self) {
    self.invalidate_api_token();
  }

  fn needs_refresh(&self, cfg: &AccountConfig) -> bool {
    const SKEW_SECS: i64 = 300;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    cfg
      .access_token_expires_at
      .map(|exp| exp - SKEW_SECS <= now)
      .unwrap_or(true)
      || cfg.access_token.is_none()
  }

  async fn refresh(&self, cfg: &AccountConfig, http: &reqwest::Client) -> Result<AccountConfig> {
    let token = self.ensure_api_token(http).await?;
    let (_, expires_at) = self.snapshot();
    let mut next = cfg.clone();
    next.access_token = Some(token);
    next.access_token_expires_at = expires_at;
    next.last_refresh = Some(time::OffsetDateTime::now_utc().unix_timestamp());
    Ok(next)
  }
}

fn headers_from_settings(a: &AccountConfig) -> Result<CopilotHeaders> {
  let value = serde_json::to_value(&a.settings).map_err(|source| error::Error::Json {
    what: "copilot account settings",
    body: format!("{:?}", a.settings),
    source,
  })?;
  let mut headers = CopilotHeaders::from_value(&value)?;
  for (name, value) in &a.headers {
    headers.extra_headers.insert(name.clone(), value.clone());
  }
  Ok(headers)
}

impl CopilotProvider {
  /// Shared upstream POST path used by every endpoint surface. The
  /// per-surface methods only differ in `path` and the wrapping error
  /// context — auth, header construction, client identity, and initiator handling
  /// are identical because Copilot proxies all three on the same host with
  /// the same auth scheme.
  #[instrument(
    name = "copilot_upstream",
    skip_all,
    fields(
      account = %self.id,
      what,
      path = tracing::field::Empty,
      stream = ctx.stream,
      initiator = tracing::field::Empty,
    ),
  )]
  async fn upstream_post(&self, ctx: RequestCtx<'_>, what: &'static str) -> Result<reqwest::Response> {
    let url = crate::operation_url(&self.target, ctx.endpoint)?;
    tracing::Span::current().record("path", url.path());
    let token = self.ensure_api_token(ctx.http).await?;
    let initiator = match ctx.endpoint {
      // For /v1/responses the inbound body uses `input`, not `messages`,
      // so the chat-style classifier would always fall through to
      // "user". Use the responses-aware variant instead.
      Endpoint::Responses => self.resolve_initiator_responses(ctx.body, ctx.inbound_headers, ctx.initiator),
      _ => self.resolve_initiator(ctx.body, ctx.inbound_headers, ctx.initiator),
    };
    tracing::Span::current().record("initiator", initiator.as_str());
    let mut h = ctx.client_headers.clone().unwrap_or_else(|| {
      headers::copilot_request_headers(token.expose(), &self.headers, ctx.stream, &initiator).unwrap_or_default()
    });
    self.patch_headers(
      &mut h,
      &HeaderPatchCtx {
        request_kind: ProviderRequestKind::Operation(ctx.endpoint),
        body: ctx.body,
        bearer_token: Some(token.expose()),
        content_encoding: ctx.content_encoding,
        stream: ctx.stream,
        initiator: &initiator,
        inbound_headers: ctx.inbound_headers,
        vars: &ctx.vars,
        agent_id: &ctx.agent_id,
      },
    )?;
    debug!(%url, "POST upstream");
    let body_bytes = ctx.request_body_bytes();
    let resp = crate::util::http::send(
      ctx.http,
      Method::POST,
      url.as_str(),
      h,
      Some(body_bytes),
      ctx.outbound.as_ref(),
      what,
    )
    .await?;
    debug!(status = %resp.status(), "upstream returned");
    Ok(resp)
  }

  /// Variant of [`Self::resolve_initiator`] for the Responses API, whose
  /// body is shaped `{ input: …, instructions: …, … }` rather than
  /// `{ messages: [...] }`.
  fn resolve_initiator_responses(&self, body: &Value, inbound: &HeaderMap, fallback: &str) -> String {
    if let Some(v) = inbound.get("x-initiator") {
      let v = v.as_str().trim().to_ascii_lowercase();
      if v == "user" || v == "agent" {
        return v;
      }
    }
    match self.headers.initiator_mode {
      InitiatorMode::AlwaysUser => "user".into(),
      InitiatorMode::AlwaysAgent => "agent".into(),
      InitiatorMode::Auto => {
        if fallback == "user" || fallback == "agent" {
          return fallback.into();
        }
        crate::util::initiator::classify_initiator_responses(body)
          .unwrap_or("user")
          .into()
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::TemplateVars;
  use tokn_core::account::AccountTier;
  use tokn_mock_server::{MockAuthConfig, MockEndpoint, MockLlmConfig, MockLlmServer, MockResponse, MockRoute};

  fn acct(refresh: Option<&str>) -> AccountConfig {
    AccountConfig {
      id: "test".into(),
      provider: ID_GITHUB_COPILOT.into(),
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
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: refresh.map(|s| Secret::new(s.into())),
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: toml::Table::new(),
    }
  }

  fn provider() -> CopilotProvider {
    CopilotProvider::from_account(Arc::new(acct(Some("gh-test-fixture")))).unwrap()
  }

  fn acct_with_cached_api_token() -> AccountConfig {
    let mut account = acct(Some("gh-test-fixture"));
    account.access_token = Some(Secret::new("api-tok-fixture".into()));
    account.access_token_expires_at = Some(time::OffsetDateTime::now_utc().unix_timestamp() + 3_600);
    account
  }

  fn patch_ctx(
    endpoint: Endpoint,
    stream: bool,
    initiator: &'static str,
    content_encoding: Option<&'static str>,
  ) -> HeaderPatchCtx<'static> {
    HeaderPatchCtx {
      request_kind: ProviderRequestKind::Operation(endpoint),
      body: Box::leak(Box::new(Value::Null)),
      bearer_token: Some("api-tok-fixture"),
      content_encoding,
      stream,
      initiator,
      inbound_headers: Box::leak(Box::new(HeaderMap::new())),
      vars: Box::leak(Box::new(TemplateVars::default())),
      agent_id: Box::leak(Box::new(tokn_core::AgentId::CopilotCli)),
    }
  }

  #[test]
  fn copilot_patch_headers_chat_streaming_user_initiator() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::ChatCompletions, true, "user", None))
      .unwrap();
    assert_eq!(h.get("authorization").unwrap().as_str(), "Bearer api-tok-fixture");
    assert_eq!(h.get("accept").unwrap().as_str(), "text/event-stream");
    assert_eq!(h.get("content-type").unwrap().as_str(), "application/json");
    assert_eq!(h.get("x-initiator").unwrap().as_str(), "user");
    assert!(h.get("content-encoding").is_none());
    let names: Vec<_> = h.iter().map(|(n, _)| n.as_str().to_string()).collect();
    assert_eq!(names.len(), 4, "unexpected extra headers: {names:?}");
  }

  #[test]
  fn copilot_patch_headers_chat_non_streaming_agent_initiator() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::ChatCompletions, false, "agent", None))
      .unwrap();
    assert_eq!(h.get("accept").unwrap().as_str(), "application/json");
    assert_eq!(h.get("x-initiator").unwrap().as_str(), "agent");
  }

  #[test]
  fn copilot_patch_headers_responses_streaming() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::Responses, true, "user", None))
      .unwrap();
    // patch_headers shape does not vary by endpoint.
    assert_eq!(h.get("accept").unwrap().as_str(), "text/event-stream");
    assert_eq!(h.get("x-initiator").unwrap().as_str(), "user");
  }

  #[test]
  fn copilot_patch_headers_messages_streaming() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(&mut h, &patch_ctx(Endpoint::Messages, true, "user", None))
      .unwrap();
    assert_eq!(h.get("accept").unwrap().as_str(), "text/event-stream");
    assert_eq!(h.get("x-initiator").unwrap().as_str(), "user");
  }

  #[test]
  fn copilot_patch_headers_round_trips_content_encoding() {
    let p = provider();
    let mut h = HeaderMap::new();
    p.patch_headers(
      &mut h,
      &patch_ctx(Endpoint::ChatCompletions, false, "user", Some("gzip")),
    )
    .unwrap();
    assert_eq!(h.get("content-encoding").unwrap().as_str(), "gzip");
  }

  #[test]
  fn copilot_patch_headers_requires_bearer_token() {
    let p = provider();
    let mut h = HeaderMap::new();
    let ctx = HeaderPatchCtx {
      request_kind: ProviderRequestKind::Models,
      body: &Value::Null,
      bearer_token: None,
      content_encoding: None,
      stream: false,
      initiator: "user",
      inbound_headers: &HeaderMap::new(),
      vars: &TemplateVars::default(),
      agent_id: &tokn_core::AgentId::CopilotCli,
    };
    let err = p.patch_headers(&mut h, &ctx).unwrap_err();
    assert!(err.to_string().contains("copilot bearer token"), "{err}");
  }

  #[test]
  fn explicit_target_owns_destination_and_model_cache() {
    let mut account = acct(Some("gh-test-fixture"));
    account.base_url = Some("https://ignored.example/copilot".into());
    let target = ProviderTarget::parse(
      "https://gateway.example/copilot/data-plane",
      CleartextHttpPolicy::LoopbackOnly,
    )
    .unwrap();
    let target_cache = target.model_cache().clone();

    let provider = CopilotProvider::from_account_at(Arc::new(account), target).unwrap();

    assert_eq!(
      provider
        .target
        .base_url()
        .operation_url(["chat", "completions"])
        .unwrap()
        .as_str(),
      "https://gateway.example/copilot/data-plane/chat/completions"
    );
    assert_eq!(
      provider.info().upstream_url,
      "https://gateway.example/copilot/data-plane/"
    );
    assert!(Arc::ptr_eq(&provider.info().model_cache, &target_cache));
  }

  #[test]
  fn legacy_constructor_reports_invalid_account_url() {
    let mut account = acct(Some("gh-test-fixture"));
    account.base_url = Some("not a URL".into());

    let error = CopilotProvider::from_account(Arc::new(account)).err().unwrap();

    assert!(matches!(
      error,
      error::Error::InvalidUpstreamUrl { ref account, .. } if account == "test"
    ));
  }

  #[tokio::test]
  async fn explicit_target_serves_models_and_operations() {
    let config = MockLlmConfig::default()
      .with_auth(MockAuthConfig::bearer(["api-tok-fixture"]))
      .with_route(MockRoute::new(
        MockEndpoint::Custom {
          method: reqwest::Method::GET,
          path: "/copilot/models".into(),
        },
        MockResponse::json(serde_json::json!({
          "object": "list",
          "data": [{"id": "mock-model", "object": "model"}]
        })),
      ))
      .with_route(MockRoute::new(
        MockEndpoint::Custom {
          method: reqwest::Method::POST,
          path: "/copilot/chat/completions".into(),
        },
        MockResponse::json(serde_json::json!({"id": "chatcmpl-mock"})),
      ));
    let server = MockLlmServer::start(config).await;
    let target = ProviderTarget::parse(
      &format!("{}/copilot", server.base_url()),
      CleartextHttpPolicy::LoopbackOnly,
    )
    .unwrap();
    let mut account = acct_with_cached_api_token();
    account.base_url = Some("https://ignored.example/copilot".into());
    let provider = CopilotProvider::from_account_at(Arc::new(account), target).unwrap();
    let http = reqwest::Client::new();

    let models = provider.list_models(&http).await.unwrap();
    assert_eq!(models["data"][0]["id"], "mock-model");

    let body = serde_json::json!({
      "model": "mock-model",
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
        agent_id: tokn_core::AgentId::CopilotCli,
      })
      .await
      .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, reqwest::Method::GET);
    assert_eq!(requests[0].path, "/copilot/models");
    assert_eq!(requests[0].header("authorization"), Some("Bearer api-tok-fixture"));
    assert_eq!(requests[1].method, reqwest::Method::POST);
    assert_eq!(requests[1].path, "/copilot/chat/completions");
    assert_eq!(requests[1].header("authorization"), Some("Bearer api-tok-fixture"));
  }
}

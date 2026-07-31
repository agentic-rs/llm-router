//! Test-only helpers shared across stage unit tests.
//!
//! Provides a minimal [`MockProvider`] (and [`mock_handle`] constructor)
//! so resolve / convert-request / build-headers tests can build a
//! synthetic [`AccountHandle`] without depending on a real provider
//! crate. Keeping this in `src/` (gated on `cfg(test)`) makes the
//! helpers reusable across modules but still excludes them from the
//! published crate surface.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokn_accounts::AccountHandle;
use tokn_core::account::AccountConfig;
use tokn_core::pipeline::InputTransformer;
use tokn_core::provider::error;
use tokn_core::provider::{
  AuthKind, CredentialPatchCtx, Endpoint, HeaderPatchCtx, ModelCache, Provider, ProviderInfo, RequestCtx,
};
use tokn_headers::{HeaderMap, HeaderName, HeaderValue};

/// One-shot canned response or error returned by a mocked provider endpoint.
/// Stored behind a [`Mutex`] because the trait method takes `&self`.
enum EndpointScript {
  Response(reqwest::Response),
  Error(Box<dyn FnOnce() -> error::Error + Send + Sync>),
}

pub struct MockProvider {
  info: ProviderInfo,
  transformer: Option<Box<dyn InputTransformer>>,
  chat_script: Mutex<Option<EndpointScript>>,
  responses_script: Mutex<Option<EndpointScript>>,
  messages_script: Mutex<Option<EndpointScript>>,
  header_patch: Vec<(String, String)>,
  normalization_patch: Vec<(String, String)>,
  credential_invalidations: Arc<AtomicUsize>,
}

impl MockProvider {
  pub fn new(id: &str) -> Self {
    Self::with_default_endpoints(id, &[Endpoint::ChatCompletions])
  }

  pub fn with_default_endpoints(id: &str, default_endpoints: &'static [Endpoint]) -> Self {
    Self {
      info: ProviderInfo {
        id: id.into(),
        aliases: &[],
        display_name: "mock",
        upstream_url: String::new(),
        auth_kind: AuthKind::StaticApiKey,
        default_models: vec![],
        default_endpoints,
        model_cache: Arc::new(ModelCache::default()),
      },
      transformer: None,
      chat_script: Mutex::new(None),
      responses_script: Mutex::new(None),
      messages_script: Mutex::new(None),
      header_patch: Vec::new(),
      normalization_patch: Vec::new(),
      credential_invalidations: Arc::new(AtomicUsize::new(0)),
    }
  }

  pub fn with_transformer(mut self, t: impl InputTransformer + 'static) -> Self {
    self.transformer = Some(Box::new(t));
    self
  }

  /// Arm the next [`Provider::chat`] call to return `resp`.
  pub fn with_chat_response(self, resp: reqwest::Response) -> Self {
    *self.chat_script.lock().unwrap() = Some(EndpointScript::Response(resp));
    self
  }

  /// Arm the next [`Provider::chat`] call to return the error built by `f`.
  pub fn with_chat_error<F>(self, f: F) -> Self
  where
    F: FnOnce() -> error::Error + Send + Sync + 'static,
  {
    *self.chat_script.lock().unwrap() = Some(EndpointScript::Error(Box::new(f)));
    self
  }

  pub fn with_responses_response(self, resp: reqwest::Response) -> Self {
    *self.responses_script.lock().unwrap() = Some(EndpointScript::Response(resp));
    self
  }

  #[allow(dead_code)]
  pub fn with_responses_error<F>(self, f: F) -> Self
  where
    F: FnOnce() -> error::Error + Send + Sync + 'static,
  {
    *self.responses_script.lock().unwrap() = Some(EndpointScript::Error(Box::new(f)));
    self
  }

  #[allow(dead_code)]
  pub fn with_messages_response(self, resp: reqwest::Response) -> Self {
    *self.messages_script.lock().unwrap() = Some(EndpointScript::Response(resp));
    self
  }

  #[allow(dead_code)]
  pub fn with_messages_error<F>(self, f: F) -> Self
  where
    F: FnOnce() -> error::Error + Send + Sync + 'static,
  {
    *self.messages_script.lock().unwrap() = Some(EndpointScript::Error(Box::new(f)));
    self
  }

  pub fn with_header(mut self, name: &str, value: &str) -> Self {
    self.header_patch.push((name.to_string(), value.to_string()));
    self
  }

  pub fn with_normalized_header(mut self, name: &str, value: &str) -> Self {
    self.normalization_patch.push((name.to_string(), value.to_string()));
    self
  }

  pub fn credential_invalidations(&self) -> Arc<AtomicUsize> {
    self.credential_invalidations.clone()
  }
}

#[async_trait]
impl Provider for MockProvider {
  fn id(&self) -> &str {
    &self.info.id
  }
  fn info(&self) -> &ProviderInfo {
    &self.info
  }
  fn input_transformer(&self) -> Option<&dyn InputTransformer> {
    self.transformer.as_deref()
  }
  fn inject_credentials(&self, headers: &mut HeaderMap, _ctx: &CredentialPatchCtx<'_>) -> error::Result<()> {
    for (name, value) in &self.header_patch {
      headers.insert(HeaderName::new(name.clone()), HeaderValue::from_string(value.clone()));
    }
    Ok(())
  }
  fn normalize_headers(&self, headers: &mut HeaderMap, _ctx: &HeaderPatchCtx<'_>) -> error::Result<Option<HeaderMap>> {
    for (name, value) in &self.normalization_patch {
      headers.insert(HeaderName::new(name.clone()), HeaderValue::from_string(value.clone()));
    }
    Ok(None)
  }
  async fn list_models(&self, _http: &reqwest::Client) -> error::Result<Value> {
    Ok(Value::Null)
  }
  async fn chat(&self, _ctx: RequestCtx<'_>) -> error::Result<reqwest::Response> {
    match self.chat_script.lock().unwrap().take() {
      Some(EndpointScript::Response(r)) => Ok(r),
      Some(EndpointScript::Error(f)) => Err(f()),
      None => unimplemented!("MockProvider::chat: no script armed; call with_chat_response/with_chat_error"),
    }
  }

  async fn responses(&self, _ctx: RequestCtx<'_>) -> error::Result<reqwest::Response> {
    match self.responses_script.lock().unwrap().take() {
      Some(EndpointScript::Response(r)) => Ok(r),
      Some(EndpointScript::Error(f)) => Err(f()),
      None => {
        unimplemented!("MockProvider::responses: no script armed; call with_responses_response/with_responses_error")
      }
    }
  }

  async fn messages(&self, _ctx: RequestCtx<'_>) -> error::Result<reqwest::Response> {
    match self.messages_script.lock().unwrap().take() {
      Some(EndpointScript::Response(r)) => Ok(r),
      Some(EndpointScript::Error(f)) => Err(f()),
      None => {
        unimplemented!("MockProvider::messages: no script armed; call with_messages_response/with_messages_error")
      }
    }
  }
  fn on_unauthorized(&self) {
    self.credential_invalidations.fetch_add(1, Ordering::Relaxed);
  }
}

/// Build an [`AccountHandle`] backed by a [`MockProvider`].
pub fn mock_handle(account_id: &str, provider_id: &str) -> Arc<AccountHandle> {
  mock_handle_with_provider(account_id, MockProvider::new(provider_id))
}

pub fn mock_handle_with_provider(account_id: &str, provider: MockProvider) -> Arc<AccountHandle> {
  let cfg = AccountConfig {
    id: account_id.to_string(),
    provider: provider.id().to_string(),
    enabled: true,
    tier: Default::default(),
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
    refresh_token: None,
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: Default::default(),
  };
  Arc::new(AccountHandle::new(Arc::new(cfg), Arc::new(provider)))
}

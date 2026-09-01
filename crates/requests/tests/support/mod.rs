#![allow(dead_code)]

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use smol_str::SmolStr;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokn_accounts::AccountHandle;
use tokn_core::account::AccountConfig;
use tokn_core::provider::{
  AuthKind, Endpoint, ModelCache, Provider, ProviderInfo, RequestCtx, Result as ProviderResult,
};
use tokn_core::request_event::RecordEvent;
use tokn_core::util::secret::Secret;
use tokn_core::AgentId;
use tokn_headers::HeaderMap;
use tokn_provider_copilot::CopilotProvider;
use tokn_provider_openai::CodexProvider;
use tokn_requests::event::{EventPayload, StageEvent};
use tokn_requests::stages::{AccountSelector, DefaultExtract, SelectorOutcome};
use tokn_requests::{Event, EventBus, PipelineError, RawInbound};

#[derive(Debug, PartialEq, Eq)]
pub struct HeaderFixtureEntry {
  pub name: String,
  pub value: String,
}

pub struct ProviderFixture {
  pub handle: Arc<AccountHandle>,
  pub bearer_token: Option<&'static str>,
}

struct StubProvider {
  info: ProviderInfo,
}

#[async_trait]
impl Provider for StubProvider {
  fn id(&self) -> &str {
    &self.info.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  async fn list_models(&self, _http: &reqwest::Client) -> ProviderResult<Value> {
    Ok(Value::Null)
  }

  async fn chat(&self, _ctx: RequestCtx<'_>) -> ProviderResult<reqwest::Response> {
    unreachable!("smoke test never reaches Send")
  }
}

pub fn stub_handle(provider_id: &str, account_id: &str) -> Arc<AccountHandle> {
  let info = ProviderInfo {
    id: provider_id.into(),
    aliases: &[],
    display_name: "stub",
    upstream_url: String::new(),
    auth_kind: AuthKind::StaticApiKey,
    default_models: vec![],
    default_endpoints: &[Endpoint::ChatCompletions],
    model_cache: Arc::new(ModelCache::default()),
  };
  let cfg = account_config(account_id, provider_id);
  Arc::new(AccountHandle::new(Arc::new(cfg), Arc::new(StubProvider { info })))
}

pub struct OkSelector;

#[async_trait]
impl AccountSelector for OkSelector {
  async fn select(
    &self,
    _ctx: &tokn_requests::pipeline::ctx::PipelineCtx,
    _ex: &tokn_requests::stage_traits::Extracted,
  ) -> Result<SelectorOutcome, PipelineError> {
    Ok(SelectorOutcome::Selected {
      account_id: SmolStr::new("acct-1"),
      provider_id: SmolStr::new("zai-coding-plan"),
      upstream_endpoint: Some(Endpoint::ChatCompletions),
      upstream_model: SmolStr::new("glm-4"),
      account_handle: stub_handle("zai-coding-plan", "acct-1"),
    })
  }
}

pub struct EmptySelector;

#[async_trait]
impl AccountSelector for EmptySelector {
  async fn select(
    &self,
    _ctx: &tokn_requests::pipeline::ctx::PipelineCtx,
    _ex: &tokn_requests::stage_traits::Extracted,
  ) -> Result<SelectorOutcome, PipelineError> {
    Ok(SelectorOutcome::NoAccount)
  }
}

pub struct PendingSend;

#[async_trait]
impl tokn_requests::stage_traits::SendStage for PendingSend {
  async fn send(
    &self,
    ctx: &tokn_requests::PipelineCtx,
    _extracted: &tokn_requests::stage_traits::Extracted,
    _resolved: &tokn_requests::stage_traits::Resolved,
    _headers: &tokn_requests::stage_traits::BuiltHeaders,
    body: &tokn_requests::stage_traits::ConvertedRequest,
  ) -> Result<tokn_requests::stage_traits::SentResponse, PipelineError> {
    ctx.emit_record(RecordEvent::UpstreamReq {
      method: SmolStr::new("POST"),
      url: SmolStr::new("https://example.test/pending"),
      headers: HeaderMap::new(),
      body: body.upstream_wire_body.clone(),
    });
    std::future::pending::<Result<tokn_requests::stage_traits::SentResponse, PipelineError>>().await
  }
}

pub fn capture_bus() -> (Arc<EventBus>, Arc<Mutex<Vec<Event>>>) {
  let bus = Arc::new(EventBus::new(256));
  let log: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
  {
    let log = log.clone();
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
      loop {
        match rx.recv().await {
          Ok(arc) => {
            if let tokn_core::event::Event::Requests(ev) = &*arc {
              log.lock().unwrap().push(ev.clone());
            }
          }
          Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
          Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
      }
    });
  }
  (bus, log)
}

pub fn drain_received_events(rx: &mut tokio::sync::broadcast::Receiver<Arc<tokn_core::event::Event>>) -> Vec<Event> {
  let mut events = Vec::new();
  loop {
    match rx.try_recv() {
      Ok(event) => {
        if let tokn_core::event::Event::Requests(event) = &*event {
          events.push(event.clone());
        }
      }
      Err(tokio::sync::broadcast::error::TryRecvError::Empty | tokio::sync::broadcast::error::TryRecvError::Closed) => {
        return events;
      }
      Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
        panic!("event receiver lagged by {skipped} events");
      }
    }
  }
}

pub fn raw_chat(model: &str) -> RawInbound {
  let body = serde_json::json!({"model": model, "messages": []});
  let decoded = Bytes::from(serde_json::to_vec(&body).unwrap());
  RawInbound {
    request_endpoint: Endpoint::ChatCompletions.into(),
    headers: HeaderMap::new(),
    raw_body: decoded.clone(),
    decoded_body: decoded,
    body_json: body,
    request_id: Some(SmolStr::new("req-smoke-1")),
  }
}

pub fn raw_responses(model: &str, headers: HeaderMap, stream: bool) -> RawInbound {
  let body = serde_json::json!({
    "model": model,
    "input": "hello from headers integration",
    "stream": stream,
    "max_output_tokens": 128,
  });
  let decoded = Bytes::from(serde_json::to_vec(&body).unwrap());
  RawInbound {
    request_endpoint: Endpoint::Responses.into(),
    headers,
    raw_body: decoded.clone(),
    decoded_body: decoded,
    body_json: body,
    request_id: Some(SmolStr::new("req-headers")),
  }
}

pub async fn drain_until_completed(log: &Arc<Mutex<Vec<Event>>>) -> std::sync::MutexGuard<'_, Vec<Event>> {
  for _ in 0..10000 {
    {
      let guard = log.lock().unwrap();
      let done = guard
        .iter()
        .any(|e| matches!(&e.payload, EventPayload::Stage(StageEvent::Completed { .. })));
      if done {
        return guard;
      }
    }
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  panic!("timed out waiting for Completed event");
}

pub async fn drain_until_completed_attempts(
  log: &Arc<Mutex<Vec<Event>>>,
  expected_attempts: u32,
) -> std::sync::MutexGuard<'_, Vec<Event>> {
  for _ in 0..10000 {
    {
      let guard = log.lock().unwrap();
      let done = guard.iter().any(|e| {
        matches!(
          &e.payload,
          EventPayload::Stage(StageEvent::Completed {
            attempts,
            ..
          }) if *attempts == expected_attempts
        )
      });
      if done {
        return guard;
      }
    }
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  panic!("timed out waiting for Completed event with attempts={expected_attempts}");
}

pub async fn drain_until_upstream_req(log: &Arc<Mutex<Vec<Event>>>) {
  for _ in 0..10000 {
    {
      let guard = log.lock().unwrap();
      let saw = guard
        .iter()
        .any(|e| matches!(&e.payload, EventPayload::Record(RecordEvent::UpstreamReq { .. })));
      if saw {
        return;
      }
    }
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  panic!("timed out waiting for UpstreamReq event");
}

pub fn known_kinds(events: &[Event]) -> Vec<&'static str> {
  events
    .iter()
    .map(|e| match &e.payload {
      EventPayload::Stage(k) => match k {
        StageEvent::Started { .. } => "started",
        StageEvent::Extract(_) => "extract",
        StageEvent::Resolve(_) => "resolve",
        StageEvent::BuildHeaders(_) => "build_headers",
        StageEvent::ConvertRequest(_) => "convert_request",
        StageEvent::Send(_) => "send",
        StageEvent::ConvertResponse(_) => "convert_response",
        StageEvent::Error { .. } => "error",
        StageEvent::Completed { .. } => "completed",
      },
      EventPayload::Record(_) => "record",
      EventPayload::Custom(c) => c.kind,
    })
    .collect()
}

struct RespondingProvider {
  info: ProviderInfo,
  resp: Mutex<Option<reqwest::Response>>,
}

#[async_trait]
impl Provider for RespondingProvider {
  fn id(&self) -> &str {
    &self.info.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  async fn list_models(&self, _http: &reqwest::Client) -> ProviderResult<Value> {
    Ok(Value::Null)
  }

  async fn chat(&self, _ctx: RequestCtx<'_>) -> ProviderResult<reqwest::Response> {
    Ok(
      self
        .resp
        .lock()
        .unwrap()
        .take()
        .expect("RespondingProvider::chat: no canned response armed"),
    )
  }
}

pub fn responding_handle(provider_id: &str, account_id: &str, resp: reqwest::Response) -> Arc<AccountHandle> {
  let info = provider_info(provider_id, "responding");
  let cfg = account_config(account_id, provider_id);
  let provider = RespondingProvider {
    info,
    resp: Mutex::new(Some(resp)),
  };
  Arc::new(AccountHandle::new(Arc::new(cfg), Arc::new(provider)))
}

pub struct CannedSelector {
  pub handle: Arc<AccountHandle>,
}

#[async_trait]
impl AccountSelector for CannedSelector {
  async fn select(
    &self,
    _ctx: &tokn_requests::pipeline::ctx::PipelineCtx,
    _ex: &tokn_requests::stage_traits::Extracted,
  ) -> Result<SelectorOutcome, PipelineError> {
    Ok(SelectorOutcome::Selected {
      account_id: SmolStr::new(self.handle.config.load().id.clone()),
      provider_id: SmolStr::new(self.handle.provider.id()),
      upstream_endpoint: Some(Endpoint::ChatCompletions),
      upstream_model: SmolStr::new("glm-4"),
      account_handle: self.handle.clone(),
    })
  }
}

pub struct CodexSelector {
  pub handle: Arc<AccountHandle>,
}

#[async_trait]
impl AccountSelector for CodexSelector {
  async fn select(
    &self,
    _ctx: &tokn_requests::pipeline::ctx::PipelineCtx,
    _ex: &tokn_requests::stage_traits::Extracted,
  ) -> Result<SelectorOutcome, PipelineError> {
    Ok(SelectorOutcome::Selected {
      account_id: SmolStr::new(self.handle.config.load().id.clone()),
      provider_id: SmolStr::new("codex"),
      upstream_endpoint: Some(Endpoint::Responses),
      upstream_model: SmolStr::new("gpt-5-codex"),
      account_handle: self.handle.clone(),
    })
  }
}

pub struct FixedAgentExtract {
  pub agent_id: AgentId,
}

#[async_trait]
impl tokn_requests::stage_traits::ExtractStage for FixedAgentExtract {
  async fn extract(
    &self,
    ctx: &tokn_requests::PipelineCtx,
    raw: RawInbound,
  ) -> Result<tokn_requests::stage_traits::Extracted, PipelineError> {
    let mut extracted = DefaultExtract.extract(ctx, raw).await?;
    extracted.agent_id = Some(self.agent_id.clone());
    Ok(extracted)
  }
}

pub fn ok_response(status: u16, body: &'static str) -> reqwest::Response {
  let resp = http::Response::builder()
    .status(status)
    .header("content-type", "application/json")
    .body(body)
    .unwrap();
  reqwest::Response::from(resp)
}

pub fn headers_from_fixture(yaml: &str) -> HeaderMap {
  let entries = load_header_fixture(yaml);
  let mut headers = HeaderMap::new();
  for HeaderFixtureEntry { name, value } in entries {
    headers.insert(
      tokn_headers::HeaderName::new(name),
      tokn_headers::HeaderValue::from_string(value),
    );
  }
  headers
}

pub fn provider_fixture(provider_id: &str) -> ProviderFixture {
  match provider_id {
    "codex" => ProviderFixture {
      handle: codex_handle("http://127.0.0.1"),
      bearer_token: None,
    },
    "github-copilot" => ProviderFixture {
      handle: copilot_handle(),
      bearer_token: Some("api-copilot"),
    },
    other => panic!("unsupported provider fixture: {other}"),
  }
}

pub fn codex_handle(base_url: &str) -> Arc<AccountHandle> {
  let config = codex_account(base_url);
  let provider = CodexProvider::from_account(config.clone()).expect("codex test account should build");
  Arc::new(AccountHandle::new(config, Arc::new(provider)))
}

fn codex_account(base_url: &str) -> Arc<AccountConfig> {
  Arc::new(AccountConfig {
    id: "codex-acct".to_string(),
    provider: "codex".to_string(),
    enabled: true,
    tier: Default::default(),
    tags: Vec::new(),
    label: None,
    base_url: Some(base_url.to_string()),
    headers: Default::default(),
    auth_type: None,
    username: None,
    api_key: None,
    api_key_expires_at: None,
    access_token: Some(Secret::new("atk-codex".to_string())),
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: Some("acct-from-provider".to_string()),
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: Default::default(),
  })
}

fn copilot_handle() -> Arc<AccountHandle> {
  let config = copilot_account();
  let provider = CopilotProvider::from_account(config.clone()).expect("copilot test account should build");
  Arc::new(AccountHandle::new(config, Arc::new(provider)))
}

fn copilot_account() -> Arc<AccountConfig> {
  Arc::new(AccountConfig {
    id: "copilot-acct".to_string(),
    provider: "github-copilot".to_string(),
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
    access_token: Some(Secret::new("api-copilot".to_string())),
    access_token_expires_at: Some(4_102_444_800),
    id_token: None,
    refresh_token: Some(Secret::new("gh-copilot".to_string())),
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: Default::default(),
  })
}

struct RecordingProvider {
  info: ProviderInfo,
  resp: Mutex<Option<reqwest::Response>>,
  seen_client_headers: Arc<Mutex<Option<HeaderMap>>>,
}

#[async_trait]
impl Provider for RecordingProvider {
  fn id(&self) -> &str {
    &self.info.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  async fn list_models(&self, _http: &reqwest::Client) -> ProviderResult<Value> {
    Ok(Value::Null)
  }

  async fn chat(&self, ctx: RequestCtx<'_>) -> ProviderResult<reqwest::Response> {
    *self.seen_client_headers.lock().unwrap() = ctx.client_headers.clone();
    Ok(
      self
        .resp
        .lock()
        .unwrap()
        .take()
        .expect("RecordingProvider::chat: no canned response armed"),
    )
  }
}

pub fn recording_handle(
  provider_id: &str,
  account_id: &str,
  resp: reqwest::Response,
) -> (Arc<AccountHandle>, Arc<Mutex<Option<HeaderMap>>>) {
  let info = provider_info(provider_id, "recording");
  let cfg = account_config(account_id, provider_id);
  let seen_client_headers = Arc::new(Mutex::new(None));
  let provider = RecordingProvider {
    info,
    resp: Mutex::new(Some(resp)),
    seen_client_headers: seen_client_headers.clone(),
  };
  (
    Arc::new(AccountHandle::new(Arc::new(cfg), Arc::new(provider))),
    seen_client_headers,
  )
}

pub fn load_header_fixture(yaml: &str) -> Vec<HeaderFixtureEntry> {
  let entries: Vec<serde_json::Map<String, Value>> = serde_yaml::from_str(yaml).expect("fixture is a YAML array");
  let mut headers = Vec::with_capacity(entries.len());
  for entry in entries {
    assert_eq!(entry.len(), 1, "each fixture row must contain exactly one header");
    let (name, value) = entry.into_iter().next().expect("fixture row must contain one header");
    let value = value
      .as_str()
      .expect("fixture header value must be a string")
      .to_string();
    headers.push(HeaderFixtureEntry { name, value });
  }
  headers
}

fn header_entries(headers: &HeaderMap) -> Vec<HeaderFixtureEntry> {
  headers
    .iter()
    .map(|(name, value)| HeaderFixtureEntry {
      name: name.original().to_string(),
      value: value.as_str().to_string(),
    })
    .collect()
}

pub fn assert_headers_match_fixture(headers: &HeaderMap, fixture_yaml: &str, label: &str) {
  assert_eq!(
    header_entries(headers),
    load_header_fixture(fixture_yaml),
    "{label}: header fixture mismatch"
  );
}

pub fn assert_headers_include_fixture(headers: &HeaderMap, fixture_yaml: &str, label: &str) {
  for HeaderFixtureEntry { name, value } in load_header_fixture(fixture_yaml) {
    assert_eq!(
      headers.get(&name).map(|value| value.as_str()),
      Some(value.as_str()),
      "{label}: header mismatch for {name}"
    );
  }
}

struct FailingProvider {
  info: ProviderInfo,
}

#[async_trait]
impl Provider for FailingProvider {
  fn id(&self) -> &str {
    &self.info.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  async fn list_models(&self, _http: &reqwest::Client) -> ProviderResult<Value> {
    Ok(Value::Null)
  }

  async fn chat(&self, _ctx: RequestCtx<'_>) -> ProviderResult<reqwest::Response> {
    let resp = http::Response::builder()
      .status(401)
      .header("content-type", "application/json")
      .body(r#"{"error":"unauthorized"}"#)
      .unwrap();
    Ok(reqwest::Response::from(resp))
  }
}

pub fn failing_handle(provider_id: &str, account_id: &str) -> Arc<AccountHandle> {
  let info = provider_info(provider_id, "failing");
  let cfg = account_config(account_id, provider_id);
  let provider = FailingProvider { info };
  Arc::new(AccountHandle::new(Arc::new(cfg), Arc::new(provider)))
}

pub enum ScriptedResponse {
  Http { status: u16, body: &'static str },
}

struct SequencedProvider {
  info: ProviderInfo,
  responses: Mutex<VecDeque<ScriptedResponse>>,
  calls: AtomicUsize,
}

#[async_trait]
impl Provider for SequencedProvider {
  fn id(&self) -> &str {
    &self.info.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  async fn list_models(&self, _http: &reqwest::Client) -> ProviderResult<Value> {
    Ok(Value::Null)
  }

  async fn chat(&self, _ctx: RequestCtx<'_>) -> ProviderResult<reqwest::Response> {
    self.calls.fetch_add(1, Ordering::Relaxed);
    let next = self
      .responses
      .lock()
      .unwrap()
      .pop_front()
      .expect("scripted provider should have a queued response");
    match next {
      ScriptedResponse::Http { status, body } => Ok(ok_response(status, body)),
    }
  }
}

pub fn sequenced_handle(provider_id: &str, account_id: &str, responses: Vec<ScriptedResponse>) -> Arc<AccountHandle> {
  let info = provider_info(provider_id, "sequenced");
  let cfg = account_config(account_id, provider_id);
  let provider = SequencedProvider {
    info,
    responses: Mutex::new(responses.into()),
    calls: AtomicUsize::new(0),
  };
  Arc::new(AccountHandle::new(Arc::new(cfg), Arc::new(provider)))
}

fn provider_info(provider_id: &str, display_name: &'static str) -> ProviderInfo {
  ProviderInfo {
    id: provider_id.into(),
    aliases: &[],
    display_name,
    upstream_url: String::new(),
    auth_kind: AuthKind::StaticApiKey,
    default_models: vec![],
    default_endpoints: &[Endpoint::ChatCompletions],
    model_cache: Arc::new(ModelCache::default()),
  }
}

fn account_config(account_id: &str, provider_id: &str) -> AccountConfig {
  AccountConfig {
    id: account_id.to_string(),
    provider: provider_id.to_string(),
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
  }
}

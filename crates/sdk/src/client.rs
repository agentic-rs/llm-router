use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use smol_str::SmolStr;
use std::path::PathBuf;
use std::sync::Arc;
use tokn_auth::{default_auth_path, AuthStore};
use tokn_config::Config;
use tokn_core::event::EventBus;
use tokn_core::provider::Endpoint;
use tokn_core::request_event::RequestEndpoint;
use tokn_headers::keys::{ACCEPT, CONTENT_TYPE};
use tokn_headers::{HeaderMap, HeaderName, HeaderValue};
use tokn_requests::{RawInbound, RunConfig};
use tokn_router::api::{AppState, RequestPolicyRuntime};

use crate::endpoint::{ChatCompletions, Messages, Responses};
use crate::response::RawResponse;
use crate::{Error, Result};

const EVENT_BUS_CAPACITY: usize = 256;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RequestOptions {
  pub profile: Option<String>,
  pub request_id: Option<String>,
  pub session_id: Option<String>,
  pub project_id: Option<String>,
  pub initiator: Option<String>,
  /// Additional inbound headers made available to provider persona and
  /// overlay normalization. Managed routes do not forward arbitrary headers
  /// verbatim.
  pub headers: Vec<(String, String)>,
}

impl RequestOptions {
  pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
    self.profile = Some(profile.into());
    self
  }

  pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
    self.request_id = Some(request_id.into());
    self
  }

  pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
    self.session_id = Some(session_id.into());
    self
  }

  pub fn with_project_id(mut self, project_id: impl Into<String>) -> Self {
    self.project_id = Some(project_id.into());
    self
  }

  pub fn with_initiator(mut self, initiator: impl Into<String>) -> Self {
    self.initiator = Some(initiator.into());
    self
  }

  pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
    self.headers.push((name.into(), value.into()));
    self
  }
}

#[derive(Clone, Debug, Default)]
pub struct ClientBuilder {
  config_path: Option<PathBuf>,
  auth_path: Option<PathBuf>,
  profile: Option<String>,
}

impl ClientBuilder {
  pub fn config_path(mut self, path: impl Into<PathBuf>) -> Self {
    self.config_path = Some(path.into());
    self
  }

  pub fn auth_path(mut self, path: impl Into<PathBuf>) -> Self {
    self.auth_path = Some(path.into());
    self
  }

  pub fn profile(mut self, profile: impl Into<String>) -> Self {
    self.profile = Some(profile.into());
    self
  }

  pub fn build(self) -> Result<Client> {
    Client::build(self)
  }
}

struct Source {
  config_path: Option<PathBuf>,
  auth_path: Option<PathBuf>,
  profile: Option<String>,
}

struct Snapshot {
  state: AppState,
  default_profile: Option<String>,
  config_path: PathBuf,
  auth_path: PathBuf,
}

pub struct Client {
  source: Source,
  snapshot: ArcSwap<Snapshot>,
}

impl Client {
  pub fn builder() -> ClientBuilder {
    ClientBuilder::default()
  }

  pub fn from_default_config() -> Result<Self> {
    Self::builder().build()
  }

  fn build(builder: ClientBuilder) -> Result<Self> {
    let source = Source {
      config_path: builder.config_path,
      auth_path: builder.auth_path,
      profile: builder.profile,
    };
    let snapshot = load_snapshot(&source)?;
    Ok(Self {
      source,
      snapshot: ArcSwap::from_pointee(snapshot),
    })
  }

  pub fn reload(&self) -> Result<()> {
    self.snapshot.store(Arc::new(load_snapshot(&self.source)?));
    Ok(())
  }

  pub fn config_path(&self) -> PathBuf {
    self.snapshot.load().config_path.clone()
  }

  pub fn auth_path(&self) -> PathBuf {
    self.snapshot.load().auth_path.clone()
  }

  pub fn responses(&self) -> Responses<'_> {
    Responses::new(self)
  }

  pub fn chat_completions(&self) -> ChatCompletions<'_> {
    ChatCompletions::new(self)
  }

  pub fn messages(&self) -> Messages<'_> {
    Messages::new(self)
  }

  pub async fn execute(&self, endpoint: Endpoint, body: Value, options: RequestOptions) -> Result<RawResponse> {
    let snapshot = self.snapshot.load_full();
    let policy = select_policy(&snapshot, options.profile.as_deref())?;
    let raw = raw_request(endpoint, body, &options)?;
    let config = RunConfig::builder().with_agent_id_opt(policy.agent_id.clone()).build();
    let pipeline = match policy.mode {
      tokn_config::RouteMode::Passthrough => &policy.passthrough_pipeline,
      tokn_config::RouteMode::Switch => &policy.switch_pipeline,
      _ => &policy.request_pipeline,
    };
    let response = pipeline
      .run_with(raw, config)
      .await
      .map_err(|source| Error::Pipeline { source })?;
    Ok(response.into())
  }

  pub(crate) async fn execute_typed<T: Serialize>(
    &self,
    endpoint: Endpoint,
    request: &T,
    stream: bool,
    options: RequestOptions,
  ) -> Result<RawResponse> {
    let mut body = serde_json::to_value(request).map_err(|source| Error::SerializeRequest { source })?;
    if let Some(object) = body.as_object_mut() {
      object.insert("stream".into(), Value::Bool(stream));
    }
    self.execute(endpoint, body, options).await
  }
}

fn load_snapshot(source: &Source) -> Result<Snapshot> {
  let (config, config_path) =
    Config::load(source.config_path.as_deref()).map_err(|source| Error::LoadConfig { source })?;
  let auth_path = match &source.auth_path {
    Some(path) => path.clone(),
    None => default_auth_path().map_err(|source| Error::LoadCredentials {
      path: PathBuf::from("<default>"),
      source,
    })?,
  };
  let credentials = AuthStore::load(Some(&auth_path), Some(&config_path)).map_err(|source| Error::LoadCredentials {
    path: auth_path.clone(),
    source,
  })?;
  let events = Arc::new(EventBus::new(EVENT_BUS_CAPACITY));
  let state = tokn_router::api::build_state(&config, &credentials.accounts, events)
    .map_err(|source| Error::BuildEngine { source })?;
  if let Some(profile) = &source.profile {
    ensure_profile(&state, profile)?;
  }
  Ok(Snapshot {
    state,
    default_profile: source.profile.clone(),
    config_path,
    auth_path,
  })
}

fn ensure_profile(state: &AppState, profile: &str) -> Result<()> {
  if state.profiles.contains_key(profile) {
    Ok(())
  } else {
    Err(Error::UnknownProfile {
      profile: profile.to_string(),
    })
  }
}

fn select_policy(snapshot: &Snapshot, request_profile: Option<&str>) -> Result<Arc<RequestPolicyRuntime>> {
  let profile = request_profile.or(snapshot.default_profile.as_deref());
  match profile {
    Some(profile) => snapshot
      .state
      .profiles
      .get(profile)
      .cloned()
      .ok_or_else(|| Error::UnknownProfile {
        profile: profile.to_string(),
      }),
    None => Ok(snapshot.state.default_policy.clone()),
  }
}

fn raw_request(endpoint: Endpoint, body: Value, options: &RequestOptions) -> Result<RawInbound> {
  let bytes = serde_json::to_vec(&body).map_err(|source| Error::SerializeRequest { source })?;
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_TYPE.clone(), HeaderValue::from_static("application/json"));
  headers.insert(ACCEPT.clone(), HeaderValue::from_static("application/json"));
  insert_option(&mut headers, "x-request-id", options.request_id.as_deref());
  insert_option(&mut headers, "x-session-id", options.session_id.as_deref());
  insert_option(&mut headers, "x-project-cwd", options.project_id.as_deref());
  insert_option(&mut headers, "x-initiator", options.initiator.as_deref());
  for (name, value) in &options.headers {
    headers.insert(HeaderName::new(name.clone()), HeaderValue::from_string(value.clone()));
  }
  let bytes = bytes::Bytes::from(bytes);
  Ok(RawInbound {
    request_endpoint: RequestEndpoint::from(endpoint),
    headers,
    raw_body: bytes.clone(),
    decoded_body: bytes,
    body_json: body,
    request_id: options.request_id.as_deref().map(SmolStr::new),
  })
}

fn insert_option(headers: &mut HeaderMap, name: &'static str, value: Option<&str>) {
  if let Some(value) = value {
    headers.insert(HeaderName::new(name), HeaderValue::from_string(value.to_string()));
  }
}

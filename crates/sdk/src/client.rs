use arc_swap::ArcSwap;
use http::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tokn_auth::{default_auth_path, AuthStore};
use tokn_core::generation::GenerationOptions;
use tokn_endpoint_core::Endpoint;
use tokn_events::{GatewayEvent, Publisher};
use tokn_policy::{ProfileId, RouteKind};
use tokn_requests::RequestLifecycleEmitter;
use tokn_router::runtime::{
  link_builtin_gateway_runtime_with_profile_roots, EmbeddedProfileRoots, ManagedGatewayExecutor, ManagedGatewayOutcome,
  ManagedGatewayRequest, ManagedSemanticCompletion,
};

use crate::endpoint::{ChatCompletions, Messages, Responses};
use crate::response::RawResponse;
use crate::{Error, Result};

const DEFAULT_PROFILE: &str = "default";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestOptions {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub request_id: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub session_id: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub project_id: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub initiator: Option<String>,
  /// Additional semantic inbound headers made available to provider persona
  /// rendering. Managed profiles do not forward arbitrary headers verbatim.
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub headers: Vec<(String, String)>,
}

impl RequestOptions {
  pub fn is_empty(&self) -> bool {
    self == &Self::default()
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
  event_publisher: Option<Publisher<GatewayEvent>>,
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

  /// Bind the client to one managed profile for its complete lifetime.
  ///
  /// Build a separate client when an application needs another profile. If
  /// omitted, the conventional `default` profile is used.
  pub fn profile(mut self, profile: impl Into<String>) -> Self {
    self.profile = Some(profile.into());
    self
  }

  /// Publish comprehensive request lifecycle events to a caller-owned hub.
  ///
  /// The client retains the supplied publisher and clones it into each runtime
  /// snapshot across successful and failed reloads. Reliable lifecycle
  /// boundaries wait for capacity in the hub's bounded queue and can therefore
  /// backpressure request execution.
  ///
  /// The caller remains responsible for the corresponding event hub. Before
  /// shutting it down, stop starting requests, await buffered requests, and
  /// fully drain or drop every live stream. Dropping [`Client`] never closes or
  /// shuts down the hub. If this method is omitted, lifecycle publication is
  /// disabled without creating a background dispatcher.
  pub fn event_publisher(mut self, publisher: Publisher<GatewayEvent>) -> Self {
    self.event_publisher = Some(publisher);
    self
  }

  pub fn build(self) -> Result<Client> {
    Client::build(self)
  }
}

struct Source {
  config_path: PathBuf,
  auth_path: PathBuf,
  profile: ProfileId,
}

struct Snapshot {
  gateway: ManagedGatewayExecutor,
}

pub(crate) struct ControlledRawResponse {
  response: RawResponse,
  semantic_completion: Option<ManagedSemanticCompletion>,
}

impl ControlledRawResponse {
  pub(crate) fn into_parts(self) -> (RawResponse, Option<ManagedSemanticCompletion>) {
    (self.response, self.semantic_completion)
  }
}

/// In-process client bound to one profile and one optional event publisher.
///
/// Runtime snapshots are replaced atomically, while the lifecycle emitter is
/// owned separately so every generation uses the same caller-owned publisher.
/// This client never owns or shuts down the corresponding event hub.
pub struct Client {
  source: Source,
  request_events: RequestLifecycleEmitter,
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
    let ClientBuilder {
      config_path,
      auth_path,
      profile,
      event_publisher,
    } = builder;
    let profile = profile.unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
    let profile = ProfileId::new(&profile).map_err(|source| Error::InvalidProfileId { profile, source })?;
    let config_path = tokn_config::paths::resolve_config_path(config_path.as_deref())
      .map_err(|source| Error::ResolveConfigPath { source })?;
    let auth_path = match auth_path {
      Some(path) => path,
      None => default_auth_path().map_err(|source| Error::LoadCredentials {
        path: PathBuf::from("<default>"),
        source,
      })?,
    };
    let source = Source {
      config_path,
      auth_path,
      profile,
    };
    let request_events = event_publisher
      .map(RequestLifecycleEmitter::new)
      .unwrap_or_else(RequestLifecycleEmitter::disabled);
    let snapshot = load_snapshot(&source, request_events.clone())?;
    Ok(Self {
      source,
      request_events,
      snapshot: ArcSwap::from_pointee(snapshot),
    })
  }

  /// Atomically replace the compiled config, linked account graph, and
  /// managed transport. In-flight requests retain the previous snapshot, and
  /// every generation uses the publisher selected when this client was built.
  /// A failed reload leaves both the previous snapshot and publisher usable.
  pub fn reload(&self) -> Result<()> {
    self
      .snapshot
      .store(Arc::new(load_snapshot(&self.source, self.request_events.clone())?));
    Ok(())
  }

  pub fn profile(&self) -> &str {
    self.source.profile.as_str()
  }

  pub fn config_path(&self) -> PathBuf {
    self.source.config_path.clone()
  }

  pub fn auth_path(&self) -> PathBuf {
    self.source.auth_path.clone()
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
    self
      .execute_with_generation_options(endpoint, body, options, None)
      .await
      .map(|response| response.response)
  }

  pub(crate) async fn execute_generation(
    &self,
    endpoint: Endpoint,
    body: Value,
    options: RequestOptions,
    generation_options: GenerationOptions,
  ) -> Result<ControlledRawResponse> {
    let generation_options = (!generation_options.is_empty()).then_some(generation_options);
    self
      .execute_with_generation_options(endpoint, body, options, generation_options)
      .await
  }

  async fn execute_with_generation_options(
    &self,
    endpoint: Endpoint,
    body: Value,
    options: RequestOptions,
    generation_options: Option<GenerationOptions>,
  ) -> Result<ControlledRawResponse> {
    let snapshot = self.snapshot.load_full();
    let headers = request_headers(&options)?;
    let mut request = ManagedGatewayRequest::new(endpoint, body).with_headers(headers);
    if let Some(session_id) = options.session_id.as_deref() {
      request = request.with_session_id(session_id);
    }
    if let Some(generation_options) = generation_options {
      request = request.with_generation_options(generation_options);
    }

    let execution = snapshot
      .gateway
      .execute_controlled(&self.source.profile, request)
      .await
      .map_err(|source| Error::ManagedRequest {
        source: Box::new(source),
      })?;
    let (outcome, semantic_completion) = execution.into_parts();
    match outcome {
      ManagedGatewayOutcome::Response { response, .. } => Ok(ControlledRawResponse {
        response: response.into(),
        semantic_completion,
      }),
      ManagedGatewayOutcome::CoolingDown { retry_at, .. } => Err(Error::CoolingDown {
        profile: self.source.profile.to_string(),
        retry_at,
      }),
      ManagedGatewayOutcome::NoEligible { reason, .. } => Err(Error::NoEligible {
        profile: self.source.profile.to_string(),
        reason: reason.to_string(),
      }),
    }
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

fn load_snapshot(source: &Source, request_events: RequestLifecycleEmitter) -> Result<Snapshot> {
  let compiled = tokn_config::v2::load(&source.config_path).map_err(|error| Error::LoadConfig {
    path: source.config_path.clone(),
    source: Box::new(error),
  })?;
  let profile = compiled
    .gateway()
    .profile(&source.profile)
    .ok_or_else(|| Error::UnknownProfile {
      profile: source.profile.to_string(),
    })?;
  if let Some(route) = compiled.gateway().route(profile.route()) {
    let kind = route.kind();
    if kind != RouteKind::Managed {
      return Err(Error::NonManagedProfile {
        profile: source.profile.to_string(),
        route: profile.route().to_string(),
        kind,
      });
    }
  }

  let credentials =
    AuthStore::load(Some(&source.auth_path), Some(&source.config_path)).map_err(|error| Error::LoadCredentials {
      path: source.auth_path.clone(),
      source: error,
    })?;
  let roots = EmbeddedProfileRoots::one(source.profile.clone());
  let runtime = link_builtin_gateway_runtime_with_profile_roots(compiled.gateway(), &credentials.accounts, &roots)
    .map_err(|source| Error::LinkRuntime {
      source: Box::new(source),
    })?;
  let http_options = compiled.service().outbound().to_http_client_options();
  let body_capture_limit = compiled.service().request_limits().max_decoded_bytes();
  let gateway =
    ManagedGatewayExecutor::build_with_events(Arc::new(runtime), &http_options, request_events, body_capture_limit)
      .map_err(|source| Error::BuildExecutor { source })?;

  Ok(Snapshot { gateway })
}

fn request_headers(options: &RequestOptions) -> Result<HeaderMap> {
  let mut headers = HeaderMap::new();
  for (name, value) in &options.headers {
    insert_header(&mut headers, name, value)?;
  }
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
  headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
  insert_option(&mut headers, "x-request-id", options.request_id.as_deref())?;
  insert_option(&mut headers, "x-session-id", options.session_id.as_deref())?;
  insert_option(&mut headers, "x-project-cwd", options.project_id.as_deref())?;
  insert_option(&mut headers, "x-initiator", options.initiator.as_deref())?;
  Ok(headers)
}

fn insert_option(headers: &mut HeaderMap, name: &'static str, value: Option<&str>) -> Result<()> {
  if let Some(value) = value {
    insert_header(headers, name, value)?;
  }
  Ok(())
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<()> {
  let header_name = name.parse::<HeaderName>().map_err(|source| Error::InvalidHeaderName {
    name: name.to_owned(),
    source,
  })?;
  let header_value = value
    .parse::<HeaderValue>()
    .map_err(|source| Error::InvalidHeaderValue {
      name: name.to_owned(),
      source,
    })?;
  headers.insert(header_name, header_value);
  Ok(())
}

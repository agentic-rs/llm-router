use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("failed to resolve the default gateway configuration path")]
  ResolveConfigPath {
    #[source]
    source: tokn_config::Error,
  },
  #[error("failed to load version 2 gateway configuration from {path}")]
  LoadConfig {
    path: PathBuf,
    #[source]
    source: Box<tokn_config::v2::Error>,
  },
  #[error("failed to load credentials from {path}")]
  LoadCredentials {
    path: PathBuf,
    #[source]
    source: anyhow::Error,
  },
  #[error("invalid SDK profile id '{profile}'")]
  InvalidProfileId {
    profile: String,
    #[source]
    source: tokn_policy::InvalidIdentifier,
  },
  #[error("unknown SDK profile '{profile}'")]
  UnknownProfile { profile: String },
  #[error("SDK profile '{profile}' uses {kind:?} route '{route}'; the embedded SDK requires a managed route")]
  NonManagedProfile {
    profile: String,
    route: String,
    kind: tokn_policy::RouteKind,
  },
  #[error("failed to link the SDK profile runtime")]
  LinkRuntime {
    #[source]
    source: Box<tokn_router::runtime::GatewayLinkError>,
  },
  #[error("failed to build the SDK managed executor")]
  BuildExecutor {
    #[source]
    source: tokn_router::runtime::ManagedGatewayBuildError,
  },
  #[error("invalid request header name '{name}'")]
  InvalidHeaderName {
    name: String,
    #[source]
    source: http::header::InvalidHeaderName,
  },
  #[error("invalid value for request header '{name}'")]
  InvalidHeaderValue {
    name: String,
    #[source]
    source: http::header::InvalidHeaderValue,
  },
  #[error("failed to serialize request")]
  SerializeRequest {
    #[source]
    source: serde_json::Error,
  },
  #[error("failed to deserialize response")]
  DeserializeResponse {
    #[source]
    source: serde_json::Error,
  },
  #[error("invalid generation request: {message}")]
  InvalidGenerateRequest { message: String },
  #[error("failed to build provider-neutral generation request")]
  BuildGenerateRequest {
    #[source]
    source: tokn_convert::error::ConvertError,
  },
  #[error("generation request failed with HTTP status {status}: {body}")]
  GenerateResponseStatus { status: u16, body: String },
  #[error("generation stream failed: {message}")]
  GenerateStream { message: String },
  #[error("failed to deserialize generation stream event")]
  DeserializeStreamEvent {
    #[source]
    source: serde_json::Error,
  },
  #[error("managed SDK request failed")]
  ManagedRequest {
    #[source]
    source: Box<tokn_router::runtime::ManagedGatewayError>,
  },
  #[error("all targets for SDK profile '{profile}' are cooling down until {retry_at:?}")]
  CoolingDown { profile: String, retry_at: Instant },
  #[error("SDK profile '{profile}' found no eligible target: {reason}")]
  NoEligible { profile: String, reason: String },
  #[error("expected a buffered response but received a stream; use the endpoint's stream method")]
  UnexpectedStream,
  #[error("expected a streaming response but received a buffered body")]
  UnexpectedBuffered,
}

pub type Result<T> = std::result::Result<T, Error>;

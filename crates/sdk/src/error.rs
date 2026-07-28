use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("failed to load configuration")]
  LoadConfig {
    #[source]
    source: tokn_config::Error,
  },
  #[error("failed to load credentials from {path}")]
  LoadCredentials {
    path: PathBuf,
    #[source]
    source: anyhow::Error,
  },
  #[error("failed to build the provider engine")]
  BuildEngine {
    #[source]
    source: anyhow::Error,
  },
  #[error("unknown SDK profile '{profile}'")]
  UnknownProfile { profile: String },
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
  #[error("request pipeline failed")]
  Pipeline {
    #[source]
    source: tokn_requests::PipelineError,
  },
  #[error("expected a buffered response but received a stream; use the endpoint's stream method")]
  UnexpectedStream,
  #[error("expected a streaming response but received a buffered body")]
  UnexpectedBuffered,
}

pub type Result<T> = std::result::Result<T, Error>;

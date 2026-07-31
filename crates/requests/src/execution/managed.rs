//! Policy-free one-attempt transport for structured managed routes.
//!
//! Dispatch has already selected the exact account, provider target, model,
//! and operation. This module prepares that structured request and invokes the
//! selected provider exactly once. It does not resolve, retry, settle account
//! state, or consume the returned response body.

use super::ManagedExecutionTarget;
use crate::utils::codec::CodecError;
use bytes::Bytes;
use snafu::Snafu;
use tokn_accounts::link::SelectionOutcome;
use tokn_convert::error::ConvertError;
use tokn_core::provider::{Endpoint, Error as ProviderError};
use tokn_headers::HeaderMap;

/// Borrowed structured input for exactly one selected managed attempt.
#[derive(Clone, Copy, Debug)]
pub struct ManagedHttpAttempt<'a> {
  target: ManagedExecutionTarget<'a>,
  headers: &'a HeaderMap,
  body: &'a Bytes,
}

impl<'a> ManagedHttpAttempt<'a> {
  pub fn new(target: ManagedExecutionTarget<'a>, headers: &'a HeaderMap, body: &'a Bytes) -> Self {
    Self { target, headers, body }
  }

  pub fn target(&self) -> ManagedExecutionTarget<'a> {
    self.target
  }

  pub fn headers(&self) -> &'a HeaderMap {
    self.headers
  }

  pub fn body(&self) -> &'a Bytes {
    self.body
  }
}

/// Request/response protocol facts retained beside a live managed response.
///
/// Requested and upstream streaming modes are intentionally separate. A
/// provider transformer may change the upstream protocol (Codex forces SSE),
/// while the downstream adapter must still honor the client's requested mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedResponseMetadata {
  requested_operation: Endpoint,
  upstream_operation: Endpoint,
  requested_stream: bool,
  upstream_stream: bool,
}

impl ManagedResponseMetadata {
  pub fn requested_operation(&self) -> Endpoint {
    self.requested_operation
  }

  pub fn upstream_operation(&self) -> Endpoint {
    self.upstream_operation
  }

  pub fn requested_stream(&self) -> bool {
    self.requested_stream
  }

  pub fn upstream_stream(&self) -> bool {
    self.upstream_stream
  }
}

/// A final managed response head with its still-live body and protocol facts.
#[derive(Debug)]
pub struct ManagedHttpResponse {
  response: reqwest::Response,
  metadata: ManagedResponseMetadata,
}

impl ManagedHttpResponse {
  pub fn response(&self) -> &reqwest::Response {
    &self.response
  }

  pub fn metadata(&self) -> ManagedResponseMetadata {
    self.metadata
  }

  pub fn selection_outcome(&self) -> SelectionOutcome {
    super::classify_selection_outcome(self.response.status())
  }

  pub fn into_parts(self) -> (reqwest::Response, ManagedResponseMetadata) {
    (self.response, self.metadata)
  }
}

/// A failure before the selected generation endpoint returned a final head.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagedAttemptError {
  #[snafu(display("invalid managed request body: {source}"))]
  InvalidRequest { source: CodecError },

  #[snafu(display("managed request body must be a JSON object"))]
  BodyObjectRequired,

  #[snafu(display(
    "managed dispatch expected model '{expected_model}', but the request body contains {}",
    actual_model.as_deref().unwrap_or("no string model")
  ))]
  DispatchBodyMismatch {
    expected_model: String,
    actual_model: Option<String>,
  },

  #[snafu(display("could not convert managed request from {from} to {to}: {source}"))]
  RequestConversion {
    from: Endpoint,
    to: Endpoint,
    source: ConvertError,
  },

  #[snafu(display("provider '{provider}' could not transform managed request: {source}"))]
  InputTransform { provider: String, source: ProviderError },

  #[snafu(display("could not serialize managed request: {source}"))]
  RequestSerialization { source: serde_json::Error },

  #[snafu(display("could not encode managed request: {source}"))]
  RequestEncoding { source: CodecError },

  #[snafu(display("provider '{provider}' could not send managed request: {source}"))]
  ProviderRequest { provider: String, source: ProviderError },
}

impl ManagedAttemptError {
  /// Pool outcome appropriate for a failure before a final response head.
  pub fn selection_outcome(&self) -> SelectionOutcome {
    match self {
      Self::ProviderRequest { source, .. } => classify_provider_error(source),
      Self::InvalidRequest { .. }
      | Self::BodyObjectRequired
      | Self::DispatchBodyMismatch { .. }
      | Self::RequestConversion { .. }
      | Self::InputTransform { .. }
      | Self::RequestSerialization { .. }
      | Self::RequestEncoding { .. } => SelectionOutcome::Unchanged,
    }
  }
}

/// One-attempt structured executor. Construct `http` with
/// [`tokn_core::util::http::build_managed_client`] so redirects cannot leave
/// the selected upstream while managed response decompression remains active.
#[derive(Clone, Debug)]
pub struct ManagedHttpExecutor {
  http: reqwest::Client,
}

impl ManagedHttpExecutor {
  pub fn new(http: reqwest::Client) -> Self {
    Self { http }
  }

  pub fn http(&self) -> &reqwest::Client {
    &self.http
  }
}

fn classify_provider_error(error: &ProviderError) -> SelectionOutcome {
  match error {
    ProviderError::HttpStatus { status, .. } if *status == reqwest::StatusCode::UNAUTHORIZED => {
      SelectionOutcome::Unauthorized
    }
    ProviderError::MissingCredential { .. }
    | ProviderError::Http { .. }
    | ProviderError::HttpStatus { .. }
    | ProviderError::Json { .. }
    | ProviderError::DeviceCodeExpired
    | ProviderError::AccessDenied
    | ProviderError::OAuth { .. }
    | ProviderError::OAuthUnexpected { .. } => SelectionOutcome::Unavailable,
    ProviderError::ProviderMismatch { .. }
    | ProviderError::UnknownProvider { .. }
    | ProviderError::InvalidUpstreamUrl { .. }
    | ProviderError::InvalidOperationPath { .. }
    | ProviderError::HeaderValue { .. }
    | ProviderError::HeaderName { .. }
    | ProviderError::UnsupportedEndpoint { .. }
    | ProviderError::Profiles { .. } => SelectionOutcome::Unchanged,
  }
}

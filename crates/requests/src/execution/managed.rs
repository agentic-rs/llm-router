//! Policy-free one-attempt transport for structured managed routes.
//!
//! Dispatch has already selected the exact account, provider target, model,
//! and operation. This module prepares that structured request and invokes the
//! selected provider exactly once. It does not resolve, retry, settle account
//! state, or consume the returned response body.

use super::ManagedExecutionTarget;
use crate::utils::codec::{decode_json_request, encode_body_bytes, CodecError, ContentEncodingKind};
use bytes::Bytes;
use serde_json::Value;
use snafu::Snafu;
use tokn_accounts::link::SelectionOutcome;
use tokn_convert::error::ConvertError;
use tokn_convert::value::messages::DEFAULT_MESSAGES_MAX_TOKENS;
use tokn_core::pipeline::InputTransformer;
use tokn_core::provider::{Endpoint, Error as ProviderError, RequestCtx};
use tokn_core::AgentId;
use tokn_headers::inbound::build_template_vars;
use tokn_headers::registry::build_wire_identity_headers;
use tokn_headers::{HeaderMap, TemplateVars};

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

  /// Prepare and send one request through the exact provider binding selected
  /// by dispatch. Every received HTTP status is returned as a response.
  pub async fn execute(&self, attempt: ManagedHttpAttempt<'_>) -> Result<ManagedHttpResponse, ManagedAttemptError> {
    let target = attempt.target();
    let selected = target.target();
    let provider = selected.binding().provider().clone();
    let provider_id = provider.info().id.clone();
    let prepared = prepare_managed_request(
      PrepareInput {
        requested_model: target.requested_model(),
        requested_operation: target.requested_operation(),
        upstream_model: selected.model(),
        upstream_operation: selected.operation(),
        headers: attempt.headers(),
        body: attempt.body(),
        wire_identity: target.wire_identity(),
      },
      provider.info().id.as_str(),
      provider.input_transformer(),
    )?;
    let metadata = ManagedResponseMetadata {
      requested_operation: target.requested_operation(),
      upstream_operation: selected.operation(),
      requested_stream: prepared.requested_stream,
      upstream_stream: prepared.upstream_stream,
    };
    let request = RequestCtx {
      endpoint: selected.operation(),
      http: &self.http,
      body: &prepared.body,
      body_bytes: Some(&prepared.wire_body),
      content_encoding: prepared.encoding.map(ContentEncodingKind::as_str),
      stream: prepared.upstream_stream,
      initiator: prepared.initiator.as_deref().unwrap_or("user"),
      inbound_headers: attempt.headers(),
      client_headers: Some(prepared.client_headers),
      outbound: None,
      vars: prepared.vars,
      wire_identity: target.wire_identity().cloned(),
    };

    let response = match selected.operation() {
      Endpoint::ChatCompletions => provider.chat(request).await,
      Endpoint::Responses => provider.responses(request).await,
      Endpoint::Messages => provider.messages(request).await,
    }
    .map_err(|source| ManagedAttemptError::ProviderRequest {
      provider: provider_id,
      source,
    })?;

    Ok(ManagedHttpResponse { response, metadata })
  }
}

#[derive(Clone, Copy)]
struct PrepareInput<'a> {
  requested_model: &'a str,
  requested_operation: Endpoint,
  upstream_model: &'a str,
  upstream_operation: Endpoint,
  headers: &'a HeaderMap,
  body: &'a Bytes,
  wire_identity: Option<&'a AgentId>,
}

struct PreparedManagedRequest {
  body: Value,
  wire_body: Bytes,
  encoding: Option<ContentEncodingKind>,
  requested_stream: bool,
  upstream_stream: bool,
  initiator: Option<String>,
  client_headers: HeaderMap,
  vars: TemplateVars,
}

fn prepare_managed_request(
  input: PrepareInput<'_>,
  provider_id: &str,
  transformer: Option<&dyn InputTransformer>,
) -> Result<PreparedManagedRequest, ManagedAttemptError> {
  let decoded = decode_json_request(input.headers, input.body.clone())
    .map_err(|source| ManagedAttemptError::InvalidRequest { source })?;
  let Some(original) = decoded.value.as_object() else {
    return Err(ManagedAttemptError::BodyObjectRequired);
  };
  let actual_model = original.get("model").and_then(Value::as_str);
  if actual_model != Some(input.requested_model) {
    return Err(ManagedAttemptError::DispatchBodyMismatch {
      expected_model: input.requested_model.to_string(),
      actual_model: actual_model.map(str::to_string),
    });
  }

  let requested_stream = infer_stream(input.headers, &decoded.value);
  let initiator = infer_initiator(input.headers, &decoded.value);
  let mut upstream_body = decoded.value.clone();
  apply_messages_compat_default(input.requested_operation, &mut upstream_body);
  upstream_body
    .as_object_mut()
    .expect("object shape checked above")
    .insert("model".into(), Value::String(input.upstream_model.to_string()));

  if input.requested_operation != input.upstream_operation {
    upstream_body = tokn_convert::convert_request(input.requested_operation, input.upstream_operation, &upstream_body)
      .map_err(|source| ManagedAttemptError::RequestConversion {
        from: input.requested_operation,
        to: input.upstream_operation,
        source,
      })?;
  }
  if let Some(transformer) = transformer {
    upstream_body = transformer
      .transform_input(input.upstream_operation, upstream_body)
      .map_err(|source| ManagedAttemptError::InputTransform {
        provider: provider_id.to_string(),
        source,
      })?;
  }
  let upstream_stream = upstream_body
    .get("stream")
    .and_then(Value::as_bool)
    .unwrap_or(requested_stream);
  let wire_body = if upstream_body == decoded.value {
    decoded.raw_body
  } else {
    let serialized =
      serde_json::to_vec(&upstream_body).map_err(|source| ManagedAttemptError::RequestSerialization { source })?;
    encode_body_bytes(&serialized, decoded.encoding)
      .map_err(|source| ManagedAttemptError::RequestEncoding { source })?
  };
  let vars = build_template_vars(input.headers);
  let client_headers = input
    .wire_identity
    .map(|identity| build_wire_identity_headers(provider_id, identity.as_str(), &vars, input.headers))
    .unwrap_or_default();

  Ok(PreparedManagedRequest {
    body: upstream_body,
    wire_body,
    encoding: decoded.encoding,
    requested_stream,
    upstream_stream,
    initiator,
    client_headers,
    vars,
  })
}

fn apply_messages_compat_default(endpoint: Endpoint, body: &mut Value) {
  if endpoint != Endpoint::Messages {
    return;
  }
  let Some(object) = body.as_object_mut() else {
    return;
  };
  object
    .entry("max_tokens")
    .or_insert_with(|| Value::from(DEFAULT_MESSAGES_MAX_TOKENS));
}

fn infer_stream(headers: &HeaderMap, body: &Value) -> bool {
  body.get("stream").and_then(Value::as_bool).unwrap_or_else(|| {
    headers.get_all("accept").any(|value| {
      value.as_str().split(',').any(|part| {
        part
          .split(';')
          .next()
          .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
      })
    })
  })
}

fn infer_initiator(headers: &HeaderMap, body: &Value) -> Option<String> {
  if let Some(header) = headers.get("x-initiator") {
    let value = header.as_str().trim().to_ascii_lowercase();
    if matches!(value.as_str(), "user" | "agent") {
      return Some(value);
    }
  }
  let inferred = if body.get("input").is_some() {
    tokn_core::util::initiator::classify_initiator_responses(body)
  } else {
    tokn_core::util::initiator::classify_initiator(body).or_else(|| {
      body
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| !tools.is_empty())
        .then_some("agent")
    })
  };
  inferred.map(str::to_string)
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

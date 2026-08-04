//! Policy-free one-attempt transport for structured managed routes.
//!
//! Dispatch has already selected the exact account, provider target, model,
//! and operation. This module prepares that structured request and invokes the
//! selected provider exactly once. It does not resolve, retry, settle account
//! state, or consume the returned response body.

mod response;

pub use response::{ManagedClientBody, ManagedClientResponse, ManagedResponseAdapter, ManagedResponseError};

use super::{
  ensure_model_supports_reasoning, lower_generation_options, GenerationControlError, ManagedExecutionTarget,
};
use bytes::Bytes;
use serde_json::Value;
use snafu::Snafu;
use tokn_accounts::link::SelectionOutcome;
use tokn_convert::error::ConvertError;
use tokn_convert::value::messages::DEFAULT_MESSAGES_MAX_TOKENS;
use tokn_core::generation::GenerationOptions;
use tokn_core::provider::{
  Endpoint, Error as ProviderError, InputTransformer, OutboundRequestObserver, Provider, RequestCtx,
};
use tokn_core::AgentId;
use tokn_headers::inbound::build_template_vars;
use tokn_headers::registry::build_wire_identity_headers;
use tokn_headers::{HeaderMap, TemplateVars};

/// Borrowed structured input for exactly one selected managed attempt.
///
/// Ingress has already decoded any content encoding and parsed `body`. Managed
/// execution therefore works only from this authoritative semantic JSON value.
#[derive(Clone, Copy, Debug)]
pub struct ManagedHttpAttempt<'a> {
  target: ManagedExecutionTarget<'a>,
  headers: &'a HeaderMap,
  body: &'a Value,
  generation_options: Option<&'a GenerationOptions>,
}

impl<'a> ManagedHttpAttempt<'a> {
  pub fn new(target: ManagedExecutionTarget<'a>, headers: &'a HeaderMap, body: &'a Value) -> Self {
    Self {
      target,
      headers,
      body,
      generation_options: None,
    }
  }

  /// Apply typed, provider-neutral controls during managed preparation.
  pub fn with_generation_options(mut self, generation_options: &'a GenerationOptions) -> Self {
    self.generation_options = Some(generation_options);
    self
  }

  pub fn target(&self) -> ManagedExecutionTarget<'a> {
    self.target
  }

  pub fn headers(&self) -> &'a HeaderMap {
    self.headers
  }

  pub fn body(&self) -> &'a Value {
    self.body
  }

  pub fn generation_options(&self) -> Option<&'a GenerationOptions> {
    self.generation_options
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
  pub fn new(
    requested_operation: Endpoint,
    upstream_operation: Endpoint,
    requested_stream: bool,
    upstream_stream: bool,
  ) -> Self {
    Self {
      requested_operation,
      upstream_operation,
      requested_stream,
      upstream_stream,
    }
  }

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
  pub fn new(response: reqwest::Response, metadata: ManagedResponseMetadata) -> Self {
    Self { response, metadata }
  }

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

  #[snafu(display("managed generation controls could not be applied: {source}"))]
  GenerationControl { source: GenerationControlError },

  #[snafu(display("provider '{provider}' could not transform managed request: {source}"))]
  InputTransform { provider: String, source: ProviderError },

  #[snafu(display("could not serialize managed request: {source}"))]
  RequestSerialization { source: serde_json::Error },

  #[snafu(display("provider '{provider}' could not send managed request: {source}"))]
  ProviderRequest { provider: String, source: ProviderError },
}

impl ManagedAttemptError {
  /// Pool outcome appropriate for a failure before a final response head.
  pub fn selection_outcome(&self) -> SelectionOutcome {
    match self {
      Self::ProviderRequest { source, .. } => classify_provider_error(source),
      Self::BodyObjectRequired
      | Self::DispatchBodyMismatch { .. }
      | Self::RequestConversion { .. }
      | Self::GenerationControl { .. }
      | Self::InputTransform { .. }
      | Self::RequestSerialization { .. } => SelectionOutcome::Unchanged,
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
    self.execute_observed(attempt, None).await
  }

  /// Execute with an optional observer for the provider-prepared reqwest request
  /// immediately before dispatch.
  pub async fn execute_observed(
    &self,
    attempt: ManagedHttpAttempt<'_>,
    request_observer: Option<&mut dyn OutboundRequestObserver>,
  ) -> Result<ManagedHttpResponse, ManagedAttemptError> {
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
        generation_options: attempt.generation_options(),
        wire_identity: target.wire_identity(),
      },
      PrepareProvider::for_selected_model(provider.as_ref(), selected.model()),
    )?;
    let metadata = ManagedResponseMetadata::new(
      target.requested_operation(),
      selected.operation(),
      prepared.requested_stream,
      prepared.upstream_stream,
    );
    let response = match request_observer {
      Some(observer) => {
        send_prepared_managed(
          &self.http,
          provider.as_ref(),
          selected.operation(),
          attempt.headers(),
          &prepared,
          target.wire_identity().cloned(),
          Some(&mut *observer),
        )
        .await
      }
      None => {
        send_prepared_managed(
          &self.http,
          provider.as_ref(),
          selected.operation(),
          attempt.headers(),
          &prepared,
          target.wire_identity().cloned(),
          None,
        )
        .await
      }
    }
    .map_err(|source| ManagedAttemptError::ProviderRequest {
      provider: provider_id,
      source,
    })?;

    Ok(ManagedHttpResponse::new(response, metadata))
  }
}

async fn send_prepared_managed<'a>(
  http: &'a reqwest::Client,
  provider: &'a dyn Provider,
  endpoint: Endpoint,
  inbound_headers: &'a HeaderMap,
  prepared: &'a PreparedManagedRequest,
  wire_identity: Option<AgentId>,
  request_observer: Option<&'a mut dyn OutboundRequestObserver>,
) -> Result<reqwest::Response, ProviderError> {
  let request = RequestCtx {
    endpoint,
    http,
    body: &prepared.body,
    body_bytes: Some(&prepared.wire_body),
    content_encoding: None,
    stream: prepared.upstream_stream,
    initiator: prepared.initiator.as_deref().unwrap_or("user"),
    inbound_headers,
    client_headers: Some(prepared.client_headers.clone()),
    vars: prepared.vars.clone(),
    wire_identity,
    request_observer,
  };
  match endpoint {
    Endpoint::ChatCompletions => provider.chat(request).await,
    Endpoint::Responses => provider.responses(request).await,
    Endpoint::Messages => provider.messages(request).await,
  }
}

#[derive(Clone, Copy)]
struct PrepareInput<'a> {
  requested_model: &'a str,
  requested_operation: Endpoint,
  upstream_model: &'a str,
  upstream_operation: Endpoint,
  headers: &'a HeaderMap,
  body: &'a Value,
  generation_options: Option<&'a GenerationOptions>,
  wire_identity: Option<&'a AgentId>,
}

#[derive(Clone, Copy)]
struct PrepareProvider<'a> {
  id: &'a str,
  reasoning_supported: Option<bool>,
  transformer: Option<&'a dyn InputTransformer>,
}

impl<'a> PrepareProvider<'a> {
  fn for_selected_model(provider: &'a dyn Provider, upstream_model: &str) -> Self {
    Self {
      id: provider.info().id.as_str(),
      reasoning_supported: provider
        .model_info(upstream_model)
        .map(|model| model.capabilities.reasoning),
      transformer: provider.input_transformer(),
    }
  }
}

struct PreparedManagedRequest {
  body: Value,
  wire_body: Bytes,
  requested_stream: bool,
  upstream_stream: bool,
  initiator: Option<String>,
  client_headers: HeaderMap,
  vars: TemplateVars,
}

fn prepare_managed_request(
  input: PrepareInput<'_>,
  provider: PrepareProvider<'_>,
) -> Result<PreparedManagedRequest, ManagedAttemptError> {
  let Some(original) = input.body.as_object() else {
    return Err(ManagedAttemptError::BodyObjectRequired);
  };
  let actual_model = original.get("model").and_then(Value::as_str);
  if actual_model != Some(input.requested_model) {
    return Err(ManagedAttemptError::DispatchBodyMismatch {
      expected_model: input.requested_model.to_string(),
      actual_model: actual_model.map(str::to_string),
    });
  }

  let requested_stream = infer_stream(input.headers, input.body);
  let initiator = infer_initiator(input.headers, input.body);
  let mut upstream_body = input.body.clone();
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
  if let Some(options) = input.generation_options {
    options
      .validate()
      .map_err(|source| GenerationControlError::InvalidOptions { source })
      .map_err(generation_control_error)?;
    ensure_model_supports_reasoning(
      input.upstream_operation,
      provider.id,
      provider.reasoning_supported,
      options,
    )
    .map_err(generation_control_error)?;
    lower_generation_options(
      &mut upstream_body,
      input.upstream_operation,
      provider.id,
      input.upstream_model,
      options,
    )
    .map_err(generation_control_error)?;
  }
  if let Some(transformer) = provider.transformer {
    upstream_body = transformer
      .transform_input(input.upstream_operation, upstream_body)
      .map_err(|source| ManagedAttemptError::InputTransform {
        provider: provider.id.to_string(),
        source,
      })?;
  }
  let upstream_stream = upstream_body
    .get("stream")
    .and_then(Value::as_bool)
    .unwrap_or(requested_stream);
  let wire_body = serde_json::to_vec(&upstream_body)
    .map(Bytes::from)
    .map_err(|source| ManagedAttemptError::RequestSerialization { source })?;
  let vars = build_template_vars(input.headers);
  let client_headers = input
    .wire_identity
    .map(|identity| build_wire_identity_headers(provider.id, identity.as_str(), &vars, input.headers))
    .unwrap_or_default();

  Ok(PreparedManagedRequest {
    body: upstream_body,
    wire_body,
    requested_stream,
    upstream_stream,
    initiator,
    client_headers,
    vars,
  })
}

fn generation_control_error(source: GenerationControlError) -> ManagedAttemptError {
  ManagedAttemptError::GenerationControl { source }
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
    | ProviderError::RequestObservation { .. }
    | ProviderError::UnsupportedEndpoint { .. }
    | ProviderError::Profiles { .. } => SelectionOutcome::Unchanged,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::provider;
  use tokn_headers::{HeaderName, HeaderValue};

  struct ForceStream;

  impl InputTransformer for ForceStream {
    fn transform_input(&self, _endpoint: Endpoint, mut body: Value) -> provider::Result<Value> {
      body.as_object_mut().unwrap().insert("stream".into(), Value::Bool(true));
      Ok(body)
    }
  }

  struct AssertGenerationLowered;

  impl InputTransformer for AssertGenerationLowered {
    fn transform_input(&self, endpoint: Endpoint, mut body: Value) -> provider::Result<Value> {
      assert_eq!(endpoint, Endpoint::ChatCompletions);
      assert_eq!(body["model"], "upstream-model");
      assert!(body.get("messages").is_some());
      assert_eq!(body["top_k"], 40);
      body
        .as_object_mut()
        .unwrap()
        .insert("transformer_saw_generation".into(), Value::Bool(true));
      Ok(body)
    }
  }

  fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
      headers.insert(HeaderName::new(*name), HeaderValue::from_string((*value).to_string()));
    }
    headers
  }

  fn input<'a>(
    headers: &'a HeaderMap,
    body: &'a Value,
    requested_operation: Endpoint,
    upstream_operation: Endpoint,
  ) -> PrepareInput<'a> {
    PrepareInput {
      requested_model: "client-model",
      requested_operation,
      upstream_model: "upstream-model",
      upstream_operation,
      headers,
      body,
      generation_options: None,
      wire_identity: None,
    }
  }

  fn prepare_provider<'a>(id: &'a str, transformer: Option<&'a dyn InputTransformer>) -> PrepareProvider<'a> {
    PrepareProvider {
      id,
      reasoning_supported: None,
      transformer,
    }
  }

  #[test]
  fn preparation_rewrites_model_serializes_identity_json_and_tracks_both_stream_modes() {
    let body = serde_json::json!({
      "model": "client-model",
      "input": "hello",
      "stream": false
    });
    let headers = headers(&[("Content-Encoding", "gzip"), ("X-Initiator", " Agent ")]);

    let prepared = prepare_managed_request(
      input(&headers, &body, Endpoint::Responses, Endpoint::Responses),
      prepare_provider("codex", Some(&ForceStream)),
    )
    .unwrap();

    assert_eq!(prepared.body["model"], "upstream-model");
    assert_eq!(prepared.body["stream"], true);
    assert!(!prepared.requested_stream);
    assert!(prepared.upstream_stream);
    assert_eq!(prepared.initiator.as_deref(), Some("agent"));
    assert!(prepared.client_headers.is_empty());
    let round_trip: Value = serde_json::from_slice(&prepared.wire_body).unwrap();
    assert_eq!(round_trip, prepared.body);
    assert_eq!(
      prepared.wire_body,
      Bytes::from(serde_json::to_vec(&prepared.body).unwrap())
    );
  }

  #[test]
  fn preparation_converts_operation_after_rewriting_model() {
    let body = serde_json::json!({
      "model": "client-model",
      "input": [{"role": "user", "content": "hello"}],
      "stream": true
    });
    let prepared = prepare_managed_request(
      input(&HeaderMap::new(), &body, Endpoint::Responses, Endpoint::ChatCompletions),
      prepare_provider("llama-cpp", None),
    )
    .unwrap();

    assert_eq!(prepared.body["model"], "upstream-model");
    assert!(prepared.body.get("messages").is_some());
    assert!(prepared.requested_stream);
    assert!(prepared.upstream_stream);
  }

  #[test]
  fn generation_lowering_runs_after_conversion_and_before_input_transformer() {
    let body = serde_json::json!({
      "model": "client-model",
      "input": [{"role": "user", "content": "hello"}]
    });
    let options = GenerationOptions::new().with_top_k(40);
    let headers = HeaderMap::new();
    let mut input = input(&headers, &body, Endpoint::Responses, Endpoint::ChatCompletions);
    input.generation_options = Some(&options);

    let prepared =
      prepare_managed_request(input, prepare_provider("llama-cpp", Some(&AssertGenerationLowered))).unwrap();

    assert_eq!(prepared.body["transformer_saw_generation"], true);
  }

  #[test]
  fn generation_lowering_uses_selected_provider_dialect() {
    let body = serde_json::json!({
      "model": "client-model",
      "messages": [{"role": "user", "content": "hello"}],
      "max_tokens": 32
    });
    let options = GenerationOptions::new().with_max_output_tokens(256);
    let headers = HeaderMap::new();
    let mut input = input(&headers, &body, Endpoint::ChatCompletions, Endpoint::ChatCompletions);
    input.generation_options = Some(&options);

    let prepared = prepare_managed_request(input, prepare_provider("openai", None)).unwrap();

    assert_eq!(prepared.body["max_completion_tokens"], 256);
    assert!(prepared.body.get("max_tokens").is_none());
  }

  #[test]
  fn selected_model_capability_failure_is_local() {
    let body = serde_json::json!({
      "model": "client-model",
      "messages": [{"role": "user", "content": "hello"}]
    });
    let options = GenerationOptions::new().with_reasoning(
      tokn_core::generation::ReasoningOptions::new().with_effort(tokn_core::generation::ReasoningEffort::High),
    );
    let headers = HeaderMap::new();
    let mut input = input(&headers, &body, Endpoint::ChatCompletions, Endpoint::ChatCompletions);
    input.generation_options = Some(&options);
    let selected_provider = PrepareProvider {
      id: "openai",
      reasoning_supported: Some(false),
      transformer: None,
    };

    let error = prepare_managed_request(input, selected_provider)
      .err()
      .expect("known non-reasoning model must reject typed reasoning");

    assert!(matches!(
      &error,
      ManagedAttemptError::GenerationControl {
        source: GenerationControlError::UnsupportedControl {
          control: "reasoning",
          provider_id,
          endpoint: Endpoint::ChatCompletions,
          ..
        }
      } if provider_id == "openai"
    ));
    assert_eq!(error.selection_outcome(), SelectionOutcome::Unchanged);
  }

  #[test]
  fn unchanged_preparation_serializes_the_parsed_body() {
    let body = serde_json::json!({"model": "client-model", "messages": []});
    let headers = HeaderMap::new();
    let mut input = input(&headers, &body, Endpoint::ChatCompletions, Endpoint::ChatCompletions);
    input.upstream_model = "client-model";

    let prepared = prepare_managed_request(input, prepare_provider("llama-cpp", None)).unwrap();

    assert_eq!(prepared.body, body);
    assert_eq!(prepared.wire_body, Bytes::from(serde_json::to_vec(&body).unwrap()));
  }

  #[test]
  fn messages_default_is_applied_before_sending() {
    let body = serde_json::json!({"model": "client-model", "messages": []});
    let prepared = prepare_managed_request(
      input(&HeaderMap::new(), &body, Endpoint::Messages, Endpoint::Messages),
      prepare_provider("deepseek", None),
    )
    .unwrap();

    assert_eq!(prepared.body["max_tokens"], DEFAULT_MESSAGES_MAX_TOKENS);
  }

  #[test]
  fn dispatch_body_mismatch_is_local_and_does_not_penalize_selection() {
    let body = serde_json::json!({"model": "different"});
    let error = prepare_managed_request(
      input(
        &HeaderMap::new(),
        &body,
        Endpoint::ChatCompletions,
        Endpoint::ChatCompletions,
      ),
      prepare_provider("openai", None),
    )
    .err()
    .unwrap();

    assert!(matches!(error, ManagedAttemptError::DispatchBodyMismatch { .. }));
    assert_eq!(error.selection_outcome(), SelectionOutcome::Unchanged);
  }

  #[test]
  fn non_object_body_is_rejected_without_penalizing_selection() {
    let body = serde_json::json!([{"model": "client-model"}]);
    let error = prepare_managed_request(
      input(
        &HeaderMap::new(),
        &body,
        Endpoint::ChatCompletions,
        Endpoint::ChatCompletions,
      ),
      prepare_provider("openai", None),
    )
    .err()
    .unwrap();

    assert!(matches!(error, ManagedAttemptError::BodyObjectRequired));
    assert_eq!(error.selection_outcome(), SelectionOutcome::Unchanged);
  }

  #[test]
  fn explicit_wire_identity_builds_headers_from_inbound_correlation() {
    let body = serde_json::json!({"model": "client-model", "messages": []});
    let headers = headers(&[("X-Session-Id", "session-1")]);
    let mut input = input(&headers, &body, Endpoint::ChatCompletions, Endpoint::ChatCompletions);
    input.wire_identity = Some(&AgentId::Opencode);

    let prepared = prepare_managed_request(input, prepare_provider("openai", None)).unwrap();

    assert!(!prepared.client_headers.is_empty());
    assert_eq!(prepared.vars.session_id.as_deref(), Some("session-1"));
  }

  #[test]
  fn token_exchange_unauthorized_penalizes_the_selected_credentials() {
    let error = ManagedAttemptError::ProviderRequest {
      provider: "copilot".into(),
      source: ProviderError::HttpStatus {
        what: "token exchange",
        status: reqwest::StatusCode::UNAUTHORIZED,
        body: "expired".into(),
      },
    };

    assert_eq!(error.selection_outcome(), SelectionOutcome::Unauthorized);
  }
}

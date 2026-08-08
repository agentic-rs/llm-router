mod response;
mod stream;

pub use response::{GenerateResponse, ToolCall, Usage};
pub use stream::{GenerateEvent, GenerateStream, TextStream};

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokn_convert::ir::{
  ContentPart as IrContentPart, IrMessage, IrRequest, Role as IrRole, Sampling, ToolCall as IrToolCall,
};
use tokn_core::generation::{GenerationOptions, ReasoningEffort, ReasoningMode, ReasoningOptions, ReasoningSummary};
use tokn_core::provider::Endpoint;
use tokn_requests::pipeline::error::RequestsError;

use crate::response::ResponseBody;
use crate::{Client, Error, RequestOptions, Result};

/// An owned, provider-neutral generation request.
///
/// The request does not borrow a [`Client`] or any builder input, so it can be
/// serialized, transformed, queued, and reused independently of a client.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenerateRequest {
  pub model: String,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub messages: Vec<Message>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub tools: Vec<Tool>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub tool_choice: Option<ToolChoice>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub temperature: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub top_p: Option<f64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub top_k: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub max_output_tokens: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub reasoning: Option<ReasoningOptions>,
  #[serde(default, skip_serializing_if = "RequestOptions::is_empty")]
  pub options: RequestOptions,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub extras: BTreeMap<String, Value>,
}

impl GenerateRequest {
  /// Start a detached request builder with a required model or configured
  /// model alias.
  pub fn builder(model: impl Into<String>) -> GenerateRequestBuilder {
    GenerateRequestBuilder {
      request: Self {
        model: model.into(),
        messages: Vec::new(),
        tools: Vec::new(),
        tool_choice: None,
        temperature: None,
        top_p: None,
        top_k: None,
        max_output_tokens: None,
        reasoning: None,
        options: RequestOptions::default(),
        extras: BTreeMap::new(),
      },
    }
  }

  /// Convert an owned request back into a detached builder for transformation.
  pub fn into_builder(self) -> GenerateRequestBuilder {
    GenerateRequestBuilder { request: self }
  }

  /// Bind this owned request to a client for fluent execution.
  pub fn bind(self, client: &Client) -> GenerateCall<'_> {
    GenerateCall { client, request: self }
  }

  /// Validate fields required by the provider-neutral generation API.
  pub fn validate(&self) -> Result<()> {
    if self.model.trim().is_empty() {
      return Err(Error::InvalidGenerateRequest {
        message: "model cannot be empty".into(),
      });
    }
    if self.messages.is_empty() {
      return Err(Error::InvalidGenerateRequest {
        message: "at least one message or prompt is required".into(),
      });
    }
    if self
      .messages
      .iter()
      .filter(|message| message.role != Role::System)
      .all(|message| message.content.is_empty() && message.tool_call_id.is_none() && message.tool_calls.is_empty())
    {
      return Err(Error::InvalidGenerateRequest {
        message: "at least one non-system message must contain content".into(),
      });
    }
    for message in &self.messages {
      if message.role != Role::Assistant && !message.tool_calls.is_empty() {
        return Err(Error::InvalidGenerateRequest {
          message: "tool calls are only valid on assistant messages".into(),
        });
      }
      if message.role == Role::Tool {
        if message.tool_call_id.as_deref().is_none_or(|id| id.trim().is_empty()) {
          return Err(Error::InvalidGenerateRequest {
            message: "tool results require a non-empty tool call id".into(),
          });
        }
      } else if message.tool_call_id.is_some() {
        return Err(Error::InvalidGenerateRequest {
          message: "tool_call_id is only valid on tool messages".into(),
        });
      }
      if message
        .tool_calls
        .iter()
        .any(|call| call.id.as_deref().is_none_or(|id| id.trim().is_empty()) || call.name.trim().is_empty())
      {
        return Err(Error::InvalidGenerateRequest {
          message: "assistant tool calls require non-empty ids and names".into(),
        });
      }
    }
    validate_finite("temperature", self.temperature)?;
    validate_finite("top_p", self.top_p)?;
    if self.top_p.is_some_and(|top_p| !(0.0..=1.0).contains(&top_p)) {
      return Err(Error::InvalidGenerateRequest {
        message: "top_p must be between 0 and 1".into(),
      });
    }
    if self.max_output_tokens == Some(0) {
      return Err(Error::InvalidGenerateRequest {
        message: "max_output_tokens must be greater than zero".into(),
      });
    }
    self
      .generation_options()
      .validate()
      .map_err(|error| Error::InvalidGenerateRequest {
        message: error.to_string(),
      })?;
    if self.reasoning.is_some() {
      const CONFLICTING_EXTRAS: &[&str] = &["reasoning", "thinking", "reasoning_effort", "output_config"];
      if let Some(name) = CONFLICTING_EXTRAS
        .iter()
        .copied()
        .find(|name| self.extras.contains_key(*name))
      {
        return Err(Error::InvalidGenerateRequest {
          message: format!("typed reasoning conflicts with extras['{name}']"),
        });
      }
    }
    if self.tools.iter().any(|tool| tool.name.trim().is_empty()) {
      return Err(Error::InvalidGenerateRequest {
        message: "tool names cannot be empty".into(),
      });
    }
    if self.tools.iter().any(|tool| !tool.parameters.is_object()) {
      return Err(Error::InvalidGenerateRequest {
        message: "tool parameters must be a JSON object".into(),
      });
    }
    if matches!(&self.tool_choice, Some(ToolChoice::Tool(name)) if name.trim().is_empty()) {
      return Err(Error::InvalidGenerateRequest {
        message: "named tool choices require a non-empty name".into(),
      });
    }
    Ok(())
  }

  fn generation_options(&self) -> GenerationOptions {
    GenerationOptions {
      max_output_tokens: self.max_output_tokens,
      top_k: self.top_k,
      reasoning: self.reasoning.clone(),
    }
  }

  fn responses_body(&self, stream: bool) -> Result<Value> {
    self.validate()?;
    let mut system = Vec::new();
    let mut messages = Vec::new();
    for message in &self.messages {
      if message.role == Role::System {
        if !message.content.is_empty() {
          system.push(message.content.clone());
        }
        continue;
      }
      messages.push(message.to_ir());
    }

    let request = IrRequest {
      model: self.model.clone(),
      system: (!system.is_empty()).then(|| system.join("\n\n")),
      messages,
      tools: self.tools.iter().map(Tool::to_ir).collect(),
      tool_choice: self.tool_choice.as_ref().map(ToolChoice::to_ir_value),
      sampling: Sampling {
        temperature: self.temperature,
        top_p: self.top_p,
        max_output_tokens: self.max_output_tokens,
        stop: None,
        n: None,
        seed: None,
      },
      reasoning: None,
      stream,
      extras: self.extras.clone(),
    };
    let body = tokn_convert::value::responses::request_to_value(&request)
      .map_err(|source| Error::BuildGenerateRequest { source })?;
    Ok(body)
  }
}

fn validate_finite(name: &str, value: Option<f64>) -> Result<()> {
  if value.is_some_and(|value| !value.is_finite()) {
    return Err(Error::InvalidGenerateRequest {
      message: format!("{name} must be finite"),
    });
  }
  Ok(())
}

/// A simple provider-neutral conversation message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
  pub role: Role,
  pub content: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub tool_call_id: Option<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub tool_calls: Vec<ToolCall>,
}

impl Message {
  pub fn system(content: impl Into<String>) -> Self {
    Self::new(Role::System, content)
  }

  pub fn user(content: impl Into<String>) -> Self {
    Self::new(Role::User, content)
  }

  pub fn assistant(content: impl Into<String>) -> Self {
    Self::new(Role::Assistant, content)
  }

  pub fn tool(call_id: impl Into<String>, content: impl Into<String>) -> Self {
    Self {
      role: Role::Tool,
      content: content.into(),
      tool_call_id: Some(call_id.into()),
      tool_calls: Vec::new(),
    }
  }

  pub fn assistant_with_tool_calls(content: impl Into<String>, tool_calls: impl IntoIterator<Item = ToolCall>) -> Self {
    Self::assistant(content).with_tool_calls(tool_calls)
  }

  pub fn with_tool_call(mut self, tool_call: ToolCall) -> Self {
    self.tool_calls.push(tool_call);
    self
  }

  pub fn with_tool_calls(mut self, tool_calls: impl IntoIterator<Item = ToolCall>) -> Self {
    self.tool_calls.extend(tool_calls);
    self
  }

  pub fn new(role: Role, content: impl Into<String>) -> Self {
    Self {
      role,
      content: content.into(),
      tool_call_id: None,
      tool_calls: Vec::new(),
    }
  }

  fn to_ir(&self) -> IrMessage {
    let mut content = if self.role == Role::Tool {
      vec![IrContentPart::ToolResult {
        id: self.tool_call_id.clone(),
        content: Value::String(self.content.clone()),
      }]
    } else if self.content.is_empty() {
      Vec::new()
    } else {
      vec![IrContentPart::Text {
        text: self.content.clone(),
      }]
    };
    if self.role == Role::Assistant {
      content.extend(self.tool_calls.iter().map(|call| IrContentPart::ToolCall {
        call: IrToolCall {
          id: call.id.clone(),
          name: call.name.clone(),
          arguments: call.arguments.clone(),
        },
      }));
    }
    IrMessage {
      role: self.role.to_ir(),
      content,
      tool_call_id: self.tool_call_id.clone(),
      name: None,
      raw: None,
    }
  }
}

/// Roles supported by the provider-neutral message API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
  System,
  User,
  Assistant,
  Tool,
}

impl Role {
  fn to_ir(self) -> IrRole {
    match self {
      Self::System => IrRole::System,
      Self::User => IrRole::User,
      Self::Assistant => IrRole::Assistant,
      Self::Tool => IrRole::Tool,
    }
  }
}

/// Common provider-neutral tool selection modes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolChoice {
  Auto,
  None,
  Required,
  Tool(String),
}

impl ToolChoice {
  pub fn named(name: impl Into<String>) -> Self {
    Self::Tool(name.into())
  }

  fn to_ir_value(&self) -> Value {
    match self {
      Self::Auto => Value::String("auto".into()),
      Self::None => Value::String("none".into()),
      Self::Required => Value::String("required".into()),
      Self::Tool(name) => serde_json::json!({
        "type": "function",
        "function": {"name": name},
      }),
    }
  }
}

impl From<&str> for ToolChoice {
  fn from(value: &str) -> Self {
    match value {
      "auto" => Self::Auto,
      "none" => Self::None,
      "required" => Self::Required,
      name => Self::Tool(name.to_string()),
    }
  }
}

impl From<String> for ToolChoice {
  fn from(value: String) -> Self {
    Self::from(value.as_str())
  }
}

/// A provider-neutral function tool definition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Tool {
  pub name: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub description: Option<String>,
  #[serde(default)]
  pub parameters: Value,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub strict: Option<bool>,
}

impl Tool {
  pub fn function(name: impl Into<String>, parameters: Value) -> Self {
    Self {
      name: name.into(),
      description: None,
      parameters,
      strict: None,
    }
  }

  pub fn description(mut self, description: impl Into<String>) -> Self {
    self.description = Some(description.into());
    self
  }

  pub fn strict(mut self, strict: bool) -> Self {
    self.strict = Some(strict);
    self
  }

  fn to_ir(&self) -> Value {
    let mut function = Map::new();
    function.insert("name".into(), Value::String(self.name.clone()));
    function.insert("parameters".into(), self.parameters.clone());
    if let Some(description) = &self.description {
      function.insert("description".into(), Value::String(description.clone()));
    }
    if let Some(strict) = self.strict {
      function.insert("strict".into(), Value::Bool(strict));
    }
    serde_json::json!({
      "type": "function",
      "function": function,
    })
  }
}

/// A client-independent builder for an owned [`GenerateRequest`].
#[derive(Clone, Debug)]
#[must_use = "request builders do nothing until built or bound"]
pub struct GenerateRequestBuilder {
  request: GenerateRequest,
}

/// A generation builder bound to a client and ready to send or stream.
#[derive(Clone)]
#[must_use = "generation calls do nothing until sent or streamed"]
pub struct GenerateCall<'client> {
  client: &'client Client,
  request: GenerateRequest,
}

impl fmt::Debug for GenerateCall<'_> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("GenerateCall")
      .field("client", &"<Client>")
      .field("request", &self.request)
      .finish()
  }
}

macro_rules! generate_builder_methods {
  ($builder:ty) => {
    impl $builder {
      pub fn prompt(self, prompt: impl Into<String>) -> Self {
        self.user(prompt)
      }

      pub fn system(mut self, content: impl Into<String>) -> Self {
        self.request.messages.push(Message::system(content));
        self
      }

      pub fn user(mut self, content: impl Into<String>) -> Self {
        self.request.messages.push(Message::user(content));
        self
      }

      pub fn assistant(mut self, content: impl Into<String>) -> Self {
        self.request.messages.push(Message::assistant(content));
        self
      }

      pub fn assistant_with_tool_calls(
        mut self,
        content: impl Into<String>,
        tool_calls: impl IntoIterator<Item = ToolCall>,
      ) -> Self {
        self
          .request
          .messages
          .push(Message::assistant_with_tool_calls(content, tool_calls));
        self
      }

      pub fn tool_result(mut self, call_id: impl Into<String>, content: impl Into<String>) -> Self {
        self.request.messages.push(Message::tool(call_id, content));
        self
      }

      pub fn message(mut self, message: Message) -> Self {
        self.request.messages.push(message);
        self
      }

      pub fn messages(mut self, messages: impl IntoIterator<Item = Message>) -> Self {
        self.request.messages.extend(messages);
        self
      }

      pub fn tool(mut self, tool: Tool) -> Self {
        self.request.tools.push(tool);
        self
      }

      pub fn tool_choice(mut self, tool_choice: impl Into<ToolChoice>) -> Self {
        self.request.tool_choice = Some(tool_choice.into());
        self
      }

      pub fn temperature(mut self, temperature: f64) -> Self {
        self.request.temperature = Some(temperature);
        self
      }

      pub fn top_p(mut self, top_p: f64) -> Self {
        self.request.top_p = Some(top_p);
        self
      }

      pub fn top_k(mut self, top_k: u64) -> Self {
        self.request.top_k = Some(top_k);
        self
      }

      pub fn max_output_tokens(mut self, max_output_tokens: u64) -> Self {
        self.request.max_output_tokens = Some(max_output_tokens);
        self
      }

      /// Alias for [`Self::max_output_tokens`].
      pub fn max_tokens(self, max_tokens: u64) -> Self {
        self.max_output_tokens(max_tokens)
      }

      pub fn reasoning(mut self, reasoning: ReasoningOptions) -> Self {
        self.request.reasoning = Some(reasoning);
        self
      }

      pub fn reasoning_mode(mut self, mode: ReasoningMode) -> Self {
        self
          .request
          .reasoning
          .get_or_insert_with(ReasoningOptions::default)
          .mode = Some(mode);
        self
      }

      pub fn reasoning_enabled(self, enabled: bool) -> Self {
        self.reasoning_mode(if enabled {
          ReasoningMode::Enabled
        } else {
          ReasoningMode::Disabled
        })
      }

      pub fn reasoning_effort(mut self, effort: impl Into<ReasoningEffort>) -> Self {
        self
          .request
          .reasoning
          .get_or_insert_with(ReasoningOptions::default)
          .effort = Some(effort.into());
        self
      }

      pub fn reasoning_budget_tokens(mut self, budget_tokens: u64) -> Self {
        self
          .request
          .reasoning
          .get_or_insert_with(ReasoningOptions::default)
          .budget_tokens = Some(budget_tokens);
        self
      }

      pub fn reasoning_summary(mut self, summary: impl Into<ReasoningSummary>) -> Self {
        self
          .request
          .reasoning
          .get_or_insert_with(ReasoningOptions::default)
          .summary = Some(summary.into());
        self
      }

      pub fn options(mut self, options: RequestOptions) -> Self {
        self.request.options = options;
        self
      }

      pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.request.options.profile = Some(profile.into());
        self
      }

      pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request.options.request_id = Some(request_id.into());
        self
      }

      pub fn session_id(mut self, session_id: impl Into<String>) -> Self {
        self.request.options.session_id = Some(session_id.into());
        self
      }

      pub fn project_id(mut self, project_id: impl Into<String>) -> Self {
        self.request.options.project_id = Some(project_id.into());
        self
      }

      pub fn initiator(mut self, initiator: impl Into<String>) -> Self {
        self.request.options.initiator = Some(initiator.into());
        self
      }

      pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request.options.headers.push((name.into(), value.into()));
        self
      }

      pub fn extra(mut self, name: impl Into<String>, value: Value) -> Self {
        self.request.extras.insert(name.into(), value);
        self
      }

      /// Finish building an owned request, detaching it from any bound client.
      pub fn build(self) -> Result<GenerateRequest> {
        self.request.validate()?;
        Ok(self.request)
      }
    }
  };
}

generate_builder_methods!(GenerateRequestBuilder);
generate_builder_methods!(GenerateCall<'_>);

impl GenerateRequestBuilder {
  /// Bind a detached builder to a client without changing the request.
  pub fn bind(self, client: &Client) -> GenerateCall<'_> {
    GenerateCall {
      client,
      request: self.request,
    }
  }
}

impl GenerateCall<'_> {
  pub async fn send(self) -> Result<GenerateResponse> {
    self.client.send(&self.request).await
  }

  pub async fn stream(self) -> Result<GenerateStream> {
    self.client.stream(&self.request).await
  }

  pub async fn stream_text(self) -> Result<TextStream> {
    self.client.stream_text(&self.request).await
  }
}

impl Client {
  /// Start a client-bound generation builder.
  pub fn generate(&self, model: impl Into<String>) -> GenerateCall<'_> {
    GenerateRequest::builder(model).bind(self)
  }

  /// Send an owned or borrowed detached request.
  pub async fn send(&self, request: impl Borrow<GenerateRequest>) -> Result<GenerateResponse> {
    let request = request.borrow();
    let body = request.responses_body(false)?;
    let response = self
      .execute_generation(
        Endpoint::Responses,
        body,
        request.options.clone(),
        request.generation_options(),
      )
      .await
      .map_err(map_generation_error)?
      .into_buffered()?;
    ensure_success(response.status, &response.data)?;
    let raw = serde_json::from_slice(&response.data).map_err(|source| Error::DeserializeResponse { source })?;
    Ok(GenerateResponse::from_raw(response.status, response.headers, raw))
  }

  /// Stream semantic generation events from an owned or borrowed request.
  pub async fn stream(&self, request: impl Borrow<GenerateRequest>) -> Result<GenerateStream> {
    let request = request.borrow();
    let body = request.responses_body(true)?;
    let response = self
      .execute_generation(
        Endpoint::Responses,
        body,
        request.options.clone(),
        request.generation_options(),
      )
      .await
      .map_err(map_generation_error)?;
    ensure_raw_success(&response)?;
    Ok(stream::parse_events(response.into_stream()?.into_stream()))
  }

  /// Stream only generated text deltas.
  pub async fn stream_text(&self, request: impl Borrow<GenerateRequest>) -> Result<TextStream> {
    let events = self.stream(request).await?;
    Ok(stream::text_only(events))
  }
}

fn map_generation_error(error: Error) -> Error {
  let Error::Request { source } = error else {
    return error;
  };
  let source = match source.into_pipeline() {
    Ok(source) => source,
    Err(source) => return Error::Request { source },
  };
  match source.inner() {
    RequestsError::UpstreamStatus { status, body } => Error::GenerateResponseStatus {
      status: *status,
      body: body.clone(),
    },
    RequestsError::InvalidGenerationOptions { .. } | RequestsError::UnsupportedGenerationControl { .. } => {
      Error::InvalidGenerateRequest {
        message: source.inner().to_string(),
      }
    }
    _ => Error::Request { source: source.into() },
  }
}

fn ensure_raw_success(response: &crate::RawResponse) -> Result<()> {
  if (200..300).contains(&response.status) {
    return Ok(());
  }
  let body = match &response.body {
    ResponseBody::Buffered(body) => String::from_utf8_lossy(body).into_owned(),
    ResponseBody::Stream(_) => "<streaming error body>".into(),
  };
  Err(Error::GenerateResponseStatus {
    status: response.status,
    body,
  })
}

fn ensure_success(status: u16, body: &[u8]) -> Result<()> {
  if (200..300).contains(&status) {
    Ok(())
  } else {
    Err(Error::GenerateResponseStatus {
      status,
      body: String::from_utf8_lossy(body).into_owned(),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn detached_request_round_trips_and_can_be_transformed() {
    let request = GenerateRequest::builder("smart")
      .system("Be concise.")
      .prompt("Hello")
      .temperature(0.2)
      .top_p(0.9)
      .top_k(0)
      .reasoning_mode(ReasoningMode::Enabled)
      .reasoning_effort(ReasoningEffort::High)
      .reasoning_budget_tokens(4096)
      .reasoning_summary(ReasoningSummary::Auto)
      .request_id("request-1")
      .build()
      .expect("build request");
    let value = serde_json::to_value(&request).expect("serialize request value");
    assert_eq!(value["top_k"], 0);
    assert_eq!(
      value["reasoning"],
      serde_json::json!({
        "mode": "enabled",
        "effort": "high",
        "budget_tokens": 4096,
        "summary": "auto"
      })
    );
    let serialized = serde_json::to_string(&request).expect("serialize request");
    let request: GenerateRequest = serde_json::from_str(&serialized).expect("deserialize request");
    let request = request
      .into_builder()
      .max_tokens(128)
      .build()
      .expect("transform request");

    assert_eq!(request.model, "smart");
    assert_eq!(
      request.messages,
      vec![Message::system("Be concise."), Message::user("Hello")]
    );
    assert_eq!(request.temperature, Some(0.2));
    assert_eq!(request.top_p, Some(0.9));
    assert_eq!(request.top_k, Some(0));
    assert_eq!(request.max_output_tokens, Some(128));
    assert_eq!(
      request.reasoning,
      Some(
        ReasoningOptions::new()
          .with_mode(ReasoningMode::Enabled)
          .with_effort(ReasoningEffort::High)
          .with_budget_tokens(4096)
          .with_summary(ReasoningSummary::Auto)
      )
    );
    assert_eq!(request.options.request_id.as_deref(), Some("request-1"));
  }

  #[test]
  fn typed_generation_controls_are_carried_out_of_band() {
    let request = GenerateRequest::builder("smart")
      .prompt("Hello")
      .max_tokens(128)
      .top_k(40)
      .reasoning_effort("high")
      .build()
      .expect("build request");

    let body = request.responses_body(false).expect("build Responses body");

    assert!(body.get("top_k").is_none());
    assert!(body.get("reasoning").is_none());
    assert_eq!(body["max_output_tokens"], 128);
    assert_eq!(
      request.generation_options(),
      GenerationOptions::new()
        .with_max_output_tokens(128)
        .with_top_k(40)
        .with_reasoning(ReasoningOptions::new().with_effort(ReasoningEffort::High))
    );
  }

  #[test]
  fn detached_request_accepts_sparse_serialized_options() {
    let request: GenerateRequest = serde_json::from_value(serde_json::json!({
      "model": "smart",
      "messages": [{"role": "user", "content": "Hello"}],
      "options": {"profile": "fast"}
    }))
    .expect("deserialize sparse request options");

    assert_eq!(request.options.profile.as_deref(), Some("fast"));
    assert!(request.options.headers.is_empty());
    assert!(serde_json::to_value(request)
      .expect("serialize request")
      .pointer("/options/headers")
      .is_none());
  }

  #[test]
  fn invalid_requests_fail_before_execution() {
    let error = GenerateRequest::builder("smart")
      .build()
      .expect_err("missing prompt should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .system("system only")
      .build()
      .expect_err("missing non-system input should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .temperature(f64::NAN)
      .build()
      .expect_err("non-finite temperature should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .top_p(1.1)
      .build()
      .expect_err("top_p outside its probability range should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .message(Message::user("invalid").with_tool_call(ToolCall::new("lookup", serde_json::json!({})).id("call_1")))
      .build()
      .expect_err("user tool call should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .tool_result(" ", "empty id")
      .build()
      .expect_err("blank tool result id should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .tool(Tool::function("lookup", Value::Null))
      .build()
      .expect_err("tool schema must be an object");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .reasoning(ReasoningOptions::new())
      .build()
      .expect_err("empty reasoning options should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .reasoning_enabled(false)
      .reasoning_effort("high")
      .build()
      .expect_err("disabled reasoning with effort should fail");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));

    let error = GenerateRequest::builder("smart")
      .prompt("hello")
      .reasoning_effort("high")
      .extra("reasoning_effort", Value::String("low".into()))
      .build()
      .expect_err("typed reasoning must not conflict with raw reasoning extras");
    assert!(matches!(error, Error::InvalidGenerateRequest { .. }));
  }
}

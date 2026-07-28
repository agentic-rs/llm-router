use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use tokn_endpoint_core::{
  drain_into_extras, peel_lenient, take_optional, take_optional_default, take_required, Extras,
};

use crate::content::ContentBlock;
use crate::message::Message;
use crate::parameters::{MessagesExtraParameters, MessagesRequestParameters};

/// Compatibility value used when a request converted to Messages does not
/// specify the API's required `max_tokens` field.
pub const DEFAULT_MESSAGES_MAX_TOKENS: u64 = 32_000;

/// `system` accepts either a single string or an array of content
/// blocks (typically `text` blocks).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SystemPrompt {
  Text(String),
  Blocks(Vec<ContentBlock>),
}

/// Request body for `POST /v1/messages`.
///
/// Behavior knobs (temperature, top_p, top_k, service_tier,
/// tool_choice, thinking) live on the embedded
/// [`MessagesRequestParameters`]; structured payloads, content,
/// `max_tokens` (required) and streaming controls stay at the top
/// level.
///
/// Deserialization is **lenient on parameter fields**: see
/// [`ChatRequest`](crate::MessagesRequest) for details; the same
/// semantics apply.
#[derive(Clone, Debug, Serialize)]
pub struct MessagesRequest {
  pub model: String,
  pub messages: Vec<Message>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub system: Option<SystemPrompt>,
  pub max_tokens: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub stream: Option<bool>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub tools: Vec<MessagesToolDef>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub stop_sequences: Option<Value>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub metadata: Option<Value>,
  #[serde(flatten)]
  pub params: MessagesRequestParameters,
  #[serde(flatten)]
  pub extra_params: MessagesExtraParameters,
  #[serde(flatten)]
  pub extras: Extras,
}

impl<'de> Deserialize<'de> for MessagesRequest {
  fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
    let mut root = Map::<String, Value>::deserialize(d)?;

    let model: String = take_required(&mut root, "model")?;
    let messages: Vec<Message> = take_required(&mut root, "messages")?;
    let system: Option<SystemPrompt> = take_optional(&mut root, "system")?;
    let max_tokens: u64 = take_required(&mut root, "max_tokens")?;
    let stream: Option<bool> = take_optional(&mut root, "stream")?;
    let tools: Vec<MessagesToolDef> = take_optional_default(&mut root, "tools")?;
    let stop_sequences: Option<Value> = root.remove("stop_sequences");
    let metadata: Option<Value> = root.remove("metadata");

    let mut extras: Extras = Map::new();
    let params: MessagesRequestParameters = peel_lenient(&mut root, &mut extras);
    let extra_params: MessagesExtraParameters = peel_lenient(&mut root, &mut extras);
    drain_into_extras(&mut root, &mut extras);

    Ok(MessagesRequest {
      model,
      messages,
      system,
      max_tokens,
      stream,
      tools,
      stop_sequences,
      metadata,
      params,
      extra_params,
      extras,
    })
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessagesToolDef {
  pub name: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub description: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub input_schema: Option<Value>,
  #[serde(default, flatten)]
  pub extras: Extras,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessagesToolChoice {
  Mode(Value),
  Named(Value),
}

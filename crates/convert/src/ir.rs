use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IrRequest {
  pub model: String,
  pub system: Option<String>,
  pub messages: Vec<IrMessage>,
  pub tools: Vec<Value>,
  pub tool_choice: Option<Value>,
  pub sampling: Sampling,
  pub reasoning: Option<Value>,
  pub stream: bool,
  pub extras: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrMessage {
  pub role: Role,
  pub content: Vec<ContentPart>,
  pub tool_call_id: Option<String>,
  pub name: Option<String>,
  pub raw: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
  System,
  User,
  Assistant,
  Tool,
  Other(String),
}

impl Role {
  pub fn from_wire(s: &str) -> Self {
    match s {
      "system" => Self::System,
      "user" => Self::User,
      "assistant" => Self::Assistant,
      "tool" => Self::Tool,
      other => Self::Other(other.to_string()),
    }
  }

  pub fn as_str(&self) -> &str {
    match self {
      Self::System => "system",
      Self::User => "user",
      Self::Assistant => "assistant",
      Self::Tool => "tool",
      Self::Other(s) => s.as_str(),
    }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentPart {
  Text { text: String },
  Reasoning { text: String },
  ToolCall { call: ToolCall },
  ToolResult { id: Option<String>, content: Value },
  Raw { value: Value },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ToolCall {
  pub id: Option<String>,
  pub name: String,
  pub arguments: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Sampling {
  pub temperature: Option<f64>,
  pub top_p: Option<f64>,
  pub max_output_tokens: Option<u64>,
  pub stop: Option<Value>,
  pub n: Option<u64>,
  pub seed: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IrResponse {
  pub id: Option<String>,
  pub model: Option<String>,
  pub role: Option<Role>,
  pub content: Vec<ContentPart>,
  pub tool_calls: Vec<ToolCall>,
  pub usage: Option<Usage>,
  pub finish_reason: Option<String>,
  pub extras: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Usage {
  pub input_tokens: Option<u64>,
  pub output_tokens: Option<u64>,
  pub total_tokens: Option<u64>,
  /// Normalized usage-details payload. Maps from either
  /// `prompt_tokens_details` or `input_tokens_details`.
  pub input_tokens_details: Option<Value>,
  /// Normalized usage-details payload. Maps from either
  /// `completion_tokens_details` or `output_tokens_details`.
  pub output_tokens_details: Option<Value>,
  /// Unknown or provider-specific top-level usage keys.
  pub extras: BTreeMap<String, Value>,
}

impl Usage {
  pub fn merge(&mut self, update: Self) {
    if update.input_tokens.is_some() {
      self.input_tokens = update.input_tokens;
    }
    if update.output_tokens.is_some() {
      self.output_tokens = update.output_tokens;
    }
    if update.total_tokens.is_some() {
      self.total_tokens = update.total_tokens;
    }
    if update.input_tokens_details.is_some() {
      self.input_tokens_details = update.input_tokens_details;
    }
    if update.output_tokens_details.is_some() {
      self.output_tokens_details = update.output_tokens_details;
    }
    self.extras.extend(update.extras);
  }
}

/// Map cross-endpoint finish reasons to the closest Responses API terminal
/// status and standard incomplete reason.
pub fn responses_completion_status(finish_reason: Option<&str>) -> (&'static str, Option<&'static str>) {
  match finish_reason {
    Some("length" | "max_tokens" | "max_output_tokens") => ("incomplete", Some("max_output_tokens")),
    Some("content_filter") => ("incomplete", Some("content_filter")),
    Some("failed" | "error") => ("failed", None),
    Some("cancelled") => ("cancelled", None),
    _ => ("completed", None),
  }
}

#[derive(Clone, Debug)]
pub enum IrDelta {
  Text(String),
  Reasoning(String),
  ToolCall {
    index: usize,
    id: Option<String>,
    name: Option<String>,
    arguments_delta: String,
  },
  Usage(Usage),
  Finish(Option<String>),
}

impl IrResponse {
  pub fn push_delta(&mut self, delta: IrDelta) {
    match delta {
      IrDelta::Text(text) => push_text_part(&mut self.content, text),
      IrDelta::Reasoning(text) => push_reasoning_part(&mut self.content, text),
      IrDelta::ToolCall {
        index,
        id,
        name,
        arguments_delta,
      } => {
        while self.tool_calls.len() <= index {
          self.tool_calls.push(ToolCall::default());
        }
        let call = &mut self.tool_calls[index];
        if id.is_some() {
          call.id = id;
        }
        if let Some(name) = name {
          call.name = name;
        }
        let mut current = call.arguments.as_str().unwrap_or_default().to_string();
        current.push_str(&arguments_delta);
        call.arguments = Value::String(current);
      }
      IrDelta::Usage(usage) => {
        if let Some(current) = &mut self.usage {
          current.merge(usage);
        } else {
          self.usage = Some(usage);
        }
      }
      IrDelta::Finish(reason) => self.finish_reason = reason,
    }
  }
}

fn push_text_part(parts: &mut Vec<ContentPart>, text: String) {
  if text.is_empty() {
    return;
  }
  if let Some(ContentPart::Text { text: existing }) = parts.last_mut() {
    existing.push_str(&text);
  } else {
    parts.push(ContentPart::Text { text });
  }
}

fn push_reasoning_part(parts: &mut Vec<ContentPart>, text: String) {
  if text.is_empty() {
    return;
  }
  if let Some(ContentPart::Reasoning { text: existing }) = parts.last_mut() {
    existing.push_str(&text);
  } else {
    parts.push(ContentPart::Reasoning { text });
  }
}

pub fn text_from_parts(parts: &[ContentPart]) -> String {
  parts
    .iter()
    .filter_map(|p| match p {
      ContentPart::Text { text } => Some(text.as_str()),
      _ => None,
    })
    .collect::<Vec<_>>()
    .join("")
}

pub fn reasoning_from_parts(parts: &[ContentPart]) -> Option<String> {
  let text = parts
    .iter()
    .filter_map(|p| match p {
      ContentPart::Reasoning { text } => Some(text.as_str()),
      _ => None,
    })
    .collect::<Vec<_>>()
    .join("");
  (!text.is_empty()).then_some(text)
}

pub fn usage_from_openai(v: &Value) -> Option<Usage> {
  let u = v.get("usage")?;
  let input_tokens_details = u
    .get("input_tokens_details")
    .cloned()
    .or_else(|| u.get("prompt_tokens_details").cloned());
  let output_tokens_details = u
    .get("output_tokens_details")
    .cloned()
    .or_else(|| u.get("completion_tokens_details").cloned());
  let extras = u
    .as_object()
    .map(|obj| {
      extras_from_object(
        obj,
        &[
          "prompt_tokens",
          "completion_tokens",
          "input_tokens",
          "output_tokens",
          "total_tokens",
          "prompt_tokens_details",
          "completion_tokens_details",
          "input_tokens_details",
          "output_tokens_details",
        ],
      )
    })
    .unwrap_or_default();
  Some(Usage {
    input_tokens: u
      .get("prompt_tokens")
      .or_else(|| u.get("input_tokens"))
      .and_then(Value::as_u64),
    output_tokens: u
      .get("completion_tokens")
      .or_else(|| u.get("output_tokens"))
      .and_then(Value::as_u64),
    total_tokens: u.get("total_tokens").and_then(Value::as_u64),
    input_tokens_details,
    output_tokens_details,
    extras,
  })
}

pub fn usage_to_chat(usage: &Usage) -> Value {
  let mut v = Map::new();
  v.extend(usage.extras.clone());
  v.insert("prompt_tokens".into(), Value::from(usage.input_tokens.unwrap_or(0)));
  v.insert(
    "completion_tokens".into(),
    Value::from(usage.output_tokens.unwrap_or(0)),
  );
  v.insert(
    "total_tokens".into(),
    Value::from(
      usage
        .total_tokens
        .unwrap_or_else(|| usage.input_tokens.unwrap_or(0) + usage.output_tokens.unwrap_or(0)),
    ),
  );
  if let Some(details) = &usage.input_tokens_details {
    v.insert("prompt_tokens_details".into(), details.clone());
  }
  if let Some(details) = &usage.output_tokens_details {
    v.insert("completion_tokens_details".into(), details.clone());
  }
  Value::Object(v)
}

pub fn usage_to_io(usage: &Usage) -> Value {
  let mut v = Map::new();
  v.extend(usage.extras.clone());
  v.insert("input_tokens".into(), Value::from(usage.input_tokens.unwrap_or(0)));
  v.insert("output_tokens".into(), Value::from(usage.output_tokens.unwrap_or(0)));
  v.insert(
    "total_tokens".into(),
    Value::from(
      usage
        .total_tokens
        .unwrap_or_else(|| usage.input_tokens.unwrap_or(0) + usage.output_tokens.unwrap_or(0)),
    ),
  );
  if let Some(details) = &usage.input_tokens_details {
    v.insert("input_tokens_details".into(), details.clone());
  }
  if let Some(details) = &usage.output_tokens_details {
    v.insert("output_tokens_details".into(), details.clone());
  }
  Value::Object(v)
}

pub fn extras_from_object(obj: &Map<String, Value>, known: &[&str]) -> BTreeMap<String, Value> {
  obj
    .iter()
    .filter(|(k, _)| !known.contains(&k.as_str()))
    .map(|(k, v)| (k.clone(), v.clone()))
    .collect()
}

pub fn insert_opt_f64(out: &mut Map<String, Value>, key: &str, value: Option<f64>) {
  if let Some(value) = value.and_then(serde_json::Number::from_f64) {
    out.insert(key.into(), Value::Number(value));
  }
}

pub fn insert_opt_u64(out: &mut Map<String, Value>, key: &str, value: Option<u64>) {
  if let Some(value) = value {
    out.insert(key.into(), Value::Number(value.into()));
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn usage_round_trip_preserves_extra_usage_fields() {
    let wire = json!({
      "usage": {
        "input_tokens": 10,
        "output_tokens": 4,
        "total_tokens": 14,
        "input_tokens_details": {
          "cached_tokens": 3,
          "text_tokens": 7
        },
        "output_tokens_details": {
          "reasoning_tokens": 2,
          "text_tokens": 2
        },
        "service_tier": "flex"
      }
    });
    let usage = usage_from_openai(&wire).expect("usage");
    assert_eq!(
      usage.input_tokens_details,
      Some(json!({ "cached_tokens": 3, "text_tokens": 7 }))
    );
    assert_eq!(
      usage.output_tokens_details,
      Some(json!({ "reasoning_tokens": 2, "text_tokens": 2 }))
    );
    assert_eq!(usage.extras.get("service_tier"), Some(&json!("flex")));
    assert_eq!(
      usage_to_io(&usage),
      json!({
        "input_tokens": 10,
        "output_tokens": 4,
        "total_tokens": 14,
        "input_tokens_details": {
          "cached_tokens": 3,
          "text_tokens": 7
        },
        "output_tokens_details": {
          "reasoning_tokens": 2,
          "text_tokens": 2
        },
        "service_tier": "flex"
      })
    );
  }

  #[test]
  fn response_accumulation_merges_split_usage_updates() {
    let mut response = IrResponse::default();
    response.push_delta(IrDelta::Usage(Usage {
      input_tokens: Some(7),
      extras: BTreeMap::from([("cache_creation_input_tokens".into(), json!(2))]),
      ..Usage::default()
    }));
    response.push_delta(IrDelta::Usage(Usage {
      output_tokens: Some(5),
      total_tokens: Some(12),
      extras: BTreeMap::from([("service_tier".into(), json!("standard"))]),
      ..Usage::default()
    }));

    let usage = response.usage.expect("merged usage");
    assert_eq!(usage.input_tokens, Some(7));
    assert_eq!(usage.output_tokens, Some(5));
    assert_eq!(usage.total_tokens, Some(12));
    assert_eq!(usage.extras["cache_creation_input_tokens"], 2);
    assert_eq!(usage.extras["service_tier"], "standard");
  }
}

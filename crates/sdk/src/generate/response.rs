use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokn_convert::ir::Usage as IrUsage;
use tokn_headers::HeaderMap;

/// Friendly buffered output from a provider-neutral generation.
#[derive(Debug)]
pub struct GenerateResponse {
  pub http_status: u16,
  pub headers: HeaderMap,
  pub id: Option<String>,
  pub model: Option<String>,
  pub status: Option<String>,
  pub finish_reason: Option<String>,
  pub text: String,
  pub reasoning: Option<String>,
  pub tool_calls: Vec<ToolCall>,
  pub usage: Option<Usage>,
  /// Full canonical Responses payload after routing and endpoint conversion.
  pub raw: Value,
}

impl GenerateResponse {
  pub(super) fn from_raw(http_status: u16, headers: HeaderMap, raw: Value) -> Self {
    let tool_calls = output_tool_calls(&raw);
    Self {
      http_status,
      headers,
      id: raw.get("id").and_then(Value::as_str).map(str::to_string),
      model: raw.get("model").and_then(Value::as_str).map(str::to_string),
      status: raw.get("status").and_then(Value::as_str).map(str::to_string),
      finish_reason: finish_reason(&raw, !tool_calls.is_empty()),
      text: output_text(&raw),
      reasoning: output_reasoning(&raw),
      tool_calls,
      usage: raw
        .get("usage")
        .filter(|usage| usage.is_object())
        .map(Usage::from_value),
      raw,
    }
  }
}

/// A normalized tool call returned by a generation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
  pub id: Option<String>,
  pub name: String,
  pub arguments: Value,
}

impl ToolCall {
  pub fn new(name: impl Into<String>, arguments: Value) -> Self {
    Self {
      id: None,
      name: name.into(),
      arguments,
    }
  }

  pub fn id(mut self, id: impl Into<String>) -> Self {
    self.id = Some(id.into());
    self
  }
}

/// Provider-neutral token usage.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Usage {
  pub input_tokens: Option<u64>,
  pub output_tokens: Option<u64>,
  pub total_tokens: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub input_tokens_details: Option<Value>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub output_tokens_details: Option<Value>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub extras: BTreeMap<String, Value>,
}

impl Usage {
  fn from_value(value: &Value) -> Self {
    let Some(object) = value.as_object() else {
      return Self::default();
    };
    let mut extras: BTreeMap<String, Value> = object.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
    for key in [
      "input_tokens",
      "prompt_tokens",
      "output_tokens",
      "completion_tokens",
      "total_tokens",
      "input_tokens_details",
      "prompt_tokens_details",
      "output_tokens_details",
      "completion_tokens_details",
    ] {
      extras.remove(key);
    }
    Self {
      input_tokens: object
        .get("input_tokens")
        .or_else(|| object.get("prompt_tokens"))
        .and_then(Value::as_u64),
      output_tokens: object
        .get("output_tokens")
        .or_else(|| object.get("completion_tokens"))
        .and_then(Value::as_u64),
      total_tokens: object.get("total_tokens").and_then(Value::as_u64),
      input_tokens_details: object
        .get("input_tokens_details")
        .or_else(|| object.get("prompt_tokens_details"))
        .cloned(),
      output_tokens_details: object
        .get("output_tokens_details")
        .or_else(|| object.get("completion_tokens_details"))
        .cloned(),
      extras,
    }
  }

  pub(super) fn from_ir(usage: IrUsage) -> Self {
    Self {
      input_tokens: usage.input_tokens,
      output_tokens: usage.output_tokens,
      total_tokens: usage.total_tokens,
      input_tokens_details: usage.input_tokens_details,
      output_tokens_details: usage.output_tokens_details,
      extras: usage.extras,
    }
  }
}

fn output_text(response: &Value) -> String {
  if let Some(text) = response
    .get("output_text")
    .and_then(Value::as_str)
    .filter(|text| !text.is_empty())
  {
    return text.to_string();
  }
  response
    .get("output")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .filter(|item| item.get("type").and_then(Value::as_str) == Some("message"))
    .flat_map(|item| item.get("content").and_then(Value::as_array).into_iter().flatten())
    .filter(|part| matches!(part.get("type").and_then(Value::as_str), Some("output_text" | "text")))
    .filter_map(|part| part.get("text").and_then(Value::as_str))
    .collect()
}

fn output_reasoning(response: &Value) -> Option<String> {
  let mut parts = Vec::new();
  for item in response.get("output").and_then(Value::as_array).into_iter().flatten() {
    match item.get("type").and_then(Value::as_str) {
      Some("reasoning") => {
        collect_reasoning_parts(item.get("content"), &mut parts);
        collect_reasoning_parts(item.get("summary"), &mut parts);
      }
      Some("message") => {
        for part in item
          .get("content")
          .and_then(Value::as_array)
          .into_iter()
          .flatten()
          .filter(|part| part.get("type").and_then(Value::as_str) == Some("reasoning"))
        {
          collect_reasoning_parts(Some(part), &mut parts);
        }
      }
      _ => {}
    }
  }
  let reasoning = parts.concat();
  (!reasoning.is_empty()).then_some(reasoning)
}

fn collect_reasoning_parts(value: Option<&Value>, output: &mut Vec<String>) {
  match value {
    Some(Value::Array(parts)) => {
      output.extend(
        parts
          .iter()
          .filter_map(|part| part.get("text").or_else(|| part.get("summary")).and_then(Value::as_str))
          .map(str::to_string),
      );
    }
    Some(Value::Object(part)) => {
      if let Some(text) = part.get("text").or_else(|| part.get("summary")).and_then(Value::as_str) {
        output.push(text.to_string());
      }
    }
    Some(Value::String(text)) => output.push(text.clone()),
    _ => {}
  }
}

fn output_tool_calls(response: &Value) -> Vec<ToolCall> {
  response
    .get("output")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .filter(|item| {
      matches!(
        item.get("type").and_then(Value::as_str),
        Some("function_call" | "custom_tool_call")
      )
    })
    .map(|item| ToolCall {
      id: item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string),
      name: item.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
      arguments: decode_arguments(
        item
          .get("arguments")
          .or_else(|| item.get("input"))
          .unwrap_or(&Value::Null),
      ),
    })
    .collect()
}

fn decode_arguments(value: &Value) -> Value {
  match value {
    Value::String(arguments) => serde_json::from_str(arguments).unwrap_or_else(|_| value.clone()),
    _ => value.clone(),
  }
}

pub(super) fn finish_reason(response: &Value, has_tool_calls: bool) -> Option<String> {
  if let Some(reason) = response.get("finish_reason").and_then(Value::as_str) {
    return Some(reason.to_string());
  }
  match response.get("status").and_then(Value::as_str) {
    Some("incomplete") => Some(
      response
        .pointer("/incomplete_details/reason")
        .and_then(Value::as_str)
        .map(|reason| match reason {
          "max_output_tokens" => "length",
          other => other,
        })
        .unwrap_or("incomplete")
        .to_string(),
    ),
    Some("completed") if has_tool_calls => Some("tool_calls".into()),
    Some("completed") => Some("stop".into()),
    Some("failed") => Some("error".into()),
    Some(status) => Some(status.to_string()),
    None if has_tool_calls => Some("tool_calls".into()),
    None => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn prefers_output_text_without_duplication() {
    let response = GenerateResponse::from_raw(
      200,
      HeaderMap::new(),
      json!({
        "id": "resp_1",
        "status": "completed",
        "output_text": "hello",
        "output": [{
          "type": "message",
          "content": [{"type": "output_text", "text": "hello"}]
        }],
        "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}
      }),
    );

    assert_eq!(response.text, "hello");
    assert_eq!(response.finish_reason.as_deref(), Some("stop"));
    assert_eq!(response.usage.expect("usage").total_tokens, Some(3));
  }

  #[test]
  fn derives_tool_and_incomplete_finish_reasons() {
    assert_eq!(
      finish_reason(
        &json!({
          "status": "completed",
          "output": [{"type": "function_call"}]
        }),
        true,
      )
      .as_deref(),
      Some("tool_calls")
    );
    assert_eq!(
      finish_reason(
        &json!({
          "status": "incomplete",
          "incomplete_details": {"reason": "max_output_tokens"}
        }),
        false,
      )
      .as_deref(),
      Some("length")
    );
  }
}

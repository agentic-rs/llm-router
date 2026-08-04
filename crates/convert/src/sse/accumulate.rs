use super::super::error::{ConvertError, Result};
use super::super::ir::{IrDelta, IrResponse};
use super::event::SseEvent;
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use serde_json::Value;
use std::collections::BTreeMap;
use tokn_endpoint_core::Endpoint;

#[derive(Default)]
struct ResponsesState {
  response_id: Option<String>,
  model: Option<String>,
  output_items: BTreeMap<usize, ResponseOutputItem>,
}

#[derive(Default)]
struct MessagesState {
  tool_arguments_seen: BTreeMap<usize, bool>,
}

#[derive(Default)]
struct ResponseOutputItem {
  item_type: Option<String>,
  id: Option<String>,
  call_id: Option<String>,
  name: Option<String>,
  status: Option<String>,
  text: String,
  reasoning_summary: BTreeMap<usize, String>,
  reasoning_content: BTreeMap<usize, String>,
  arguments: String,
}

#[derive(Clone, Debug, Default)]
pub struct SseMetadata {
  pub response_id: Option<String>,
  pub model: Option<String>,
}

pub struct SseAccumulator {
  endpoint: Endpoint,
  response: IrResponse,
  responses: ResponsesState,
  messages: MessagesState,
}

impl SseAccumulator {
  pub fn new(endpoint: Endpoint) -> Self {
    Self {
      endpoint,
      response: IrResponse::default(),
      responses: ResponsesState::default(),
      messages: MessagesState::default(),
    }
  }

  pub fn push_value(&mut self, value: &Value) -> Vec<IrDelta> {
    let deltas = match self.endpoint {
      Endpoint::ChatCompletions => {
        self.observe_chat_chunk(value);
        crate::value::chat::delta_from_chat_chunk(value)
      }
      Endpoint::Responses => self.delta_from_responses_event(value),
      Endpoint::Messages => {
        self.observe_messages_event(value);
        self.delta_from_messages_event(value)
      }
    };
    for delta in deltas.iter().cloned() {
      self.response.push_delta(delta);
    }
    deltas
  }

  pub fn finish(self) -> IrResponse {
    let mut response = self.response;
    if matches!(self.endpoint, Endpoint::Responses)
      && response.finish_reason.is_none()
      && self.responses.has_tool_call()
    {
      response.finish_reason = Some("tool_calls".into());
    }
    response
  }

  pub fn metadata(&self) -> SseMetadata {
    SseMetadata {
      response_id: self.responses.response_id.clone(),
      model: self.responses.model.clone(),
    }
  }

  pub fn responses_completed_finish_reason(&self, value: Option<&Value>) -> &'static str {
    if value
      .and_then(|event| event.get("response"))
      .is_some_and(crate::value::responses::response_has_tool_call_output)
      || self.responses.has_tool_call()
    {
      "tool_calls"
    } else {
      "stop"
    }
  }

  pub fn responses_has_tool_call(&self) -> bool {
    self.responses.has_tool_call()
  }

  fn delta_from_responses_event(&mut self, value: &Value) -> Vec<IrDelta> {
    self.observe_responses_response(value);
    self.observe_responses_output_item(value);
    self.observe_responses_part(value);
    let mut deltas = crate::value::responses::delta_from_responses_event(value);
    self.observe_responses_deltas(value, &deltas);
    if matches!(value.get("type").and_then(Value::as_str), Some("response.completed")) {
      let reason = self.responses_completed_finish_reason(Some(value));
      for delta in &mut deltas {
        if let IrDelta::Finish(current) = delta {
          *current = Some(reason.into());
        }
      }
    }
    for delta in &mut deltas {
      if let IrDelta::ToolCall { index, id, name, .. } = delta {
        if let Some(item) = self.responses.output_items.get(index) {
          if item.call_id.is_some() {
            *id = item.call_id.clone();
          } else if id.is_none() {
            *id = item.id.clone();
          }
          if name.is_none() {
            *name = item.name.clone();
          }
        }
      }
    }
    deltas
  }

  fn observe_chat_chunk(&mut self, value: &Value) {
    if self.responses.response_id.is_none() {
      self.responses.response_id = value.get("id").and_then(Value::as_str).map(str::to_string);
    }
    if self.responses.model.is_none() {
      self.responses.model = value.get("model").and_then(Value::as_str).map(str::to_string);
    }
  }

  fn observe_messages_event(&mut self, value: &Value) {
    if !matches!(value.get("type").and_then(Value::as_str), Some("message_start")) {
      return;
    }
    let Some(message) = value.get("message") else {
      return;
    };
    if self.responses.response_id.is_none() {
      self.responses.response_id = message.get("id").and_then(Value::as_str).map(str::to_string);
    }
    if self.responses.model.is_none() {
      self.responses.model = message.get("model").and_then(Value::as_str).map(str::to_string);
    }
  }

  fn delta_from_messages_event(&mut self, value: &Value) -> Vec<IrDelta> {
    let mut deltas = crate::value::messages::delta_from_messages_event(value);
    let index = value.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;

    match value.get("type").and_then(Value::as_str) {
      Some("content_block_start")
        if value
          .get("content_block")
          .and_then(|block| block.get("type"))
          .and_then(Value::as_str)
          == Some("tool_use") =>
      {
        let arguments_seen = deltas
          .iter()
          .any(|delta| matches!(delta, IrDelta::ToolCall { arguments_delta, .. } if !arguments_delta.is_empty()));
        self.messages.tool_arguments_seen.insert(index, arguments_seen);
      }
      Some("content_block_delta") => {
        let arguments_seen = deltas
          .iter()
          .any(|delta| matches!(delta, IrDelta::ToolCall { arguments_delta, .. } if !arguments_delta.is_empty()));
        if arguments_seen {
          self.messages.tool_arguments_seen.insert(index, true);
        }
      }
      Some("content_block_stop") if self.messages.tool_arguments_seen.remove(&index) == Some(false) => {
        deltas.push(IrDelta::ToolCall {
          index,
          id: None,
          name: None,
          arguments_delta: "{}".into(),
        });
      }
      _ => {}
    }

    deltas
  }

  fn observe_responses_response(&mut self, value: &Value) {
    let Some(response) = value.get("response") else {
      return;
    };
    if self.responses.response_id.is_none() {
      self.responses.response_id = response.get("id").and_then(Value::as_str).map(str::to_string);
    }
    if self.responses.model.is_none() {
      self.responses.model = response.get("model").and_then(Value::as_str).map(str::to_string);
    }
    if let Some(usage) = crate::ir::usage_from_openai(response) {
      if let Some(current) = &mut self.response.usage {
        current.merge(usage);
      } else {
        self.response.usage = Some(usage);
      }
    }
  }

  fn observe_responses_output_item(&mut self, value: &Value) {
    match value.get("type").and_then(Value::as_str) {
      Some("response.output_item.added") | Some("response.output_item.done") => {}
      _ => return,
    }
    let Some(index) = value.get("output_index").and_then(Value::as_u64).map(|v| v as usize) else {
      return;
    };
    let Some(item) = value.get("item") else {
      return;
    };
    let entry = self.responses.output_items.entry(index).or_default();
    if entry.item_type.is_none() {
      entry.item_type = item.get("type").and_then(Value::as_str).map(str::to_string);
    }
    if entry.status.is_none() {
      entry.status = item.get("status").and_then(Value::as_str).map(str::to_string);
    }
    if entry.id.is_none() {
      entry.id = item
        .get("id")
        .or_else(|| value.get("item_id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    }
    if entry.call_id.is_none() {
      entry.call_id = item.get("call_id").and_then(Value::as_str).map(str::to_string);
    }
    if entry.name.is_none() {
      entry.name = item.get("name").and_then(Value::as_str).map(str::to_string);
    }
    if let Some(arguments) = item
      .get("arguments")
      .or_else(|| item.get("input"))
      .and_then(Value::as_str)
    {
      entry.arguments = arguments.to_string();
    }
  }

  fn observe_responses_part(&mut self, value: &Value) {
    let Some(index) = value.get("output_index").and_then(Value::as_u64).map(|v| v as usize) else {
      return;
    };
    let Some(entry) = self.responses.output_items.get_mut(&index) else {
      return;
    };
    match value.get("type").and_then(Value::as_str) {
      Some("response.output_text.done") => {
        if let Some(text) = value.get("text").and_then(Value::as_str) {
          entry.text = text.to_string();
        }
      }
      Some("response.reasoning_summary_text.done") => {
        if let (Some(summary_index), Some(text)) = (
          value.get("summary_index").and_then(Value::as_u64).map(|v| v as usize),
          value.get("text").and_then(Value::as_str),
        ) {
          entry.reasoning_summary.insert(summary_index, text.to_string());
        }
      }
      Some("response.function_call_arguments.done") | Some("response.custom_tool_call_input.done") => {
        if let Some(arguments) = value
          .get("arguments")
          .or_else(|| value.get("input"))
          .and_then(Value::as_str)
        {
          entry.arguments = arguments.to_string();
        }
      }
      _ => {}
    }
  }

  fn observe_responses_deltas(&mut self, value: &Value, deltas: &[IrDelta]) {
    let Some(index) = value.get("output_index").and_then(Value::as_u64).map(|v| v as usize) else {
      return;
    };
    let entry = self.responses.output_items.entry(index).or_default();
    for delta in deltas {
      match delta {
        IrDelta::Text(text) => entry.text.push_str(text),
        IrDelta::Reasoning(text) => {
          let target = match value.get("type").and_then(Value::as_str) {
            Some("response.reasoning_summary_text.delta") => value
              .get("summary_index")
              .and_then(Value::as_u64)
              .map(|v| v as usize)
              .map(|i| entry.reasoning_summary.entry(i).or_default()),
            Some("response.reasoning_text.delta") => value
              .get("content_index")
              .and_then(Value::as_u64)
              .map(|v| v as usize)
              .map(|i| entry.reasoning_content.entry(i).or_default()),
            _ => None,
          };
          if let Some(buf) = target {
            buf.push_str(text);
          }
        }
        IrDelta::ToolCall { arguments_delta, .. } => entry.arguments.push_str(arguments_delta),
        _ => {}
      }
    }
  }
}

impl ResponsesState {
  fn has_tool_call(&self) -> bool {
    self
      .output_items
      .values()
      .any(|item| matches!(item.item_type.as_deref(), Some("function_call" | "custom_tool_call")))
  }
}

pub async fn accumulate(endpoint: Endpoint, resp: reqwest::Response) -> Result<IrResponse> {
  let mut acc = SseAccumulator::new(endpoint);
  let mut stream = resp.bytes_stream().eventsource();
  while let Some(item) = stream.next().await {
    let ev = item.map_err(|e| ConvertError::sse(e.to_string()))?;
    let event = SseEvent::from(ev);
    if event.is_done() {
      break;
    }
    let value = event
      .json
      .as_ref()
      .ok_or_else(|| ConvertError::sse("expected JSON SSE payload"))?;
    acc.push_value(value);
  }
  Ok(acc.finish())
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  fn messages_tool_start(input: Value) -> Value {
    json!({
      "type": "content_block_start",
      "index": 0,
      "content_block": {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "lookup",
        "input": input
      }
    })
  }

  #[test]
  fn messages_empty_tool_input_is_synthesized_when_the_block_closes() {
    let mut accumulator = SseAccumulator::new(Endpoint::Messages);

    let start = accumulator.push_value(&messages_tool_start(json!({})));
    assert!(matches!(
      start.as_slice(),
      [IrDelta::ToolCall { arguments_delta, .. }] if arguments_delta.is_empty()
    ));

    let stop = accumulator.push_value(&json!({
      "type": "content_block_stop",
      "index": 0
    }));
    assert!(matches!(
      stop.as_slice(),
      [IrDelta::ToolCall { arguments_delta, .. }] if arguments_delta == "{}"
    ));

    let response = accumulator.finish();
    assert_eq!(response.tool_calls[0].id.as_deref(), Some("toolu_1"));
    assert_eq!(response.tool_calls[0].name, "lookup");
    assert_eq!(response.tool_calls[0].arguments, json!("{}"));
  }

  #[test]
  fn messages_empty_tool_start_does_not_prefix_streamed_arguments() {
    let mut accumulator = SseAccumulator::new(Endpoint::Messages);

    accumulator.push_value(&messages_tool_start(json!({})));
    for partial_json in [r#"{"query":"#, r#""rust"}"#] {
      accumulator.push_value(&json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {
          "type": "input_json_delta",
          "partial_json": partial_json
        }
      }));
    }
    let stop = accumulator.push_value(&json!({
      "type": "content_block_stop",
      "index": 0
    }));

    assert!(stop.is_empty());
    let response = accumulator.finish();
    assert_eq!(response.tool_calls[0].arguments, json!(r#"{"query":"rust"}"#));
  }
}

use super::chat::args_to_string;
use crate::error::{ConvertError, Result};
use crate::ir::*;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub use tokn_endpoint_messages::DEFAULT_MESSAGES_MAX_TOKENS;

const REQUEST_KEYS: &[&str] = &[
  "model",
  "system",
  "messages",
  "tools",
  "tool_choice",
  "temperature",
  "top_p",
  "max_tokens",
  "stop_sequences",
  "stream",
  "thinking",
  "metadata",
];

fn usage_extras(u: &Value, known: &[&str]) -> BTreeMap<String, Value> {
  u.as_object()
    .map(|obj| crate::ir::extras_from_object(obj, known))
    .unwrap_or_default()
}

pub fn request_from_value(v: &Value) -> Result<IrRequest> {
  let obj = v
    .as_object()
    .ok_or_else(|| ConvertError::bad_shape("body", "expected object"))?;
  let (tool_choice, parallel_tool_calls) = messages_tool_choice_from_value(obj.get("tool_choice"));
  let mut extras = extras_from_object(obj, REQUEST_KEYS);
  if let Some(parallel_tool_calls) = parallel_tool_calls {
    extras.insert("parallel_tool_calls".into(), Value::Bool(parallel_tool_calls));
  }
  let messages = obj
    .get("messages")
    .and_then(Value::as_array)
    .ok_or(ConvertError::MissingField { field: "messages" })?
    .iter()
    .map(message_from_messages)
    .collect::<Result<Vec<_>>>()?;
  Ok(IrRequest {
    model: obj
      .get("model")
      .and_then(Value::as_str)
      .unwrap_or("unknown")
      .to_string(),
    system: system_to_string(obj.get("system")),
    messages,
    tools: crate::tools::normalise_tools(
      obj
        .get("tools")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]),
    ),
    tool_choice,
    sampling: Sampling {
      temperature: obj.get("temperature").and_then(Value::as_f64),
      top_p: obj.get("top_p").and_then(Value::as_f64),
      max_output_tokens: obj.get("max_tokens").and_then(Value::as_u64),
      stop: obj.get("stop_sequences").cloned(),
      n: None,
      seed: None,
    },
    reasoning: obj.get("thinking").cloned(),
    stream: obj.get("stream").and_then(Value::as_bool).unwrap_or(false),
    extras,
  })
}

pub fn request_to_value(req: &IrRequest) -> Result<Value> {
  let mut out = Map::new();
  out.insert("model".into(), Value::String(req.model.clone()));
  if let Some(system) = &req.system {
    out.insert("system".into(), Value::String(system.clone()));
  }
  out.insert(
    "messages".into(),
    Value::Array(req.messages.iter().map(message_to_messages).collect()),
  );
  let tools: Vec<Value> = req
    .tools
    .iter()
    .filter(|t| t.get("function").and_then(Value::as_object).is_some())
    .map(crate::tools::tool_to_messages)
    .collect();
  if !tools.is_empty() {
    out.insert("tools".into(), Value::Array(tools));

    let mut tool_choice = req.tool_choice.as_ref().map(crate::tools::tool_choice_to_messages);
    if let Some(parallel_tool_calls) = req.extras.get("parallel_tool_calls").and_then(Value::as_bool) {
      let choice = tool_choice.get_or_insert_with(|| json!({"type": "auto"}));
      if let Some(choice) = choice.as_object_mut() {
        choice.insert("disable_parallel_tool_use".into(), Value::Bool(!parallel_tool_calls));
      }
    }
    if let Some(tool_choice) = tool_choice {
      out.insert("tool_choice".into(), tool_choice);
    }
  }
  insert_opt_f64(&mut out, "temperature", req.sampling.temperature);
  insert_opt_f64(&mut out, "top_p", req.sampling.top_p);
  out.insert(
    "max_tokens".into(),
    Value::from(req.sampling.max_output_tokens.unwrap_or(DEFAULT_MESSAGES_MAX_TOKENS)),
  );
  if let Some(v) = &req.sampling.stop {
    out.insert("stop_sequences".into(), stop_sequences_to_messages(v));
  }
  if let Some(v) = &req.reasoning {
    out.insert("thinking".into(), v.clone());
  }
  if req.stream {
    out.insert("stream".into(), Value::Bool(true));
  }
  for (k, v) in &req.extras {
    if k == "parallel_tool_calls" {
      continue;
    }
    out.entry(k.clone()).or_insert_with(|| v.clone());
  }
  Ok(Value::Object(out))
}

pub fn response_from_value(v: &Value) -> Result<IrResponse> {
  let mut content = Vec::new();
  let mut tool_calls = Vec::new();
  if let Some(parts) = v.get("content").and_then(Value::as_array) {
    for part in parts {
      match part.get("type").and_then(Value::as_str) {
        Some("text") => content.push(ContentPart::Text {
          text: part.get("text").and_then(Value::as_str).unwrap_or_default().to_string(),
        }),
        Some("thinking") | Some("redacted_thinking") => content.push(ContentPart::Reasoning {
          text: part
            .get("thinking")
            .or_else(|| part.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        }),
        Some("tool_use") => tool_calls.push(ToolCall {
          id: part.get("id").and_then(Value::as_str).map(str::to_string),
          name: part.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
          arguments: part.get("input").cloned().unwrap_or(Value::Null),
        }),
        _ => content.push(ContentPart::Raw { value: part.clone() }),
      }
    }
  }
  Ok(IrResponse {
    id: v.get("id").and_then(Value::as_str).map(str::to_string),
    model: v.get("model").and_then(Value::as_str).map(str::to_string),
    role: v.get("role").and_then(Value::as_str).map(Role::from_wire),
    content,
    tool_calls,
    usage: v.get("usage").map(|u| Usage {
      input_tokens: u.get("input_tokens").and_then(Value::as_u64),
      output_tokens: u.get("output_tokens").and_then(Value::as_u64),
      total_tokens: None,
      input_tokens_details: None,
      output_tokens_details: None,
      extras: usage_extras(u, &["input_tokens", "output_tokens"]),
    }),
    finish_reason: v
      .get("stop_reason")
      .and_then(Value::as_str)
      .map(finish_reason_from_messages),
    extras: BTreeMap::new(),
  })
}

pub fn response_to_value(resp: &IrResponse) -> Result<Value> {
  let mut content = Vec::new();
  let text = text_from_parts(&resp.content);
  if !text.is_empty() {
    content.push(json!({ "type": "text", "text": text }));
  }
  if let Some(reasoning) = reasoning_from_parts(&resp.content) {
    content.push(json!({ "type": "thinking", "thinking": reasoning }));
  }
  for call in &resp.tool_calls {
    content.push(json!({
      "type": "tool_use",
      "id": call.id.clone().unwrap_or_else(|| "toolu_converted".into()),
      "name": call.name,
      "input": call.arguments,
    }));
  }
  let mut out = json!({
    "id": resp.id.clone().unwrap_or_else(|| "msg_converted".into()),
    "type": "message",
    "role": "assistant",
    "model": resp.model.clone().unwrap_or_default(),
    "content": content,
    "stop_reason": finish_reason_to_messages(resp.finish_reason.as_deref()),
    "stop_sequence": null,
  });
  if let Some(usage) = &resp.usage {
    let mut usage_json = serde_json::Map::new();
    usage_json.extend(usage.extras.clone());
    usage_json.insert("input_tokens".into(), Value::from(usage.input_tokens.unwrap_or(0)));
    usage_json.insert("output_tokens".into(), Value::from(usage.output_tokens.unwrap_or(0)));
    out["usage"] = Value::Object(usage_json);
  }
  Ok(out)
}

pub fn delta_from_messages_event(v: &Value) -> Vec<IrDelta> {
  let mut out = Vec::new();
  match v.get("type").and_then(Value::as_str) {
    Some("content_block_start") => {
      if let Some(content_block) = v
        .get("content_block")
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
      {
        out.push(IrDelta::ToolCall {
          index: v.get("index").and_then(Value::as_u64).unwrap_or(0) as usize,
          id: content_block.get("id").and_then(Value::as_str).map(str::to_string),
          name: content_block.get("name").and_then(Value::as_str).map(str::to_string),
          arguments_delta: content_block
            .get("input")
            .filter(|input| !matches!(input, Value::Object(object) if object.is_empty()))
            .map(Value::to_string)
            .unwrap_or_default(),
        });
      }
    }
    Some("content_block_delta") => {
      if let Some(delta) = v.get("delta") {
        match delta.get("type").and_then(Value::as_str) {
          Some("text_delta") => {
            if let Some(text) = delta.get("text").and_then(Value::as_str) {
              out.push(IrDelta::Text(text.to_string()));
            }
          }
          Some("thinking_delta") => {
            if let Some(text) = delta.get("thinking").and_then(Value::as_str) {
              out.push(IrDelta::Reasoning(text.to_string()));
            }
          }
          Some("input_json_delta") => out.push(IrDelta::ToolCall {
            index: v.get("index").and_then(Value::as_u64).unwrap_or(0) as usize,
            id: None,
            name: None,
            arguments_delta: delta
              .get("partial_json")
              .and_then(Value::as_str)
              .unwrap_or_default()
              .to_string(),
          }),
          _ => {}
        }
      }
    }
    Some("message_delta") => {
      if let Some(stop) = v
        .get("delta")
        .and_then(|d| d.get("stop_reason"))
        .and_then(Value::as_str)
      {
        out.push(IrDelta::Finish(Some(finish_reason_from_messages(stop))));
      }
      if let Some(u) = v.get("usage") {
        out.push(IrDelta::Usage(Usage {
          input_tokens: None,
          output_tokens: u.get("output_tokens").and_then(Value::as_u64),
          total_tokens: None,
          input_tokens_details: None,
          output_tokens_details: None,
          extras: usage_extras(u, &["output_tokens"]),
        }));
      }
    }
    Some("message_start") => {
      if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
        out.push(IrDelta::Usage(Usage {
          input_tokens: u.get("input_tokens").and_then(Value::as_u64),
          output_tokens: u.get("output_tokens").and_then(Value::as_u64),
          total_tokens: None,
          input_tokens_details: None,
          output_tokens_details: None,
          extras: usage_extras(u, &["input_tokens", "output_tokens"]),
        }));
      }
    }
    _ => {}
  }
  out
}

pub fn events_from_deltas(resp_id: &str, model: &str, deltas: &[IrDelta], finish: bool) -> Vec<(String, Value)> {
  let mut events = Vec::new();
  for delta in deltas {
    match delta {
      IrDelta::Text(text) => events.push((
        "content_block_delta".into(),
        json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": text } }),
      )),
      IrDelta::Reasoning(text) => events.push((
        "content_block_delta".into(),
        json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "thinking_delta", "thinking": text } }),
      )),
      IrDelta::ToolCall { index, arguments_delta, .. } => events.push((
        "content_block_delta".into(),
        json!({ "type": "content_block_delta", "index": index, "delta": { "type": "input_json_delta", "partial_json": arguments_delta } }),
      )),
      IrDelta::Usage(usage) => events.push((
        "message_delta".into(),
        {
          let mut usage_json = serde_json::Map::new();
          usage_json.extend(usage.extras.clone());
          usage_json.insert(
            "output_tokens".into(),
            Value::from(usage.output_tokens.unwrap_or(0)),
          );
          json!({ "type": "message_delta", "delta": {}, "usage": usage_json })
        },
      )),
      IrDelta::Finish(reason) => events.push((
        "message_delta".into(),
        json!({ "type": "message_delta", "delta": { "stop_reason": finish_reason_to_messages(reason.as_deref()), "stop_sequence": null } }),
      )),
    }
  }
  if finish {
    events.insert(
      0,
      (
        "message_start".into(),
        json!({
          "type": "message_start",
          "message": { "id": resp_id, "type": "message", "role": "assistant", "model": model, "content": [], "stop_reason": null, "stop_sequence": null, "usage": { "input_tokens": 0, "output_tokens": 0 } }
        }),
      ),
    );
    events.push((
      "content_block_stop".into(),
      json!({ "type": "content_block_stop", "index": 0 }),
    ));
    events.push(("message_stop".into(), json!({ "type": "message_stop" })));
  }
  events
}

fn message_from_messages(v: &Value) -> Result<IrMessage> {
  let role = Role::from_wire(v.get("role").and_then(Value::as_str).unwrap_or("user"));
  Ok(IrMessage {
    role,
    content: content_from_messages(v.get("content")),
    tool_call_id: None,
    name: None,
    raw: None,
  })
}

fn content_from_messages(content: Option<&Value>) -> Vec<ContentPart> {
  match content {
    Some(Value::String(s)) => vec![ContentPart::Text { text: s.clone() }],
    Some(Value::Array(parts)) => parts.iter().map(part_from_messages).collect(),
    Some(v) => vec![ContentPart::Raw { value: v.clone() }],
    None => Vec::new(),
  }
}

fn part_from_messages(v: &Value) -> ContentPart {
  match v.get("type").and_then(Value::as_str) {
    Some("text") => ContentPart::Text {
      text: v.get("text").and_then(Value::as_str).unwrap_or_default().to_string(),
    },
    Some("thinking") | Some("redacted_thinking") => ContentPart::Reasoning {
      text: v
        .get("thinking")
        .or_else(|| v.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string(),
    },
    Some("tool_use") => ContentPart::ToolCall {
      call: ToolCall {
        id: v.get("id").and_then(Value::as_str).map(str::to_string),
        name: v.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
        arguments: v.get("input").cloned().unwrap_or(Value::Null),
      },
    },
    Some("tool_result") => ContentPart::ToolResult {
      id: v.get("tool_use_id").and_then(Value::as_str).map(str::to_string),
      content: v.get("content").cloned().unwrap_or(Value::Null),
    },
    _ => ContentPart::Raw { value: v.clone() },
  }
}

fn message_to_messages(msg: &IrMessage) -> Value {
  let content: Vec<_> = msg.content.iter().map(part_to_messages).collect();
  let role = if msg
    .content
    .iter()
    .any(|part| matches!(part, ContentPart::ToolResult { .. }))
  {
    "user"
  } else {
    msg.role.as_str()
  };
  json!({ "role": role, "content": content })
}

fn part_to_messages(part: &ContentPart) -> Value {
  match part {
    ContentPart::Text { text } => json!({ "type": "text", "text": text }),
    ContentPart::Reasoning { text } => json!({ "type": "thinking", "thinking": text }),
    ContentPart::ToolCall { call } => json!({
      "type": "tool_use",
      "id": call.id.clone().unwrap_or_else(|| "toolu_converted".into()),
      "name": call.name,
      "input": call.arguments,
    }),
    ContentPart::ToolResult { id, content } => json!({
      "type": "tool_result",
      "tool_use_id": id,
      "content": content,
    }),
    ContentPart::Raw { value } => value.clone(),
  }
}

fn system_to_string(system: Option<&Value>) -> Option<String> {
  match system {
    Some(Value::String(s)) => Some(s.clone()),
    Some(Value::Array(parts)) => {
      let text = parts
        .iter()
        .filter_map(|p| p.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n\n");
      (!text.is_empty()).then_some(text)
    }
    _ => None,
  }
}

fn stop_sequences_to_messages(stop: &Value) -> Value {
  match stop {
    Value::String(_) => Value::Array(vec![stop.clone()]),
    _ => stop.clone(),
  }
}

fn messages_tool_choice_from_value(tool_choice: Option<&Value>) -> (Option<Value>, Option<bool>) {
  let Some(tool_choice) = tool_choice else {
    return (None, None);
  };
  let mut canonical = tool_choice.clone();
  let parallel_tool_calls = canonical
    .as_object_mut()
    .and_then(|choice| choice.remove("disable_parallel_tool_use"))
    .and_then(|disabled| disabled.as_bool())
    .map(|disabled| !disabled);
  (
    Some(crate::tools::normalise_tool_choice(&canonical)),
    parallel_tool_calls,
  )
}

fn finish_reason_from_messages(reason: &str) -> String {
  match reason {
    "end_turn" | "stop_sequence" => "stop",
    "max_tokens" => "length",
    "tool_use" => "tool_calls",
    other => other,
  }
  .to_string()
}

fn finish_reason_to_messages(reason: Option<&str>) -> String {
  match reason {
    None | Some("stop" | "end_turn" | "stop_sequence") => "end_turn",
    Some("length" | "max_tokens" | "max_output_tokens") => "max_tokens",
    Some("tool_calls" | "tool_use") => "tool_use",
    Some(other) => other,
  }
  .to_string()
}

#[allow(dead_code)]
fn _tool_args_string(call: &ToolCall) -> String {
  args_to_string(&call.arguments)
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn messages_response_preserves_usage_extras() {
    let value = json!({
      "id": "msg_1",
      "type": "message",
      "role": "assistant",
      "model": "claude-test",
      "content": [],
      "stop_reason": "end_turn",
      "usage": {
        "input_tokens": 12,
        "output_tokens": 5,
        "cache_creation_input_tokens": 4,
        "cache_read_input_tokens": 3
      }
    });

    let response = response_from_value(&value).expect("response");
    let round_trip = response_to_value(&response).expect("round trip");

    assert_eq!(
      round_trip.get("usage"),
      Some(&json!({
        "input_tokens": 12,
        "output_tokens": 5,
        "cache_creation_input_tokens": 4,
        "cache_read_input_tokens": 3
      }))
    );
  }

  #[test]
  fn tool_results_use_user_role_and_tool_result_blocks() {
    let request = IrRequest {
      model: "claude-test".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::Tool,
        content: vec![ContentPart::ToolResult {
          id: Some("call_1".into()),
          content: Value::String("tool output".into()),
        }],
        tool_call_id: Some("call_1".into()),
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras: BTreeMap::new(),
    };

    let body = request_to_value(&request).expect("render Messages request");

    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(
      body["messages"][0]["content"][0],
      json!({
        "type": "tool_result",
        "tool_use_id": "call_1",
        "content": "tool output"
      })
    );
  }

  #[test]
  fn messages_request_defaults_required_max_tokens() {
    let request = IrRequest {
      model: "claude-test".into(),
      ..IrRequest::default()
    };

    let body = request_to_value(&request).expect("render Messages request");

    assert_eq!(body["max_tokens"], DEFAULT_MESSAGES_MAX_TOKENS);
  }

  #[test]
  fn messages_request_normalizes_scalar_stop_sequence() {
    let request = IrRequest {
      model: "claude-test".into(),
      sampling: Sampling {
        stop: Some(json!("DONE")),
        ..Sampling::default()
      },
      ..IrRequest::default()
    };

    let body = request_to_value(&request).expect("render Messages request");

    assert_eq!(body["stop_sequences"], json!(["DONE"]));
  }

  #[test]
  fn messages_request_preserves_array_and_raw_stop_sequences() {
    for stop in [json!(["DONE", "STOP"]), json!({ "provider_extension": true })] {
      let request = IrRequest {
        model: "claude-test".into(),
        sampling: Sampling {
          stop: Some(stop.clone()),
          ..Sampling::default()
        },
        ..IrRequest::default()
      };

      let body = request_to_value(&request).expect("render Messages request");

      assert_eq!(body["stop_sequences"], stop);
    }
  }

  #[test]
  fn messages_tool_choice_extensions_round_trip_and_translate() {
    let body = json!({
      "model": "claude-test",
      "messages": [{ "role": "user", "content": "Find it" }],
      "max_tokens": 128,
      "tools": [{
        "name": "lookup",
        "input_schema": { "type": "object" }
      }],
      "tool_choice": {
        "type": "auto",
        "disable_parallel_tool_use": true
      }
    });

    let request = request_from_value(&body).expect("parse Messages request");

    assert_eq!(request.tool_choice, Some(json!("auto")));
    assert_eq!(request.extras.get("parallel_tool_calls"), Some(&json!(false)));

    let responses = crate::value::responses::request_to_value(&request).expect("render Responses request");
    assert_eq!(responses["tool_choice"], "auto");
    assert_eq!(responses["parallel_tool_calls"], false);

    let round_trip = request_to_value(&request).expect("render Messages request");
    assert_eq!(
      round_trip["tool_choice"],
      json!({
        "type": "auto",
        "disable_parallel_tool_use": true
      })
    );
    assert!(round_trip.get("parallel_tool_calls").is_none());
  }

  #[test]
  fn messages_omits_tool_controls_when_no_tools_can_be_converted() {
    let request = IrRequest {
      model: "claude-test".into(),
      tools: vec![json!({"type": "web_search"})],
      tool_choice: Some(json!("auto")),
      extras: BTreeMap::from([("parallel_tool_calls".into(), json!(false))]),
      ..IrRequest::default()
    };

    let body = request_to_value(&request).expect("render Messages request");

    assert!(body.get("tools").is_none());
    assert!(body.get("tool_choice").is_none());
    assert!(body.get("parallel_tool_calls").is_none());
  }

  #[test]
  fn messages_finish_reasons_use_canonical_ir_values() {
    for (messages_reason, canonical_reason) in [
      ("end_turn", "stop"),
      ("stop_sequence", "stop"),
      ("max_tokens", "length"),
      ("tool_use", "tool_calls"),
    ] {
      let body = json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": [],
        "stop_reason": messages_reason
      });

      let response = response_from_value(&body).expect("parse Messages response");
      assert_eq!(response.finish_reason.as_deref(), Some(canonical_reason));

      let deltas = delta_from_messages_event(&json!({
        "type": "message_delta",
        "delta": { "stop_reason": messages_reason }
      }));
      assert!(matches!(
        deltas.as_slice(),
        [IrDelta::Finish(Some(reason))] if reason == canonical_reason
      ));
    }
  }

  #[test]
  fn canonical_finish_reasons_render_as_messages_values() {
    for (canonical_reason, messages_reason) in [
      ("stop", "end_turn"),
      ("length", "max_tokens"),
      ("tool_calls", "tool_use"),
    ] {
      let response = IrResponse {
        finish_reason: Some(canonical_reason.into()),
        ..IrResponse::default()
      };
      let body = response_to_value(&response).expect("render Messages response");
      assert_eq!(body["stop_reason"], messages_reason);

      let events = events_from_deltas(
        "msg_1",
        "claude-test",
        &[IrDelta::Finish(Some(canonical_reason.into()))],
        false,
      );
      assert_eq!(events[0].1["delta"]["stop_reason"], messages_reason);
    }
  }

  #[test]
  fn messages_tool_start_emits_identity_and_complete_input() {
    let start = json!({
      "type": "content_block_start",
      "index": 2,
      "content_block": {
        "type": "tool_use",
        "id": "toolu_123",
        "name": "lookup",
        "input": { "query": "rust" }
      }
    });

    let deltas = delta_from_messages_event(&start);

    assert_eq!(deltas.len(), 1);
    match &deltas[0] {
      IrDelta::ToolCall {
        index,
        id,
        name,
        arguments_delta,
      } => {
        assert_eq!(*index, 2);
        assert_eq!(id.as_deref(), Some("toolu_123"));
        assert_eq!(name.as_deref(), Some("lookup"));
        assert_eq!(arguments_delta, r#"{"query":"rust"}"#);
      }
      other => panic!("expected tool call delta, got {other:?}"),
    }

    let mut response = IrResponse::default();
    for delta in deltas {
      response.push_delta(delta);
    }

    assert_eq!(response.tool_calls[2].id.as_deref(), Some("toolu_123"));
    assert_eq!(response.tool_calls[2].name, "lookup");
    assert_eq!(response.tool_calls[2].arguments, json!(r#"{"query":"rust"}"#));
  }
}

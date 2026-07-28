use super::chat::args_to_string;
use crate::error::{ConvertError, Result};
use crate::ir::*;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const REQUEST_KEYS: &[&str] = &[
  "model",
  "input",
  "instructions",
  "tools",
  "tool_choice",
  "temperature",
  "top_p",
  "max_output_tokens",
  "max_tokens",
  "stop",
  "stream",
  "reasoning",
  "store",
  "metadata",
];

pub fn request_from_value(v: &Value) -> Result<IrRequest> {
  let obj = v
    .as_object()
    .ok_or_else(|| ConvertError::bad_shape("body", "expected object"))?;
  let model = obj
    .get("model")
    .and_then(Value::as_str)
    .unwrap_or("unknown")
    .to_string();
  let input = obj.get("input").ok_or(ConvertError::MissingField { field: "input" })?;
  let (instruction_parts, messages) = input_to_messages(input)?;
  let mut system_parts = Vec::new();
  if let Some(instructions) = obj.get("instructions").and_then(Value::as_str) {
    if !instructions.is_empty() {
      system_parts.push(instructions.to_string());
    }
  }
  system_parts.extend(instruction_parts);
  Ok(IrRequest {
    model,
    system: (!system_parts.is_empty()).then(|| system_parts.join("\n\n")),
    messages,
    tools: crate::tools::normalise_tools(
      obj
        .get("tools")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]),
    ),
    tool_choice: obj.get("tool_choice").map(crate::tools::normalise_tool_choice),
    sampling: Sampling {
      temperature: obj.get("temperature").and_then(Value::as_f64),
      top_p: obj.get("top_p").and_then(Value::as_f64),
      max_output_tokens: obj
        .get("max_output_tokens")
        .or_else(|| obj.get("max_tokens"))
        .and_then(Value::as_u64),
      stop: obj.get("stop").cloned(),
      n: None,
      seed: None,
    },
    reasoning: obj.get("reasoning").cloned(),
    stream: obj.get("stream").and_then(Value::as_bool).unwrap_or(false),
    extras: extras_from_object(obj, REQUEST_KEYS),
  })
}

pub fn request_to_value(req: &IrRequest) -> Result<Value> {
  let mut out = Map::new();
  out.insert("model".into(), Value::String(req.model.clone()));
  if let Some(system) = &req.system {
    out.insert("instructions".into(), Value::String(system.clone()));
  }
  out.insert(
    "input".into(),
    Value::Array(req.messages.iter().flat_map(message_to_responses_input_items).collect()),
  );
  if !req.tools.is_empty() {
    out.insert(
      "tools".into(),
      Value::Array(req.tools.iter().map(crate::tools::tool_to_responses).collect()),
    );
  }
  if let Some(v) = &req.tool_choice {
    out.insert("tool_choice".into(), crate::tools::tool_choice_to_responses(v));
  }
  insert_opt_f64(&mut out, "temperature", req.sampling.temperature);
  insert_opt_f64(&mut out, "top_p", req.sampling.top_p);
  insert_opt_u64(&mut out, "max_output_tokens", req.sampling.max_output_tokens);
  if let Some(v) = &req.sampling.stop {
    out.insert("stop".into(), v.clone());
  }
  if let Some(v) = normalize_reasoning(
    req.reasoning.clone(),
    req.extras.get("reasoning_effort").and_then(Value::as_str),
  ) {
    out.insert("reasoning".into(), v.clone());
  }
  out.insert(
    "store".into(),
    req.extras.get("store").cloned().unwrap_or(Value::Bool(false)),
  );
  if req.stream {
    out.insert("stream".into(), Value::Bool(true));
  }
  for (k, v) in &req.extras {
    if k == "reasoning_effort" || k == "verbosity" {
      continue;
    }
    out.entry(k.clone()).or_insert_with(|| v.clone());
  }
  normalize_text_verbosity(&mut out, req.extras.get("verbosity"));
  Ok(Value::Object(out))
}

fn normalize_text_verbosity(out: &mut Map<String, Value>, verbosity: Option<&Value>) {
  let Some(verbosity) = verbosity.cloned() else {
    return;
  };

  match out.get_mut("text") {
    Some(Value::Object(text)) => {
      text.entry("verbosity").or_insert(verbosity);
    }
    Some(_) => {}
    None => {
      out.insert("text".into(), json!({ "verbosity": verbosity }));
    }
  }
}

fn normalize_reasoning(reasoning: Option<Value>, reasoning_effort: Option<&str>) -> Option<Value> {
  let Some(effort) = reasoning_effort else {
    return reasoning;
  };

  match reasoning {
    Some(Value::Object(mut obj)) => {
      obj.entry("effort").or_insert_with(|| Value::String(effort.to_string()));
      Some(Value::Object(obj))
    }
    Some(other) => Some(other),
    None => Some(json!({ "effort": effort })),
  }
}

pub fn response_from_value(v: &Value) -> Result<IrResponse> {
  let mut content = Vec::new();
  let mut tool_calls = Vec::new();
  if let Some(text) = v.get("output_text").and_then(Value::as_str) {
    content.push(ContentPart::Text { text: text.to_string() });
  }
  if let Some(output) = v.get("output").and_then(Value::as_array) {
    for item in output {
      match item.get("type").and_then(Value::as_str) {
        Some("message") => {
          if let Some(parts) = item.get("content").and_then(Value::as_array) {
            for part in parts {
              match part.get("type").and_then(Value::as_str) {
                Some("output_text") | Some("text") => content.push(ContentPart::Text {
                  text: part.get("text").and_then(Value::as_str).unwrap_or_default().to_string(),
                }),
                Some("reasoning") => content.push(ContentPart::Reasoning {
                  text: part
                    .get("summary")
                    .or_else(|| part.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                }),
                _ => content.push(ContentPart::Raw { value: part.clone() }),
              }
            }
          }
        }
        Some("function_call") => tool_calls.push(ToolCall {
          id: item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string),
          name: item.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
          arguments: item
            .get("arguments")
            .and_then(Value::as_str)
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| item.get("arguments").cloned().unwrap_or(Value::Null)),
        }),
        _ => {}
      }
    }
  }
  let finish_reason = match v.get("status").and_then(Value::as_str) {
    Some("incomplete") => v
      .pointer("/incomplete_details/reason")
      .and_then(Value::as_str)
      .map(|reason| match reason {
        "max_output_tokens" => "length".to_string(),
        other => other.to_string(),
      })
      .or_else(|| Some("incomplete".into())),
    Some("completed") if response_has_tool_call_output(v) => Some("tool_calls".into()),
    Some("completed") => Some("stop".into()),
    Some(status) => Some(status.to_string()),
    None => None,
  };
  Ok(IrResponse {
    id: v.get("id").and_then(Value::as_str).map(str::to_string),
    model: v.get("model").and_then(Value::as_str).map(str::to_string),
    role: Some(Role::Assistant),
    content,
    tool_calls,
    usage: crate::ir::usage_from_openai(v),
    finish_reason,
    extras: BTreeMap::new(),
  })
}

pub fn response_to_value(resp: &IrResponse) -> Result<Value> {
  let id = resp.id.clone().unwrap_or_else(|| "resp_converted".into());
  let mut output = Vec::new();
  let mut content = Vec::new();
  let text = text_from_parts(&resp.content);
  if !text.is_empty() {
    content.push(json!({ "type": "output_text", "text": text, "annotations": [] }));
  }
  if let Some(reasoning) = reasoning_from_parts(&resp.content) {
    content.push(json!({ "type": "reasoning", "summary": reasoning }));
  }
  if !content.is_empty() {
    output.push(json!({ "type": "message", "id": format!("msg_{id}"), "status": "completed", "role": "assistant", "content": content }));
  }
  for call in &resp.tool_calls {
    output.push(json!({
      "type": "function_call",
      "id": call.id.clone().unwrap_or_else(|| "fc_converted".into()),
      "call_id": call.id.clone().unwrap_or_else(|| "call_converted".into()),
      "name": call.name,
      "arguments": args_to_string(&call.arguments),
      "status": "completed",
    }));
  }
  let (status, incomplete_reason) = responses_completion_status(resp.finish_reason.as_deref());
  let mut out = json!({
    "id": id,
    "object": "response",
    "status": status,
    "model": resp.model.clone().unwrap_or_default(),
    "output": output,
    "output_text": text_from_parts(&resp.content),
  });
  if let Some(usage) = &resp.usage {
    out["usage"] = usage_to_io(usage);
  }
  if let Some(reason) = incomplete_reason {
    out["incomplete_details"] = json!({"reason": reason});
  }
  Ok(out)
}

pub fn delta_from_responses_event(v: &Value) -> Vec<IrDelta> {
  let mut out = Vec::new();
  match v.get("type").and_then(Value::as_str) {
    Some("response.output_text.delta") => {
      if let Some(delta) = v.get("delta").and_then(Value::as_str) {
        out.push(IrDelta::Text(delta.to_string()));
      }
    }
    Some("response.reasoning_summary_text.delta") | Some("response.reasoning_text.delta") => {
      if let Some(delta) = v.get("delta").and_then(Value::as_str) {
        out.push(IrDelta::Reasoning(delta.to_string()));
      }
    }
    Some("response.function_call_arguments.delta") | Some("response.custom_tool_call_input.delta") => {
      out.push(IrDelta::ToolCall {
        index: v.get("output_index").and_then(Value::as_u64).unwrap_or(0) as usize,
        id: v
          .get("call_id")
          .or_else(|| v.get("item_id"))
          .and_then(Value::as_str)
          .map(str::to_string),
        name: None,
        arguments_delta: v.get("delta").and_then(Value::as_str).unwrap_or_default().to_string(),
      })
    }
    Some("response.completed") => {
      if let Some(resp) = v.get("response") {
        if let Some(usage) = crate::ir::usage_from_openai(resp) {
          out.push(IrDelta::Usage(usage));
        }
      }
      let reason = v.get("response").map(completed_finish_reason).unwrap_or("stop");
      out.push(IrDelta::Finish(Some(reason.into())));
    }
    _ => {}
  }
  out
}

pub(crate) fn response_has_tool_call_output(response: &Value) -> bool {
  response.get("output").and_then(Value::as_array).is_some_and(|output| {
    output.iter().any(|item| {
      matches!(
        item.get("type").and_then(Value::as_str),
        Some("function_call" | "custom_tool_call")
      )
    })
  })
}

pub(crate) fn completed_finish_reason(response: &Value) -> &'static str {
  if response_has_tool_call_output(response) {
    "tool_calls"
  } else {
    "stop"
  }
}

pub fn events_from_deltas(resp_id: &str, model: &str, deltas: &[IrDelta], finish: bool) -> Vec<(String, Value)> {
  let mut events = Vec::new();
  for delta in deltas {
    match delta {
      IrDelta::Text(text) => events.push((
        "response.output_text.delta".into(),
        json!({ "type": "response.output_text.delta", "response_id": resp_id, "output_index": 0, "content_index": 0, "delta": text }),
      )),
      IrDelta::Reasoning(text) => events.push((
        "response.reasoning_text.delta".into(),
        json!({ "type": "response.reasoning_text.delta", "response_id": resp_id, "output_index": 0, "content_index": 0, "delta": text }),
      )),
      IrDelta::ToolCall { index, arguments_delta, .. } => events.push((
        "response.function_call_arguments.delta".into(),
        json!({ "type": "response.function_call_arguments.delta", "response_id": resp_id, "output_index": index, "delta": arguments_delta }),
      )),
      IrDelta::Usage(_) => {}
      IrDelta::Finish(_) => {}
    }
  }
  if finish {
    events.push((
      "response.completed".into(),
      json!({
        "type": "response.completed",
        "response": { "id": resp_id, "object": "response", "status": "completed", "model": model }
      }),
    ));
  }
  events
}

fn input_to_messages(input: &Value) -> Result<(Vec<String>, Vec<IrMessage>)> {
  if let Some(s) = input.as_str() {
    return Ok((
      Vec::new(),
      vec![IrMessage {
        role: Role::User,
        content: vec![ContentPart::Text { text: s.to_string() }],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
    ));
  }
  let arr = input
    .as_array()
    .ok_or_else(|| ConvertError::bad_shape("input", "expected string or array"))?;
  let mut system_parts = Vec::new();
  let mut messages = Vec::new();
  let mut pending_assistant: Option<IrMessage> = None;
  for item in arr {
    // Dispatch on `type` for special items first; everything else falls
    // through to role-based message handling.
    match item.get("type").and_then(Value::as_str) {
      Some("reasoning") => {
        if let Some(text) = reasoning_text_from_input_item(item) {
          push_assistant_part(&mut pending_assistant, ContentPart::Reasoning { text });
        }
        continue;
      }
      Some("function_call") => {
        let call_id = item.get("call_id").and_then(Value::as_str).map(str::to_string);
        let name = item.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        let arguments_raw = item.get("arguments").cloned().unwrap_or(Value::Null);
        let arguments = match &arguments_raw {
          Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone())),
          other => other.clone(),
        };
        push_assistant_part(
          &mut pending_assistant,
          ContentPart::ToolCall {
            call: ToolCall {
              id: call_id,
              name,
              arguments,
            },
          },
        );
        continue;
      }
      Some("function_call_output") => {
        flush_pending_assistant(&mut messages, &mut pending_assistant);
        let call_id = item.get("call_id").and_then(Value::as_str).map(str::to_string);
        let output = item.get("output").cloned().unwrap_or(Value::Null);
        messages.push(IrMessage {
          role: Role::Tool,
          content: vec![ContentPart::ToolResult {
            id: call_id.clone(),
            content: output,
          }],
          tool_call_id: call_id,
          name: None,
          raw: None,
        });
        continue;
      }
      _ => {}
    }
    let message = input_item_to_message(item)?;
    let role = item.get("role").and_then(Value::as_str).unwrap_or("user");
    if matches!(role, "system" | "developer") {
      flush_pending_assistant(&mut messages, &mut pending_assistant);
      let text = text_from_parts(&message.content);
      if !text.is_empty() {
        system_parts.push(text);
      }
    } else if role == "assistant" {
      let pending = pending_assistant.get_or_insert_with(empty_assistant_message);
      pending.content.extend(message.content);
    } else {
      flush_pending_assistant(&mut messages, &mut pending_assistant);
      messages.push(message);
    }
  }
  flush_pending_assistant(&mut messages, &mut pending_assistant);
  Ok((system_parts, messages))
}

fn empty_assistant_message() -> IrMessage {
  IrMessage {
    role: Role::Assistant,
    content: Vec::new(),
    tool_call_id: None,
    name: None,
    raw: None,
  }
}

fn push_assistant_part(pending: &mut Option<IrMessage>, part: ContentPart) {
  pending.get_or_insert_with(empty_assistant_message).content.push(part);
}

fn flush_pending_assistant(messages: &mut Vec<IrMessage>, pending: &mut Option<IrMessage>) {
  if let Some(message) = pending.take() {
    messages.push(message);
  }
}

/// Pull text out of a Responses-API reasoning input item. Prefers
/// `content[].text` (full reasoning_text) and falls back to `summary[].text`.
fn reasoning_text_from_input_item(item: &Value) -> Option<String> {
  fn join_texts(arr: &[Value], type_filter: &[&str]) -> String {
    arr
      .iter()
      .filter_map(|p| {
        let kind = p.get("type").and_then(Value::as_str).unwrap_or_default();
        if type_filter.contains(&kind) {
          p.get("text").and_then(Value::as_str).map(str::to_string)
        } else {
          None
        }
      })
      .collect::<Vec<_>>()
      .join("")
  }
  let content_text = item
    .get("content")
    .and_then(Value::as_array)
    .map(|arr| join_texts(arr, &["reasoning_text", "text"]))
    .unwrap_or_default();
  if !content_text.is_empty() {
    return Some(content_text);
  }
  let summary_text = item
    .get("summary")
    .and_then(Value::as_array)
    .map(|arr| join_texts(arr, &["summary_text", "text"]))
    .unwrap_or_default();
  (!summary_text.is_empty()).then_some(summary_text)
}

fn input_item_to_message(item: &Value) -> Result<IrMessage> {
  let role = Role::from_wire(item.get("role").and_then(Value::as_str).unwrap_or("user"));
  let content = match item.get("content") {
    Some(Value::String(s)) => vec![ContentPart::Text { text: s.clone() }],
    Some(Value::Array(parts)) => parts.iter().map(part_from_responses).collect(),
    Some(v) => vec![ContentPart::Raw { value: v.clone() }],
    None => Vec::new(),
  };
  Ok(IrMessage {
    role,
    content,
    tool_call_id: item.get("call_id").and_then(Value::as_str).map(str::to_string),
    name: item.get("name").and_then(Value::as_str).map(str::to_string),
    raw: None,
  })
}

fn part_from_responses(v: &Value) -> ContentPart {
  match v.get("type").and_then(Value::as_str) {
    Some("input_text") | Some("output_text") | Some("text") => ContentPart::Text {
      text: v.get("text").and_then(Value::as_str).unwrap_or_default().to_string(),
    },
    _ => ContentPart::Raw { value: v.clone() },
  }
}

fn message_to_responses_input_items(msg: &IrMessage) -> Vec<Value> {
  let mut items: Vec<_> = msg
    .content
    .iter()
    .filter_map(|part| match part {
      ContentPart::ToolResult { id, content } => Some(json!({
        "type": "function_call_output",
        "call_id": id.as_ref().or(msg.tool_call_id.as_ref()).cloned().unwrap_or_default(),
        "output": tool_result_output(content),
      })),
      _ => None,
    })
    .collect();
  let has_tool_results = !items.is_empty();
  if msg.role == Role::Tool && !has_tool_results {
    return vec![json!({
      "type": "function_call_output",
      "call_id": msg.tool_call_id.clone().unwrap_or_default(),
      "output": text_from_parts(&msg.content),
    })];
  }
  let role = if has_tool_results { &Role::User } else { &msg.role };
  let text_type = match role {
    Role::Assistant => "output_text",
    _ => "input_text",
  };
  let parts: Vec<_> = msg
    .content
    .iter()
    .filter_map(|p| match p {
      ContentPart::Text { text } => Some(json!({ "type": text_type, "text": text })),
      ContentPart::Raw { value } => Some(value.clone()),
      _ => None,
    })
    .collect();
  let tool_calls: Vec<_> = msg
    .content
    .iter()
    .filter_map(|part| match part {
      ContentPart::ToolCall { call } => Some(json!({
        "type": "function_call",
        "call_id": call.id.clone().unwrap_or_default(),
        "name": call.name,
        "arguments": args_to_string(&call.arguments),
      })),
      _ => None,
    })
    .collect();
  if !parts.is_empty() || (!has_tool_results && tool_calls.is_empty() && !matches!(msg.role, Role::Assistant)) {
    items.push(json!({ "role": role.as_str(), "content": parts }));
  }
  items.extend(tool_calls);
  items
}

fn tool_result_output(content: &Value) -> String {
  content
    .as_str()
    .map(str::to_string)
    .unwrap_or_else(|| serde_json::to_string(content).unwrap_or_default())
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn request_from_value_merges_system_and_developer_items_into_system_prompt() {
    let body = json!({
      "model": "deepseek-v4-flash",
      "instructions": "top instructions",
      "input": [
        { "role": "developer", "content": [{ "type": "input_text", "text": "dev first" }] },
        { "role": "user", "content": [{ "type": "input_text", "text": "hello" }] },
        { "role": "developer", "content": [{ "type": "input_text", "text": "dev middle" }] },
        { "role": "assistant", "content": [{ "type": "output_text", "text": "hi" }] }
      ]
    });

    let req = request_from_value(&body).expect("request should parse");

    assert_eq!(
      req.system.as_deref(),
      Some("top instructions\n\ndev first\n\ndev middle")
    );
    assert_eq!(req.messages.len(), 2);
    assert_eq!(req.messages[0].role, Role::User);
    assert_eq!(req.messages[1].role, Role::Assistant);
  }

  #[test]
  fn request_to_value_defaults_store_to_false() {
    let req = IrRequest {
      model: "deepseek-v4-flash".into(),
      system: Some("sys".into()),
      messages: vec![IrMessage {
        role: Role::User,
        content: vec![ContentPart::Text { text: "hello".into() }],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras: Default::default(),
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(body.get("store"), Some(&Value::Bool(false)));
  }

  #[test]
  fn request_to_value_uses_output_text_for_assistant_message_content() {
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![
        IrMessage {
          role: Role::User,
          content: vec![ContentPart::Text { text: "hi".into() }],
          tool_call_id: None,
          name: None,
          raw: None,
        },
        IrMessage {
          role: Role::Assistant,
          content: vec![ContentPart::Text { text: "hello".into() }],
          tool_call_id: None,
          name: None,
          raw: None,
        },
      ],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras: Default::default(),
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(body["input"][0]["content"][0]["type"], "input_text");
    assert_eq!(body["input"][1]["content"][0]["type"], "output_text");
  }

  #[test]
  fn request_to_value_renders_tool_messages_as_function_call_output_items() {
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::Tool,
        content: vec![ContentPart::Text {
          text: "tool result".into(),
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
      extras: Default::default(),
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(body["input"][0]["type"], "function_call_output");
    assert_eq!(body["input"][0]["call_id"], "call_1");
    assert_eq!(body["input"][0]["output"], "tool result");
    assert!(body["input"][0].get("role").is_none());
  }

  #[test]
  fn request_to_value_preserves_all_tool_results_and_sibling_content() {
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::User,
        content: vec![
          ContentPart::ToolResult {
            id: Some("call_1".into()),
            content: json!("first result"),
          },
          ContentPart::ToolResult {
            id: Some("call_2".into()),
            content: json!({ "value": 2 }),
          },
          ContentPart::Text {
            text: "Now compare them.".into(),
          },
          ContentPart::Raw {
            value: json!({
              "type": "input_image",
              "image_url": "https://example.invalid/chart.png"
            }),
          },
        ],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras: Default::default(),
    };

    let body = request_to_value(&req).expect("request should render");
    let input = body["input"].as_array().expect("input items");

    assert_eq!(input.len(), 3);
    assert_eq!(
      input[0],
      json!({
        "type": "function_call_output",
        "call_id": "call_1",
        "output": "first result",
      })
    );
    assert_eq!(
      input[1],
      json!({
        "type": "function_call_output",
        "call_id": "call_2",
        "output": "{\"value\":2}",
      })
    );
    assert_eq!(
      input[2],
      json!({
        "role": "user",
        "content": [
          { "type": "input_text", "text": "Now compare them." },
          {
            "type": "input_image",
            "image_url": "https://example.invalid/chart.png"
          }
        ],
      })
    );
  }

  #[test]
  fn request_to_value_renders_assistant_tool_calls_as_function_call_items() {
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::Assistant,
        content: vec![
          ContentPart::Text {
            text: "I'll inspect it.".into(),
          },
          ContentPart::ToolCall {
            call: ToolCall {
              id: Some("call_1".into()),
              name: "bash".into(),
              arguments: json!({ "command": "ls \"/tmp\"", "description": "Verifies temporary directory exists" }),
            },
          },
        ],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras: Default::default(),
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(body["input"][0]["role"], "assistant");
    assert_eq!(body["input"][0]["content"][0]["type"], "output_text");
    assert_eq!(body["input"][1]["type"], "function_call");
    assert_eq!(body["input"][1]["call_id"], "call_1");
    assert_eq!(body["input"][1]["name"], "bash");
    let args: Value = serde_json::from_str(body["input"][1]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(args["command"], "ls \"/tmp\"");
    assert!(body["input"][1].get("role").is_none());
  }

  #[test]
  fn request_to_value_promotes_reasoning_effort_extra() {
    let mut extras = std::collections::BTreeMap::new();
    extras.insert("reasoning_effort".into(), json!("high"));
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::User,
        content: vec![ContentPart::Text { text: "hello".into() }],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras,
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(body.get("reasoning"), Some(&json!({ "effort": "high" })));
    assert!(body.get("reasoning_effort").is_none());
  }

  #[test]
  fn request_to_value_preserves_existing_reasoning_effort() {
    let mut extras = std::collections::BTreeMap::new();
    extras.insert("reasoning_effort".into(), json!("high"));
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::User,
        content: vec![ContentPart::Text { text: "hello".into() }],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: Some(json!({ "effort": "low", "summary": "auto" })),
      stream: false,
      extras,
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(
      body.get("reasoning"),
      Some(&json!({ "effort": "low", "summary": "auto" }))
    );
    assert!(body.get("reasoning_effort").is_none());
  }

  #[test]
  fn request_to_value_promotes_verbosity_extra_into_text() {
    let mut extras = std::collections::BTreeMap::new();
    extras.insert("verbosity".into(), json!("low"));
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::User,
        content: vec![ContentPart::Text { text: "hello".into() }],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras,
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(body.get("text"), Some(&json!({ "verbosity": "low" })));
    assert!(body.get("verbosity").is_none());
  }

  #[test]
  fn request_to_value_preserves_existing_text_verbosity() {
    let mut extras = std::collections::BTreeMap::new();
    extras.insert("verbosity".into(), json!("low"));
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::User,
        content: vec![ContentPart::Text { text: "hello".into() }],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras,
    };

    let mut body = request_to_value(&req).expect("request should render");
    body.as_object_mut().expect("request body object").insert(
      "text".into(),
      json!({ "verbosity": "high", "format": { "type": "text" } }),
    );

    normalize_text_verbosity(body.as_object_mut().expect("request body object"), Some(&json!("low")));

    assert_eq!(
      body.get("text"),
      Some(&json!({ "verbosity": "high", "format": { "type": "text" } }))
    );
    assert!(body.get("verbosity").is_none());
  }

  #[test]
  fn request_to_value_preserves_explicit_text_extra_before_normalizing_verbosity() {
    let mut extras = std::collections::BTreeMap::new();
    extras.insert("verbosity".into(), json!("low"));
    extras.insert("text".into(), json!({ "format": { "type": "text" } }));
    let req = IrRequest {
      model: "gpt-5.4".into(),
      system: None,
      messages: vec![IrMessage {
        role: Role::User,
        content: vec![ContentPart::Text { text: "hello".into() }],
        tool_call_id: None,
        name: None,
        raw: None,
      }],
      tools: Vec::new(),
      tool_choice: None,
      sampling: Sampling::default(),
      reasoning: None,
      stream: false,
      extras,
    };

    let body = request_to_value(&req).expect("request should render");

    assert_eq!(
      body.get("text"),
      Some(&json!({ "format": { "type": "text" }, "verbosity": "low" }))
    );
    assert!(body.get("verbosity").is_none());
  }

  #[test]
  fn responses_input_reasoning_item_renders_assistant_reasoning_content() {
    let body = single_item_request(json!({
      "content": [
        {
          "text": "\nI'll read the numbers from `tool_call/data.txt`, sum them, and write the total to `tool_call/answer.txt`.",
          "type": "reasoning_text"
        }
      ],
      "encrypted_content": null,
      "summary": [],
      "type": "reasoning"
    }));

    let messages = render_chat_messages(&body);
    assert_eq!(messages.len(), 1, "expected 1 chat message, got {messages:?}");

    let m = &messages[0];
    assert_eq!(m.get("role").and_then(Value::as_str), Some("assistant"));
    assert_eq!(
      m.get("reasoning_content").and_then(Value::as_str),
      Some(
        "\nI'll read the numbers from `tool_call/data.txt`, sum them, and write the total to `tool_call/answer.txt`."
      )
    );
    // No tool_calls expected for a pure reasoning item.
    assert!(
      m.get("tool_calls").is_none(),
      "reasoning item must not carry tool_calls"
    );
  }

  #[test]
  fn responses_input_function_call_item_renders_assistant_tool_calls() {
    let body = single_item_request(json!({
      "arguments": "{\"cmd\": \"awk '{sum+=$1} END {print sum}' tool_call/data.txt > tool_call/answer.txt\"}",
      "call_id": "tool-f0095fe26fc64ca6bb22994d08bd1724",
      "name": "exec_command",
      "type": "function_call"
    }));

    let messages = render_chat_messages(&body);
    assert_eq!(messages.len(), 1, "expected 1 chat message, got {messages:?}");

    let m = &messages[0];
    assert_eq!(m.get("role").and_then(Value::as_str), Some("assistant"));

    let tool_calls = m
      .get("tool_calls")
      .and_then(Value::as_array)
      .expect("tool_calls present");
    assert_eq!(tool_calls.len(), 1);
    let call = &tool_calls[0];
    assert_eq!(
      call.get("id").and_then(Value::as_str),
      Some("tool-f0095fe26fc64ca6bb22994d08bd1724")
    );
    assert_eq!(call.get("type").and_then(Value::as_str), Some("function"));
    assert_eq!(
      call.pointer("/function/name").and_then(Value::as_str),
      Some("exec_command")
    );
    let args_str = call
      .pointer("/function/arguments")
      .and_then(Value::as_str)
      .expect("arguments rendered as string");
    let args_json: Value = serde_json::from_str(args_str).expect("arguments is valid JSON string");
    assert_eq!(
      args_json.get("cmd").and_then(Value::as_str),
      Some("awk '{sum+=$1} END {print sum}' tool_call/data.txt > tool_call/answer.txt")
    );
  }

  #[test]
  fn responses_input_function_call_output_item_renders_tool_message() {
    let body = single_item_request(json!({
      "call_id": "tool-f0095fe26fc64ca6bb22994d08bd1724",
      "output": "Chunk ID: f0d8f5\nWall time: 0.0000 seconds\nProcess exited with code 0\nOriginal token count: 0\nOutput:\n",
      "type": "function_call_output"
    }));

    let messages = render_chat_messages(&body);
    assert_eq!(messages.len(), 1, "expected 1 chat message, got {messages:?}");

    let m = &messages[0];
    assert_eq!(m.get("role").and_then(Value::as_str), Some("tool"));
    assert_eq!(
      m.get("tool_call_id").and_then(Value::as_str),
      Some("tool-f0095fe26fc64ca6bb22994d08bd1724")
    );
    assert_eq!(
      m.get("content").and_then(Value::as_str),
      Some(
        "Chunk ID: f0d8f5\nWall time: 0.0000 seconds\nProcess exited with code 0\nOriginal token count: 0\nOutput:\n"
      )
    );
  }

  #[test]
  fn responses_input_assistant_parts_render_as_one_chat_message() {
    let body = json!({
      "model": "deepseek-v4-flash",
      "input": [
        {
          "type": "reasoning",
          "content": [{ "type": "reasoning_text", "text": "think" }],
          "summary": []
        },
        {
          "role": "assistant",
          "content": [{ "type": "output_text", "text": "answer" }]
        },
        {
          "type": "function_call",
          "call_id": "call_1",
          "name": "lookup",
          "arguments": "{\"q\":\"rust\"}"
        },
        {
          "type": "function_call_output",
          "call_id": "call_1",
          "output": "result"
        }
      ]
    });

    let messages = render_chat_messages(&body);
    assert_eq!(
      messages.len(),
      2,
      "expected assistant plus tool messages, got {messages:?}"
    );

    let assistant = &messages[0];
    assert_eq!(assistant.get("role").and_then(Value::as_str), Some("assistant"));
    assert_eq!(assistant.get("content").and_then(Value::as_str), Some("answer"));
    assert_eq!(
      assistant.get("reasoning_content").and_then(Value::as_str),
      Some("think")
    );
    let tool_calls = assistant
      .get("tool_calls")
      .and_then(Value::as_array)
      .expect("tool_calls present");
    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0].get("id").and_then(Value::as_str), Some("call_1"));
    assert_eq!(
      tool_calls[0].pointer("/function/name").and_then(Value::as_str),
      Some("lookup")
    );

    let tool = &messages[1];
    assert_eq!(tool.get("role").and_then(Value::as_str), Some("tool"));
    assert_eq!(tool.get("tool_call_id").and_then(Value::as_str), Some("call_1"));
    assert_eq!(tool.get("content").and_then(Value::as_str), Some("result"));
  }

  fn single_item_request(item: Value) -> Value {
    json!({
      "model": "deepseek-v4-flash",
      "input": [item]
    })
  }

  fn render_chat_messages(body: &Value) -> Vec<Value> {
    let ir = request_from_value(body).expect("parse responses request");
    let chat = crate::value::chat::request_to_value(&ir).expect("render chat request");
    chat
      .get("messages")
      .and_then(Value::as_array)
      .cloned()
      .expect("messages array")
  }
}

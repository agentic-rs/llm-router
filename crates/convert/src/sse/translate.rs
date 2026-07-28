use super::accumulate::SseAccumulator;
use super::event::SseEvent;
use super::pipeline::EventTransformer;
use super::responses_emit::ResponsesEmitter;
use crate::error::{ConvertError, Result};
use crate::ir::IrDelta;
use crate::provider::Endpoint;

pub struct EndpointTranslator {
  from: Endpoint,
  acc: SseAccumulator,
  emit: EmitState,
  terminal_seen: bool,
  finished: bool,
}

impl EndpointTranslator {
  pub fn new(from: Endpoint, to: Endpoint) -> Self {
    Self {
      from,
      acc: SseAccumulator::new(from),
      emit: EmitState::new(to),
      terminal_seen: false,
      finished: false,
    }
  }

  fn finish_once(&mut self) -> Result<Vec<SseEvent>> {
    if self.finished {
      return Ok(Vec::new());
    }
    self.finished = true;
    if !self.terminal_seen {
      return Err(ConvertError::sse("upstream stream ended before a terminal event"));
    }
    self.emit.update_metadata(self.acc.metadata());
    Ok(self.emit.finish())
  }
}

impl EventTransformer for EndpointTranslator {
  fn transform(&mut self, event: SseEvent) -> Result<Vec<SseEvent>> {
    if self.finished {
      return Ok(Vec::new());
    }
    if event.is_done() {
      let infer_responses_finish =
        !self.terminal_seen && matches!(self.from, Endpoint::Responses) && self.acc.responses_has_tool_call();
      self.terminal_seen = true;
      let mut out = if infer_responses_finish {
        self.emit.emit(&[IrDelta::Finish(Some("tool_calls".into()))])
      } else {
        Vec::new()
      };
      out.extend(self.finish_once()?);
      return Ok(out);
    }
    let value = event
      .json
      .as_ref()
      .ok_or_else(|| ConvertError::sse("expected JSON SSE payload"))?;
    let mut deltas = self.acc.push_value(value);
    let terminal_reason = terminal_reason(self.from, value, &self.acc, &deltas);
    if let Some(reason) = terminal_reason {
      if self.terminal_seen {
        deltas.retain(|delta| !matches!(delta, IrDelta::Finish(_)));
      } else {
        self.terminal_seen = true;
        let mut finish_seen = false;
        for delta in &mut deltas {
          if let IrDelta::Finish(current) = delta {
            *current = reason.clone();
            finish_seen = true;
          }
        }
        if !finish_seen {
          deltas.push(IrDelta::Finish(reason));
        }
      }
    } else if deltas.iter().any(|delta| matches!(delta, IrDelta::Finish(_))) {
      if self.terminal_seen {
        deltas.retain(|delta| !matches!(delta, IrDelta::Finish(_)));
      } else {
        self.terminal_seen = true;
      }
    }
    self.emit.update_metadata(self.acc.metadata());
    Ok(self.emit.emit(&deltas))
  }

  fn finish(&mut self) -> Result<Vec<SseEvent>> {
    self.finish_once()
  }
}

fn terminal_reason(
  endpoint: Endpoint,
  value: &serde_json::Value,
  acc: &SseAccumulator,
  deltas: &[IrDelta],
) -> Option<Option<String>> {
  match endpoint {
    Endpoint::ChatCompletions => value
      .get("choices")
      .and_then(serde_json::Value::as_array)
      .and_then(|choices| {
        choices.iter().find_map(|choice| {
          choice
            .get("finish_reason")
            .filter(|reason| !reason.is_null())
            .map(|reason| reason.as_str().map(str::to_string))
        })
      }),
    Endpoint::Messages => match value.get("type").and_then(serde_json::Value::as_str) {
      Some("message_stop") => Some(Some("stop".into())),
      Some("message_delta") => value
        .pointer("/delta/stop_reason")
        .filter(|reason| !reason.is_null())
        .map(|reason| {
          deltas
            .iter()
            .find_map(|delta| match delta {
              IrDelta::Finish(reason) => Some(reason.clone()),
              _ => None,
            })
            .unwrap_or_else(|| reason.as_str().map(str::to_string))
        }),
      _ => None,
    },
    Endpoint::Responses => match value.get("type").and_then(serde_json::Value::as_str) {
      Some("response.completed") => Some(Some(acc.responses_completed_finish_reason(Some(value)).into())),
      Some("response.incomplete") => Some(Some(
        value
          .pointer("/response/incomplete_details/reason")
          .and_then(serde_json::Value::as_str)
          .map(|reason| match reason {
            "max_output_tokens" => "length",
            other => other,
          })
          .unwrap_or("incomplete")
          .to_string(),
      )),
      Some("response.failed" | "error") => Some(Some("failed".into())),
      Some("response.cancelled") => Some(Some("cancelled".into())),
      _ => None,
    },
  }
}

struct EmitState {
  to: Endpoint,
  id: String,
  model: String,
  started: bool,
  finished: bool,
  responses: Option<ResponsesEmitter>,
}

impl EmitState {
  fn new(to: Endpoint) -> Self {
    let id: String = match to {
      Endpoint::ChatCompletions => "chatcmpl-converted".into(),
      Endpoint::Responses => "resp_converted".into(),
      Endpoint::Messages => "msg_converted".into(),
    };
    let responses = if matches!(to, Endpoint::Responses) {
      Some(ResponsesEmitter::new(id.clone(), String::new()))
    } else {
      None
    };
    Self {
      to,
      id,
      model: String::new(),
      started: false,
      finished: false,
      responses,
    }
  }

  fn update_metadata(&mut self, metadata: super::accumulate::SseMetadata) {
    if let Some(id) = metadata.response_id {
      self.id = id.clone();
      if let Some(emitter) = self.responses.as_mut() {
        emitter.update_id(id);
      }
    }
    if let Some(model) = metadata.model {
      self.model = model.clone();
      if let Some(emitter) = self.responses.as_mut() {
        emitter.update_model(model);
      }
    }
  }

  fn emit(&mut self, deltas: &[IrDelta]) -> Vec<SseEvent> {
    if deltas.is_empty() {
      return Vec::new();
    }
    let mut out = Vec::new();
    if !self.started && !matches!(self.to, Endpoint::Responses) {
      out.extend(self.start());
      self.started = true;
    }
    match self.to {
      Endpoint::ChatCompletions => {
        for value in crate::value::chat::chunk_from_deltas(&self.id, &self.model, deltas, false) {
          out.push(SseEvent::json(None, value));
        }
      }
      Endpoint::Responses => {
        if let Some(emitter) = self.responses.as_mut() {
          out.extend(emitter.emit(deltas));
          self.started = true;
        }
      }
      Endpoint::Messages => {
        for (event, value) in crate::value::messages::events_from_deltas(&self.id, &self.model, deltas, false) {
          out.push(SseEvent::json(Some(&event), value));
        }
      }
    }
    out
  }

  fn finish(&mut self) -> Vec<SseEvent> {
    if self.finished {
      return Vec::new();
    }
    self.finished = true;
    let mut out = Vec::new();
    if !self.started && !matches!(self.to, Endpoint::Responses) {
      out.extend(self.start());
      self.started = true;
    }
    match self.to {
      Endpoint::ChatCompletions => out.push(SseEvent::done()),
      Endpoint::Responses => {
        if let Some(emitter) = self.responses.as_mut() {
          out.extend(emitter.finish());
        }
      }
      Endpoint::Messages => {
        out.push(SseEvent::json(
          Some("content_block_stop"),
          serde_json::json!({ "type": "content_block_stop", "index": 0 }),
        ));
        out.push(SseEvent::json(
          Some("message_stop"),
          serde_json::json!({ "type": "message_stop" }),
        ));
      }
    }
    out
  }

  fn start(&self) -> Vec<SseEvent> {
    match self.to {
      Endpoint::ChatCompletions | Endpoint::Responses => Vec::new(),
      Endpoint::Messages => vec![
        SseEvent::json(
          Some("message_start"),
          serde_json::json!({
            "type": "message_start",
            "message": { "id": self.id, "type": "message", "role": "assistant", "model": self.model, "content": [], "stop_reason": null, "stop_sequence": null, "usage": { "input_tokens": 0, "output_tokens": 0 } }
          }),
        ),
        SseEvent::json(
          Some("content_block_start"),
          serde_json::json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
        ),
      ],
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn responses_to_chat_finishes_when_upstream_ends_without_done_sentinel() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    let out = t
      .transform(SseEvent::json(
        Some("response.output_text.delta"),
        json!({"type": "response.output_text.delta", "delta": "hi"}),
      ))
      .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].json.as_ref().unwrap()["choices"][0]["delta"]["content"], "hi");

    let out = t
      .transform(SseEvent::json(
        Some("response.completed"),
        json!({"type": "response.completed", "response": {"usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}}}),
      ))
      .unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].json.as_ref().unwrap()["usage"]["prompt_tokens"], 1);
    assert_eq!(out[1].json.as_ref().unwrap()["choices"][0]["finish_reason"], "stop");

    let out = t.finish().unwrap();
    assert_eq!(out.len(), 1);
    assert!(out[0].is_done());
  }

  #[test]
  fn responses_to_chat_finish_is_idempotent() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    assert_eq!(t.transform(SseEvent::done()).unwrap().len(), 1);
    assert!(t.finish().unwrap().is_empty());
  }

  #[test]
  fn clean_eof_without_an_upstream_terminal_is_an_error() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    t.transform(chat_text_chunk("chatcmpl-x", "gpt-5", "partial")).unwrap();

    let error = t.finish().expect_err("truncated stream must not become completed");

    assert!(matches!(
      error,
      ConvertError::Sse { message } if message.contains("before a terminal event")
    ));
    assert!(t.finish().unwrap().is_empty());
  }

  #[test]
  fn chat_finish_reason_allows_clean_eof() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    t.transform(SseEvent::json(
      None,
      json!({
        "id": "chatcmpl-x",
        "model": "gpt-5",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
      }),
    ))
    .unwrap();

    let terminal = t.finish().unwrap().pop().expect("terminal event");

    assert_eq!(terminal.event.as_deref(), Some("response.completed"));
    assert!(t.finish().unwrap().is_empty());
  }

  #[test]
  fn messages_stop_events_allow_clean_eof() {
    for (event_type, terminal) in [
      (
        "message_delta",
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}}),
      ),
      ("message_stop", json!({"type": "message_stop"})),
    ] {
      let mut t = EndpointTranslator::new(Endpoint::Messages, Endpoint::Responses);
      t.transform(SseEvent::json(Some(event_type), terminal)).unwrap();

      let event = t.finish().unwrap().pop().expect("terminal event");
      assert_eq!(event.event.as_deref(), Some("response.completed"));
    }
  }

  #[test]
  fn bare_messages_stop_defaults_to_stop_reason() {
    let mut t = EndpointTranslator::new(Endpoint::Messages, Endpoint::ChatCompletions);

    let finish = t
      .transform(SseEvent::json(Some("message_stop"), json!({"type": "message_stop"})))
      .unwrap();

    assert_eq!(finish.len(), 1);
    assert_eq!(finish[0].json.as_ref().unwrap()["choices"][0]["finish_reason"], "stop");
  }

  #[test]
  fn messages_stop_does_not_duplicate_message_delta_finish() {
    let mut t = EndpointTranslator::new(Endpoint::Messages, Endpoint::ChatCompletions);

    let finish = t
      .transform(SseEvent::json(
        Some("message_delta"),
        json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
      ))
      .unwrap();
    assert_eq!(finish.len(), 1);
    assert_eq!(
      finish[0].json.as_ref().unwrap()["choices"][0]["finish_reason"],
      "tool_calls"
    );

    let duplicate = t
      .transform(SseEvent::json(Some("message_stop"), json!({"type": "message_stop"})))
      .unwrap();
    assert!(duplicate.is_empty());

    let done = t.finish().unwrap();
    assert_eq!(done.len(), 1);
    assert!(done[0].is_done());
  }

  #[test]
  fn responses_terminal_statuses_survive_fallback_conversion() {
    for (kind, response, expected, status) in [
      (
        "response.incomplete",
        json!({"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}}),
        "response.incomplete",
        "incomplete",
      ),
      (
        "response.failed",
        json!({"status": "failed", "error": {"message": "provider failed"}}),
        "response.failed",
        "failed",
      ),
      (
        "response.cancelled",
        json!({"status": "cancelled"}),
        "response.cancelled",
        "cancelled",
      ),
    ] {
      let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::Responses);
      t.transform(SseEvent::json(Some(kind), json!({"type": kind, "response": response})))
        .unwrap();

      let event = t.finish().unwrap().pop().expect("terminal event");
      assert_eq!(event.event.as_deref(), Some(expected));
      assert_eq!(event.json.as_ref().unwrap()["response"]["status"], status);
    }
  }

  #[test]
  fn responses_to_chat_translates_resp_md_style_reasoning_text_and_tool_arguments() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    let reasoning = t
      .transform(SseEvent::json(
        Some("response.reasoning_text.delta"),
        json!({"content_index":0,"delta":"Let","output_index":0,"response_id":"resp_converted","type":"response.reasoning_text.delta"}),
      ))
      .unwrap();
    assert_eq!(
      reasoning[0].json.as_ref().unwrap()["choices"][0]["delta"]["reasoning_content"],
      "Let"
    );

    let text = t
      .transform(SseEvent::json(
        Some("response.output_text.delta"),
        json!({"content_index":0,"delta":"I'll help","output_index":0,"response_id":"resp_converted","type":"response.output_text.delta"}),
      ))
      .unwrap();
    assert_eq!(
      text[0].json.as_ref().unwrap()["choices"][0]["delta"]["content"],
      "I'll help"
    );

    let tool = t
      .transform(SseEvent::json(
        Some("response.function_call_arguments.delta"),
        json!({"delta":"{\"cmd\": \"ls -la\"}","output_index":0,"response_id":"resp_converted","type":"response.function_call_arguments.delta"}),
      ))
      .unwrap();
    let call = &tool[0].json.as_ref().unwrap()["choices"][0]["delta"]["tool_calls"][0];
    assert_eq!(call["index"], 0);
    assert_eq!(call["type"], "function");
    assert_eq!(call["function"]["arguments"], "{\"cmd\": \"ls -la\"}");

    let completed = t
      .transform(SseEvent::json(
        Some("response.completed"),
        json!({"response":{"id":"resp_converted","model":"","object":"response","status":"completed"},"type":"response.completed"}),
      ))
      .unwrap();
    assert_eq!(
      completed[0].json.as_ref().unwrap()["choices"][0]["finish_reason"],
      "stop"
    );

    let done = t.finish().unwrap();
    assert_eq!(done.len(), 1);
    assert!(done[0].is_done());
  }

  #[test]
  fn responses_to_chat_tracks_official_output_item_lifecycle() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    assert!(t
      .transform(SseEvent::json(
        Some("response.created"),
        json!({"type":"response.created","response":{"id":"resp_real","model":"gpt-5.4","status":"in_progress"}}),
      ))
      .unwrap()
      .is_empty());

    assert!(t
      .transform(SseEvent::json(
        Some("response.output_item.added"),
        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","status":"in_progress","role":"assistant","content":[]}}),
      ))
      .unwrap()
      .is_empty());
    assert!(t
      .transform(SseEvent::json(
        Some("response.content_part.added"),
        json!({"type":"response.content_part.added","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}),
      ))
      .unwrap()
      .is_empty());

    let text = t
      .transform(SseEvent::json(
        Some("response.output_text.delta"),
        json!({"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"Hi"}),
      ))
      .unwrap();
    assert_eq!(text[0].json.as_ref().unwrap()["choices"][0]["delta"]["content"], "Hi");
    assert_eq!(text[0].json.as_ref().unwrap()["id"], "resp_real");
    assert_eq!(text[0].json.as_ref().unwrap()["model"], "gpt-5.4");

    assert!(t
      .transform(SseEvent::json(
        Some("response.output_text.done"),
        json!({"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":"Hi"}),
      ))
      .unwrap()
      .is_empty());
    assert!(t
      .transform(SseEvent::json(
        Some("response.output_item.done"),
        json!({"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Hi","annotations":[]}]}}),
      ))
      .unwrap()
      .is_empty());

    let completed = t
      .transform(SseEvent::json(
        Some("response.completed"),
        json!({"type":"response.completed","response":{"usage":{"input_tokens":37,"output_tokens":11,"total_tokens":48}}}),
      ))
      .unwrap();
    assert_eq!(completed[0].json.as_ref().unwrap()["usage"]["prompt_tokens"], 37);
    assert_eq!(
      completed[1].json.as_ref().unwrap()["choices"][0]["finish_reason"],
      "stop"
    );
  }

  #[test]
  fn responses_to_chat_uses_output_item_metadata_for_function_calls() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    assert!(t
      .transform(SseEvent::json(
        Some("response.output_item.added"),
        json!({"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","call_id":"call_1","type":"function_call","status":"in_progress","name":"exec_command","arguments":""}}),
      ))
      .unwrap()
      .is_empty());

    let tool = t
      .transform(SseEvent::json(
        Some("response.function_call_arguments.delta"),
        json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"cmd\":"}),
      ))
      .unwrap();
    let call = &tool[0].json.as_ref().unwrap()["choices"][0]["delta"]["tool_calls"][0];
    assert_eq!(call["index"], 1);
    assert_eq!(call["id"], "call_1");
    assert_eq!(call["function"]["name"], "exec_command");
    assert_eq!(call["function"]["arguments"], "{\"cmd\":");

    assert!(t
      .transform(SseEvent::json(
        Some("response.function_call_arguments.done"),
        json!({"type":"response.function_call_arguments.done","output_index":1,"arguments":"{\"cmd\": \"ls\"}"}),
      ))
      .unwrap()
      .is_empty());
  }

  #[test]
  fn responses_to_chat_uses_observed_tool_item_for_terminal_finish_reason() {
    for item_type in ["function_call", "custom_tool_call"] {
      let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

      t.transform(SseEvent::json(
        Some("response.output_item.added"),
        json!({
          "type": "response.output_item.added",
          "output_index": 0,
          "item": {
            "id": "tool_1",
            "call_id": "call_1",
            "type": item_type,
            "status": "in_progress",
            "name": "lookup"
          }
        }),
      ))
      .unwrap();

      let terminal = t
        .transform(SseEvent::json(
          Some("response.completed"),
          json!({
            "type": "response.completed",
            "response": {
              "id": "resp_1",
              "status": "completed"
            }
          }),
        ))
        .unwrap();

      assert_eq!(
        terminal[0].json.as_ref().unwrap()["choices"][0]["finish_reason"],
        "tool_calls",
        "item type {item_type}"
      );
    }
  }

  #[test]
  fn responses_to_chat_uses_terminal_output_for_tool_finish_reason() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    let terminal = t
      .transform(SseEvent::json(
        Some("response.completed"),
        json!({
          "type": "response.completed",
          "response": {
            "id": "resp_1",
            "status": "completed",
            "output": [{
              "type": "function_call",
              "call_id": "call_1",
              "name": "lookup",
              "arguments": "{}"
            }]
          }
        }),
      ))
      .unwrap();

    assert_eq!(
      terminal[0].json.as_ref().unwrap()["choices"][0]["finish_reason"],
      "tool_calls"
    );
  }

  #[test]
  fn responses_to_chat_supports_reasoning_summary_text_events() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    assert!(t
      .transform(SseEvent::json(
        Some("response.reasoning_summary_part.added"),
        json!({"type":"response.reasoning_summary_part.added","item_id":"rs_1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":""}}),
      ))
      .unwrap()
      .is_empty());
    let reasoning = t
      .transform(SseEvent::json(
        Some("response.reasoning_summary_text.delta"),
        json!({"type":"response.reasoning_summary_text.delta","item_id":"rs_1","output_index":0,"summary_index":0,"delta":"Thinking"}),
      ))
      .unwrap();
    assert_eq!(
      reasoning[0].json.as_ref().unwrap()["choices"][0]["delta"]["reasoning_content"],
      "Thinking"
    );
    assert!(t
      .transform(SseEvent::json(
        Some("response.reasoning_summary_text.done"),
        json!({"type":"response.reasoning_summary_text.done","item_id":"rs_1","output_index":0,"summary_index":0,"text":"Thinking"}),
      ))
      .unwrap()
      .is_empty());
  }

  #[test]
  fn responses_to_chat_supports_custom_tool_call_input_delta() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    assert!(t
      .transform(SseEvent::json(
        Some("response.output_item.added"),
        json!({"type":"response.output_item.added","output_index":2,"item":{"id":"ctc_1","call_id":"call_custom","type":"custom_tool_call","status":"in_progress","name":"apply_patch","input":""}}),
      ))
      .unwrap()
      .is_empty());

    let tool = t
      .transform(SseEvent::json(
        Some("response.custom_tool_call_input.delta"),
        json!({"type":"response.custom_tool_call_input.delta","output_index":2,"item_id":"ctc_1","call_id":"call_custom","delta":"*** Begin"}),
      ))
      .unwrap();

    let call = &tool[0].json.as_ref().unwrap()["choices"][0]["delta"]["tool_calls"][0];
    assert_eq!(call["index"], 2);
    assert_eq!(call["id"], "call_custom");
    assert_eq!(call["function"]["name"], "apply_patch");
    assert_eq!(call["function"]["arguments"], "*** Begin");
  }

  #[test]
  fn responses_to_chat_uses_delta_item_id_when_no_output_item_metadata_exists() {
    let mut t = EndpointTranslator::new(Endpoint::Responses, Endpoint::ChatCompletions);

    let tool = t
      .transform(SseEvent::json(
        Some("response.custom_tool_call_input.delta"),
        json!({"type":"response.custom_tool_call_input.delta","item_id":"ctc_1","delta":"abc"}),
      ))
      .unwrap();

    let call = &tool[0].json.as_ref().unwrap()["choices"][0]["delta"]["tool_calls"][0];
    assert_eq!(call["id"], "ctc_1");
    assert_eq!(call["function"]["arguments"], "abc");
  }

  fn collect_event_types(events: &[SseEvent]) -> Vec<String> {
    events
      .iter()
      .map(|e| {
        e.event
          .clone()
          .or_else(|| {
            e.json
              .as_ref()
              .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
          })
          .unwrap_or_default()
      })
      .collect()
  }

  fn chat_text_chunk(id: &str, model: &str, content: &str) -> SseEvent {
    SseEvent::json(
      None,
      json!({
        "id": id,
        "model": model,
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
      }),
    )
  }

  #[test]
  fn chat_to_responses_emits_full_text_lifecycle() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    let mut events = Vec::new();
    for piece in ["Hi", "!", " 👋", " What", " can", " I", " help"] {
      events.extend(
        t.transform(chat_text_chunk("chatcmpl-x", "gpt-5.3-codex", piece))
          .unwrap(),
      );
    }
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"chatcmpl-x","model":"gpt-5.3-codex",
          "choices":[{"index":0,"delta":{"content":null},"finish_reason":"stop"}],
          "usage":{"prompt_tokens":7,"completion_tokens":7,"total_tokens":14}
        }),
      ))
      .unwrap(),
    );
    events.extend(t.transform(SseEvent::done()).unwrap());

    let kinds = collect_event_types(&events);
    assert_eq!(
      kinds,
      vec![
        "response.created",
        "response.in_progress",
        "response.output_item.added",
        "response.content_part.added",
        "response.output_text.delta",
        "response.output_text.delta",
        "response.output_text.delta",
        "response.output_text.delta",
        "response.output_text.delta",
        "response.output_text.delta",
        "response.output_text.delta",
        "response.output_text.done",
        "response.content_part.done",
        "response.output_item.done",
        "response.completed",
      ]
    );

    // sequence numbers monotonic from 0
    for (i, e) in events.iter().enumerate() {
      assert_eq!(e.json.as_ref().unwrap()["sequence_number"], i as u64);
    }

    let created = &events[0].json.as_ref().unwrap()["response"];
    assert_eq!(created["id"], "chatcmpl-x");
    assert_eq!(created["model"], "gpt-5.3-codex");
    assert_eq!(created["status"], "in_progress");

    let item_added = &events[2].json.as_ref().unwrap()["item"];
    assert_eq!(item_added["type"], "message");
    assert_eq!(item_added["status"], "in_progress");
    let item_id = item_added["id"].as_str().unwrap().to_string();
    assert!(item_id.starts_with("msg_"));

    let text_delta = events[4].json.as_ref().unwrap();
    assert_eq!(text_delta["item_id"], item_id);
    assert_eq!(text_delta["output_index"], 0);
    assert_eq!(text_delta["content_index"], 0);
    assert_eq!(text_delta["delta"], "Hi");

    let text_done = events[11].json.as_ref().unwrap();
    assert_eq!(text_done["text"], "Hi! 👋 What can I help");

    let item_done = events[13].json.as_ref().unwrap();
    assert_eq!(item_done["item"]["status"], "completed");
    assert_eq!(item_done["item"]["content"][0]["text"], "Hi! 👋 What can I help");

    let completed = &events[14].json.as_ref().unwrap()["response"];
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["usage"]["input_tokens"], 7);
    assert_eq!(completed["usage"]["output_tokens"], 7);
    assert_eq!(completed["output"][0]["type"], "message");
    assert_eq!(completed["output"][0]["content"][0]["text"], "Hi! 👋 What can I help");
  }

  #[test]
  fn chat_to_responses_function_call_lifecycle() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    let mut events = Vec::new();
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"chatcmpl-y","model":"gpt-5",
          "choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"exec","arguments":"{\"cmd\":"}}]},"finish_reason":null}]
        }),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"chatcmpl-y","model":"gpt-5",
          "choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"ls\"}"}}]},"finish_reason":null}]
        }),
      ))
      .unwrap(),
    );
    events.extend(t.transform(SseEvent::done()).unwrap());

    let kinds = collect_event_types(&events);
    assert_eq!(
      kinds,
      vec![
        "response.created",
        "response.in_progress",
        "response.output_item.added",
        "response.function_call_arguments.delta",
        "response.function_call_arguments.delta",
        "response.function_call_arguments.done",
        "response.output_item.done",
        "response.completed",
      ]
    );

    let added = &events[2].json.as_ref().unwrap()["item"];
    assert_eq!(added["type"], "function_call");
    assert_eq!(added["call_id"], "call_abc");
    assert_eq!(added["name"], "exec");

    let args_done = events[5].json.as_ref().unwrap();
    assert_eq!(args_done["arguments"], "{\"cmd\":\"ls\"}");

    let item_done = &events[6].json.as_ref().unwrap()["item"];
    assert_eq!(item_done["status"], "completed");
    assert_eq!(item_done["arguments"], "{\"cmd\":\"ls\"}");
    assert_eq!(item_done["call_id"], "call_abc");
  }

  #[test]
  fn chat_to_responses_reasoning_lifecycle() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    let mut events = Vec::new();
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"chatcmpl-z","model":"gpt-5",
          "choices":[{"index":0,"delta":{"reasoning_content":"Think"},"finish_reason":null}]
        }),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"chatcmpl-z","model":"gpt-5",
          "choices":[{"index":0,"delta":{"reasoning_content":"ing"},"finish_reason":null}]
        }),
      ))
      .unwrap(),
    );
    events.extend(t.transform(SseEvent::done()).unwrap());

    let kinds = collect_event_types(&events);
    assert_eq!(
      kinds,
      vec![
        "response.created",
        "response.in_progress",
        "response.output_item.added",
        "response.reasoning_text.delta",
        "response.reasoning_text.delta",
        "response.reasoning_text.done",
        "response.output_item.done",
        "response.completed",
      ]
    );
    assert_eq!(events[5].json.as_ref().unwrap()["text"], "Thinking");
  }

  #[test]
  fn messages_to_responses_emits_full_text_lifecycle() {
    let mut t = EndpointTranslator::new(Endpoint::Messages, Endpoint::Responses);
    let mut events = Vec::new();
    events.extend(
      t.transform(SseEvent::json(
        Some("message_start"),
        json!({
          "type":"message_start",
          "message":{"id":"msg_abc","model":"claude-3","role":"assistant","content":[],"usage":{"input_tokens":4,"output_tokens":0}}
        }),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        Some("content_block_start"),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        Some("content_block_delta"),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        Some("content_block_delta"),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"!"}}),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        Some("message_delta"),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}),
      ))
      .unwrap(),
    );
    events.extend(t.transform(SseEvent::done()).unwrap());

    let kinds = collect_event_types(&events);
    assert_eq!(
      kinds,
      vec![
        "response.created",
        "response.in_progress",
        "response.output_item.added",
        "response.content_part.added",
        "response.output_text.delta",
        "response.output_text.delta",
        "response.output_text.done",
        "response.content_part.done",
        "response.output_item.done",
        "response.completed",
      ]
    );

    let created = &events[0].json.as_ref().unwrap()["response"];
    assert_eq!(created["id"], "msg_abc");
    assert_eq!(created["model"], "claude-3");

    let text_done = events[6].json.as_ref().unwrap();
    assert_eq!(text_done["text"], "Hi!");
  }

  #[test]
  fn chat_to_responses_closes_reasoning_before_text() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    let mut events = Vec::new();
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({"id":"c1","model":"m","choices":[{"index":0,"delta":{"reasoning_content":"think"},"finish_reason":null}]}),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({"id":"c1","model":"m","choices":[{"index":0,"delta":{"content":"Answer"},"finish_reason":null}]}),
      ))
      .unwrap(),
    );
    events.extend(t.transform(SseEvent::done()).unwrap());

    let kinds = collect_event_types(&events);
    assert_eq!(
      kinds,
      vec![
        "response.created",
        "response.in_progress",
        "response.output_item.added", // reasoning
        "response.reasoning_text.delta",
        "response.reasoning_text.done",
        "response.output_item.done",  // reasoning closed
        "response.output_item.added", // message
        "response.content_part.added",
        "response.output_text.delta",
        "response.output_text.done",
        "response.content_part.done",
        "response.output_item.done",
        "response.completed",
      ]
    );
    // assert sequential output_index
    let reasoning_done = events[5].json.as_ref().unwrap();
    let message_added = events[6].json.as_ref().unwrap();
    assert_eq!(reasoning_done["output_index"], 0);
    assert_eq!(message_added["output_index"], 1);
  }

  #[test]
  fn chat_to_responses_closes_message_before_function_call() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    let mut events = Vec::new();
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({"id":"c1","model":"m","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"c1","model":"m",
          "choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]},"finish_reason":null}]
        }),
      ))
      .unwrap(),
    );
    events.extend(t.transform(SseEvent::done()).unwrap());

    let kinds = collect_event_types(&events);
    assert_eq!(
      kinds,
      vec![
        "response.created",
        "response.in_progress",
        "response.output_item.added", // message
        "response.content_part.added",
        "response.output_text.delta",
        "response.output_text.done",
        "response.content_part.done",
        "response.output_item.done",  // message closed
        "response.output_item.added", // function_call
        "response.function_call_arguments.delta",
        "response.function_call_arguments.done",
        "response.output_item.done",
        "response.completed",
      ]
    );
  }

  #[test]
  fn chat_to_responses_handles_two_sequential_function_calls() {
    let mut t = EndpointTranslator::new(Endpoint::ChatCompletions, Endpoint::Responses);
    let mut events = Vec::new();
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"c1","model":"m",
          "choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"x","arguments":"{}"}}]},"finish_reason":null}]
        }),
      ))
      .unwrap(),
    );
    events.extend(
      t.transform(SseEvent::json(
        None,
        json!({
          "id":"c1","model":"m",
          "choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"b","type":"function","function":{"name":"y","arguments":"{}"}}]},"finish_reason":null}]
        }),
      ))
      .unwrap(),
    );
    events.extend(t.transform(SseEvent::done()).unwrap());

    let kinds = collect_event_types(&events);
    assert_eq!(
      kinds,
      vec![
        "response.created",
        "response.in_progress",
        "response.output_item.added", // call a
        "response.function_call_arguments.delta",
        "response.function_call_arguments.done",
        "response.output_item.done",  // a closed
        "response.output_item.added", // call b
        "response.function_call_arguments.delta",
        "response.function_call_arguments.done",
        "response.output_item.done",
        "response.completed",
      ]
    );

    let a_added = &events[2].json.as_ref().unwrap()["item"];
    assert_eq!(a_added["call_id"], "a");
    assert_eq!(a_added["name"], "x");
    let b_added = &events[6].json.as_ref().unwrap()["item"];
    assert_eq!(b_added["call_id"], "b");
    assert_eq!(b_added["name"], "y");
    assert_eq!(
      b_added["id"].as_str().unwrap(),
      events[6].json.as_ref().unwrap()["item"]["id"].as_str().unwrap()
    );
  }
}

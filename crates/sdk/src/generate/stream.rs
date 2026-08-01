use eventsource_stream::{EventStream, Eventsource};
use futures_util::stream::{self, BoxStream};
use futures_util::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use tokn_convert::ir::IrDelta;
use tokn_convert::sse::SseAccumulator;
use tokn_endpoint_core::Endpoint;

use super::response::finish_reason;
use super::Usage;
use crate::{Error, Result};

/// Provider-neutral semantic events produced by a streaming generation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GenerateEvent {
  TextDelta {
    text: String,
  },
  ReasoningDelta {
    text: String,
  },
  ToolCallDelta {
    index: usize,
    id: Option<String>,
    name: Option<String>,
    arguments_delta: String,
  },
  Usage {
    usage: Usage,
  },
  Completed {
    finish_reason: Option<String>,
  },
  Other {
    kind: String,
    data: Value,
  },
}

/// A stream of provider-neutral generation events.
///
/// Normal semantic completion is withheld until the underlying transport
/// reaches EOF. A transport error encountered while draining after a terminal
/// event is surfaced instead of reporting successful completion. Dropping the
/// stream early abandons that drain and cancels any attached request lifecycle.
pub type GenerateStream = BoxStream<'static, Result<GenerateEvent>>;

/// A convenience stream containing only generated text deltas.
///
/// It retains the same transport-EOF and early-drop semantics as
/// [`GenerateStream`].
pub type TextStream = BoxStream<'static, Result<String>>;

struct EventParseState {
  events: EventStream<crate::ByteStream>,
  accumulator: SseAccumulator,
  pending: VecDeque<Result<GenerateEvent>>,
  terminal: Option<VecDeque<Result<GenerateEvent>>>,
  finished: bool,
}

impl EventParseState {
  fn new(bytes: crate::ByteStream) -> Self {
    Self {
      events: bytes.eventsource(),
      accumulator: SseAccumulator::new(Endpoint::Responses),
      pending: VecDeque::new(),
      terminal: None,
      finished: false,
    }
  }

  fn enqueue(&mut self, results: Vec<Result<GenerateEvent>>) {
    for result in results {
      let failed = result.is_err();
      self.pending.push_back(result);
      if failed {
        self.finished = true;
        break;
      }
    }
  }

  fn begin_terminal_drain(&mut self, results: Vec<Result<GenerateEvent>>) {
    self.terminal = Some(results.into());
  }

  fn finish_terminal_drain(&mut self) {
    self
      .pending
      .append(self.terminal.as_mut().expect("terminal drain is active"));
    self.terminal = None;
    self.finished = true;
  }

  fn fail(&mut self, error: Error) {
    self.pending.clear();
    self.terminal = None;
    self.pending.push_back(Err(error));
    self.finished = true;
  }
}

pub(super) fn parse_events(bytes: crate::ByteStream) -> GenerateStream {
  stream::unfold(EventParseState::new(bytes), |mut state| async move {
    loop {
      if let Some(result) = state.pending.pop_front() {
        return Some((result, state));
      }
      if state.finished {
        return None;
      }

      if state.terminal.is_some() {
        match state.events.next().await {
          Some(Ok(_)) => continue,
          Some(Err(error)) => state.fail(Error::GenerateStream {
            message: error.to_string(),
          }),
          None => state.finish_terminal_drain(),
        }
        continue;
      }

      match state.events.next().await {
        Some(Ok(event)) if event.data.trim().is_empty() => {}
        Some(Ok(event)) if event.data.trim() == "[DONE]" => {
          state.begin_terminal_drain(Vec::new());
        }
        Some(Ok(event)) => match serde_json::from_str::<Value>(&event.data) {
          Ok(value) => {
            let terminal = is_terminal_value(&value);
            let results = results_from_value(&mut state.accumulator, value);
            if terminal {
              state.begin_terminal_drain(results);
            } else {
              state.enqueue(results);
            }
          }
          Err(source) => state.fail(Error::DeserializeStreamEvent { source }),
        },
        Some(Err(error)) => state.fail(Error::GenerateStream {
          message: error.to_string(),
        }),
        None => state.fail(Error::GenerateStream {
          message: "generation stream ended before a terminal event".into(),
        }),
      }
    }
  })
  .boxed()
}

fn is_terminal_value(value: &Value) -> bool {
  matches!(
    value.get("type").and_then(Value::as_str),
    Some("response.completed" | "response.incomplete" | "response.failed" | "response.cancelled" | "error")
  )
}

pub(super) fn text_only(events: GenerateStream) -> TextStream {
  events
    .try_filter_map(|event| async move {
      Ok(match event {
        GenerateEvent::TextDelta { text } => Some(text),
        _ => None,
      })
    })
    .boxed()
}

fn results_from_value(accumulator: &mut SseAccumulator, value: Value) -> Vec<Result<GenerateEvent>> {
  let kind = value.get("type").and_then(Value::as_str).unwrap_or_default();
  let completion_reason = matches!(
    kind,
    "response.completed" | "response.incomplete" | "response.cancelled"
  )
  .then(|| value.get("response"))
  .flatten()
  .and_then(|response| finish_reason(response, response_has_tool_calls(response)));
  let deltas = accumulator.push_value(&value);

  if matches!(kind, "response.failed" | "error") {
    return vec![Err(Error::GenerateStream {
      message: stream_error_message(&value),
    })];
  }
  if matches!(kind, "response.incomplete" | "response.cancelled") {
    let mut events = value
      .get("response")
      .and_then(tokn_convert::ir::usage_from_openai)
      .map(|usage| {
        vec![Ok(GenerateEvent::Usage {
          usage: Usage::from_ir(usage),
        })]
      })
      .unwrap_or_default();
    events.push(Ok(GenerateEvent::Completed {
      finish_reason: completion_reason.or_else(|| Some(kind.trim_start_matches("response.").into())),
    }));
    return events;
  }
  if let Some(event) = tool_call_started(&value) {
    return vec![Ok(event)];
  }
  if deltas.is_empty() {
    return vec![Ok(GenerateEvent::Other {
      kind: value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string(),
      data: value,
    })];
  }
  deltas
    .into_iter()
    .map(|delta| match delta {
      IrDelta::Finish(_) if completion_reason.is_some() => Ok(GenerateEvent::Completed {
        finish_reason: completion_reason.clone(),
      }),
      other => Ok(event_from_delta(other)),
    })
    .collect()
}

fn tool_call_started(value: &Value) -> Option<GenerateEvent> {
  if value.get("type").and_then(Value::as_str) != Some("response.output_item.added") {
    return None;
  }
  let item = value.get("item")?;
  if !matches!(
    item.get("type").and_then(Value::as_str),
    Some("function_call" | "custom_tool_call")
  ) {
    return None;
  }
  Some(GenerateEvent::ToolCallDelta {
    index: value.get("output_index").and_then(Value::as_u64).unwrap_or(0) as usize,
    id: item
      .get("call_id")
      .or_else(|| item.get("id"))
      .and_then(Value::as_str)
      .map(str::to_string),
    name: item.get("name").and_then(Value::as_str).map(str::to_string),
    arguments_delta: item
      .get("arguments")
      .or_else(|| item.get("input"))
      .and_then(Value::as_str)
      .unwrap_or_default()
      .to_string(),
  })
}

fn stream_error_message(value: &Value) -> String {
  value
    .pointer("/error/message")
    .or_else(|| value.pointer("/response/error/message"))
    .and_then(Value::as_str)
    .map(str::to_string)
    .unwrap_or_else(|| value.to_string())
}

fn response_has_tool_calls(response: &Value) -> bool {
  response.get("output").and_then(Value::as_array).is_some_and(|output| {
    output.iter().any(|item| {
      matches!(
        item.get("type").and_then(Value::as_str),
        Some("function_call" | "custom_tool_call")
      )
    })
  })
}

fn event_from_delta(delta: IrDelta) -> GenerateEvent {
  match delta {
    IrDelta::Text(text) => GenerateEvent::TextDelta { text },
    IrDelta::Reasoning(text) => GenerateEvent::ReasoningDelta { text },
    IrDelta::ToolCall {
      index,
      id,
      name,
      arguments_delta,
    } => GenerateEvent::ToolCallDelta {
      index,
      id,
      name,
      arguments_delta,
    },
    IrDelta::Usage(usage) => GenerateEvent::Usage {
      usage: Usage::from_ir(usage),
    },
    IrDelta::Finish(finish_reason) => GenerateEvent::Completed { finish_reason },
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use bytes::Bytes;
  use futures_util::stream;
  use std::collections::VecDeque;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::sync::Arc;
  use std::task::Poll;

  fn byte_stream(body: String) -> crate::ByteStream {
    Box::pin(stream::once(async move { Ok(Bytes::from(body)) }))
  }

  fn tracked_byte_stream(chunks: Vec<std::io::Result<Bytes>>) -> (crate::ByteStream, Arc<AtomicBool>) {
    let reached_eof = Arc::new(AtomicBool::new(false));
    let eof_observation = Arc::clone(&reached_eof);
    let mut chunks = VecDeque::from(chunks);
    let bytes = stream::poll_fn(move |_| match chunks.pop_front() {
      Some(chunk) => Poll::Ready(Some(chunk)),
      None => {
        eof_observation.store(true, Ordering::SeqCst);
        Poll::Ready(None)
      }
    });
    (Box::pin(bytes), reached_eof)
  }

  fn sse(values: impl IntoIterator<Item = Value>) -> String {
    values.into_iter().map(|value| format!("data: {value}\n\n")).collect()
  }

  #[tokio::test]
  async fn failed_streams_surface_as_errors() {
    let body = sse([serde_json::json!({
      "type": "response.failed",
      "response": {
        "status": "failed",
        "error": {"message": "provider failed"}
      }
    })]);

    let error = parse_events(byte_stream(body))
      .try_collect::<Vec<_>>()
      .await
      .expect_err("failed terminal event should fail the stream");

    assert!(matches!(error, Error::GenerateStream { message } if message == "provider failed"));
  }

  #[tokio::test]
  async fn semantic_errors_are_terminal() {
    let body = sse([
      serde_json::json!({
        "type": "response.failed",
        "response": {
          "status": "failed",
          "error": {"message": "provider failed"}
        }
      }),
      serde_json::json!({
        "type": "response.output_text.delta",
        "delta": "must not be emitted"
      }),
    ]);
    let mut events = parse_events(byte_stream(body));

    assert!(matches!(
      events.next().await,
      Some(Err(Error::GenerateStream { message })) if message == "provider failed"
    ));
    assert!(events.next().await.is_none());
  }

  #[tokio::test]
  async fn decode_errors_are_terminal() {
    let body = format!(
      "data: not-json\n\n{}",
      sse([serde_json::json!({
        "type": "response.output_text.delta",
        "delta": "must not be emitted"
      })])
    );
    let mut events = parse_events(byte_stream(body));

    assert!(matches!(
      events.next().await,
      Some(Err(Error::DeserializeStreamEvent { .. }))
    ));
    assert!(events.next().await.is_none());
  }

  #[tokio::test]
  async fn transport_errors_are_terminal() {
    let trailing = sse([serde_json::json!({
      "type": "response.output_text.delta",
      "delta": "must not be emitted"
    })]);
    let bytes: crate::ByteStream = Box::pin(stream::iter([
      Err(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset",
      )),
      Ok(Bytes::from(trailing)),
    ]));
    let mut events = parse_events(bytes);

    assert!(matches!(
      events.next().await,
      Some(Err(Error::GenerateStream { message })) if message.contains("connection reset")
    ));
    assert!(events.next().await.is_none());
  }

  #[tokio::test]
  async fn incomplete_streams_keep_usage_and_finish_reason() {
    let body = sse([serde_json::json!({
      "type": "response.incomplete",
      "response": {
        "status": "incomplete",
        "incomplete_details": {"reason": "max_output_tokens"},
        "usage": {"input_tokens": 4, "output_tokens": 8, "total_tokens": 12}
      }
    })]);

    let events = parse_events(byte_stream(body))
      .try_collect::<Vec<_>>()
      .await
      .expect("incomplete terminal event remains a valid partial result");

    assert!(events.iter().any(|event| {
      matches!(
        event,
        GenerateEvent::Usage {
          usage: Usage {
            total_tokens: Some(12),
            ..
          }
        }
      )
    }));
    assert!(events.iter().any(|event| {
      matches!(
        event,
        GenerateEvent::Completed {
          finish_reason: Some(reason)
        } if reason == "length"
      )
    }));
  }

  #[tokio::test]
  async fn cancelled_streams_complete_with_a_clear_reason() {
    let body = sse([serde_json::json!({
      "type": "response.cancelled",
      "response": {
        "status": "cancelled",
        "usage": {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}
      }
    })]);

    let events = parse_events(byte_stream(body))
      .try_collect::<Vec<_>>()
      .await
      .expect("cancelled is a valid terminal result");

    assert!(events.iter().any(|event| {
      matches!(
        event,
        GenerateEvent::Usage {
          usage: Usage {
            total_tokens: Some(4),
            ..
          }
        }
      )
    }));
    assert!(events.iter().any(|event| {
      matches!(
        event,
        GenerateEvent::Completed {
          finish_reason: Some(reason)
        } if reason == "cancelled"
      )
    }));
  }

  #[tokio::test]
  async fn successful_terminal_events_drain_later_events_without_emitting_them() {
    let body = sse([
      serde_json::json!({
        "type": "response.completed",
        "response": {
          "status": "completed",
          "output": []
        }
      }),
      serde_json::json!({
        "type": "response.output_text.delta",
        "delta": "must not be emitted"
      }),
    ]);
    let events = parse_events(byte_stream(body))
      .try_collect::<Vec<_>>()
      .await
      .expect("completed terminal event should end the stream");

    assert_eq!(
      events,
      vec![GenerateEvent::Completed {
        finish_reason: Some("stop".into())
      }]
    );
  }

  #[tokio::test]
  async fn terminal_event_and_done_marker_reach_transport_eof_before_completion() {
    let terminal = sse([serde_json::json!({
      "type": "response.completed",
      "response": {
        "status": "completed",
        "output": []
      }
    })]);
    let (bytes, reached_eof) = tracked_byte_stream(vec![
      Ok(Bytes::from(terminal)),
      Ok(Bytes::from_static(b"data: [DONE]\n\n")),
    ]);
    let mut events = parse_events(bytes);

    assert!(matches!(
      events.next().await,
      Some(Ok(GenerateEvent::Completed {
        finish_reason: Some(reason)
      })) if reason == "stop"
    ));
    assert!(reached_eof.load(Ordering::SeqCst));
    assert!(events.next().await.is_none());
  }

  #[tokio::test]
  async fn done_marker_without_semantic_terminal_still_drains_to_eof() {
    let (bytes, reached_eof) = tracked_byte_stream(vec![Ok(Bytes::from_static(b"data: [DONE]\n\n"))]);

    let events = parse_events(bytes)
      .try_collect::<Vec<_>>()
      .await
      .expect("DONE marker should end the semantic stream");

    assert!(events.is_empty());
    assert!(reached_eof.load(Ordering::SeqCst));
  }

  #[tokio::test]
  async fn transport_error_while_draining_replaces_normal_completion() {
    let terminal = sse([serde_json::json!({
      "type": "response.completed",
      "response": {
        "status": "completed",
        "output": []
      }
    })]);
    let bytes: crate::ByteStream = Box::pin(stream::iter([
      Ok(Bytes::from(terminal)),
      Err(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset while draining",
      )),
    ]));
    let mut events = parse_events(bytes);

    assert!(matches!(
      events.next().await,
      Some(Err(Error::GenerateStream { message })) if message.contains("connection reset while draining")
    ));
    assert!(events.next().await.is_none());
  }

  #[tokio::test]
  async fn clean_eof_without_terminal_event_is_an_error() {
    let body = sse([serde_json::json!({
      "type": "response.output_text.delta",
      "delta": "partial"
    })]);
    let mut events = parse_events(byte_stream(body));

    assert!(matches!(
      events.next().await,
      Some(Ok(GenerateEvent::TextDelta { text })) if text == "partial"
    ));
    assert!(matches!(
      events.next().await,
      Some(Err(Error::GenerateStream { message })) if message.contains("before a terminal event")
    ));
  }
}

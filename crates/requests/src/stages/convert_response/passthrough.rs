//! Pass-through ConvertResponse stage.
//!
//! Mirrors the legacy `crates/router/src/relay/passthrough.rs` behaviour:
//!
//! * **Non-SSE** responses: drain into bytes and return
//!   [`ConvertedBody::Buffered`] with the original byte payload. Usage is
//!   parsed synchronously from the JSON body via
//!   [`parse_usage_any_json`](tokn_convert::usage::parse_usage_any_json)
//!   and emitted as [`RecordEvent::Usage`].
//! * **SSE** responses (`Content-Type: text/event-stream`): return
//!   [`ConvertedBody::Stream`] forwarding the upstream byte chunks
//!   verbatim — **no** SSE re-encoding, **no** endpoint translation.
//!   A background `tokio::spawn` task parses each SSE frame with
//!   [`eventsource_stream`] (via [`SsePipeline`]'s parsed tap) and emits
//!   per-frame [`RecordEvent::Usage`] when figures change.
//!
//! Note: the trait-provided
//! [`ConvertResponseStage::convert_response`](crate::pipeline::stages::ConvertResponseStage::convert_response)
//! dispatcher already wraps streaming outputs with an internal
//! `AccumHelper` that emits `RecordEvent::UpstreamBody` /
//! `RecordEvent::ConvertedBody` and per-500ms `Event::StreamProgress`
//! events. We don't duplicate that here.
//!
//! Detection helper mirrors
//! `crates/router/src/relay/passthrough.rs::is_sse_response`.

use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::PipelineError;
use crate::pipeline::stages::{
  ConvertResponseStage, ConvertedBody, ConvertedResponse, ConvertedResponseKind, SentResponse,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use tokn_convert::sse::{observer_channel, ObserverMsg, SsePipeline};
use tokn_convert::usage::{parse_usage_any_json, parse_usage_any_value, usage_has_any};
use tokn_core::provider::Endpoint;
use tokn_core::request_event::RecordEvent;
use tokn_headers::HeaderMap;
use tracing::{debug, instrument};

/// Pass-through ConvertResponse. Forwards bytes verbatim; usage is extracted
/// in a background task without blocking the response.
pub struct PassthroughConvertResponse;

impl PassthroughConvertResponse {
  pub fn new() -> Self {
    Self
  }
}

impl Default for PassthroughConvertResponse {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait]
impl ConvertResponseStage for PassthroughConvertResponse {
  #[instrument(name = "passthrough_convert_buffered", skip_all, fields(
    status = status,
    upstream_endpoint = ?upstream_endpoint,
    body_len = body.len(),
  ))]
  async fn convert_buffered(
    &self,
    ctx: &PipelineCtx,
    status: u16,
    headers: HeaderMap,
    upstream_endpoint: Option<Endpoint>,
    body: Bytes,
  ) -> Result<ConvertedResponse, PipelineError> {
    let _ = upstream_endpoint;

    // Best-effort usage parse, synchronous on the full body. Cheap
    // relative to network IO and avoids spawning a task per request
    // for the buffered path.
    if !body.is_empty() {
      let usage = parse_usage_any_json(&body);
      if usage_has_any(&usage) {
        ctx.emit_record(RecordEvent::Usage(usage));
      }
    }

    Ok(ConvertedResponse {
      status,
      headers,
      kind: ConvertedResponseKind::Opaque,
      body: ConvertedBody::Buffered {
        // Body intentionally not deserialized — passthrough preserves
        // wire bytes only.
        body_json: None,
        body_bytes: body,
      },
    })
  }

  #[instrument(name = "passthrough_convert_stream", skip_all, fields(
    status = status,
    upstream_endpoint = ?upstream_endpoint,
  ))]
  async fn convert_stream(
    &self,
    ctx: &PipelineCtx,
    status: u16,
    headers: HeaderMap,
    upstream_endpoint: Option<Endpoint>,
    body: BoxStream<'static, std::io::Result<Bytes>>,
  ) -> Result<ConvertedResponse, PipelineError> {
    let _ = upstream_endpoint;
    debug!("forwarding upstream SSE chunks verbatim");

    // Spawn an SSE parser that taps the byte stream, extracts usage from
    // each parsed frame, and emits `RecordEvent::Usage` when figures
    // change. The forwarded byte stream is unaffected (the tap consumes
    // a clone via SsePipeline).
    //
    // The `SsePipeline` here is used only for parsing — its byte output
    // is dropped. The client-facing stream is the original raw byte
    // stream (`forward_stream` below).
    //
    // To avoid duplicating the upstream stream (which is not Clone),
    // we use an intermediate channel: the byte stream forwards to the
    // client while also being teed into the SSE parser.
    let (parse_tx, mut parse_rx) = tokio::sync::mpsc::unbounded_channel::<std::io::Result<Bytes>>();

    let forward_stream = body
      .inspect(move |chunk| {
        // Best-effort tap — if the parser task exited, drop chunks
        // silently (it just means usage extraction stopped early).
        let cloned: std::io::Result<Bytes> = match chunk {
          Ok(b) => Ok(b.clone()),
          Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
        };
        let _ = parse_tx.send(cloned);
      })
      .boxed();

    // Background SSE parser task: drains the parse channel, runs
    // SsePipeline with a parsed tap, extracts usage, emits events.
    let parse_request_id = ctx.request_id.clone();
    let parse_attempt = ctx.attempt;
    let parse_events = ctx.events.clone();
    let parse_guard = ctx.events.begin_finalizer();
    tokio::spawn(async move {
      // Adapt the mpsc receiver into a Stream.
      let parse_byte_stream = futures_util::stream::poll_fn(move |cx| parse_rx.poll_recv(cx)).boxed();

      let (tap_tx, mut tap_rx) = observer_channel();
      let pipeline = SsePipeline::from_stream(parse_byte_stream).with_tap_parsed(tap_tx);

      // Drive the pipeline. We don't care about its byte output here —
      // it exists purely so the tap fires. Drain in the background.
      let drive = async move {
        let mut s = pipeline.run();
        while let Some(_chunk) = s.next().await {
          // discard
        }
      };

      let tap = async move {
        while let Some(msg) = tap_rx.recv().await {
          match msg {
            ObserverMsg::Parsed(Some(value)) => {
              let parsed = parse_usage_any_value(&value);
              if !usage_has_any(&parsed) {
                continue;
              }
              parse_events.emit(tokn_core::event::Event::Requests(
                tokn_core::request_event::RequestEvent {
                  request_id: parse_request_id.clone(),
                  attempt: parse_attempt,
                  ts: tokn_core::util::now_unix_ms(),
                  payload: tokn_core::request_event::RequestEventPayload::Record(RecordEvent::Usage(parsed)),
                },
              ));
            }
            ObserverMsg::Done | ObserverMsg::Error(_) => break,
            _ => {}
          }
        }
      };

      tokio::join!(drive, tap);
      parse_guard.finish();
    });

    Ok(ConvertedResponse {
      status,
      headers,
      kind: ConvertedResponseKind::Opaque,
      body: ConvertedBody::Stream { body: forward_stream },
    })
  }

  fn is_sse_response(&self, _ctx: &PipelineCtx, sent: &SentResponse) -> bool {
    if sent.status >= 400 {
      return false;
    }
    is_sse_response(&sent.headers, sent.stream)
  }
}

/// Returns `true` when the upstream response should be forwarded as a
/// stream. Mirrors `crates/router/src/relay/passthrough.rs::is_sse_response`:
/// trust `Content-Type: text/event-stream` first, fall back to the
/// caller-supplied hint when no `Content-Type` is set.
fn is_sse_response(headers: &HeaderMap, fallback_stream: bool) -> bool {
  use tokn_headers::keys;
  match headers
    .get(&keys::CONTENT_TYPE)
    .map(|v| v.as_str())
    .and_then(|value| value.split(';').next())
    .map(str::trim)
  {
    Some(value) => value.eq_ignore_ascii_case("text/event-stream"),
    None => fallback_stream,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::{EventBus, EventPayload};
  use bytes::Bytes;
  use futures_util::StreamExt;
  use std::sync::Arc;
  use std::time::Duration;
  use tokn_core::provider::Endpoint;
  use tokn_headers::HeaderMap;

  fn ctx() -> (PipelineCtx, Arc<EventBus>) {
    let events = Arc::new(EventBus::new(128));
    (
      PipelineCtx::new("req-pcr", Endpoint::ChatCompletions.into(), events.clone()),
      events,
    )
  }

  fn response(status: u16, body: &'static str, content_type: &'static str) -> reqwest::Response {
    let resp = http::Response::builder()
      .status(status)
      .header("content-type", content_type)
      .body(body)
      .unwrap();
    reqwest::Response::from(resp)
  }

  fn headers(content_type: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
      tokn_headers::keys::CONTENT_TYPE.clone(),
      tokn_headers::HeaderValue::from_string(content_type.to_string()),
    );
    h
  }

  #[tokio::test]
  async fn buffered_forwards_bytes_verbatim() {
    let (c, _ev) = ctx();
    let raw = Bytes::from_static(br#"{"choices":[{"text":"hi"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}"#);
    let out = PassthroughConvertResponse::new()
      .convert_buffered(&c, 200, HeaderMap::new(), Some(Endpoint::ChatCompletions), raw.clone())
      .await
      .unwrap();
    assert_eq!(out.status, 200);
    match out.body {
      ConvertedBody::Buffered { body_json, body_bytes } => {
        assert_eq!(body_json, None, "body must NOT be parsed");
        assert_eq!(body_bytes, raw, "bytes verbatim");
      }
      _ => panic!("expected buffered"),
    }
  }

  #[tokio::test]
  async fn buffered_emits_usage_event() {
    let (c, events) = ctx();
    let mut rx = events.subscribe();
    let raw = Bytes::from_static(br#"{"usage":{"prompt_tokens":3,"completion_tokens":4}}"#);
    let _out = PassthroughConvertResponse::new()
      .convert_buffered(&c, 200, HeaderMap::new(), Some(Endpoint::ChatCompletions), raw)
      .await
      .unwrap();

    let mut saw_usage = false;
    for _ in 0..8 {
      let ev = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .ok()
        .and_then(|r| r.ok());
      let Some(ev) = ev else { break };
      if let tokn_core::event::Event::Requests(req) = &*ev {
        if let EventPayload::Record(RecordEvent::Usage(u)) = &req.payload {
          assert_eq!(u.input_tokens, Some(3));
          assert_eq!(u.output_tokens, Some(4));
          saw_usage = true;
          break;
        }
      }
    }
    assert!(saw_usage, "buffered passthrough should emit RecordEvent::Usage");
  }

  #[tokio::test]
  async fn stream_forwards_chunks_verbatim_and_extracts_usage_in_background() {
    let (c, events) = ctx();
    let mut rx = events.subscribe();
    let frame1 = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
    let frame2 = "data: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":9}}\n\n";
    let frame3 = "data: [DONE]\n\n";
    let body = futures_util::stream::iter(vec![
      Ok::<_, std::io::Error>(Bytes::from(frame1)),
      Ok(Bytes::from(frame2)),
      Ok(Bytes::from(frame3)),
    ])
    .boxed();

    let out = PassthroughConvertResponse::new()
      .convert_stream(&c, 200, HeaderMap::new(), Some(Endpoint::ChatCompletions), body)
      .await
      .unwrap();

    assert_eq!(out.status, 200);
    let ConvertedBody::Stream { mut body } = out.body else {
      panic!("expected stream");
    };
    let mut forwarded = Vec::new();
    while let Some(chunk) = body.next().await {
      forwarded.extend_from_slice(&chunk.expect("chunk ok"));
    }
    let expected = format!("{frame1}{frame2}{frame3}");
    assert_eq!(
      String::from_utf8(forwarded).unwrap(),
      expected,
      "stream chunks must be forwarded verbatim"
    );

    // Now wait for the background task to emit the usage event.
    let mut saw_usage = false;
    for _ in 0..16 {
      let ev = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .ok()
        .and_then(|r| r.ok());
      let Some(ev) = ev else { break };
      if let tokn_core::event::Event::Requests(req) = &*ev {
        if let EventPayload::Record(RecordEvent::Usage(u)) = &req.payload {
          assert_eq!(u.input_tokens, Some(7));
          assert_eq!(u.output_tokens, Some(9));
          saw_usage = true;
          break;
        }
      }
    }
    assert!(
      saw_usage,
      "background task should emit RecordEvent::Usage from SSE frames"
    );
  }

  #[tokio::test]
  async fn upstream_4xx_is_buffered_even_for_streaming_requests() {
    let (c, _events) = ctx();
    let sent = SentResponse {
      status: 403,
      headers: headers("text/event-stream"),
      stream: true,
      upstream_endpoint: Some(Endpoint::ChatCompletions),
      response: response(403, "event: error\ndata: forbidden\n\n", "text/event-stream"),
    };

    let out = PassthroughConvertResponse::new()
      .convert_response(&c, sent)
      .await
      .unwrap();

    assert_eq!(out.status, 403);
    match out.body {
      ConvertedBody::Buffered { body_bytes, .. } => {
        assert_eq!(body_bytes.as_ref(), b"event: error\ndata: forbidden\n\n");
      }
      ConvertedBody::Stream { .. } => panic!("4xx proxy errors must not be surfaced as SSE streams"),
    }
  }

  #[tokio::test]
  async fn is_sse_response_detects_content_type() {
    let mut h = HeaderMap::new();
    h.insert(
      tokn_headers::keys::CONTENT_TYPE.clone(),
      tokn_headers::HeaderValue::from_string("text/event-stream; charset=utf-8".into()),
    );
    assert!(is_sse_response(&h, false));

    let mut h = HeaderMap::new();
    h.insert(
      tokn_headers::keys::CONTENT_TYPE.clone(),
      tokn_headers::HeaderValue::from_string("application/json".into()),
    );
    assert!(!is_sse_response(&h, true), "explicit Content-Type wins over hint");

    let h = HeaderMap::new();
    assert!(is_sse_response(&h, true), "fallback used when no Content-Type");
    assert!(!is_sse_response(&h, false));
  }
}

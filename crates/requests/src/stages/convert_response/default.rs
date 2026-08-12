//! Production [`ConvertResponseStage`] implementation.
//!
//! Two focused methods split by the trait's provided dispatcher:
//!
//! 1. [`convert_buffered`](DefaultConvertResponse::convert_buffered):
//!    receives the already-drained body bytes, parses JSON, and optionally
//!    translates via [`tokn_convert::convert_response`] when upstream/inbound
//!    endpoints differ.
//!
//! 2. [`convert_stream`](DefaultConvertResponse::convert_stream):
//!    wraps the live response byte stream in [`SsePipeline`]; installs an
//!    [`EndpointTranslator`] when endpoints differ.
//!
//! The trait's provided [`convert_response`](ConvertResponseStage::convert_response)
//! handles the dispatch (buffered vs stream).

use crate::event::Stage;
use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::{PipelineError, RequestsError};
use crate::pipeline::stages::{ConvertResponseStage, ConvertedBody, ConvertedResponse, ConvertedResponseKind};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use serde_json::Value;
use std::sync::Arc;
use tokn_convert::sse::{observer_channel, EndpointTranslator, ObserverMsg, SsePipeline};
use tokn_convert::usage::{parse_usage_any_value, usage_has_any};
use tokn_core::provider::Endpoint;
use tokn_core::request_event::RecordEvent;
use tokn_headers::HeaderMap;
use tracing::{debug, instrument};

pub struct DefaultConvertResponse;

impl DefaultConvertResponse {
  pub fn new() -> Self {
    Self
  }
}

impl Default for DefaultConvertResponse {
  fn default() -> Self {
    Self::new()
  }
}

#[async_trait]
impl ConvertResponseStage for DefaultConvertResponse {
  #[instrument(name = "default_convert_buffered", skip_all, fields(
    status = status,
    upstream_endpoint = ?upstream_endpoint,
    inbound_endpoint = ?ctx.request_endpoint,
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
    let inbound_endpoint = ctx.request_endpoint.resolved().ok_or_else(|| {
      PipelineError::permanent(
        Stage::ConvertResponse,
        RequestsError::MissingResolvedEndpoint {
          request_endpoint: smol_str::SmolStr::new(ctx.request_endpoint.as_str()),
        },
      )
    })?;
    let upstream_endpoint = upstream_endpoint.ok_or_else(|| {
      PipelineError::permanent(
        Stage::ConvertResponse,
        RequestsError::MissingUpstreamEndpoint {
          request_endpoint: smol_str::SmolStr::new(ctx.request_endpoint.as_str()),
        },
      )
    })?;

    if body.is_empty() {
      return Ok(ConvertedResponse {
        status,
        headers,
        kind: ConvertedResponseKind::Managed,
        body: ConvertedBody::Buffered {
          body_json: None,
          body_bytes: Bytes::new(),
        },
      });
    }

    let upstream_json: Value = serde_json::from_slice(&body).map_err(|source| {
      PipelineError::permanent(
        crate::event::Stage::ConvertResponse,
        RequestsError::UpstreamBodyNotJson { source },
      )
    })?;

    // Best-effort usage extraction. Emit a RecordEvent::Usage so the
    // persistence layer (and any other subscriber) can pick it up.
    let parsed_usage = parse_usage_any_value(&upstream_json);
    if usage_has_any(&parsed_usage) {
      ctx.emit_record(RecordEvent::Usage(parsed_usage));
    }

    let (body_json, body_bytes) = if upstream_endpoint == inbound_endpoint {
      (upstream_json, body)
    } else {
      let translated =
        tokn_convert::convert_response(upstream_endpoint, inbound_endpoint, &upstream_json).map_err(|source| {
          PipelineError::permanent(
            crate::event::Stage::ConvertResponse,
            RequestsError::ResponseConversion { source },
          )
        })?;
      let bytes = serde_json::to_vec(&translated).map(Bytes::from).map_err(|source| {
        PipelineError::permanent(
          crate::event::Stage::ConvertResponse,
          RequestsError::SerializeTranslatedResponse { source },
        )
      })?;
      (translated, bytes)
    };

    Ok(ConvertedResponse {
      status,
      headers,
      kind: ConvertedResponseKind::Managed,
      body: ConvertedBody::Buffered {
        body_json: Some(Arc::new(body_json)),
        body_bytes,
      },
    })
  }

  #[instrument(name = "default_convert_stream", skip_all, fields(
    status = status,
    upstream_endpoint = ?upstream_endpoint,
    inbound_endpoint = ?ctx.request_endpoint,
  ))]
  async fn convert_stream(
    &self,
    ctx: &PipelineCtx,
    status: u16,
    headers: HeaderMap,
    upstream_endpoint: Option<Endpoint>,
    body: BoxStream<'static, std::io::Result<Bytes>>,
  ) -> Result<ConvertedResponse, PipelineError> {
    debug!("wrapping upstream response as SSE stream");
    let inbound_endpoint = ctx.request_endpoint.resolved().ok_or_else(|| {
      PipelineError::permanent(
        Stage::ConvertResponse,
        RequestsError::MissingResolvedEndpoint {
          request_endpoint: smol_str::SmolStr::new(ctx.request_endpoint.as_str()),
        },
      )
    })?;
    let upstream_endpoint = upstream_endpoint.ok_or_else(|| {
      PipelineError::permanent(
        Stage::ConvertResponse,
        RequestsError::MissingUpstreamEndpoint {
          request_endpoint: smol_str::SmolStr::new(ctx.request_endpoint.as_str()),
        },
      )
    })?;
    let mut pipeline = SsePipeline::from_stream(body);
    if upstream_endpoint != inbound_endpoint {
      pipeline = pipeline.with_transformer(EndpointTranslator::new(upstream_endpoint, inbound_endpoint));
    }

    // Tap parsed SSE event JSON to extract usage and emit
    // `RecordEvent::Usage` per frame that yields new figures. The shared
    // `usage_state` aggregate is also updated so the runner's periodic
    // `StreamProgress` events carry live usage.
    let (tap_tx, mut tap_rx) = observer_channel();
    pipeline = pipeline.with_tap_parsed(tap_tx);
    let tap_request_id = ctx.request_id.clone();
    let tap_attempt = ctx.attempt;
    let tap_events = ctx.events.clone();
    let tap_guard = ctx.events.begin_finalizer();
    tokio::spawn(async move {
      while let Some(msg) = tap_rx.recv().await {
        match msg {
          ObserverMsg::Parsed(Some(value)) => {
            let parsed = parse_usage_any_value(&value);
            if !usage_has_any(&parsed) {
              continue;
            }
            tap_events.emit(tokn_core::event::Event::Requests(
              tokn_core::request_event::RequestEvent {
                request_id: tap_request_id.clone(),
                attempt: tap_attempt,
                ts: tokn_core::util::now_unix_ms(),
                payload: tokn_core::request_event::RequestEventPayload::Record(RecordEvent::Usage(parsed)),
              },
            ));
          }
          ObserverMsg::Done | ObserverMsg::Error(_) => break,
          _ => {}
        }
      }
      tap_guard.finish();
    });

    Ok(ConvertedResponse {
      status,
      headers,
      kind: ConvertedResponseKind::Managed,
      body: ConvertedBody::Stream { body: pipeline.run() },
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::{EventBus, EventPayload};
  use crate::pipeline::stages::SentResponse;
  use futures_util::StreamExt;
  use std::sync::Arc;
  use tokn_core::provider::Endpoint;
  use tokn_core::request_event::RecordEvent;
  use tokn_headers::HeaderMap;

  fn ctx(endpoint: Endpoint) -> PipelineCtx {
    PipelineCtx::new("req-cr", endpoint.into(), Arc::new(EventBus::new(64)))
  }

  fn response(status: u16, body: &'static str, content_type: &'static str) -> reqwest::Response {
    let resp = http::Response::builder()
      .status(status)
      .header("content-type", content_type)
      .body(body)
      .unwrap();
    reqwest::Response::from(resp)
  }

  #[tokio::test]
  async fn buffered_passthrough_same_endpoint() {
    let stage = DefaultConvertResponse::new();
    let out = stage
      .convert_buffered(
        &ctx(Endpoint::ChatCompletions),
        200,
        HeaderMap::new(),
        Some(Endpoint::ChatCompletions),
        Bytes::from_static(br#"{"id":"x","choices":[]}"#),
      )
      .await
      .unwrap();
    assert_eq!(out.status, 200);
    match out.body {
      ConvertedBody::Buffered { body_json, body_bytes } => {
        assert_eq!(body_json.unwrap()["id"], "x");
        assert_eq!(body_bytes.as_ref(), br#"{"id":"x","choices":[]}"#);
      }
      _ => panic!("expected buffered"),
    }
  }

  #[tokio::test]
  async fn buffered_empty_body_yields_null() {
    let stage = DefaultConvertResponse::new();
    let out = stage
      .convert_buffered(
        &ctx(Endpoint::ChatCompletions),
        502,
        HeaderMap::new(),
        Some(Endpoint::ChatCompletions),
        Bytes::new(),
      )
      .await
      .unwrap();
    assert_eq!(out.status, 502);
    match out.body {
      ConvertedBody::Buffered { body_json, body_bytes } => {
        assert!(body_json.is_none());
        assert!(body_bytes.is_empty());
      }
      _ => panic!("expected buffered"),
    }
  }

  #[tokio::test]
  async fn buffered_invalid_json_is_permanent() {
    let stage = DefaultConvertResponse::new();
    let err = stage
      .convert_buffered(
        &ctx(Endpoint::ChatCompletions),
        200,
        HeaderMap::new(),
        Some(Endpoint::ChatCompletions),
        Bytes::from_static(b"not json"),
      )
      .await
      .unwrap_err();
    assert_eq!(err.stage, crate::event::Stage::ConvertResponse);
    assert!(!err.recoverable);
    assert!(err.message().contains("not valid JSON"));
  }

  #[tokio::test]
  async fn stream_branch_returns_stream_variant() {
    let stage = DefaultConvertResponse::new();
    let body = "data: {\"hello\":1}\n\ndata: [DONE]\n\n";
    let out = stage
      .convert_stream(
        &ctx(Endpoint::ChatCompletions),
        200,
        HeaderMap::new(),
        Some(Endpoint::ChatCompletions),
        futures_util::stream::iter(vec![Ok(Bytes::from(body))]).boxed(),
      )
      .await
      .unwrap();
    assert_eq!(out.status, 200);
    match out.body {
      ConvertedBody::Stream { mut body } => {
        let chunk = body.next().await.expect("at least one chunk").expect("ok chunk");
        assert!(!chunk.is_empty());
      }
      _ => panic!("expected stream"),
    }
  }

  #[tokio::test]
  async fn provided_convert_response_emits_upstream_body_for_buffered() {
    let stage = DefaultConvertResponse::new();
    let events = Arc::new(EventBus::new(64));
    let ctx = PipelineCtx::new("req-body", Endpoint::ChatCompletions.into(), events.clone());
    let mut rx = events.subscribe();
    let sent = SentResponse {
      status: 200,
      headers: HeaderMap::new(),
      stream: false,
      upstream_endpoint: Some(Endpoint::ChatCompletions),
      response: response(200, r#"{"ok":true}"#, "application/json"),
    };
    let out = stage.convert_response(&ctx, sent).await.unwrap();
    assert_eq!(out.status, 200);
    match out.body {
      ConvertedBody::Buffered { body_bytes, .. } => {
        assert_eq!(body_bytes.as_ref(), br#"{"ok":true}"#);
      }
      _ => panic!("expected buffered"),
    }
    let mut saw = false;
    for _ in 0..4 {
      if let Ok(ev) = rx.recv().await {
        if let tokn_core::event::Event::Requests(req) = &*ev {
          if let EventPayload::Record(RecordEvent::UpstreamBody { body, error }) = &req.payload {
            assert_eq!(body.as_ref(), br#"{"ok":true}"#);
            assert!(error.is_none());
            saw = true;
            break;
          }
        }
      }
    }
    assert!(saw, "buffered convert_response should emit UpstreamBody");
  }

  #[tokio::test]
  async fn provided_convert_response_stream_emits_body_records() {
    let stage = DefaultConvertResponse::new();
    let events = Arc::new(EventBus::new(64));
    let ctx = PipelineCtx::new("req-stream", Endpoint::ChatCompletions.into(), events.clone());
    let mut rx = events.subscribe();
    let sent = SentResponse {
      status: 200,
      headers: HeaderMap::new(),
      stream: true,
      upstream_endpoint: Some(Endpoint::ChatCompletions),
      response: response(200, "data: {}\n\ndata: [DONE]\n\n", "text/event-stream"),
    };
    let out = stage.convert_response(&ctx, sent).await.unwrap();
    let ConvertedBody::Stream { mut body } = out.body else {
      panic!("expected stream");
    };
    while let Some(chunk) = body.next().await {
      chunk.expect("stream chunk");
    }

    let mut saw_upstream = false;
    let mut saw_converted = false;
    for _ in 0..4 {
      if let Ok(ev) = rx.recv().await {
        if let tokn_core::event::Event::Requests(req) = &*ev {
          match &req.payload {
            EventPayload::Record(RecordEvent::UpstreamBody { body, error }) => {
              assert_eq!(body.as_ref(), b"data: {}\n\ndata: [DONE]\n\n");
              assert!(error.is_none());
              saw_upstream = true;
            }
            EventPayload::Record(RecordEvent::ConvertedBody { body, error }) => {
              assert!(!body.is_empty());
              assert!(error.is_none());
              saw_converted = true;
            }
            _ => {}
          }
          if saw_upstream && saw_converted {
            break;
          }
        }
      }
    }
    assert!(saw_upstream, "stream convert_response should emit UpstreamBody");
    assert!(saw_converted, "stream convert_response should emit ConvertedBody");
  }
}

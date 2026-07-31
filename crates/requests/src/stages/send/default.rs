//! Production [`SendStage`] implementation.
//!
//! Bridges the requests stage pipeline to the legacy `Provider` trait
//! (`tokn_core::provider::Provider`). Build a [`tokn_core::provider::RequestCtx`]
//! from the upstream-shaped body (produced by ConvertRequest), persona
//! headers (produced by BuildHeaders), and a few inbound facts pulled from
//! `Extracted`; then dispatch on the resolved upstream endpoint to the
//! provider's `chat` / `responses` / `messages` method.
//!
//! The provider is responsible for URL construction, auth injection, and
//! the actual HTTP call — `DefaultSend` only wires the data flow and
//! classifies failures into recoverable / permanent [`PipelineError`]s.
//!
//! The returned [`SentResponse`] carries the live [`reqwest::Response`];
//! draining or wrapping it as an SSE stream is the next stage's job.

use crate::event::Stage;
use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::{PipelineError, ProviderError, RequestsError};
use crate::pipeline::stages::{
  require_upstream_endpoint, BuiltHeaders, ConvertedRequest, Extracted, Resolved, SendStage, SentResponse,
};
use async_trait::async_trait;
use bytes::Bytes;
use smol_str::SmolStr;
use tokn_core::provider::{new_outbound_capture, Endpoint, RequestCtx};
use tokn_core::request_event::RecordEvent;
use tokn_headers::HeaderMap;
use tracing::{debug, instrument, warn};

pub struct DefaultSend {
  http: reqwest::Client,
}

impl DefaultSend {
  pub fn new(http: reqwest::Client) -> Self {
    Self { http }
  }
}

#[async_trait]
impl SendStage for DefaultSend {
  #[instrument(name = "default_send", skip_all, fields(
    account = %resolved.account_id,
    provider = %resolved.provider_id,
    endpoint = ?resolved.route.upstream_endpoint(),
    stream = extracted.stream,
  ))]
  async fn send(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
    headers: &BuiltHeaders,
    body: &ConvertedRequest,
  ) -> Result<SentResponse, PipelineError> {
    let upstream_endpoint = require_upstream_endpoint(ctx, resolved, Stage::Send)?;
    let initiator = extracted.initiator.as_deref().unwrap_or("user");
    // Client-derived headers are passed via `client_headers`. The provider's
    // own `patch_headers` will run on top to inject auth + content-type;
    // `inbound_headers` therefore only needs to provide template-vars-
    // adjacent context — empty is fine because we already populated
    // `vars` in BuildHeaders.
    let inbound_headers = HeaderMap::new();
    // Wire-truth capture slot. Providers populate this from inside
    // `tokn_core::util::http::send` immediately before reqwest dispatch,
    // so the snapshot reflects the actual on-wire request (post auth
    // injection, post Host/Content-Length strip). We later forward it
    // as `Record::UpstreamReq` / `Record::UpstreamResp` events so the
    // persistence handler can write wire-accurate values into the row.
    let capture = new_outbound_capture();
    let req_ctx = RequestCtx {
      endpoint: upstream_endpoint,
      http: &self.http,
      body: body.upstream_body.as_ref(),
      body_bytes: Some(&body.upstream_wire_body),
      content_encoding: body.content_encoding.map(|e| e.as_str()),
      stream: extracted.stream,
      initiator,
      inbound_headers: &inbound_headers,
      client_headers: Some(headers.headers.clone()),
      outbound: Some(capture.clone()),
      vars: headers.vars.clone(),
      agent_id: headers.agent_id.clone(),
    };

    let provider = resolved.account_handle.provider.clone();
    let resp_result = match upstream_endpoint {
      Endpoint::ChatCompletions => provider.chat(req_ctx).await,
      Endpoint::Responses => provider.responses(req_ctx).await,
      Endpoint::Messages => provider.messages(req_ctx).await,
    };

    // Emit the request-side record regardless of outcome — even on a
    // transport failure the capture may have been populated before the
    // wire call actually failed, and persisting it helps diagnose.
    // Providers that never call `util::http::send` leave the slot empty,
    // in which case we simply skip the event.
    if let Some(snap) = capture.get() {
      let method = snap.method.clone().unwrap_or_else(|| "POST".to_string());
      let url = snap.url.clone().unwrap_or_default();
      ctx.emit_record(RecordEvent::UpstreamReq {
        method: SmolStr::new(method),
        url: SmolStr::new(url),
        headers: snap.req_headers.clone(),
        body: snap.req_body.clone(),
      });
    } else {
      warn!(
        provider = %resolved.provider_id,
        "outbound capture not populated; provider may not route through util::http::send"
      );
    }

    let resp = resp_result.map_err(classify_provider_error)?;

    let status = resp.status().as_u16();
    let resp_headers = HeaderMap::from(resp.headers());
    debug!(%status, "upstream responded");

    // Response-side record: status + headers as soon as they arrive.
    // The body lives in `resp` and is consumed by ConvertResponse;
    // `Record::UpstreamBody` is emitted from there for buffered flows.
    ctx.emit_record(RecordEvent::UpstreamResp {
      status,
      headers: resp_headers.clone(),
    });

    // Status-based classification: 5xx is recoverable (transient
    // upstream issue), 4xx is permanent (won't change on retry). 2xx/3xx
    // flow through normally.
    if status >= 500 {
      let body_text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
          return Err(PipelineError::recoverable(
            Stage::Send,
            RequestsError::UpstreamReadFailed { status, source: e },
          ));
        }
      };
      ctx.emit_record(RecordEvent::UpstreamBody {
        body: Bytes::copy_from_slice(body_text.as_bytes()),
        error: None,
      });
      return Err(PipelineError::recoverable(
        Stage::Send,
        RequestsError::UpstreamStatus {
          status,
          body: truncate(&body_text, 512),
        },
      ));
    }
    if status >= 400 {
      let body_text = resp.text().await.unwrap_or_default();
      ctx.emit_record(RecordEvent::UpstreamBody {
        body: Bytes::copy_from_slice(body_text.as_bytes()),
        error: None,
      });
      return Err(PipelineError::permanent(
        Stage::Send,
        RequestsError::UpstreamStatus {
          status,
          body: truncate(&body_text, 512),
        },
      ));
    }

    Ok(SentResponse {
      status,
      headers: resp_headers,
      stream: extracted.stream,
      upstream_endpoint: Some(upstream_endpoint),
      response: resp,
    })
  }
}

/// Map an `tokn_core::provider::Error` to a [`PipelineError`]. Transport-
/// level failures (connect, timeout, etc.) are recoverable; everything else
/// is permanent for this attempt.
///
/// The error message walks the full `std::error::Error::source()` chain so
/// transport failures like `error sending request for url (…)` expose
/// their underlying cause (e.g. `tcp connect error: Connection refused`,
/// `dns error: failed to lookup address information`). Without this,
/// reqwest's top-level `Display` hides everything below it and the user
/// can't tell DNS failure from TLS failure from refused-connection.
pub(super) fn classify_provider_error(err: tokn_core::provider::Error) -> PipelineError {
  use tokn_core::provider::Error as E;
  let recoverable = matches!(&err, E::Http { .. });
  let source = RequestsError::Provider {
    source: ProviderError::new(err),
  };
  if recoverable {
    PipelineError::recoverable(Stage::Send, source)
  } else {
    PipelineError::permanent(Stage::Send, source)
  }
}

fn truncate(s: &str, max: usize) -> String {
  if s.len() <= max {
    s.to_string()
  } else {
    format!("{}…", &s[..max])
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::EventBus;
  use crate::event::EventPayload;
  use crate::pipeline::config::RunConfig;
  use crate::pipeline::stages::{BuiltHeaders, ConvertedRequest, Extracted, Resolved, ResolvedRoute};
  use crate::test_support::{mock_handle_with_provider, MockProvider};
  use bytes::Bytes;
  use serde_json::Value;
  use smol_str::SmolStr;
  use std::sync::Arc;
  use tokn_core::provider::{Endpoint, Result as ProviderResult};

  fn ctx() -> PipelineCtx {
    PipelineCtx::new(
      "req-send",
      Endpoint::ChatCompletions.into(),
      Arc::new(EventBus::new(64)),
    )
  }

  fn ctx_with_config(config: RunConfig) -> PipelineCtx {
    PipelineCtx::new_with_config(
      "req-send",
      Endpoint::ChatCompletions.into(),
      Arc::new(EventBus::new(64)),
      Arc::new(config),
    )
  }

  fn extracted() -> Extracted {
    Extracted {
      agent_id: None,
      model: SmolStr::new("m"),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: None,
      header_initiator: None,
      route_mode_hint: None,
      headers: HeaderMap::new(),
      raw_body: Bytes::new(),
      decoded_body: Bytes::new(),
      body_json: std::sync::Arc::new(Value::Null),
      content_encoding: None,
    }
  }

  fn resolved(handle: Arc<tokn_accounts::AccountHandle>) -> Resolved {
    Resolved {
      agent_id: None,
      model: SmolStr::new("m"),
      upstream_model: SmolStr::new("m"),
      route: ResolvedRoute::operation(Endpoint::ChatCompletions, Endpoint::ChatCompletions),
      account_id: SmolStr::new("acct-1"),
      provider_id: SmolStr::from(handle.provider.id()),
      account_handle: handle,
    }
  }

  fn body() -> ConvertedRequest {
    let bytes = Bytes::from(serde_json::to_vec(&serde_json::json!({"model":"m"})).unwrap());
    ConvertedRequest {
      upstream_body: std::sync::Arc::new(Value::Null),
      upstream_wire_body: bytes.clone(),
      debug_outbound_body: bytes,
      content_encoding: None,
    }
  }

  fn ok_response(status: u16, body: &'static str) -> reqwest::Response {
    let resp = http::Response::builder()
      .status(status)
      .header("content-type", "application/json")
      .body(body)
      .unwrap();
    reqwest::Response::from(resp)
  }

  #[tokio::test]
  async fn dispatches_to_chat_and_returns_sent_response() {
    let provider = MockProvider::new("mock").with_chat_response(ok_response(200, r#"{"ok":true}"#));
    let handle = mock_handle_with_provider("acct", provider);
    let send = DefaultSend::new(reqwest::Client::new());
    let out = send
      .send(
        &ctx(),
        &extracted(),
        &resolved(handle),
        &BuiltHeaders::default(),
        &body(),
      )
      .await
      .expect("send should succeed");
    assert_eq!(out.status, 200);
    assert_eq!(out.upstream_endpoint, Some(Endpoint::ChatCompletions));
    assert!(!out.stream);
  }

  #[tokio::test]
  async fn five_xx_is_recoverable() {
    let provider = MockProvider::new("mock").with_chat_response(ok_response(503, "boom"));
    let handle = mock_handle_with_provider("acct", provider);
    let send = DefaultSend::new(reqwest::Client::new());
    let err = send
      .send(
        &ctx(),
        &extracted(),
        &resolved(handle),
        &BuiltHeaders::default(),
        &body(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::Send);
    assert!(err.recoverable);
    match err.inner() {
      RequestsError::UpstreamStatus { status, .. } => assert_eq!(*status, 503),
      other => panic!("expected UpstreamStatus, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn four_xx_is_permanent() {
    let provider = MockProvider::new("mock").with_chat_response(ok_response(401, "no"));
    let handle = mock_handle_with_provider("acct", provider);
    let send = DefaultSend::new(reqwest::Client::new());
    let err = send
      .send(
        &ctx(),
        &extracted(),
        &resolved(handle),
        &BuiltHeaders::default(),
        &body(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::Send);
    assert!(!err.recoverable);
    match err.inner() {
      RequestsError::UpstreamStatus { status, .. } => assert_eq!(*status, 401),
      other => panic!("expected UpstreamStatus, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn upstream_error_emits_response_and_body_records() {
    let events = Arc::new(EventBus::new(16));
    let mut rx = events.subscribe();
    let provider = MockProvider::new("mock").with_chat_response(ok_response(502, r#"{"error":"boom"}"#));
    let handle = mock_handle_with_provider("acct", provider);
    let send = DefaultSend::new(reqwest::Client::new());
    let ctx = PipelineCtx::new("req-send-err", Endpoint::ChatCompletions.into(), events);

    let err = send
      .send(&ctx, &extracted(), &resolved(handle), &BuiltHeaders::default(), &body())
      .await
      .unwrap_err();

    assert!(matches!(err.inner(), RequestsError::UpstreamStatus { status: 502, .. }));

    let first = rx.recv().await.unwrap();
    let second = rx.recv().await.unwrap();

    let mut saw_resp = false;
    let mut saw_body = false;
    for event in [&first, &second] {
      match event.as_ref() {
        tokn_core::event::Event::Requests(req) => match &req.payload {
          EventPayload::Record(RecordEvent::UpstreamResp { status, .. }) => {
            saw_resp = true;
            assert_eq!(*status, 502);
          }
          EventPayload::Record(RecordEvent::UpstreamBody { body, error }) => {
            saw_body = true;
            assert_eq!(std::str::from_utf8(body.as_ref()).unwrap(), r#"{"error":"boom"}"#);
            assert!(error.is_none());
          }
          other => panic!("unexpected request event: {other:?}"),
        },
        other => panic!("unexpected event: {other:?}"),
      }
    }

    assert!(saw_resp, "missing UpstreamResp record");
    assert!(saw_body, "missing UpstreamBody record");
  }

  #[tokio::test]
  async fn provider_error_classified_by_kind() {
    let provider =
      MockProvider::new("mock").with_chat_error(|| tokn_core::provider::Error::Profiles { message: "boom".into() });
    let handle = mock_handle_with_provider("acct", provider);
    let send = DefaultSend::new(reqwest::Client::new());
    let err = send
      .send(
        &ctx(),
        &extracted(),
        &resolved(handle),
        &BuiltHeaders::default(),
        &body(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::Send);
    assert!(!err.recoverable);
    assert!(err.to_string().contains("boom"));
  }

  #[tokio::test]
  async fn uses_run_config_upstream_endpoint_override() {
    let provider =
      MockProvider::new("mock").with_responses_response(ok_response(200, r#"{"id":"resp_123","output":[]}"#));
    let handle = mock_handle_with_provider("acct", provider);
    let send = DefaultSend::new(reqwest::Client::new());
    let ctx = ctx_with_config(
      RunConfig::builder()
        .with_str(crate::pipeline::stages::RUN_UPSTREAM_ENDPOINT_KEY, "responses")
        .build(),
    );
    let resolved = resolved(handle);

    let out = send
      .send(&ctx, &extracted(), &resolved, &BuiltHeaders::default(), &body())
      .await
      .expect("send should use configured upstream endpoint");

    assert_eq!(out.status, 200);
    assert_eq!(out.upstream_endpoint, Some(Endpoint::Responses));
  }

  #[tokio::test]
  async fn errors_when_no_upstream_endpoint_can_be_resolved() {
    let provider = MockProvider::new("mock");
    let handle = mock_handle_with_provider("acct", provider);
    let send = DefaultSend::new(reqwest::Client::new());
    let mut resolved = resolved(handle);
    resolved.route = ResolvedRoute::provider_traffic(tokn_core::provider::ProviderRequestKind::Opaque);
    let ctx = PipelineCtx::new(
      "req-send-missing",
      tokn_core::request_event::RequestEndpoint::custom("/v1/experimental/agents"),
      Arc::new(EventBus::new(64)),
    );

    let err = send
      .send(&ctx, &extracted(), &resolved, &BuiltHeaders::default(), &body())
      .await
      .unwrap_err();

    assert_eq!(err.stage, Stage::Send);
    assert!(!err.recoverable);
    match err.inner() {
      RequestsError::MissingUpstreamEndpoint { request_endpoint } => {
        assert_eq!(request_endpoint.as_str(), "/v1/experimental/agents");
      }
      other => panic!("expected MissingUpstreamEndpoint, got {other:?}"),
    }
  }

  // Ensure the test harness compiles even if `ProviderResult` is unused
  // in some build variants.
  #[allow(dead_code)]
  fn _types_used() -> Option<ProviderResult<()>> {
    None
  }
}

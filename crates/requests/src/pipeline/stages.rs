//! Stage traits + the data structs that flow between them.
//!
//! Each stage is an `async_trait`-object so [`Profile`] can store them behind
//! `Arc<dyn ...>`. Stages take `&PipelineCtx` (not `&mut`) — the runner owns
//! the ctx and is the sole authority on the per-request state shape. Stages
//! may publish custom events through `ctx.emit_custom`.
//!
//! Each stage returns `Result<Output, PipelineError>`. The runner emits the
//! corresponding success [`StageEvent`] on `Ok` and a tagged
//! [`StageEvent::Error`] on `Err`.
//!
//! [`Profile`]: crate::profile::Profile
//! [`StageEvent`]: crate::event::StageEvent
//! [`StageEvent::Error`]: crate::event::StageEvent::Error

use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::{PipelineError, RequestsError};
use crate::utils::codec::ContentEncodingKind;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use serde_json::Value;
use smol_str::SmolStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokn_accounts::AccountHandle;
use tokn_core::provider::{Endpoint, ProviderRequestKind};
use tokn_core::request_event::RequestEndpoint;
use tokn_core::AgentId;
use tokn_headers::{HeaderMap, TemplateVars};

pub const RUN_UPSTREAM_ENDPOINT_KEY: &str = "run.upstream_endpoint";

#[derive(Clone)]
pub(crate) struct AccumHelper {
  tx: mpsc::UnboundedSender<AccumMsg>,
}

pub(crate) enum AccumMsg {
  Upstream(Bytes),
  Converted(Bytes),
  UpstreamError(SmolStr),
  ConvertedError(SmolStr),
  Finish,
}

impl AccumHelper {
  pub(crate) fn spawn(ctx: &PipelineCtx, model: SmolStr) -> Self {
    let request_id = ctx.request_id.clone();
    let attempt = ctx.attempt;
    let attempts = attempt + 1;
    let request_endpoint = ctx.request_endpoint.as_str().to_string();
    let events = ctx.events.clone();
    let guard = ctx.events.begin_finalizer();
    let (tx, mut rx) = mpsc::unbounded_channel::<AccumMsg>();
    let usage: Arc<std::sync::Mutex<tokn_core::db::Usage>> =
      Arc::new(std::sync::Mutex::new(tokn_core::db::Usage::default()));
    let usage_for_task = usage.clone();
    tokio::spawn(async move {
      use tokio::time::{interval, Duration, MissedTickBehavior};

      let mut upstream = Vec::new();
      let mut converted = Vec::new();
      let mut upstream_error = None;
      let mut converted_error = None;
      let mut bytes_streamed: u64 = 0;
      let mut chunks: u64 = 0;

      let mut tick = interval(Duration::from_millis(500));
      tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
      tick.tick().await;

      loop {
        tokio::select! {
          msg = rx.recv() => {
            match msg {
              Some(AccumMsg::Upstream(bytes)) => upstream.extend_from_slice(&bytes),
              Some(AccumMsg::Converted(bytes)) => {
                bytes_streamed += bytes.len() as u64;
                chunks += 1;
                converted.extend_from_slice(&bytes);
              }
              Some(AccumMsg::UpstreamError(err)) => upstream_error = Some(err),
              Some(AccumMsg::ConvertedError(err)) => converted_error = Some(err),
              Some(AccumMsg::Finish) | None => break,
            }
          }
          _ = tick.tick() => {
            let snapshot = usage_for_task.lock().map(|u| u.clone()).unwrap_or_default();
            events.emit(tokn_core::event::Event::StreamProgress {
              request_id: request_id.to_string(),
              model: model.to_string(),
              endpoint: request_endpoint.clone(),
              usage: snapshot,
              bytes_streamed,
              chunks,
            });
          }
        }
      }

      events.emit(tokn_core::event::Event::Requests(
        tokn_core::request_event::RequestEvent {
          request_id: request_id.clone(),
          attempt,
          ts: tokn_core::util::now_unix_ms(),
          payload: tokn_core::request_event::RequestEventPayload::Record(
            tokn_core::request_event::RecordEvent::UpstreamBody {
              body: Bytes::from(upstream),
              error: upstream_error,
            },
          ),
        },
      ));
      events.emit(tokn_core::event::Event::Requests(
        tokn_core::request_event::RequestEvent {
          request_id: request_id.clone(),
          attempt,
          ts: tokn_core::util::now_unix_ms(),
          payload: tokn_core::request_event::RequestEventPayload::Record(
            tokn_core::request_event::RecordEvent::ConvertedBody {
              body: Bytes::from(converted),
              error: converted_error,
            },
          ),
        },
      ));
      events.emit(tokn_core::event::Event::Requests(
        tokn_core::request_event::RequestEvent {
          request_id,
          attempt,
          ts: tokn_core::util::now_unix_ms(),
          payload: tokn_core::request_event::RequestEventPayload::Stage(
            tokn_core::request_event::StageEvent::Completed {
              success: true,
              attempts,
            },
          ),
        },
      ));
      guard.finish();
    });
    Self { tx }
  }

  pub(crate) fn note_upstream(&self, item: &std::io::Result<Bytes>) {
    match item {
      Ok(bytes) => {
        let _ = self.tx.send(AccumMsg::Upstream(bytes.clone()));
      }
      Err(err) => {
        tracing::warn!("got upstream chunk error: {:?}", err);
        let _ = self.tx.send(AccumMsg::UpstreamError(SmolStr::new(err.to_string())));
      }
    }
  }

  pub(crate) fn note_converted(&self, item: &std::io::Result<Bytes>) {
    match item {
      Ok(bytes) => {
        let _ = self.tx.send(AccumMsg::Converted(bytes.clone()));
      }
      Err(err) => {
        tracing::warn!("got converted chunk error: {:?}", err);
        let _ = self.tx.send(AccumMsg::ConvertedError(SmolStr::new(err.to_string())));
      }
    }
  }

  pub(crate) fn finish(&self) {
    tracing::debug!("upstream stream ended");
    let _ = self.tx.send(AccumMsg::Finish);
  }
}

impl Drop for AccumHelper {
  fn drop(&mut self) {
    self.finish();
  }
}

/// Raw inbound HTTP payload passed to the Extract stage. The runner is
/// responsible for assembling this from whatever transport is in front of
/// requests (axum in production, fixtures in tests).
#[derive(Debug, Clone)]
pub struct RawInbound {
  pub request_endpoint: RequestEndpoint,
  pub headers: HeaderMap,
  /// Original wire body (still compressed if it arrived compressed). PR1
  /// does not require decompression; the production path will populate
  /// `decoded_body` separately when wiring real transport.
  pub raw_body: Bytes,
  /// Post-decompression body bytes — equal to `raw_body` when the inbound
  /// payload was uncompressed.
  pub decoded_body: Bytes,
  pub body_json: Value,
  /// Optional request id supplied by the transport. When `None`, the runner
  /// generates one before constructing [`PipelineCtx`].
  pub request_id: Option<SmolStr>,
}

/// Output of [`ExtractStage`]: everything subsequent stages need to know
/// about the inbound request, in normalized form.
///
/// `Extracted` deliberately does **not** carry the inbound endpoint — that
/// lives on [`PipelineCtx`] (`ctx.request_endpoint`) because the runner has it
/// from the start and every stage gets `&PipelineCtx`. Keeping it on the ctx
/// avoids duplication and ensures a single source of truth.
#[derive(Debug, Clone)]
pub struct Extracted {
  pub agent_id: Option<AgentId>,
  pub model: SmolStr,
  pub stream: bool,
  pub session_id: Option<SmolStr>,
  pub project_id: Option<SmolStr>,
  pub initiator: Option<SmolStr>,
  pub header_initiator: Option<SmolStr>,
  pub route_mode_hint: Option<SmolStr>,
  pub headers: HeaderMap,
  pub raw_body: Bytes,
  pub decoded_body: Bytes,
  pub body_json: Arc<Value>,
  /// Content-encoding the client used on the request body, parsed from
  /// the inbound `Content-Encoding` header. `None` when the body arrived
  /// uncompressed. ConvertRequest uses this to re-encode the outbound
  /// payload with the same codec when possible.
  pub content_encoding: Option<ContentEncodingKind>,
}

/// Output of [`ResolveStage`]: which account+upstream answers this request.
#[derive(Clone)]
pub struct Resolved {
  pub agent_id: Option<AgentId>,
  pub model: SmolStr,
  pub upstream_model: SmolStr,
  pub route: ResolvedRoute,
  pub account_id: SmolStr,
  pub provider_id: SmolStr,
  /// Typed handle to the selected account. Holding the [`AccountHandle`]
  /// directly (instead of an `Arc<dyn Any>`) lets downstream stages call
  /// `provider.input_transformer()` etc. without a downcast.
  pub account_handle: std::sync::Arc<AccountHandle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedRoute {
  Operation {
    resolved_endpoint: Endpoint,
    upstream_endpoint: Endpoint,
  },
  ProviderTraffic {
    request_kind: ProviderRequestKind,
  },
}

impl ResolvedRoute {
  pub fn operation(resolved_endpoint: Endpoint, upstream_endpoint: Endpoint) -> Self {
    Self::Operation {
      resolved_endpoint,
      upstream_endpoint,
    }
  }

  pub fn provider_traffic(request_kind: ProviderRequestKind) -> Self {
    Self::ProviderTraffic { request_kind }
  }

  pub fn resolved_endpoint(self) -> Option<Endpoint> {
    match self {
      Self::Operation { resolved_endpoint, .. } => Some(resolved_endpoint),
      Self::ProviderTraffic { .. } => None,
    }
  }

  pub fn upstream_endpoint(self) -> Option<Endpoint> {
    match self {
      Self::Operation { upstream_endpoint, .. } => Some(upstream_endpoint),
      Self::ProviderTraffic { .. } => None,
    }
  }

  pub fn provider_request_kind(self) -> ProviderRequestKind {
    match self {
      Self::Operation { upstream_endpoint, .. } => ProviderRequestKind::Operation(upstream_endpoint),
      Self::ProviderTraffic { request_kind } => request_kind,
    }
  }
}

impl std::fmt::Debug for Resolved {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Resolved")
      .field("agent_id", &self.agent_id)
      .field("model", &self.model)
      .field("upstream_model", &self.upstream_model)
      .field("route", &self.route)
      .field("account_id", &self.account_id)
      .field("provider_id", &self.provider_id)
      .field("account_handle", &"<opaque>")
      .finish()
  }
}

/// Output of [`BuildHeadersStage`]: the composed outbound `HeaderMap` that
/// the Send stage will use as the upstream request's headers, plus the
/// [`TemplateVars`] derived from the inbound request (kept around so later
/// stages can splice values without re-parsing inbound headers).
#[derive(Debug, Clone, Default)]
pub struct BuiltHeaders {
  pub headers: HeaderMap,
  pub vars: TemplateVars,
  pub agent_id: AgentId,
}

/// Output of [`ConvertRequestStage`]: the upstream-shaped JSON body, the
/// (re-encoded) bytes we'll actually send on the wire, the
/// post-encoding-but-pre-compression bytes (handy for logging), and the
/// `Content-Encoding` value to put on the outbound request (when any).
#[derive(Debug, Clone)]
pub struct ConvertedRequest {
  /// Upstream-shaped JSON body. Wrapped in `Arc` so observers receiving
  /// [`StageEvent::ConvertRequest`](crate::event::StageEvent::ConvertRequest)
  /// can clone the payload cheaply.
  pub upstream_body: Arc<Value>,
  pub upstream_wire_body: Bytes,
  /// Uncompressed serialized JSON, mirroring the legacy
  /// `prepare_request` behaviour where structured logs / tests want to
  /// inspect the outbound payload without inflating it.
  pub debug_outbound_body: Bytes,
  pub content_encoding: Option<ContentEncodingKind>,
}

/// Output of [`SendStage`]: a live upstream HTTP response plus the metadata
/// downstream stages need without consuming the body.
///
/// Holds the raw [`reqwest::Response`] so that [`ConvertResponseStage`] can
/// choose at use-time whether to drain it into a buffered JSON payload or
/// wrap it in an SSE pipeline. Not `Clone`: the response is single-shot.
pub struct SentResponse {
  pub status: u16,
  pub headers: HeaderMap,
  /// Whether the request *asked* for SSE streaming (mirrors `Extracted.stream`).
  /// ConvertResponse uses this to pick the buffered vs. stream branch.
  pub stream: bool,
  /// Endpoint the upstream provider was actually called with — may differ
  /// from the inbound `request_endpoint` when a request-shape translation
  /// happened in ConvertRequest.
  pub upstream_endpoint: Option<Endpoint>,
  pub response: reqwest::Response,
}

impl std::fmt::Debug for SentResponse {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("SentResponse")
      .field("status", &self.status)
      .field("headers", &self.headers)
      .field("stream", &self.stream)
      .field("upstream_endpoint", &self.upstream_endpoint)
      .field("response", &"<reqwest::Response>")
      .finish()
  }
}

fn invalid_configured_endpoint(stage: crate::event::Stage, value: &str) -> PipelineError {
  PipelineError::permanent(
    stage,
    RequestsError::InvalidConfiguredEndpoint {
      key: RUN_UPSTREAM_ENDPOINT_KEY,
      value: SmolStr::new(value),
    },
  )
}

fn parse_endpoint(value: &str) -> Option<Endpoint> {
  match value {
    "chat_completions" | "chat" | "chat-completions" => Some(Endpoint::ChatCompletions),
    "responses" => Some(Endpoint::Responses),
    "messages" => Some(Endpoint::Messages),
    _ => None,
  }
}

pub fn configured_upstream_endpoint(
  ctx: &PipelineCtx,
  stage: crate::event::Stage,
) -> Result<Option<Endpoint>, PipelineError> {
  match ctx.config.get_str(RUN_UPSTREAM_ENDPOINT_KEY) {
    Some(value) => parse_endpoint(value)
      .map(Some)
      .ok_or_else(|| invalid_configured_endpoint(stage, value)),
    None => Ok(None),
  }
}

pub fn resolved_upstream_endpoint(
  ctx: &PipelineCtx,
  resolved: &Resolved,
  stage: crate::event::Stage,
) -> Result<Option<Endpoint>, PipelineError> {
  Ok(configured_upstream_endpoint(ctx, stage)?.or(resolved.route.upstream_endpoint()))
}

pub fn require_resolved_endpoint(
  ctx: &PipelineCtx,
  resolved: &Resolved,
  stage: crate::event::Stage,
) -> Result<Endpoint, PipelineError> {
  resolved.route.resolved_endpoint().ok_or_else(|| {
    PipelineError::permanent(
      stage,
      RequestsError::MissingResolvedEndpoint {
        request_endpoint: SmolStr::new(ctx.request_endpoint.as_str()),
      },
    )
  })
}

pub fn provider_request_kind(
  ctx: &PipelineCtx,
  resolved: &Resolved,
  stage: crate::event::Stage,
) -> Result<ProviderRequestKind, PipelineError> {
  match resolved.route {
    ResolvedRoute::Operation { upstream_endpoint, .. } => Ok(ProviderRequestKind::Operation(
      configured_upstream_endpoint(ctx, stage)?.unwrap_or(upstream_endpoint),
    )),
    ResolvedRoute::ProviderTraffic { request_kind } => Ok(request_kind),
  }
}

pub fn require_upstream_endpoint(
  ctx: &PipelineCtx,
  resolved: &Resolved,
  stage: crate::event::Stage,
) -> Result<Endpoint, PipelineError> {
  resolved_upstream_endpoint(ctx, resolved, stage)?.ok_or_else(|| {
    PipelineError::permanent(
      stage,
      RequestsError::MissingUpstreamEndpoint {
        request_endpoint: SmolStr::new(ctx.request_endpoint.as_str()),
      },
    )
  })
}

/// Output of [`ConvertResponseStage`]: a status/header envelope plus either a
/// fully-buffered body or a live SSE byte stream.
pub struct ConvertedResponse {
  pub status: u16,
  pub headers: HeaderMap,
  pub kind: ConvertedResponseKind,
  pub body: ConvertedBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertedResponseKind {
  Managed,
  Opaque,
}

pub enum ConvertedBody {
  Buffered {
    /// Buffered upstream JSON. `Arc`-wrapped so the matching
    /// [`StageEvent::ConvertResponse`](crate::event::StageEvent::ConvertResponse)
    /// payload can share the value without re-serializing the body.
    body_json: Option<Arc<Value>>,
    body_bytes: Bytes,
  },
  Stream {
    /// SSE byte stream ready to forward to the client. When upstream and
    /// inbound endpoints differ, frames are already endpoint-translated.
    body: futures_util::stream::BoxStream<'static, std::io::Result<Bytes>>,
  },
}

impl std::fmt::Debug for ConvertedBody {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Buffered { body_bytes, body_json } => f
        .debug_struct("ConvertedBody::Buffered")
        .field("body_bytes_len", &body_bytes.len())
        .field("body_json", if body_json.is_some() { &"<present>" } else { &"<none>" })
        .finish(),
      Self::Stream { .. } => f
        .debug_struct("ConvertedBody::Stream")
        .field("body", &"<sse stream>")
        .finish(),
    }
  }
}

impl ConvertedResponse {
  pub fn status(&self) -> u16 {
    self.status
  }

  pub fn headers(&self) -> &HeaderMap {
    &self.headers
  }
}

impl ConvertedBody {
  pub async fn bytes(self) -> std::io::Result<Bytes> {
    match self {
      Self::Buffered { body_bytes, .. } => Ok(body_bytes),
      Self::Stream { body } => body
        .try_fold(bytes::BytesMut::new(), |mut out, chunk| async move {
          out.extend_from_slice(&chunk);
          Ok(out)
        })
        .await
        .map(|buf| buf.freeze()),
    }
  }
}

impl std::fmt::Debug for ConvertedResponse {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut dbg = f.debug_struct("ConvertedResponse");
    dbg
      .field("status", &self.status)
      .field("headers", &self.headers)
      .field("response_kind", &self.kind);
    match &self.body {
      ConvertedBody::Buffered { body_bytes, .. } => {
        dbg
          .field("kind", &"buffered")
          .field("body_bytes_len", &body_bytes.len());
      }
      ConvertedBody::Stream { .. } => {
        dbg.field("kind", &"stream").field("body", &"<sse stream>");
      }
    }
    dbg.finish()
  }
}

#[async_trait]
pub trait ExtractStage: Send + Sync {
  async fn extract(&self, ctx: &PipelineCtx, raw: RawInbound) -> Result<Extracted, PipelineError>;
}

#[async_trait]
pub trait ResolveStage: Send + Sync {
  async fn resolve(&self, ctx: &PipelineCtx, extracted: &Extracted) -> Result<Resolved, PipelineError>;
}

#[async_trait]
pub trait BuildHeadersStage: Send + Sync {
  async fn build_headers(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
  ) -> Result<BuiltHeaders, PipelineError>;
}

#[async_trait]
pub trait ConvertRequestStage: Send + Sync {
  async fn convert_request(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
  ) -> Result<ConvertedRequest, PipelineError>;
}

#[async_trait]
pub trait SendStage: Send + Sync {
  async fn send(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
    headers: &BuiltHeaders,
    body: &ConvertedRequest,
  ) -> Result<SentResponse, PipelineError>;
}

#[async_trait]
pub trait ConvertResponseStage: Send + Sync {
  async fn convert_buffered(
    &self,
    ctx: &PipelineCtx,
    status: u16,
    headers: HeaderMap,
    upstream_endpoint: Option<Endpoint>,
    body: Bytes,
  ) -> Result<ConvertedResponse, PipelineError>;

  /// Convert a streaming upstream response.
  ///
  /// Implementations should attach a parsed-frame tap to the SSE pipeline
  /// and emit `RecordEvent::Usage` for each frame that yields new figures.
  /// The default `convert_response` dispatcher reads this state from its
  /// periodic `StreamProgress` emitter so progress events carry live usage.
  /// running inside that dispatcher.
  async fn convert_stream(
    &self,
    ctx: &PipelineCtx,
    status: u16,
    headers: HeaderMap,
    upstream_endpoint: Option<Endpoint>,
    body: futures_util::stream::BoxStream<'static, std::io::Result<Bytes>>,
  ) -> Result<ConvertedResponse, PipelineError>;

  fn is_sse_response(&self, _ctx: &PipelineCtx, sent: &SentResponse) -> bool {
    sent.stream
  }

  async fn convert_response(&self, ctx: &PipelineCtx, sent: SentResponse) -> Result<ConvertedResponse, PipelineError> {
    let is_sse = self.is_sse_response(ctx, &sent);
    let SentResponse {
      status,
      headers,
      upstream_endpoint,
      response,
      ..
    } = sent;
    if is_sse {
      let accum = AccumHelper::spawn(ctx, SmolStr::default());
      let accum_upstream = accum.clone();
      let body = response
        .bytes_stream()
        .map_err(std::io::Error::other)
        .inspect(move |item| accum_upstream.note_upstream(item))
        .boxed();
      let converted = self
        .convert_stream(ctx, status, headers, upstream_endpoint, body)
        .await?;
      if let ConvertedBody::Stream { body } = converted.body {
        return Ok(ConvertedResponse {
          status: converted.status,
          headers: converted.headers,
          kind: converted.kind,
          body: ConvertedBody::Stream {
            body: stream::unfold((body, accum), |(mut body, accum)| async move {
              match body.next().await {
                Some(item) => {
                  accum.note_converted(&item);
                  Some((item, (body, accum)))
                }
                None => {
                  accum.finish();
                  None
                }
              }
            })
            .boxed(),
          },
        });
      }
      return Ok(converted);
    }
    let raw = response.bytes().await.map_err(|e| {
      PipelineError::recoverable(
        crate::event::Stage::ConvertResponse,
        crate::pipeline::error::RequestsError::ReadingUpstreamBody { source: e },
      )
    })?;
    ctx.emit_record(tokn_core::request_event::RecordEvent::UpstreamBody {
      body: raw.clone(),
      error: None,
    });
    self
      .convert_buffered(ctx, status, headers, upstream_endpoint, raw)
      .await
  }
}

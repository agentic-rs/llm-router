//! Closed set of pipeline-observation events emitted by `tokn-requests`'s
//! `PipelineRunner`.
//!
//! These types live in `tokn-core` (rather than `tokn-requests`) so that the
//! workspace's `tokn_core::event::Event` enum can embed a `Requests(StageEvent)`
//! variant without inverting the dep graph (requests depends on tokn-core).
//!
//! `StageEvent` carries **lossy summaries** of each stage's output rather than
//! the full stage-output structs. The full structs in `tokn-requests` embed
//! types (`AccountHandle`, internal codec enums, etc.) that should not leak
//! into tokn-core's public surface. Summaries are cheap to clone and carry the
//! fields subscribers actually need (status, body bytes, headers, model id,
//! endpoint, request_id, etc.).
//!
//! Each `*Summary` struct corresponds 1:1 with a requests stage output
//! (`Extracted`, `Resolved`, `BuiltHeaders`, `ConvertedRequest`,
//! `SentResponse`, `ConvertedResponse`); requests provides `From` impls.

use crate::provider::Endpoint;
use crate::AgentId;
use bytes::Bytes;
use serde::Serialize;
use serde_json::Value;
use smol_str::SmolStr;
use std::sync::Arc;
use tokn_headers::{HeaderMap, TemplateVars};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum RequestEndpoint {
  Known(Endpoint),
  CustomPath(SmolStr),
}

impl RequestEndpoint {
  pub fn as_str(&self) -> &str {
    match self {
      RequestEndpoint::Known(endpoint) => endpoint.as_str(),
      RequestEndpoint::CustomPath(label) => label.as_str(),
    }
  }

  pub fn custom(label: impl Into<SmolStr>) -> Self {
    Self::CustomPath(label.into())
  }

  pub fn infer_from_path(path: impl AsRef<str>) -> Self {
    let path = path.as_ref();
    if let Some(endpoint) = infer_endpoint_from_path(path) {
      Self::Known(endpoint)
    } else {
      Self::CustomPath(SmolStr::new(path))
    }
  }

  pub fn resolved(&self) -> Option<Endpoint> {
    match self {
      RequestEndpoint::Known(endpoint) => Some(*endpoint),
      RequestEndpoint::CustomPath(_) => None,
    }
  }
}

/// Best-effort endpoint inference for pipeline observation only.
///
/// This intentionally preserves the legacy suffix behavior: the input is not
/// parsed as a URI and query strings are not stripped.
fn infer_endpoint_from_path(path: &str) -> Option<Endpoint> {
  if path.ends_with("/chat/completions") {
    Some(Endpoint::ChatCompletions)
  } else if path.ends_with("/responses") {
    Some(Endpoint::Responses)
  } else if path.ends_with("/messages") {
    Some(Endpoint::Messages)
  } else {
    None
  }
}

impl From<Endpoint> for RequestEndpoint {
  fn from(value: Endpoint) -> Self {
    Self::Known(value)
  }
}

impl PartialEq<Endpoint> for RequestEndpoint {
  fn eq(&self, other: &Endpoint) -> bool {
    match self {
      RequestEndpoint::Known(endpoint) => endpoint == other,
      RequestEndpoint::CustomPath(_) => false,
    }
  }
}

impl std::fmt::Display for RequestEndpoint {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Identifies which pipeline stage produced an event. Used both as a tag on
/// success variants (implicit via the variant name) and as a field on
/// [`StageEvent::Error`] so subscribers can filter without pattern-matching
/// on N error variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
  Extract,
  Resolve,
  BuildHeaders,
  ConvertRequest,
  Send,
  ConvertResponse,
}

impl Stage {
  pub fn as_str(self) -> &'static str {
    match self {
      Stage::Extract => "extract",
      Stage::Resolve => "resolve",
      Stage::BuildHeaders => "build_headers",
      Stage::ConvertRequest => "convert_request",
      Stage::Send => "send",
      Stage::ConvertResponse => "convert_response",
    }
  }
}

impl std::fmt::Display for Stage {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Cloneable summary of `tokn_requests::pipeline::stages::Extracted`. Drops
/// the requests-internal `content_encoding` enum (kept inside requests only).
#[derive(Debug, Clone)]
pub struct ExtractedSummary {
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
}

/// Cloneable summary of `tokn_requests::pipeline::stages::Resolved`. Drops
/// the typed `AccountHandle` (which would require tokn-core to depend on
/// tokn-accounts).
#[derive(Debug, Clone)]
pub struct ResolvedSummary {
  pub agent_id: Option<AgentId>,
  pub model: SmolStr,
  pub resolved_endpoint: Option<Endpoint>,
  pub upstream_model: SmolStr,
  pub upstream_endpoint: Option<Endpoint>,
  pub account_id: SmolStr,
  pub provider_id: SmolStr,
}

/// Cloneable summary of `tokn_requests::pipeline::stages::BuiltHeaders`.
#[derive(Debug, Clone, Default)]
pub struct BuiltHeadersSummary {
  pub headers: HeaderMap,
  pub vars: TemplateVars,
  pub agent_id: AgentId,
}

/// Cloneable summary of `tokn_requests::pipeline::stages::ConvertedRequest`.
/// `content_encoding` is the wire token (e.g. `"gzip"`/`"zstd"`); the
/// requests-internal codec enum is intentionally not exposed here to keep
/// tokn-core free of requests's `utils::codec` types.
#[derive(Debug, Clone)]
pub struct ConvertedRequestSummary {
  pub upstream_body: Arc<Value>,
  pub upstream_wire_body: Bytes,
  pub debug_outbound_body: Bytes,
  pub content_encoding: Option<SmolStr>,
}

/// Cloneable summary of `tokn_requests::pipeline::stages::SentResponse`.
/// The full struct can't be cloned (it owns a single-shot `reqwest::Response`),
/// so the `Send` event carries this summary instead.
#[derive(Debug, Clone)]
pub struct SentSummary {
  pub status: u16,
  pub headers: HeaderMap,
  pub upstream_endpoint: Option<Endpoint>,
  /// Mirrors the inbound `stream` flag — true iff the client asked for SSE.
  pub stream: bool,
}

/// Cloneable summary of `tokn_requests::pipeline::stages::ConvertedResponse`.
/// `Buffered` shares the response's `Arc<Value>` body; `Stream` leaves
/// `body` as `None` because the live SSE byte stream is single-shot.
#[derive(Debug, Clone)]
pub struct ConvertedResponseSummary {
  pub status: u16,
  pub headers: HeaderMap,
  /// `Some` for buffered responses; `None` for streaming responses.
  pub body: Option<Arc<Value>>,
}

#[derive(Debug, Clone)]
pub enum StageEvent {
  /// Emitted once at the very start of requests's `PipelineRunner::run`,
  /// before any stage has produced output.
  Started { request_endpoint: RequestEndpoint },
  /// Extract stage completed successfully.
  Extract(ExtractedSummary),
  /// Resolve stage completed successfully.
  Resolve(ResolvedSummary),
  /// BuildHeaders stage completed successfully.
  BuildHeaders(BuiltHeadersSummary),
  /// ConvertRequest stage completed successfully.
  ConvertRequest(ConvertedRequestSummary),
  /// Send stage completed successfully.
  Send(SentSummary),
  /// ConvertResponse stage completed successfully. Buffered bodies are
  /// shared via `Arc<Value>`; streaming bodies are not included on the
  /// event (the live byte stream is single-shot).
  ConvertResponse(ConvertedResponseSummary),
  /// Any stage failure (or deliberate stop). `recoverable` and `stop` are
  /// propagated verbatim from the requests `PipelineError`. Subscribers that
  /// need partial state fold prior per-stage events themselves.
  Error {
    stage: Stage,
    message: SmolStr,
    recoverable: bool,
    stop: bool,
  },
  /// Emitted once at the end of requests's `PipelineRunner::run`. `success`
  /// is `true` only when the pipeline produced a `ConvertedResponse`; both
  /// real failures and deliberate stops set it to `false`.
  Completed { success: bool, attempts: u32 },
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn request_endpoint_infers_every_known_path_suffix() {
    for (path, endpoint) in [
      ("/v1/chat/completions", Endpoint::ChatCompletions),
      ("/v1/responses", Endpoint::Responses),
      ("/v1/messages", Endpoint::Messages),
    ] {
      assert_eq!(RequestEndpoint::infer_from_path(path), endpoint);
    }
  }

  #[test]
  fn request_endpoint_preserves_custom_and_query_paths_exactly() {
    assert_eq!(
      RequestEndpoint::infer_from_path("/custom?next=/responses"),
      Endpoint::Responses
    );

    for path in ["/v1/models", "/v1/responses?stream=true"] {
      let inferred = RequestEndpoint::infer_from_path(path);

      assert_eq!(inferred, RequestEndpoint::CustomPath(SmolStr::new(path)));
      assert_eq!(inferred.as_str(), path);
      assert_eq!(inferred.resolved(), None);
    }
  }
}

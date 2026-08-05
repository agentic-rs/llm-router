//! Request-side records captured alongside pipeline execution.
//!
//! Distinct from the upstream-shaped *intent* values carried on stage
//! summaries (`ConvertedRequestSummary`, `SentSummary`):
//!
//! - intent values describe what requests *prepared*;
//! - records describe transport-adjacent facts the pipeline itself does
//!   not retain: inbound connection metadata, outbound wire-truth after
//!   `Provider::patch_headers` auth injection / `Host`+`Content-Length`
//!   stripping in [`crate::util::http::send`], and parsed usage.
//!
//! Persistence uses records to populate connection, usage, outbound,
//! and fully-converted response body columns; intent values still flow through the per-stage
//! stage events for diagnostics (and for dry-run profiles whose Send stage is a
//! no-op).
//!
//! Records ride a dedicated [`RequestEventPayload::Record`] variant
//! (peer of `Stage` and `Custom`) rather than nesting inside
//! `StageEvent`, so subscribers that only care about lifecycle/error
//! observation don't pay a match-arm tax for wire-truth captures, and
//! vice versa.
//!
//! [`RequestEventPayload::Record`]: super::RequestEventPayload::Record

use crate::db::Usage;
use bytes::Bytes;
use serde::Serialize;
use smol_str::SmolStr;
use tokn_headers::HeaderMap;

/// Wire-truth capture from the actual outbound HTTP call (via
/// [`OutboundCapture`](crate::provider::OutboundCapture)).
///
/// The four variants split a single capture so subscribers can write
/// each piece as soon as it's known: request side before the response
/// arrives, response status+headers as soon as they come back, body
/// once it's been drained/accumulated, and converted body once the client-facing
/// payload is fully materialized.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum RecordEvent {
  /// Inbound client->router connection facts captured by the transport
  /// before the pipeline starts. Emitted outside the runner so callers can
  /// supply whatever connection context they have without widening
  /// [`RawInbound`](tokn_requests::RawInbound).
  InboundConnection {
    /// Authenticated client label. This is the API-key name for managed
    /// requests and is absent when client authentication is bypassed.
    user: Option<SmolStr>,
    /// Stable identifier of the client API key used for authentication.
    api_key_id: Option<SmolStr>,
    local_addr: Option<SmolStr>,
    peer_addr: Option<SmolStr>,
    mode: SmolStr,
    method: SmolStr,
    inbound_method: SmolStr,
    url: Option<SmolStr>,
  },
  /// Outbound request as it left reqwest. Headers reflect post-strip,
  /// post-patch state; `body` is the exact bytes handed to reqwest.
  UpstreamReq {
    method: SmolStr,
    url: SmolStr,
    headers: HeaderMap,
    body: Bytes,
  },
  /// Upstream response status + headers, captured as soon as they
  /// arrive. Headers reflect reqwest's post-decompression view (the
  /// `Content-Encoding` and `Content-Length` headers are stripped when
  /// reqwest decompresses).
  UpstreamResp { status: u16, headers: HeaderMap },
  /// Materialized upstream response body. Emitted only for buffered
  /// responses or after streaming accumulation finishes. Streaming paths may
  /// carry a partial body plus the stream termination error.
  UpstreamBody { body: Bytes, error: Option<SmolStr> },
  /// Materialized client-facing response body after any endpoint translation.
  /// For buffered responses the `StageEvent::ConvertResponse` summary already
  /// carries the JSON body, so this record is emitted only for streaming paths.
  ConvertedBody { body: Bytes, error: Option<SmolStr> },
  /// Parsed token usage attributed to the request. Added now so callers and
  /// persistence can converge on a stable shape before every execution path
  /// emits it.
  Usage(Usage),
}

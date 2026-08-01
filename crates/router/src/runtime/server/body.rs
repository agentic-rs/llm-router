//! Request-body admission for the v2 serving path.
//!
//! Listener matching has already pinned a profile and route before this
//! boundary runs. Opaque route families therefore collect only bounded wire
//! bytes, while managed routes decode and validate their structured payload
//! without allowing payload facts to change the matched route.

use super::super::{LinkedRouteKind, ManagedRequestBody, ManagedRequestBodyError, MatchedHttpRoute};
use crate::runtime::observation::{body_header_facts, merge_body_json_facts};
use axum::body::Body;
use bytes::{Bytes, BytesMut};
use flate2::read::MultiGzDecoder;
use futures_util::StreamExt;
use http::header::CONTENT_ENCODING;
use http::HeaderMap;
use serde_json::Value;
use smol_str::SmolStr;
use snafu::Snafu;
use std::fmt;
use std::io::{self, Read};
use tokn_core::provider::ProviderRequestKind;
use tokn_events::{BodyCapture, BodyOutcome, CaptureOmission, EventFailure, RequestBodyObservation};

const MAX_CONTENT_ENCODING_LAYERS: usize = 4;
// The reference zstd encoder may declare a multi-megabyte window even for a
// small payload. Keep a bounded compatibility floor while independently
// enforcing the exact decoded-output limit below.
const MIN_ZSTD_WINDOW_LOG: u32 = 23;
const MAX_ZSTD_WINDOW_LOG: u32 = 27;
const READ_BUFFER_BYTES: usize = 8 * 1024;

/// Independent limits for bytes received from the client and bytes produced
/// by managed content decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBodyLimits {
  max_wire_bytes: usize,
  max_decoded_bytes: usize,
}

impl RequestBodyLimits {
  pub const fn new(max_wire_bytes: usize, max_decoded_bytes: usize) -> Self {
    Self {
      max_wire_bytes,
      max_decoded_bytes,
    }
  }

  pub const fn max_wire_bytes(self) -> usize {
    self.max_wire_bytes
  }

  pub const fn max_decoded_bytes(self) -> usize {
    self.max_decoded_bytes
  }
}

/// A request body admitted according to its already-matched route family.
#[derive(Clone)]
pub enum BufferedRequestBody {
  /// Relay and transparent routes preserve the client's exact data bytes.
  /// `None` means the request had no body framing; `Some(Bytes::new())` means
  /// a body was present but contained zero data bytes.
  Opaque { wire_body: Option<Bytes> },
  /// Managed routes retain only validated request semantics. Execution owns
  /// identity-encoded JSON serialization and never needs the compressed wire
  /// representation or an encoding stack.
  Managed(ManagedRequestBody),
}

impl BufferedRequestBody {
  pub fn opaque_wire_body(&self) -> Option<Option<&Bytes>> {
    match self {
      Self::Opaque { wire_body } => Some(wire_body.as_ref()),
      Self::Managed(_) => None,
    }
  }

  pub fn managed(&self) -> Option<&ManagedRequestBody> {
    match self {
      Self::Managed(body) => Some(body),
      Self::Opaque { .. } => None,
    }
  }
}

impl fmt::Debug for BufferedRequestBody {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Opaque { wire_body } => formatter
        .debug_struct("OpaqueRequestBody")
        .field("body_present", &wire_body.is_some())
        .field("wire_bytes", &wire_body.as_ref().map(Bytes::len))
        .finish(),
      Self::Managed(body) => formatter.debug_tuple("ManagedRequestBody").field(body).finish(),
    }
  }
}

/// The public observation and executable result of request-body admission.
///
/// Keeping the observation outside the `Result` ensures that callers can
/// publish the same complete boundary for accepted and rejected requests.
/// In particular, an error never discards transport bytes already received.
#[must_use = "request-body observations must be published or deliberately handled"]
pub struct RequestBodyAdmission {
  observation: RequestBodyObservation,
  body: RequestBodyResult<BufferedRequestBody>,
}

impl RequestBodyAdmission {
  fn accepted(observation: RequestBodyObservation, body: BufferedRequestBody) -> Self {
    Self {
      observation,
      body: Ok(body),
    }
  }

  fn rejected(
    wire: BodyCapture,
    decoded: Option<BodyCapture>,
    facts: RequestBodyFacts,
    error: RequestBodyError,
  ) -> Self {
    let outcome = BodyOutcome::Rejected(error.event_failure());
    Self {
      observation: facts.observation(wire, decoded, outcome),
      body: Err(error),
    }
  }

  /// The wire, semantic, and terminal facts observed at this boundary.
  pub const fn observation(&self) -> &RequestBodyObservation {
    &self.observation
  }

  /// Borrow the admitted body or its original routing error.
  pub fn body(&self) -> Result<&BufferedRequestBody, &RequestBodyError> {
    self.body.as_ref()
  }

  /// Split the event observation from the executable admission result.
  pub fn into_parts(self) -> (RequestBodyObservation, RequestBodyResult<BufferedRequestBody>) {
    (self.observation, self.body)
  }

  /// Discard the observation and retain the historical body result.
  ///
  /// Lifecycle-aware callers should prefer [`Self::into_parts`]. This helper
  /// lets callers adopt the richer boundary without changing wire behavior.
  pub fn into_body_result(self) -> RequestBodyResult<BufferedRequestBody> {
    self.body
  }
}

impl fmt::Debug for RequestBodyAdmission {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut debug = formatter.debug_struct("RequestBodyAdmission");
    debug
      .field("wire", &self.observation.wire)
      .field("decoded", &self.observation.decoded)
      .field("requested_model_present", &self.observation.requested_model.is_some())
      .field("stream", &self.observation.stream)
      .field("initiator_present", &self.observation.initiator.is_some())
      .field("outcome", &self.observation.outcome);
    match &self.body {
      Ok(body) => debug.field("body", body),
      Err(error) => debug.field("body_error", &error.event_failure()),
    };
    debug.finish()
  }
}

#[derive(Clone, Debug, Default)]
struct RequestBodyFacts {
  requested_model: Option<SmolStr>,
  stream: Option<bool>,
  initiator: Option<SmolStr>,
}

impl RequestBodyFacts {
  fn from_headers(headers: &HeaderMap) -> Self {
    let (stream, initiator) = body_header_facts(headers);
    Self {
      requested_model: None,
      stream,
      initiator,
    }
  }

  fn observe_json(mut self, value: &Value) -> Self {
    let (requested_model, stream, initiator) = merge_body_json_facts(self.stream, self.initiator.take(), value);
    self.requested_model = requested_model;
    self.stream = stream;
    self.initiator = initiator;
    self
  }

  fn observation(
    self,
    wire: BodyCapture,
    decoded: Option<BodyCapture>,
    outcome: BodyOutcome,
  ) -> RequestBodyObservation {
    RequestBodyObservation {
      wire,
      decoded,
      requested_model: self.requested_model,
      stream: self.stream,
      initiator: self.initiator,
      outcome,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentEncoding {
  Identity,
  Gzip,
  Zstd,
}

/// Buffer and validate one request body after listener matching but before
/// account/upstream resolution.
///
/// `body_present` is a framing fact retained by the HTTP server before it
/// consumes the body. It deliberately distinguishes no representation from a
/// present, zero-length representation for opaque forwarding.
pub async fn buffer_matched_body(
  matched: &MatchedHttpRoute,
  headers: &HeaderMap,
  body: Body,
  body_present: bool,
  limits: RequestBodyLimits,
) -> RequestBodyAdmission {
  let facts = RequestBodyFacts::from_headers(headers);
  match matched.route().kind() {
    LinkedRouteKind::Relay(_) | LinkedRouteKind::Transparent(_) => {
      if !body_present {
        return RequestBodyAdmission::accepted(
          facts.observation(BodyCapture::Absent, None, BodyOutcome::Accepted),
          BufferedRequestBody::Opaque { wire_body: None },
        );
      }
      let CollectedBody { capture, result } = collect_wire_body(body, limits.max_wire_bytes()).await;
      match result {
        Ok(wire_body) => {
          let inspection = match parse_content_encodings(headers) {
            Ok(encodings) => {
              let fallback_facts = facts.clone();
              let inspection_body = wire_body.clone();
              match tokio::task::spawn_blocking(move || {
                inspect_opaque_body(inspection_body, encodings, limits.max_decoded_bytes(), facts)
              })
              .await
              {
                Ok(inspection) => inspection,
                Err(_) => OpaqueBodyInspection::unavailable(fallback_facts),
              }
            }
            Err(_) => OpaqueBodyInspection::unavailable(facts),
          };
          RequestBodyAdmission::accepted(
            inspection
              .facts
              .observation(capture, Some(inspection.decoded), BodyOutcome::Accepted),
            BufferedRequestBody::Opaque {
              wire_body: Some(wire_body),
            },
          )
        }
        Err(error) => RequestBodyAdmission::rejected(capture, None, facts, error),
      }
    }
    LinkedRouteKind::Managed(_) => {
      if !matches!(matched.request_kind(), ProviderRequestKind::Operation(_)) {
        return RequestBodyAdmission::rejected(
          unpolled_wire_capture(body_present),
          None,
          facts,
          RequestBodyError::ManagedOperationRequired {
            request_kind: matched.request_kind(),
          },
        );
      }
      if !body_present {
        return RequestBodyAdmission::rejected(BodyCapture::Absent, None, facts, RequestBodyError::ManagedBodyRequired);
      }

      // Encoding metadata is a managed semantic. Parse it before polling the
      // body so malformed metadata cannot consume request data or affect an
      // opaque route family.
      let encodings = match parse_content_encodings(headers) {
        Ok(encodings) => encodings,
        Err(error) => {
          return RequestBodyAdmission::rejected(unpolled_wire_capture(true), None, facts, error);
        }
      };
      let CollectedBody {
        capture: wire_capture,
        result: wire_result,
      } = collect_wire_body(body, limits.max_wire_bytes()).await;
      let wire_body = match wire_result {
        Ok(wire_body) => wire_body,
        Err(error) => return RequestBodyAdmission::rejected(wire_capture, None, facts, error),
      };
      let decoded_limit = limits.max_decoded_bytes();
      let processing = match tokio::task::spawn_blocking(move || {
        decode_and_validate(wire_body, encodings, decoded_limit, facts)
      })
      .await
      {
        Ok(processing) => processing,
        Err(source) => {
          return RequestBodyAdmission::rejected(
            wire_capture,
            None,
            RequestBodyFacts::from_headers(headers),
            RequestBodyError::ManagedProcessingUnavailable { source },
          );
        }
      };
      match processing.result {
        Ok(buffered) => RequestBodyAdmission::accepted(
          processing
            .facts
            .observation(wire_capture, processing.decoded, BodyOutcome::Accepted),
          buffered,
        ),
        Err(error) => RequestBodyAdmission::rejected(wire_capture, processing.decoded, processing.facts, error),
      }
    }
  }
}

struct CollectedBody<E> {
  capture: BodyCapture,
  result: Result<Bytes, E>,
}

async fn collect_wire_body(body: Body, limit: usize) -> CollectedBody<RequestBodyError> {
  let mut stream = body.into_data_stream();
  let mut output = BytesMut::new();
  while let Some(chunk) = stream.next().await {
    let chunk = match chunk {
      Ok(chunk) => chunk,
      Err(source) => {
        let prefix = output.freeze();
        return CollectedBody {
          capture: incomplete_capture(prefix.clone(), prefix.len()),
          result: Err(RequestBodyError::BodyRead { source }),
        };
      }
    };
    if chunk.len() > limit.saturating_sub(output.len()) {
      let bytes_seen = output.len().saturating_add(chunk.len());
      let retained = limit.saturating_sub(output.len()).min(chunk.len());
      output.extend_from_slice(&chunk[..retained]);
      return CollectedBody {
        capture: incomplete_capture(output.freeze(), bytes_seen),
        result: Err(RequestBodyError::WireBodyTooLarge { limit }),
      };
    }
    output.extend_from_slice(&chunk);
  }
  let body = output.freeze();
  CollectedBody {
    capture: BodyCapture::Complete(body.clone()),
    result: Ok(body),
  }
}

fn parse_content_encodings(headers: &HeaderMap) -> RequestBodyResult<Vec<ContentEncoding>> {
  let mut encodings = Vec::new();
  for (field_index, value) in headers.get_all(CONTENT_ENCODING).iter().enumerate() {
    let value = value
      .to_str()
      .map_err(|_| RequestBodyError::InvalidContentEncodingHeader { field_index })?;
    for (member_index, member) in value.split(',').map(str::trim).enumerate() {
      if member.is_empty() {
        return Err(RequestBodyError::EmptyContentEncodingMember {
          field_index,
          member_index,
        });
      }
      let encoding = if member.eq_ignore_ascii_case("identity") {
        ContentEncoding::Identity
      } else if member.eq_ignore_ascii_case("gzip") {
        ContentEncoding::Gzip
      } else if member.eq_ignore_ascii_case("zstd") {
        ContentEncoding::Zstd
      } else {
        return Err(RequestBodyError::UnsupportedContentEncoding {
          encoding: member.to_owned(),
        });
      };
      encodings.push(encoding);
      if encodings.len() > MAX_CONTENT_ENCODING_LAYERS {
        return Err(RequestBodyError::TooManyContentEncodings {
          limit: MAX_CONTENT_ENCODING_LAYERS,
          actual: encodings.len(),
        });
      }
    }
  }
  Ok(encodings)
}

fn unpolled_wire_capture(body_present: bool) -> BodyCapture {
  if body_present {
    BodyCapture::Omitted {
      reason: CaptureOmission::Unavailable,
      bytes_seen: 0,
    }
  } else {
    BodyCapture::Absent
  }
}

fn incomplete_capture(prefix: Bytes, bytes_seen: usize) -> BodyCapture {
  BodyCapture::Truncated {
    prefix,
    bytes_seen: u64::try_from(bytes_seen).unwrap_or(u64::MAX),
  }
}

fn unavailable_decoded_capture() -> BodyCapture {
  BodyCapture::Omitted {
    reason: CaptureOmission::Unavailable,
    bytes_seen: 0,
  }
}

struct OpaqueBodyInspection {
  decoded: BodyCapture,
  facts: RequestBodyFacts,
}

impl OpaqueBodyInspection {
  fn unavailable(facts: RequestBodyFacts) -> Self {
    Self {
      decoded: unavailable_decoded_capture(),
      facts,
    }
  }
}

fn inspect_opaque_body(
  wire_body: Bytes,
  content_encodings: Vec<ContentEncoding>,
  decoded_limit: usize,
  facts: RequestBodyFacts,
) -> OpaqueBodyInspection {
  let decoded = decode_content(wire_body, &content_encodings, decoded_limit);
  let facts = match &decoded.result {
    Ok(body) => match serde_json::from_slice(body) {
      Ok(value) => facts.observe_json(&value),
      Err(_) => facts,
    },
    Err(_) => facts,
  };
  OpaqueBodyInspection {
    decoded: decoded.capture,
    facts,
  }
}

struct ManagedBodyProcessing {
  decoded: Option<BodyCapture>,
  facts: RequestBodyFacts,
  result: RequestBodyResult<BufferedRequestBody>,
}

impl ManagedBodyProcessing {
  fn rejected(decoded: BodyCapture, facts: RequestBodyFacts, error: RequestBodyError) -> Self {
    Self {
      decoded: Some(decoded),
      facts,
      result: Err(error),
    }
  }
}

fn decode_and_validate(
  wire_body: Bytes,
  content_encodings: Vec<ContentEncoding>,
  decoded_limit: usize,
  facts: RequestBodyFacts,
) -> ManagedBodyProcessing {
  let decoded = decode_content(wire_body, &content_encodings, decoded_limit);
  let decoded_body = match decoded.result {
    Ok(body) => body,
    Err(error) => return ManagedBodyProcessing::rejected(decoded.capture, facts, error),
  };

  let decoded_capture = BodyCapture::Complete(decoded_body.clone());
  let value: Value = match serde_json::from_slice(&decoded_body) {
    Ok(value) => value,
    Err(source) => {
      return ManagedBodyProcessing::rejected(decoded_capture, facts, RequestBodyError::InvalidManagedJson { source });
    }
  };
  let facts = facts.observe_json(&value);
  let body = match ManagedRequestBody::try_from(value) {
    Ok(body) => body,
    Err(source) => {
      return ManagedBodyProcessing::rejected(decoded_capture, facts, RequestBodyError::InvalidManagedBody { source });
    }
  };

  ManagedBodyProcessing {
    decoded: Some(decoded_capture),
    facts,
    result: Ok(BufferedRequestBody::Managed(body)),
  }
}

fn decode_content(
  mut body: Bytes,
  content_encodings: &[ContentEncoding],
  decoded_limit: usize,
) -> CollectedBody<RequestBodyError> {
  if content_encodings.is_empty() {
    return retain_with_limit(body, decoded_limit);
  }

  for (layer_index, encoding) in content_encodings.iter().rev().copied().enumerate() {
    let decoded = match encoding {
      ContentEncoding::Identity => retain_with_limit(body, decoded_limit),
      ContentEncoding::Gzip => decode_gzip(body, decoded_limit),
      ContentEncoding::Zstd => decode_zstd(body, decoded_limit),
    };
    body = match decoded.result {
      Ok(body) => body,
      Err(error) => {
        let final_capture = if layer_index + 1 == content_encodings.len() {
          decoded.capture
        } else {
          unavailable_decoded_capture()
        };
        return CollectedBody {
          capture: final_capture,
          result: Err(error),
        };
      }
    };
  }

  CollectedBody {
    capture: BodyCapture::Complete(body.clone()),
    result: Ok(body),
  }
}

fn retain_with_limit(body: Bytes, limit: usize) -> CollectedBody<RequestBodyError> {
  if body.len() <= limit {
    return CollectedBody {
      capture: BodyCapture::Complete(body.clone()),
      result: Ok(body),
    };
  }
  CollectedBody {
    capture: incomplete_capture(body.slice(..limit), body.len()),
    result: Err(RequestBodyError::DecodedBodyTooLarge { limit }),
  }
}

fn decode_gzip(body: Bytes, limit: usize) -> CollectedBody<RequestBodyError> {
  let decoder = MultiGzDecoder::new(body.as_ref());
  map_decode_result(read_decoded(decoder, limit), limit, |source| {
    RequestBodyError::GzipDecode { source }
  })
}

fn decode_zstd(body: Bytes, limit: usize) -> CollectedBody<RequestBodyError> {
  let mut decoder = match zstd::stream::read::Decoder::new(body.as_ref()) {
    Ok(decoder) => decoder,
    Err(source) => return failed_decode(RequestBodyError::ZstdDecode { source }),
  };
  if let Err(source) = decoder.window_log_max(zstd_window_log(limit)) {
    return failed_decode(RequestBodyError::ZstdDecode { source });
  }
  map_decode_result(read_decoded(decoder, limit), limit, |source| {
    RequestBodyError::ZstdDecode { source }
  })
}

fn failed_decode(error: RequestBodyError) -> CollectedBody<RequestBodyError> {
  CollectedBody {
    capture: incomplete_capture(Bytes::new(), 0),
    result: Err(error),
  }
}

fn map_decode_result(
  decoded: CollectedBody<DecodeReadError>,
  limit: usize,
  io_error: impl FnOnce(io::Error) -> RequestBodyError,
) -> CollectedBody<RequestBodyError> {
  CollectedBody {
    capture: decoded.capture,
    result: decoded.result.map_err(|error| match error {
      DecodeReadError::Io(source) => io_error(source),
      DecodeReadError::TooLarge => RequestBodyError::DecodedBodyTooLarge { limit },
    }),
  }
}

fn zstd_window_log(limit: usize) -> u32 {
  let bytes = limit.max(1 << MIN_ZSTD_WINDOW_LOG);
  let ceiling_log = usize::BITS - bytes.saturating_sub(1).leading_zeros();
  ceiling_log.clamp(MIN_ZSTD_WINDOW_LOG, MAX_ZSTD_WINDOW_LOG)
}

fn read_decoded(mut reader: impl Read, limit: usize) -> CollectedBody<DecodeReadError> {
  let mut output = Vec::with_capacity(limit.min(READ_BUFFER_BYTES));
  let mut buffer = [0_u8; READ_BUFFER_BYTES];
  loop {
    let remaining = limit.saturating_sub(output.len());
    let read_length = buffer.len().min(remaining.saturating_add(1));
    let read = match reader.read(&mut buffer[..read_length]) {
      Ok(read) => read,
      Err(source) => {
        let prefix = Bytes::from(output);
        return CollectedBody {
          capture: incomplete_capture(prefix.clone(), prefix.len()),
          result: Err(DecodeReadError::Io(source)),
        };
      }
    };
    if read == 0 {
      let body = Bytes::from(output);
      return CollectedBody {
        capture: BodyCapture::Complete(body.clone()),
        result: Ok(body),
      };
    }
    if read > remaining {
      output.extend_from_slice(&buffer[..remaining]);
      return CollectedBody {
        capture: incomplete_capture(Bytes::from(output), limit.saturating_add(read - remaining)),
        result: Err(DecodeReadError::TooLarge),
      };
    }
    output.extend_from_slice(&buffer[..read]);
  }
}

enum DecodeReadError {
  Io(io::Error),
  TooLarge,
}

/// A request body rejected before target selection or upstream execution.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum RequestBodyError {
  #[snafu(display("managed route requires an LLM operation request, got {request_kind:?}"))]
  ManagedOperationRequired { request_kind: ProviderRequestKind },

  #[snafu(display("managed route requires a request body"))]
  ManagedBodyRequired,

  #[snafu(display("request body exceeds the {limit}-byte wire limit"))]
  WireBodyTooLarge { limit: usize },

  #[snafu(display("could not read request body: {source}"))]
  BodyRead { source: axum::Error },

  #[snafu(display("content-encoding field {} is not valid text", field_index + 1))]
  InvalidContentEncodingHeader { field_index: usize },

  #[snafu(display(
    "content-encoding field {} contains an empty list member at position {}",
    field_index + 1,
    member_index + 1
  ))]
  EmptyContentEncodingMember { field_index: usize, member_index: usize },

  #[snafu(display("unsupported content-encoding '{encoding}'"))]
  UnsupportedContentEncoding { encoding: String },

  #[snafu(display("request declares {actual} content-encoding layers; at most {limit} are allowed"))]
  TooManyContentEncodings { limit: usize, actual: usize },

  #[snafu(display("decoded request body exceeds the {limit}-byte limit"))]
  DecodedBodyTooLarge { limit: usize },

  #[snafu(display("could not decode gzip request body: {source}"))]
  GzipDecode { source: io::Error },

  #[snafu(display("could not decode zstd request body: {source}"))]
  ZstdDecode { source: io::Error },

  #[snafu(display("managed request body processing task was unavailable: {source}"))]
  ManagedProcessingUnavailable { source: tokio::task::JoinError },

  #[snafu(display("managed request body is not valid JSON: {source}"))]
  InvalidManagedJson { source: serde_json::Error },

  #[snafu(display("{source}"))]
  InvalidManagedBody { source: ManagedRequestBodyError },
}

impl RequestBodyError {
  /// A stable, disclosure-safe public description of this admission failure.
  ///
  /// Source errors remain available to internal diagnostics through this
  /// error value, but their display strings are deliberately excluded from
  /// the event contract.
  pub fn event_failure(&self) -> EventFailure {
    let (code, message) = match self {
      Self::ManagedOperationRequired { .. } => (
        "managed_operation_required",
        "managed request-body admission requires an LLM operation",
      ),
      Self::ManagedBodyRequired => ("managed_body_required", "a managed request body is required"),
      Self::WireBodyTooLarge { .. } => (
        "wire_body_too_large",
        "the request body exceeds the configured wire-size limit",
      ),
      Self::BodyRead { .. } => ("body_read_failed", "the request body could not be read"),
      Self::InvalidContentEncodingHeader { .. } => (
        "invalid_content_encoding_header",
        "a request content-encoding header is not valid text",
      ),
      Self::EmptyContentEncodingMember { .. } => (
        "empty_content_encoding_member",
        "a request content-encoding list contains an empty member",
      ),
      Self::UnsupportedContentEncoding { .. } => (
        "unsupported_content_encoding",
        "the request content encoding is not supported",
      ),
      Self::TooManyContentEncodings { .. } => (
        "too_many_content_encodings",
        "the request declares too many content-encoding layers",
      ),
      Self::DecodedBodyTooLarge { .. } => (
        "decoded_body_too_large",
        "the decoded request body exceeds the configured size limit",
      ),
      Self::GzipDecode { .. } => ("gzip_decode_failed", "the gzip request body could not be decoded"),
      Self::ZstdDecode { .. } => ("zstd_decode_failed", "the zstd request body could not be decoded"),
      Self::ManagedProcessingUnavailable { .. } => (
        "managed_processing_unavailable",
        "managed request-body processing is unavailable",
      ),
      Self::InvalidManagedJson { .. } => ("invalid_json", "the managed request body is not valid JSON"),
      Self::InvalidManagedBody {
        source: ManagedRequestBodyError::ObjectRequired,
      } => (
        "managed_body_object_required",
        "the managed request body must be a JSON object",
      ),
      Self::InvalidManagedBody {
        source: ManagedRequestBodyError::ModelStringRequired,
      } => (
        "managed_model_string_required",
        "the managed request model must be a string",
      ),
      Self::InvalidManagedBody {
        source: ManagedRequestBodyError::ModelEmpty,
      } => ("managed_model_empty", "the managed request model must not be empty"),
      Self::InvalidManagedBody {
        source: ManagedRequestBodyError::ModelSurroundingWhitespace,
      } => (
        "managed_model_noncanonical",
        "the managed request model must not have surrounding whitespace",
      ),
    };
    EventFailure {
      code: SmolStr::new_static(code),
      message: SmolStr::new_static(message),
    }
  }
}

pub type RequestBodyResult<T> = std::result::Result<T, RequestBodyError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{
    link_gateway_runtime, match_http, HttpRequestHead, HttpRouteMatch, MatchedHttpRoute, RuntimeNameRegistry,
  };
  use flate2::write::GzEncoder;
  use flate2::Compression;
  use http::header::ACCEPT;
  use http::{HeaderValue, Method};
  use hyper::body::{Body as HttpBody, Frame};
  use smol_str::SmolStr;
  use std::collections::{BTreeMap, BTreeSet};
  use std::convert::Infallible;
  use std::io::Write;
  use std::net::{Ipv4Addr, SocketAddr};
  use std::pin::Pin;
  use std::task::{Context, Poll};
  use std::time::Duration;
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, CanonicalAuthority, ClientAuthPlan,
    ConnectAction, ForwardProxyListenerPlan, GatewayPlan, HttpAction, HttpIngress, HttpScheme, ListenerId,
    ListenerPlan, LlmApiListenerPlan, ManagedRetry, ManagedRoute, ManagedTarget, ModelGroupId, ModelSelector,
    ProfileId, ProfilePlan, ProviderId, RelayRetry, RelayRoute, RelayTarget, RouteId, RoutePlan, UpstreamId,
    UpstreamPlan, UpstreamSelector, WireIdentity,
  };

  #[derive(Clone, Copy)]
  enum FixtureFamily {
    Managed,
    Relay,
    Transparent,
  }

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn profile_id(value: &str) -> ProfileId {
    ProfileId::new(value).unwrap()
  }

  fn route_id(value: &str) -> RouteId {
    RouteId::new(value).unwrap()
  }

  fn pool_id(value: &str) -> AccountPoolId {
    AccountPoolId::new(value).unwrap()
  }

  fn upstream_id(value: &str) -> UpstreamId {
    UpstreamId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
  }

  fn account() -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.tier = AccountTier::Active;
    account
  }

  fn matched_route(family: FixtureFamily, request_kind: ProviderRequestKind) -> MatchedHttpRoute {
    let listener = listener_id("listener");
    let profile = profile_id("profile");
    let route = route_id("route");
    let pool = pool_id("pool");
    let upstream = upstream_id("upstream");
    let listener_plan = match family {
      FixtureFamily::Managed | FixtureFamily::Relay => ListenerPlan::LlmApi(LlmApiListenerPlan::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
        ClientAuthPlan::None,
        Box::default(),
        HttpAction::Route(profile.clone()),
      )),
      FixtureFamily::Transparent => ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 42_500)),
        ClientAuthPlan::None,
        Box::default(),
        HttpAction::Route(profile.clone()),
        Box::default(),
        ConnectAction::Tunnel,
        None,
      )),
    };
    let route_plan = match family {
      FixtureFamily::Managed => RoutePlan::Managed(ManagedRoute::new(
        ManagedTarget::new(
          pool.clone(),
          UpstreamSelector::Fixed(upstream.clone()),
          ModelSelector::Capability,
        ),
        tokn_policy::OperationPolicy::TranslateCompatible,
        None,
        ManagedRetry::Never,
      )),
      FixtureFamily::Relay => RoutePlan::Relay(RelayRoute::new(
        RelayTarget::FixedUpstream {
          upstream: upstream.clone(),
          account_pool: pool.clone(),
        },
        None,
        RelayRetry::Never,
      )),
      FixtureFamily::Transparent => RoutePlan::Transparent(Default::default()),
    };
    let needs_provider_graph = !matches!(family, FixtureFamily::Transparent);
    let pools = if needs_provider_graph {
      BTreeMap::from([(
        pool,
        AccountPoolPlan::new(
          AccountSelector::all(),
          AccountSelectionStrategy::RoundRobin,
          Duration::from_secs(30),
          None,
        ),
      )])
    } else {
      BTreeMap::new()
    };
    let upstreams = if needs_provider_graph {
      BTreeMap::from([(
        upstream,
        UpstreamPlan::new(
          provider_id(ID_LLAMA_CPP),
          Some("https://upstream.example/v1/".into()),
          Box::default(),
          false,
        )
        .with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("fixture")]))),
      )])
    } else {
      BTreeMap::new()
    };
    let plan = GatewayPlan::new(
      BTreeMap::from([(listener.clone(), listener_plan)]),
      BTreeMap::from([(profile, ProfilePlan::new(route.clone(), WireIdentity::None))]),
      BTreeMap::from([(route, route_plan)]),
      pools,
      upstreams,
      BTreeMap::<ModelGroupId, _>::new(),
    );
    let accounts = needs_provider_graph.then(account).into_iter().collect::<Vec<_>>();
    let runtime =
      link_gateway_runtime(&plan, &accounts, &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap();
    let linked_listener = runtime.listeners().listener(&listener).unwrap();
    let head = HttpRequestHead::new(
      HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse("client.example").unwrap()),
      Method::POST,
      "/v1/responses".parse().unwrap(),
    )
    .unwrap();
    let HttpRouteMatch::Route(matched) = match_http(linked_listener, head, request_kind) else {
      panic!("fixture listener must route the request");
    };
    matched
  }

  #[derive(Debug)]
  struct PanicOnPollBody;

  impl HttpBody for PanicOnPollBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
      self: Pin<&mut Self>,
      _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
      panic!("request body must not be polled")
    }
  }

  fn panic_body() -> Body {
    Body::new(PanicOnPollBody)
  }

  fn gzip(body: &[u8]) -> Bytes {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    Bytes::from(encoder.finish().unwrap())
  }

  fn zstd(body: &[u8]) -> Bytes {
    Bytes::from(zstd::stream::encode_all(body, 0).unwrap())
  }

  fn generous_limits() -> RequestBodyLimits {
    RequestBodyLimits::new(128 * 1024, 256 * 1024)
  }

  fn assert_rejected_code(observation: &RequestBodyObservation, expected: &str) {
    let BodyOutcome::Rejected(failure) = &observation.outcome else {
      panic!("expected a rejected body observation, got {:?}", observation.outcome)
    };
    assert_eq!(failure.code, expected);
  }

  #[test]
  fn zstd_window_limit_has_a_compatibility_floor_and_hard_cap() {
    assert_eq!(zstd_window_log(0), MIN_ZSTD_WINDOW_LOG);
    assert_eq!(zstd_window_log(1 << 24), 24);
    assert_eq!(zstd_window_log(usize::MAX), MAX_ZSTD_WINDOW_LOG);
  }

  #[tokio::test]
  async fn public_body_debug_output_never_discloses_payload_or_source_text() {
    let managed = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let secret_body = Bytes::from_static(br#"{"model":"secret-model","input":"secret-prompt"}"#);
    let admission = buffer_matched_body(
      &managed,
      &HeaderMap::new(),
      Body::from(secret_body),
      true,
      generous_limits(),
    )
    .await;
    let admission_debug = format!("{admission:?}");
    assert!(!admission_debug.contains("secret-model"));
    assert!(!admission_debug.contains("secret-prompt"));

    let buffered = admission.into_body_result().unwrap();
    let buffered_debug = format!("{buffered:?}");
    assert!(!buffered_debug.contains("secret-model"));
    assert!(!buffered_debug.contains("secret-prompt"));

    let opaque = BufferedRequestBody::Opaque {
      wire_body: Some(Bytes::from_static(b"secret-opaque-body")),
    };
    let opaque_debug = format!("{opaque:?}");
    assert!(opaque_debug.contains("wire_bytes"));
    assert!(!opaque_debug.contains("secret-opaque-body"));

    let relay = matched_route(FixtureFamily::Relay, ProviderRequestKind::Opaque);
    let rejected = buffer_matched_body(
      &relay,
      &HeaderMap::new(),
      Body::from_stream(futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"secret-partial-body")),
        Err(io::Error::other("secret-source-error")),
      ])),
      true,
      generous_limits(),
    )
    .await;
    let rejected_debug = format!("{rejected:?}");
    assert!(!rejected_debug.contains("secret-partial-body"));
    assert!(!rejected_debug.contains("secret-source-error"));
  }

  #[tokio::test]
  async fn opaque_families_preserve_exact_data_when_encoding_cannot_be_inspected() {
    for family in [FixtureFamily::Relay, FixtureFamily::Transparent] {
      let matched = matched_route(family, ProviderRequestKind::Opaque);
      let mut headers = HeaderMap::new();
      headers.insert(CONTENT_ENCODING, HeaderValue::from_bytes(b"\x80").unwrap());
      let body = Body::from_stream(futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"first\0")),
        Ok(Bytes::from_static(b"\xfflast")),
      ]));

      let admission = buffer_matched_body(&matched, &headers, body, true, RequestBodyLimits::new(11, 0)).await;
      assert_eq!(
        admission.observation(),
        &RequestBodyObservation {
          wire: BodyCapture::Complete(Bytes::from_static(b"first\0\xfflast")),
          decoded: Some(BodyCapture::Omitted {
            reason: CaptureOmission::Unavailable,
            bytes_seen: 0,
          }),
          requested_model: None,
          stream: None,
          initiator: None,
          outcome: BodyOutcome::Accepted,
        }
      );
      let buffered = admission.into_body_result().unwrap();

      assert_eq!(
        buffered.opaque_wire_body(),
        Some(Some(&Bytes::from_static(b"first\0\xfflast")))
      );
    }
  }

  #[tokio::test]
  async fn opaque_families_best_effort_extract_compressed_body_facts_without_changing_forwarding() {
    let decoded = Bytes::from_static(br#"{"model":"opaque-model","stream":true,"tools":[{}]}"#);
    let wire = gzip(&decoded);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

    for family in [FixtureFamily::Relay, FixtureFamily::Transparent] {
      let matched = matched_route(family, ProviderRequestKind::Opaque);
      let admission = buffer_matched_body(&matched, &headers, Body::from(wire.clone()), true, generous_limits()).await;

      assert_eq!(admission.observation().wire, BodyCapture::Complete(wire.clone()));
      assert_eq!(
        admission.observation().decoded,
        Some(BodyCapture::Complete(decoded.clone()))
      );
      assert_eq!(admission.observation().requested_model.as_deref(), Some("opaque-model"));
      assert_eq!(admission.observation().stream, Some(true));
      assert_eq!(admission.observation().initiator.as_deref(), Some("agent"));
      assert_eq!(admission.observation().outcome, BodyOutcome::Accepted);
      assert_eq!(
        admission.into_body_result().unwrap().opaque_wire_body(),
        Some(Some(&wire))
      );
    }
  }

  #[tokio::test]
  async fn opaque_inspection_failures_are_truthful_but_never_reject_forwarding() {
    let matched = matched_route(FixtureFamily::Relay, ProviderRequestKind::Opaque);
    let invalid_gzip = Bytes::from_static(b"not-a-gzip-body");
    let mut gzip_headers = HeaderMap::new();
    gzip_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    let corrupt = buffer_matched_body(
      &matched,
      &gzip_headers,
      Body::from(invalid_gzip.clone()),
      true,
      generous_limits(),
    )
    .await;

    assert_eq!(corrupt.observation().wire, BodyCapture::Complete(invalid_gzip.clone()));
    assert!(matches!(
      corrupt.observation().decoded,
      Some(BodyCapture::Truncated { .. })
    ));
    assert_eq!(corrupt.observation().outcome, BodyOutcome::Accepted);
    assert_eq!(
      corrupt.into_body_result().unwrap().opaque_wire_body(),
      Some(Some(&invalid_gzip))
    );

    let invalid_json = Bytes::from_static(b"not-json");
    let plain = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from(invalid_json.clone()),
      true,
      generous_limits(),
    )
    .await;
    assert_eq!(plain.observation().wire, BodyCapture::Complete(invalid_json.clone()));
    assert_eq!(
      plain.observation().decoded,
      Some(BodyCapture::Complete(invalid_json.clone()))
    );
    assert_eq!(plain.observation().requested_model, None);
    assert_eq!(plain.observation().stream, None);
    assert_eq!(plain.observation().initiator, None);
    assert_eq!(plain.observation().outcome, BodyOutcome::Accepted);
    assert_eq!(
      plain.into_body_result().unwrap().opaque_wire_body(),
      Some(Some(&invalid_json))
    );
  }

  #[tokio::test]
  async fn opaque_absent_and_present_empty_bodies_remain_distinct() {
    let matched = matched_route(FixtureFamily::Transparent, ProviderRequestKind::Opaque);

    let absent = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      panic_body(),
      false,
      RequestBodyLimits::new(0, 0),
    )
    .await;
    let present = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::empty(),
      true,
      RequestBodyLimits::new(0, 0),
    )
    .await;

    assert_eq!(absent.observation().wire, BodyCapture::Absent);
    assert_eq!(present.observation().wire, BodyCapture::Complete(Bytes::new()));
    assert_eq!(absent.observation().decoded, None);
    assert_eq!(present.observation().decoded, Some(BodyCapture::Complete(Bytes::new())));
    assert_eq!(absent.into_body_result().unwrap().opaque_wire_body(), Some(None));
    assert_eq!(
      present.into_body_result().unwrap().opaque_wire_body(),
      Some(Some(&Bytes::new()))
    );
  }

  #[tokio::test]
  async fn opaque_collection_enforces_the_wire_limit_and_surfaces_read_errors() {
    let matched = matched_route(FixtureFamily::Relay, ProviderRequestKind::Opaque);
    let exact = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from("1234"),
      true,
      RequestBodyLimits::new(4, 0),
    )
    .await
    .into_body_result()
    .unwrap();
    assert_eq!(exact.opaque_wire_body(), Some(Some(&Bytes::from_static(b"1234"))));

    let too_large = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from_stream(futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"12")),
        Ok(Bytes::from_static(b"345")),
      ])),
      true,
      RequestBodyLimits::new(4, 0),
    )
    .await;
    assert_eq!(
      too_large.observation().wire,
      BodyCapture::Truncated {
        prefix: Bytes::from_static(b"1234"),
        bytes_seen: 5,
      }
    );
    assert_rejected_code(too_large.observation(), "wire_body_too_large");
    let too_large = too_large.into_body_result().unwrap_err();
    assert!(matches!(too_large, RequestBodyError::WireBodyTooLarge { limit: 4 }));

    let read_error = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from_stream(futures_util::stream::iter([
        Ok::<_, io::Error>(Bytes::from_static(b"partial")),
        Err(io::Error::other("fixture read failure")),
      ])),
      true,
      generous_limits(),
    )
    .await;
    assert_eq!(
      read_error.observation().wire,
      BodyCapture::Truncated {
        prefix: Bytes::from_static(b"partial"),
        bytes_seen: 7,
      }
    );
    assert_rejected_code(read_error.observation(), "body_read_failed");
    let read_error = read_error.into_body_result().unwrap_err();
    assert!(matches!(read_error, RequestBodyError::BodyRead { .. }));
  }

  #[tokio::test]
  async fn managed_route_rejects_non_operations_and_absent_bodies_without_polling() {
    for request_kind in [ProviderRequestKind::Models, ProviderRequestKind::Opaque] {
      let matched = matched_route(FixtureFamily::Managed, request_kind);
      let admission = buffer_matched_body(&matched, &HeaderMap::new(), panic_body(), true, generous_limits()).await;
      assert_eq!(
        admission.observation().wire,
        BodyCapture::Omitted {
          reason: CaptureOmission::Unavailable,
          bytes_seen: 0,
        }
      );
      assert_rejected_code(admission.observation(), "managed_operation_required");
      let error = admission.into_body_result().unwrap_err();
      assert!(matches!(
        error,
        RequestBodyError::ManagedOperationRequired {
          request_kind: actual
        } if actual == request_kind
      ));
    }

    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let admission = buffer_matched_body(&matched, &HeaderMap::new(), panic_body(), false, generous_limits()).await;
    assert_eq!(admission.observation().wire, BodyCapture::Absent);
    assert_rejected_code(admission.observation(), "managed_body_required");
    let error = admission.into_body_result().unwrap_err();
    assert!(matches!(error, RequestBodyError::ManagedBodyRequired));
  }

  #[tokio::test]
  async fn managed_body_decodes_all_encoding_fields_in_reverse_order() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let decoded = Bytes::from_static(br#"{"model":"inbound-model","input":"hello"}"#);
    let gzip_encoded = gzip(&decoded);
    let wire = zstd(&gzip_encoded);
    let expected_wire = wire.clone();
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_ENCODING, HeaderValue::from_static("GZip, identity"));
    headers.append(CONTENT_ENCODING, HeaderValue::from_static("ZSTD"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
    headers.insert("x-initiator", HeaderValue::from_static("Agent"));

    let admission = buffer_matched_body(&matched, &headers, Body::from(wire), true, generous_limits()).await;
    assert_eq!(
      admission.observation(),
      &RequestBodyObservation {
        wire: BodyCapture::Complete(expected_wire),
        decoded: Some(BodyCapture::Complete(decoded)),
        requested_model: Some("inbound-model".into()),
        stream: Some(true),
        initiator: Some("agent".into()),
        outcome: BodyOutcome::Accepted,
      }
    );
    let buffered = admission.into_body_result().unwrap();
    let BufferedRequestBody::Managed(managed) = buffered else {
      panic!("managed route must produce managed semantics");
    };

    assert_eq!(managed.requested_model(), "inbound-model");
    assert_eq!(managed.value()["input"], "hello");
    let (value, requested_model) = managed.into_parts();
    assert_eq!(value["model"], "inbound-model");
    assert_eq!(requested_model, "inbound-model");
  }

  #[tokio::test]
  async fn managed_gzip_supports_concatenated_members() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let mut wire = gzip(br#"{"model":"multi""#).to_vec();
    wire.extend_from_slice(&gzip(br#", "input":"member"}"#));
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

    let buffered = buffer_matched_body(&matched, &headers, Body::from(wire), true, generous_limits())
      .await
      .into_body_result()
      .unwrap();

    assert_eq!(buffered.managed().unwrap().requested_model(), "multi");
    assert_eq!(buffered.managed().unwrap().value()["input"], "member");
  }

  #[tokio::test]
  async fn managed_encoding_metadata_is_strict_and_checked_before_polling() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let mut too_many = HeaderMap::new();
    too_many.append(CONTENT_ENCODING, HeaderValue::from_static("gzip, identity"));
    too_many.append(CONTENT_ENCODING, HeaderValue::from_static("zstd, identity, gzip"));
    let admission = buffer_matched_body(&matched, &too_many, panic_body(), true, generous_limits()).await;
    assert_eq!(
      admission.observation().wire,
      BodyCapture::Omitted {
        reason: CaptureOmission::Unavailable,
        bytes_seen: 0,
      }
    );
    assert_eq!(admission.observation().decoded, None);
    assert_rejected_code(admission.observation(), "too_many_content_encodings");
    let error = admission.into_body_result().unwrap_err();
    assert!(matches!(
      error,
      RequestBodyError::TooManyContentEncodings { limit: 4, actual: 5 }
    ));

    let mut unsupported = HeaderMap::new();
    unsupported.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
    let error = buffer_matched_body(&matched, &unsupported, panic_body(), true, generous_limits())
      .await
      .into_body_result()
      .unwrap_err();
    assert!(matches!(
      error,
      RequestBodyError::UnsupportedContentEncoding { encoding } if encoding == "br"
    ));

    let mut invalid_text = HeaderMap::new();
    invalid_text.insert(CONTENT_ENCODING, HeaderValue::from_bytes(b"\x80").unwrap());
    let error = buffer_matched_body(&matched, &invalid_text, panic_body(), true, generous_limits())
      .await
      .into_body_result()
      .unwrap_err();
    assert!(matches!(
      error,
      RequestBodyError::InvalidContentEncodingHeader { field_index: 0 }
    ));

    for value in ["", "   ", "gzip,", ",gzip", "gzip,,zstd", "gzip, ,zstd"] {
      let mut empty_member = HeaderMap::new();
      empty_member.insert(CONTENT_ENCODING, HeaderValue::from_str(value).unwrap());
      let error = buffer_matched_body(&matched, &empty_member, panic_body(), true, generous_limits())
        .await
        .into_body_result()
        .unwrap_err();
      assert!(
        matches!(error, RequestBodyError::EmptyContentEncodingMember { .. }),
        "expected empty member rejection for {value:?}, got {error}"
      );
    }
  }

  #[tokio::test]
  async fn managed_limits_apply_to_wire_final_and_intermediate_decoded_bytes() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let decoded = Bytes::from_static(br#"{"model":"m"}"#);

    let wire_admission = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from(decoded.clone()),
      true,
      RequestBodyLimits::new(decoded.len() - 1, decoded.len()),
    )
    .await;
    assert_eq!(
      wire_admission.observation().wire,
      BodyCapture::Truncated {
        prefix: decoded.slice(..decoded.len() - 1),
        bytes_seen: decoded.len() as u64,
      }
    );
    assert_eq!(wire_admission.observation().decoded, None);
    let wire_error = wire_admission.into_body_result().unwrap_err();
    assert!(matches!(wire_error, RequestBodyError::WireBodyTooLarge { .. }));

    let decoded_admission = buffer_matched_body(
      &matched,
      &HeaderMap::new(),
      Body::from(decoded.clone()),
      true,
      RequestBodyLimits::new(decoded.len(), decoded.len() - 1),
    )
    .await;
    assert_eq!(
      decoded_admission.observation().wire,
      BodyCapture::Complete(decoded.clone())
    );
    assert_eq!(
      decoded_admission.observation().decoded,
      Some(BodyCapture::Truncated {
        prefix: decoded.slice(..decoded.len() - 1),
        bytes_seen: decoded.len() as u64,
      })
    );
    assert_rejected_code(decoded_admission.observation(), "decoded_body_too_large");
    let decoded_error = decoded_admission.into_body_result().unwrap_err();
    assert!(matches!(
      decoded_error,
      RequestBodyError::DecodedBodyTooLarge { limit } if limit == decoded.len() - 1
    ));

    let gzip_encoded = gzip(&decoded);
    assert!(gzip_encoded.len() > decoded.len());
    let wire = zstd(&gzip_encoded);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip, zstd"));
    let intermediate_admission = buffer_matched_body(
      &matched,
      &headers,
      Body::from(wire.clone()),
      true,
      RequestBodyLimits::new(1024, decoded.len()),
    )
    .await;
    assert_eq!(intermediate_admission.observation().wire, BodyCapture::Complete(wire));
    assert_eq!(
      intermediate_admission.observation().decoded,
      Some(BodyCapture::Omitted {
        reason: CaptureOmission::Unavailable,
        bytes_seen: 0,
      })
    );
    let intermediate_error = intermediate_admission.into_body_result().unwrap_err();
    assert!(matches!(
      intermediate_error,
      RequestBodyError::DecodedBodyTooLarge { limit } if limit == decoded.len()
    ));
  }

  #[tokio::test]
  async fn managed_body_rejects_invalid_json_and_propagates_semantic_errors() {
    type ErrorPredicate = fn(&RequestBodyError) -> bool;
    struct RejectedBodyCase {
      body: &'static [u8],
      failure_code: &'static str,
      requested_model: Option<&'static str>,
      stream: Option<bool>,
      initiator: Option<&'static str>,
      expected: ErrorPredicate,
    }

    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    let cases = [
      RejectedBodyCase {
        body: b"not-json",
        failure_code: "invalid_json",
        requested_model: None,
        stream: None,
        initiator: None,
        expected: |error| matches!(error, RequestBodyError::InvalidManagedJson { .. }),
      },
      RejectedBodyCase {
        body: b"[]",
        failure_code: "managed_body_object_required",
        requested_model: None,
        stream: Some(false),
        initiator: None,
        expected: |error| {
          matches!(
            error,
            RequestBodyError::InvalidManagedBody {
              source: ManagedRequestBodyError::ObjectRequired
            }
          )
        },
      },
      RejectedBodyCase {
        body: br#"{"model":"","stream":true,"tools":[{}]}"#,
        failure_code: "managed_model_empty",
        requested_model: Some(""),
        stream: Some(true),
        initiator: Some("agent"),
        expected: |error| {
          matches!(
            error,
            RequestBodyError::InvalidManagedBody {
              source: ManagedRequestBodyError::ModelEmpty
            }
          )
        },
      },
    ];

    for case in cases {
      let admission = buffer_matched_body(
        &matched,
        &HeaderMap::new(),
        Body::from(Bytes::copy_from_slice(case.body)),
        true,
        generous_limits(),
      )
      .await;
      let captured = Bytes::copy_from_slice(case.body);
      assert_eq!(admission.observation().wire, BodyCapture::Complete(captured.clone()));
      assert_eq!(admission.observation().decoded, Some(BodyCapture::Complete(captured)));
      assert_eq!(admission.observation().requested_model.as_deref(), case.requested_model);
      assert_eq!(admission.observation().stream, case.stream);
      assert_eq!(admission.observation().initiator.as_deref(), case.initiator);
      assert_rejected_code(admission.observation(), case.failure_code);
      let error = admission.into_body_result().unwrap_err();
      assert!((case.expected)(&error), "unexpected error for {:?}: {error}", case.body);
    }
  }

  #[tokio::test]
  async fn managed_corrupt_compressed_bodies_report_the_selected_codec() {
    let matched = matched_route(
      FixtureFamily::Managed,
      ProviderRequestKind::Operation(Endpoint::Responses),
    );
    for encoding in ["gzip", "zstd"] {
      let mut headers = HeaderMap::new();
      headers.insert(CONTENT_ENCODING, HeaderValue::from_str(encoding).unwrap());
      let admission = buffer_matched_body(
        &matched,
        &headers,
        Body::from("not-compressed"),
        true,
        generous_limits(),
      )
      .await;
      assert_eq!(
        admission.observation().wire,
        BodyCapture::Complete(Bytes::from_static(b"not-compressed"))
      );
      assert!(matches!(
        admission.observation().decoded,
        Some(BodyCapture::Truncated { .. })
      ));
      assert_rejected_code(
        admission.observation(),
        match encoding {
          "gzip" => "gzip_decode_failed",
          "zstd" => "zstd_decode_failed",
          _ => unreachable!(),
        },
      );
      let error = admission.into_body_result().unwrap_err();
      match encoding {
        "gzip" => assert!(matches!(error, RequestBodyError::GzipDecode { .. })),
        "zstd" => assert!(matches!(error, RequestBodyError::ZstdDecode { .. })),
        _ => unreachable!(),
      }
    }
  }
}

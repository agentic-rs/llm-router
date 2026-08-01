//! Shared disclosure-safe projections of application-boundary HTTP facts.

use http::header::ACCEPT;
use http::HeaderMap;
use serde_json::Value;
use smol_str::SmolStr;
use tokn_events::{is_sensitive_header_name, CapturedHeader, CapturedHeaders, Correlation};
use tokn_headers::inbound::{first_present_smol, inbound_correlation, PROJECT_ID_HEADERS, REQUEST_ID_HEADERS};
use tokn_headers::keys::{X_CLIENT_REQUEST_ID, X_PARENT_SESSION_ID};

/// Preserve duplicate and non-UTF-8 field values while enforcing the event
/// contract's minimum credential denylist.
pub(crate) fn capture_headers(headers: &HeaderMap) -> CapturedHeaders {
  headers
    .iter()
    .map(|(name, value)| {
      if is_sensitive_header_name(name.as_str()) {
        CapturedHeader::redacted(name.as_str())
      } else {
        CapturedHeader::value(name.as_str(), bytes::Bytes::copy_from_slice(value.as_bytes()))
      }
    })
    .collect()
}

/// Resolve supported correlation fields from the exact string-backed header
/// semantics shared by listener and embedded managed requests.
pub(crate) fn correlation(headers: &tokn_headers::HeaderMap) -> Correlation {
  let inbound = inbound_correlation(headers);
  let client_request_id = first_present_smol(headers, &[X_CLIENT_REQUEST_ID.as_str()])
    .or_else(|| first_present_smol(headers, REQUEST_ID_HEADERS));

  Correlation {
    client_request_id,
    session_id: inbound.session_id,
    thread_id: inbound.thread_id,
    parent_thread_id: inbound.parent_thread_id,
    parent_session_id: first_present_smol(headers, &[X_PARENT_SESSION_ID.as_str()]),
    project_id: first_present_smol(headers, PROJECT_ID_HEADERS),
    turn_id: inbound.turn_id,
  }
}

pub(crate) fn native_correlation(headers: &HeaderMap) -> Correlation {
  correlation(&tokn_headers::HeaderMap::from(headers))
}

/// Initial semantic facts available before JSON inspection.
pub(crate) fn body_header_facts(headers: &HeaderMap) -> (Option<bool>, Option<SmolStr>) {
  (accepts_event_stream(headers).then_some(true), header_initiator(headers))
}

/// Semantic facts contributed by one decoded JSON request body.
pub(crate) fn body_json_facts(headers: &HeaderMap, body: &Value) -> (Option<SmolStr>, Option<bool>, Option<SmolStr>) {
  let (header_stream, header_initiator) = body_header_facts(headers);
  merge_body_json_facts(header_stream, header_initiator, body)
}

pub(crate) fn merge_body_json_facts(
  header_stream: Option<bool>,
  header_initiator: Option<SmolStr>,
  body: &Value,
) -> (Option<SmolStr>, Option<bool>, Option<SmolStr>) {
  let requested_model = body.get("model").and_then(Value::as_str).map(SmolStr::new);
  let stream = Some(
    body
      .get("stream")
      .and_then(Value::as_bool)
      .unwrap_or(header_stream == Some(true)),
  );
  let initiator = header_initiator.or_else(|| infer_body_initiator(body).map(SmolStr::new));
  (requested_model, stream, initiator)
}

fn accepts_event_stream(headers: &HeaderMap) -> bool {
  headers.get_all(ACCEPT).iter().any(|value| {
    value.to_str().is_ok_and(|value| {
      value.split(',').any(|part| {
        part
          .split(';')
          .next()
          .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
      })
    })
  })
}

fn header_initiator(headers: &HeaderMap) -> Option<SmolStr> {
  let value = headers.get("x-initiator")?.to_str().ok()?.trim().to_ascii_lowercase();
  matches!(value.as_str(), "user" | "agent").then(|| SmolStr::new(value))
}

fn infer_body_initiator(body: &Value) -> Option<&'static str> {
  if body.get("input").is_some() {
    tokn_core::util::initiator::classify_initiator_responses(body)
  } else {
    tokn_core::util::initiator::classify_initiator(body).or_else(|| {
      body
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| !tools.is_empty())
        .then_some("agent")
    })
  }
}

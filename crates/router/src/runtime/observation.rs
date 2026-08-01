//! Shared disclosure-safe projections of native HTTP wire facts.

use http::HeaderMap;
use tokn_events::{is_sensitive_header_name, CapturedHeader, CapturedHeaders};

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

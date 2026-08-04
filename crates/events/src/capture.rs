use bytes::Bytes;
use smol_str::SmolStr;
use std::fmt;

/// One duplicate-preserving captured HTTP field.
///
/// Producers must replace credentials and other denied values with
/// [`CapturedHeaderValue::Redacted`] before publishing the event. Raw header
/// values are bytes because valid HTTP field values are not necessarily UTF-8.
#[derive(Clone, Eq, PartialEq)]
pub struct CapturedHeader {
  name: SmolStr,
  value: CapturedHeaderValue,
}

impl CapturedHeader {
  pub fn value(name: impl Into<SmolStr>, value: impl Into<Bytes>) -> Self {
    Self {
      name: name.into(),
      value: CapturedHeaderValue::Value(value.into()),
    }
  }

  pub fn redacted(name: impl Into<SmolStr>) -> Self {
    Self {
      name: name.into(),
      value: CapturedHeaderValue::Redacted,
    }
  }

  pub fn name(&self) -> &str {
    self.name.as_str()
  }

  pub fn captured_value(&self) -> &CapturedHeaderValue {
    &self.value
  }
}

/// Whether a header name belongs to the gateway's minimum credential denylist.
///
/// Producers should redact these values before publication. Durable consumers
/// should apply the same check independently as defense in depth.
pub fn is_sensitive_header_name(name: &str) -> bool {
  let name = name.to_ascii_lowercase();
  matches!(
    name.as_str(),
    "authorization"
      | "proxy-authorization"
      | "cookie"
      | "set-cookie"
      | "api-key"
      | "x-api-key"
      | "x-goog-api-key"
      | "x-auth-token"
      | "x-access-token"
      | "ocp-apim-subscription-key"
  ) || name.contains("api-key")
}

impl fmt::Debug for CapturedHeader {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CapturedHeader")
      .field("name", &self.name)
      .field("value", &self.value)
      .finish()
  }
}

/// Captured or deliberately hidden HTTP field value.
#[derive(Clone, Eq, PartialEq)]
pub enum CapturedHeaderValue {
  Value(Bytes),
  Redacted,
}

impl CapturedHeaderValue {
  pub fn as_bytes(&self) -> Option<&[u8]> {
    match self {
      Self::Value(value) => Some(value.as_ref()),
      Self::Redacted => None,
    }
  }

  pub const fn is_redacted(&self) -> bool {
    matches!(self, Self::Redacted)
  }
}

impl fmt::Debug for CapturedHeaderValue {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Value(value) => formatter.debug_struct("Value").field("bytes", &value.len()).finish(),
      Self::Redacted => formatter.write_str("Redacted"),
    }
  }
}

/// Ordered, duplicate-preserving HTTP fields safe to publish to consumers.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CapturedHeaders(Box<[CapturedHeader]>);

impl CapturedHeaders {
  pub fn new(fields: impl IntoIterator<Item = CapturedHeader>) -> Self {
    Self(fields.into_iter().collect())
  }

  pub fn iter(&self) -> impl ExactSizeIterator<Item = &CapturedHeader> {
    self.0.iter()
  }

  pub fn len(&self) -> usize {
    self.0.len()
  }

  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl fmt::Debug for CapturedHeaders {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CapturedHeaders")
      .field("fields", &self.len())
      .finish()
  }
}

impl FromIterator<CapturedHeader> for CapturedHeaders {
  fn from_iter<T: IntoIterator<Item = CapturedHeader>>(iter: T) -> Self {
    Self::new(iter)
  }
}

/// URI or request-target captured according to the publisher's privacy policy.
#[derive(Clone, Eq, PartialEq)]
pub struct CapturedUri {
  value: SmolStr,
  redacted: bool,
}

impl CapturedUri {
  pub fn exact(value: impl Into<SmolStr>) -> Self {
    Self {
      value: value.into(),
      redacted: false,
    }
  }

  pub fn redacted(value: impl Into<SmolStr>) -> Self {
    Self {
      value: value.into(),
      redacted: true,
    }
  }

  pub fn as_str(&self) -> &str {
    self.value.as_str()
  }

  pub const fn is_redacted(&self) -> bool {
    self.redacted
  }
}

impl fmt::Debug for CapturedUri {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("CapturedUri")
      .field("bytes", &self.value.len())
      .field("redacted", &self.redacted)
      .finish()
  }
}

/// Why payload bytes were deliberately omitted from an event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureOmission {
  Disabled,
  Sensitive,
  Unavailable,
}

/// Bounded payload observation.
///
/// `bytes_seen` reports transport progress even when bytes are omitted or a
/// prefix is retained. Debug output never renders payload contents.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum BodyCapture {
  Absent,
  Omitted { reason: CaptureOmission, bytes_seen: u64 },
  Complete(Bytes),
  Truncated { prefix: Bytes, bytes_seen: u64 },
}

impl BodyCapture {
  pub fn bytes(&self) -> Option<&[u8]> {
    match self {
      Self::Complete(bytes) => Some(bytes.as_ref()),
      Self::Truncated { prefix, .. } => Some(prefix.as_ref()),
      Self::Absent | Self::Omitted { .. } => None,
    }
  }

  pub fn bytes_seen(&self) -> u64 {
    match self {
      Self::Absent => 0,
      Self::Omitted { bytes_seen, .. } | Self::Truncated { bytes_seen, .. } => *bytes_seen,
      Self::Complete(bytes) => bytes.len() as u64,
    }
  }

  pub const fn is_complete(&self) -> bool {
    matches!(self, Self::Absent | Self::Complete(_))
  }
}

impl fmt::Debug for BodyCapture {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Absent => formatter.write_str("Absent"),
      Self::Omitted { reason, bytes_seen } => formatter
        .debug_struct("Omitted")
        .field("reason", reason)
        .field("bytes_seen", bytes_seen)
        .finish(),
      Self::Complete(bytes) => formatter.debug_struct("Complete").field("bytes", &bytes.len()).finish(),
      Self::Truncated { prefix, bytes_seen } => formatter
        .debug_struct("Truncated")
        .field("prefix_bytes", &prefix.len())
        .field("bytes_seen", bytes_seen)
        .finish(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn headers_preserve_duplicates_without_debugging_values() {
    let headers = CapturedHeaders::new([
      CapturedHeader::value("set-cookie", "secret-cookie"),
      CapturedHeader::value("set-cookie", "second-cookie"),
      CapturedHeader::redacted("authorization"),
    ]);

    assert_eq!(headers.len(), 3);
    assert_eq!(headers.iter().filter(|field| field.name() == "set-cookie").count(), 2);
    assert!(headers.iter().last().unwrap().captured_value().is_redacted());
    let debug = format!("{headers:?}");
    assert!(!debug.contains("secret-cookie"));
    assert!(!debug.contains("second-cookie"));
  }

  #[test]
  fn sensitive_header_policy_is_case_insensitive_and_covers_api_key_variants() {
    for name in [
      "Authorization",
      "proxy-authorization",
      "Cookie",
      "set-cookie",
      "X-Api-Key",
      "x-vendor-api-key-id",
      "ocp-apim-subscription-key",
    ] {
      assert!(is_sensitive_header_name(name), "expected `{name}` to be sensitive");
    }
    assert!(!is_sensitive_header_name("content-type"));
    assert!(!is_sensitive_header_name("x-request-id"));
  }

  #[test]
  fn body_capture_debug_never_renders_content() {
    let body = BodyCapture::Truncated {
      prefix: Bytes::from_static(b"private payload"),
      bytes_seen: 42,
    };

    assert_eq!(body.bytes(), Some(b"private payload".as_slice()));
    assert_eq!(body.bytes_seen(), 42);
    assert!(!body.is_complete());
    assert!(!format!("{body:?}").contains("private payload"));
  }

  #[test]
  fn capture_value_objects_report_policy_without_exposing_content() {
    let value = CapturedHeader::value("x-label", Bytes::from_static(b"private"));
    assert_eq!(value.captured_value().as_bytes(), Some(b"private".as_slice()));
    assert!(!value.captured_value().is_redacted());
    assert!(!format!("{value:?}").contains("private"));

    let redacted = CapturedHeader::redacted("authorization");
    assert_eq!(redacted.captured_value().as_bytes(), None);
    assert_eq!(format!("{:?}", redacted.captured_value()), "Redacted");

    let empty = std::iter::empty::<CapturedHeader>().collect::<CapturedHeaders>();
    assert!(empty.is_empty());
    assert_eq!(empty.iter().len(), 0);

    let exact_uri = CapturedUri::exact("/v1/models?limit=1");
    assert_eq!(exact_uri.as_str(), "/v1/models?limit=1");
    assert!(!exact_uri.is_redacted());
    assert!(!format!("{exact_uri:?}").contains("/v1/models"));

    let redacted_uri = CapturedUri::redacted("/v1/models?<redacted>");
    assert_eq!(redacted_uri.as_str(), "/v1/models?<redacted>");
    assert!(redacted_uri.is_redacted());
    assert!(!format!("{redacted_uri:?}").contains("/v1/models"));
  }

  #[test]
  fn body_capture_reports_every_retention_state() {
    let absent = BodyCapture::Absent;
    assert_eq!(absent.bytes(), None);
    assert_eq!(absent.bytes_seen(), 0);
    assert!(absent.is_complete());
    assert_eq!(format!("{absent:?}"), "Absent");

    let omitted = BodyCapture::Omitted {
      reason: CaptureOmission::Sensitive,
      bytes_seen: 12,
    };
    assert_eq!(omitted.bytes(), None);
    assert_eq!(omitted.bytes_seen(), 12);
    assert!(!omitted.is_complete());
    assert_eq!(format!("{omitted:?}"), "Omitted { reason: Sensitive, bytes_seen: 12 }");

    let complete = BodyCapture::Complete(Bytes::from_static(b"private"));
    assert_eq!(complete.bytes(), Some(b"private".as_slice()));
    assert_eq!(complete.bytes_seen(), 7);
    assert!(complete.is_complete());
    assert_eq!(format!("{complete:?}"), "Complete { bytes: 7 }");
  }
}

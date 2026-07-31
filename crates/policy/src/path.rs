use smol_str::SmolStr;
use std::fmt;

/// A canonical raw encoded HTTP request path.
///
/// Percent escapes are normalized to uppercase hexadecimal, but never
/// decoded. In particular, `%2F` remains distinct from `/`, so routing cannot
/// accidentally reinterpret a segment boundary.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalHttpPath(SmolStr);

impl CanonicalHttpPath {
  pub fn parse(raw: &str) -> Result<Self, InvalidHttpPath> {
    canonicalize(raw).map(Self)
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

impl AsRef<str> for CanonicalHttpPath {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl fmt::Display for CanonicalHttpPath {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

/// A non-catch-all prefix matched against a [`CanonicalHttpPath`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HttpPathPrefix(SmolStr);

impl HttpPathPrefix {
  pub fn parse(raw: &str) -> Result<Self, InvalidHttpPath> {
    let path = canonicalize(raw)?;
    if path == "/" {
      return Err(InvalidHttpPath::CatchAllPrefix);
    }
    Ok(Self(path))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }

  pub fn matches(&self, path: &CanonicalHttpPath) -> bool {
    path.as_str().starts_with(self.as_str())
  }

  /// Whether every path matched by `other` is also matched by this prefix.
  pub fn subsumes(&self, other: &Self) -> bool {
    other.as_str().starts_with(self.as_str())
  }
}

impl AsRef<str> for HttpPathPrefix {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl fmt::Display for HttpPathPrefix {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidHttpPath {
  Empty,
  MissingLeadingSlash,
  CatchAllPrefix,
  NonAscii,
  InvalidPercentEscape,
  InvalidCharacter,
  DotSegment,
}

impl fmt::Display for InvalidHttpPath {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Empty => formatter.write_str("HTTP paths must not be empty"),
      Self::MissingLeadingSlash => formatter.write_str("HTTP paths must start with `/`"),
      Self::CatchAllPrefix => formatter.write_str(
        "`/` matches every path; omit this dimension (and use the listener default action if no constraints remain)",
      ),
      Self::NonAscii => formatter.write_str("HTTP paths must be ASCII; percent-encode non-ASCII bytes"),
      Self::InvalidPercentEscape => {
        formatter.write_str("percent escapes in HTTP paths must contain exactly two hexadecimal digits")
      }
      Self::InvalidCharacter => {
        formatter.write_str("HTTP paths may only contain RFC 3986 path characters and percent escapes")
      }
      Self::DotSegment => {
        formatter.write_str("HTTP paths must not contain literal or percent-encoded `.` or `..` segments")
      }
    }
  }
}

impl std::error::Error for InvalidHttpPath {}

fn canonicalize(raw: &str) -> Result<SmolStr, InvalidHttpPath> {
  if raw.is_empty() {
    return Err(InvalidHttpPath::Empty);
  }
  if !raw.starts_with('/') {
    return Err(InvalidHttpPath::MissingLeadingSlash);
  }
  if !raw.is_ascii() {
    return Err(InvalidHttpPath::NonAscii);
  }

  let bytes = raw.as_bytes();
  let mut canonical = String::with_capacity(raw.len());
  let mut index = 0;
  while index < bytes.len() {
    let byte = bytes[index];
    if byte == b'%' {
      let Some(encoded) = bytes.get(index + 1..index + 3) else {
        return Err(InvalidHttpPath::InvalidPercentEscape);
      };
      if !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err(InvalidHttpPath::InvalidPercentEscape);
      }
      canonical.push('%');
      canonical.push(char::from(encoded[0].to_ascii_uppercase()));
      canonical.push(char::from(encoded[1].to_ascii_uppercase()));
      index += 3;
      continue;
    }
    if byte != b'/' && !is_rfc3986_pchar(byte) {
      return Err(InvalidHttpPath::InvalidCharacter);
    }
    canonical.push(char::from(byte));
    index += 1;
  }

  if canonical.split('/').any(is_dot_segment) {
    return Err(InvalidHttpPath::DotSegment);
  }
  Ok(SmolStr::new(canonical))
}

fn is_rfc3986_pchar(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&byte)
}

fn is_dot_segment(segment: &str) -> bool {
  let bytes = segment.as_bytes();
  let mut dots = 0;
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'.' {
      dots += 1;
      index += 1;
    } else if bytes.get(index..index + 3) == Some(b"%2E") {
      dots += 1;
      index += 3;
    } else {
      return false;
    }
  }
  matches!(dots, 1 | 2)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn canonicalizes_percent_escapes_without_decoding_segments() {
    let encoded = CanonicalHttpPath::parse("/v1%2fchat/%7emodel").unwrap();
    let segmented = CanonicalHttpPath::parse("/v1/chat/~model").unwrap();

    assert_eq!(encoded.as_str(), "/v1%2Fchat/%7Emodel");
    assert_eq!(segmented.as_str(), "/v1/chat/~model");
    assert_ne!(encoded, segmented);
  }

  #[test]
  fn prefix_matching_uses_the_canonical_raw_path() {
    let prefix = HttpPathPrefix::parse("/v1/%2f").unwrap();
    assert!(prefix.matches(&CanonicalHttpPath::parse("/v1/%2Fmodels").unwrap()));
    assert!(!prefix.matches(&CanonicalHttpPath::parse("/v1//models").unwrap()));
  }

  #[test]
  fn prefix_subsumption_is_explicit() {
    let broad = HttpPathPrefix::parse("/v1").unwrap();
    let narrow = HttpPathPrefix::parse("/v1/chat").unwrap();
    assert!(broad.subsumes(&narrow));
    assert!(!narrow.subsumes(&broad));
  }

  #[test]
  fn request_root_is_valid_but_catch_all_prefix_is_not() {
    assert_eq!(CanonicalHttpPath::parse("/").unwrap().as_str(), "/");
    assert_eq!(HttpPathPrefix::parse("/"), Err(InvalidHttpPath::CatchAllPrefix));
  }

  #[test]
  fn rejects_invalid_raw_paths() {
    for (raw, expected) in [
      ("", InvalidHttpPath::Empty),
      ("v1", InvalidHttpPath::MissingLeadingSlash),
      ("/café", InvalidHttpPath::NonAscii),
      ("/%", InvalidHttpPath::InvalidPercentEscape),
      ("/%2x", InvalidHttpPath::InvalidPercentEscape),
      ("/v1 path", InvalidHttpPath::InvalidCharacter),
      ("/v1?query", InvalidHttpPath::InvalidCharacter),
      ("/v1/../secret", InvalidHttpPath::DotSegment),
      ("/v1/.%2e/secret", InvalidHttpPath::DotSegment),
    ] {
      assert_eq!(CanonicalHttpPath::parse(raw), Err(expected), "accepted {raw:?}");
    }
  }
}

use smol_str::SmolStr;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Maximum encoded length of a gateway request identity.
pub const REQUEST_ID_MAX_BYTES: usize = 128;

/// Gateway-generated identity for one inbound or embedded request.
///
/// Client-provided request identifiers remain correlation metadata and must
/// never be used as the persistence primary key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(SmolStr);

impl RequestId {
  /// Creates a validated request identity.
  ///
  /// Request ids begin with an ASCII letter or digit and may then contain
  /// ASCII letters, digits, `-`, `_`, or `.`. In particular, `:` is reserved
  /// for persistence-layer attempt suffixes and is never part of a logical
  /// request identity.
  pub fn new(value: impl Into<SmolStr>) -> Result<Self, RequestIdError> {
    let value = value.into();
    validate(value.as_str())?;
    Ok(Self(value))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

/// Why a string cannot be used as a [`RequestId`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RequestIdError {
  #[error("request ID must not be empty")]
  Empty,
  #[error("request ID is {length} bytes; the maximum is {maximum}")]
  TooLong { length: usize, maximum: usize },
  #[error("request ID must begin with an ASCII letter or digit")]
  InvalidStart,
  #[error(
    "request ID contains an unsupported character at byte {index}; use only ASCII letters, digits, '-', '_', or '.'"
  )]
  InvalidCharacter { index: usize },
}

fn validate(value: &str) -> Result<(), RequestIdError> {
  if value.is_empty() {
    return Err(RequestIdError::Empty);
  }
  if value.len() > REQUEST_ID_MAX_BYTES {
    return Err(RequestIdError::TooLong {
      length: value.len(),
      maximum: REQUEST_ID_MAX_BYTES,
    });
  }

  let bytes = value.as_bytes();
  if !bytes[0].is_ascii_alphanumeric() {
    return Err(RequestIdError::InvalidStart);
  }
  if let Some((index, _)) = bytes
    .iter()
    .enumerate()
    .skip(1)
    .find(|(_, byte)| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
  {
    return Err(RequestIdError::InvalidCharacter { index });
  }

  Ok(())
}

impl AsRef<str> for RequestId {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl fmt::Debug for RequestId {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_tuple("RequestId").field(&self.as_str()).finish()
  }
}

impl fmt::Display for RequestId {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

impl TryFrom<String> for RequestId {
  type Error = RequestIdError;

  fn try_from(value: String) -> Result<Self, Self::Error> {
    Self::new(value)
  }
}

impl TryFrom<SmolStr> for RequestId {
  type Error = RequestIdError;

  fn try_from(value: SmolStr) -> Result<Self, Self::Error> {
    Self::new(value)
  }
}

impl TryFrom<&str> for RequestId {
  type Error = RequestIdError;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    Self::new(value)
  }
}

impl FromStr for RequestId {
  type Err = RequestIdError;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    Self::new(value)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn accepts_generated_and_embedder_friendly_ids() {
    for value in ["request-1", "A.b_c-9", "019e271b-4023-7081-be3e-7a69d97138a2"] {
      assert_eq!(RequestId::new(value).unwrap().as_str(), value);
    }
  }

  #[test]
  fn rejects_empty_ids() {
    assert_eq!(RequestId::new("").unwrap_err(), RequestIdError::Empty);
  }

  #[test]
  fn rejects_overlong_ids() {
    let value = "a".repeat(REQUEST_ID_MAX_BYTES + 1);
    assert_eq!(
      RequestId::new(value).unwrap_err(),
      RequestIdError::TooLong {
        length: REQUEST_ID_MAX_BYTES + 1,
        maximum: REQUEST_ID_MAX_BYTES,
      }
    );
  }

  #[test]
  fn rejects_leading_punctuation() {
    for value in ["-request", "_request", ".request"] {
      assert_eq!(RequestId::new(value).unwrap_err(), RequestIdError::InvalidStart);
    }
  }

  #[test]
  fn rejects_reserved_colon() {
    assert_eq!(
      RequestId::new("request:1").unwrap_err(),
      RequestIdError::InvalidCharacter { index: 7 }
    );
  }

  #[test]
  fn rejects_unicode_and_control_characters() {
    assert_eq!(
      RequestId::new("request-☁").unwrap_err(),
      RequestIdError::InvalidCharacter { index: 8 }
    );
    assert_eq!(
      RequestId::new("request\n1").unwrap_err(),
      RequestIdError::InvalidCharacter { index: 7 }
    );
  }

  #[test]
  fn supports_fallible_standard_conversions() {
    let from_str: RequestId = "request-1".parse().unwrap();
    let from_string = RequestId::try_from(String::from("request-1")).unwrap();
    let from_smol = RequestId::try_from(SmolStr::new("request-1")).unwrap();
    assert_eq!(from_str, from_string);
    assert_eq!(from_string, from_smol);
  }
}

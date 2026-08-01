use smol_str::SmolStr;
use std::fmt;

/// Gateway-generated identity for one inbound or embedded request.
///
/// Client-provided request identifiers remain correlation metadata and must
/// never be used as the persistence primary key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(SmolStr);

impl RequestId {
  pub fn new(value: impl Into<SmolStr>) -> Self {
    Self(value.into())
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
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

impl From<String> for RequestId {
  fn from(value: String) -> Self {
    Self::new(value)
  }
}

impl From<SmolStr> for RequestId {
  fn from(value: SmolStr) -> Self {
    Self::new(value)
  }
}

impl From<&str> for RequestId {
  fn from(value: &str) -> Self {
    Self::new(value)
  }
}

use smol_str::SmolStr;
use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

/// Error returned when a policy identifier is not in canonical form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidIdentifier {
  kind: &'static str,
  value: SmolStr,
}

impl InvalidIdentifier {
  pub fn kind(&self) -> &'static str {
    self.kind
  }

  pub fn value(&self) -> &str {
    self.value.as_str()
  }
}

impl fmt::Display for InvalidIdentifier {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "invalid {} identifier '{}': expected lowercase ASCII letters or digits, optionally separated by '.', '-' or '_'",
      self.kind, self.value
    )
  }
}

impl std::error::Error for InvalidIdentifier {}

fn parse_identifier(kind: &'static str, value: &str) -> Result<SmolStr, InvalidIdentifier> {
  let mut previous_was_separator = false;
  let valid = !value.is_empty()
    && value.bytes().enumerate().all(|(index, byte)| {
      let is_alphanumeric = byte.is_ascii_lowercase() || byte.is_ascii_digit();
      let is_separator = matches!(byte, b'.' | b'-' | b'_');
      let valid = is_alphanumeric || (index > 0 && is_separator && !previous_was_separator);
      previous_was_separator = is_separator;
      valid
    })
    && !previous_was_separator;

  if valid {
    Ok(SmolStr::new(value))
  } else {
    Err(InvalidIdentifier {
      kind,
      value: SmolStr::new(value),
    })
  }
}

macro_rules! define_identifier {
  ($name:ident, $kind:literal) => {
    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct $name(SmolStr);

    impl $name {
      pub fn new(value: impl AsRef<str>) -> Result<Self, InvalidIdentifier> {
        parse_identifier($kind, value.as_ref()).map(Self)
      }

      pub fn as_str(&self) -> &str {
        self.0.as_str()
      }
    }

    impl AsRef<str> for $name {
      fn as_ref(&self) -> &str {
        self.as_str()
      }
    }

    impl Borrow<str> for $name {
      fn borrow(&self) -> &str {
        self.as_str()
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
      }
    }

    impl FromStr for $name {
      type Err = InvalidIdentifier;

      fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
      }
    }

    impl TryFrom<String> for $name {
      type Error = InvalidIdentifier;

      fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
      }
    }

    impl TryFrom<SmolStr> for $name {
      type Error = InvalidIdentifier;

      fn try_from(value: SmolStr) -> Result<Self, Self::Error> {
        Self::new(value)
      }
    }
  };
}

define_identifier!(ListenerId, "listener");
define_identifier!(BindingId, "binding");
define_identifier!(RouteId, "route");
define_identifier!(ProfileId, "profile");
define_identifier!(AccountPoolId, "account pool");
define_identifier!(ProviderId, "provider");
define_identifier!(UpstreamId, "upstream");
define_identifier!(ModelGroupId, "model group");
define_identifier!(HeaderPatchSetId, "header patch set");
define_identifier!(RetryPolicyId, "retry policy");
define_identifier!(WireIdentityId, "wire identity");
define_identifier!(OperationId, "operation");

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn identifiers_accept_canonical_names() {
    for value in ["default", "openai-public", "coding_v2", "team.primary"] {
      assert_eq!(RouteId::new(value).unwrap().as_str(), value);
    }
  }

  #[test]
  fn identifiers_reject_ambiguous_or_noncanonical_names() {
    for value in [
      "",
      "-route",
      "route-",
      "route..primary",
      "route-_primary",
      "Route",
      "route/name",
      "route name",
      "route💥",
    ] {
      assert!(RouteId::new(value).is_err(), "{value:?} should be rejected");
    }
  }

  #[test]
  fn identifier_errors_include_kind_and_value() {
    let error = AccountPoolId::new("Bad Pool").unwrap_err();
    assert_eq!(error.kind(), "account pool");
    assert_eq!(error.value(), "Bad Pool");
    assert!(error.to_string().contains("account pool"));
  }
}

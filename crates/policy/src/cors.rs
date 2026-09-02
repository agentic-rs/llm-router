use std::collections::BTreeSet;

/// Compiled CORS permissions for one API listener. Empty permissions disable CORS.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorsPlan {
  allowed_origins: BTreeSet<String>,
  allow_localhost: bool,
}

impl CorsPlan {
  /// Origins must already be validated and canonicalized by the config compiler.
  pub fn new(allowed_origins: BTreeSet<String>, allow_localhost: bool) -> Self {
    Self {
      allowed_origins,
      allow_localhost,
    }
  }

  /// Exact HTTP(S) origins permitted to read API responses.
  pub fn allowed_origins(&self) -> &BTreeSet<String> {
    &self.allowed_origins
  }

  /// Whether HTTP(S) localhost origins are additionally permitted.
  pub fn allow_localhost(&self) -> bool {
    self.allow_localhost
  }
}

//! Strict version 2 configuration decoding and compilation.
//!
//! This module is deliberately separate from the legacy [`crate::Config`]
//! loader. Callers must opt into v2 until the runtime cutover and explicit
//! migration command are complete.

mod error;
mod raw;

use std::path::Path;

pub use error::{CompileError, Error, Result};
pub use raw::SCHEMA_VERSION;
pub use raw::{
  RawAccountPool, RawBinding, RawBindingAction, RawClientAuth, RawConfig, RawFallbackSelector, RawListener,
  RawModelCandidate, RawModelSelector, RawOperationPolicy, RawPoolStrategy, RawProfile, RawQualificationNamespace,
  RawRelayTarget, RawRoute, RawUpstream, RawUpstreamSelector, RawWireIdentity,
};

/// Decode a version 2 document without compiling references.
///
/// Migration code uses this boundary to validate emitted syntax before the
/// semantic compiler links it into a runtime plan.
pub fn decode(contents: &str, source: &Path) -> Result<RawConfig> {
  let document: toml::Value = toml::from_str(contents).map_err(|source_error| Error::Parse {
    path: source.to_path_buf(),
    source: source_error,
  })?;
  let version = document
    .get("schema_version")
    .ok_or_else(|| Error::MissingSchemaVersion {
      path: source.to_path_buf(),
    })?
    .as_integer()
    .ok_or_else(|| Error::InvalidSchemaVersion {
      path: source.to_path_buf(),
    })?;
  if version != i64::from(SCHEMA_VERSION) {
    return Err(Error::UnsupportedSchemaVersion {
      path: source.to_path_buf(),
      found: version,
    });
  }

  toml::from_str(contents).map_err(|source_error| Error::Parse {
    path: source.to_path_buf(),
    source: source_error,
  })
}

/// Read and strictly decode a version 2 document.
///
/// Unlike the legacy loader, a missing file is always an error.
pub fn load_raw(path: &Path) -> Result<RawConfig> {
  let contents = std::fs::read_to_string(path).map_err(|source| Error::Read {
    path: path.to_path_buf(),
    source,
  })?;
  decode(&contents, path)
}

#[cfg(test)]
mod tests {
  use super::*;

  const EMPTY_V2: &str = "schema_version = 2\n";

  #[test]
  fn version_errors_are_distinct() {
    let path = Path::new("config.toml");

    assert!(matches!(decode("", path), Err(Error::MissingSchemaVersion { .. })));
    assert!(matches!(
      decode("schema_version = \"2\"", path),
      Err(Error::InvalidSchemaVersion { .. })
    ));
    assert!(matches!(
      decode("schema_version = 1", path),
      Err(Error::UnsupportedSchemaVersion { found: 1, .. })
    ));
    assert_eq!(decode(EMPTY_V2, path).unwrap().schema_version, SCHEMA_VERSION);
  }

  #[test]
  fn malformed_toml_is_a_parse_error() {
    let error = decode("schema_version = [", Path::new("broken.toml")).unwrap_err();
    assert!(matches!(error, Error::Parse { .. }));
  }

  #[test]
  fn missing_file_is_not_replaced_with_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.toml");
    let error = load_raw(&path).unwrap_err();
    assert!(matches!(error, Error::Read { source, .. } if source.kind() == std::io::ErrorKind::NotFound));
  }
}

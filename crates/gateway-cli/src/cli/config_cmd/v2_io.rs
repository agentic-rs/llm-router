#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use std::path::Path;
use tokn_config::ConfigFileSnapshot;

/// A validated version 2 config backed by an exact file snapshot.
#[derive(Debug)]
pub(super) struct V2ConfigFile {
  snapshot: ConfigFileSnapshot,
}

impl V2ConfigFile {
  /// Read exact bytes from an existing file and validate the complete v2 schema.
  pub(super) fn read(path: &Path) -> Result<Self> {
    let snapshot =
      ConfigFileSnapshot::capture(path).with_context(|| format!("capture version 2 config `{}`", path.display()))?;
    let contents = snapshot
      .contents()
      .ok_or_else(|| anyhow!("version 2 config `{}` does not exist", path.display()))?;
    validate(contents, path).context("validate existing version 2 config")?;
    Ok(Self { snapshot })
  }

  /// Path whose exact contents were captured.
  pub(super) fn path(&self) -> &Path {
    self.snapshot.path()
  }

  /// Exact bytes captured from the file, including comments and whitespace.
  pub(super) fn contents(&self) -> &[u8] {
    self
      .snapshot
      .contents()
      .expect("V2ConfigFile is only constructed from a present config")
  }

  /// Validate candidate bytes and atomically replace the unchanged snapshot.
  pub(super) fn replace_contents(&self, candidate: &[u8]) -> Result<()> {
    validate(candidate, self.path()).context("validate candidate version 2 config")?;
    tokn_config::replace_contents_if_unchanged(self.path(), Some(self.contents()), candidate)
      .with_context(|| format!("replace version 2 config `{}`", self.path().display()))
  }
}

fn validate(contents: &[u8], path: &Path) -> Result<()> {
  let contents =
    std::str::from_utf8(contents).with_context(|| format!("read version 2 config `{}` as UTF-8", path.display()))?;
  tokn_config::v2::parse(contents, path).with_context(|| format!("parse version 2 config `{}`", path.display()))?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_config::{v2, GuardedEditError};

  const VALID: &[u8] = b"# keep this comment\r\nschema_version = 2\r\n\r\n";
  const REPLACEMENT: &[u8] = b"schema_version = 2\n# replacement whitespace stays  \n";

  fn write_config(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, contents).unwrap();
    (directory, path)
  }

  #[test]
  fn reads_valid_v2_without_changing_exact_bytes() {
    let (_directory, path) = write_config(VALID);

    let file = V2ConfigFile::read(&path).unwrap();

    assert_eq!(file.path(), path);
    assert_eq!(file.contents(), VALID);
  }

  #[test]
  fn missing_file_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.toml");

    let error = V2ConfigFile::read(&path).unwrap_err();

    assert!(error.to_string().contains("does not exist"));
    assert!(!path.exists());
  }

  #[test]
  fn rejects_legacy_config() {
    let (_directory, path) = write_config(b"[server]\nport = 4141\n");

    let error = V2ConfigFile::read(&path).unwrap_err();

    assert!(matches!(
      error.downcast_ref::<v2::Error>(),
      Some(v2::Error::MissingSchemaVersion { .. })
    ));
  }

  #[test]
  fn rejects_malformed_config() {
    let (_directory, path) = write_config(b"schema_version = 2\n[listeners\n");

    let error = V2ConfigFile::read(&path).unwrap_err();

    assert!(matches!(
      error.downcast_ref::<v2::Error>(),
      Some(v2::Error::Parse { .. })
    ));
  }

  #[test]
  fn replaces_an_unchanged_file_with_exact_valid_candidate_bytes() {
    let (_directory, path) = write_config(VALID);
    let file = V2ConfigFile::read(&path).unwrap();

    file.replace_contents(REPLACEMENT).unwrap();

    assert_eq!(std::fs::read(path).unwrap(), REPLACEMENT);
  }

  #[test]
  fn invalid_candidate_leaves_the_original_unchanged() {
    let (_directory, path) = write_config(VALID);
    let file = V2ConfigFile::read(&path).unwrap();

    let error = file.replace_contents(b"schema_version = 2\n[listeners\n").unwrap_err();

    assert!(matches!(
      error.downcast_ref::<v2::Error>(),
      Some(v2::Error::Parse { .. })
    ));
    assert_eq!(std::fs::read(path).unwrap(), VALID);
  }

  #[test]
  fn concurrent_replacement_is_rejected_without_overwriting_it() {
    let (_directory, path) = write_config(VALID);
    let file = V2ConfigFile::read(&path).unwrap();
    let concurrent = b"schema_version = 2\n# written concurrently\n";
    std::fs::write(&path, concurrent).unwrap();

    let error = file.replace_contents(REPLACEMENT).unwrap_err();

    assert!(matches!(
      error.downcast_ref::<GuardedEditError>(),
      Some(GuardedEditError::Changed { path: changed }) if changed == &path
    ));
    assert_eq!(std::fs::read(path).unwrap(), concurrent);
  }
}

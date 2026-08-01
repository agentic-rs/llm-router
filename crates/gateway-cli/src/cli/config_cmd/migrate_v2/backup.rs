use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokn_config::GuardedEditError;

const LEGACY_BACKUP_SUFFIX: &str = ".legacy-v1.bak";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LegacyConfigBackup {
  pub(super) path: PathBuf,
  pub(super) created: bool,
}

pub(super) fn legacy_backup_path(config_path: &Path) -> Result<PathBuf> {
  let file_name = config_path
    .file_name()
    .ok_or_else(|| anyhow::anyhow!("config path must name a file: {}", config_path.display()))?;
  let mut backup_name = OsString::from(file_name);
  backup_name.push(LEGACY_BACKUP_SUFFIX);
  Ok(config_path.with_file_name(backup_name))
}

/// Ensure the deterministic legacy backup exists without ever replacing it.
///
/// An existing backup is reusable only when it is a direct regular file with
/// exact contents and private Unix permissions. The generic guarded config
/// writer stages and fsyncs a private file before its create-if-absent commit.
pub(super) fn ensure_legacy_backup(config_path: &Path, legacy_contents: &[u8]) -> Result<LegacyConfigBackup> {
  let path = legacy_backup_path(config_path)?;
  let lock =
    tokn_config::lock_config_file(&path).with_context(|| format!("lock legacy config backup `{}`", path.display()))?;
  if validate_existing_backup(&path, legacy_contents)? {
    return Ok(LegacyConfigBackup { path, created: false });
  }

  let created = match lock.replace_contents_if_unchanged(None, legacy_contents) {
    Ok(()) => true,
    Err(GuardedEditError::Changed { .. }) if validate_existing_backup(&path, legacy_contents)? => false,
    Err(error) => return Err(error).with_context(|| format!("create legacy config backup `{}`", path.display())),
  };
  if !validate_existing_backup(&path, legacy_contents)? {
    bail!("legacy config backup `{}` was not installed", path.display());
  }
  Ok(LegacyConfigBackup { path, created })
}

fn validate_existing_backup(path: &Path, expected: &[u8]) -> Result<bool> {
  let linked_before = match inspect_backup_path(path)? {
    Some(metadata) => metadata,
    None => return Ok(false),
  };
  let mut file = fs::File::open(path).with_context(|| format!("open legacy config backup `{}`", path.display()))?;
  let opened = file
    .metadata()
    .with_context(|| format!("inspect opened legacy config backup `{}`", path.display()))?;
  if !metadata_is_same_file(&opened, &linked_before) {
    bail!(
      "legacy config backup `{}` changed while it was being opened; retry the migration",
      path.display()
    );
  }
  require_private_permissions(path, &opened)?;
  require_single_link(path, &opened)?;

  let mut actual = Vec::new();
  file
    .read_to_end(&mut actual)
    .with_context(|| format!("read legacy config backup `{}`", path.display()))?;
  let Some(linked_after) = inspect_backup_path(path)? else {
    bail!(
      "legacy config backup `{}` disappeared while it was being read; retry the migration",
      path.display()
    );
  };
  if !metadata_is_same_file(&opened, &linked_after) {
    bail!(
      "legacy config backup `{}` changed while it was being read; retry the migration",
      path.display()
    );
  }
  if actual != expected {
    bail!(
      "legacy config backup `{}` does not match the config being migrated; refusing to overwrite it",
      path.display()
    );
  }
  Ok(true)
}

fn inspect_backup_path(path: &Path) -> Result<Option<fs::Metadata>> {
  let metadata = match fs::symlink_metadata(path) {
    Ok(metadata) => metadata,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
    Err(error) => return Err(error).with_context(|| format!("inspect legacy config backup `{}`", path.display())),
  };
  if metadata.file_type().is_symlink() {
    bail!("legacy config backup must not be a symlink: `{}`", path.display());
  }
  if !metadata.is_file() {
    bail!("legacy config backup must be a regular file: `{}`", path.display());
  }
  Ok(Some(metadata))
}

#[cfg(unix)]
fn require_private_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
  use std::os::unix::fs::PermissionsExt;

  let mode = metadata.permissions().mode() & 0o777;
  if mode & 0o077 != 0 {
    bail!(
      "legacy config backup `{}` has non-private permissions {mode:#05o}; expected no group or other access",
      path.display()
    );
  }
  Ok(())
}

#[cfg(not(unix))]
fn require_private_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
  Ok(())
}

#[cfg(unix)]
fn require_single_link(path: &Path, metadata: &fs::Metadata) -> Result<()> {
  use std::os::unix::fs::MetadataExt;

  if metadata.nlink() != 1 {
    bail!(
      "legacy config backup `{}` must not have multiple hard links",
      path.display()
    );
  }
  Ok(())
}

#[cfg(not(unix))]
fn require_single_link(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
  Ok(())
}

#[cfg(unix)]
fn metadata_is_same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
  use std::os::unix::fs::MetadataExt;

  left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn metadata_is_same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
  use std::os::windows::fs::MetadataExt;

  let left_identity = (left.volume_serial_number(), left.file_index());
  let right_identity = (right.volume_serial_number(), right.file_index());
  left_identity.0.is_none() || left_identity.1.is_none() || left_identity == right_identity
}

#[cfg(not(any(unix, windows)))]
fn metadata_is_same_file(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
  true
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn backup_path_is_adjacent_and_deterministic() {
    assert_eq!(
      legacy_backup_path(Path::new("/tmp/router/config.toml")).unwrap(),
      Path::new("/tmp/router/config.toml.legacy-v1.bak")
    );
  }

  #[test]
  fn backup_is_exact_and_reused_without_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let legacy = b"legacy config with credential\n";

    let created = ensure_legacy_backup(&config_path, legacy).unwrap();
    let reused = ensure_legacy_backup(&config_path, legacy).unwrap();

    assert!(created.created);
    assert!(!reused.created);
    assert_eq!(created.path, reused.path);
    assert_eq!(fs::read(created.path).unwrap(), legacy);
  }

  #[cfg(unix)]
  #[test]
  fn newly_created_backup_has_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let backup = ensure_legacy_backup(&directory.path().join("config.toml"), b"legacy").unwrap();

    assert_eq!(fs::metadata(backup.path).unwrap().permissions().mode() & 0o777, 0o600);
  }

  #[test]
  fn conflicting_backup_is_never_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let backup_path = legacy_backup_path(&config_path).unwrap();
    let existing = b"different legacy config";
    fs::write(&backup_path, existing).unwrap();
    make_private(&backup_path);

    let error = ensure_legacy_backup(&config_path, b"current legacy config").unwrap_err();

    assert!(error.to_string().contains("refusing to overwrite"));
    assert_eq!(fs::read(backup_path).unwrap(), existing);
  }

  #[cfg(unix)]
  #[test]
  fn non_private_existing_backup_is_rejected_without_chmod() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let backup_path = legacy_backup_path(&config_path).unwrap();
    fs::write(&backup_path, b"legacy").unwrap();
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o644)).unwrap();

    let error = ensure_legacy_backup(&config_path, b"legacy").unwrap_err();

    assert!(error.to_string().contains("non-private permissions"));
    assert_eq!(fs::metadata(backup_path).unwrap().permissions().mode() & 0o777, 0o644);
  }

  #[cfg(unix)]
  #[test]
  fn backup_symlink_is_rejected_without_touching_its_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let backup_path = legacy_backup_path(&config_path).unwrap();
    let victim = directory.path().join("victim");
    let victim_contents = b"must remain untouched";
    fs::write(&victim, victim_contents).unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&victim, &backup_path).unwrap();

    let error = ensure_legacy_backup(&config_path, victim_contents).unwrap_err();

    assert!(error.to_string().contains("must not be a symlink"));
    assert_eq!(fs::read(&victim).unwrap(), victim_contents);
    assert_eq!(fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
  }

  #[cfg(unix)]
  #[test]
  fn hard_linked_backup_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let backup_path = legacy_backup_path(&config_path).unwrap();
    let alias = directory.path().join("backup-alias");
    fs::write(&backup_path, b"legacy").unwrap();
    make_private(&backup_path);
    fs::hard_link(&backup_path, &alias).unwrap();

    let error = ensure_legacy_backup(&config_path, b"legacy").unwrap_err();

    assert!(error.to_string().contains("must not have multiple hard links"));
    assert_eq!(fs::read(&alias).unwrap(), b"legacy");
  }

  #[cfg(unix)]
  fn make_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
  }

  #[cfg(not(unix))]
  fn make_private(_path: &Path) {}
}

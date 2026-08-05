use super::{auth_shard_dir, default_auth_path, AUTH_SHARD_EXTENSION};
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// An exclusive credential-store write lease shared across processes.
///
/// The lock file is persistent, but the operating-system lock is released
/// when this value is dropped. Acquire the lock before loading when a workflow
/// needs one consistent read-modify-write transaction; ordinary
/// [`super::AuthStore::save`] calls acquire the same lock automatically.
pub struct AuthStoreLock {
  auth_path: PathBuf,
  lock_path: PathBuf,
  _file: fs::File,
}

impl std::fmt::Debug for AuthStoreLock {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("AuthStoreLock")
      .field("auth_path", &self.auth_path)
      .field("lock_path", &self.lock_path)
      .finish_non_exhaustive()
  }
}

impl AuthStoreLock {
  /// Try to acquire the write lock for an auth-store root.
  ///
  /// This is deliberately nonblocking. A competing writer produces an error
  /// so commands can ask the user to retry instead of waiting indefinitely.
  pub fn acquire(auth_path: Option<&Path>) -> Result<Self> {
    let requested = resolve_auth_path(auth_path)?;
    let parent = auth_parent(&requested);
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let auth_path = canonical_auth_path(&requested)?;
    let lock_path = auth_lock_path(&auth_path)?;
    let file =
      open_private_lock_file(&lock_path).with_context(|| format!("opening auth store lock {}", lock_path.display()))?;
    match file.try_lock() {
      Ok(()) => {
        revalidate_locked_file(&lock_path, &file)
          .with_context(|| format!("revalidating auth store lock {}", lock_path.display()))?;
        validate_direct_auth_layout(&auth_path)?;
        Ok(Self {
          auth_path,
          lock_path,
          _file: file,
        })
      }
      Err(fs::TryLockError::WouldBlock) => bail!(
        "another auth store writer is already in progress for {}; retry the command",
        auth_path.display()
      ),
      Err(fs::TryLockError::Error(error)) => {
        Err(error).with_context(|| format!("locking auth store {}", auth_path.display()))
      }
    }
  }

  /// The normalized auth-store root guarded by this lock.
  pub fn auth_path(&self) -> &Path {
    &self.auth_path
  }

  pub(super) fn ensure_matches(&self, auth_path: &Path) -> Result<()> {
    let actual = canonical_auth_path(auth_path)?;
    if actual != self.auth_path {
      bail!(
        "auth store lock for {} cannot guard {}; acquire a lock for the store being saved",
        self.auth_path.display(),
        actual.display()
      );
    }
    Ok(())
  }
}

pub(super) fn resolve_auth_path(auth_path: Option<&Path>) -> Result<PathBuf> {
  match auth_path {
    Some(path) => Ok(path.to_path_buf()),
    None => default_auth_path(),
  }
}

/// Locked write transactions accept only direct credential sources. This
/// avoids reading through a symlink and later replacing the link itself with
/// an atomic rename.
pub(super) fn validate_direct_auth_layout(root_auth_path: &Path) -> Result<()> {
  reject_auth_symlink(root_auth_path, "auth store root")?;

  let shard_dir = auth_shard_dir(root_auth_path);
  let metadata = match fs::symlink_metadata(&shard_dir) {
    Ok(metadata) if metadata.file_type().is_symlink() => {
      bail!("auth shard directory must not be a symlink: {}", shard_dir.display())
    }
    Ok(metadata) => metadata,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
    Err(error) => return Err(error).with_context(|| format!("inspecting {}", shard_dir.display())),
  };
  if !metadata.is_dir() {
    bail!("auth shard path must be a directory: {}", shard_dir.display());
  }
  for entry in fs::read_dir(&shard_dir).with_context(|| format!("reading {}", shard_dir.display()))? {
    let entry = entry?;
    let path = entry.path();
    if path.extension().and_then(|extension| extension.to_str()) == Some(AUTH_SHARD_EXTENSION)
      && entry.file_type()?.is_symlink()
    {
      bail!("auth shard must not be a symlink: {}", path.display());
    }
  }
  Ok(())
}

fn reject_auth_symlink(path: &Path, description: &str) -> Result<()> {
  match fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_symlink() => {
      bail!("{description} must not be a symlink: {}", path.display())
    }
    Ok(_) => Ok(()),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
  }
}

fn auth_parent(path: &Path) -> &Path {
  path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."))
}

fn canonical_auth_path(path: &Path) -> Result<PathBuf> {
  let file_name = path
    .file_name()
    .ok_or_else(|| anyhow!("auth store path must name a file: {}", path.display()))?;
  let parent = auth_parent(path);
  let parent =
    fs::canonicalize(parent).with_context(|| format!("resolving auth store directory {}", parent.display()))?;
  Ok(parent.join(file_name))
}

fn auth_lock_path(auth_path: &Path) -> Result<PathBuf> {
  let file_name = auth_path
    .file_name()
    .ok_or_else(|| anyhow!("auth store path must name a file: {}", auth_path.display()))?;
  let mut lock_name = OsString::from(".");
  lock_name.push(file_name);
  lock_name.push(".lock");
  Ok(auth_parent(auth_path).join(lock_name))
}

#[cfg(unix)]
fn open_private_lock_file(path: &Path) -> std::io::Result<fs::File> {
  use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

  validate_lock_path_before_open(path)?;
  let file = fs::OpenOptions::new()
    .create(true)
    .truncate(false)
    .read(true)
    .write(true)
    .mode(0o600)
    .open(path)?;
  revalidate_locked_file(path, &file)?;
  file.set_permissions(fs::Permissions::from_mode(0o600))?;
  Ok(file)
}

#[cfg(not(unix))]
fn open_private_lock_file(path: &Path) -> std::io::Result<fs::File> {
  validate_lock_path_before_open(path)?;
  let file = fs::OpenOptions::new()
    .create(true)
    .truncate(false)
    .read(true)
    .write(true)
    .open(path)?;
  revalidate_locked_file(path, &file)?;
  Ok(file)
}

#[cfg(unix)]
fn revalidate_locked_file(path: &Path, file: &fs::File) -> std::io::Result<()> {
  use std::os::unix::fs::MetadataExt;

  let opened = file.metadata()?;
  let linked = validate_opened_lock_path(path)?;
  if opened.dev() != linked.dev() || opened.ino() != linked.ino() {
    return Err(invalid_lock_file(path, "changed while it was being opened or locked"));
  }
  if opened.nlink() != 1 {
    return Err(invalid_lock_file(path, "must not have multiple hard links"));
  }
  Ok(())
}

#[cfg(windows)]
fn revalidate_locked_file(path: &Path, file: &fs::File) -> std::io::Result<()> {
  validate_opened_lock_path(path)?;
  let opened = tokn_config::FileIdentity::from_file(file)?;
  let linked = tokn_config::FileIdentity::from_path(path)?;
  if opened != linked {
    return Err(invalid_lock_file(path, "changed while it was being opened or locked"));
  }
  Ok(())
}

#[cfg(not(any(unix, windows)))]
fn revalidate_locked_file(path: &Path, _file: &fs::File) -> std::io::Result<()> {
  validate_opened_lock_path(path)?;
  Ok(())
}

fn validate_lock_path_before_open(path: &Path) -> std::io::Result<()> {
  match fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_symlink() => Err(invalid_lock_file(path, "must not be a symlink")),
    Ok(metadata) if !metadata.is_file() => Err(invalid_lock_file(path, "must be a regular file")),
    Ok(_) => Ok(()),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(error) => Err(error),
  }
}

fn validate_opened_lock_path(path: &Path) -> std::io::Result<fs::Metadata> {
  let metadata = fs::symlink_metadata(path)?;
  if metadata.file_type().is_symlink() {
    return Err(invalid_lock_file(path, "must not be a symlink"));
  }
  if !metadata.is_file() {
    return Err(invalid_lock_file(path, "must be a regular file"));
  }
  Ok(metadata)
}

fn invalid_lock_file(path: &Path, reason: &str) -> std::io::Error {
  std::io::Error::new(
    std::io::ErrorKind::InvalidInput,
    format!("auth store lock {} {reason}", path.display()),
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn lock_is_nonblocking_and_released_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.yaml");
    let lock = AuthStoreLock::acquire(Some(&path)).unwrap();

    let error = AuthStoreLock::acquire(Some(&path)).unwrap_err();

    assert!(error
      .to_string()
      .contains("another auth store writer is already in progress"));
    drop(lock);
    AuthStoreLock::acquire(Some(&path)).unwrap();
    assert!(dir.path().join(".auth.yaml.lock").exists());
  }

  #[cfg(unix)]
  #[test]
  fn lock_rejects_a_symlink_without_touching_its_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.yaml");
    let lock_path = dir.path().join(".auth.yaml.lock");
    let victim = dir.path().join("victim");
    let victim_contents = b"must remain untouched\n";
    fs::write(&victim, victim_contents).unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&victim, &lock_path).unwrap();

    let error = AuthStoreLock::acquire(Some(&auth_path)).unwrap_err();

    assert!(format!("{error:#}").contains("must not be a symlink"));
    assert_eq!(fs::read(&victim).unwrap(), victim_contents);
    assert_eq!(fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
  }

  #[cfg(unix)]
  #[test]
  fn locked_file_revalidation_rejects_a_replaced_path() {
    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join(".auth.yaml.lock");
    let displaced_path = dir.path().join("displaced.lock");
    let file = open_private_lock_file(&lock_path).unwrap();
    file.try_lock().unwrap();
    fs::rename(&lock_path, &displaced_path).unwrap();
    fs::write(&lock_path, "replacement").unwrap();

    let error = revalidate_locked_file(&lock_path, &file).unwrap_err();

    assert!(error
      .to_string()
      .contains("changed while it was being opened or locked"));
  }

  #[cfg(unix)]
  #[test]
  fn locked_transactions_reject_indirect_auth_sources() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();

    let root_target = dir.path().join("root-target.yaml");
    let root_link = dir.path().join("root-link.yaml");
    fs::write(&root_target, "root").unwrap();
    symlink(&root_target, &root_link).unwrap();
    let root_error = AuthStoreLock::acquire(Some(&root_link)).unwrap_err();
    assert!(root_error.to_string().contains("auth store root must not be a symlink"));

    let directory_case = dir.path().join("directory-case");
    let external_shards = dir.path().join("external-shards");
    fs::create_dir_all(&directory_case).unwrap();
    fs::create_dir_all(&external_shards).unwrap();
    symlink(&external_shards, directory_case.join(super::super::AUTH_SHARD_DIR_NAME)).unwrap();
    let directory_error = AuthStoreLock::acquire(Some(&directory_case.join(super::super::AUTH_FILE_NAME))).unwrap_err();
    assert!(directory_error
      .to_string()
      .contains("auth shard directory must not be a symlink"));

    let shard_case = dir.path().join("shard-case");
    let shard_dir = shard_case.join(super::super::AUTH_SHARD_DIR_NAME);
    let shard_target = dir.path().join("shard-target.yaml");
    fs::create_dir_all(&shard_dir).unwrap();
    fs::write(&shard_target, "shard").unwrap();
    symlink(&shard_target, shard_dir.join("linked.yaml")).unwrap();
    let shard_error = AuthStoreLock::acquire(Some(&shard_case.join(super::super::AUTH_FILE_NAME))).unwrap_err();
    assert!(shard_error.to_string().contains("auth shard must not be a symlink"));
  }
}

use crate::adapter::ProviderRoute;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use tokn_core::AgentId;

pub(crate) const CURRENT_VERSION: u32 = 5;

pub(crate) struct AgentMigrationLock {
  _file: std::fs::File,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationManifest {
  pub version: u32,
  #[serde(default = "default_completed")]
  pub completed: bool,
  pub agent: AgentId,
  pub timestamp: String,
  pub profile: Option<String>,
  pub target_base_url: String,
  #[serde(default)]
  pub gateway_auth_path: Option<PathBuf>,
  /// Agent-owned credential shard within the gateway auth store. Older
  /// manifests stored imported credentials directly in `gateway_auth_path`,
  /// so the absence of this field retains that restore behavior.
  #[serde(default)]
  pub gateway_auth_shard_path: Option<PathBuf>,
  #[serde(default)]
  pub agent_auth_path: Option<PathBuf>,
  #[serde(default)]
  pub provider_routes: Vec<ProviderRoute>,
  #[serde(default)]
  pub previous_manifest: Option<PathBuf>,
  #[serde(default)]
  pub unlinked: bool,
  #[serde(default)]
  pub credentials_handoff_complete: bool,
  pub imported_account_ids: Vec<String>,
  pub files: Vec<FileBackup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileBackup {
  pub original: PathBuf,
  pub backup: Option<PathBuf>,
  pub existed: bool,
  pub created_by_migration: bool,
  /// SHA-256 of the last bytes checkpointed by a v5 link or sync. Legacy
  /// manifests omit this field. An incomplete v5 manifest may omit it only
  /// for a path that had not yet been checkpointed.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub applied_sha256: Option<String>,
}

impl MigrationManifest {
  pub(crate) fn in_progress(mut self) -> Self {
    self.completed = false;
    self
  }

  pub(crate) fn complete(mut self) -> Self {
    self.completed = true;
    self
  }
}

pub(crate) fn manifest_path(timestamp: &str, agent: &AgentId) -> Result<PathBuf> {
  Ok(manifest_dir()?.join(format!("{timestamp}-{}.json", agent.as_str())))
}

pub(crate) fn try_lock_agent(agent: &AgentId) -> Result<AgentMigrationLock> {
  let dir = manifest_dir()?;
  try_lock_agent_in(&dir, agent)
}

pub(crate) fn try_lock_agent_in(dir: &Path, agent: &AgentId) -> Result<AgentMigrationLock> {
  std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
  let path = dir.join(format!(".{}.lock", agent.as_str()));
  let file = std::fs::OpenOptions::new()
    .create(true)
    .truncate(false)
    .read(true)
    .write(true)
    .open(&path)
    .with_context(|| format!("opening agent migration lock {}", path.display()))?;
  file
    .try_lock()
    .with_context(|| format!("another {} link, sync, or unlink is already in progress", agent))?;
  Ok(AgentMigrationLock { _file: file })
}

pub(crate) fn resolve_manifest(agent: &AgentId, backup_id: Option<&str>) -> Result<PathBuf> {
  if let Some(id) = backup_id {
    let path = PathBuf::from(id);
    if path.exists() {
      return std::path::absolute(&path).with_context(|| format!("resolving manifest path {}", path.display()));
    }
    let candidate = manifest_dir()?.join(if id.ends_with(".json") {
      id.to_string()
    } else {
      format!("{id}-{}.json", agent.as_str())
    });
    if candidate.exists() {
      return Ok(candidate);
    }
    bail!("backup manifest not found: {id}");
  }

  latest_active_manifest(agent)?.ok_or_else(|| anyhow!("no active migration manifest found for {}", agent.as_str()))
}

pub(crate) fn latest_active_manifest(agent: &AgentId) -> Result<Option<PathBuf>> {
  let dir = manifest_dir()?;
  latest_active_manifest_in(&dir, agent)
}

fn latest_active_manifest_in(dir: &Path, agent: &AgentId) -> Result<Option<PathBuf>> {
  let suffix = format!("-{}.json", agent.as_str());
  let mut candidates = Vec::new();
  if dir.exists() {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
      let entry = entry?;
      let path = entry.path();
      if path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(&suffix))
        .unwrap_or(false)
      {
        candidates.push(path);
      }
    }
  }
  candidates.sort();
  for path in candidates.into_iter().rev() {
    let manifest = read_manifest(&path)?;
    if !manifest.unlinked {
      return Ok(Some(path));
    }
  }
  Ok(None)
}

pub(crate) fn read_manifest(path: &Path) -> Result<MigrationManifest> {
  let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
  serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

pub(crate) fn prepare_manifest_for_restore(
  path: &Path,
  mut manifest: MigrationManifest,
  legacy_root: Option<&Path>,
) -> Result<MigrationManifest> {
  let Some(relative) = first_relative_path(&manifest) else {
    return Ok(manifest);
  };
  if manifest.version >= CURRENT_VERSION {
    bail!(
      "migration manifest {} contains relative restore path '{}'; refusing to interpret it",
      path.display(),
      relative.display()
    );
  }
  let root = legacy_root.ok_or_else(|| {
    anyhow!(
      "legacy migration manifest {} contains relative restore path '{}'; supply the original link working directory as an explicit legacy root",
      path.display(),
      relative.display()
    )
  })?;
  if !root.is_absolute() {
    bail!(
      "legacy manifest compatibility root must be absolute: {}",
      root.display()
    );
  }
  normalize_legacy_paths(&mut manifest, root)?;
  Ok(manifest)
}

pub(crate) fn first_relative_path(manifest: &MigrationManifest) -> Option<&Path> {
  manifest
    .gateway_auth_path
    .iter()
    .chain(manifest.gateway_auth_shard_path.iter())
    .chain(manifest.agent_auth_path.iter())
    .chain(manifest.previous_manifest.iter())
    .chain(manifest.files.iter().map(|file| &file.original))
    .chain(manifest.files.iter().filter_map(|file| file.backup.as_ref()))
    .find(|path| path.is_relative())
    .map(PathBuf::as_path)
}

fn normalize_legacy_paths(manifest: &mut MigrationManifest, root: &Path) -> Result<()> {
  for path in manifest
    .gateway_auth_path
    .iter_mut()
    .chain(manifest.gateway_auth_shard_path.iter_mut())
    .chain(manifest.agent_auth_path.iter_mut())
    .chain(manifest.previous_manifest.iter_mut())
  {
    if path.is_relative() {
      *path = resolve_legacy_path(root, path)?;
    }
  }
  for file in &mut manifest.files {
    if file.original.is_relative() {
      file.original = resolve_legacy_path(root, &file.original)?;
    }
    if let Some(backup) = &mut file.backup {
      if backup.is_relative() {
        *backup = resolve_legacy_path(root, backup)?;
      }
    }
  }
  Ok(())
}

fn resolve_legacy_path(root: &Path, relative: &Path) -> Result<PathBuf> {
  let joined = root.join(relative);
  if root
    .try_exists()
    .with_context(|| format!("checking legacy manifest compatibility root {}", root.display()))?
  {
    // Preserve filesystem `..` traversal through any symlinks under a real
    // legacy working directory.
    return Ok(joined);
  }

  let ancestor = deepest_existing_ancestor(root)?;
  let mut resolved = ancestor.canonicalize().with_context(|| {
    format!(
      "resolving existing ancestor {} of missing legacy root",
      ancestor.display()
    )
  })?;
  if !resolved.is_dir() {
    bail!(
      "existing ancestor {} of missing legacy root {} is not a directory",
      ancestor.display(),
      root.display()
    );
  }

  let suffix = root
    .strip_prefix(ancestor)
    .expect("an ancestor is always a lexical prefix");
  let mut missing_depth = 0usize;
  for component in suffix.components() {
    match component {
      Component::CurDir => {}
      Component::Normal(segment) => {
        resolved.push(segment);
        missing_depth += 1;
      }
      Component::ParentDir => {
        bail!(
          "missing legacy root {} contains an unresolved parent component; supply its physical path instead",
          root.display()
        );
      }
      Component::Prefix(_) | Component::RootDir => unreachable!("a stripped path suffix is relative"),
    }
  }

  resolve_from_missing_root(resolved, missing_depth, relative, root)
}

fn deepest_existing_ancestor(root: &Path) -> Result<&Path> {
  for candidate in root.ancestors() {
    if candidate
      .try_exists()
      .with_context(|| format!("checking ancestor {} of missing legacy root", candidate.display()))?
    {
      return Ok(candidate);
    }
    match std::fs::symlink_metadata(candidate) {
      Ok(metadata) if metadata.file_type().is_symlink() => {
        bail!(
          "cannot safely resolve missing legacy root {} through dangling symbolic link {}",
          root.display(),
          candidate.display()
        );
      }
      Ok(_) => {}
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Err(error) => {
        return Err(error)
          .with_context(|| format!("inspecting ancestor {} of missing legacy root", candidate.display()));
      }
    }
  }
  bail!(
    "cannot find an existing ancestor for missing legacy manifest compatibility root {}",
    root.display()
  )
}

fn resolve_from_missing_root(
  mut resolved: PathBuf,
  mut missing_depth: usize,
  relative: &Path,
  root: &Path,
) -> Result<PathBuf> {
  let mut current_is_directory = true;
  let mut components = relative.components().peekable();
  while let Some(component) = components.next() {
    if !current_is_directory {
      bail!(
        "legacy restore path '{}' traverses through non-directory {}",
        relative.display(),
        resolved.display()
      );
    }
    match component {
      Component::CurDir => {}
      Component::ParentDir => {
        resolved.pop();
        missing_depth = missing_depth.saturating_sub(1);
      }
      Component::Normal(segment) if missing_depth > 0 => {
        resolved.push(segment);
        missing_depth += 1;
      }
      Component::Normal(segment) => {
        let candidate = resolved.join(segment);
        if components.peek().is_none() {
          // The manifest records a pathname, not the identity of its current
          // target. Preserve a terminal symlink so rollback removes or
          // replaces that link rather than acting on the linked-to file.
          resolved = candidate;
          continue;
        }
        if candidate
          .try_exists()
          .with_context(|| format!("checking legacy restore path {}", candidate.display()))?
        {
          let metadata = std::fs::metadata(&candidate)
            .with_context(|| format!("reading metadata for legacy restore path {}", candidate.display()))?;
          resolved = candidate
            .canonicalize()
            .with_context(|| format!("resolving legacy restore path {}", candidate.display()))?;
          current_is_directory = metadata.is_dir();
        } else {
          match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
              bail!(
                "cannot safely resolve legacy restore path '{}' through dangling symbolic link {}",
                relative.display(),
                candidate.display()
              );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
              return Err(error).with_context(|| format!("inspecting legacy restore path {}", candidate.display()));
            }
          }
          resolved = candidate;
          missing_depth = 1;
        }
      }
      Component::Prefix(_) | Component::RootDir => {
        bail!(
          "legacy restore path '{}' is not relative to compatibility root {}",
          relative.display(),
          root.display()
        );
      }
    }
  }
  Ok(resolved)
}

/// Record a backup entry and return the entry's authoritative `existed`
/// observation. Repeated calls return the value recorded by the first call.
pub(crate) fn backup_path_for(path: &Path, timestamp: &str, files: &mut Vec<FileBackup>) -> Result<bool> {
  if let Some(existing) = files.iter().find(|file| file.original == path) {
    return Ok(existing.existed);
  }
  let existed = path.exists();
  let backup = if existed {
    let backup = adjacent_backup_path(path, timestamp)?;
    std::fs::copy(path, &backup).with_context(|| format!("backing up {} to {}", path.display(), backup.display()))?;
    Some(backup)
  } else {
    None
  };
  files.push(FileBackup {
    original: path.to_path_buf(),
    backup,
    existed,
    created_by_migration: false,
    applied_sha256: None,
  });
  Ok(existed)
}

/// Back up a credential file without leaving a world-readable token copy.
/// Generic migration backups preserve their original permissions, but auth
/// shards are always secrets and should be private even when their source was
/// accidentally created with a broader mode.
///
/// Returns the same authoritative `existed` observation stored in the backup
/// entry, including when that entry was created by an earlier call.
pub(crate) fn backup_sensitive_path_for(path: &Path, timestamp: &str, files: &mut Vec<FileBackup>) -> Result<bool> {
  if let Some(existing) = files.iter().find(|file| file.original == path) {
    return Ok(existing.existed);
  }
  let existed = path.exists();
  let backup = if existed {
    let backup = adjacent_backup_path(path, timestamp)?;
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    write_private_file(&backup, &bytes)?;
    Some(backup)
  } else {
    None
  };
  files.push(FileBackup {
    original: path.to_path_buf(),
    backup,
    existed,
    created_by_migration: false,
    applied_sha256: None,
  });
  Ok(existed)
}

pub(crate) fn validate_applied_digests<'a>(files: impl IntoIterator<Item = &'a FileBackup>) -> Result<()> {
  for file in files {
    let expected = file.applied_sha256.as_deref().ok_or_else(|| {
      anyhow!(
        "managed migration file {} was not checkpointed; refusing to complete the link or sync",
        file.original.display()
      )
    })?;
    let bytes = std::fs::read(&file.original)
      .with_context(|| format!("reading applied migration file {}", file.original.display()))?;
    if sha256(&bytes) != expected {
      bail!(
        "managed migration file {} changed after it was written; refusing to complete the link or sync",
        file.original.display()
      );
    }
  }
  Ok(())
}

pub(crate) fn set_applied_digest_for_path(files: &mut [FileBackup], path: &Path, digest: String) -> bool {
  let Some(file) = files.iter_mut().find(|file| file.original == path) else {
    return false;
  };
  file.applied_sha256 = Some(digest);
  true
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
  tokn_core::util::digest::sha256_hex(bytes)
}

pub(crate) fn restore_sensitive_path_from_backup(backup: &Path, destination: &Path) -> Result<()> {
  let bytes = std::fs::read(backup).with_context(|| format!("reading {}", backup.display()))?;
  write_private_file(destination, &bytes)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
  use std::io::Write;
  use std::os::unix::fs::OpenOptionsExt;
  use std::sync::atomic::{AtomicU64, Ordering};

  static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

  let parent = path
    .parent()
    .ok_or_else(|| anyhow!("cannot write path without parent: {}", path.display()))?;
  std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
  let file_name = path
    .file_name()
    .and_then(|name| name.to_str())
    .ok_or_else(|| anyhow!("cannot write path without file name: {}", path.display()))?;

  for _ in 0..16 {
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{file_name}.tokn-{:#x}-{sequence}.tmp", std::process::id()));
    let file = match std::fs::OpenOptions::new()
      .create_new(true)
      .write(true)
      .mode(0o600)
      .open(&temporary)
    {
      Ok(file) => file,
      Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
      Err(error) => {
        return Err(error).with_context(|| format!("creating private temporary file {}", temporary.display()));
      }
    };
    let result = (|| -> Result<()> {
      let mut file = file;
      file
        .write_all(bytes)
        .with_context(|| format!("writing private temporary file {}", temporary.display()))?;
      file
        .sync_all()
        .with_context(|| format!("syncing private temporary file {}", temporary.display()))?;
      drop(file);
      std::fs::rename(&temporary, path)
        .with_context(|| format!("replacing {} with private temporary file", path.display()))?;
      Ok(())
    })();
    if result.is_err() {
      let _ = std::fs::remove_file(&temporary);
    }
    return result;
  }
  bail!("could not allocate a private temporary file for {}", path.display())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
  }
  std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
  Ok(())
}

pub(crate) fn mark_created(files: &mut [FileBackup], path: &Path, existed: bool) {
  if !existed {
    if let Some(file) = files.iter_mut().find(|file| file.original == path) {
      file.created_by_migration = true;
    }
  }
}

pub(crate) fn adjacent_backup_path(path: &Path, timestamp: &str) -> Result<PathBuf> {
  let name = path
    .file_name()
    .and_then(|name| name.to_str())
    .ok_or_else(|| anyhow!("cannot back up path without file name: {}", path.display()))?;
  Ok(path.with_file_name(format!("{name}.bak.{timestamp}")))
}

pub(crate) fn write_manifest(path: &Path, manifest: &MigrationManifest) -> Result<()> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
  }
  std::fs::write(path, serde_json::to_vec_pretty(manifest)?).with_context(|| format!("writing {}", path.display()))
}

fn manifest_dir() -> Result<PathBuf> {
  Ok(tokn_config::paths::config_dir()?.join("agent-migrations"))
}

fn default_completed() -> bool {
  true
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn adjacent_backup_keeps_original_name() {
    let path = PathBuf::from("/tmp/auth.json");
    assert_eq!(
      adjacent_backup_path(&path, "20260604T153012Z").unwrap(),
      PathBuf::from("/tmp/auth.json.bak.20260604T153012Z")
    );
  }

  #[test]
  fn backup_path_for_records_missing_file_without_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.json");
    let mut files = Vec::new();

    assert!(!backup_path_for(&path, "20260604T153012Z", &mut files).unwrap());
    std::fs::write(&path, "created later").unwrap();
    assert!(!backup_path_for(&path, "20260604T153012Z", &mut files).unwrap());

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].original, path);
    assert_eq!(files[0].backup, None);
    assert!(!files[0].existed);
    assert!(!files[0].created_by_migration);
  }

  #[test]
  fn backup_path_for_copies_existing_file_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.json");
    std::fs::write(&path, "original").unwrap();
    let mut files = Vec::new();

    assert!(backup_path_for(&path, "20260604T153012Z", &mut files).unwrap());
    std::fs::remove_file(&path).unwrap();
    assert!(backup_path_for(&path, "20260604T153012Z", &mut files).unwrap());

    assert_eq!(files.len(), 1);
    let backup = files[0].backup.as_ref().unwrap();
    assert_eq!(backup, &dir.path().join("auth.json.bak.20260604T153012Z"));
    assert_eq!(std::fs::read_to_string(backup).unwrap(), "original");
    assert!(files[0].existed);
  }

  #[cfg(unix)]
  #[test]
  fn sensitive_backup_is_private_even_when_source_is_not() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.d/opencode.yaml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "secret").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut files = Vec::new();

    assert!(backup_sensitive_path_for(&path, "20260604T153012Z", &mut files).unwrap());

    let backup = files[0].backup.as_ref().unwrap();
    assert_eq!(std::fs::metadata(backup).unwrap().permissions().mode() & 0o777, 0o600);
  }

  #[cfg(unix)]
  #[test]
  fn sensitive_restore_replaces_destination_with_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("opencode.yaml.bak");
    let destination = dir.path().join("auth.d/opencode.yaml");
    std::fs::write(&backup, "secret").unwrap();
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, "old").unwrap();
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o644)).unwrap();

    restore_sensitive_path_from_backup(&backup, &destination).unwrap();

    assert_eq!(std::fs::read_to_string(&destination).unwrap(), "secret");
    assert_eq!(
      std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
      0o600
    );
  }

  #[test]
  fn mark_created_only_marks_new_files() {
    let existing = PathBuf::from("existing");
    let created = PathBuf::from("created");
    let mut files = vec![
      FileBackup {
        original: existing.clone(),
        backup: None,
        existed: true,
        created_by_migration: false,
        applied_sha256: None,
      },
      FileBackup {
        original: created.clone(),
        backup: None,
        existed: false,
        created_by_migration: false,
        applied_sha256: None,
      },
    ];

    mark_created(&mut files, &existing, true);
    mark_created(&mut files, &created, false);

    assert!(!files[0].created_by_migration);
    assert!(files[1].created_by_migration);
  }

  #[test]
  fn applied_digest_validation_rejects_changes_after_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, b"linked config").unwrap();
    let mut files = vec![FileBackup {
      original: path.clone(),
      backup: None,
      existed: false,
      created_by_migration: true,
      applied_sha256: None,
    }];

    assert!(set_applied_digest_for_path(&mut files, &path, sha256(b"linked config")));

    assert_eq!(
      files[0].applied_sha256.as_deref(),
      Some("ce7dbbfbdaf29a44bfc74f1f02d919a58af05dac4c2a2cad822b6bc56deef164")
    );
    validate_applied_digests(&files).unwrap();

    std::fs::write(path, b"user edit").unwrap();
    let error = validate_applied_digests(&files).unwrap_err();
    assert!(error.to_string().contains("changed after it was written"));
  }

  #[test]
  fn resolve_manifest_accepts_full_path_and_rejects_missing_id() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("20260604T153012Z-codex-cli.json");
    std::fs::write(&manifest, "{}").unwrap();

    assert_eq!(
      resolve_manifest(&AgentId::CodexCli, Some(manifest.to_str().unwrap())).unwrap(),
      manifest
    );
    assert!(resolve_manifest(&AgentId::CodexCli, Some("does-not-exist")).is_err());
  }

  #[test]
  fn manifest_without_completed_field_defaults_to_complete() {
    let manifest: MigrationManifest = serde_json::from_str(
      r#"{
        "version": 1,
        "agent": "codex-cli",
        "timestamp": "20260604T153012Z",
        "profile": "codex",
        "target_base_url": "http://127.0.0.1:4141/codex/v1",
        "imported_account_ids": [],
        "files": []
      }"#,
    )
    .unwrap();

    assert!(manifest.completed);
  }

  #[test]
  fn legacy_file_backup_without_applied_digest_remains_readable() {
    let backup: FileBackup = serde_json::from_str(
      r#"{
        "original": "/tmp/opencode.json",
        "backup": "/tmp/opencode.json.bak",
        "existed": true,
        "created_by_migration": false
      }"#,
    )
    .unwrap();

    assert_eq!(backup.applied_sha256, None);
  }

  #[test]
  fn legacy_relative_paths_require_an_explicit_compatibility_root() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("legacy.json");
    let manifest: MigrationManifest = serde_json::from_str(
      r#"{
        "version": 4,
        "agent": "opencode",
        "timestamp": "20260729T000000Z",
        "profile": "opencode",
        "target_base_url": "http://127.0.0.1:4141/opencode/v1",
        "gateway_auth_path": "gateway/auth.yaml",
        "previous_manifest": "manifests/previous.json",
        "imported_account_ids": [],
        "files": [{
          "original": "gateway/config.d/opencode.toml",
          "backup": "gateway/config.d/opencode.toml.bak",
          "existed": true,
          "created_by_migration": false
        }]
      }"#,
    )
    .unwrap();
    write_manifest(&manifest_path, &manifest).unwrap();
    let error = prepare_manifest_for_restore(&manifest_path, read_manifest(&manifest_path).unwrap(), None).unwrap_err();
    assert!(error.to_string().contains("explicit legacy root"));

    let root = dir.path().join("legacy-invocation");
    let manifest =
      prepare_manifest_for_restore(&manifest_path, read_manifest(&manifest_path).unwrap(), Some(&root)).unwrap();
    let resolved_root = dir.path().canonicalize().unwrap().join("legacy-invocation");

    assert_eq!(
      manifest.gateway_auth_path.as_deref(),
      Some(resolved_root.join("gateway/auth.yaml").as_path())
    );
    assert_eq!(
      manifest.previous_manifest.as_deref(),
      Some(resolved_root.join("manifests/previous.json").as_path())
    );
    assert_eq!(
      manifest.files[0].original,
      resolved_root.join("gateway/config.d/opencode.toml")
    );
    assert_eq!(
      manifest.files[0].backup.as_deref(),
      Some(resolved_root.join("gateway/config.d/opencode.toml.bak").as_path())
    );
  }

  #[test]
  fn missing_legacy_root_normalizes_parent_components_from_existing_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("existing");
    std::fs::create_dir_all(&existing).unwrap();
    let missing_root = existing.join("deleted/nested");

    let resolved = resolve_legacy_path(&missing_root, Path::new("../../config.toml")).unwrap();

    assert_eq!(resolved, existing.canonicalize().unwrap().join("config.toml"));
  }

  #[cfg(unix)]
  #[test]
  fn missing_legacy_root_resolves_symlinked_existing_ancestor_physically() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let physical = dir.path().join("physical/work");
    let logical = dir.path().join("logical");
    std::fs::create_dir_all(&physical).unwrap();
    symlink(&physical, &logical).unwrap();
    let missing_root = logical.join("deleted/nested");

    let resolved = resolve_legacy_path(&missing_root, Path::new("../../config.toml")).unwrap();

    assert_eq!(resolved, physical.canonicalize().unwrap().join("config.toml"));
  }

  #[cfg(unix)]
  #[test]
  fn missing_legacy_root_preserves_a_terminal_symlink() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let physical = dir.path().join("physical/work");
    let logical = dir.path().join("logical");
    let target = dir.path().join("user-owned-target");
    std::fs::create_dir_all(&physical).unwrap();
    std::fs::write(&target, "keep").unwrap();
    symlink(&physical, &logical).unwrap();
    symlink(&target, physical.join("managed")).unwrap();
    let missing_root = logical.join("deleted/nested");

    let resolved = resolve_legacy_path(&missing_root, Path::new("../../managed")).unwrap();

    assert_eq!(resolved, physical.canonicalize().unwrap().join("managed"));
    assert!(std::fs::symlink_metadata(&resolved).unwrap().file_type().is_symlink());
    std::fs::remove_file(resolved).unwrap();
    assert_eq!(std::fs::read_to_string(target).unwrap(), "keep");
  }

  #[cfg(unix)]
  #[test]
  fn missing_legacy_root_refuses_a_dangling_symlink_ancestor() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let dangling = dir.path().join("dangling");
    symlink(dir.path().join("missing-target"), &dangling).unwrap();

    let error = resolve_legacy_path(&dangling.join("deleted"), Path::new("../config.toml")).unwrap_err();

    assert!(error.to_string().contains("dangling symbolic link"));
  }

  #[test]
  fn current_manifests_never_accept_relative_restore_paths() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("current.json");
    let manifest = MigrationManifest {
      version: CURRENT_VERSION,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260729T000000Z".into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: None,
      gateway_auth_shard_path: None,
      agent_auth_path: None,
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: true,
      imported_account_ids: Vec::new(),
      files: vec![FileBackup {
        original: "relative/config.toml".into(),
        backup: None,
        existed: false,
        created_by_migration: true,
        applied_sha256: None,
      }],
    };
    write_manifest(&manifest_path, &manifest).unwrap();

    let error = prepare_manifest_for_restore(&manifest_path, read_manifest(&manifest_path).unwrap(), Some(dir.path()))
      .unwrap_err();

    assert!(error.to_string().contains("refusing to interpret"));
  }

  #[test]
  fn incomplete_manifest_remains_active_until_it_is_unlinked() {
    let dir = tempfile::tempdir().unwrap();
    let older = dir.path().join("20260729T000000Z-opencode.json");
    let pending = dir.path().join("20260729T000001Z-opencode.json");
    let base = MigrationManifest {
      version: 4,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260729T000000Z".into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: None,
      gateway_auth_shard_path: None,
      agent_auth_path: None,
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: true,
      imported_account_ids: Vec::new(),
      files: Vec::new(),
    };
    write_manifest(&older, &base).unwrap();
    write_manifest(
      &pending,
      &MigrationManifest {
        completed: false,
        timestamp: "20260729T000001Z".into(),
        previous_manifest: Some(older),
        ..base
      },
    )
    .unwrap();

    assert_eq!(
      latest_active_manifest_in(dir.path(), &AgentId::Opencode).unwrap(),
      Some(pending)
    );
  }
}

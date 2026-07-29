use crate::adapter::ProviderRoute;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokn_core::AgentId;

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

pub(crate) fn backup_path_for(path: &Path, timestamp: &str, files: &mut Vec<FileBackup>) -> Result<()> {
  if files.iter().any(|file| file.original == path) {
    return Ok(());
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
  });
  Ok(())
}

/// Back up a credential file without leaving a world-readable token copy.
/// Generic migration backups preserve their original permissions, but auth
/// shards are always secrets and should be private even when their source was
/// accidentally created with a broader mode.
pub(crate) fn backup_sensitive_path_for(path: &Path, timestamp: &str, files: &mut Vec<FileBackup>) -> Result<()> {
  if files.iter().any(|file| file.original == path) {
    return Ok(());
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
  });
  Ok(())
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

    backup_path_for(&path, "20260604T153012Z", &mut files).unwrap();

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

    backup_path_for(&path, "20260604T153012Z", &mut files).unwrap();
    backup_path_for(&path, "20260604T153012Z", &mut files).unwrap();

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

    backup_sensitive_path_for(&path, "20260604T153012Z", &mut files).unwrap();

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
      },
      FileBackup {
        original: created.clone(),
        backup: None,
        existed: false,
        created_by_migration: false,
      },
    ];

    mark_created(&mut files, &existing, true);
    mark_created(&mut files, &created, false);

    assert!(!files[0].created_by_migration);
    assert!(files[1].created_by_migration);
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

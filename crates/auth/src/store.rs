//! Credential storage rooted at `auth.yaml`.
//!
//! The root file is for user-managed and shared accounts. Linked agents can
//! own a credential-only shard in the sibling `auth.d/` directory. The store
//! presents the merged account pool to callers while retaining each account's
//! source so refreshes and removals never flatten agent credentials into the
//! root file.

mod lock;

use anyhow::{anyhow, bail, Context, Result};
pub use lock::AuthStoreLock;
use lock::{resolve_auth_path, validate_direct_auth_layout};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokn_core::account::AccountConfig;

const CURRENT_VERSION: u32 = 1;
const AUTH_FILE_NAME: &str = "auth.yaml";
const AUTH_SHARD_DIR_NAME: &str = "auth.d";
const AUTH_SHARD_EXTENSION: &str = "yaml";

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A credential source contributing to the effective account pool.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthSource {
  /// The user-managed root `auth.yaml` file.
  Main,
  /// A managed fragment at `auth.d/<name>.yaml`.
  Shard(String),
}

/// On-disk schema. Future versions can introduce new top-level keys; the
/// `version` field is mandatory so we can detect format upgrades.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthFile {
  #[serde(default = "default_version")]
  version: u32,
  #[serde(default)]
  accounts: Vec<AccountConfig>,
}

/// Canonical account fingerprints used for change detection. The values can
/// contain credential material, so debug output intentionally exposes only a
/// count.
#[derive(Clone, Default, PartialEq, Eq)]
struct SourceBaseline(BTreeMap<String, String>);

impl std::fmt::Debug for SourceBaseline {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("SourceBaseline")
      .field("accounts", &self.0.len())
      .finish()
  }
}

/// Exact bytes observed when a source was loaded. This detects changes before
/// a staged commit. Missing sources additionally use atomic create-if-absent;
/// replacing an existing source retains the portable check-to-rename window.
#[derive(Clone, PartialEq, Eq)]
enum SourceSnapshot {
  Missing,
  Contents(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFileInstall {
  /// Atomically install the staged inode only if the target is still absent.
  CreateIfAbsent,
  /// Replace after exact-byte validation. Portable filesystems do not expose
  /// a content-based compare-and-swap for the final rename window.
  Replace,
}

impl std::fmt::Debug for SourceSnapshot {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Missing => formatter.write_str("Missing"),
      Self::Contents(contents) => formatter
        .debug_struct("Contents")
        .field("length", &contents.len())
        .finish(),
    }
  }
}

impl SourceSnapshot {
  fn capture(path: &Path) -> Result<Self> {
    match fs::read(path) {
      Ok(contents) => Ok(Self::Contents(contents)),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::Missing),
      Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
  }

  fn validate(&self, path: &Path) -> Result<()> {
    if &Self::capture(path)? != self {
      bail!(
        "{} changed after loading the auth store; retry the command",
        path.display()
      );
    }
    Ok(())
  }

  fn install_mode(&self) -> AuthFileInstall {
    match self {
      Self::Missing => AuthFileInstall::CreateIfAbsent,
      Self::Contents(_) => AuthFileInstall::Replace,
    }
  }
}

fn default_version() -> u32 {
  CURRENT_VERSION
}

/// In-memory account store backed by a root `auth.yaml` file plus optional
/// `auth.d/*.yaml` fragments.
///
/// `accounts` remains public for compatibility with account-management code.
/// `save()` compares the aggregate state with source baselines and writes each
/// changed source back to its own secured file.
#[derive(Debug, Clone)]
pub struct AuthStore {
  path: PathBuf,
  pub accounts: Vec<AccountConfig>,
  account_sources: BTreeMap<String, AuthSource>,
  source_paths: BTreeMap<AuthSource, PathBuf>,
  source_baselines: BTreeMap<AuthSource, SourceBaseline>,
  source_snapshots: BTreeMap<AuthSource, SourceSnapshot>,
}

impl AuthStore {
  /// Load the root `auth.yaml` and sorted `auth.d/*.yaml` fragments.
  ///
  /// `auth_path` overrides the default router auth path. `config_path` is
  /// accepted for source compatibility but is no longer consulted; callers
  /// should run `tokn-router-legacy-config` before latest auth loading.
  pub fn load(auth_path: Option<&Path>, _config_path: Option<&Path>) -> Result<Self> {
    Self::load_from_path(resolve_auth_path(auth_path)?)
  }

  /// Load an auth store while retaining an already-acquired write lock.
  ///
  /// Use this when loading, inspecting, and saving credentials must form one
  /// cooperative transaction. Finish the transaction with
  /// [`Self::save_locked`] before dropping `lock`.
  pub fn load_locked(lock: &AuthStoreLock) -> Result<Self> {
    validate_direct_auth_layout(lock.auth_path())?;
    Self::load_from_path(lock.auth_path().to_path_buf())
  }

  fn load_from_path(resolved: PathBuf) -> Result<Self> {
    let mut store = Self {
      path: resolved.clone(),
      accounts: Vec::new(),
      account_sources: BTreeMap::new(),
      source_paths: BTreeMap::new(),
      source_baselines: BTreeMap::new(),
      source_snapshots: BTreeMap::new(),
    };
    store.load_source(AuthSource::Main, resolved.clone())?;
    for (source, path) in discover_shards(&resolved)? {
      store.load_source(source, path)?;
    }
    Ok(store)
  }

  /// Persist every source whose accounts changed. New account ids added by
  /// direct mutation default to the root source; use [`Self::upsert_in_shard`]
  /// for an agent-owned credential.
  ///
  /// A source missing at load is installed atomically only if it remains
  /// absent. Existing sources are revalidated after staging, but their final
  /// portable rename is not a content-based compare-and-swap. This method
  /// acquires the store's cooperative write lock before revalidating and
  /// committing changes.
  pub fn save(&mut self) -> Result<()> {
    let lock = AuthStoreLock::acquire(Some(&self.path))?;
    self.save_locked(&lock)
  }

  /// Persist changes under an already-acquired store write lock.
  ///
  /// The guard must belong to this store's root. Every loaded source is
  /// revalidated after lock acquisition, including when no write is needed.
  pub fn save_locked(&mut self, lock: &AuthStoreLock) -> Result<()> {
    self.validate_locked(lock)?;
    self.save_with_before_commit(|_| {})
  }

  /// Verify that this guard belongs to the store and every loaded credential
  /// source still has the exact source set and bytes observed at load or save.
  pub fn validate_locked(&self, lock: &AuthStoreLock) -> Result<()> {
    lock.ensure_matches(&self.path)?;
    self.validate_sources_unchanged()
  }

  fn save_with_before_commit(&mut self, mut before_commit: impl FnMut(&Path)) -> Result<()> {
    let mut source_paths = self.source_paths.clone();
    let mut accounts_by_source = BTreeMap::<AuthSource, Vec<AccountConfig>>::new();
    let mut account_ids = BTreeSet::new();

    for account in &self.accounts {
      if !account_ids.insert(account.id.clone()) {
        bail!("duplicate account id '{}' in the in-memory auth store", account.id);
      }
      let source = self
        .account_sources
        .get(&account.id)
        .cloned()
        .unwrap_or(AuthSource::Main);
      let path = self.source_path(&source)?;
      source_paths.entry(source.clone()).or_insert(path);
      accounts_by_source.entry(source).or_default().push(account.clone());
    }

    let mut changes = Vec::new();
    for (source, path) in source_paths {
      let accounts = accounts_by_source.remove(&source).unwrap_or_default();
      let current = SourceBaseline(account_fingerprints(&accounts)?);
      if self.source_baselines.get(&source) == Some(&current) {
        continue;
      }
      changes.push((source, path, current, accounts));
    }

    for (source, path, current, accounts) in changes {
      let install = self
        .source_snapshots
        .get(&source)
        .map(SourceSnapshot::install_mode)
        .ok_or_else(|| anyhow!("missing load-time snapshot for {}", path.display()))?;
      let staged = stage_auth_file(&path, &accounts)?;
      self.validate_sources_unchanged()?;
      before_commit(&path);
      let contents = staged.commit(&path, install)?;
      self.source_baselines.insert(source.clone(), current);
      self.source_snapshots.insert(source, SourceSnapshot::Contents(contents));
    }
    Ok(())
  }

  /// Insert or replace an account by id, retaining its current source. New
  /// accounts are user-managed and therefore belong to root `auth.yaml`.
  pub fn upsert(&mut self, account: AccountConfig) {
    let source = self
      .account_sources
      .get(&account.id)
      .cloned()
      .unwrap_or(AuthSource::Main);
    self
      .upsert_in_source(source, account)
      .expect("account sources are validated while loading");
  }

  /// Insert or replace a user-managed account in the root `auth.yaml`.
  /// A caller must resolve an id collision with an agent-owned shard instead
  /// of silently replacing the linked agent's credential.
  pub fn upsert_in_main(&mut self, account: AccountConfig) -> Result<()> {
    self.upsert_in_source(AuthSource::Main, account)
  }

  /// Insert or replace an account in a named credential shard. An existing
  /// id can never silently move from root or another shard.
  pub fn upsert_in_shard(&mut self, shard: &str, account: AccountConfig) -> Result<()> {
    self.upsert_in_source(AuthSource::Shard(shard.to_string()), account)
  }

  /// Insert or replace an account in an explicit source.
  pub fn upsert_in_source(&mut self, source: AuthSource, account: AccountConfig) -> Result<()> {
    let target_path = self.source_path(&source)?;
    if let Some(existing_source) = self.account_sources.get(&account.id).cloned() {
      if existing_source != source {
        let existing_path = self.source_path(&existing_source)?;
        bail!(
          "account '{}' is already owned by {}; refusing to move it to {}",
          account.id,
          existing_path.display(),
          target_path.display()
        );
      }
    }
    if !self.source_paths.contains_key(&source) {
      if target_path.exists() {
        bail!(
          "credential source {} appeared after loading the auth store; retry the command",
          target_path.display()
        );
      }
      self.source_paths.insert(source.clone(), target_path);
      self.source_baselines.entry(source.clone()).or_default();
      self.source_snapshots.insert(source.clone(), SourceSnapshot::Missing);
    }
    let account_id = account.id.clone();
    if let Some(slot) = self.accounts.iter_mut().find(|existing| existing.id == account.id) {
      *slot = account;
    } else {
      self.accounts.push(account);
    }
    self.account_sources.insert(account_id, source);
    Ok(())
  }

  /// Remove the account with the given id, returning the removed value if any.
  /// The next save updates the account's owning source rather than root.
  pub fn remove(&mut self, id: &str) -> Option<AccountConfig> {
    let index = self.accounts.iter().position(|account| account.id == id)?;
    self.account_sources.remove(id);
    Some(self.accounts.remove(index))
  }

  /// Remove an account only if it belongs to `source`.
  pub fn remove_from_source(&mut self, source: &AuthSource, id: &str) -> Result<Option<AccountConfig>> {
    if let Some(existing) = self.account_sources.get(id) {
      if existing != source {
        bail!(
          "account '{id}' belongs to {}, not {}",
          self.source_path(existing)?.display(),
          self.source_path(source)?.display()
        );
      }
    }
    Ok(self.remove(id))
  }

  /// Borrow the account with the given id, if any.
  pub fn get(&self, id: &str) -> Option<&AccountConfig> {
    self.accounts.iter().find(|account| account.id == id)
  }

  /// Mutably borrow the account with the given id, if any.
  pub fn get_mut(&mut self, id: &str) -> Option<&mut AccountConfig> {
    self.accounts.iter_mut().find(|account| account.id == id)
  }

  /// Return the source which owns an account.
  pub fn account_source(&self, id: &str) -> Option<AuthSource> {
    self.account_sources.get(id).cloned()
  }

  /// Return the credential file which owns an account.
  pub fn account_source_path(&self, id: &str) -> Option<PathBuf> {
    self
      .account_source(id)
      .and_then(|source| self.source_path(&source).ok())
  }

  /// Return every currently loaded source in stable order.
  pub fn sources(&self) -> Vec<AuthSource> {
    self.source_paths.keys().cloned().collect()
  }

  /// Return every currently loaded credential path in stable source order.
  pub fn source_paths(&self) -> Vec<PathBuf> {
    self.source_paths.values().cloned().collect()
  }

  /// Whether a modern root or shard credential source existed when loaded or
  /// has since been written by this store.
  ///
  /// A present, valid source is authoritative even when it contains no
  /// accounts. Callers can use this to decide whether legacy embedded
  /// credentials are eligible for one-time import.
  pub fn has_persisted_sources(&self) -> bool {
    self
      .source_snapshots
      .values()
      .any(|snapshot| matches!(snapshot, SourceSnapshot::Contents(_)))
  }

  /// Return the SHA-256 digest of the exact bytes loaded or most recently
  /// written for a credential source.
  ///
  /// This supports conflict-safe migration checkpoints without exposing
  /// credential contents or adopting a later filesystem mutation.
  pub fn source_sha256(&self, source: &AuthSource) -> Option<String> {
    let SourceSnapshot::Contents(contents) = self.source_snapshots.get(source)? else {
      return None;
    };
    Some(tokn_core::util::digest::sha256_hex(contents))
  }

  /// Resolve a source to its backing path. A validated shard path can be
  /// resolved before it has been created.
  pub fn source_path(&self, source: &AuthSource) -> Result<PathBuf> {
    if let Some(path) = self.source_paths.get(source) {
      return Ok(path.clone());
    }
    match source {
      AuthSource::Main => Ok(self.path.clone()),
      AuthSource::Shard(shard) => Self::shard_path_for(&self.path, shard),
    }
  }

  /// Resolve a named shard relative to the root auth file.
  pub fn shard_path(&self, shard: &str) -> Result<PathBuf> {
    Self::shard_path_for(&self.path, shard)
  }

  /// Resolve a named shard relative to an explicit root auth file.
  pub fn shard_path_for(root_auth_path: &Path, shard: &str) -> Result<PathBuf> {
    validate_shard_name(shard)?;
    Ok(auth_shard_dir(root_auth_path).join(format!("{shard}.{AUTH_SHARD_EXTENSION}")))
  }

  /// The root auth path, retained for backwards compatibility.
  pub fn path(&self) -> &Path {
    &self.path
  }

  fn load_source(&mut self, source: AuthSource, path: PathBuf) -> Result<()> {
    let snapshot = SourceSnapshot::capture(&path)?;
    let file = match &snapshot {
      SourceSnapshot::Missing => AuthFile {
        version: CURRENT_VERSION,
        accounts: Vec::new(),
      },
      SourceSnapshot::Contents(contents) => parse_auth_file(&path, contents)?,
    };
    let baseline = SourceBaseline(account_fingerprints(&file.accounts)?);
    self.source_paths.insert(source.clone(), path.clone());
    for account in file.accounts {
      if let Some(previous_source) = self.account_sources.get(&account.id) {
        let previous_path = self.source_path(previous_source)?;
        bail!(
          "duplicate account id '{}' in {} and {}",
          account.id,
          previous_path.display(),
          path.display()
        );
      }
      self.account_sources.insert(account.id.clone(), source.clone());
      self.accounts.push(account);
    }
    self.source_baselines.insert(source.clone(), baseline);
    self.source_snapshots.insert(source, snapshot);
    Ok(())
  }

  /// Ensure no loaded credential source was added, removed, or edited since
  /// this store was opened. Checking the whole source set before every write
  /// prevents a save to one shard from making a concurrent change elsewhere
  /// produce a duplicate account id in the merged pool.
  fn validate_sources_unchanged(&self) -> Result<()> {
    validate_direct_auth_layout(&self.path)?;
    let expected_shards = self
      .source_snapshots
      .iter()
      .filter(|(source, snapshot)| matches!((source, snapshot), (AuthSource::Shard(_), SourceSnapshot::Contents(_))))
      .map(|(source, _)| source.clone())
      .collect::<BTreeSet<_>>();
    let actual_shards = discover_shards(&self.path)?
      .into_iter()
      .map(|(source, _)| source)
      .collect::<BTreeSet<_>>();
    if actual_shards != expected_shards {
      bail!("auth.d sources changed after loading the auth store; retry the command");
    }
    for (source, path) in &self.source_paths {
      let snapshot = self
        .source_snapshots
        .get(source)
        .ok_or_else(|| anyhow!("missing load-time snapshot for {}", path.display()))?;
      snapshot.validate(path)?;
    }
    Ok(())
  }
}

fn discover_shards(root_auth_path: &Path) -> Result<Vec<(AuthSource, PathBuf)>> {
  let dir = auth_shard_dir(root_auth_path);
  if !dir.exists() {
    return Ok(Vec::new());
  }
  let mut shards = Vec::new();
  for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
    let entry = entry?;
    let path = entry.path();
    if !entry.file_type()?.is_file()
      || path.extension().and_then(|extension| extension.to_str()) != Some(AUTH_SHARD_EXTENSION)
    {
      continue;
    }
    let name = path
      .file_stem()
      .and_then(|name| name.to_str())
      .ok_or_else(|| anyhow!("{} has no valid UTF-8 shard name", path.display()))?;
    validate_shard_name(name)?;
    shards.push((AuthSource::Shard(name.to_string()), path));
  }
  shards.sort_by(|left, right| left.0.cmp(&right.0));
  Ok(shards)
}

fn auth_shard_dir(root_auth_path: &Path) -> PathBuf {
  root_auth_path
    .parent()
    .unwrap_or_else(|| Path::new("."))
    .join(AUTH_SHARD_DIR_NAME)
}

fn validate_shard_name(shard: &str) -> Result<()> {
  if shard.is_empty()
    || !shard
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
  {
    bail!("invalid auth shard name '{shard}'");
  }
  Ok(())
}

fn parse_auth_file(path: &Path, contents: &[u8]) -> Result<AuthFile> {
  let raw = std::str::from_utf8(contents).with_context(|| format!("reading {} as UTF-8", path.display()))?;
  let parsed: AuthFile =
    serde_yaml::from_str(raw).with_context(|| format!("parsing {} (expected `version: 1` schema)", path.display()))?;
  if parsed.version != CURRENT_VERSION {
    bail!(
      "{}: unsupported version {} (this build understands {})",
      path.display(),
      parsed.version,
      CURRENT_VERSION
    );
  }
  Ok(parsed)
}

fn account_fingerprints(accounts: &[AccountConfig]) -> Result<BTreeMap<String, String>> {
  let mut fingerprints = BTreeMap::new();
  for account in accounts {
    let fingerprint = serde_yaml::to_string(account).context("serialising account for change detection")?;
    if fingerprints.insert(account.id.clone(), fingerprint).is_some() {
      bail!("duplicate account id '{}' in one credential source", account.id);
    }
  }
  Ok(fingerprints)
}

struct StagedAuthFile {
  file: StagedPrivateFile,
  contents: Vec<u8>,
}

impl StagedAuthFile {
  fn commit(self, path: &Path, install: AuthFileInstall) -> Result<Vec<u8>> {
    let Self { file, contents } = self;
    match file.commit(path, install) {
      Ok(()) => Ok(contents),
      Err(error) if install == AuthFileInstall::CreateIfAbsent && error.kind() == std::io::ErrorKind::AlreadyExists => {
        bail!(
          "{} changed after loading the auth store; retry the command",
          path.display()
        )
      }
      Err(error) => Err(error).with_context(|| format!("writing {}", path.display())),
    }
  }
}

struct StagedPrivateFile {
  path: Option<PathBuf>,
}

impl StagedPrivateFile {
  fn commit(mut self, path: &Path, install: AuthFileInstall) -> std::io::Result<()> {
    let temporary = self.path.as_deref().expect("staged auth file should have a path");
    match install {
      AuthFileInstall::CreateIfAbsent => {
        fs::hard_link(temporary, path)?;
        // The target is installed once the link succeeds. Temporary-name
        // cleanup is best effort and retried by Drop; it must not make the
        // successful credential write look like a failed save.
        let _ = fs::remove_file(temporary);
        return Ok(());
      }
      AuthFileInstall::Replace => fs::rename(temporary, path)?,
    }
    self.path = None;
    Ok(())
  }
}

impl Drop for StagedPrivateFile {
  fn drop(&mut self) {
    if let Some(path) = &self.path {
      let _ = fs::remove_file(path);
    }
  }
}

fn stage_auth_file(path: &Path, accounts: &[AccountConfig]) -> Result<StagedAuthFile> {
  let file = AuthFile {
    version: CURRENT_VERSION,
    accounts: accounts.to_vec(),
  };
  let bytes = serde_yaml::to_string(&file)
    .context("serialising auth.yaml")?
    .into_bytes();
  let file = stage_secured_atomic(path, &bytes).with_context(|| format!("writing {}", path.display()))?;
  Ok(StagedAuthFile { file, contents: bytes })
}

fn stage_secured_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<StagedPrivateFile> {
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent)?;
    secure_shard_directory(parent)?;
  }
  for _ in 0..16 {
    let temporary = temporary_path(path)?;
    match write_private_file(&temporary, bytes) {
      Ok(()) => {}
      Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
      Err(error) => {
        let _ = fs::remove_file(&temporary);
        return Err(error);
      }
    }
    return Ok(StagedPrivateFile { path: Some(temporary) });
  }
  Err(std::io::Error::new(
    std::io::ErrorKind::AlreadyExists,
    format!("could not allocate a private temporary file for {}", path.display()),
  ))
}

fn temporary_path(path: &Path) -> std::io::Result<PathBuf> {
  let name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      format!("cannot create an auth temporary file for {}", path.display()),
    )
  })?;
  let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
  Ok(path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), sequence)))
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  use std::io::Write;
  use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

  let mut file = fs::OpenOptions::new()
    .create_new(true)
    .write(true)
    .mode(0o600)
    .open(path)?;
  file.set_permissions(fs::Permissions::from_mode(0o600))?;
  file.write_all(bytes)?;
  file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  use std::io::Write;

  let mut file = fs::OpenOptions::new().create_new(true).write(true).open(path)?;
  file.write_all(bytes)?;
  file.sync_all()
}

#[cfg(unix)]
fn secure_shard_directory(path: &Path) -> std::io::Result<()> {
  use std::os::unix::fs::PermissionsExt;

  if path
    .file_name()
    .is_some_and(|name| name.to_string_lossy() == AUTH_SHARD_DIR_NAME)
  {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
  }
  Ok(())
}

#[cfg(not(unix))]
fn secure_shard_directory(_path: &Path) -> std::io::Result<()> {
  Ok(())
}

/// Default path: the gateway config directory's `auth.yaml`.
pub fn default_auth_path() -> Result<PathBuf> {
  Ok(tokn_config::paths::config_dir()?.join(AUTH_FILE_NAME))
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::account::{AccountTier, AuthType};

  fn sample_account(id: &str) -> AccountConfig {
    AccountConfig {
      id: id.into(),
      provider: "github-copilot".into(),
      enabled: true,
      tier: AccountTier::Active,
      tags: vec![],
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: Some(AuthType::Bearer),
      username: None,
      api_key: None,
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: toml::Table::new(),
    }
  }

  fn write_auth(path: &Path, accounts: &[AccountConfig]) {
    if let Some(parent) = path.parent() {
      fs::create_dir_all(parent).unwrap();
    }
    let yaml = serde_yaml::to_string(&AuthFile {
      version: CURRENT_VERSION,
      accounts: accounts.to_vec(),
    })
    .unwrap();
    fs::write(path, yaml).unwrap();
  }

  #[test]
  fn locked_load_and_save_cover_one_write_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.yaml");
    let lock = AuthStoreLock::acquire(Some(&path)).unwrap();
    let mut store = AuthStore::load_locked(&lock).unwrap();
    store.upsert(sample_account("locked"));

    store.save_locked(&lock).unwrap();

    let loaded = AuthStore::load(Some(&path), None).unwrap();
    assert_eq!(loaded.accounts.len(), 1);
    assert_eq!(loaded.accounts[0].id, "locked");
  }

  #[test]
  fn locked_validation_detects_an_external_change_without_saving() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.yaml");
    write_auth(&path, &[sample_account("original")]);
    let lock = AuthStoreLock::acquire(Some(&path)).unwrap();
    let store = AuthStore::load_locked(&lock).unwrap();
    write_auth(&path, &[sample_account("external")]);

    let error = store.validate_locked(&lock).unwrap_err();

    assert!(error.to_string().contains("changed after loading the auth store"));
  }

  #[test]
  fn locked_save_rejects_a_guard_for_another_store() {
    let dir = tempfile::tempdir().unwrap();
    let guarded = dir.path().join("guarded.yaml");
    let other = dir.path().join("other.yaml");
    let lock = AuthStoreLock::acquire(Some(&guarded)).unwrap();
    let mut store = AuthStore::load(Some(&other), None).unwrap();
    store.upsert(sample_account("other"));

    let error = store.save_locked(&lock).unwrap_err();

    assert!(error.to_string().contains("cannot guard"));
    assert!(!other.exists());
  }

  #[test]
  fn ordinary_save_uses_the_cooperative_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&path), None).unwrap();
    store.upsert(sample_account("blocked"));
    let _lock = AuthStoreLock::acquire(Some(&path)).unwrap();

    let error = store.save().unwrap_err();

    assert!(error
      .to_string()
      .contains("another auth store writer is already in progress"));
    assert!(!path.exists());
  }

  #[test]
  fn roundtrip_yaml_preserves_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&path), None).unwrap();
    store.upsert(sample_account("a1"));
    store.upsert(sample_account("a2"));
    store.save().unwrap();

    let loaded = AuthStore::load(Some(&path), None).unwrap();
    assert_eq!(loaded.accounts.len(), 2);
    assert_eq!(loaded.accounts[0].id, "a1");
    assert_eq!(loaded.accounts[1].id, "a2");
  }

  #[test]
  fn source_digest_tracks_exact_saved_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&path), None).unwrap();
    store.upsert(sample_account("a1"));
    store.save().unwrap();
    let first = store.source_sha256(&AuthSource::Main).unwrap();

    store.get_mut("a1").unwrap().label = Some("updated".into());
    store.save().unwrap();
    let second = store.source_sha256(&AuthSource::Main).unwrap();
    let reloaded = AuthStore::load(Some(&path), None).unwrap();

    assert_ne!(first, second);
    assert_eq!(
      reloaded.source_sha256(&AuthSource::Main).as_deref(),
      Some(second.as_str())
    );
  }

  #[test]
  fn root_and_shard_merge_without_flattening_on_save() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    write_auth(&root, &[sample_account("main")]);
    write_auth(&shard, &[sample_account("opencode")]);
    let root_before = fs::read(&root).unwrap();

    let mut store = AuthStore::load(Some(&root), None).unwrap();
    assert_eq!(store.accounts.len(), 2);
    assert_eq!(store.account_source("main"), Some(AuthSource::Main));
    assert_eq!(
      store.account_source("opencode"),
      Some(AuthSource::Shard("opencode".into()))
    );
    store.get_mut("opencode").unwrap().label = Some("OpenCode".into());
    store.save().unwrap();

    assert_eq!(fs::read(&root).unwrap(), root_before);
    let shard_contents = fs::read_to_string(&shard).unwrap();
    assert!(shard_contents.contains("OpenCode"));
    assert!(!shard_contents.contains("id: main"));
  }

  #[test]
  fn sidecar_only_auth_is_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    write_auth(&shard, &[sample_account("opencode")]);

    let store = AuthStore::load(Some(&root), None).unwrap();

    assert!(!root.exists());
    assert_eq!(store.accounts.len(), 1);
    assert_eq!(store.account_source_path("opencode"), Some(shard));
  }

  #[test]
  fn persisted_source_authority_includes_empty_root_and_sidecar_only_stores() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing/auth.yaml");
    let empty = dir.path().join("empty/auth.yaml");
    let sidecar_root = dir.path().join("sidecar/auth.yaml");
    write_auth(&empty, &[]);
    write_auth(
      &AuthStore::shard_path_for(&sidecar_root, "opencode").unwrap(),
      &[sample_account("opencode")],
    );

    assert!(!AuthStore::load(Some(&missing), None).unwrap().has_persisted_sources());
    assert!(AuthStore::load(Some(&empty), None).unwrap().has_persisted_sources());
    assert!(AuthStore::load(Some(&sidecar_root), None)
      .unwrap()
      .has_persisted_sources());
  }

  #[test]
  fn duplicate_ids_across_sources_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    write_auth(&root, &[sample_account("duplicate")]);
    write_auth(&shard, &[sample_account("duplicate")]);

    let error = AuthStore::load(Some(&root), None).unwrap_err();

    assert!(error.to_string().contains("duplicate account id 'duplicate'"));
    assert!(error.to_string().contains("auth.yaml"));
    assert!(error.to_string().contains("opencode.yaml"));
  }

  #[test]
  fn shard_upsert_refuses_to_move_a_root_account() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    write_auth(&root, &[sample_account("main")]);
    let mut store = AuthStore::load(Some(&root), None).unwrap();

    let error = store.upsert_in_shard("opencode", sample_account("main")).unwrap_err();

    assert!(error.to_string().contains("already owned"));
  }

  #[test]
  fn main_upsert_refuses_to_replace_a_shard_account() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    write_auth(&shard, &[sample_account("opencode")]);
    let mut store = AuthStore::load(Some(&root), None).unwrap();

    let error = store.upsert_in_main(sample_account("opencode")).unwrap_err();

    assert!(error.to_string().contains("already owned"));
    assert_eq!(
      store.account_source("opencode"),
      Some(AuthSource::Shard("opencode".into()))
    );
  }

  #[test]
  fn upsert_replaces_by_id_without_changing_its_source() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    write_auth(&shard, &[sample_account("a1")]);
    let mut store = AuthStore::load(Some(&root), None).unwrap();
    let mut updated = sample_account("a1");
    updated.label = Some("renamed".into());

    store.upsert(updated);
    store.save().unwrap();

    assert!(!root.exists());
    assert!(fs::read_to_string(shard).unwrap().contains("renamed"));
  }

  #[test]
  fn save_does_not_clobber_root_created_after_validation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let concurrent = b"concurrently created root credentials\n";
    let mut store = AuthStore::load(Some(&root), None).unwrap();
    store.upsert(sample_account("local"));
    let mut before_commit_called = false;

    let error = store
      .save_with_before_commit(|path| {
        assert_eq!(path, root);
        fs::write(path, concurrent).unwrap();
        before_commit_called = true;
      })
      .unwrap_err();

    assert!(before_commit_called);
    assert!(error.to_string().contains("changed after loading the auth store"));
    assert_eq!(fs::read(&root).unwrap(), concurrent);
  }

  #[test]
  fn save_does_not_clobber_shard_created_after_validation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    let concurrent = b"concurrently created shard credentials\n";
    let mut store = AuthStore::load(Some(&root), None).unwrap();
    store.upsert_in_shard("opencode", sample_account("local")).unwrap();
    let mut before_commit_called = false;

    let error = store
      .save_with_before_commit(|path| {
        assert_eq!(path, shard);
        fs::write(path, concurrent).unwrap();
        before_commit_called = true;
      })
      .unwrap_err();

    assert!(before_commit_called);
    assert!(error.to_string().contains("changed after loading the auth store"));
    assert_eq!(fs::read(&shard).unwrap(), concurrent);
    assert!(!root.exists());
  }

  #[test]
  fn save_rejects_an_external_change_to_an_unchanged_source() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    write_auth(&root, &[sample_account("main")]);
    write_auth(&shard, &[sample_account("opencode")]);
    let root_before = fs::read(&root).unwrap();

    let mut store = AuthStore::load(Some(&root), None).unwrap();
    store.get_mut("main").unwrap().label = Some("local update".into());
    let mut externally_updated = sample_account("opencode");
    externally_updated.label = Some("external update".into());
    write_auth(&shard, &[externally_updated]);

    let error = store.save().unwrap_err();

    assert!(error.to_string().contains("changed after loading the auth store"));
    assert_eq!(fs::read(&root).unwrap(), root_before);
    assert!(fs::read_to_string(shard).unwrap().contains("external update"));
  }

  #[test]
  fn save_rejects_an_external_shard_added_after_loading() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    write_auth(&root, &[sample_account("main")]);
    let root_before = fs::read(&root).unwrap();

    let mut store = AuthStore::load(Some(&root), None).unwrap();
    store.get_mut("main").unwrap().label = Some("local update".into());
    let added_shard = AuthStore::shard_path_for(&root, "codex-cli").unwrap();
    write_auth(&added_shard, &[sample_account("codex")]);

    let error = store.save().unwrap_err();

    assert!(error.to_string().contains("auth.d sources changed"));
    assert_eq!(fs::read(&root).unwrap(), root_before);
    assert!(added_shard.exists());
  }

  #[test]
  fn remove_returns_extracted_account_and_updates_owning_shard() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    write_auth(&shard, &[sample_account("a1"), sample_account("a2")]);
    let mut store = AuthStore::load(Some(&root), None).unwrap();

    let popped = store.remove("a1").unwrap();
    store.save().unwrap();

    assert_eq!(popped.id, "a1");
    assert_eq!(store.accounts.len(), 1);
    assert!(store.remove("ghost").is_none());
    let contents = fs::read_to_string(shard).unwrap();
    assert!(!contents.contains("id: a1"));
    assert!(contents.contains("id: a2"));
  }

  #[cfg(unix)]
  #[test]
  fn created_auth_files_and_shard_directories_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("auth.yaml");
    let shard = AuthStore::shard_path_for(&root, "opencode").unwrap();
    let mut store = AuthStore::load(Some(&root), None).unwrap();
    store.upsert(sample_account("main"));
    store.upsert_in_shard("opencode", sample_account("a1")).unwrap();
    store.save().unwrap();

    assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&shard).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(
      fs::metadata(dir.path().join(".auth.yaml.lock"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777,
      0o600
    );
    assert_eq!(
      fs::metadata(shard.parent().unwrap()).unwrap().permissions().mode() & 0o777,
      0o700
    );
  }

  #[test]
  fn default_auth_path_uses_gateway_config_dir() {
    let expected = tokn_config::paths::config_dir().unwrap().join(AUTH_FILE_NAME);
    assert_eq!(default_auth_path().unwrap(), expected);
  }

  #[test]
  fn missing_yaml_ignores_legacy_config_after_schema_migration_split() {
    let dir = tempfile::tempdir().unwrap();
    let yaml_path = dir.path().join("auth.yaml");
    let cfg_path = dir.path().join("config.toml");
    fs::write(
      &cfg_path,
      r#"
[[accounts]]
id = "legacy"
provider = "github-copilot"
enabled = true
"#,
    )
    .unwrap();

    let store = AuthStore::load(Some(&yaml_path), Some(&cfg_path)).unwrap();
    assert!(store.accounts.is_empty());
    assert!(!yaml_path.exists());
  }

  #[test]
  fn missing_both_yields_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let yaml_path = dir.path().join("auth.yaml");
    let store = AuthStore::load(Some(&yaml_path), None).unwrap();
    assert!(store.accounts.is_empty());
  }

  #[test]
  fn unknown_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.yaml");
    fs::write(&path, "version: 99\naccounts: []\n").unwrap();
    let error = AuthStore::load(Some(&path), None).unwrap_err();
    assert!(error.to_string().contains("unsupported version 99"));
  }
}

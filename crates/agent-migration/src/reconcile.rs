use crate::adapter::{adapter_for, source_provider_id, ProviderRoute};
use crate::manifest::{self, FileBackup, MigrationManifest};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use tokn_accounts::registry::Registry;
use tokn_auth::{default_auth_path, AuthSource, AuthStore};
use tokn_config::{Account, AgentAccountSource, Config, ConfigSources, RouteMode};
use tokn_core::AgentId;

#[derive(Debug)]
pub struct ImportRequest {
  pub agent: AgentId,
  pub gateway_config_path: Option<PathBuf>,
  pub agent_home: Option<PathBuf>,
}

#[derive(Debug)]
pub struct ReconcileRequest {
  pub agent: AgentId,
  pub profile: Option<String>,
  pub mode: Option<RouteMode>,
  /// `Some` is an explicit caller choice. `None` preserves an existing
  /// linked agent's stored account source and defaults fresh links to agent
  /// accounts.
  pub account_source: Option<AgentAccountSource>,
  /// Provider selected by a main-account verbatim link. This is optional
  /// when the profile or global defaults already declares one.
  pub default_provider_id: Option<String>,
  /// Agent-side provider identifiers redirected to the main account pool.
  /// `None` preserves the linked main-account binding during `agent sync`.
  pub source_provider_ids: Option<Vec<String>>,
  pub gateway_config_path: Option<PathBuf>,
  pub agent_home: Option<PathBuf>,
}

#[derive(Debug)]
pub struct UnlinkRequest {
  pub agent: AgentId,
  pub backup_id: Option<String>,
}

#[derive(Debug)]
pub struct ReconcilePlan {
  pub agent: AgentId,
  pub timestamp: String,
  pub gateway_config_path: PathBuf,
  pub gateway_config_fragment_path: PathBuf,
  /// The user-owned root auth store. Agent links read it together with
  /// shards, but never write it.
  pub gateway_auth_path: PathBuf,
  /// The per-agent auth shard that an agent-owned link writes, if it has
  /// imported credentials. Main-account links intentionally leave this unset.
  pub gateway_auth_shard_path: Option<PathBuf>,
  gateway_config_snapshot: ConfigSourcesSnapshot,
  gateway_auth_sources_snapshot: Option<AuthSourcesSnapshot>,
  gateway_auth_snapshot: Option<FileSnapshot>,
  gateway_auth_shard_snapshot: Option<FileSnapshot>,
  source_auth_path: Option<PathBuf>,
  source_auth_snapshot: Option<FileSnapshot>,
  pub agent_auth_path: Option<PathBuf>,
  pub binding_profile: Option<String>,
  pub binding_mode: RouteMode,
  pub account_source: AgentAccountSource,
  pub default_provider_id: Option<String>,
  pub source_provider_ids: Vec<String>,
  pub target_base_url: String,
  pub imported_accounts: Vec<Account>,
  pub(crate) provider_routes: Vec<ProviderRoute>,
  pub edits: Vec<PlannedEdit>,
  pub(crate) previous_manifest: Option<PathBuf>,
}

#[derive(Debug)]
pub struct PlannedEdit {
  pub path: PathBuf,
  pub(crate) kind: EditKind,
  pub(crate) backup: bool,
  source_snapshot: FileSnapshot,
}

pub(crate) enum EditKind {
  Json(Value),
  Jsonc(String),
  Toml(toml_edit::DocumentMut),
}

impl std::fmt::Debug for EditKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let (kind, length) = match self {
      Self::Json(value) => ("Json", serde_json::to_vec(value).map_or(0, |value| value.len())),
      Self::Jsonc(raw) => ("Jsonc", raw.len()),
      Self::Toml(doc) => ("Toml", doc.to_string().len()),
    };
    f.debug_struct(kind).field("length", &length).finish_non_exhaustive()
  }
}

#[derive(PartialEq, Eq)]
enum FileSnapshot {
  Missing,
  Contents(Vec<u8>),
}

impl std::fmt::Debug for FileSnapshot {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Missing => f.write_str("Missing"),
      Self::Contents(contents) => f
        .debug_struct("Contents")
        .field("length", &contents.len())
        .finish_non_exhaustive(),
    }
  }
}

impl FileSnapshot {
  fn capture(path: &Path) -> Result<Self> {
    if !path.exists() {
      return Ok(Self::Missing);
    }
    std::fs::read(path)
      .map(Self::Contents)
      .with_context(|| format!("reading {}", path.display()))
  }

  fn validate(&self, path: &Path) -> Result<()> {
    if &Self::capture(path)? != self {
      bail!(
        "{} changed after the agent migration plan was created; rerun the command",
        path.display()
      );
    }
    Ok(())
  }
}

/// Snapshot every file that contributes to the effective gateway config.
/// A sidecar added or changed after planning can alter ownership checks just
/// as materially as the primary config, so it is part of the link precondition.
#[derive(Debug)]
struct ConfigSourcesSnapshot {
  sources: ConfigSources,
  files: BTreeMap<PathBuf, FileSnapshot>,
}

/// Snapshot every credential source that contributes to the merged auth
/// store. A different agent shard added after planning could introduce a
/// duplicate account id or otherwise change ownership, even though this link
/// writes only its own shard.
#[derive(Debug)]
struct AuthSourcesSnapshot {
  paths: Vec<PathBuf>,
  files: BTreeMap<PathBuf, FileSnapshot>,
}

impl AuthSourcesSnapshot {
  fn capture(store: &AuthStore) -> Result<Self> {
    let mut paths = store
      .sources()
      .iter()
      .map(|source| store.source_path(source))
      .collect::<Result<Vec<_>>>()?;
    paths.sort();
    paths.dedup();
    let mut files = BTreeMap::new();
    for path in &paths {
      files.insert(path.clone(), FileSnapshot::capture(path)?);
    }
    Ok(Self { paths, files })
  }

  fn validate(&self, root_auth_path: &Path) -> Result<()> {
    let store = AuthStore::load(Some(root_auth_path), None)?;
    let current = Self::capture(&store)?;
    if current.paths != self.paths {
      bail!("gateway auth sources changed after the agent migration plan was created; rerun the command");
    }
    for (path, snapshot) in &self.files {
      snapshot.validate(path)?;
    }
    Ok(())
  }
}

impl ConfigSourcesSnapshot {
  fn capture(sources: ConfigSources) -> Result<Self> {
    let mut files = BTreeMap::new();
    for path in std::iter::once(&sources.root).chain(sources.fragments.iter()) {
      files.insert(path.clone(), FileSnapshot::capture(path)?);
    }
    Ok(Self { sources, files })
  }

  fn validate(&self) -> Result<()> {
    let loaded = Config::load_with_sources(Some(&self.sources.root))?;
    if loaded.sources != self.sources {
      bail!("gateway config sources changed after the agent migration plan was created; rerun the command");
    }
    for (path, snapshot) in &self.files {
      snapshot.validate(path)?;
    }
    Ok(())
  }
}

fn load_stable_config(path: &Path) -> Result<(Config, ConfigSourcesSnapshot)> {
  let initial = Config::load_with_sources(Some(path))?;
  let snapshot = ConfigSourcesSnapshot::capture(initial.sources)?;
  snapshot.validate()?;
  let loaded = Config::load_with_sources(Some(path))?;
  if loaded.sources != snapshot.sources {
    bail!("gateway config sources changed while preparing the agent migration plan; rerun the command");
  }
  snapshot.validate()?;
  Ok((loaded.config, snapshot))
}

fn load_stable_auth_store(path: &Path, config_path: &Path) -> Result<(AuthStore, AuthSourcesSnapshot)> {
  let initial = AuthStore::load(Some(path), Some(config_path))?;
  let snapshot = AuthSourcesSnapshot::capture(&initial)?;
  snapshot.validate(path)?;
  let loaded = AuthStore::load(Some(path), Some(config_path))?;
  let loaded_sources = AuthSourcesSnapshot::capture(&loaded)?;
  if loaded_sources.paths != snapshot.paths {
    bail!("gateway auth sources changed while preparing the agent migration plan; rerun the command");
  }
  snapshot.validate(path)?;
  Ok((loaded, snapshot))
}

impl PlannedEdit {
  pub(crate) fn new(path: PathBuf, kind: EditKind, backup: bool, source: Option<Vec<u8>>) -> Self {
    Self {
      path,
      kind,
      backup,
      source_snapshot: source.map_or(FileSnapshot::Missing, FileSnapshot::Contents),
    }
  }

  fn validate_source(&self) -> Result<()> {
    self.source_snapshot.validate(&self.path)
  }
}

#[derive(Debug)]
pub struct ImportReport {
  pub gateway_auth_path: PathBuf,
  pub imported_account_ids: Vec<String>,
  pub disabled_account_ids: Vec<String>,
}

#[derive(Debug)]
pub struct ApplyReport {
  pub manifest_path: PathBuf,
  pub files: Vec<FileBackup>,
}

#[derive(Debug)]
pub struct UnlinkReport {
  pub manifest_path: PathBuf,
  pub timestamp: String,
  pub actions: Vec<FileAction>,
}

#[derive(Debug)]
pub enum FileAction {
  Removed(PathBuf),
  Restored { original: PathBuf, backup: PathBuf },
}

pub fn import_accounts(request: ImportRequest) -> Result<ImportReport> {
  let gateway_auth_path = default_gateway_auth_path()?;
  import_accounts_with_gateway_auth_path(request, gateway_auth_path)
}

fn import_accounts_with_gateway_auth_path(request: ImportRequest, gateway_auth_path: PathBuf) -> Result<ImportReport> {
  let adapter = adapter_for(&request.agent).ok_or_else(|| anyhow!("unsupported agent {}", request.agent))?;
  let gateway_config_path = Config::load(request.gateway_config_path.as_deref())?.1;
  let home = resolve_home(request.agent_home)?;
  let timestamp = timestamp()?;
  let imported_accounts = adapter.discover_accounts(&home, &timestamp)?;
  let imported_account_ids = imported_accounts
    .iter()
    .map(|account| account.id.clone())
    .collect::<BTreeSet<_>>();
  let mut store = AuthStore::load(Some(&gateway_auth_path), Some(&gateway_config_path))?;
  let disabled_account_ids = disable_missing_root_source_accounts(&mut store, &request.agent, &imported_account_ids);
  for account in imported_accounts {
    // `agent import` remains a user-owned, root-store operation. Do not
    // silently replace an account owned by a linked agent shard.
    store.upsert_in_source(AuthSource::Main, account)?;
  }
  store.save()?;
  Ok(ImportReport {
    gateway_auth_path,
    imported_account_ids: imported_account_ids.into_iter().collect(),
    disabled_account_ids,
  })
}

pub fn plan_reconcile(request: ReconcileRequest) -> Result<ReconcilePlan> {
  let gateway_auth_path = default_gateway_auth_path()?;
  plan_reconcile_with_gateway_auth_path(request, gateway_auth_path)
}

fn plan_reconcile_with_gateway_auth_path(
  request: ReconcileRequest,
  gateway_auth_path: PathBuf,
) -> Result<ReconcilePlan> {
  let adapter = adapter_for(&request.agent).ok_or_else(|| anyhow!("unsupported agent {}", request.agent))?;
  let gateway_config_path = match request.gateway_config_path.as_deref() {
    Some(path) => path.to_path_buf(),
    None => tokn_config::paths::config_path()?,
  };
  let (cfg, gateway_config_snapshot) = load_stable_config(&gateway_config_path)?;
  let gateway_config_fragment_path =
    tokn_config::paths::agent_config_fragment_path(&gateway_config_path, request.agent.as_str());
  let existing_binding = cfg.agents.get(request.agent.as_str());
  let account_source = request
    .account_source
    .or_else(|| existing_binding.map(|binding| binding.account_source))
    .unwrap_or(AgentAccountSource::Agent);
  reject_account_source_transition(account_source, existing_binding, &request.agent)?;
  if account_source == AgentAccountSource::Main && !adapter.supports_main_accounts() {
    bail!(
      "{} cannot use --use-main-accounts yet because its local credential bootstrap would be changed; use the default link mode or choose opencode",
      request.agent
    );
  }
  let source_provider_ids = resolve_main_source_provider_ids(
    request.source_provider_ids.as_deref(),
    existing_binding,
    account_source,
    adapter.default_provider_id(),
  )?;
  let timestamp = timestamp()?;
  let home = resolve_home(request.agent_home)?;
  let (
    gateway_auth_sources_snapshot,
    gateway_auth_snapshot,
    gateway_auth_shard_path,
    gateway_auth_shard_snapshot,
    source_auth_path,
    source_auth_snapshot,
    imported_accounts,
    transferred_source_providers,
  ) = if account_source == AgentAccountSource::Main {
    (None, None, None, None, None, None, Vec::new(), BTreeSet::new())
  } else {
    let source_auth_path = adapter.auth_path(&home);
    let source_auth_snapshot = FileSnapshot::capture(&source_auth_path)?;
    let discovered_accounts = adapter.discover_accounts(&home, &timestamp)?;
    let transferred_source_providers = discovered_accounts
      .iter()
      .filter_map(source_provider_id)
      .map(str::to_string)
      .collect::<BTreeSet<_>>();
    let shard_path = AuthStore::shard_path_for(&gateway_auth_path, request.agent.as_str())?;
    let has_existing_agent_binding =
      existing_binding.map(|binding| binding.account_source) == Some(AgentAccountSource::Agent);

    // A source-transfer link can have no credentials left in the local agent
    // store after its first successful link. Load the auth store for an
    // existing agent binding so sync retains its shard-owned credentials.
    let needs_store = !discovered_accounts.is_empty() || has_existing_agent_binding;
    let (
      gateway_auth_sources_snapshot,
      gateway_auth_snapshot,
      gateway_auth_shard_path,
      gateway_auth_shard_snapshot,
      imported_accounts,
    ) = if needs_store {
      let (store, auth_sources_snapshot) = load_stable_auth_store(&gateway_auth_path, &gateway_config_path)?;
      reject_legacy_root_auth_accounts(&store, existing_binding, &request.agent, &gateway_auth_path)?;
      let imported_accounts = if adapter.transfers_credentials() {
        merge_transferred_accounts(&store, &request.agent, &shard_path, discovered_accounts)
      } else {
        discovered_accounts
      };
      validate_imported_account_shard_ownership(&store, &request.agent, &shard_path, &imported_accounts)?;
      let manages_shard =
        !imported_accounts.is_empty() || has_agent_managed_accounts_in_shard(&store, &request.agent, &shard_path);
      if manages_shard {
        (
          Some(auth_sources_snapshot),
          Some(FileSnapshot::capture(&gateway_auth_path)?),
          Some(shard_path.clone()),
          Some(FileSnapshot::capture(&shard_path)?),
          imported_accounts,
        )
      } else {
        (None, None, None, None, imported_accounts)
      }
    } else {
      (None, None, None, None, discovered_accounts)
    };
    (
      gateway_auth_sources_snapshot,
      gateway_auth_snapshot,
      gateway_auth_shard_path,
      gateway_auth_shard_snapshot,
      Some(source_auth_path),
      Some(source_auth_snapshot),
      imported_accounts,
      transferred_source_providers,
    )
  };
  let binding_mode = request
    .mode
    .or_else(|| existing_binding.and_then(|binding| binding.mode))
    .unwrap_or(RouteMode::Route);
  let binding_profile = resolve_binding_profile(
    request.profile.as_deref(),
    existing_binding,
    &request.agent,
    &imported_accounts,
    account_source,
    binding_mode,
  )?;
  let main_default_provider_id = resolve_main_default_provider(
    &cfg,
    binding_profile.as_deref(),
    existing_binding,
    binding_mode,
    account_source,
    request.default_provider_id.as_deref(),
  )?;
  let target_base_url = gateway_profile_base_url(&cfg, binding_profile.as_deref());
  let provider_routes = match account_source {
    AgentAccountSource::Agent => provider_routes(
      &cfg,
      binding_profile.as_deref(),
      &imported_accounts,
      &transferred_source_providers,
      adapter.default_provider_id(),
    ),
    AgentAccountSource::Main => main_provider_routes(
      &cfg,
      binding_profile.as_deref(),
      &source_provider_ids,
      main_default_provider_id.as_deref(),
    ),
  };
  let default_provider_id = materialized_default_provider(
    binding_mode,
    account_source,
    main_default_provider_id.as_deref(),
    &provider_routes,
    adapter.default_provider_id(),
  );
  let removed_source_provider_ids =
    stale_source_provider_ids(existing_binding, &provider_routes, adapter.default_provider_id());
  validate_binding_profile(&cfg, &request.agent, binding_profile.as_deref())?;
  validate_provider_route_profiles(&cfg, &request.agent, &provider_routes)?;
  validate_switch_profile_owners(
    &cfg,
    &request.agent,
    binding_profile.as_deref(),
    binding_mode,
    &imported_accounts,
    &provider_routes,
  )?;
  validate_verbatim_provider_routes(adapter.as_ref(), binding_mode, &provider_routes)?;
  let edits = adapter.rewrite_config(
    &home,
    binding_mode,
    &target_base_url,
    &provider_routes,
    &removed_source_provider_ids,
  )?;
  gateway_config_snapshot.validate()?;
  if let Some(snapshot) = &gateway_auth_sources_snapshot {
    snapshot.validate(&gateway_auth_path)?;
  }
  if let Some(snapshot) = &gateway_auth_snapshot {
    snapshot.validate(&gateway_auth_path)?;
  }
  if let (Some(path), Some(snapshot)) = (&gateway_auth_shard_path, &gateway_auth_shard_snapshot) {
    snapshot.validate(path)?;
  }
  if let (Some(path), Some(snapshot)) = (&source_auth_path, &source_auth_snapshot) {
    snapshot.validate(path)?;
  }
  Ok(ReconcilePlan {
    agent: request.agent,
    timestamp,
    gateway_config_path,
    gateway_config_fragment_path,
    gateway_auth_path,
    gateway_auth_shard_path,
    gateway_config_snapshot,
    gateway_auth_sources_snapshot,
    gateway_auth_snapshot,
    gateway_auth_shard_snapshot,
    source_auth_path,
    source_auth_snapshot,
    agent_auth_path: (account_source == AgentAccountSource::Agent
      && adapter.transfers_credentials()
      && !imported_accounts.is_empty())
    .then(|| adapter.auth_path(&home)),
    binding_profile,
    binding_mode,
    account_source,
    default_provider_id,
    source_provider_ids,
    target_base_url,
    imported_accounts,
    provider_routes,
    edits,
    previous_manifest: None,
  })
}

/// Changing an existing binding's credential boundary can transfer or
/// re-enable credentials. Keep its account source immutable until unlink so
/// a relink cannot perform that migration implicitly.
fn reject_account_source_transition(
  account_source: AgentAccountSource,
  existing_binding: Option<&tokn_config::AgentConfig>,
  agent: &AgentId,
) -> Result<()> {
  let Some(existing_account_source) = existing_binding.map(|binding| binding.account_source) else {
    return Ok(());
  };
  if account_source == existing_account_source {
    return Ok(());
  }
  bail!(
    "{} is already linked; changing account source with `agent link` is not supported yet. Run `agent unlink {}` before linking it again.",
    agent,
    agent
  );
}

/// Agent links before auth shards stored imported credentials in the root
/// `auth.yaml`. Moving those records while a binding is active would rewrite
/// the user-owned store and make unlink restoration ambiguous. Restore the old
/// link first, then create a fresh shard-backed one.
fn reject_legacy_root_auth_accounts(
  store: &AuthStore,
  existing_binding: Option<&tokn_config::AgentConfig>,
  agent: &AgentId,
  root_auth_path: &Path,
) -> Result<()> {
  if existing_binding.map(|binding| binding.account_source) != Some(AgentAccountSource::Agent) {
    return Ok(());
  }
  let account_ids = legacy_root_auth_account_ids(store, agent, root_auth_path);
  if account_ids.is_empty() {
    return Ok(());
  }
  bail!(
    "{} has legacy imported accounts in {}; run `agent unlink {}` before relinking so credentials can move to auth.d/{}",
    agent,
    root_auth_path.display(),
    agent,
    agent.as_str()
  );
}

fn legacy_root_auth_account_ids<'a>(store: &'a AuthStore, agent: &AgentId, root_auth_path: &Path) -> Vec<&'a str> {
  store
    .accounts
    .iter()
    .filter(|account| {
      is_source_managed_account(account, agent)
        && store.account_source_path(&account.id).as_deref() == Some(root_auth_path)
    })
    .map(|account| account.id.as_str())
    .collect()
}

fn validate_imported_account_shard_ownership(
  store: &AuthStore,
  agent: &AgentId,
  shard_path: &Path,
  accounts: &[Account],
) -> Result<()> {
  for account in accounts {
    let Some(existing_path) = store.account_source_path(&account.id) else {
      continue;
    };
    if existing_path != shard_path {
      bail!(
        "imported account '{}' is already owned by {}; it cannot be moved into {} without unlinking or removing the conflicting account",
        account.id,
        existing_path.display(),
        shard_path.display()
      );
    }
    if store
      .get(&account.id)
      .is_some_and(|existing| !is_source_managed_account(existing, agent))
    {
      bail!(
        "account '{}' in {} is not owned by {}; refusing to overwrite it",
        account.id,
        shard_path.display(),
        agent
      );
    }
  }
  Ok(())
}

pub fn apply_reconcile(mut plan: ReconcilePlan) -> Result<ApplyReport> {
  plan.previous_manifest = manifest::latest_active_manifest(&plan.agent)?;
  let manifest_path = manifest::manifest_path(&plan.timestamp, &plan.agent)?;
  apply_reconcile_to_manifest_path(plan, manifest_path)
}

pub fn unlink(request: UnlinkRequest) -> Result<UnlinkReport> {
  let manifest_path = manifest::resolve_manifest(&request.agent, request.backup_id.as_deref())?;
  if let Some(successor) = active_manifest_successor(&manifest_path, &request.agent)? {
    bail!(
      "manifest {} has newer active successor {}; unlink the latest migration instead",
      manifest_path.display(),
      successor.display()
    );
  }
  let mut chain = manifest_chain(&manifest_path, &request.agent)?;
  let latest = chain.first().expect("manifest chain contains selected manifest");
  if latest.1.unlinked {
    bail!("manifest {} has already been unlinked", latest.0.display());
  }
  let timestamp = latest.1.timestamp.clone();

  if !latest.1.credentials_handoff_complete {
    restore_latest_credentials(&request.agent, &latest.1)?;
    let latest = chain.first_mut().expect("manifest chain contains selected manifest");
    latest.1.credentials_handoff_complete = true;
    manifest::write_manifest(&latest.0, &latest.1)?;
  }
  let mut actions = Vec::new();
  for (_, current) in &chain {
    restore_manifest_files(current, &mut actions)?;
  }
  // Keep the latest manifest active until every ancestor is marked. A retry
  // can then finish cleanly if writing one of the older manifests fails.
  for (path, current) in chain.iter_mut().rev() {
    current.unlinked = true;
    manifest::write_manifest(path, current)?;
  }

  Ok(UnlinkReport {
    manifest_path,
    timestamp,
    actions,
  })
}

fn active_manifest_successor(path: &Path, agent: &AgentId) -> Result<Option<PathBuf>> {
  let Some(dir) = path.parent() else {
    return Ok(None);
  };
  let suffix = format!("-{}.json", agent.as_str());
  let mut successors = Vec::new();
  for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
    let candidate = entry?.path();
    if candidate == path
      || !candidate
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(&suffix))
        .unwrap_or(false)
    {
      continue;
    }
    let manifest = manifest::read_manifest(&candidate)?;
    if manifest.agent != *agent || !manifest.completed || manifest.unlinked {
      continue;
    }
    let chain = manifest_chain(&candidate, agent)?;
    if chain.iter().skip(1).any(|(ancestor, _)| same_path(ancestor, path)) {
      successors.push(candidate);
    }
  }
  successors.sort();
  Ok(successors.pop())
}

fn same_path(left: &Path, right: &Path) -> bool {
  left == right
    || left
      .canonicalize()
      .ok()
      .zip(right.canonicalize().ok())
      .map(|(left, right)| left == right)
      .unwrap_or(false)
}

fn manifest_chain(path: &Path, agent: &AgentId) -> Result<Vec<(PathBuf, MigrationManifest)>> {
  let mut chain = Vec::new();
  let mut seen = BTreeSet::new();
  let mut current = Some(path.to_path_buf());
  while let Some(path) = current {
    if !seen.insert(path.clone()) {
      bail!("migration manifest chain contains a cycle at {}", path.display());
    }
    let manifest = manifest::read_manifest(&path)?;
    if manifest.agent != *agent {
      bail!("manifest {} is for {}, not {}", path.display(), manifest.agent, agent);
    }
    current = manifest.previous_manifest.clone();
    chain.push((path, manifest));
  }
  Ok(chain)
}

fn restore_latest_credentials(agent: &AgentId, manifest: &MigrationManifest) -> Result<()> {
  let Some(agent_auth_path) = &manifest.agent_auth_path else {
    return Ok(());
  };
  let Some(gateway_auth_path) = &manifest.gateway_auth_path else {
    bail!("manifest is missing the gateway auth path required to restore transferred credentials");
  };
  let store = AuthStore::load(Some(gateway_auth_path), None)?;
  let accounts = manifest
    .imported_account_ids
    .iter()
    .map(|id| {
      let account = store.get(id).cloned().ok_or_else(|| {
        anyhow!(
          "transferred account '{id}' is missing from {}",
          gateway_auth_path.display()
        )
      })?;
      if let Some(shard_path) = manifest.gateway_auth_shard_path.as_deref() {
        if store.account_source_path(id).as_deref() != Some(shard_path) {
          bail!(
            "transferred account '{id}' is no longer owned by {}",
            shard_path.display()
          );
        }
      }
      Ok(account)
    })
    .collect::<Result<Vec<_>>>()?;
  adapter_for(agent)
    .ok_or_else(|| anyhow!("unsupported agent {agent}"))?
    .restore_transferred_credentials(agent_auth_path, &accounts)
}

fn restore_manifest_files(manifest: &MigrationManifest, actions: &mut Vec<FileAction>) -> Result<()> {
  for file in manifest.files.iter().rev() {
    if file.created_by_migration {
      if file.original.exists() {
        std::fs::remove_file(&file.original).with_context(|| format!("removing {}", file.original.display()))?;
        actions.push(FileAction::Removed(file.original.clone()));
      }
      continue;
    }
    let Some(backup) = &file.backup else {
      continue;
    };
    if let Some(parent) = file.original.parent() {
      std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if manifest.gateway_auth_shard_path.as_deref() == Some(file.original.as_path()) {
      manifest::restore_sensitive_path_from_backup(backup, &file.original)?;
    } else {
      std::fs::copy(backup, &file.original)
        .with_context(|| format!("restoring {} from {}", file.original.display(), backup.display()))?;
    }
    actions.push(FileAction::Restored {
      original: file.original.clone(),
      backup: backup.clone(),
    });
  }
  Ok(())
}

fn apply_reconcile_to_manifest_path(plan: ReconcilePlan, manifest_path: PathBuf) -> Result<ApplyReport> {
  plan.gateway_config_snapshot.validate()?;
  validate_gateway_auth_snapshots(&plan)?;
  if let (Some(path), Some(snapshot)) = (&plan.source_auth_path, &plan.source_auth_snapshot) {
    snapshot.validate(path)?;
  }
  for edit in &plan.edits {
    edit.validate_source()?;
  }
  reject_legacy_root_auth_accounts_for_successor(&plan)?;
  reject_successor_without_pending_credentials(&plan)?;

  let mut files = Vec::new();
  let manages_gateway_auth = plan.gateway_auth_shard_path.is_some();
  let imported_account_ids = plan
    .imported_accounts
    .iter()
    .map(|account| account.id.clone())
    .collect::<BTreeSet<_>>();

  if let Some(shard_path) = &plan.gateway_auth_shard_path {
    let shard_existed = shard_path.exists();
    manifest::backup_sensitive_path_for(shard_path, &plan.timestamp, &mut files)?;
    manifest::mark_created(&mut files, shard_path, shard_existed);
  }
  let gateway_fragment_existed = plan.gateway_config_fragment_path.exists();
  manifest::backup_path_for(&plan.gateway_config_fragment_path, &plan.timestamp, &mut files)?;
  manifest::mark_created(&mut files, &plan.gateway_config_fragment_path, gateway_fragment_existed);

  for edit in &plan.edits {
    if !edit.backup {
      continue;
    }
    let existed = edit.path.exists();
    manifest::backup_path_for(&edit.path, &plan.timestamp, &mut files)?;
    manifest::mark_created(&mut files, &edit.path, existed);
  }

  let manifest = MigrationManifest {
    version: 4,
    completed: true,
    agent: plan.agent.clone(),
    timestamp: plan.timestamp.clone(),
    profile: plan.binding_profile.clone(),
    target_base_url: plan.target_base_url.clone(),
    gateway_auth_path: manages_gateway_auth.then_some(plan.gateway_auth_path.clone()),
    gateway_auth_shard_path: plan.gateway_auth_shard_path.clone(),
    agent_auth_path: plan.agent_auth_path.clone(),
    provider_routes: plan.provider_routes.clone(),
    previous_manifest: plan.previous_manifest.clone(),
    unlinked: false,
    credentials_handoff_complete: plan.agent_auth_path.is_none(),
    imported_account_ids: plan
      .imported_accounts
      .iter()
      .map(|account| account.id.clone())
      .collect(),
    files,
  };
  manifest::write_manifest(&manifest_path, &manifest.clone().in_progress())?;

  if let Some(shard_path) = &plan.gateway_auth_shard_path {
    validate_gateway_auth_snapshots(&plan)?;
    let mut store = AuthStore::load(Some(&plan.gateway_auth_path), Some(&plan.gateway_config_path))?;
    remove_replaced_gateway_accounts(&mut store, &plan.agent, shard_path, &plan.imported_accounts);
    disable_missing_source_accounts_in_path(&mut store, &plan.agent, &imported_account_ids, shard_path);
    for account in &plan.imported_accounts {
      store.upsert_in_shard(plan.agent.as_str(), account.clone())?;
    }
    validate_gateway_auth_snapshots(&plan)?;
    store.save()?;
  }

  plan.gateway_config_snapshot.validate()?;
  let fallback_provider_id = adapter_for(&plan.agent)
    .expect("supported agent should still have adapter")
    .default_provider_id();
  let write = AgentProfileWrite {
    agent: &plan.agent,
    profile: plan.binding_profile.as_deref(),
    mode: plan.binding_mode,
    account_source: plan.account_source,
    source_provider_ids: &plan.source_provider_ids,
    accounts: &plan.imported_accounts,
    provider_routes: &plan.provider_routes,
    default_provider_id: plan.default_provider_id.as_deref(),
    fallback_provider_id,
  };
  upsert_agent_and_profiles_with_source(&plan.gateway_config_fragment_path, &write)?;

  for edit in &plan.edits {
    write_edit(edit)?;
  }

  let manifest = manifest.complete();
  manifest::write_manifest(&manifest_path, &manifest)?;
  Ok(ApplyReport {
    manifest_path,
    files: manifest.files,
  })
}

/// Configuration drift must not let a pre-shard link silently chain into a
/// shard-backed manifest. `apply_reconcile` supplies the active predecessor,
/// so this catches an old root-owned credential even when its config binding
/// was manually removed after the original link.
fn reject_legacy_root_auth_accounts_for_successor(plan: &ReconcilePlan) -> Result<()> {
  if plan.account_source != AgentAccountSource::Agent || plan.previous_manifest.is_none() {
    return Ok(());
  }
  let store = AuthStore::load(Some(&plan.gateway_auth_path), Some(&plan.gateway_config_path))?;
  if legacy_root_auth_account_ids(&store, &plan.agent, &plan.gateway_auth_path).is_empty() {
    return Ok(());
  }
  bail!(
    "{} has legacy imported accounts in {}; run `agent unlink {}` before relinking so credentials can move to auth.d/{}",
    plan.agent,
    plan.gateway_auth_path.display(),
    plan.agent,
    plan.agent.as_str()
  );
}

/// Do not create a successor manifest that would hide an earlier pending
/// credential handoff. This can happen only after an agent-owned shard was
/// deleted or corrupted while OpenCode's source auth is still stripped. A
/// later unlink restores credentials from the latest manifest, so continuing
/// here would make the original credentials unreachable.
fn reject_successor_without_pending_credentials(plan: &ReconcilePlan) -> Result<()> {
  if plan.account_source != AgentAccountSource::Agent || !plan.imported_accounts.is_empty() {
    return Ok(());
  }
  let Some(previous_manifest_path) = &plan.previous_manifest else {
    return Ok(());
  };
  let adapter = adapter_for(&plan.agent).expect("supported agent should still have an adapter");
  if !adapter.transfers_credentials() {
    return Ok(());
  }
  let previous = manifest::read_manifest(previous_manifest_path)?;
  if previous.agent_auth_path.is_none() || previous.credentials_handoff_complete {
    return Ok(());
  }
  bail!(
    "{} has a pending credential handoff in {}, but its managed auth shard is unavailable; restore the shard or source credentials before syncing",
    plan.agent,
    previous_manifest_path.display()
  );
}

fn validate_gateway_auth_snapshots(plan: &ReconcilePlan) -> Result<()> {
  if let Some(snapshot) = &plan.gateway_auth_sources_snapshot {
    snapshot.validate(&plan.gateway_auth_path)?;
  }
  if let Some(snapshot) = &plan.gateway_auth_snapshot {
    snapshot.validate(&plan.gateway_auth_path)?;
  }
  if let (Some(path), Some(snapshot)) = (&plan.gateway_auth_shard_path, &plan.gateway_auth_shard_snapshot) {
    snapshot.validate(path)?;
  }
  Ok(())
}

pub(crate) fn annotate_imported_account(
  mut account: Account,
  agent: AgentId,
  source_path: &Path,
  source_key: &str,
  imported_at: &str,
) -> Account {
  let source_tag = format!("source:{}", agent.as_str());
  for tag in ["imported", "agent-managed", agent.as_str(), source_tag.as_str()] {
    if !account.tags.iter().any(|existing| existing == tag) {
      account.tags.push(tag.to_string());
    }
  }

  let mut import = toml::Table::new();
  import.insert("source_agent".into(), toml::Value::String(agent.to_string()));
  import.insert(
    "source_path".into(),
    toml::Value::String(source_path.display().to_string()),
  );
  import.insert("source_key".into(), toml::Value::String(source_key.into()));
  import.insert("imported_at".into(), toml::Value::String(imported_at.into()));
  import.insert("last_seen_at".into(), toml::Value::String(imported_at.into()));
  import.insert("sync_managed".into(), toml::Value::Boolean(true));
  import.insert("missing_from_source".into(), toml::Value::Boolean(false));
  account.settings.insert("import".into(), toml::Value::Table(import));
  account.enabled = true;
  account
}

fn merge_transferred_accounts(
  store: &AuthStore,
  agent: &AgentId,
  shard_path: &Path,
  discovered_accounts: Vec<Account>,
) -> Vec<Account> {
  let mut accounts = store
    .accounts
    .iter()
    .filter(|account| {
      is_gateway_owned_account(account, agent) && store.account_source_path(&account.id).as_deref() == Some(shard_path)
    })
    .map(|account| (transfer_source_provider(account).to_string(), account.clone()))
    .collect::<BTreeMap<_, _>>();
  for account in discovered_accounts {
    let account = mark_gateway_owned(account);
    accounts.insert(transfer_source_provider(&account).to_string(), account);
  }
  accounts.into_values().collect()
}

fn mark_gateway_owned(mut account: Account) -> Account {
  let provider = account.provider.clone();
  if let Some(import) = account.settings.get_mut("import").and_then(toml::Value::as_table_mut) {
    import
      .entry("source_provider")
      .or_insert_with(|| toml::Value::String(provider));
    import.insert("ownership".into(), toml::Value::String("gateway".into()));
    import.insert("sync_managed".into(), toml::Value::Boolean(false));
    import.insert("missing_from_source".into(), toml::Value::Boolean(false));
  }
  account
}

fn remove_replaced_gateway_accounts(
  store: &mut AuthStore,
  agent: &AgentId,
  shard_path: &Path,
  desired_accounts: &[Account],
) {
  let desired = desired_accounts
    .iter()
    .map(|account| (transfer_source_provider(account), account.id.as_str()))
    .collect::<BTreeMap<_, _>>();
  let obsolete_ids = store
    .accounts
    .iter()
    .filter(|account| {
      is_gateway_owned_account(account, agent) && store.account_source_path(&account.id).as_deref() == Some(shard_path)
    })
    .filter(|account| {
      desired
        .get(transfer_source_provider(account))
        .map(|desired_id| **desired_id != account.id)
        .unwrap_or(false)
    })
    .map(|account| account.id.clone())
    .collect::<Vec<_>>();
  for account_id in obsolete_ids {
    let _ = store.remove(&account_id);
  }
}

fn transfer_source_provider(account: &Account) -> &str {
  source_provider_id(account).unwrap_or(&account.provider)
}

fn is_gateway_owned_account(account: &Account, agent: &AgentId) -> bool {
  is_source_managed_account(account, agent)
    && account
      .settings
      .get("import")
      .and_then(toml::Value::as_table)
      .and_then(|import| import.get("ownership"))
      .and_then(toml::Value::as_str)
      == Some("gateway")
}

fn provider_routes(
  cfg: &Config,
  binding_profile: Option<&str>,
  accounts: &[Account],
  transferred_source_providers: &BTreeSet<String>,
  default_provider_id: &str,
) -> Vec<ProviderRoute> {
  if accounts.is_empty() {
    return vec![ProviderRoute {
      source_provider_id: default_provider_id.to_string(),
      gateway_provider_id: default_provider_id.to_string(),
      account_id: String::new(),
      profile: binding_profile.unwrap_or_default().to_string(),
      base_url: gateway_profile_base_url(cfg, binding_profile),
      transfer_source_auth: false,
    }];
  }

  let Some(binding_profile) = binding_profile else {
    return Vec::new();
  };
  let mut routes = BTreeMap::new();
  for account in accounts {
    let Some(source_provider_id) = source_provider_id(account) else {
      continue;
    };
    let profile = format!("{binding_profile}-{}", account.provider);
    routes.insert(
      source_provider_id.to_string(),
      ProviderRoute {
        source_provider_id: source_provider_id.to_string(),
        gateway_provider_id: account.provider.clone(),
        account_id: account.id.clone(),
        base_url: gateway_profile_base_url(cfg, Some(&profile)),
        profile,
        transfer_source_auth: transferred_source_providers.contains(source_provider_id),
      },
    );
  }
  routes.into_values().collect()
}

fn main_provider_routes(
  cfg: &Config,
  binding_profile: Option<&str>,
  source_provider_ids: &[String],
  default_provider_id: Option<&str>,
) -> Vec<ProviderRoute> {
  source_provider_ids
    .iter()
    .map(|source_provider_id| ProviderRoute {
      source_provider_id: source_provider_id.clone(),
      gateway_provider_id: default_provider_id.unwrap_or(source_provider_id).to_string(),
      account_id: String::new(),
      profile: binding_profile.unwrap_or_default().to_string(),
      base_url: gateway_profile_base_url(cfg, binding_profile),
      transfer_source_auth: false,
    })
    .collect()
}

fn resolve_main_source_provider_ids(
  explicit_provider_ids: Option<&[String]>,
  existing_binding: Option<&tokn_config::AgentConfig>,
  account_source: AgentAccountSource,
  fallback_provider_id: &str,
) -> Result<Vec<String>> {
  if account_source != AgentAccountSource::Main {
    return Ok(Vec::new());
  }
  let configured = explicit_provider_ids.or_else(|| {
    existing_binding
      .and_then(|binding| binding.source_providers.as_deref())
      .filter(|provider_ids| !provider_ids.is_empty())
  });
  let mut source_provider_ids = BTreeSet::new();
  for provider_id in configured.unwrap_or(&[]) {
    let provider_id = provider_id.trim();
    if provider_id.is_empty() {
      bail!("--source-provider must not be empty");
    }
    if !source_provider_ids.insert(provider_id.to_string()) {
      bail!("--source-provider '{provider_id}' was specified more than once");
    }
  }
  if source_provider_ids.is_empty() {
    source_provider_ids.insert(fallback_provider_id.to_string());
  }
  Ok(source_provider_ids.into_iter().collect())
}

fn stale_source_provider_ids(
  existing_binding: Option<&tokn_config::AgentConfig>,
  routes: &[ProviderRoute],
  fallback_provider_id: &str,
) -> Vec<String> {
  let Some(existing_binding) = existing_binding.filter(|binding| binding.account_source == AgentAccountSource::Main)
  else {
    return Vec::new();
  };
  let previous = existing_binding
    .source_providers
    .as_deref()
    .filter(|provider_ids| !provider_ids.is_empty())
    .map(|provider_ids| provider_ids.iter().map(String::as_str).collect::<BTreeSet<_>>())
    .unwrap_or_else(|| BTreeSet::from([fallback_provider_id]));
  let current = routes
    .iter()
    .map(|route| route.source_provider_id.as_str())
    .collect::<BTreeSet<_>>();
  previous
    .difference(&current)
    .map(|provider_id| (*provider_id).to_string())
    .collect()
}

fn is_verbatim_mode(mode: RouteMode) -> bool {
  matches!(mode, RouteMode::Passthrough | RouteMode::Switch)
}

fn resolve_main_default_provider(
  cfg: &Config,
  binding_profile: Option<&str>,
  existing_binding: Option<&tokn_config::AgentConfig>,
  mode: RouteMode,
  account_source: AgentAccountSource,
  explicit_provider: Option<&str>,
) -> Result<Option<String>> {
  if explicit_provider.is_some() && (account_source != AgentAccountSource::Main || !is_verbatim_mode(mode)) {
    bail!("--provider is only valid with --use-main-accounts and --mode passthrough or switch");
  }
  if account_source != AgentAccountSource::Main || !is_verbatim_mode(mode) {
    return Ok(None);
  }
  // An agent-owned binding may have materialised a provider from its imported
  // accounts. Do not silently reuse that stale target while changing it into
  // a main-account raw route.
  let configured_provider = (existing_binding.map(|binding| binding.account_source) != Some(AgentAccountSource::Agent))
    .then(|| {
      binding_profile
        .and_then(|profile| cfg.profiles.get(profile))
        .and_then(|profile| profile.default_provider_id.as_deref())
    })
    .flatten();
  let provider = explicit_provider
    .or(configured_provider)
    .or(cfg.defaults.default_provider_id.as_deref())
    .map(str::trim)
    .filter(|provider| !provider.is_empty())
    .map(str::to_string)
    .ok_or_else(|| {
      anyhow!(
        "--use-main-accounts with --mode {} requires --provider <id> or [defaults].default_provider_id",
        route_mode_as_str(mode)
      )
    })?;
  Ok(Some(provider))
}

fn materialized_default_provider(
  mode: RouteMode,
  account_source: AgentAccountSource,
  main_default_provider_id: Option<&str>,
  provider_routes: &[ProviderRoute],
  adapter_default_provider_id: &str,
) -> Option<String> {
  if !is_verbatim_mode(mode) {
    return None;
  }
  if account_source == AgentAccountSource::Main {
    return main_default_provider_id.map(str::to_string);
  }
  provider_routes
    .iter()
    .find(|route| route.source_provider_id == adapter_default_provider_id)
    .or_else(|| provider_routes.first())
    .map(|route| route.gateway_provider_id.clone())
    .or_else(|| Some(adapter_default_provider_id.to_string()))
}

fn validate_verbatim_provider_routes(
  adapter: &dyn crate::adapter::AgentAdapter,
  mode: RouteMode,
  routes: &[ProviderRoute],
) -> Result<()> {
  if !is_verbatim_mode(mode) {
    return Ok(());
  }
  let endpoint = adapter.switch_endpoint();
  let registry = Registry::builtin();
  let mut checked = BTreeSet::new();
  for route in routes {
    if !checked.insert(route.gateway_provider_id.as_str()) {
      continue;
    }
    let descriptor = registry.resolve(&route.gateway_provider_id).ok_or_else(|| {
      anyhow!(
        "{} link selected unknown provider '{}' for --mode {}",
        adapter.default_provider_id(),
        route.gateway_provider_id,
        route_mode_as_str(mode)
      )
    })?;
    if descriptor.endpoints.iter().any(|spec| spec.endpoint == endpoint) {
      continue;
    }
    bail!(
      "{} --mode {} sends {:?} traffic, but provider '{}' does not support that endpoint; use --mode route instead",
      adapter.default_provider_id(),
      route_mode_as_str(mode),
      endpoint,
      route.gateway_provider_id
    );
  }
  Ok(())
}

fn validate_provider_route_profiles(cfg: &Config, agent: &AgentId, routes: &[ProviderRoute]) -> Result<()> {
  for route in routes {
    if route.account_id.is_empty() || route.profile.is_empty() {
      continue;
    }
    if let Some(existing) = cfg.profiles.get(&route.profile) {
      if existing.agent_id.as_ref() != Some(agent) {
        bail!(
          "generated profile '{}' already exists and is not owned by {}",
          route.profile,
          agent
        );
      }
    }
  }
  Ok(())
}

fn validate_binding_profile(cfg: &Config, agent: &AgentId, profile: Option<&str>) -> Result<()> {
  let Some((profile, existing)) =
    profile.and_then(|profile| cfg.profiles.get(profile).map(|existing| (profile, existing)))
  else {
    return Ok(());
  };
  if existing.agent_id.as_ref() != Some(agent) {
    bail!("profile '{profile}' already exists and is not owned by {agent}");
  }
  Ok(())
}

fn validate_switch_profile_owners(
  cfg: &Config,
  agent: &AgentId,
  profile: Option<&str>,
  mode: RouteMode,
  accounts: &[Account],
  provider_routes: &[ProviderRoute],
) -> Result<()> {
  if mode != RouteMode::Switch || !provider_routes.is_empty() {
    return Ok(());
  }
  let Some(profile) = profile else {
    return Ok(());
  };
  let providers = accounts
    .iter()
    .map(|account| account.provider.as_str())
    .collect::<BTreeSet<_>>();
  for provider in providers {
    let name = format!("{profile}-{provider}");
    if let Some(existing) = cfg.profiles.get(&name) {
      if existing.agent_id.as_ref() != Some(agent) {
        bail!("generated profile '{name}' already exists and is not owned by {agent}");
      }
    }
  }
  Ok(())
}

pub(crate) fn imported_account_ids(store: &AuthStore, agent: &AgentId) -> Vec<String> {
  let mut ids = store
    .accounts
    .iter()
    .filter(|account| is_source_managed_account(account, agent))
    .map(|account| account.id.clone())
    .collect::<Vec<_>>();
  ids.sort();
  ids
}

/// Disable stale source-managed accounts only in the user-owned root auth
/// file. Agent-owned shards are outside the scope of `agent import`.
pub(crate) fn disable_missing_root_source_accounts(
  store: &mut AuthStore,
  agent: &AgentId,
  seen_ids: &BTreeSet<String>,
) -> Vec<String> {
  disable_missing_source_accounts_in_source(store, agent, seen_ids, &AuthSource::Main)
}

fn disable_missing_source_accounts_in_source(
  store: &mut AuthStore,
  agent: &AgentId,
  seen_ids: &BTreeSet<String>,
  source: &AuthSource,
) -> Vec<String> {
  let account_ids = store
    .accounts
    .iter()
    .filter(|account| {
      !seen_ids.contains(&account.id)
        && is_source_managed_account(account, agent)
        && is_sync_managed(account)
        && store.account_source(&account.id).as_ref() == Some(source)
    })
    .map(|account| account.id.clone())
    .collect::<Vec<_>>();
  disable_source_accounts(store, account_ids)
}

fn disable_missing_source_accounts_in_path(
  store: &mut AuthStore,
  agent: &AgentId,
  seen_ids: &BTreeSet<String>,
  source_path: &Path,
) -> Vec<String> {
  disable_missing_source_accounts_in_optional_path(store, agent, seen_ids, Some(source_path))
}

fn disable_missing_source_accounts_in_optional_path(
  store: &mut AuthStore,
  agent: &AgentId,
  seen_ids: &BTreeSet<String>,
  source_path: Option<&Path>,
) -> Vec<String> {
  let account_ids = store
    .accounts
    .iter()
    .filter(|account| {
      !seen_ids.contains(&account.id)
        && is_source_managed_account(account, agent)
        && is_sync_managed(account)
        && source_path
          .map(|source_path| store.account_source_path(&account.id).as_deref() == Some(source_path))
          .unwrap_or(true)
    })
    .map(|account| account.id.clone())
    .collect::<Vec<_>>();
  disable_source_accounts(store, account_ids)
}

fn disable_source_accounts(store: &mut AuthStore, account_ids: Vec<String>) -> Vec<String> {
  let mut disabled = Vec::new();
  for account_id in account_ids {
    let account = store
      .get_mut(&account_id)
      .expect("account selected from the auth store must still be present");
    account.enabled = false;
    if !account.tags.iter().any(|tag| tag == "source:missing") {
      account.tags.push("source:missing".into());
    }
    if let Some(import) = account.settings.get_mut("import").and_then(toml::Value::as_table_mut) {
      import.insert("missing_from_source".into(), toml::Value::Boolean(true));
    }
    disabled.push(account_id);
  }
  disabled.sort();
  disabled
}

fn has_agent_managed_accounts_in_shard(store: &AuthStore, agent: &AgentId, shard_path: &Path) -> bool {
  store.accounts.iter().any(|account| {
    is_source_managed_account(account, agent) && store.account_source_path(&account.id).as_deref() == Some(shard_path)
  })
}

fn is_sync_managed(account: &Account) -> bool {
  account
    .settings
    .get("import")
    .and_then(toml::Value::as_table)
    .and_then(|import| import.get("sync_managed"))
    .and_then(toml::Value::as_bool)
    .unwrap_or(true)
}

pub(crate) fn is_source_managed_account(account: &Account, agent: &AgentId) -> bool {
  let source_agent = account
    .settings
    .get("import")
    .and_then(toml::Value::as_table)
    .and_then(|import| import.get("source_agent"))
    .and_then(toml::Value::as_str);
  if source_agent == Some(agent.as_str()) {
    return true;
  }
  let source_tag = format!("source:{}", agent.as_str());
  account.tags.iter().any(|tag| tag == &source_tag)
}

fn write_edit(edit: &PlannedEdit) -> Result<()> {
  edit.validate_source()?;
  if let Some(parent) = edit.path.parent() {
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
  }
  match &edit.kind {
    EditKind::Json(value) => {
      std::fs::write(&edit.path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("writing {}", edit.path.display()))?;
    }
    EditKind::Jsonc(raw) => {
      std::fs::write(&edit.path, raw).with_context(|| format!("writing {}", edit.path.display()))?;
    }
    EditKind::Toml(doc) => {
      std::fs::write(&edit.path, doc.to_string()).with_context(|| format!("writing {}", edit.path.display()))?;
    }
  }
  Ok(())
}

#[cfg(test)]
fn upsert_agent_and_profiles(
  path: &Path,
  agent: &AgentId,
  profile: Option<&str>,
  mode: RouteMode,
  accounts: &[Account],
  provider_routes: &[ProviderRoute],
  fallback_provider_id: &str,
) -> Result<()> {
  let default_provider_id = is_verbatim_mode(mode).then_some(fallback_provider_id);
  let write = AgentProfileWrite {
    agent,
    profile,
    mode,
    account_source: AgentAccountSource::Agent,
    source_provider_ids: &[],
    accounts,
    provider_routes,
    default_provider_id,
    fallback_provider_id,
  };
  upsert_agent_and_profiles_with_source(path, &write)
}

struct AgentProfileWrite<'a> {
  agent: &'a AgentId,
  profile: Option<&'a str>,
  mode: RouteMode,
  account_source: AgentAccountSource,
  source_provider_ids: &'a [String],
  accounts: &'a [Account],
  provider_routes: &'a [ProviderRoute],
  default_provider_id: Option<&'a str>,
  fallback_provider_id: &'a str,
}

fn upsert_agent_and_profiles_with_source(path: &Path, write: &AgentProfileWrite<'_>) -> Result<()> {
  Ok(Config::edit_in_place(path, |doc| {
    let previous_profile = existing_agent_profile(doc, write.agent);
    upsert_agent(doc, write);
    if let Some(previous_profile) = previous_profile.as_deref() {
      if Some(previous_profile) != write.profile {
        remove_materialized_profile(doc, previous_profile, write.agent);
      }
    }
    if let Some(profile) = write.profile {
      validate_profile_item_owner(doc, profile, write.agent)?;
      upsert_profile_item(doc, profile, write);
      if !write.provider_routes.is_empty() {
        remove_agent_profiles(doc, profile, write.agent);
        upsert_provider_route_profiles(doc, write.agent, write.mode, write.provider_routes)?;
      } else if write.mode == RouteMode::Switch {
        upsert_switch_profiles(doc, profile, write.agent, write.accounts)?;
      } else {
        remove_agent_profiles(doc, profile, write.agent);
      }
    }
    Ok(())
  })?)
}

fn existing_agent_profile(doc: &toml_edit::DocumentMut, agent: &AgentId) -> Option<String> {
  doc
    .get("agents")
    .and_then(toml_edit::Item::as_table_like)
    .and_then(|agents| agents.get(agent.as_str()))
    .and_then(toml_edit::Item::as_table_like)
    .and_then(|agent| agent.get("profile"))
    .and_then(toml_edit::Item::as_str)
    .map(str::to_string)
}

fn upsert_agent(doc: &mut toml_edit::DocumentMut, write: &AgentProfileWrite<'_>) {
  let agents = doc["agents"].or_insert(toml_edit::table());
  let agent_item = agents[write.agent.as_str()].or_insert(toml_edit::table());
  agent_item["mode"] = toml_edit::value(route_mode_as_str(write.mode));
  if let Some(profile) = write.profile {
    agent_item["profile"] = toml_edit::value(profile);
  } else if let Some(table) = agent_item.as_table_mut() {
    table.remove("profile");
  }
  if write.account_source == AgentAccountSource::Main {
    agent_item["account_source"] = toml_edit::value("main");
    agent_item["source_providers"] = array_value(write.source_provider_ids);
  } else if let Some(table) = agent_item.as_table_mut() {
    table.remove("account_source");
    table.remove("source_providers");
  }
  agent_item["sync"] = toml_edit::value(true);
}

fn upsert_profile_item(doc: &mut toml_edit::DocumentMut, profile: &str, write: &AgentProfileWrite<'_>) {
  let profiles = doc["profiles"].or_insert(toml_edit::table());
  let profile_item = profiles[profile].or_insert(toml_edit::table());
  profile_item["mode"] = toml_edit::value(route_mode_as_str(write.mode));
  profile_item["agent_id"] = toml_edit::value(write.agent.as_str());
  if let Some(default_provider_id) = write.default_provider_id {
    profile_item["default_provider_id"] = toml_edit::value(default_provider_id);
  } else if let Some(table) = profile_item.as_table_mut() {
    table.remove("default_provider_id");
  }

  if write.account_source == AgentAccountSource::Main {
    if is_verbatim_mode(write.mode) {
      let default_provider_id = write.default_provider_id.expect("verbatim main profile has a provider");
      profile_item["providers"] = array_value(&[default_provider_id.to_string()]);
    } else if let Some(table) = profile_item.as_table_mut() {
      table.remove("providers");
    }
    profile_item.as_table_mut().map(|table| table.remove("accounts"));
    return;
  }

  let account_ids = write
    .accounts
    .iter()
    .map(|account| account.id.clone())
    .collect::<Vec<_>>();
  let mut providers = write
    .accounts
    .iter()
    .map(|account| account.provider.clone())
    .collect::<Vec<_>>();
  if providers.is_empty() {
    providers.push(write.fallback_provider_id.to_string());
  }
  providers.sort();
  providers.dedup();
  profile_item["providers"] = array_value(&providers);
  if write.accounts.is_empty() {
    profile_item.as_table_mut().map(|table| table.remove("accounts"));
  } else {
    profile_item["accounts"] = array_value(&account_ids);
  }
}

fn upsert_switch_profiles(
  doc: &mut toml_edit::DocumentMut,
  profile: &str,
  agent: &AgentId,
  accounts: &[Account],
) -> Result<()> {
  let mut by_provider: BTreeMap<String, Vec<String>> = BTreeMap::new();
  for account in accounts {
    by_provider
      .entry(account.provider.clone())
      .or_default()
      .push(account.id.clone());
  }
  for (provider, account_ids) in by_provider {
    let synthetic_profile = format!("{profile}-{provider}");
    validate_profile_item_owner(doc, &synthetic_profile, agent)?;
    let profiles = doc["profiles"].or_insert(toml_edit::table());
    let item = profiles[synthetic_profile.as_str()].or_insert(toml_edit::table());
    item["mode"] = toml_edit::value("switch");
    item["agent_id"] = toml_edit::value(agent.as_str());
    item["default_provider_id"] = toml_edit::value(provider.as_str());
    item["providers"] = array_value(std::slice::from_ref(&provider));
    item["accounts"] = array_value(&account_ids);
  }
  Ok(())
}

fn upsert_provider_route_profiles(
  doc: &mut toml_edit::DocumentMut,
  agent: &AgentId,
  mode: RouteMode,
  routes: &[ProviderRoute],
) -> Result<()> {
  let profiles = doc["profiles"].or_insert(toml_edit::table());
  for route in routes {
    if route.account_id.is_empty() || route.profile.is_empty() {
      continue;
    }
    if let Some(existing) = profiles.get(route.profile.as_str()) {
      let owner = existing
        .as_table_like()
        .and_then(|profile| profile.get("agent_id"))
        .and_then(toml_edit::Item::as_str);
      if owner != Some(agent.as_str()) {
        bail!(
          "generated profile '{}' already exists and is not owned by {}",
          route.profile,
          agent
        );
      }
    }
    let item = profiles[route.profile.as_str()].or_insert(toml_edit::table());
    item["mode"] = toml_edit::value(route_mode_as_str(mode));
    item["agent_id"] = toml_edit::value(agent.as_str());
    if is_verbatim_mode(mode) {
      item["default_provider_id"] = toml_edit::value(route.gateway_provider_id.as_str());
    } else if let Some(table) = item.as_table_mut() {
      table.remove("default_provider_id");
    }
    item["providers"] = array_value(std::slice::from_ref(&route.gateway_provider_id));
    item["accounts"] = array_value(std::slice::from_ref(&route.account_id));
  }
  Ok(())
}

fn remove_materialized_profile(doc: &mut toml_edit::DocumentMut, profile: &str, agent: &AgentId) {
  if let Some(table) = doc["profiles"].as_table_mut() {
    let owned = table
      .get(profile)
      .and_then(toml_edit::Item::as_table_like)
      .and_then(|profile| profile.get("agent_id"))
      .and_then(toml_edit::Item::as_str)
      == Some(agent.as_str());
    if owned {
      table.remove(profile);
    }
  }
  remove_agent_profiles(doc, profile, agent);
}

fn validate_profile_item_owner(doc: &toml_edit::DocumentMut, profile: &str, agent: &AgentId) -> Result<()> {
  let Some(existing) = doc
    .get("profiles")
    .and_then(toml_edit::Item::as_table_like)
    .and_then(|profiles| profiles.get(profile))
  else {
    return Ok(());
  };
  let owner = existing
    .as_table_like()
    .and_then(|profile| profile.get("agent_id"))
    .and_then(toml_edit::Item::as_str);
  if owner != Some(agent.as_str()) {
    bail!("profile '{profile}' already exists and is not owned by {agent}");
  }
  Ok(())
}

fn remove_agent_profiles(doc: &mut toml_edit::DocumentMut, profile: &str, agent: &AgentId) {
  let Some(table) = doc["profiles"].as_table_mut() else {
    return;
  };
  let prefix = format!("{profile}-");
  let keys = table
    .iter()
    .filter(|(key, item)| {
      key.starts_with(&prefix)
        && item
          .as_table_like()
          .and_then(|profile| profile.get("agent_id"))
          .and_then(toml_edit::Item::as_str)
          == Some(agent.as_str())
    })
    .map(|(key, _)| key.to_string())
    .collect::<Vec<_>>();
  for key in keys {
    table.remove(&key);
  }
}

fn array_value(values: &[String]) -> toml_edit::Item {
  let mut arr = toml_edit::Array::new();
  for value in values {
    arr.push(value.as_str());
  }
  toml_edit::value(arr)
}

fn route_mode_as_str(mode: RouteMode) -> &'static str {
  match mode {
    RouteMode::Passthrough => "passthrough",
    RouteMode::Switch => "switch",
    RouteMode::Exact => "exact",
    RouteMode::Route => "route",
    RouteMode::Fuzzy => "fuzzy",
  }
}

fn resolve_binding_profile(
  explicit_profile: Option<&str>,
  existing_binding: Option<&tokn_config::AgentConfig>,
  agent: &AgentId,
  imported_accounts: &[Account],
  account_source: AgentAccountSource,
  mode: RouteMode,
) -> Result<Option<String>> {
  if let Some(profile) = explicit_profile {
    validate_profile_name(profile)?;
    return Ok(Some(profile.to_string()));
  }
  if let Some(profile) = existing_binding.and_then(|binding| binding.profile.as_deref()) {
    validate_profile_name(profile)?;
    return Ok(Some(profile.to_string()));
  }
  if imported_accounts.is_empty() && account_source != AgentAccountSource::Main && !is_verbatim_mode(mode) {
    return Ok(None);
  }
  Ok(Some(agent.as_str().to_string()))
}

fn validate_profile_name(profile: &str) -> Result<()> {
  if profile.trim().is_empty() || profile.contains('/') {
    bail!("profile name must be non-empty and must not contain '/'");
  }
  Ok(())
}

fn gateway_profile_base_url(cfg: &Config, profile: Option<&str>) -> String {
  match profile {
    Some(profile) => format!("http://{}:{}/{profile}/v1", cfg.server.host, cfg.server.port),
    None => format!("http://{}:{}/v1", cfg.server.host, cfg.server.port),
  }
}

fn timestamp() -> Result<String> {
  let now = time::OffsetDateTime::now_utc();
  let rfc3339 = now.format(&Rfc3339)?;
  Ok(compact_rfc3339_timestamp(&rfc3339))
}

fn compact_rfc3339_timestamp(rfc3339: &str) -> String {
  let compact = rfc3339
    .replace(['-', ':'], "")
    .replace('.', "")
    .trim_end_matches('Z')
    .to_string();
  format!("{compact}Z")
}

fn resolve_home(home: Option<PathBuf>) -> Result<PathBuf> {
  match home {
    Some(home) => Ok(home),
    None => directories::BaseDirs::new()
      .map(|dirs| dirs.home_dir().to_path_buf())
      .ok_or_else(|| anyhow!("cannot resolve home directory")),
  }
}

fn default_gateway_auth_path() -> Result<PathBuf> {
  default_auth_path()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_account(id: &str, provider: &str) -> Account {
    Account {
      id: id.into(),
      provider: provider.into(),
      enabled: true,
      tier: tokn_core::account::AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: None,
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

  fn config_snapshot(path: &Path) -> ConfigSourcesSnapshot {
    let loaded = Config::load_with_sources(Some(path)).unwrap();
    ConfigSourcesSnapshot::capture(loaded.sources).unwrap()
  }

  #[test]
  fn default_gateway_auth_path_uses_auth_store_default() {
    assert_eq!(default_gateway_auth_path().unwrap(), default_auth_path().unwrap());
  }

  #[test]
  fn compact_timestamp_preserves_fractional_seconds() {
    assert_eq!(
      compact_rfc3339_timestamp("2026-06-05T10:11:12.123456789Z"),
      "20260605T101112123456789Z"
    );
  }

  #[test]
  fn plan_reconcile_uses_explicit_agent_home_and_defaults_fresh_links_to_agent_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let agent_home = dir.path().join("agent-home");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(
      &gateway_config_path,
      r#"
[server]
host = "127.0.0.1"
port = 4141
"#,
    )
    .unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::json!({
        "openai": {
          "type": "api",
          "key": "sk-test"
        }
      })
      .to_string(),
    )
    .unwrap();
    std::fs::write(&opencode_config_path, "{\n  // user config\n  \"mcp\": {},\n}\n").unwrap();

    let plan = plan_reconcile(ReconcileRequest {
      agent: AgentId::Opencode,
      profile: None,
      mode: None,
      account_source: None,
      default_provider_id: None,
      source_provider_ids: None,
      gateway_config_path: Some(gateway_config_path.clone()),
      agent_home: Some(agent_home),
    })
    .unwrap();

    assert_eq!(plan.agent, AgentId::Opencode);
    assert_eq!(plan.gateway_config_path, gateway_config_path);
    assert_eq!(plan.target_base_url, "http://127.0.0.1:4141/opencode/v1");
    assert_eq!(plan.binding_profile.as_deref(), Some("opencode"));
    assert_eq!(plan.account_source, AgentAccountSource::Agent);
    assert_eq!(plan.imported_accounts.len(), 1);
    assert_eq!(plan.agent_auth_path.as_deref(), Some(opencode_auth_path.as_path()));
    assert!(plan.edits.iter().any(|edit| edit.path == opencode_config_path));
  }

  #[test]
  fn plan_reconcile_falls_back_to_defaults_when_no_accounts_exist() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let agent_home = dir.path().join("agent-home");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "").unwrap();
    std::fs::write(&opencode_config_path, serde_json::json!({}).to_string()).unwrap();

    let plan = plan_reconcile(ReconcileRequest {
      agent: AgentId::Opencode,
      profile: None,
      mode: None,
      account_source: Some(AgentAccountSource::Agent),
      default_provider_id: None,
      source_provider_ids: None,
      gateway_config_path: Some(gateway_config_path),
      agent_home: Some(agent_home),
    })
    .unwrap();

    assert_eq!(plan.binding_profile, None);
    assert_eq!(plan.target_base_url, "http://127.0.0.1:4141/v1");
  }

  #[test]
  fn opencode_main_account_switch_preserves_auth_and_root_config_and_syncs_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("main-opencode.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();

    let root_config = r#"
[server]
host = "127.0.0.1"
port = 4141

[profiles.user]
providers = ["anthropic"]
"#;
    let opencode_config = r#"{
  // Preserve unrelated user settings.
  "mcp": {"local": true},
}
"#;
    let opencode_auth = b"this need not be valid JSON for a main-account link";
    let gateway_auth = b"this gateway auth fixture is deliberately opaque";
    std::fs::write(&gateway_config_path, root_config).unwrap();
    std::fs::write(&opencode_config_path, opencode_config).unwrap();
    std::fs::write(&opencode_auth_path, opencode_auth).unwrap();
    std::fs::write(&gateway_auth_path, gateway_auth).unwrap();

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: Some(tokn_core::provider::ID_OPENAI.into()),
        source_provider_ids: Some(vec!["openai".into(), "github-copilot".into()]),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    assert!(plan.imported_accounts.is_empty());
    assert!(plan.gateway_auth_snapshot.is_none());
    assert!(plan.source_auth_path.is_none());
    assert!(plan.agent_auth_path.is_none());
    assert_eq!(
      plan.source_provider_ids,
      vec!["github-copilot".to_string(), "openai".to_string()]
    );
    assert_eq!(plan.edits.len(), 1);
    plan.timestamp = "20260714T010101Z".into();

    apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap();

    let fragment_path = tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "opencode");
    assert!(fragment_path.exists());
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), gateway_auth);
    assert_eq!(std::fs::read(&opencode_auth_path).unwrap(), opencode_auth);

    let (effective, _) = Config::load(Some(&gateway_config_path)).unwrap();
    let binding = &effective.agents["opencode"];
    assert_eq!(binding.account_source, AgentAccountSource::Main);
    assert_eq!(binding.mode, Some(RouteMode::Switch));
    assert_eq!(
      binding.source_providers.as_deref(),
      Some(&["github-copilot".to_string(), "openai".to_string()][..])
    );
    let profile = &effective.profiles["opencode"];
    assert_eq!(profile.mode, Some(RouteMode::Switch));
    assert_eq!(
      profile.default_provider_id.as_deref(),
      Some(tokn_core::provider::ID_OPENAI)
    );
    assert_eq!(
      profile.providers.as_deref(),
      Some(&[tokn_core::provider::ID_OPENAI.to_string()][..])
    );
    assert_eq!(profile.accounts, None);

    let rewritten = crate::jsonc::read_jsonc(&opencode_config_path).unwrap();
    assert_eq!(rewritten["mcp"]["local"], true);
    assert_eq!(
      rewritten["provider"]["tokn-router-openai"]["options"]["baseURL"],
      "http://127.0.0.1:4141/opencode/v1"
    );
    assert!(rewritten["provider"].get("tokn-router-github-copilot").is_none());
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.gateway_auth_path, None);
    assert_eq!(manifest.agent_auth_path, None);
    assert!(manifest.credentials_handoff_complete);
    assert!(manifest.imported_account_ids.is_empty());

    let relink_plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Route),
        account_source: None,
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    assert_eq!(relink_plan.account_source, AgentAccountSource::Main);
    assert_eq!(relink_plan.binding_mode, RouteMode::Route);
    assert!(relink_plan.imported_accounts.is_empty());
    assert!(relink_plan.gateway_auth_sources_snapshot.is_none());
    assert!(relink_plan.gateway_auth_snapshot.is_none());
    assert!(relink_plan.gateway_auth_shard_path.is_none());
    assert!(relink_plan.gateway_auth_shard_snapshot.is_none());
    assert!(relink_plan.source_auth_path.is_none());
    assert!(relink_plan.source_auth_snapshot.is_none());
    assert!(relink_plan.agent_auth_path.is_none());
    assert_eq!(
      relink_plan.source_provider_ids,
      vec!["github-copilot".to_string(), "openai".to_string()]
    );
    assert_eq!(
      relink_plan
        .provider_routes
        .iter()
        .map(|route| route.source_provider_id.as_str())
        .collect::<Vec<_>>(),
      vec!["github-copilot", "openai"]
    );

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap();
    assert!(!fragment_path.exists());
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), gateway_auth);
    assert_eq!(std::fs::read(&opencode_auth_path).unwrap(), opencode_auth);
    assert_eq!(std::fs::read_to_string(&opencode_config_path).unwrap(), opencode_config);
  }

  #[test]
  fn switch_with_no_imported_agent_accounts_still_materializes_a_profile() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("no-accounts-switch.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "").unwrap();
    std::fs::write(&opencode_config_path, "{}\n").unwrap();

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path,
    )
    .unwrap();
    assert!(plan.imported_accounts.is_empty());
    assert_eq!(plan.binding_profile.as_deref(), Some("opencode"));
    assert_eq!(
      plan.default_provider_id.as_deref(),
      Some(tokn_core::provider::ID_OPENAI)
    );
    assert_eq!(plan.agent_auth_path, None);
    plan.timestamp = "20260714T010102Z".into();
    apply_reconcile_to_manifest_path(plan, manifest_path).unwrap();

    let (effective, _) = Config::load(Some(&gateway_config_path)).unwrap();
    let profile = &effective.profiles["opencode"];
    assert_eq!(profile.mode, Some(RouteMode::Switch));
    assert_eq!(
      profile.default_provider_id.as_deref(),
      Some(tokn_core::provider::ID_OPENAI)
    );
  }

  #[test]
  fn opencode_switch_rejects_a_responses_only_import_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    let root_config = "[server]\nport = 4141\n";
    let opencode_config = "{\"mcp\": {}}\n";
    let opencode_auth = r#"{"openai":{"type":"oauth","access":"at","refresh":"rt","expires":0}}"#;
    std::fs::write(&gateway_config_path, root_config).unwrap();
    std::fs::write(&opencode_config_path, opencode_config).unwrap();
    std::fs::write(&opencode_auth_path, opencode_auth).unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not support that endpoint"));
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(std::fs::read_to_string(&opencode_config_path).unwrap(), opencode_config);
    assert_eq!(std::fs::read_to_string(&opencode_auth_path).unwrap(), opencode_auth);
    assert!(!gateway_auth_path.exists());
    assert!(!tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "opencode").exists());
  }

  #[test]
  fn main_account_source_provider_ids_reject_empty_and_duplicate_values() {
    let duplicate = vec!["openai".to_string(), "openai".to_string()];
    let error = resolve_main_source_provider_ids(
      Some(&duplicate),
      None,
      AgentAccountSource::Main,
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap_err();
    assert!(error.to_string().contains("more than once"));

    let blank = vec![" ".to_string()];
    let error = resolve_main_source_provider_ids(
      Some(&blank),
      None,
      AgentAccountSource::Main,
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap_err();
    assert!(error.to_string().contains("must not be empty"));
  }

  #[test]
  fn stale_main_source_provider_ids_are_cleaned_on_a_narrower_relink() {
    let existing = tokn_config::AgentConfig {
      account_source: AgentAccountSource::Main,
      source_providers: Some(vec!["openai".into(), "github-copilot".into()]),
      ..Default::default()
    };
    let routes = [ProviderRoute {
      source_provider_id: "openai".into(),
      gateway_provider_id: "openai".into(),
      account_id: String::new(),
      profile: "opencode".into(),
      base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      transfer_source_auth: false,
    }];
    assert_eq!(
      stale_source_provider_ids(Some(&existing), &routes, tokn_core::provider::ID_OPENAI),
      vec!["github-copilot".to_string()]
    );
  }

  #[test]
  fn main_account_link_rejects_codex_cli_without_touching_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let agent_home = dir.path().join("home");
    let codex_auth_path = agent_home.join(".codex/auth.json");
    std::fs::create_dir_all(codex_auth_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();
    std::fs::write(&codex_auth_path, "opaque local credential data").unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::CodexCli,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: Some(tokn_core::provider::ID_OPENAI.into()),
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("cannot use --use-main-accounts"));
    assert_eq!(
      std::fs::read_to_string(codex_auth_path).unwrap(),
      "opaque local credential data"
    );
    assert!(!gateway_auth_path.exists());
  }

  #[test]
  fn changing_from_agent_to_main_accounts_requires_unlink_before_reading_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    let root_config = r#"
[agents.opencode]
mode = "route"
sync = true
"#;
    std::fs::write(&gateway_config_path, root_config).unwrap();
    std::fs::write(&opencode_auth_path, "opaque local credential data").unwrap();
    // An agent-to-main transition is rejected from the existing config
    // binding alone. Deliberately keep both credential files unparsable to
    // prove this path does not inspect either one.
    std::fs::write(&gateway_auth_path, "opaque gateway credential data").unwrap();
    let gateway_auth = std::fs::read(&gateway_auth_path).unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: Some(tokn_core::provider::ID_OPENAI.into()),
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("changing account source"));
    assert!(error.to_string().contains("agent unlink opencode"));
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), gateway_auth);
    assert_eq!(
      std::fs::read_to_string(opencode_auth_path).unwrap(),
      "opaque local credential data"
    );
  }

  #[test]
  fn changing_from_main_to_agent_accounts_requires_unlink_before_reading_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    let root_config = r#"
[agents.opencode]
account_source = "main"
mode = "route"
sync = true
"#;
    std::fs::write(&gateway_config_path, root_config).unwrap();
    std::fs::write(&opencode_auth_path, "opaque local credential data").unwrap();
    std::fs::write(&gateway_auth_path, "opaque gateway credential data").unwrap();
    let gateway_auth = std::fs::read(&gateway_auth_path).unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("changing account source"));
    assert!(error.to_string().contains("agent unlink opencode"));
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), gateway_auth);
    assert_eq!(
      std::fs::read_to_string(opencode_auth_path).unwrap(),
      "opaque local credential data"
    );
  }

  #[test]
  fn legacy_agent_link_with_root_owned_credentials_requires_unlink_before_sharding() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    let root_config = r#"
[agents.opencode]
mode = "route"
sync = true
"#;
    std::fs::write(&gateway_config_path, root_config).unwrap();
    let mut store = AuthStore::load(Some(&gateway_auth_path), Some(&gateway_config_path)).unwrap();
    store.upsert(annotate_imported_account(
      sample_account("opencode-openai", tokn_core::provider::ID_OPENAI),
      AgentId::Opencode,
      Path::new("/tmp/opencode-auth.json"),
      "auth.openai",
      "20260714T020102Z",
    ));
    store.save().unwrap();
    let root_auth = std::fs::read(&gateway_auth_path).unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("legacy imported accounts"));
    assert!(error.to_string().contains("agent unlink opencode"));
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), root_auth);
    assert!(!gateway_auth_path
      .with_file_name("auth.d")
      .join("opencode.yaml")
      .exists());
  }

  #[test]
  fn apply_reconcile_rejects_a_fragment_added_after_planning() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("manifest.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();
    std::fs::write(&opencode_config_path, "{}\n").unwrap();

    let plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Route),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap();
    let added_fragment = tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "codex-cli");
    std::fs::create_dir_all(added_fragment.parent().unwrap()).unwrap();
    std::fs::write(
      &added_fragment,
      r#"
[agents.codex-cli]
mode = "route"
"#,
    )
    .unwrap();

    let error = apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap_err();
    assert!(error.to_string().contains("config sources changed"));
    assert!(!manifest_path.exists());
    assert_eq!(std::fs::read_to_string(opencode_config_path).unwrap(), "{}\n");
  }

  #[test]
  fn apply_reconcile_rejects_an_auth_shard_added_after_planning() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("manifest.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();
    std::fs::write(&gateway_auth_path, "version: 1\naccounts: []\n").unwrap();
    std::fs::write(&opencode_config_path, "{}\n").unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::json!({"openai": {"type": "api", "key": "sk-planned"}}).to_string(),
    )
    .unwrap();

    let plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    let added_shard = gateway_auth_path.parent().unwrap().join("auth.d/codex-cli.yaml");
    std::fs::create_dir_all(added_shard.parent().unwrap()).unwrap();
    std::fs::write(&added_shard, "version: 1\naccounts: []\n").unwrap();

    let error = apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap_err();

    assert!(error.to_string().contains("gateway auth sources changed"));
    assert!(!manifest_path.exists());
    assert_eq!(std::fs::read_to_string(opencode_config_path).unwrap(), "{}\n");
    assert!(std::fs::read_to_string(opencode_auth_path)
      .unwrap()
      .contains("sk-planned"));
  }

  #[test]
  fn apply_reconcile_rejects_agent_files_changed_after_planning() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("manifest.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    let gateway_config = "[server]\nhost = \"127.0.0.1\"\nport = 4141\n";
    let opencode_config = "{\n  // user config\n}\n";
    std::fs::write(&gateway_config_path, gateway_config).unwrap();
    std::fs::write(&opencode_config_path, opencode_config).unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::to_vec_pretty(&serde_json::json!({
        "openai": {"type": "api", "key": "sk-planned"}
      }))
      .unwrap(),
    )
    .unwrap();

    let plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    let changed_auth = serde_json::json!({
      "openai": {"type": "api", "key": "sk-rotated"},
      "anthropic": {"type": "api", "key": "keep-new"}
    });
    std::fs::write(&opencode_auth_path, serde_json::to_vec_pretty(&changed_auth).unwrap()).unwrap();

    let error = apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap_err();

    assert!(error.to_string().contains("changed after the agent migration plan"));
    assert_eq!(std::fs::read_to_string(gateway_config_path).unwrap(), gateway_config);
    assert!(!gateway_auth_path.exists());
    assert!(!manifest_path.exists());
    assert_eq!(std::fs::read_to_string(opencode_config_path).unwrap(), opencode_config);
    assert_eq!(
      serde_json::from_str::<Value>(&std::fs::read_to_string(opencode_auth_path).unwrap()).unwrap(),
      changed_auth
    );
  }

  #[test]
  fn apply_reconcile_rejects_managed_auth_shard_changed_after_planning() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let first_manifest_path = dir.path().join("first-manifest.json");
    let second_manifest_path = dir.path().join("second-manifest.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    let gateway_config = "[server]\nhost = \"127.0.0.1\"\nport = 4141\n";
    let opencode_config = "{\n  // user config\n}\n";
    std::fs::write(&gateway_config_path, gateway_config).unwrap();
    let root_auth = b"version: 1\naccounts: []\n";
    std::fs::write(&gateway_auth_path, root_auth).unwrap();
    std::fs::write(&opencode_config_path, opencode_config).unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::json!({"openai": {"type": "api", "key": "sk-planned"}}).to_string(),
    )
    .unwrap();

    let mut first_plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    first_plan.timestamp = "20260714T020104Z".into();
    apply_reconcile_to_manifest_path(first_plan, first_manifest_path).unwrap();

    let sync_plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    assert_eq!(sync_plan.imported_accounts.len(), 1);
    let gateway_auth_shard_path = sync_plan.gateway_auth_shard_path.clone().unwrap();
    let linked_opencode_config = std::fs::read_to_string(&opencode_config_path).unwrap();

    let mut rotated_store = AuthStore::load(Some(&gateway_auth_path), None).unwrap();
    rotated_store.get_mut("opencode-openai").unwrap().api_key =
      Some(tokn_core::util::secret::Secret::new("sk-rotated".into()));
    rotated_store.save().unwrap();
    let rotated_gateway_auth_shard = std::fs::read(&gateway_auth_shard_path).unwrap();

    let error = apply_reconcile_to_manifest_path(sync_plan, second_manifest_path.clone()).unwrap_err();

    assert!(error.to_string().contains("changed after the agent migration plan"));
    assert!(error
      .to_string()
      .contains(&gateway_auth_shard_path.display().to_string()));
    assert_eq!(std::fs::read_to_string(gateway_config_path).unwrap(), gateway_config);
    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), root_auth);
    assert_eq!(
      std::fs::read(gateway_auth_shard_path).unwrap(),
      rotated_gateway_auth_shard
    );
    assert_eq!(
      std::fs::read_to_string(opencode_config_path).unwrap(),
      linked_opencode_config
    );
    assert!(!second_manifest_path.exists());
  }

  #[test]
  fn opencode_v1_link_upgrades_and_unlinks_through_the_manifest_chain() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    let original_backup_path = dir.path().join("opencode.json.before-v1");
    let first_manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    let second_manifest_path = dir.path().join("20260604T153013Z-opencode.json");
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();

    let original = r#"{
  // Original user config.
  "mcp": {"x": true}
}"#;
    let legacy = r#"{
  // Original user config.
  "mcp": {"x": true},
  "provider": {
    "tokn-router": {
      "name": "tokn-router",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/v1"
      }
    }
  }
}"#;
    std::fs::write(&original_backup_path, original).unwrap();
    std::fs::write(&opencode_config_path, legacy).unwrap();
    std::fs::write(
      &gateway_config_path,
      r#"[server]
host = "127.0.0.1"
port = 4141

[agents.opencode]
mode = "route"
sync = true
"#,
    )
    .unwrap();
    manifest::write_manifest(
      &first_manifest_path,
      &MigrationManifest {
        version: 1,
        completed: true,
        agent: AgentId::Opencode,
        timestamp: "20260604T153012Z".into(),
        profile: None,
        target_base_url: "http://127.0.0.1:4141/v1".into(),
        gateway_auth_path: None,
        gateway_auth_shard_path: None,
        agent_auth_path: None,
        provider_routes: Vec::new(),
        previous_manifest: None,
        unlinked: false,
        credentials_handoff_complete: false,
        imported_account_ids: Vec::new(),
        files: vec![FileBackup {
          original: opencode_config_path.clone(),
          backup: Some(original_backup_path),
          existed: true,
          created_by_migration: false,
        }],
      },
    )
    .unwrap();

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap();
    plan.timestamp = "20260604T153013Z".into();
    plan.previous_manifest = Some(first_manifest_path.clone());

    apply_reconcile_to_manifest_path(plan, second_manifest_path.clone()).unwrap();

    let linked = crate::jsonc::read_jsonc(&opencode_config_path).unwrap();
    assert!(linked["provider"].get("tokn-router").is_none());
    assert_eq!(
      linked["provider"]["openai"]["options"]["baseURL"],
      "http://127.0.0.1:4141/v1"
    );

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(second_manifest_path.display().to_string()),
    })
    .unwrap();

    assert_eq!(std::fs::read_to_string(opencode_config_path).unwrap(), original);
    assert!(manifest::read_manifest(&first_manifest_path).unwrap().unlinked);
    assert!(manifest::read_manifest(&second_manifest_path).unwrap().unlinked);
  }

  #[test]
  fn validate_profile_name_rejects_empty_and_path_like_names() {
    assert!(validate_profile_name("").is_err());
    assert!(validate_profile_name("   ").is_err());
    assert!(validate_profile_name("agent/profile").is_err());
    assert!(validate_profile_name("agent").is_ok());
  }

  #[test]
  fn upsert_agent_and_profiles_without_imported_accounts_scopes_to_agent_provider() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    upsert_agent_and_profiles(
      &path,
      &AgentId::Opencode,
      Some("opencode"),
      RouteMode::Route,
      &[],
      &[],
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap();

    let (cfg, _) = Config::load(Some(&path)).unwrap();
    let agent = cfg.agents.get("opencode").unwrap();
    assert_eq!(agent.mode, Some(RouteMode::Route));
    assert_eq!(agent.profile.as_deref(), Some("opencode"));
    assert!(agent.sync);
    let profile = cfg.profiles.get("opencode").unwrap();
    assert_eq!(profile.agent_id, Some(AgentId::Opencode));
    assert_eq!(
      profile.providers.as_deref(),
      Some(&[tokn_core::provider::ID_OPENAI.to_string()][..])
    );
    assert_eq!(profile.accounts, None);
  }

  #[test]
  fn upsert_agent_and_profiles_with_imported_accounts_scopes_to_accounts_and_providers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let accounts = vec![sample_account("codex-cli-codex", tokn_core::provider::ID_CODEX)];

    upsert_agent_and_profiles(
      &path,
      &AgentId::CodexCli,
      Some("codex"),
      RouteMode::Route,
      &accounts,
      &[],
      tokn_core::provider::ID_CODEX,
    )
    .unwrap();

    let (cfg, _) = Config::load(Some(&path)).unwrap();
    let agent = cfg.agents.get("codex-cli").unwrap();
    assert_eq!(agent.profile.as_deref(), Some("codex"));
    let profile = cfg.profiles.get("codex").unwrap();
    assert_eq!(profile.agent_id, Some(AgentId::CodexCli));
    assert_eq!(
      profile.providers.as_deref(),
      Some(&[tokn_core::provider::ID_CODEX.to_string()][..])
    );
    assert_eq!(profile.accounts.as_deref(), Some(&["codex-cli-codex".to_string()][..]));
  }

  #[test]
  fn provider_route_profiles_reject_unowned_name_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let original = r#"[profiles.opencode-openai]
providers = ["anthropic"]
"#;
    std::fs::write(&path, original).unwrap();
    let account = sample_account("opencode-openai", tokn_core::provider::ID_OPENAI);
    let routes = [ProviderRoute {
      source_provider_id: "openai".into(),
      gateway_provider_id: tokn_core::provider::ID_OPENAI.into(),
      account_id: account.id.clone(),
      profile: "opencode-openai".into(),
      base_url: "http://127.0.0.1:4141/opencode-openai/v1".into(),
      transfer_source_auth: true,
    }];

    let error = upsert_agent_and_profiles(
      &path,
      &AgentId::Opencode,
      Some("opencode"),
      RouteMode::Route,
      &[account],
      &routes,
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap_err();

    assert!(error.to_string().contains("is not owned by opencode"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
  }

  #[test]
  fn base_profile_rejects_unowned_name_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let original = r#"[profiles.shared]
providers = ["anthropic"]
"#;
    std::fs::write(&path, original).unwrap();

    let error = upsert_agent_and_profiles(
      &path,
      &AgentId::Opencode,
      Some("shared"),
      RouteMode::Route,
      &[],
      &[],
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap_err();

    assert!(error.to_string().contains("profile 'shared' already exists"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
  }

  #[test]
  fn changing_binding_preserves_an_unowned_previous_profile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
      &path,
      r#"[agents.opencode]
profile = "shared"

[profiles.shared]
providers = ["anthropic"]
"#,
    )
    .unwrap();

    upsert_agent_and_profiles(
      &path,
      &AgentId::Opencode,
      Some("opencode"),
      RouteMode::Route,
      &[],
      &[],
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap();

    let (config, _) = Config::load(Some(&path)).unwrap();
    assert_eq!(config.agents["opencode"].profile.as_deref(), Some("opencode"));
    assert_eq!(
      config.profiles["shared"].providers.as_deref(),
      Some(&["anthropic".into()][..])
    );
    assert_eq!(config.profiles["opencode"].agent_id, Some(AgentId::Opencode));
  }

  #[test]
  fn switch_profiles_reject_unowned_name_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let original = r#"[profiles.opencode-openai]
providers = ["anthropic"]
"#;
    std::fs::write(&path, original).unwrap();
    let account = sample_account("opencode-openai", tokn_core::provider::ID_OPENAI);

    let error = upsert_agent_and_profiles(
      &path,
      &AgentId::Opencode,
      Some("opencode"),
      RouteMode::Switch,
      &[account],
      &[],
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap_err();

    assert!(error.to_string().contains("profile 'opencode-openai' already exists"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
  }

  #[test]
  fn upsert_agent_and_profiles_respects_switch_mode_with_synthetic_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut openai = sample_account("opencode-openai", tokn_core::provider::ID_OPENAI);
    let mut codex = sample_account("opencode-codex", tokn_core::provider::ID_CODEX);
    openai.tags.push("source:opencode".into());
    codex.tags.push("source:opencode".into());

    upsert_agent_and_profiles(
      &path,
      &AgentId::Opencode,
      Some("opencode"),
      RouteMode::Switch,
      &[openai, codex],
      &[],
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap();

    let (cfg, _) = Config::load(Some(&path)).unwrap();
    assert_eq!(cfg.agents["opencode"].mode, Some(RouteMode::Switch));
    assert_eq!(cfg.profiles["opencode"].mode, Some(RouteMode::Switch));
    assert_eq!(
      cfg.profiles["opencode-openai"].accounts.as_deref(),
      Some(&["opencode-openai".to_string()][..])
    );
    assert_eq!(
      cfg.profiles["opencode-codex"].accounts.as_deref(),
      Some(&["opencode-codex".to_string()][..])
    );
  }

  #[test]
  fn disable_missing_root_source_accounts_disables_previously_imported_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    store
      .upsert_in_main(annotate_imported_account(
        sample_account("opencode-openai", tokn_core::provider::ID_OPENAI),
        AgentId::Opencode,
        Path::new("/tmp/opencode-auth.json"),
        "auth.openai",
        "20260604T153012Z",
      ))
      .unwrap();
    store
      .upsert_in_main(sample_account("manual-openai", tokn_core::provider::ID_OPENAI))
      .unwrap();

    disable_missing_root_source_accounts(&mut store, &AgentId::Opencode, &BTreeSet::new());

    let imported = store.get("opencode-openai").unwrap();
    assert!(!imported.enabled);
    assert!(imported.tags.iter().any(|tag| tag == "source:missing"));
    assert!(store.get("manual-openai").unwrap().enabled);
  }

  #[test]
  fn agent_import_only_disables_root_accounts_and_leaves_agent_shards_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let agent_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(agent_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();

    let mut store = AuthStore::load(Some(&gateway_auth_path), None).unwrap();
    store
      .upsert_in_main(annotate_imported_account(
        sample_account("opencode-root-stale", tokn_core::provider::ID_OPENAI),
        AgentId::Opencode,
        &agent_auth_path,
        "auth.root-stale",
        "20260714T030101Z",
      ))
      .unwrap();
    store
      .upsert_in_shard(
        AgentId::Opencode.as_str(),
        annotate_imported_account(
          sample_account("opencode-shard-stale", tokn_core::provider::ID_OPENAI),
          AgentId::Opencode,
          &agent_auth_path,
          "auth.shard-stale",
          "20260714T030101Z",
        ),
      )
      .unwrap();
    store.save().unwrap();
    let shard_path = AuthStore::shard_path_for(&gateway_auth_path, AgentId::Opencode.as_str()).unwrap();
    let shard_before_import = std::fs::read(&shard_path).unwrap();

    std::fs::write(
      &agent_auth_path,
      serde_json::json!({"openai": {"type": "api", "key": "sk-imported"}}).to_string(),
    )
    .unwrap();
    let report = import_accounts_with_gateway_auth_path(
      ImportRequest {
        agent: AgentId::Opencode,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();

    assert_eq!(report.disabled_account_ids, vec!["opencode-root-stale"]);
    let store = AuthStore::load(Some(&gateway_auth_path), Some(&gateway_config_path)).unwrap();
    assert!(!store.get("opencode-root-stale").unwrap().enabled);
    assert_eq!(store.account_source("opencode-root-stale"), Some(AuthSource::Main));
    assert!(store.get("opencode-shard-stale").unwrap().enabled);
    assert_eq!(
      store.account_source("opencode-shard-stale"),
      Some(AuthSource::Shard(AgentId::Opencode.as_str().into()))
    );
    assert_eq!(store.account_source("opencode-openai"), Some(AuthSource::Main));
    assert_eq!(std::fs::read(&shard_path).unwrap(), shard_before_import);
  }

  #[test]
  fn agent_import_refuses_to_replace_an_account_owned_by_an_agent_shard() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let agent_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(agent_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();

    let mut store = AuthStore::load(Some(&gateway_auth_path), None).unwrap();
    store
      .upsert_in_shard(
        AgentId::Opencode.as_str(),
        sample_account("opencode-openai", tokn_core::provider::ID_OPENAI),
      )
      .unwrap();
    store.save().unwrap();
    let shard_path = AuthStore::shard_path_for(&gateway_auth_path, AgentId::Opencode.as_str()).unwrap();
    let shard_before_import = std::fs::read(&shard_path).unwrap();

    std::fs::write(
      &agent_auth_path,
      serde_json::json!({"openai": {"type": "api", "key": "sk-imported"}}).to_string(),
    )
    .unwrap();
    let error = import_accounts_with_gateway_auth_path(
      ImportRequest {
        agent: AgentId::Opencode,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("already owned by"));
    assert!(!gateway_auth_path.exists());
    assert_eq!(std::fs::read(&shard_path).unwrap(), shard_before_import);
  }

  #[test]
  fn transferred_account_replaces_an_old_credential_for_the_same_source_provider() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.yaml");
    let source_path = dir.path().join("opencode-auth.json");
    let mut old = annotate_imported_account(
      sample_account("opencode-codex", tokn_core::provider::ID_CODEX),
      AgentId::Opencode,
      &source_path,
      "auth.openai",
      "20260604T153012Z",
    );
    old
      .settings
      .get_mut("import")
      .and_then(toml::Value::as_table_mut)
      .unwrap()
      .insert("source_provider".into(), toml::Value::String("openai".into()));
    let old = mark_gateway_owned(old);
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let shard_path = AuthStore::shard_path_for(&auth_path, AgentId::Opencode.as_str()).unwrap();
    store.upsert_in_shard(AgentId::Opencode.as_str(), old).unwrap();

    let mut replacement = annotate_imported_account(
      sample_account("opencode-openai", tokn_core::provider::ID_OPENAI),
      AgentId::Opencode,
      &source_path,
      "auth.openai",
      "20260604T153013Z",
    );
    replacement
      .settings
      .get_mut("import")
      .and_then(toml::Value::as_table_mut)
      .unwrap()
      .insert("source_provider".into(), toml::Value::String("openai".into()));

    let desired = merge_transferred_accounts(&store, &AgentId::Opencode, &shard_path, vec![replacement]);
    remove_replaced_gateway_accounts(&mut store, &AgentId::Opencode, &shard_path, &desired);

    assert_eq!(desired.len(), 1);
    assert_eq!(desired[0].id, "opencode-openai");
    assert!(store.accounts.is_empty());
  }

  #[test]
  fn write_edit_creates_parent_directories_for_json_and_toml() {
    let dir = tempfile::tempdir().unwrap();
    let json_path = dir.path().join("nested/auth.json");
    let toml_path = dir.path().join("nested/config.toml");
    let mut doc = toml_edit::DocumentMut::new();
    doc["model_provider"] = toml_edit::value("tokn-router");

    write_edit(&PlannedEdit::new(
      json_path.clone(),
      EditKind::Json(serde_json::json!({"auth_mode": "api_key"})),
      true,
      None,
    ))
    .unwrap();
    write_edit(&PlannedEdit::new(toml_path.clone(), EditKind::Toml(doc), true, None)).unwrap();

    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(json_path).unwrap()).unwrap();
    assert_eq!(json["auth_mode"], "api_key");
    assert!(std::fs::read_to_string(toml_path).unwrap().contains("model_provider"));
  }

  #[test]
  fn planned_edit_debug_redacts_file_contents() {
    let edit = PlannedEdit::new(
      PathBuf::from("auth.json"),
      EditKind::Json(serde_json::json!({"key": "super-secret"})),
      false,
      Some(b"super-secret".to_vec()),
    );

    let debug = format!("{edit:?}");
    assert!(!debug.contains("super-secret"));
    assert!(debug.contains("length"));
  }

  #[test]
  fn apply_reconcile_writes_gateway_state_agent_edits_and_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let gateway_auth_shard_path = dir.path().join("gateway/auth.d/opencode.yaml");
    let gateway_config_fragment_path =
      tokn_config::paths::agent_config_fragment_path(&gateway_config_path, AgentId::Opencode.as_str());
    let agent_config_path = dir.path().join("agent/config.json");
    let manifest_path = dir.path().join("manifest.json");
    let mut account = sample_account("opencode-openai", tokn_core::provider::ID_OPENAI);
    account.api_key = Some(tokn_core::util::secret::Secret::new("sk-test".to_string()));
    let plan = ReconcilePlan {
      agent: AgentId::Opencode,
      timestamp: "20260604T153012Z".into(),
      gateway_config_path: gateway_config_path.clone(),
      gateway_config_fragment_path: gateway_config_fragment_path.clone(),
      gateway_auth_path: gateway_auth_path.clone(),
      gateway_auth_shard_path: Some(gateway_auth_shard_path.clone()),
      gateway_config_snapshot: config_snapshot(&gateway_config_path),
      gateway_auth_sources_snapshot: None,
      gateway_auth_snapshot: Some(FileSnapshot::Missing),
      gateway_auth_shard_snapshot: Some(FileSnapshot::Missing),
      source_auth_path: Some(dir.path().join("source-auth.json")),
      source_auth_snapshot: Some(FileSnapshot::Missing),
      agent_auth_path: Some(dir.path().join("agent/auth.json")),
      binding_profile: Some("opencode".into()),
      binding_mode: RouteMode::Route,
      account_source: AgentAccountSource::Agent,
      default_provider_id: None,
      source_provider_ids: Vec::new(),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      imported_accounts: vec![account],
      provider_routes: Vec::new(),
      edits: vec![PlannedEdit::new(
        agent_config_path.clone(),
        EditKind::Json(serde_json::json!({"provider": "tokn-router"})),
        true,
        None,
      )],
      previous_manifest: None,
    };

    let report = apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap();

    assert_eq!(report.manifest_path, manifest_path);
    assert!(!gateway_config_path.exists());
    assert!(gateway_config_fragment_path.exists());
    assert!(!gateway_auth_path.exists());
    assert!(gateway_auth_shard_path.exists());
    assert_eq!(
      serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(agent_config_path).unwrap()).unwrap()
        ["provider"],
      "tokn-router"
    );
    let manifest: MigrationManifest = serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    assert!(manifest.completed);
    assert_eq!(manifest.imported_account_ids, vec!["opencode-openai"]);
    assert_eq!(manifest.profile.as_deref(), Some("opencode"));
    assert_eq!(manifest.gateway_auth_path.as_deref(), Some(gateway_auth_path.as_path()));
    assert_eq!(
      manifest.gateway_auth_shard_path.as_deref(),
      Some(gateway_auth_shard_path.as_path())
    );
    assert!(report
      .files
      .iter()
      .any(|file| file.original == gateway_config_fragment_path));
    assert!(report.files.iter().any(|file| file.original == gateway_auth_shard_path));
  }

  #[test]
  fn apply_reconcile_leaves_in_progress_manifest_if_later_edit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let gateway_auth_shard_path = dir.path().join("gateway/auth.d/opencode.yaml");
    let gateway_config_fragment_path =
      tokn_config::paths::agent_config_fragment_path(&gateway_config_path, AgentId::Opencode.as_str());
    let edit_path = dir.path().join("agent/config.json");
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(dir.path().join("agent"), "not a directory").unwrap();
    let mut account = sample_account("opencode-openai", tokn_core::provider::ID_OPENAI);
    account.api_key = Some(tokn_core::util::secret::Secret::new("sk-test".to_string()));
    let plan = ReconcilePlan {
      agent: AgentId::Opencode,
      timestamp: "20260604T153012Z".into(),
      gateway_config_path: gateway_config_path.clone(),
      gateway_config_fragment_path,
      gateway_auth_path,
      gateway_auth_shard_path: Some(gateway_auth_shard_path),
      gateway_config_snapshot: config_snapshot(&gateway_config_path),
      gateway_auth_sources_snapshot: None,
      gateway_auth_snapshot: Some(FileSnapshot::Missing),
      gateway_auth_shard_snapshot: Some(FileSnapshot::Missing),
      source_auth_path: Some(dir.path().join("source-auth.json")),
      source_auth_snapshot: Some(FileSnapshot::Missing),
      agent_auth_path: Some(dir.path().join("agent/auth.json")),
      binding_profile: Some("opencode".into()),
      binding_mode: RouteMode::Route,
      account_source: AgentAccountSource::Agent,
      default_provider_id: None,
      source_provider_ids: Vec::new(),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      imported_accounts: vec![account],
      provider_routes: Vec::new(),
      edits: vec![PlannedEdit::new(
        edit_path.clone(),
        EditKind::Json(serde_json::json!({"provider": "tokn-router"})),
        true,
        None,
      )],
      previous_manifest: None,
    };

    let err = apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap_err();

    assert!(format!("{err:#}").contains("creating"));
    let manifest: MigrationManifest = serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    assert!(!manifest.completed);
    assert!(manifest.files.iter().any(|file| file.original == edit_path));
  }

  #[test]
  fn opencode_link_keeps_root_auth_unchanged_and_restores_its_own_shard() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let gateway_auth_shard_path = dir.path().join("gateway/auth.d/opencode.yaml");
    let manifest_path = dir.path().join("opencode-link.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();

    let root_config = "[server]\nhost = \"127.0.0.1\"\nport = 4141\n";
    let root_auth = b"version: 1\naccounts: []\n";
    let original_opencode_config = "{\n  // user config\n  \"mcp\": {}\n}\n";
    let original_opencode_auth = serde_json::json!({
      "openai": {"type": "api", "key": "sk-opencode"}
    });
    std::fs::write(&gateway_config_path, root_config).unwrap();
    std::fs::write(&gateway_auth_path, root_auth).unwrap();
    std::fs::write(&opencode_config_path, original_opencode_config).unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::to_vec_pretty(&original_opencode_auth).unwrap(),
    )
    .unwrap();

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        source_provider_ids: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    assert_eq!(
      plan.gateway_auth_shard_path.as_deref(),
      Some(gateway_auth_shard_path.as_path())
    );
    plan.timestamp = "20260714T020101Z".into();

    apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap();

    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), root_auth);
    assert!(gateway_auth_shard_path.exists());
    assert!(std::fs::read_to_string(&gateway_auth_shard_path)
      .unwrap()
      .contains("opencode-openai"));
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.gateway_auth_path.as_deref(), Some(gateway_auth_path.as_path()));
    assert_eq!(
      manifest.gateway_auth_shard_path.as_deref(),
      Some(gateway_auth_shard_path.as_path())
    );
    assert!(manifest
      .files
      .iter()
      .any(|file| file.original == gateway_auth_shard_path));
    assert!(!manifest.files.iter().any(|file| file.original == gateway_auth_path));

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap();

    assert_eq!(std::fs::read(&gateway_auth_path).unwrap(), root_auth);
    assert!(!gateway_auth_shard_path.exists());
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(
      std::fs::read_to_string(&opencode_config_path).unwrap(),
      original_opencode_config
    );
    assert_eq!(
      serde_json::from_str::<Value>(&std::fs::read_to_string(&opencode_auth_path).unwrap()).unwrap(),
      original_opencode_auth
    );
  }

  #[test]
  fn successor_cannot_skip_an_older_pending_opencode_credential_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let previous_manifest_path = dir.path().join("previous-opencode.json");
    manifest::write_manifest(
      &previous_manifest_path,
      &MigrationManifest {
        version: 4,
        completed: true,
        agent: AgentId::Opencode,
        timestamp: "20260714T020102Z".into(),
        profile: Some("opencode".into()),
        target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
        gateway_auth_path: Some(gateway_auth_path.clone()),
        gateway_auth_shard_path: Some(dir.path().join("gateway/auth.d/opencode.yaml")),
        agent_auth_path: Some(dir.path().join("home/.local/share/opencode/auth.json")),
        provider_routes: Vec::new(),
        previous_manifest: None,
        unlinked: false,
        credentials_handoff_complete: false,
        imported_account_ids: vec!["opencode-openai".into()],
        files: Vec::new(),
      },
    )
    .unwrap();
    let plan = ReconcilePlan {
      agent: AgentId::Opencode,
      timestamp: "20260714T020103Z".into(),
      gateway_config_path: gateway_config_path.clone(),
      gateway_config_fragment_path: dir.path().join("gateway/config.d/opencode.toml"),
      gateway_auth_path,
      gateway_auth_shard_path: None,
      gateway_config_snapshot: config_snapshot(&gateway_config_path),
      gateway_auth_sources_snapshot: None,
      gateway_auth_snapshot: None,
      gateway_auth_shard_snapshot: None,
      source_auth_path: None,
      source_auth_snapshot: None,
      agent_auth_path: None,
      binding_profile: Some("opencode".into()),
      binding_mode: RouteMode::Route,
      account_source: AgentAccountSource::Agent,
      default_provider_id: None,
      source_provider_ids: Vec::new(),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      imported_accounts: Vec::new(),
      provider_routes: Vec::new(),
      edits: Vec::new(),
      previous_manifest: Some(previous_manifest_path),
    };

    let error = reject_successor_without_pending_credentials(&plan).unwrap_err();

    assert!(error.to_string().contains("pending credential handoff"));
  }

  #[test]
  fn opencode_transfer_survives_sync_and_unlink_exports_latest_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    let first_manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    let second_manifest_path = dir.path().join("20260604T153013Z-opencode.json");
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();

    let original_gateway_config = r#"[server]
host = "127.0.0.1"
port = 4141

[profiles.existing]
providers = ["openai"]

[profiles.opencode-user]
providers = ["anthropic"]
"#;
    let original_opencode_config = r#"{
  // Preserve the user's global model choice.
  "model": "openai/gpt-5",
  "provider": {
    "anthropic": {
      "options": { "apiKey": "leave-alone" },
    },
  },
}
"#;
    std::fs::write(&gateway_config_path, original_gateway_config).unwrap();
    std::fs::write(&opencode_config_path, original_opencode_config).unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::to_vec_pretty(&serde_json::json!({
        "openai": {
          "type": "api",
          "key": "sk-original"
        },
        "github-copilot": {
          "type": "oauth",
          "refresh": "ghu-original",
          "access": "tid-original",
          "expires": 0
        },
        "anthropic": {
          "type": "api",
          "key": "anthropic-keep"
        }
      }))
      .unwrap(),
    )
    .unwrap();

    let request = || ReconcileRequest {
      agent: AgentId::Opencode,
      profile: None,
      mode: None,
      account_source: Some(AgentAccountSource::Agent),
      default_provider_id: None,
      source_provider_ids: None,
      gateway_config_path: Some(gateway_config_path.clone()),
      agent_home: Some(agent_home.clone()),
    };
    let mut first_plan = plan_reconcile_with_gateway_auth_path(request(), gateway_auth_path.clone()).unwrap();
    first_plan.timestamp = "20260604T153012Z".into();
    assert_eq!(first_plan.imported_accounts.len(), 2);
    assert_eq!(first_plan.provider_routes.len(), 2);
    assert!(first_plan
      .provider_routes
      .iter()
      .all(|route| route.transfer_source_auth));
    apply_reconcile_to_manifest_path(first_plan, first_manifest_path.clone()).unwrap();

    let linked_auth: Value = serde_json::from_str(&std::fs::read_to_string(&opencode_auth_path).unwrap()).unwrap();
    assert!(linked_auth.get("openai").is_none());
    assert!(linked_auth.get("github-copilot").is_none());
    assert_eq!(linked_auth["anthropic"]["key"], "anthropic-keep");

    let linked_config = crate::jsonc::read_jsonc(&opencode_config_path).unwrap();
    assert_eq!(linked_config["model"], "openai/gpt-5");
    assert_eq!(
      linked_config["provider"]["openai"]["options"]["baseURL"],
      "http://127.0.0.1:4141/opencode-openai/v1"
    );
    assert_eq!(
      linked_config["provider"]["github-copilot"]["options"]["baseURL"],
      "http://127.0.0.1:4141/opencode-github-copilot/v1"
    );
    assert!(std::fs::read_to_string(&opencode_config_path)
      .unwrap()
      .contains("Preserve the user's global model choice"));

    let (linked_gateway_config, _) = Config::load(Some(&gateway_config_path)).unwrap();
    assert!(linked_gateway_config.profiles.contains_key("opencode-user"));
    assert_eq!(
      linked_gateway_config.profiles["opencode-openai"].accounts.as_deref(),
      Some(&["opencode-openai".to_string()][..])
    );
    assert_eq!(
      linked_gateway_config.profiles["opencode-github-copilot"]
        .accounts
        .as_deref(),
      Some(&["opencode-github-copilot".to_string()][..])
    );

    let mut store = AuthStore::load(Some(&gateway_auth_path), None).unwrap();
    assert_eq!(
      store.get("opencode-openai").unwrap().api_key.as_ref().unwrap().expose(),
      "sk-original"
    );
    assert_eq!(
      store
        .get("opencode-github-copilot")
        .unwrap()
        .refresh_token
        .as_ref()
        .unwrap()
        .expose(),
      "ghu-original"
    );
    store.get_mut("opencode-openai").unwrap().api_key = Some(tokn_core::util::secret::Secret::new("sk-latest".into()));
    let copilot = store.get_mut("opencode-github-copilot").unwrap();
    copilot.refresh_token = Some(tokn_core::util::secret::Secret::new("ghu-latest".into()));
    copilot.access_token = Some(tokn_core::util::secret::Secret::new("tid-latest".into()));
    copilot.access_token_expires_at = Some(222);
    store.save().unwrap();

    let mut second_plan = plan_reconcile_with_gateway_auth_path(request(), gateway_auth_path.clone()).unwrap();
    second_plan.timestamp = "20260604T153013Z".into();
    second_plan.previous_manifest = Some(first_manifest_path.clone());
    assert_eq!(second_plan.imported_accounts.len(), 2);
    assert!(second_plan.imported_accounts.iter().all(|account| account.enabled));
    assert!(second_plan
      .provider_routes
      .iter()
      .all(|route| !route.transfer_source_auth));
    apply_reconcile_to_manifest_path(second_plan, second_manifest_path.clone()).unwrap();

    let synced_store = AuthStore::load(Some(&gateway_auth_path), None).unwrap();
    assert_eq!(synced_store.accounts.len(), 2);
    assert_eq!(
      synced_store
        .get("opencode-github-copilot")
        .unwrap()
        .refresh_token
        .as_ref()
        .unwrap()
        .expose(),
      "ghu-latest"
    );
    let second_manifest = manifest::read_manifest(&second_manifest_path).unwrap();
    assert_eq!(
      second_manifest.previous_manifest.as_deref(),
      Some(first_manifest_path.as_path())
    );

    let err = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(first_manifest_path.display().to_string()),
    })
    .unwrap_err();
    assert!(err.to_string().contains("newer active successor"));

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(second_manifest_path.display().to_string()),
    })
    .unwrap();

    assert_eq!(
      std::fs::read_to_string(&opencode_config_path).unwrap(),
      original_opencode_config
    );
    assert_eq!(
      std::fs::read_to_string(&gateway_config_path).unwrap(),
      original_gateway_config
    );
    assert!(!gateway_auth_path.exists());
    let restored_auth: Value = serde_json::from_str(&std::fs::read_to_string(&opencode_auth_path).unwrap()).unwrap();
    assert_eq!(restored_auth["openai"]["type"], "api");
    assert_eq!(restored_auth["openai"]["key"], "sk-latest");
    assert_eq!(restored_auth["github-copilot"]["type"], "oauth");
    assert_eq!(restored_auth["github-copilot"]["refresh"], "ghu-latest");
    assert_eq!(restored_auth["github-copilot"]["access"], "ghu-latest");
    assert_eq!(restored_auth["github-copilot"]["expires"], 0);
    assert_eq!(restored_auth["anthropic"]["key"], "anthropic-keep");
    assert!(manifest::read_manifest(&first_manifest_path).unwrap().unlinked);
    let second_manifest = manifest::read_manifest(&second_manifest_path).unwrap();
    assert!(second_manifest.unlinked);
    assert!(second_manifest.credentials_handoff_complete);
  }

  #[test]
  fn unlink_resumes_after_credentials_handoff_without_gateway_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    let agent_auth_path = dir.path().join("opencode-auth.json");
    let gateway_auth_path = dir.path().join("missing-gateway-auth.yaml");
    let auth = serde_json::json!({"openai": {"type": "api", "key": "already-restored"}});
    std::fs::write(&agent_auth_path, serde_json::to_vec_pretty(&auth).unwrap()).unwrap();
    let manifest = MigrationManifest {
      version: 2,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260604T153012Z".into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: Some(gateway_auth_path),
      gateway_auth_shard_path: None,
      agent_auth_path: Some(agent_auth_path.clone()),
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: true,
      imported_account_ids: vec!["opencode-openai".into()],
      files: Vec::new(),
    };
    manifest::write_manifest(&manifest_path, &manifest).unwrap();

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap();

    assert_eq!(
      serde_json::from_str::<Value>(&std::fs::read_to_string(agent_auth_path).unwrap()).unwrap(),
      auth
    );
    assert!(manifest::read_manifest(&manifest_path).unwrap().unlinked);
  }

  #[test]
  fn unlink_restores_file_from_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("config.toml");
    let backup = dir.path().join("config.toml.bak.20260604T153012Z");
    let manifest_path = dir.path().join("20260604T153012Z-codex-cli.json");
    std::fs::write(&original, "mutated").unwrap();
    std::fs::write(&backup, "original").unwrap();
    let manifest = MigrationManifest {
      version: 1,
      completed: true,
      agent: AgentId::CodexCli,
      timestamp: "20260604T153012Z".into(),
      profile: Some("codex".into()),
      target_base_url: "http://127.0.0.1:4141/codex/v1".into(),
      gateway_auth_path: None,
      gateway_auth_shard_path: None,
      agent_auth_path: None,
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: false,
      imported_account_ids: vec!["codex-cli-codex".into()],
      files: vec![FileBackup {
        original: original.clone(),
        backup: Some(backup),
        existed: true,
        created_by_migration: false,
      }],
    };
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let report = unlink(UnlinkRequest {
      agent: AgentId::CodexCli,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap();

    assert_eq!(std::fs::read_to_string(original).unwrap(), "original");
    assert_eq!(report.actions.len(), 1);
  }

  #[test]
  fn unlink_removes_files_created_by_migration() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("created.toml");
    let manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    std::fs::write(&original, "created").unwrap();
    let manifest = MigrationManifest {
      version: 1,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260604T153012Z".into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: None,
      gateway_auth_shard_path: None,
      agent_auth_path: None,
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: false,
      imported_account_ids: vec!["opencode-openai".into()],
      files: vec![FileBackup {
        original: original.clone(),
        backup: None,
        existed: false,
        created_by_migration: true,
      }],
    };
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let report = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap();

    assert!(!original.exists());
    assert!(matches!(report.actions.as_slice(), [FileAction::Removed(path)] if path == &original));
  }

  #[test]
  fn unlink_rejects_manifest_for_different_agent() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("20260604T153012Z-codex-cli.json");
    let manifest = MigrationManifest {
      version: 1,
      completed: true,
      agent: AgentId::CodexCli,
      timestamp: "20260604T153012Z".into(),
      profile: Some("codex".into()),
      target_base_url: "http://127.0.0.1:4141/codex/v1".into(),
      gateway_auth_path: None,
      gateway_auth_shard_path: None,
      agent_auth_path: None,
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: false,
      imported_account_ids: vec!["codex-cli-codex".into()],
      files: Vec::new(),
    };
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let err = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap_err();

    assert!(err.to_string().contains("not opencode"));
  }
}

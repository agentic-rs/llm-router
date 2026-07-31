use crate::adapter::{adapter_for, source_provider_id, ProviderRoute};
use crate::manifest::{self, FileBackup, MigrationManifest};
use crate::projection::{compile_opencode_publications, AgentConfigProjection, OpenCodePublicationPlan};
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
  /// Optional provider to pin for a main-account verbatim link. When absent,
  /// every enabled provider in the effective main account pool is linked.
  pub default_provider_id: Option<String>,
  /// Optional canonical gateway-provider filter for the main account pool.
  /// `Some([])` selects automatic discovery, while `None` preserves the
  /// existing binding's filter during `agent sync`.
  pub provider_filter: Option<Vec<String>>,
  pub gateway_config_path: Option<PathBuf>,
  pub agent_home: Option<PathBuf>,
}

#[derive(Debug)]
pub struct UnlinkRequest {
  pub agent: AgentId,
  pub backup_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProfileLayout {
  /// One generated profile exposes a merged provider catalogue.
  Single,
  /// One generated profile is pinned to one gateway provider.
  SinglePinned,
  /// One generated child profile is materialized per gateway provider.
  PerProvider,
}

impl AgentProfileLayout {
  pub fn for_binding(mode: RouteMode, account_source: AgentAccountSource, provider: Option<&str>) -> Self {
    if mode.is_verbatim() && (account_source == AgentAccountSource::Agent || provider.is_none()) {
      Self::PerProvider
    } else if mode.is_verbatim() {
      Self::SinglePinned
    } else {
      Self::Single
    }
  }
}

impl std::fmt::Display for AgentProfileLayout {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(match self {
      Self::Single => "single",
      Self::SinglePinned => "single_pinned",
      Self::PerProvider => "per_provider",
    })
  }
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
  /// Previously materialized base profile, discovered independently of the
  /// desired binding. This lets apply remove a renamed profile and its
  /// generated children.
  pub previous_materialized_profile: Option<String>,
  pub binding_mode: RouteMode,
  pub account_source: AgentAccountSource,
  /// Optional provider pin for a main-account raw-mode binding.
  pub provider: Option<String>,
  pub default_provider_id: Option<String>,
  /// Desired filter persisted in the agent binding. `None` means automatic
  /// discovery from the effective main account pool.
  pub provider_filter: Option<Vec<String>>,
  /// Canonical main-account providers materialized for this reconciliation.
  pub(crate) published_provider_ids: Vec<String>,
  /// Providers whose catalogue is dynamic or otherwise has no static models
  /// that OpenCode can put in its model picker.
  pub providers_without_models: Vec<String>,
  pub target_base_url: String,
  /// All imported credential routes, including disabled accounts. These keep
  /// credential transfer and unlink ownership complete without making a
  /// disabled account routable.
  pub(crate) credential_routes: Vec<ProviderRoute>,
  pub imported_accounts: Vec<Account>,
  /// Enabled provider routes materialized into profiles and publications.
  pub(crate) provider_routes: Vec<ProviderRoute>,
  pub edits: Vec<PlannedEdit>,
  pub(crate) previous_manifest: Option<PathBuf>,
  opencode_preflight: Option<crate::opencode_markdown::OpenCodePreflight>,
}

impl ReconcilePlan {
  /// Canonical gateway providers reachable through this materialized link.
  pub fn gateway_provider_ids(&self) -> Vec<String> {
    self
      .provider_routes
      .iter()
      .map(|route| route.gateway_provider_id.as_str())
      .collect::<BTreeSet<_>>()
      .into_iter()
      .map(str::to_string)
      .collect()
  }

  /// Provider IDs injected into the agent's own model picker/configuration.
  pub fn injected_provider_ids(&self) -> Vec<String> {
    if self.agent == AgentId::Opencode && self.binding_mode.is_verbatim() {
      return self
        .gateway_provider_ids()
        .into_iter()
        .map(|provider| format!("{}-{provider}", crate::projection::SHARED_PROVIDER_ID))
        .collect();
    }
    vec![crate::projection::SHARED_PROVIDER_ID.to_string()]
  }

  pub fn profile_layout(&self) -> AgentProfileLayout {
    AgentProfileLayout::for_binding(self.binding_mode, self.account_source, self.provider.as_deref())
  }
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

  fn contents(&self) -> Option<&[u8]> {
    match self {
      Self::Missing => None,
      Self::Contents(contents) => Some(contents),
    }
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

  fn file_preimage(&self, path: &Path) -> Option<&[u8]> {
    self.files.get(path).and_then(FileSnapshot::contents)
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
  let previous_manifest_path = manifest::latest_active_manifest(&request.agent)?;
  if let Some(path) = &previous_manifest_path {
    validate_manifest_chain_for_reconcile(path, &request.agent)?;
  }
  let previous_manifest = previous_manifest_path
    .as_deref()
    .map(manifest::read_manifest)
    .transpose()?;
  plan_reconcile_with_gateway_auth_path_and_manifest(
    request,
    gateway_auth_path,
    previous_manifest_path,
    previous_manifest.as_ref(),
  )
}

#[cfg(test)]
fn plan_reconcile_with_gateway_auth_path(
  request: ReconcileRequest,
  gateway_auth_path: PathBuf,
) -> Result<ReconcilePlan> {
  plan_reconcile_with_gateway_auth_path_and_manifest(request, gateway_auth_path, None, None)
}

fn plan_reconcile_with_gateway_auth_path_and_manifest(
  request: ReconcileRequest,
  gateway_auth_path: PathBuf,
  previous_manifest_path: Option<PathBuf>,
  previous_manifest: Option<&MigrationManifest>,
) -> Result<ReconcilePlan> {
  let adapter = adapter_for(&request.agent).ok_or_else(|| anyhow!("unsupported agent {}", request.agent))?;
  let gateway_auth_path = std::path::absolute(&gateway_auth_path)
    .with_context(|| format!("resolving gateway auth path {}", gateway_auth_path.display()))?;
  let configured_gateway_path = match request.gateway_config_path.as_deref() {
    Some(path) => path.to_path_buf(),
    None => tokn_config::paths::config_path()?,
  };
  let gateway_config_path = std::path::absolute(&configured_gateway_path)
    .with_context(|| format!("resolving gateway config path {}", configured_gateway_path.display()))?;
  let (cfg, gateway_config_snapshot) = load_stable_config(&gateway_config_path)?;
  let gateway_config_fragment_path =
    tokn_config::paths::agent_config_fragment_path(&gateway_config_path, request.agent.as_str());
  if let Some(previous_manifest) = previous_manifest {
    validate_previous_manifest_scope(previous_manifest, &gateway_config_fragment_path, &request.agent)?;
  }
  let existing_binding = cfg.agents.get(request.agent.as_str());
  let previous_materialized_profile =
    resolve_previous_materialized_profile(&cfg, existing_binding, &request.agent, previous_manifest)?;
  let account_source = request
    .account_source
    .or_else(|| existing_binding.map(|binding| binding.account_source))
    .unwrap_or(AgentAccountSource::Agent);
  let previous_account_source = previous_manifest
    .map(manifest_account_source)
    .or_else(|| previous_materialized_account_source(&cfg, previous_materialized_profile.as_deref(), existing_binding));
  reject_account_source_transition(account_source, previous_account_source, &request.agent)?;
  if account_source == AgentAccountSource::Main && !adapter.supports_main_accounts() {
    bail!(
      "{} cannot use --use-main-accounts yet because its local credential bootstrap would be changed; use the default link mode or choose opencode",
      request.agent
    );
  }
  let binding_mode = request
    .mode
    .or_else(|| existing_binding.and_then(|binding| binding.mode))
    .unwrap_or(RouteMode::Route);
  if binding_mode == RouteMode::Exact && !adapter.supports_exact_mode() {
    bail!(
      "{} cannot use --mode exact because it does not encode provider-qualified model ids; use route, fuzzy, switch, or passthrough",
      request.agent
    );
  }
  if cfg.api_key.enabled {
    bail!(
      "{} cannot use --mode {} while [api_key].enabled = true because generated agent credentials are not provisioned as gateway client keys yet; disable API-key enforcement before linking",
      request.agent,
      route_mode_as_str(binding_mode)
    );
  }
  let previous_mode = previous_materialized_mode(&cfg, previous_materialized_profile.as_deref());
  let previous_provider_ids =
    previous_materialized_provider_ids(&cfg, previous_materialized_profile.as_deref(), previous_mode);
  let provider_filter = resolve_main_provider_filter(
    request.provider_filter.as_deref(),
    existing_binding,
    account_source,
    binding_mode,
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
    main_accounts,
    transferred_source_providers,
  ) = if account_source == AgentAccountSource::Main {
    let (store, auth_sources_snapshot) = load_stable_auth_store(&gateway_auth_path, &gateway_config_path)?;
    (
      Some(auth_sources_snapshot),
      None,
      None,
      None,
      None,
      None,
      Vec::new(),
      crate::effective_main_accounts(&cfg, &store).cloned().collect(),
      BTreeSet::new(),
    )
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
      Vec::new(),
      transferred_source_providers,
    )
  };
  if account_source == AgentAccountSource::Agent && imported_accounts.is_empty() {
    if adapter.supports_main_accounts() {
      bail!(
        "{} has no importable credentials; authenticate it first or link with --use-main-accounts",
        request.agent
      );
    }
    bail!(
      "{} has no importable credentials; authenticate it before linking",
      request.agent
    );
  }
  let enabled_imported_accounts = imported_accounts
    .iter()
    .filter(|account| account.enabled)
    .cloned()
    .collect::<Vec<_>>();
  if account_source == AgentAccountSource::Agent && enabled_imported_accounts.is_empty() {
    let managed_path = gateway_auth_shard_path.as_deref().unwrap_or(&gateway_auth_path);
    bail!(
      "{} has imported credentials, but none are enabled in {}; enable at least one account before linking or syncing",
      request.agent,
      managed_path.display()
    );
  }
  let binding_profile = resolve_binding_profile(request.profile.as_deref(), existing_binding, &request.agent)?;
  let main_default_provider_id = resolve_main_default_provider(
    &cfg,
    previous_materialized_profile.as_deref(),
    existing_binding,
    binding_mode,
    account_source,
    request.default_provider_id.as_deref(),
    request.provider_filter.is_none(),
  )?;
  let published_provider_ids = materialize_main_provider_ids(
    account_source,
    binding_mode,
    provider_filter.as_deref().unwrap_or_default(),
    main_default_provider_id.as_deref(),
    &main_accounts,
  )?;
  let publication_accounts = if account_source == AgentAccountSource::Main {
    filter_publication_accounts(&main_accounts, &published_provider_ids)
  } else {
    enabled_imported_accounts.clone()
  };
  let target_base_url = gateway_profile_base_url(&cfg, binding_profile.as_deref());
  let main_per_provider_profiles = binding_mode.is_verbatim() && main_default_provider_id.is_none();
  let credential_routes = match account_source {
    AgentAccountSource::Agent => provider_routes(
      &cfg,
      binding_profile.as_deref(),
      &imported_accounts,
      &transferred_source_providers,
      adapter.default_provider_id(),
    )?,
    AgentAccountSource::Main => main_provider_routes(
      &cfg,
      binding_profile.as_deref(),
      &published_provider_ids,
      main_per_provider_profiles,
    ),
  };
  let provider_routes = match account_source {
    AgentAccountSource::Agent => provider_routes(
      &cfg,
      binding_profile.as_deref(),
      &enabled_imported_accounts,
      &transferred_source_providers,
      adapter.default_provider_id(),
    )?,
    AgentAccountSource::Main => main_provider_routes(
      &cfg,
      binding_profile.as_deref(),
      &published_provider_ids,
      main_per_provider_profiles,
    ),
  };
  let default_provider_id = materialized_default_provider(
    binding_mode,
    account_source,
    main_default_provider_id.as_deref(),
    &provider_routes,
    adapter.default_provider_id(),
  );
  validate_binding_profile(&cfg, &request.agent, binding_profile.as_deref(), existing_binding)?;
  if binding_mode.is_verbatim() {
    validate_provider_route_profiles(&cfg, &request.agent, binding_profile.as_deref(), &provider_routes)?;
  }
  validate_verbatim_provider_routes(&request.agent, adapter.as_ref(), binding_mode, &provider_routes)?;
  let publication_plan = if request.agent == AgentId::Opencode {
    compile_opencode_publications(
      binding_mode,
      previous_mode,
      previous_provider_ids.as_deref(),
      &target_base_url,
      &publication_accounts,
      &provider_routes,
      adapter.switch_endpoint(),
    )?
  } else {
    OpenCodePublicationPlan::default()
  };
  let projection = AgentConfigProjection {
    target_base_url: &target_base_url,
    mode: binding_mode,
    previous_mode,
    credential_routes: &credential_routes,
    publications: &publication_plan.publications,
    model_reference_rules: &publication_plan.model_reference_rules,
  };
  let opencode_preflight = (request.agent == AgentId::Opencode).then(|| {
    crate::opencode_markdown::OpenCodePreflight::new(&home, &adapter.config_path(&home), account_source, &projection)
  });
  if let Some(preflight) = &opencode_preflight {
    preflight.validate()?;
  }
  let edits = adapter.rewrite_config(&home, &projection)?;
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
      && credential_routes.iter().any(|route| route.transfer_source_auth))
    .then(|| adapter.auth_path(&home)),
    binding_profile,
    previous_materialized_profile,
    binding_mode,
    account_source,
    provider: main_default_provider_id,
    default_provider_id,
    provider_filter,
    published_provider_ids,
    providers_without_models: publication_plan.providers_without_models,
    target_base_url,
    credential_routes,
    imported_accounts,
    provider_routes,
    edits,
    previous_manifest: previous_manifest_path,
    opencode_preflight,
  })
}

/// Changing an existing binding's credential boundary can transfer or
/// re-enable credentials. Keep its account source immutable until unlink so
/// a relink cannot perform that migration implicitly.
fn reject_account_source_transition(
  account_source: AgentAccountSource,
  previous_account_source: Option<AgentAccountSource>,
  agent: &AgentId,
) -> Result<()> {
  let Some(previous_account_source) = previous_account_source else {
    return Ok(());
  };
  if account_source == previous_account_source {
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

pub fn apply_reconcile(plan: ReconcilePlan) -> Result<ApplyReport> {
  let _lock = manifest::try_lock_agent(&plan.agent)?;
  let active_manifest = manifest::latest_active_manifest(&plan.agent)?;
  if active_manifest != plan.previous_manifest {
    bail!(
      "{} active migration changed after reconciliation was planned; plan the link or sync again",
      plan.agent
    );
  }
  let manifest_path = manifest::manifest_path(&plan.timestamp, &plan.agent)?;
  apply_reconcile_to_manifest_path(plan, manifest_path)
}

pub fn unlink(request: UnlinkRequest) -> Result<UnlinkReport> {
  unlink_inner(request, None)
}

/// Unlink a legacy migration whose manifest stored paths relative to the
/// working directory used for that link invocation.
///
/// A single compatibility root can safely recover only one relative-path
/// manifest in a chain. Chains containing multiple such manifests are refused
/// because each invocation may have used a different working directory.
pub fn unlink_with_legacy_root(request: UnlinkRequest, legacy_root: &Path) -> Result<UnlinkReport> {
  let legacy_root = std::path::absolute(legacy_root)
    .with_context(|| format!("resolving legacy manifest compatibility root {}", legacy_root.display()))?;
  unlink_inner(request, Some(&legacy_root))
}

fn unlink_inner(request: UnlinkRequest, legacy_root: Option<&Path>) -> Result<UnlinkReport> {
  let manifest_path = manifest::resolve_manifest(&request.agent, request.backup_id.as_deref())?;
  let lock_dir = manifest_path
    .parent()
    .ok_or_else(|| anyhow!("manifest has no parent directory: {}", manifest_path.display()))?;
  let _lock = manifest::try_lock_agent_in(lock_dir, &request.agent)?;
  if let Some(successor) = active_manifest_successor(&manifest_path, &request.agent, legacy_root)? {
    bail!(
      "manifest {} has newer active successor {}; unlink the latest migration instead",
      manifest_path.display(),
      successor.display()
    );
  }
  if manifest::read_manifest(&manifest_path)?.unlinked {
    bail!("manifest {} has already been unlinked", manifest_path.display());
  }
  let mut chain = manifest_chain(&manifest_path, &request.agent, legacy_root)?;
  let latest = chain.first().expect("manifest chain contains selected manifest");
  let timestamp = latest.1.timestamp.clone();

  preflight_manifest_file_restoration(&chain)?;
  restore_pending_credentials(&request.agent, &mut chain)?;
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
  let archived_manifest_path = chain
    .iter()
    .map(|(path, _)| manifest::archive_manifest(path))
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .next()
    .expect("manifest chain contains selected manifest");

  Ok(UnlinkReport {
    manifest_path: archived_manifest_path,
    timestamp,
    actions,
  })
}

fn active_manifest_successor(path: &Path, agent: &AgentId, legacy_root: Option<&Path>) -> Result<Option<PathBuf>> {
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
        .map(|name| !name.starts_with('.') && name.ends_with(&suffix))
        .unwrap_or(false)
    {
      continue;
    }
    let manifest = manifest::read_manifest(&candidate)?;
    if manifest.agent != *agent || manifest.unlinked {
      continue;
    }
    let chain = manifest_chain(&candidate, agent, legacy_root)?;
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

fn validate_manifest_chain_for_reconcile(path: &Path, agent: &AgentId) -> Result<()> {
  let mut seen = BTreeSet::new();
  let mut current = Some(path.to_path_buf());
  while let Some(path) = current {
    if !path.is_absolute() {
      bail!(
        "migration manifest path '{}' is relative and cannot be inspected safely; unlink the legacy migration first",
        path.display()
      );
    }
    if !seen.insert(path.clone()) {
      bail!("migration manifest chain contains a cycle at {}", path.display());
    }
    let manifest = manifest::read_manifest(&path)?;
    if manifest.agent != *agent {
      bail!("manifest {} is for {}, not {}", path.display(), manifest.agent, agent);
    }
    if !manifest.completed {
      bail!(
        "{} has an incomplete migration at {}; run `agent unlink {} --backup-id {}` before linking or syncing again",
        agent,
        path.display(),
        agent,
        path.display()
      );
    }
    if let Some(relative) = manifest::first_relative_path(&manifest) {
      bail!(
        "{} has a legacy migration at {} with relative restore path '{}'; unlink it with that invocation's original working directory supplied as --legacy-root before linking or syncing again",
        agent,
        path.display(),
        relative.display()
      );
    }
    current = manifest.previous_manifest;
  }
  Ok(())
}

fn manifest_chain(
  path: &Path,
  agent: &AgentId,
  legacy_root: Option<&Path>,
) -> Result<Vec<(PathBuf, MigrationManifest)>> {
  let mut chain = Vec::new();
  let mut seen = BTreeSet::new();
  let mut relative_manifest_path: Option<PathBuf> = None;
  let mut current = Some(path.to_path_buf());
  while let Some(path) = current {
    if !path.is_absolute() {
      bail!(
        "migration manifest path '{}' is relative and cannot be restored safely; use an absolute manifest path",
        path.display()
      );
    }
    if !seen.insert(path.clone()) {
      bail!("migration manifest chain contains a cycle at {}", path.display());
    }
    let raw_manifest = manifest::read_manifest(&path)?;
    if manifest::first_relative_path(&raw_manifest).is_some() {
      if let Some(first) = &relative_manifest_path {
        bail!(
          "legacy migration chain contains relative restore paths in both {} and {}; one --legacy-root cannot safely resolve manifests created by different invocations",
          first.display(),
          path.display()
        );
      }
      relative_manifest_path = Some(path.clone());
    }
    let manifest = manifest::prepare_manifest_for_restore(&path, raw_manifest, legacy_root)?;
    validate_manifest_restore_paths(&path, &manifest)?;
    if manifest.agent != *agent {
      bail!("manifest {} is for {}, not {}", path.display(), manifest.agent, agent);
    }
    current = manifest.previous_manifest.clone();
    chain.push((path, manifest));
  }
  Ok(chain)
}

fn validate_manifest_restore_paths(path: &Path, manifest: &MigrationManifest) -> Result<()> {
  let mut paths = manifest
    .gateway_auth_path
    .iter()
    .chain(manifest.gateway_auth_shard_path.iter())
    .chain(manifest.agent_auth_path.iter())
    .chain(manifest.previous_manifest.iter())
    .chain(manifest.files.iter().map(|file| &file.original))
    .chain(manifest.files.iter().filter_map(|file| file.backup.as_ref()));
  if let Some(relative) = paths.find(|candidate| !candidate.is_absolute()) {
    bail!(
      "migration manifest {} contains relative restore path '{}'; refusing to interpret it from the current working directory",
      path.display(),
      relative.display()
    );
  }
  Ok(())
}

#[derive(Debug)]
enum SimulatedFileState {
  Missing,
  Contents(Vec<u8>),
}

impl SimulatedFileState {
  fn capture(path: &Path) -> Result<Self> {
    match std::fs::read(path) {
      Ok(bytes) => Ok(Self::Contents(bytes)),
      Err(error)
        if matches!(
          error.kind(),
          std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        ) =>
      {
        Ok(Self::Missing)
      }
      Err(error) => Err(error).with_context(|| format!("reading managed migration file {}", path.display())),
    }
  }
}

/// Validate every destructive file transition before credential handoff or
/// file rollback starts. Each predecessor is checked against a simulated
/// restore of its successor, so edits made between syncs cannot be hidden by
/// checking only the latest on-disk image.
///
/// The agent auth shard is intentionally exempt from the comparison. Runtime
/// credential refresh is expected to mutate it, and unlink preserves that
/// state through `restore_pending_credentials` before removing the shard.
fn preflight_manifest_file_restoration(chain: &[(PathBuf, MigrationManifest)]) -> Result<()> {
  let mut simulated = BTreeMap::<PathBuf, SimulatedFileState>::new();

  for (manifest_path, current) in chain {
    for file in &current.files {
      if current.gateway_auth_shard_path.as_deref() == Some(file.original.as_path()) {
        continue;
      }
      if !simulated.contains_key(&file.original) {
        simulated.insert(file.original.clone(), SimulatedFileState::capture(&file.original)?);
      }
      let state = simulated
        .get(&file.original)
        .expect("simulated state was inserted above");
      let matches = match file.applied_sha256.as_deref() {
        Some(expected) => match state {
          SimulatedFileState::Missing => false,
          SimulatedFileState::Contents(bytes) => manifest::sha256(bytes) == expected,
        },
        None if current.version < manifest::CURRENT_VERSION => {
          // Legacy manifests predate post-image tracking and retain their
          // historical unconditional restore behavior.
          true
        }
        None => uncheckpointed_file_still_matches_preimage(file, state)?,
      };
      if !matches {
        bail!(
          "{} changed after the link or sync recorded by {}; refusing to unlink because rollback would overwrite those changes",
          file.original.display(),
          manifest_path.display()
        );
      }
    }

    for file in current.files.iter().rev() {
      let restored = if file.created_by_migration {
        SimulatedFileState::Missing
      } else if let Some(backup) = &file.backup {
        let bytes = std::fs::read(backup).with_context(|| format!("reading migration backup {}", backup.display()))?;
        SimulatedFileState::Contents(bytes)
      } else {
        continue;
      };
      simulated.insert(file.original.clone(), restored);
    }
  }

  Ok(())
}

fn uncheckpointed_file_still_matches_preimage(file: &FileBackup, state: &SimulatedFileState) -> Result<bool> {
  match state {
    SimulatedFileState::Missing => Ok(file.created_by_migration || !file.existed),
    SimulatedFileState::Contents(current) => {
      let Some(backup) = &file.backup else {
        return Ok(false);
      };
      let original = std::fs::read(backup).with_context(|| format!("reading migration backup {}", backup.display()))?;
      Ok(current == &original)
    }
  }
}

fn restore_pending_credentials(agent: &AgentId, chain: &mut [(PathBuf, MigrationManifest)]) -> Result<()> {
  if chain.iter().all(|(_, manifest)| manifest.credentials_handoff_complete) {
    return Ok(());
  }

  let has_pending_auth_path = chain
    .iter()
    .any(|(_, manifest)| !manifest.credentials_handoff_complete && manifest.agent_auth_path.is_some());
  let latest_requires_transferred_credentials = chain
    .first()
    .is_some_and(|(_, manifest)| manifest_requires_transferred_credentials(manifest));
  let accounts = if has_pending_auth_path {
    let latest = &chain.first().expect("manifest chain contains selected manifest").1;
    load_transferred_credentials(latest)?
  } else {
    Vec::new()
  };
  let accounts_by_source = accounts
    .iter()
    .map(|account| (transfer_source_provider(account).to_string(), account))
    .collect::<BTreeMap<_, _>>();
  let accounts_by_id = accounts
    .iter()
    .map(|account| (account.id.as_str(), account))
    .collect::<BTreeMap<_, _>>();
  let mut target_sources = BTreeMap::<PathBuf, BTreeSet<String>>::new();

  for (manifest_path, current) in chain
    .iter()
    .filter(|(_, manifest)| !manifest.credentials_handoff_complete)
  {
    let Some(agent_auth_path) = current.agent_auth_path.as_ref() else {
      continue;
    };
    for route in current
      .provider_routes
      .iter()
      .filter(|route| route.transfer_source_auth)
    {
      target_sources
        .entry(agent_auth_path.clone())
        .or_default()
        .insert(route.source_provider_id.clone());
    }
    if current.provider_routes.is_empty() {
      let sources = target_sources.entry(agent_auth_path.clone()).or_default();
      for account_id in &current.imported_account_ids {
        if let Some(account) = accounts_by_id.get(account_id.as_str()) {
          sources.insert(transfer_source_provider(account).to_string());
        } else if current.completed {
          bail!(
            "legacy transferred account '{account_id}' recorded by {} is missing from the latest gateway credential set",
            manifest_path.display()
          );
        }
      }
    }
  }
  let adapter = adapter_for(agent).ok_or_else(|| anyhow!("unsupported agent {agent}"))?;
  for (agent_auth_path, sources) in target_sources {
    let target_accounts = sources
      .iter()
      .filter_map(|source| {
        accounts_by_source.get(source).copied().map(Ok).or_else(|| {
          latest_requires_transferred_credentials.then(|| {
            Err(anyhow!(
              "transferred provider '{source}' is missing from the latest gateway credential set"
            ))
          })
        })
      })
      .collect::<Result<Vec<_>>>()?
      .into_iter()
      .cloned()
      .collect::<Vec<_>>();
    adapter.restore_transferred_credentials(&agent_auth_path, &target_accounts)?;
  }

  // Checkpoint every pending handoff before file rollback removes the auth
  // shard. If writing one manifest fails, retrying is safe because credential
  // restoration does not replace keys that are already present.
  for (path, current) in chain
    .iter_mut()
    .filter(|(_, manifest)| !manifest.credentials_handoff_complete)
  {
    current.credentials_handoff_complete = true;
    manifest::write_manifest(path, current)?;
  }
  Ok(())
}

fn load_transferred_credentials(manifest: &MigrationManifest) -> Result<Vec<Account>> {
  if manifest.imported_account_ids.is_empty() {
    return Ok(Vec::new());
  }
  let Some(gateway_auth_path) = &manifest.gateway_auth_path else {
    bail!("manifest is missing the gateway auth path required to restore transferred credentials");
  };
  let store = AuthStore::load(Some(gateway_auth_path), None)?;
  if let Some(shard_path) = manifest.gateway_auth_shard_path.as_deref() {
    if manifest_has_checkpointed_transfer_shard(manifest) {
      validate_restorable_transferred_route_accounts(manifest, &store, shard_path)?;
    }
  }
  let required = manifest_requires_transferred_credentials(manifest);
  let mut accounts = Vec::new();
  for id in &manifest.imported_account_ids {
    let Some(account) = store.get(id).cloned() else {
      // Agent auth is stripped only after the shard save completes. A missing
      // account in an incomplete migration therefore means that account's
      // source auth is still authoritative. Keep loading older chain accounts
      // so their original stripped paths can still be restored.
      if !required {
        continue;
      }
      bail!(
        "transferred account '{id}' is missing from {}",
        gateway_auth_path.display()
      );
    };
    if let Some(shard_path) = manifest.gateway_auth_shard_path.as_deref() {
      if store.account_source_path(id).as_deref() != Some(shard_path) {
        if !required {
          continue;
        }
        bail!(
          "transferred account '{id}' is no longer owned by {}",
          shard_path.display()
        );
      }
    }
    accounts.push(account);
  }
  Ok(accounts)
}

/// Once the auth shard itself is checkpointed, a later edit may already have
/// stripped the source credential even if final reconciliation failed. At that
/// point unlink must fail closed unless the transferred account is still
/// available for restoration.
fn manifest_requires_transferred_credentials(manifest: &MigrationManifest) -> bool {
  manifest.completed || manifest_has_checkpointed_transfer_shard(manifest)
}

fn manifest_has_checkpointed_transfer_shard(manifest: &MigrationManifest) -> bool {
  manifest.gateway_auth_shard_path.as_ref().is_some_and(|shard_path| {
    manifest
      .files
      .iter()
      .any(|file| file.original == *shard_path && file.applied_sha256.is_some())
      && manifest.provider_routes.iter().any(|route| route.transfer_source_auth)
  })
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
  if let Some(preflight) = &plan.opencode_preflight {
    preflight.validate()?;
  }

  let mut files = Vec::new();
  let manages_gateway_auth = plan.gateway_auth_shard_path.is_some();
  let imported_account_ids = plan
    .imported_accounts
    .iter()
    .map(|account| account.id.clone())
    .collect::<BTreeSet<_>>();

  if let Some(shard_path) = &plan.gateway_auth_shard_path {
    let shard_existed = manifest::backup_sensitive_path_for(shard_path, &plan.timestamp, &mut files)?;
    manifest::mark_created(&mut files, shard_path, shard_existed);
  }
  let gateway_fragment_existed =
    manifest::backup_path_for(&plan.gateway_config_fragment_path, &plan.timestamp, &mut files)?;
  manifest::mark_created(&mut files, &plan.gateway_config_fragment_path, gateway_fragment_existed);

  for edit in &plan.edits {
    if !edit.backup {
      continue;
    }
    let existed = manifest::backup_path_for(&edit.path, &plan.timestamp, &mut files)?;
    manifest::mark_created(&mut files, &edit.path, existed);
  }

  let mut manifest = MigrationManifest {
    version: manifest::CURRENT_VERSION,
    completed: true,
    agent: plan.agent.clone(),
    timestamp: plan.timestamp.clone(),
    profile: plan.binding_profile.clone(),
    target_base_url: plan.target_base_url.clone(),
    gateway_auth_path: manages_gateway_auth.then_some(plan.gateway_auth_path.clone()),
    gateway_auth_shard_path: plan.gateway_auth_shard_path.clone(),
    agent_auth_path: plan.agent_auth_path.clone(),
    provider_routes: plan.credential_routes.clone(),
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
    let source = AuthSource::Shard(plan.agent.as_str().to_string());
    let digest = store.source_sha256(&source).ok_or_else(|| {
      anyhow!(
        "managed auth shard {} was not written; refusing to complete the link or sync",
        shard_path.display()
      )
    })?;
    checkpoint_manifest_file(&manifest_path, &mut manifest, shard_path, digest, false)?;
  }

  plan.gateway_config_snapshot.validate()?;
  let fallback_provider_id = adapter_for(&plan.agent)
    .expect("supported agent should still have adapter")
    .default_provider_id();
  let enabled_imported_accounts = plan
    .imported_accounts
    .iter()
    .filter(|account| account.enabled)
    .cloned()
    .collect::<Vec<_>>();
  let write = AgentProfileWrite {
    agent: &plan.agent,
    profile: plan.binding_profile.as_deref(),
    previous_profile: plan.previous_materialized_profile.as_deref(),
    mode: plan.binding_mode,
    account_source: plan.account_source,
    provider: plan.provider.as_deref(),
    provider_filter: plan.provider_filter.as_deref(),
    materialized_provider_ids: &plan.published_provider_ids,
    accounts: &enabled_imported_accounts,
    provider_routes: &plan.provider_routes,
    default_provider_id: plan.default_provider_id.as_deref(),
    fallback_provider_id,
  };
  let config_contents = upsert_agent_and_profiles_with_source_if_unchanged(
    &plan.gateway_config_fragment_path,
    plan
      .gateway_config_snapshot
      .file_preimage(&plan.gateway_config_fragment_path),
    &write,
  )?;
  checkpoint_manifest_file(
    &manifest_path,
    &mut manifest,
    &plan.gateway_config_fragment_path,
    manifest::sha256(config_contents.as_bytes()),
    true,
  )?;

  for edit in &plan.edits {
    let contents = write_edit(edit)?;
    if edit.backup {
      checkpoint_manifest_file(
        &manifest_path,
        &mut manifest,
        &edit.path,
        manifest::sha256(&contents),
        true,
      )?;
    }
  }

  validate_reconcile_checkpoints(&manifest)?;
  let manifest = manifest.complete();
  manifest::write_manifest(&manifest_path, &manifest)?;
  Ok(ApplyReport {
    manifest_path,
    files: manifest.files,
  })
}

fn checkpoint_manifest_file(
  path: &Path,
  migration: &mut MigrationManifest,
  written_path: &Path,
  applied_sha256: String,
  validate_current_bytes: bool,
) -> Result<()> {
  if !manifest::set_applied_digest_for_path(&mut migration.files, written_path, applied_sha256) {
    bail!(
      "managed migration file {} was written without a tracked backup entry",
      written_path.display()
    );
  }
  manifest::write_manifest(path, &migration.clone().in_progress())?;
  if validate_current_bytes {
    let checkpoint = migration
      .files
      .iter()
      .find(|file| file.original == written_path)
      .expect("checkpointed migration file remains tracked");
    manifest::validate_applied_digests(std::iter::once(checkpoint))?;
  }
  Ok(())
}

fn validate_reconcile_checkpoints(migration: &MigrationManifest) -> Result<()> {
  let mutable_auth_shard = migration.gateway_auth_shard_path.as_deref();
  if mutable_auth_shard.is_none() && migration.provider_routes.iter().any(|route| route.transfer_source_auth) {
    bail!(
      "{} has transferred credential routes without a managed auth shard; refusing to complete the link or sync",
      migration.agent
    );
  }
  if let Some(path) = mutable_auth_shard {
    let checkpoint = migration
      .files
      .iter()
      .find(|file| file.original == path)
      .and_then(|file| file.applied_sha256.as_deref());
    if checkpoint.is_none() {
      bail!(
        "managed auth shard {} was not checkpointed; refusing to complete the link or sync",
        path.display()
      );
    }
    let root = migration.gateway_auth_path.as_deref().ok_or_else(|| {
      anyhow!(
        "managed auth shard {} has no root auth path in its migration manifest",
        path.display()
      )
    })?;
    let store =
      AuthStore::load(Some(root), None).with_context(|| format!("validating managed auth shard {}", path.display()))?;
    for account_id in &migration.imported_account_ids {
      let account = store.get(account_id).ok_or_else(|| {
        anyhow!(
          "managed auth shard {} no longer contains transferred account '{}'; refusing to complete the link or sync",
          path.display(),
          account_id
        )
      })?;
      if store
        .account_source_path(account_id)
        .is_none_or(|source_path| !same_path(&source_path, path))
        || !is_source_managed_account(account, &migration.agent)
      {
        bail!(
          "transferred account '{}' is no longer owned by {} in {}; refusing to complete the link or sync",
          account_id,
          migration.agent,
          path.display()
        );
      }
    }
    validate_transferred_route_accounts(migration, &store, path)?;
  }
  manifest::validate_applied_digests(
    migration
      .files
      .iter()
      .filter(|file| Some(file.original.as_path()) != mutable_auth_shard),
  )
}

fn validate_transferred_route_accounts(
  migration: &MigrationManifest,
  store: &AuthStore,
  shard_path: &Path,
) -> Result<()> {
  validate_transferred_route_accounts_inner(migration, store, shard_path, true)
}

fn validate_restorable_transferred_route_accounts(
  migration: &MigrationManifest,
  store: &AuthStore,
  shard_path: &Path,
) -> Result<()> {
  validate_transferred_route_accounts_inner(migration, store, shard_path, false)
}

fn validate_transferred_route_accounts_inner(
  migration: &MigrationManifest,
  store: &AuthStore,
  shard_path: &Path,
  require_enabled: bool,
) -> Result<()> {
  let transferred_routes = migration
    .provider_routes
    .iter()
    .filter(|route| route.transfer_source_auth)
    .collect::<Vec<_>>();
  if transferred_routes.is_empty() {
    return Ok(());
  }

  let adapter = adapter_for(&migration.agent).ok_or_else(|| {
    anyhow!(
      "unsupported agent {} has transferred credential routes",
      migration.agent
    )
  })?;
  if !adapter.transfers_credentials() {
    bail!(
      "{} does not support reversible credential transfer; refusing to finalize its managed auth shard",
      migration.agent
    );
  }

  let imported_account_ids = migration
    .imported_account_ids
    .iter()
    .map(String::as_str)
    .collect::<BTreeSet<_>>();
  for route in transferred_routes {
    if route.account_id.is_empty() || !imported_account_ids.contains(route.account_id.as_str()) {
      bail!(
        "transferred route for source provider '{}' references account '{}' that is not recorded as imported; refusing to complete the link or sync",
        route.source_provider_id,
        route.account_id
      );
    }
    let account = store.get(&route.account_id).ok_or_else(|| {
      anyhow!(
        "managed auth shard {} no longer contains transferred account '{}'; refusing to complete the link or sync",
        shard_path.display(),
        route.account_id
      )
    })?;
    if store
      .account_source_path(&account.id)
      .is_none_or(|source_path| !same_path(&source_path, shard_path))
      || !is_gateway_owned_account(account, &migration.agent)
    {
      bail!(
        "transferred account '{}' is no longer strictly gateway-owned by {} in {}; refusing to complete the link or sync",
        account.id,
        migration.agent,
        shard_path.display()
      );
    }
    if require_enabled && !account.enabled {
      bail!(
        "transferred account '{}' is disabled in {}; refusing to complete the link or sync",
        account.id,
        shard_path.display()
      );
    }
    if account.provider != route.gateway_provider_id {
      bail!(
        "transferred account '{}' uses gateway provider '{}', but its route requires '{}'; refusing to complete the link or sync",
        account.id,
        account.provider,
        route.gateway_provider_id
      );
    }
    let account_source_provider = source_provider_id(account).ok_or_else(|| {
      anyhow!(
        "transferred account '{}' is missing its source provider metadata; refusing to complete the link or sync",
        account.id
      )
    })?;
    if account_source_provider != route.source_provider_id {
      bail!(
        "transferred account '{}' came from source provider '{}', but its route requires '{}'; refusing to complete the link or sync",
        account.id,
        account_source_provider,
        route.source_provider_id
      );
    }
    validate_exportable_transferred_credentials(&migration.agent, account_source_provider, account)?;
  }
  Ok(())
}

fn validate_exportable_transferred_credentials(
  agent: &AgentId,
  source_provider_id: &str,
  account: &Account,
) -> Result<()> {
  if *agent != AgentId::Opencode {
    bail!(
      "{} does not define a reversible credential export contract for transferred account '{}'",
      agent,
      account.id
    );
  }

  if let Some(api_key) = &account.api_key {
    if api_key.expose().trim().is_empty() {
      bail!(
        "transferred account '{}' has an empty API key and cannot be restored to OpenCode",
        account.id
      );
    }
    return Ok(());
  }

  account
    .refresh_token
    .as_ref()
    .filter(|token| !token.expose().trim().is_empty())
    .ok_or_else(|| {
      anyhow!(
        "transferred account '{}' has no exportable API key or OAuth refresh token for OpenCode",
        account.id
      )
    })?;
  if source_provider_id == tokn_core::provider::ID_GITHUB_COPILOT {
    return Ok(());
  }

  account
    .access_token
    .as_ref()
    .filter(|token| !token.expose().trim().is_empty())
    .ok_or_else(|| {
      anyhow!(
        "transferred account '{}' has no exportable OAuth access token for OpenCode",
        account.id
      )
    })?;
  let expires_at = account.access_token_expires_at.ok_or_else(|| {
    anyhow!(
      "transferred account '{}' has no OAuth access-token expiry for OpenCode",
      account.id
    )
  })?;
  if expires_at < 0 {
    bail!(
      "transferred account '{}' has a negative OAuth access-token expiry and cannot be restored to OpenCode",
      account.id
    );
  }
  Ok(())
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
  let previous_chain = manifest_chain(previous_manifest_path, &plan.agent, None)?;
  let Some((pending_path, _)) = previous_chain
    .iter()
    .find(|(_, previous)| previous.agent_auth_path.is_some() && !previous.credentials_handoff_complete)
  else {
    return Ok(());
  };
  bail!(
    "{} has a pending credential handoff in {}, but its managed auth shard is unavailable; restore the shard or source credentials before syncing",
    plan.agent,
    pending_path.display()
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
) -> Result<Vec<ProviderRoute>> {
  if accounts.is_empty() {
    return Ok(vec![ProviderRoute {
      source_provider_id: default_provider_id.to_string(),
      gateway_provider_id: default_provider_id.to_string(),
      account_id: String::new(),
      profile: binding_profile.unwrap_or_default().to_string(),
      base_url: gateway_profile_base_url(cfg, binding_profile),
      transfer_source_auth: false,
    }]);
  }

  let Some(binding_profile) = binding_profile else {
    return Ok(Vec::new());
  };
  let mut selected_accounts = BTreeMap::<&str, &Account>::new();
  for account in accounts {
    let Some(source_provider_id) = source_provider_id(account) else {
      continue;
    };
    if let Some(existing) = selected_accounts.get(source_provider_id).copied() {
      if existing.enabled && account.enabled && existing.id != account.id {
        bail!(
          "OpenCode source provider '{source_provider_id}' maps to multiple enabled gateway accounts ('{}' for '{}' and '{}' for '{}'); disable all but one before linking or syncing",
          existing.id,
          existing.provider,
          account.id,
          account.provider
        );
      }
      if existing.enabled || !account.enabled {
        continue;
      }
    }
    selected_accounts.insert(source_provider_id, account);
  }

  let routes = selected_accounts
    .into_iter()
    .map(|(source_provider_id, account)| {
      let profile = format!("{binding_profile}-{}", account.provider);
      ProviderRoute {
        source_provider_id: source_provider_id.to_string(),
        gateway_provider_id: account.provider.clone(),
        account_id: account.id.clone(),
        base_url: gateway_profile_base_url(cfg, Some(&profile)),
        profile,
        transfer_source_auth: transferred_source_providers.contains(source_provider_id),
      }
    })
    .collect();
  Ok(routes)
}

pub(crate) fn main_provider_routes(
  cfg: &Config,
  binding_profile: Option<&str>,
  provider_ids: &[String],
  per_provider_profiles: bool,
) -> Vec<ProviderRoute> {
  provider_ids
    .iter()
    .map(|gateway_provider_id| {
      let profile = if per_provider_profiles {
        binding_profile
          .map(|profile| format!("{profile}-{gateway_provider_id}"))
          .unwrap_or_default()
      } else {
        binding_profile.unwrap_or_default().to_string()
      };
      ProviderRoute {
        source_provider_id: crate::adapters::opencode::source_namespace_for_gateway(gateway_provider_id).to_string(),
        gateway_provider_id: gateway_provider_id.to_string(),
        account_id: String::new(),
        base_url: gateway_profile_base_url(cfg, (!profile.is_empty()).then_some(profile.as_str())),
        profile,
        transfer_source_auth: false,
      }
    })
    .collect()
}

fn resolve_main_provider_filter(
  explicit_provider_ids: Option<&[String]>,
  existing_binding: Option<&tokn_config::AgentConfig>,
  account_source: AgentAccountSource,
  mode: RouteMode,
) -> Result<Option<Vec<String>>> {
  if existing_binding.is_some_and(|binding| binding.source_providers.is_some()) {
    bail!(
      "legacy agents.*.source_providers cannot be relinked safely because the previous link may have replaced a direct OpenCode provider; run 'agent unlink opencode' to restore it, then link again"
    );
  }
  if account_source != AgentAccountSource::Main {
    return Ok(None);
  }
  if mode.is_verbatim() {
    if explicit_provider_ids.is_some_and(|provider_ids| !provider_ids.is_empty()) {
      bail!("--provider-filter is not valid with --mode passthrough or switch; use --provider <id>");
    }
    return Ok(None);
  }
  let configured = explicit_provider_ids.or_else(|| {
    existing_binding
      .and_then(|binding| binding.provider_filter.as_deref())
      .filter(|provider_ids| !provider_ids.is_empty())
  });
  let mut provider_filter = BTreeSet::new();
  for provider_id in configured.unwrap_or(&[]) {
    let provider_id = provider_id.trim();
    if provider_id.is_empty() {
      bail!("--provider-filter must not be empty");
    }
    if !provider_filter.insert(provider_id.to_string()) {
      bail!("--provider-filter '{provider_id}' was specified more than once");
    }
  }
  Ok((!provider_filter.is_empty()).then(|| provider_filter.into_iter().collect()))
}

fn materialize_main_provider_ids(
  account_source: AgentAccountSource,
  mode: RouteMode,
  requested_provider_ids: &[String],
  default_provider_id: Option<&str>,
  accounts: &[Account],
) -> Result<Vec<String>> {
  if account_source != AgentAccountSource::Main {
    return Ok(Vec::new());
  }
  let available = accounts
    .iter()
    .map(|account| account.provider.as_str())
    .collect::<BTreeSet<_>>();
  if available.is_empty() {
    bail!("OpenCode main-account link found no enabled accounts in the effective gateway pool");
  }
  if mode.is_verbatim() {
    if let Some(default_provider_id) = default_provider_id {
      if !available.contains(default_provider_id) {
        bail!(
          "OpenCode main-account link selected provider '{default_provider_id}', but the effective gateway pool has no enabled account for it"
        );
      }
      return Ok(vec![default_provider_id.to_string()]);
    }
    return Ok(available.into_iter().map(str::to_string).collect());
  }
  if requested_provider_ids.is_empty() {
    return Ok(available.into_iter().map(str::to_string).collect());
  }
  for provider_id in requested_provider_ids {
    if !available.contains(provider_id.as_str()) {
      bail!("--provider-filter '{provider_id}' has no enabled account in the effective gateway pool");
    }
  }
  Ok(requested_provider_ids.to_vec())
}

fn filter_publication_accounts(accounts: &[Account], provider_ids: &[String]) -> Vec<Account> {
  let provider_ids = provider_ids.iter().map(String::as_str).collect::<BTreeSet<_>>();
  accounts
    .iter()
    .filter(|account| provider_ids.contains(account.provider.as_str()))
    .cloned()
    .collect()
}

fn previous_materialized_provider_ids(
  cfg: &Config,
  previous_profile: Option<&str>,
  previous_mode: Option<RouteMode>,
) -> Option<Vec<String>> {
  let profile = previous_profile.and_then(|profile| cfg.profiles.get(profile))?;
  if let Some(providers) = profile.providers.as_ref().filter(|providers| !providers.is_empty()) {
    return Some(providers.clone());
  }
  if previous_mode.is_some_and(RouteMode::is_verbatim) {
    return profile
      .default_provider_id
      .as_ref()
      .map(|provider| vec![provider.clone()]);
  }
  None
}

fn validate_previous_manifest_scope(
  manifest: &MigrationManifest,
  gateway_config_fragment_path: &Path,
  agent: &AgentId,
) -> Result<()> {
  if manifest
    .files
    .iter()
    .any(|file| file.original == gateway_config_fragment_path)
  {
    return Ok(());
  }
  bail!(
    "{} already has an active link for a different gateway configuration; unlink it before linking this configuration",
    agent
  )
}

fn previous_materialized_mode(cfg: &Config, previous_profile: Option<&str>) -> Option<RouteMode> {
  let previous_profile = previous_profile?;
  let default_mode = if cfg.defaults.mode == RouteMode::Route && cfg.server.route_mode != RouteMode::Route {
    cfg.server.route_mode
  } else {
    cfg.defaults.mode
  };
  Some(
    cfg
      .profiles
      .get(previous_profile)
      .and_then(|profile| profile.mode)
      .unwrap_or(default_mode),
  )
}

fn resolve_previous_materialized_profile(
  cfg: &Config,
  existing_binding: Option<&tokn_config::AgentConfig>,
  agent: &AgentId,
  previous_manifest: Option<&MigrationManifest>,
) -> Result<Option<String>> {
  if let Some(profile_name) = previous_manifest.and_then(|manifest| manifest.profile.as_deref()) {
    let profile = cfg.profiles.get(profile_name).ok_or_else(|| {
      anyhow!(
        "{} active migration names generated profile '{}', but that profile is missing; restore it or unlink before syncing",
        agent,
        profile_name
      )
    })?;
    if profile.agent_id.as_ref() != Some(agent) {
      bail!(
        "{} active migration names profile '{}', but that profile is no longer owned by the agent",
        agent,
        profile_name
      );
    }
    return Ok(Some(profile_name.to_string()));
  }
  let Some(binding) = existing_binding else {
    return Ok(None);
  };
  let owned_profiles = cfg
    .profiles
    .iter()
    .filter(|(_, profile)| profile.agent_id.as_ref() == Some(agent))
    .map(|(name, _)| name.as_str())
    .collect::<Vec<_>>();
  let roots = owned_profiles
    .iter()
    .copied()
    .filter(|candidate| {
      let profile = cfg
        .profiles
        .get(*candidate)
        .expect("owned profile name came from the config");
      !looks_like_generated_child_profile(candidate, profile)
        && !owned_profiles
          .iter()
          .copied()
          .any(|other| other != *candidate && candidate.starts_with(&format!("{other}-")))
    })
    .collect::<Vec<_>>();
  if let Some(profile_name) = binding.profile.as_deref() {
    if owned_profiles.contains(&profile_name) {
      let profile = cfg
        .profiles
        .get(profile_name)
        .expect("owned profile name came from the config");
      if roots.contains(&profile_name) && !looks_like_generated_child_profile(profile_name, profile) {
        return Ok(Some(profile_name.to_string()));
      }
      bail!(
        "{} binding profile '{}' is a generated child profile, not a base profile; restore the base binding or unlink before syncing",
        agent,
        profile_name
      );
    }
  }
  match roots.as_slice() {
    [profile] => Ok(Some((*profile).to_string())),
    [] if binding.profile.is_none() => Ok(None),
    [] => bail!(
      "{} binding names missing profile '{}', and no generated profile can recover its previous materialization",
      agent,
      binding.profile.as_deref().expect("checked as present")
    ),
    _ => bail!(
      "{} has ambiguous generated base profiles ({}); remove the stale generated profiles or unlink before syncing",
      agent,
      roots.join(", ")
    ),
  }
}

fn looks_like_generated_child_profile(name: &str, profile: &tokn_config::ProfileConfig) -> bool {
  let Some(provider_id) = profile.default_provider_id.as_deref() else {
    return false;
  };
  name
    .strip_suffix(&format!("-{provider_id}"))
    .is_some_and(|base| !base.is_empty())
    && profile
      .providers
      .as_ref()
      .is_some_and(|providers| providers.len() == 1 && providers[0] == provider_id)
    && profile.accounts.as_ref().is_some_and(|accounts| accounts.len() == 1)
}

fn manifest_account_source(manifest: &MigrationManifest) -> AgentAccountSource {
  let owns_agent_credentials = manifest.gateway_auth_path.is_some()
    || manifest.gateway_auth_shard_path.is_some()
    || manifest.agent_auth_path.is_some()
    || !manifest.imported_account_ids.is_empty()
    || manifest
      .provider_routes
      .iter()
      .any(|route| !route.account_id.is_empty());
  if owns_agent_credentials {
    AgentAccountSource::Agent
  } else {
    AgentAccountSource::Main
  }
}

fn previous_materialized_account_source(
  cfg: &Config,
  previous_profile: Option<&str>,
  existing_binding: Option<&tokn_config::AgentConfig>,
) -> Option<AgentAccountSource> {
  // The declarative binding owns the credential boundary. Generated profile
  // shape is only a legacy recovery signal when there is no binding; otherwise
  // profile drift could make an explicit account-source change look safe.
  existing_binding.map(|binding| binding.account_source).or_else(|| {
    previous_profile
      .and_then(|profile| cfg.profiles.get(profile))
      .map(|profile| {
        if profile.accounts.is_some() {
          AgentAccountSource::Agent
        } else {
          AgentAccountSource::Main
        }
      })
  })
}

fn resolve_main_default_provider(
  cfg: &Config,
  previous_materialized_profile: Option<&str>,
  existing_binding: Option<&tokn_config::AgentConfig>,
  mode: RouteMode,
  account_source: AgentAccountSource,
  explicit_provider: Option<&str>,
  preserve_existing_provider: bool,
) -> Result<Option<String>> {
  if explicit_provider.is_some() && (account_source != AgentAccountSource::Main || !mode.is_verbatim()) {
    bail!("--provider is only valid with --use-main-accounts and --mode passthrough or switch");
  }
  if account_source != AgentAccountSource::Main || !mode.is_verbatim() {
    return Ok(None);
  }
  let provider = explicit_provider
    .or_else(|| {
      preserve_existing_provider
        .then(|| existing_binding.and_then(|binding| binding.provider.as_deref()))
        .flatten()
    })
    .or_else(|| {
      (preserve_existing_provider
        && !previous_materialized_profile_has_provider_routes(cfg, previous_materialized_profile, existing_binding))
      .then(|| {
        previous_materialized_profile
          .and_then(|profile| cfg.profiles.get(profile))
          .and_then(|profile| profile.default_provider_id.as_deref())
      })
      .flatten()
    })
    .map(str::trim)
    .filter(|provider| !provider.is_empty())
    .map(str::to_string);
  Ok(provider)
}

fn previous_materialized_profile_has_provider_routes(
  cfg: &Config,
  previous_materialized_profile: Option<&str>,
  binding: Option<&tokn_config::AgentConfig>,
) -> bool {
  let Some(profile) = previous_materialized_profile.or_else(|| binding.and_then(|binding| binding.profile.as_deref()))
  else {
    return false;
  };
  let prefix = format!("{profile}-");
  cfg.profiles.iter().any(|(name, profile)| {
    name.starts_with(&prefix)
      && profile.agent_id == Some(AgentId::Opencode)
      && profile.default_provider_id.is_some()
      && profile.providers.as_ref().is_some_and(|providers| providers.len() == 1)
  })
}

fn materialized_default_provider(
  mode: RouteMode,
  account_source: AgentAccountSource,
  main_default_provider_id: Option<&str>,
  provider_routes: &[ProviderRoute],
  adapter_default_provider_id: &str,
) -> Option<String> {
  if !mode.is_verbatim() {
    return None;
  }
  if account_source == AgentAccountSource::Main {
    return main_default_provider_id
      .map(str::to_string)
      .or_else(|| provider_routes.first().map(|route| route.gateway_provider_id.clone()));
  }
  provider_routes
    .iter()
    .find(|route| route.source_provider_id == adapter_default_provider_id)
    .or_else(|| provider_routes.first())
    .map(|route| route.gateway_provider_id.clone())
    .or_else(|| Some(adapter_default_provider_id.to_string()))
}

fn validate_verbatim_provider_routes(
  agent: &AgentId,
  adapter: &dyn crate::adapter::AgentAdapter,
  mode: RouteMode,
  routes: &[ProviderRoute],
) -> Result<()> {
  if !mode.is_verbatim() {
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
        agent,
        route.gateway_provider_id,
        route_mode_as_str(mode)
      )
    })?;
    if descriptor.endpoints.iter().any(|spec| spec.endpoint == endpoint) {
      continue;
    }
    bail!(
      "{} --mode {} sends {:?} traffic, but provider '{}' does not support that endpoint; use --mode route instead",
      agent,
      route_mode_as_str(mode),
      endpoint,
      route.gateway_provider_id
    );
  }
  Ok(())
}

fn validate_provider_route_profiles(
  cfg: &Config,
  agent: &AgentId,
  binding_profile: Option<&str>,
  routes: &[ProviderRoute],
) -> Result<()> {
  for route in routes {
    if route.profile.is_empty() || Some(route.profile.as_str()) == binding_profile {
      continue;
    }
    if let Some(existing) = cfg.profiles.get(&route.profile) {
      let matches_generated_route = existing.agent_id.as_ref() == Some(agent)
        && existing.default_provider_id.as_deref() == Some(route.gateway_provider_id.as_str())
        && existing
          .providers
          .as_ref()
          .is_some_and(|providers| providers == std::slice::from_ref(&route.gateway_provider_id))
        && if route.account_id.is_empty() {
          existing.accounts.is_none()
        } else {
          existing
            .accounts
            .as_ref()
            .is_some_and(|accounts| accounts == std::slice::from_ref(&route.account_id))
        };
      if !matches_generated_route {
        bail!(
          "generated profile '{}' already exists but does not match the route owned by {}",
          route.profile,
          agent
        );
      }
    }
  }
  Ok(())
}

fn validate_binding_profile(
  cfg: &Config,
  agent: &AgentId,
  profile: Option<&str>,
  existing_binding: Option<&tokn_config::AgentConfig>,
) -> Result<()> {
  let Some((profile, existing)) =
    profile.and_then(|profile| cfg.profiles.get(profile).map(|existing| (profile, existing)))
  else {
    return Ok(());
  };
  let binding_already_owns_profile = existing_binding.and_then(|binding| binding.profile.as_deref()) == Some(profile);
  if !binding_already_owns_profile || existing.agent_id.as_ref() != Some(agent) {
    bail!("profile '{profile}' already exists and is not owned by {agent}");
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

fn write_edit(edit: &PlannedEdit) -> Result<Vec<u8>> {
  edit.validate_source()?;
  if let Some(parent) = edit.path.parent() {
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
  }
  let contents = match &edit.kind {
    EditKind::Json(value) => serde_json::to_vec_pretty(value)?,
    EditKind::Jsonc(raw) => raw.as_bytes().to_vec(),
    EditKind::Toml(doc) => doc.to_string().into_bytes(),
  };
  std::fs::write(&edit.path, &contents).with_context(|| format!("writing {}", edit.path.display()))?;
  Ok(contents)
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
  let default_provider_id = mode.is_verbatim().then_some(fallback_provider_id);
  let write = AgentProfileWrite {
    agent,
    profile,
    previous_profile: None,
    mode,
    account_source: AgentAccountSource::Agent,
    provider: None,
    provider_filter: None,
    materialized_provider_ids: &[],
    accounts,
    provider_routes,
    default_provider_id,
    fallback_provider_id,
  };
  upsert_agent_and_profiles_with_source(path, &write).map(drop)
}

struct AgentProfileWrite<'a> {
  agent: &'a AgentId,
  profile: Option<&'a str>,
  previous_profile: Option<&'a str>,
  mode: RouteMode,
  account_source: AgentAccountSource,
  provider: Option<&'a str>,
  provider_filter: Option<&'a [String]>,
  materialized_provider_ids: &'a [String],
  accounts: &'a [Account],
  provider_routes: &'a [ProviderRoute],
  default_provider_id: Option<&'a str>,
  fallback_provider_id: &'a str,
}

#[cfg(test)]
fn upsert_agent_and_profiles_with_source(path: &Path, write: &AgentProfileWrite<'_>) -> Result<String> {
  Ok(Config::edit_in_place_with_contents(path, |doc| {
    Ok(edit_agent_and_profiles(doc, write)?)
  })?)
}

fn upsert_agent_and_profiles_with_source_if_unchanged(
  path: &Path,
  expected: Option<&[u8]>,
  write: &AgentProfileWrite<'_>,
) -> Result<String> {
  Ok(Config::edit_in_place_with_contents_if_unchanged(
    path,
    expected,
    |doc| Ok(edit_agent_and_profiles(doc, write)?),
  )?)
}

fn edit_agent_and_profiles(doc: &mut toml_edit::DocumentMut, write: &AgentProfileWrite<'_>) -> Result<()> {
  let previous_profile = write
    .previous_profile
    .map(str::to_string)
    .or_else(|| existing_agent_profile(doc, write.agent));
  upsert_agent(doc, write);
  if let Some(previous_profile) = previous_profile.as_deref() {
    if Some(previous_profile) != write.profile {
      remove_materialized_profile(doc, previous_profile, write.agent);
    }
  }
  if let Some(profile) = write.profile {
    validate_profile_item_owner(doc, profile, write.agent)?;
    upsert_profile_item(doc, profile, write);
    if write.mode.is_verbatim() && !write.provider_routes.is_empty() {
      remove_agent_profiles(doc, profile, write.agent);
      upsert_provider_route_profiles(doc, write.agent, write.mode, write.provider_routes)?;
    } else {
      remove_agent_profiles(doc, profile, write.agent);
    }
  }
  Ok(())
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
    if let Some(provider) = write.provider {
      agent_item["provider"] = toml_edit::value(provider);
    } else if let Some(table) = agent_item.as_table_mut() {
      table.remove("provider");
    }
    if let Some(provider_filter) = write.provider_filter {
      agent_item["provider_filter"] = array_value(provider_filter);
    } else if let Some(table) = agent_item.as_table_mut() {
      table.remove("provider_filter");
    }
    if let Some(table) = agent_item.as_table_mut() {
      table.remove("source_providers");
    }
  } else if let Some(table) = agent_item.as_table_mut() {
    table.remove("account_source");
    table.remove("provider");
    table.remove("provider_filter");
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
    if !write.materialized_provider_ids.is_empty() {
      profile_item["providers"] = array_value(write.materialized_provider_ids);
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

fn upsert_provider_route_profiles(
  doc: &mut toml_edit::DocumentMut,
  agent: &AgentId,
  mode: RouteMode,
  routes: &[ProviderRoute],
) -> Result<()> {
  let profiles = doc["profiles"].or_insert(toml_edit::table());
  for route in routes {
    if route.profile.is_empty() {
      continue;
    }
    if let Some(existing) = profiles.get(route.profile.as_str()) {
      if !profile_item_matches_route(existing, agent, route) {
        bail!(
          "generated profile '{}' already exists but does not match the route owned by {}",
          route.profile,
          agent
        );
      }
    }
    let item = profiles[route.profile.as_str()].or_insert(toml_edit::table());
    item["mode"] = toml_edit::value(route_mode_as_str(mode));
    item["agent_id"] = toml_edit::value(agent.as_str());
    if mode.is_verbatim() {
      item["default_provider_id"] = toml_edit::value(route.gateway_provider_id.as_str());
    } else if let Some(table) = item.as_table_mut() {
      table.remove("default_provider_id");
    }
    item["providers"] = array_value(std::slice::from_ref(&route.gateway_provider_id));
    if route.account_id.is_empty() {
      item.as_table_mut().map(|table| table.remove("accounts"));
    } else {
      item["accounts"] = array_value(std::slice::from_ref(&route.account_id));
    }
  }
  Ok(())
}

fn profile_item_matches_route(item: &toml_edit::Item, agent: &AgentId, route: &ProviderRoute) -> bool {
  let Some(profile) = item.as_table_like() else {
    return false;
  };
  profile.get("agent_id").and_then(toml_edit::Item::as_str) == Some(agent.as_str())
    && profile.get("default_provider_id").and_then(toml_edit::Item::as_str) == Some(route.gateway_provider_id.as_str())
    && table_array_equals(
      profile.get("providers"),
      std::slice::from_ref(&route.gateway_provider_id),
    )
    && if route.account_id.is_empty() {
      profile.get("accounts").is_none()
    } else {
      table_array_equals(profile.get("accounts"), std::slice::from_ref(&route.account_id))
    }
}

fn table_array_equals(item: Option<&toml_edit::Item>, expected: &[String]) -> bool {
  item.and_then(toml_edit::Item::as_array).is_some_and(|array| {
    array.len() == expected.len()
      && array
        .iter()
        .zip(expected)
        .all(|(actual, expected)| actual.as_str() == Some(expected.as_str()))
  })
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
    .filter(|(key, item)| key.starts_with(&prefix) && materialized_child_profile(item, agent))
    .map(|(key, _)| key.to_string())
    .collect::<Vec<_>>();
  for key in keys {
    table.remove(&key);
  }
}

fn materialized_child_profile(item: &toml_edit::Item, agent: &AgentId) -> bool {
  let Some(profile) = item.as_table_like() else {
    return false;
  };
  let Some(provider) = profile.get("default_provider_id").and_then(toml_edit::Item::as_str) else {
    return false;
  };
  profile.get("agent_id").and_then(toml_edit::Item::as_str) == Some(agent.as_str())
    && table_array_equals(profile.get("providers"), &[provider.to_string()])
    && profile
      .get("accounts")
      .and_then(toml_edit::Item::as_array)
      .is_none_or(|accounts| !accounts.is_empty())
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
) -> Result<Option<String>> {
  if let Some(profile) = explicit_profile {
    validate_profile_name(profile)?;
    return Ok(Some(profile.to_string()));
  }
  if let Some(profile) = existing_binding.and_then(|binding| binding.profile.as_deref()) {
    validate_profile_name(profile)?;
    return Ok(Some(profile.to_string()));
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
  let home = match home {
    Some(home) => home,
    None => directories::BaseDirs::new()
      .map(|dirs| dirs.home_dir().to_path_buf())
      .ok_or_else(|| anyhow!("cannot resolve home directory"))?,
  };
  std::path::absolute(&home).with_context(|| format!("resolving agent home path {}", home.display()))
}

fn default_gateway_auth_path() -> Result<PathBuf> {
  default_auth_path()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn diagnostic_starts_with_path(message: &str, expected: &Path, marker: &str) -> bool {
    message
      .split_once(marker)
      .is_some_and(|(actual, _)| same_path(Path::new(actual), expected))
  }

  #[test]
  fn main_codex_route_uses_opencodes_openai_source_namespace() {
    let cfg = Config::default();
    let routes = main_provider_routes(
      &cfg,
      Some("opencode"),
      &[tokn_core::provider::ID_CODEX.to_string()],
      false,
    );

    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].source_provider_id, tokn_core::provider::ID_OPENAI);
    assert_eq!(routes[0].gateway_provider_id, tokn_core::provider::ID_CODEX);
  }

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

  #[test]
  fn declarative_binding_owns_the_previous_account_source_when_profile_shape_drifts() {
    for (binding_source, materialized_source) in [
      (AgentAccountSource::Agent, AgentAccountSource::Main),
      (AgentAccountSource::Main, AgentAccountSource::Agent),
    ] {
      let mut cfg = Config::default();
      cfg.profiles.insert(
        "work".into(),
        tokn_config::ProfileConfig {
          mode: Some(RouteMode::Route),
          agent_id: Some(AgentId::Opencode),
          default_provider_id: None,
          providers: Some(vec!["openai".into()]),
          accounts: (materialized_source == AgentAccountSource::Agent).then(|| vec!["opencode-openai".into()]),
          model_families: None,
        },
      );
      let binding = tokn_config::AgentConfig {
        mode: Some(RouteMode::Route),
        profile: Some("work".into()),
        account_source: binding_source,
        provider: None,
        provider_filter: None,
        source_providers: None,
        sync: true,
      };

      assert_eq!(
        previous_materialized_account_source(&cfg, Some("work"), Some(&binding)),
        Some(binding_source)
      );
    }
  }

  #[test]
  fn provider_routes_reject_multiple_enabled_accounts_for_one_opencode_source() {
    let imported = |id: &str, provider: &str| {
      let mut account = annotate_imported_account(
        sample_account(id, provider),
        AgentId::Opencode,
        Path::new("/tmp/opencode-auth.json"),
        "auth.openai",
        "20260729T000000Z",
      );
      account
        .settings
        .get_mut("import")
        .and_then(toml::Value::as_table_mut)
        .unwrap()
        .insert("source_provider".into(), toml::Value::String("openai".into()));
      account
    };
    let accounts = [
      imported("opencode-openai", tokn_core::provider::ID_OPENAI),
      imported("opencode-codex", tokn_core::provider::ID_CODEX),
    ];

    let error = provider_routes(
      &Config::default(),
      Some("opencode"),
      &accounts,
      &BTreeSet::new(),
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap_err();

    assert!(error.to_string().contains("multiple enabled gateway accounts"));
    assert!(error.to_string().contains("disable all but one"));
  }

  fn sample_active_manifest(
    profile: Option<&str>,
    fragment_path: &Path,
    account_source: AgentAccountSource,
  ) -> MigrationManifest {
    let agent_owned = account_source == AgentAccountSource::Agent;
    MigrationManifest {
      version: 4,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260729T000000Z".into(),
      profile: profile.map(str::to_string),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: agent_owned.then(|| PathBuf::from("/tmp/auth.yaml")),
      gateway_auth_shard_path: agent_owned.then(|| PathBuf::from("/tmp/auth.d/opencode.yaml")),
      agent_auth_path: None,
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: true,
      imported_account_ids: if agent_owned {
        vec!["opencode-openai".into()]
      } else {
        Vec::new()
      },
      files: vec![FileBackup {
        original: fragment_path.to_path_buf(),
        backup: None,
        existed: true,
        created_by_migration: false,
        applied_sha256: None,
      }],
    }
  }

  #[test]
  fn reconcile_rejects_a_relative_path_in_any_manifest_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    let ancestor_path = dir.path().join("20260729T000000Z-opencode.json");
    let latest_path = dir.path().join("20260729T000001Z-opencode.json");
    let ancestor = sample_active_manifest(
      Some("opencode"),
      Path::new("config.d/opencode.toml"),
      AgentAccountSource::Main,
    );
    let mut latest = sample_active_manifest(
      Some("opencode"),
      &dir.path().join("config.d/opencode.toml"),
      AgentAccountSource::Main,
    );
    latest.timestamp = "20260729T000001Z".into();
    latest.previous_manifest = Some(ancestor_path.clone());
    manifest::write_manifest(&ancestor_path, &ancestor).unwrap();
    manifest::write_manifest(&latest_path, &latest).unwrap();

    let error = validate_manifest_chain_for_reconcile(&latest_path, &AgentId::Opencode).unwrap_err();

    assert!(error.to_string().contains(&ancestor_path.display().to_string()));
    assert!(error.to_string().contains("--legacy-root"));
  }

  fn save_main_accounts(auth_path: &Path, config_path: &Path, providers: &[(&str, &str)]) {
    let mut store = AuthStore::load(Some(auth_path), Some(config_path)).unwrap();
    for (account_id, provider_id) in providers {
      let mut account = sample_account(account_id, provider_id);
      account.api_key = Some(tokn_core::util::secret::Secret::new(format!("sk-{account_id}")));
      store.upsert(account);
    }
    store.save().unwrap();
  }

  fn save_agent_shard_accounts(auth_path: &Path, source_auth_path: &Path, accounts: &[(&str, &str, bool)]) -> PathBuf {
    let mut store = AuthStore::load(Some(auth_path), None).unwrap();
    for (account_id, provider_id, enabled) in accounts {
      let mut discovered = sample_account(account_id, provider_id);
      discovered.api_key = Some(tokn_core::util::secret::Secret::new(format!("sk-{account_id}")));
      let mut account = annotate_imported_account(
        discovered,
        AgentId::Opencode,
        source_auth_path,
        &format!("auth.{provider_id}"),
        "20260729T010203Z",
      );
      account.enabled = *enabled;
      let account = mark_gateway_owned(account);
      store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();
    }
    store.save().unwrap();
    AuthStore::shard_path_for(auth_path, AgentId::Opencode.as_str()).unwrap()
  }

  fn create_failed_post_strip_opencode_link(root: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let agent_home = root.join("home");
    let gateway_config_path = root.join("gateway/config.toml");
    let gateway_auth_path = root.join("gateway/auth.yaml");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    let manifest_path = root.join("opencode-link.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nhost = \"127.0.0.1\"\nport = 4141\n").unwrap();
    std::fs::write(&gateway_auth_path, "version: 1\naccounts: []\n").unwrap();
    std::fs::write(&opencode_config_path, "{}\n").unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::to_vec_pretty(&serde_json::json!({
        "openai": {"type": "api", "key": "sk-post-strip"}
      }))
      .unwrap(),
    )
    .unwrap();

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    plan.timestamp = "20260729T050101Z".into();
    let shard_path = plan.gateway_auth_shard_path.clone().unwrap();
    let blocked_parent = root.join("blocked-parent");
    std::fs::write(&blocked_parent, "not a directory").unwrap();
    plan.edits.push(PlannedEdit::new(
      blocked_parent.join("late.json"),
      EditKind::Json(serde_json::json!({"late": true})),
      true,
      None,
    ));

    let error = apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap_err();
    assert!(format!("{error:#}").contains("creating"));
    let linked_auth: Value = serde_json::from_str(&std::fs::read_to_string(&opencode_auth_path).unwrap()).unwrap();
    assert!(linked_auth.get("openai").is_none());
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert!(!manifest.completed);
    assert!(!manifest.credentials_handoff_complete);
    assert!(manifest
      .files
      .iter()
      .any(|file| { file.original == shard_path && file.applied_sha256.is_some() }));

    (gateway_auth_path, shard_path, opencode_auth_path, manifest_path)
  }

  fn write_existing_opencode_agent_link(gateway_config_path: &Path) {
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::write(gateway_config_path, "[server]\nhost = \"127.0.0.1\"\nport = 4141\n").unwrap();
    let fragment_path = tokn_config::paths::agent_config_fragment_path(gateway_config_path, AgentId::Opencode.as_str());
    std::fs::create_dir_all(fragment_path.parent().unwrap()).unwrap();
    std::fs::write(
      fragment_path,
      r#"[agents.opencode]
mode = "route"
profile = "opencode"
sync = true

[profiles.opencode]
mode = "route"
agent_id = "opencode"
providers = ["openai", "deepseek"]
accounts = ["opencode-openai", "opencode-deepseek"]
"#,
    )
    .unwrap();
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
  fn active_manifest_serializes_an_agent_link_across_gateway_configs() {
    let first_fragment = PathBuf::from("/tmp/first/config.d/opencode.toml");
    let second_fragment = PathBuf::from("/tmp/second/config.d/opencode.toml");
    let manifest = sample_active_manifest(Some("opencode"), &first_fragment, AgentAccountSource::Main);

    validate_previous_manifest_scope(&manifest, &first_fragment, &AgentId::Opencode).unwrap();
    let error = validate_previous_manifest_scope(&manifest, &second_fragment, &AgentId::Opencode)
      .expect_err("a second gateway config must not share the agent-owned files");
    assert!(error.to_string().contains("active link for a different gateway"));
    assert!(error.to_string().contains("unlink"));
  }

  #[test]
  fn manifest_source_rejects_account_source_edits_even_when_the_profile_was_also_edited() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let gateway_auth_path = dir.path().join("auth.yaml");
    let fragment_path = tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "opencode");
    std::fs::create_dir_all(fragment_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "").unwrap();

    for (desired_source, previous_source, profile_accounts) in [
      (
        AgentAccountSource::Agent,
        AgentAccountSource::Main,
        "accounts = [\"forged\"]",
      ),
      (AgentAccountSource::Main, AgentAccountSource::Agent, ""),
    ] {
      std::fs::write(
        &fragment_path,
        format!(
          r#"
[agents.opencode]
mode = "route"
profile = "opencode"
account_source = "{}"
sync = true

[profiles.opencode]
mode = "route"
agent_id = "opencode"
providers = ["openai"]
{profile_accounts}
"#,
          match desired_source {
            AgentAccountSource::Agent => "agent",
            AgentAccountSource::Main => "main",
          }
        ),
      )
      .unwrap();
      let manifest = sample_active_manifest(Some("opencode"), &fragment_path, previous_source);
      let error = plan_reconcile_with_gateway_auth_path_and_manifest(
        ReconcileRequest {
          agent: AgentId::Opencode,
          profile: None,
          mode: None,
          account_source: None,
          default_provider_id: None,
          provider_filter: None,
          gateway_config_path: Some(gateway_config_path.clone()),
          agent_home: Some(dir.path().join("home")),
        },
        gateway_auth_path.clone(),
        Some(dir.path().join("manifest.json")),
        Some(&manifest),
      )
      .expect_err("manifest source must be authoritative");
      assert!(error.to_string().contains("changing account source"));
      assert!(error.to_string().contains("agent unlink"));
    }
  }

  #[test]
  fn manifest_profile_is_authoritative_and_must_still_exist() {
    let mut cfg = Config::default();
    let binding = tokn_config::AgentConfig {
      profile: Some("renamed".into()),
      ..Default::default()
    };
    let manifest = sample_active_manifest(
      Some("old-profile"),
      Path::new("/tmp/config.d/opencode.toml"),
      AgentAccountSource::Main,
    );

    let error =
      resolve_previous_materialized_profile(&cfg, Some(&binding), &AgentId::Opencode, Some(&manifest)).unwrap_err();
    assert!(error.to_string().contains("old-profile"));
    assert!(error.to_string().contains("missing"));

    cfg.profiles.insert(
      "old-profile".into(),
      tokn_config::ProfileConfig {
        agent_id: Some(AgentId::Opencode),
        ..Default::default()
      },
    );
    assert_eq!(
      resolve_previous_materialized_profile(&cfg, Some(&binding), &AgentId::Opencode, Some(&manifest)).unwrap(),
      Some("old-profile".into())
    );
  }

  #[test]
  fn legacy_profile_inventory_rejects_a_generated_child_as_the_base() {
    let mut cfg = Config::default();
    for name in ["work", "work-openai"] {
      cfg.profiles.insert(
        name.into(),
        tokn_config::ProfileConfig {
          agent_id: Some(AgentId::Opencode),
          ..Default::default()
        },
      );
    }
    let binding = tokn_config::AgentConfig {
      profile: Some("work-openai".into()),
      ..Default::default()
    };

    let error = resolve_previous_materialized_profile(&cfg, Some(&binding), &AgentId::Opencode, None)
      .expect_err("a generated child cannot become the base profile");
    assert!(error.to_string().contains("generated child profile"));
  }

  #[test]
  fn legacy_profile_inventory_does_not_adopt_a_lone_generated_child() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
      "work-openai".into(),
      tokn_config::ProfileConfig {
        agent_id: Some(AgentId::Opencode),
        default_provider_id: Some(tokn_core::provider::ID_OPENAI.into()),
        providers: Some(vec![tokn_core::provider::ID_OPENAI.into()]),
        accounts: Some(vec!["opencode-openai".into()]),
        ..Default::default()
      },
    );

    let missing_binding = tokn_config::AgentConfig {
      profile: Some("work".into()),
      ..Default::default()
    };
    let error =
      resolve_previous_materialized_profile(&cfg, Some(&missing_binding), &AgentId::Opencode, None).unwrap_err();
    assert!(error.to_string().contains("no generated profile"));

    let profileless_binding = tokn_config::AgentConfig::default();
    assert_eq!(
      resolve_previous_materialized_profile(&cfg, Some(&profileless_binding), &AgentId::Opencode, None,).unwrap(),
      None
    );
  }

  #[test]
  fn previous_mode_comes_from_the_materialized_runtime_profile() {
    let mut cfg = Config::default();
    cfg.defaults.mode = RouteMode::Fuzzy;
    cfg.profiles.insert(
      "opencode".into(),
      tokn_config::ProfileConfig {
        mode: Some(RouteMode::Switch),
        agent_id: Some(AgentId::Opencode),
        default_provider_id: Some(tokn_core::provider::ID_DEEPSEEK.into()),
        ..Default::default()
      },
    );
    let binding = tokn_config::AgentConfig {
      mode: Some(RouteMode::Exact),
      profile: Some("opencode".into()),
      ..Default::default()
    };
    let previous_profile =
      resolve_previous_materialized_profile(&cfg, Some(&binding), &AgentId::Opencode, None).unwrap();

    assert_eq!(
      previous_materialized_mode(&cfg, previous_profile.as_deref()),
      Some(RouteMode::Switch)
    );
    assert_eq!(
      previous_materialized_provider_ids(&cfg, previous_profile.as_deref(), Some(RouteMode::Switch)),
      Some(vec![tokn_core::provider::ID_DEEPSEEK.into()])
    );

    cfg.profiles.get_mut("opencode").unwrap().mode = None;
    assert_eq!(
      previous_materialized_mode(&cfg, previous_profile.as_deref()),
      Some(RouteMode::Fuzzy)
    );

    let binding_without_profile = tokn_config::AgentConfig {
      mode: Some(RouteMode::Exact),
      ..Default::default()
    };
    let previous_profile =
      resolve_previous_materialized_profile(&cfg, Some(&binding_without_profile), &AgentId::Opencode, None).unwrap();
    assert_eq!(
      previous_materialized_mode(&cfg, previous_profile.as_deref()),
      Some(RouteMode::Fuzzy)
    );
  }

  #[test]
  fn legacy_raw_main_relink_recovers_the_old_materialized_profile_target() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
      "old-profile".into(),
      tokn_config::ProfileConfig {
        mode: Some(RouteMode::Switch),
        agent_id: Some(AgentId::Opencode),
        default_provider_id: Some(tokn_core::provider::ID_DEEPSEEK.into()),
        ..Default::default()
      },
    );
    let binding = tokn_config::AgentConfig {
      mode: Some(RouteMode::Switch),
      profile: Some("old-profile".into()),
      account_source: AgentAccountSource::Main,
      ..Default::default()
    };

    assert_eq!(
      resolve_main_default_provider(
        &cfg,
        Some("old-profile"),
        Some(&binding),
        RouteMode::Switch,
        AgentAccountSource::Main,
        None,
        true,
      )
      .unwrap()
      .as_deref(),
      Some(tokn_core::provider::ID_DEEPSEEK)
    );
  }

  #[test]
  fn raw_main_provider_prefers_explicit_then_stored_binding_intent() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
      "opencode".into(),
      tokn_config::ProfileConfig {
        default_provider_id: Some("deepseek".into()),
        ..Default::default()
      },
    );
    let binding = tokn_config::AgentConfig {
      mode: Some(RouteMode::Switch),
      profile: Some("opencode".into()),
      account_source: AgentAccountSource::Main,
      provider: Some("openai".into()),
      ..Default::default()
    };

    assert_eq!(
      resolve_main_default_provider(
        &cfg,
        Some("opencode"),
        Some(&binding),
        RouteMode::Switch,
        AgentAccountSource::Main,
        None,
        true,
      )
      .unwrap()
      .as_deref(),
      Some("openai")
    );
    assert_eq!(
      resolve_main_default_provider(
        &cfg,
        Some("opencode"),
        Some(&binding),
        RouteMode::Switch,
        AgentAccountSource::Main,
        Some("deepseek"),
        true,
      )
      .unwrap()
      .as_deref(),
      Some("deepseek")
    );
  }

  #[test]
  fn plan_reconcile_uses_explicit_agent_home_and_defaults_fresh_links_to_agent_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let gateway_auth_path = dir.path().join("auth.yaml");
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

    let plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
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
  fn agent_owned_link_rejects_global_markdown_references_before_transferring_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let gateway_auth_path = dir.path().join("auth.yaml");
    let agent_home = dir.path().join("agent-home");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let markdown_path = agent_home.join(".config/opencode/agents/reviewer.md");
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(markdown_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "").unwrap();
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
    std::fs::write(&opencode_config_path, "{}\n").unwrap();
    std::fs::write(&markdown_path, "---\nmodel: openai/gpt-5\n---\nReview changes.\n").unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .expect_err("global Markdown selections must be migrated before credential transfer");

    let message = error.to_string();
    assert!(
      crate::opencode_markdown::diagnostic_mentions_markdown_path(&message, &markdown_path),
      "{message}"
    );
    assert!(message.contains("openai/gpt-5"));
    assert!(message.contains("tokn-router/gpt-5"));
  }

  #[test]
  fn agent_owned_link_requires_importable_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let gateway_auth_path = dir.path().join("auth.yaml");
    let agent_home = dir.path().join("agent-home");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "").unwrap();
    std::fs::write(&opencode_config_path, serde_json::json!({}).to_string()).unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap_err();

    assert_eq!(
      error.to_string(),
      "opencode has no importable credentials; authenticate it first or link with --use-main-accounts"
    );
  }

  #[test]
  fn agent_owned_sync_routes_only_enabled_imported_accounts_and_keeps_disabled_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("sync-manifest.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    write_existing_opencode_agent_link(&gateway_config_path);
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&opencode_config_path, "{}\n").unwrap();
    let shard_path = save_agent_shard_accounts(
      &gateway_auth_path,
      &opencode_auth_path,
      &[
        ("opencode-openai", tokn_core::provider::ID_OPENAI, true),
        ("opencode-deepseek", tokn_core::provider::ID_DEEPSEEK, false),
      ],
    );

    let plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();

    assert_eq!(plan.imported_accounts.len(), 2);
    assert_eq!(plan.credential_routes.len(), 2);
    assert_eq!(plan.provider_routes.len(), 1);
    assert_eq!(
      plan.provider_routes[0].gateway_provider_id,
      tokn_core::provider::ID_OPENAI
    );
    let projected_config = plan
      .edits
      .iter()
      .find(|edit| edit.path == opencode_config_path)
      .and_then(|edit| match &edit.kind {
        EditKind::Jsonc(raw) => Some(crate::jsonc::parse_jsonc(raw, &edit.path).unwrap()),
        _ => None,
      })
      .unwrap();
    let published_models = projected_config["provider"]["tokn-router"]["models"]
      .as_object()
      .unwrap();
    assert!(published_models.contains_key("gpt-5"));
    assert!(!published_models.keys().any(|model| model.starts_with("deepseek-")));

    apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap();

    let (cfg, _) = Config::load(Some(&gateway_config_path)).unwrap();
    assert_eq!(
      cfg.profiles["opencode"].accounts.as_deref(),
      Some(&["opencode-openai".to_string()][..])
    );
    assert_eq!(
      cfg.profiles["opencode"].providers.as_deref(),
      Some(&[tokn_core::provider::ID_OPENAI.to_string()][..])
    );
    let store = AuthStore::load(Some(&gateway_auth_path), Some(&gateway_config_path)).unwrap();
    assert!(!store.get("opencode-deepseek").unwrap().enabled);
    assert_eq!(
      store.account_source_path("opencode-deepseek").as_deref(),
      Some(shard_path.as_path())
    );
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.provider_routes.len(), 2);
    assert_eq!(manifest.imported_account_ids.len(), 2);
  }

  #[test]
  fn agent_owned_sync_rejects_a_shard_with_no_enabled_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    write_existing_opencode_agent_link(&gateway_config_path);
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&opencode_config_path, "{}\n").unwrap();
    let shard_path = save_agent_shard_accounts(
      &gateway_auth_path,
      &opencode_auth_path,
      &[
        ("opencode-openai", tokn_core::provider::ID_OPENAI, false),
        ("opencode-deepseek", tokn_core::provider::ID_DEEPSEEK, false),
      ],
    );

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap_err();

    assert_eq!(
      error.to_string(),
      format!(
        "opencode has imported credentials, but none are enabled in {}; enable at least one account before linking or syncing",
        shard_path.display()
      )
    );
  }

  #[test]
  fn opencode_main_account_modes_publish_from_main_accounts_without_modifying_them() {
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
  "model": "openai/gpt-5",
}
"#;
    let opencode_auth = b"this need not be valid JSON for a main-account link";
    std::fs::write(&gateway_config_path, root_config).unwrap();
    std::fs::write(&opencode_config_path, opencode_config).unwrap();
    std::fs::write(&opencode_auth_path, opencode_auth).unwrap();
    let mut store = AuthStore::load(Some(&gateway_auth_path), Some(&gateway_config_path)).unwrap();
    let mut openai = sample_account("main-openai", tokn_core::provider::ID_OPENAI);
    openai.api_key = Some(tokn_core::util::secret::Secret::new("sk-main-openai".into()));
    store.upsert(openai);
    let mut deepseek = sample_account("main-deepseek", tokn_core::provider::ID_DEEPSEEK);
    deepseek.api_key = Some(tokn_core::util::secret::Secret::new("sk-main-deepseek".into()));
    store.upsert(deepseek);
    store.save().unwrap();
    let gateway_auth = std::fs::read(&gateway_auth_path).unwrap();

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: Some(tokn_core::provider::ID_OPENAI.into()),
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    assert!(plan.imported_accounts.is_empty());
    assert!(plan.gateway_auth_sources_snapshot.is_some());
    assert!(plan.gateway_auth_snapshot.is_none());
    assert!(plan.source_auth_path.is_none());
    assert!(plan.agent_auth_path.is_none());
    assert_eq!(plan.provider.as_deref(), Some(tokn_core::provider::ID_OPENAI));
    assert_eq!(plan.provider_filter, None);
    assert_eq!(plan.published_provider_ids, vec!["openai".to_string()]);
    assert_eq!(plan.gateway_provider_ids(), vec!["openai".to_string()]);
    assert_eq!(plan.injected_provider_ids(), vec!["tokn-router-openai".to_string()]);
    assert_eq!(plan.profile_layout(), AgentProfileLayout::SinglePinned);
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
    assert_eq!(binding.provider.as_deref(), Some(tokn_core::provider::ID_OPENAI));
    assert_eq!(binding.provider_filter, None);
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
    assert!(rewritten["provider"]["tokn-router-openai"]["models"]["gpt-5"].is_object());
    assert_eq!(rewritten["model"], "tokn-router-openai/gpt-5");
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.gateway_auth_path, None);
    assert_eq!(manifest.agent_auth_path, None);
    assert!(manifest.credentials_handoff_complete);
    assert!(manifest.imported_account_ids.is_empty());

    let linked_fragment = std::fs::read_to_string(&fragment_path).unwrap();
    let mut fragment = linked_fragment.parse::<toml_edit::DocumentMut>().unwrap();
    fragment["agents"]["opencode"]["mode"] = toml_edit::value("route");
    fragment["agents"]["opencode"]
      .as_table_mut()
      .unwrap()
      .remove("provider");
    std::fs::write(&fragment_path, fragment.to_string()).unwrap();

    let relink_plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    assert_eq!(relink_plan.account_source, AgentAccountSource::Main);
    assert_eq!(relink_plan.binding_mode, RouteMode::Route);
    assert!(relink_plan.imported_accounts.is_empty());
    assert!(relink_plan.gateway_auth_sources_snapshot.is_some());
    assert!(relink_plan.gateway_auth_snapshot.is_none());
    assert!(relink_plan.gateway_auth_shard_path.is_none());
    assert!(relink_plan.gateway_auth_shard_snapshot.is_none());
    assert!(relink_plan.source_auth_path.is_none());
    assert!(relink_plan.source_auth_snapshot.is_none());
    assert!(relink_plan.agent_auth_path.is_none());
    assert_eq!(relink_plan.provider, None);
    assert_eq!(relink_plan.provider_filter, None);
    assert_eq!(
      relink_plan.published_provider_ids,
      vec!["deepseek".to_string(), "openai".to_string()]
    );
    assert_eq!(
      relink_plan.gateway_provider_ids(),
      vec!["deepseek".to_string(), "openai".to_string()]
    );
    assert_eq!(relink_plan.injected_provider_ids(), vec!["tokn-router".to_string()]);
    assert_eq!(relink_plan.profile_layout(), AgentProfileLayout::Single);
    assert_eq!(
      relink_plan
        .provider_routes
        .iter()
        .map(|route| route.source_provider_id.as_str())
        .collect::<Vec<_>>(),
      vec!["deepseek", "openai"]
    );
    let rewritten = relink_plan
      .edits
      .iter()
      .find(|edit| edit.path == opencode_config_path)
      .and_then(|edit| match &edit.kind {
        EditKind::Jsonc(raw) => Some(crate::jsonc::parse_jsonc(raw, &edit.path).unwrap()),
        _ => None,
      })
      .unwrap();
    assert_eq!(rewritten["model"], "tokn-router/gpt-5");

    // This test only previews the declarative relink. Put the active
    // manifest's post-image back before using unlink for cleanup.
    std::fs::write(&fragment_path, linked_fragment).unwrap();
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
  fn main_account_switch_without_provider_links_every_enabled_provider() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("main-switch.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();
    std::fs::write(&opencode_config_path, r#"{"model":"deepseek/deepseek-v4-flash"}"#).unwrap();
    save_main_accounts(
      &gateway_auth_path,
      &gateway_config_path,
      &[("main-openai", "openai"), ("main-deepseek", "deepseek")],
    );

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: None,
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();

    assert_eq!(plan.provider, None);
    assert_eq!(plan.default_provider_id.as_deref(), Some("deepseek"));
    assert_eq!(plan.published_provider_ids, ["deepseek", "openai"]);
    assert_eq!(plan.gateway_provider_ids(), ["deepseek", "openai"]);
    assert_eq!(
      plan.injected_provider_ids(),
      ["tokn-router-deepseek", "tokn-router-openai"]
    );
    assert_eq!(plan.profile_layout(), AgentProfileLayout::PerProvider);
    assert_eq!(
      plan
        .provider_routes
        .iter()
        .map(|route| (route.profile.as_str(), route.base_url.as_str()))
        .collect::<Vec<_>>(),
      [
        ("opencode-deepseek", "http://127.0.0.1:4141/opencode-deepseek/v1"),
        ("opencode-openai", "http://127.0.0.1:4141/opencode-openai/v1"),
      ]
    );
    let projected_config = plan
      .edits
      .iter()
      .find(|edit| edit.path == opencode_config_path)
      .and_then(|edit| match &edit.kind {
        EditKind::Jsonc(raw) => Some(crate::jsonc::parse_jsonc(raw, &edit.path).unwrap()),
        _ => None,
      })
      .unwrap();
    assert_eq!(projected_config["model"], "tokn-router-deepseek/deepseek-v4-flash");
    assert!(projected_config["provider"]["tokn-router-deepseek"].is_object());
    assert!(projected_config["provider"]["tokn-router-openai"].is_object());
    assert_eq!(
      projected_config["provider"]["tokn-router-deepseek"]["options"]["baseURL"],
      "http://127.0.0.1:4141/opencode-deepseek/v1"
    );
    assert_eq!(
      projected_config["provider"]["tokn-router-openai"]["options"]["baseURL"],
      "http://127.0.0.1:4141/opencode-openai/v1"
    );

    plan.timestamp = "20260731T000000Z".into();
    apply_reconcile_to_manifest_path(plan, manifest_path).unwrap();

    let (cfg, _) = Config::load(Some(&gateway_config_path)).unwrap();
    assert_eq!(cfg.agents["opencode"].provider, None);
    assert_eq!(
      cfg.profiles["opencode"].default_provider_id.as_deref(),
      Some("deepseek")
    );
    assert_eq!(
      cfg.profiles["opencode"].providers.as_deref(),
      Some(&["deepseek".to_string(), "openai".to_string()][..])
    );
    for provider in ["deepseek", "openai"] {
      let profile = &cfg.profiles[&format!("opencode-{provider}")];
      assert_eq!(profile.mode, Some(RouteMode::Switch));
      assert_eq!(profile.default_provider_id.as_deref(), Some(provider));
      assert_eq!(profile.providers.as_deref(), Some(&[provider.to_string()][..]));
      assert_eq!(profile.accounts, None);
    }

    let sync_plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap();
    assert_eq!(sync_plan.provider, None);
    assert_eq!(sync_plan.profile_layout(), AgentProfileLayout::PerProvider);
    assert_eq!(
      sync_plan
        .provider_routes
        .iter()
        .map(|route| route.profile.as_str())
        .collect::<Vec<_>>(),
      ["opencode-deepseek", "opencode-openai"]
    );
  }

  #[test]
  fn declarative_route_to_switch_sync_reads_provider_from_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let first_manifest_path = dir.path().join("route.json");
    let second_manifest_path = dir.path().join("switch.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();
    std::fs::write(&opencode_config_path, r#"{"model":"openai/gpt-5"}"#).unwrap();
    save_main_accounts(&gateway_auth_path, &gateway_config_path, &[("main-openai", "openai")]);

    let mut initial = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Route),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: None,
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    initial.timestamp = "20260729T030101Z".into();
    apply_reconcile_to_manifest_path(initial, first_manifest_path).unwrap();

    let fragment_path = tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "opencode");
    let mut fragment = std::fs::read_to_string(&fragment_path)
      .unwrap()
      .parse::<toml_edit::DocumentMut>()
      .unwrap();
    fragment["agents"]["opencode"]["mode"] = toml_edit::value("switch");
    fragment["agents"]["opencode"]["provider"] = toml_edit::value("openai");
    std::fs::write(&fragment_path, fragment.to_string()).unwrap();

    let mut sync = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap();
    assert_eq!(sync.binding_mode, RouteMode::Switch);
    assert_eq!(sync.provider.as_deref(), Some("openai"));
    assert_eq!(sync.previous_materialized_profile.as_deref(), Some("opencode"));
    sync.timestamp = "20260729T030102Z".into();
    apply_reconcile_to_manifest_path(sync, second_manifest_path).unwrap();

    let (cfg, _) = Config::load(Some(&gateway_config_path)).unwrap();
    assert_eq!(cfg.agents["opencode"].provider.as_deref(), Some("openai"));
    assert_eq!(cfg.profiles["opencode"].mode, Some(RouteMode::Switch));
    assert_eq!(cfg.profiles["opencode"].default_provider_id.as_deref(), Some("openai"));
  }

  #[test]
  fn main_account_scope_change_rejects_a_removed_provider_model_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("main-route.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();
    std::fs::write(&opencode_config_path, r#"{"model": "deepseek/deepseek-chat"}"#).unwrap();
    save_main_accounts(
      &gateway_auth_path,
      &gateway_config_path,
      &[("main-openai", "openai"), ("main-deepseek", "deepseek")],
    );

    let mut initial = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Route),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: None,
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    initial.timestamp = "20260729T010101Z".into();
    apply_reconcile_to_manifest_path(initial, manifest_path).unwrap();

    let linked = crate::jsonc::read_jsonc(&opencode_config_path).unwrap();
    assert_eq!(linked["model"], "tokn-router/deepseek-chat");
    let (linked_config, _) = Config::load(Some(&gateway_config_path)).unwrap();
    assert_eq!(
      linked_config.profiles["opencode"].providers.as_deref(),
      Some(&["deepseek".to_string(), "openai".to_string()][..])
    );

    let mut store = AuthStore::load(Some(&gateway_auth_path), Some(&gateway_config_path)).unwrap();
    assert!(store.remove("main-deepseek").is_some());
    store.save().unwrap();
    let before = std::fs::read_to_string(&opencode_config_path).unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: None,
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap_err();

    assert!(error
      .to_string()
      .contains("is not present in the new gateway model catalogue"));
    assert_eq!(std::fs::read_to_string(opencode_config_path).unwrap(), before);
  }

  #[test]
  fn raw_main_provider_retarget_rejects_an_old_provider_only_model_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("main-switch.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();
    std::fs::write(&opencode_config_path, r#"{"model": "openai/openai-only-model"}"#).unwrap();
    save_main_accounts(
      &gateway_auth_path,
      &gateway_config_path,
      &[("main-openai", "openai"), ("main-deepseek", "deepseek")],
    );

    let mut initial = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: Some("openai".into()),
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    initial.timestamp = "20260729T010102Z".into();
    apply_reconcile_to_manifest_path(initial, manifest_path).unwrap();

    let linked = crate::jsonc::read_jsonc(&opencode_config_path).unwrap();
    assert_eq!(linked["model"], "tokn-router-openai/openai-only-model");
    let before = std::fs::read_to_string(&opencode_config_path).unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: Some("deepseek".into()),
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap_err();

    assert!(
      error
        .to_string()
        .contains("is not published by the pinned gateway provider"),
      "{error:#}"
    );
    assert_eq!(std::fs::read_to_string(opencode_config_path).unwrap(), before);
  }

  #[test]
  fn switch_with_no_imported_agent_accounts_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "").unwrap();
    std::fs::write(&opencode_config_path, "{}\n").unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Switch),
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path,
    )
    .unwrap_err();
    assert_eq!(
      error.to_string(),
      "opencode has no importable credentials; authenticate it first or link with --use-main-accounts"
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
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home.clone()),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not support that endpoint"));
    assert!(error.to_string().contains("opencode --mode switch"));
    assert_eq!(std::fs::read_to_string(&gateway_config_path).unwrap(), root_config);
    assert_eq!(std::fs::read_to_string(&opencode_config_path).unwrap(), opencode_config);
    assert_eq!(std::fs::read_to_string(&opencode_auth_path).unwrap(), opencode_auth);
    assert!(!gateway_auth_path.exists());
    assert!(!tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "opencode").exists());
  }

  #[test]
  fn main_account_provider_filter_rejects_blank_duplicate_and_raw_values() {
    let duplicate = vec!["openai".to_string(), "openai".to_string()];
    let error =
      resolve_main_provider_filter(Some(&duplicate), None, AgentAccountSource::Main, RouteMode::Route).unwrap_err();
    assert!(error.to_string().contains("more than once"));

    let blank = vec![" ".to_string()];
    let error =
      resolve_main_provider_filter(Some(&blank), None, AgentAccountSource::Main, RouteMode::Route).unwrap_err();
    assert!(error.to_string().contains("must not be empty"));

    let raw = vec!["openai".to_string()];
    let error =
      resolve_main_provider_filter(Some(&raw), None, AgentAccountSource::Main, RouteMode::Switch).unwrap_err();
    assert!(error.to_string().contains("--provider-filter is not valid"));
  }

  #[test]
  fn main_account_provider_filter_preserves_explicit_intent_and_supports_auto_discovery() {
    let existing = tokn_config::AgentConfig {
      account_source: AgentAccountSource::Main,
      provider_filter: Some(vec!["openai".into()]),
      ..Default::default()
    };
    assert_eq!(
      resolve_main_provider_filter(None, Some(&existing), AgentAccountSource::Main, RouteMode::Route).unwrap(),
      Some(vec!["openai".to_string()])
    );
    assert_eq!(
      resolve_main_provider_filter(Some(&[]), Some(&existing), AgentAccountSource::Main, RouteMode::Route).unwrap(),
      None
    );
  }

  #[test]
  fn legacy_source_namespaces_require_unlink_before_relink() {
    for source_providers in [vec!["openai".into()], Vec::new()] {
      for account_source in [AgentAccountSource::Main, AgentAccountSource::Agent] {
        let existing = tokn_config::AgentConfig {
          account_source,
          source_providers: Some(source_providers.clone()),
          ..Default::default()
        };

        let error = resolve_main_provider_filter(None, Some(&existing), account_source, RouteMode::Route)
          .expect_err("sync must not reinterpret source namespaces as gateway providers");
        assert!(error.to_string().contains("agent unlink opencode"));
        let error = resolve_main_provider_filter(Some(&[]), Some(&existing), account_source, RouteMode::Route)
          .expect_err("explicit relink must restore legacy provider state first");
        assert!(error.to_string().contains("agent unlink opencode"));
      }
    }
  }

  #[test]
  fn main_account_provider_filter_scopes_the_materialized_profile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("opencode.toml");
    let provider_filter = vec![tokn_core::provider::ID_DEEPSEEK.to_string()];
    upsert_agent_and_profiles_with_source(
      &path,
      &AgentProfileWrite {
        agent: &AgentId::Opencode,
        profile: Some("opencode"),
        previous_profile: None,
        mode: RouteMode::Route,
        account_source: AgentAccountSource::Main,
        provider: None,
        provider_filter: Some(&provider_filter),
        materialized_provider_ids: &provider_filter,
        accounts: &[],
        provider_routes: &[],
        default_provider_id: None,
        fallback_provider_id: tokn_core::provider::ID_OPENAI,
      },
    )
    .unwrap();

    let (cfg, _) = Config::load(Some(&path)).unwrap();
    assert_eq!(
      cfg.agents["opencode"].provider_filter.as_deref(),
      Some(provider_filter.as_slice())
    );
    assert_eq!(
      cfg.profiles["opencode"].providers.as_deref(),
      Some(provider_filter.as_slice())
    );
  }

  #[test]
  fn main_account_auto_discovery_persists_its_materialized_provider_scope() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("opencode.toml");
    let materialized = vec![
      tokn_core::provider::ID_DEEPSEEK.to_string(),
      tokn_core::provider::ID_OPENAI.to_string(),
    ];
    upsert_agent_and_profiles_with_source(
      &path,
      &AgentProfileWrite {
        agent: &AgentId::Opencode,
        profile: Some("opencode"),
        previous_profile: None,
        mode: RouteMode::Route,
        account_source: AgentAccountSource::Main,
        provider: None,
        provider_filter: None,
        materialized_provider_ids: &materialized,
        accounts: &[],
        provider_routes: &[],
        default_provider_id: None,
        fallback_provider_id: tokn_core::provider::ID_OPENAI,
      },
    )
    .unwrap();

    let (cfg, _) = Config::load(Some(&path)).unwrap();
    assert_eq!(cfg.agents["opencode"].provider_filter, None);
    assert_eq!(
      cfg.profiles["opencode"].providers.as_deref(),
      Some(materialized.as_slice())
    );
    assert_eq!(
      previous_materialized_provider_ids(&cfg, Some("opencode"), Some(RouteMode::Route)),
      Some(materialized)
    );
  }

  #[test]
  fn config_edit_profile_rename_removes_the_previous_generated_base_and_children() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("opencode.toml");
    std::fs::write(
      &path,
      r#"
[agents.opencode]
mode = "route"
profile = "renamed"
account_source = "main"
sync = true

[profiles.old]
mode = "switch"
agent_id = "opencode"
default_provider_id = "openai"
providers = ["openai"]

[profiles.old-openai]
mode = "switch"
agent_id = "opencode"
default_provider_id = "openai"
providers = ["openai"]
accounts = ["opencode-openai"]
"#,
    )
    .unwrap();
    let providers = vec!["openai".to_string()];

    upsert_agent_and_profiles_with_source(
      &path,
      &AgentProfileWrite {
        agent: &AgentId::Opencode,
        profile: Some("renamed"),
        previous_profile: Some("old"),
        mode: RouteMode::Route,
        account_source: AgentAccountSource::Main,
        provider: None,
        provider_filter: None,
        materialized_provider_ids: &providers,
        accounts: &[],
        provider_routes: &[],
        default_provider_id: None,
        fallback_provider_id: tokn_core::provider::ID_OPENAI,
      },
    )
    .unwrap();

    let (cfg, _) = Config::load(Some(&path)).unwrap();
    assert_eq!(cfg.agents["opencode"].profile.as_deref(), Some("renamed"));
    assert!(cfg.profiles.contains_key("renamed"));
    assert!(!cfg.profiles.contains_key("old"));
    assert!(!cfg.profiles.contains_key("old-openai"));
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
        provider_filter: None,
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
  fn codex_cli_rejects_exact_mode_before_reading_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nport = 4141\n").unwrap();

    let error = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::CodexCli,
        profile: None,
        mode: Some(RouteMode::Exact),
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path),
        agent_home: Some(dir.path().join("home")),
      },
      gateway_auth_path.clone(),
    )
    .unwrap_err();

    assert!(error
      .to_string()
      .contains("does not encode provider-qualified model ids"));
    assert!(!gateway_auth_path.exists());
  }

  #[test]
  fn generated_agent_clients_reject_managed_modes_with_api_key_enforcement() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let agent_home = dir.path().join("home");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[api_key]\nenabled = true\n").unwrap();
    std::fs::write(&gateway_auth_path, "opaque gateway credential data").unwrap();
    std::fs::write(&opencode_auth_path, "opaque local credential data").unwrap();

    for mode in [
      RouteMode::Route,
      RouteMode::Fuzzy,
      RouteMode::Exact,
      RouteMode::Switch,
      RouteMode::Passthrough,
    ] {
      let error = plan_reconcile_with_gateway_auth_path(
        ReconcileRequest {
          agent: AgentId::Opencode,
          profile: None,
          mode: Some(mode),
          account_source: Some(AgentAccountSource::Main),
          default_provider_id: mode.is_verbatim().then(|| tokn_core::provider::ID_OPENAI.into()),
          provider_filter: None,
          gateway_config_path: Some(gateway_config_path.clone()),
          agent_home: Some(agent_home.clone()),
        },
        gateway_auth_path.clone(),
      )
      .unwrap_err();

      assert!(error.to_string().contains("[api_key].enabled = true"));
      assert!(error.to_string().contains("agent credentials"));
    }
    assert_eq!(
      std::fs::read_to_string(&gateway_auth_path).unwrap(),
      "opaque gateway credential data"
    );
    assert_eq!(
      std::fs::read_to_string(&opencode_auth_path).unwrap(),
      "opaque local credential data"
    );
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
        provider_filter: None,
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
        provider_filter: None,
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
        provider_filter: None,
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
    let mut store = AuthStore::load(Some(&gateway_auth_path), Some(&gateway_config_path)).unwrap();
    let mut account = sample_account("main-openai", tokn_core::provider::ID_OPENAI);
    account.api_key = Some(tokn_core::util::secret::Secret::new("sk-main-openai".into()));
    store.upsert(account);
    store.save().unwrap();

    let plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Route),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: None,
        provider_filter: None,
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
        provider_filter: None,
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
        provider_filter: None,
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
        provider_filter: None,
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
        provider_filter: None,
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
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    let original_backup_path = dir.path().join("opencode.json.before-v1");
    let first_manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    let second_manifest_path = dir.path().join("20260604T153013Z-opencode.json");
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
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
      &opencode_auth_path,
      serde_json::json!({
        "openai": {
          "type": "api",
          "key": "sk-legacy"
        }
      })
      .to_string(),
    )
    .unwrap();
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
          applied_sha256: None,
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
        provider_filter: None,
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
    assert_eq!(
      linked["provider"]["tokn-router"]["options"]["baseURL"],
      "http://127.0.0.1:4141/opencode/v1"
    );
    assert!(linked["provider"]["tokn-router"]["models"].is_object());

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(second_manifest_path.display().to_string()),
    })
    .unwrap();

    assert_eq!(std::fs::read_to_string(opencode_config_path).unwrap(), original);
    assert!(!first_manifest_path.exists());
    assert!(!second_manifest_path.exists());
    assert!(
      manifest::read_manifest(&manifest::inactive_manifest_path(&first_manifest_path).unwrap())
        .unwrap()
        .unlinked
    );
    assert!(
      manifest::read_manifest(&manifest::inactive_manifest_path(&second_manifest_path).unwrap())
        .unwrap()
        .unlinked
    );
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
      RouteMode::Switch,
      &[account],
      &routes,
      tokn_core::provider::ID_OPENAI,
    )
    .unwrap_err();

    assert!(error.to_string().contains("does not match the route owned by opencode"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
  }

  #[test]
  fn provider_route_profiles_reject_same_owner_with_different_allowlists() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
      "opencode-openai".into(),
      tokn_config::ProfileConfig {
        mode: Some(RouteMode::Switch),
        agent_id: Some(AgentId::Opencode),
        default_provider_id: Some(tokn_core::provider::ID_OPENAI.into()),
        providers: Some(vec!["anthropic".into()]),
        accounts: Some(vec!["opencode-openai".into()]),
        model_families: None,
      },
    );
    let routes = [ProviderRoute {
      source_provider_id: "openai".into(),
      gateway_provider_id: tokn_core::provider::ID_OPENAI.into(),
      account_id: "opencode-openai".into(),
      profile: "opencode-openai".into(),
      base_url: "http://127.0.0.1:4141/opencode-openai/v1".into(),
      transfer_source_auth: true,
    }];

    let error = validate_provider_route_profiles(&cfg, &AgentId::Opencode, Some("opencode"), &routes).unwrap_err();
    assert!(error.to_string().contains("does not match the route owned by opencode"));
  }

  #[test]
  fn fresh_binding_rejects_a_same_owner_base_profile_collision() {
    let mut cfg = Config::default();
    cfg.profiles.insert(
      "shared".into(),
      tokn_config::ProfileConfig {
        agent_id: Some(AgentId::Opencode),
        ..Default::default()
      },
    );

    let error = validate_binding_profile(&cfg, &AgentId::Opencode, Some("shared"), None).unwrap_err();
    assert!(error.to_string().contains("profile 'shared' already exists"));

    let binding = tokn_config::AgentConfig {
      profile: Some("shared".into()),
      ..Default::default()
    };
    validate_binding_profile(&cfg, &AgentId::Opencode, Some("shared"), Some(&binding)).unwrap();
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
  fn raw_mode_without_provider_routes_uses_only_the_base_profile() {
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
      cfg.profiles["opencode"].accounts.as_deref(),
      Some(&["opencode-openai".to_string(), "opencode-codex".to_string()][..])
    );
    assert_eq!(
      cfg
        .profiles
        .keys()
        .filter(|profile| profile.starts_with("opencode-"))
        .count(),
      0
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
    let source_auth_path = dir.path().join("source-auth.json");
    let manifest_path = dir.path().join("manifest.json");
    let mut account = sample_account("opencode-openai", tokn_core::provider::ID_OPENAI);
    account.api_key = Some(tokn_core::util::secret::Secret::new("sk-test".to_string()));
    let account = mark_gateway_owned(annotate_imported_account(
      account,
      AgentId::Opencode,
      &source_auth_path,
      "auth.openai",
      "20260604T153012Z",
    ));
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
      source_auth_path: Some(source_auth_path),
      source_auth_snapshot: Some(FileSnapshot::Missing),
      agent_auth_path: Some(dir.path().join("agent/auth.json")),
      binding_profile: Some("opencode".into()),
      previous_materialized_profile: None,
      binding_mode: RouteMode::Route,
      account_source: AgentAccountSource::Agent,
      provider: None,
      default_provider_id: None,
      provider_filter: None,
      published_provider_ids: Vec::new(),
      providers_without_models: Vec::new(),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      credential_routes: Vec::new(),
      imported_accounts: vec![account],
      provider_routes: Vec::new(),
      edits: vec![PlannedEdit::new(
        agent_config_path.clone(),
        EditKind::Json(serde_json::json!({"provider": "tokn-router"})),
        true,
        None,
      )],
      previous_manifest: None,
      opencode_preflight: None,
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
    let manifest: MigrationManifest = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
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
      gateway_config_fragment_path: gateway_config_fragment_path.clone(),
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
      previous_materialized_profile: None,
      binding_mode: RouteMode::Route,
      account_source: AgentAccountSource::Agent,
      provider: None,
      default_provider_id: None,
      provider_filter: None,
      published_provider_ids: Vec::new(),
      providers_without_models: Vec::new(),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      credential_routes: Vec::new(),
      imported_accounts: vec![account],
      provider_routes: Vec::new(),
      edits: vec![PlannedEdit::new(
        edit_path.clone(),
        EditKind::Json(serde_json::json!({"provider": "tokn-router"})),
        true,
        None,
      )],
      previous_manifest: None,
      opencode_preflight: None,
    };

    let err = apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap_err();

    assert!(format!("{err:#}").contains("creating"));
    let manifest: MigrationManifest = serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(!manifest.completed);
    assert!(manifest.files.iter().any(|file| file.original == edit_path));
    assert!(manifest
      .files
      .iter()
      .find(|file| file.original == gateway_config_fragment_path)
      .is_some_and(|file| file.applied_sha256.is_some()));

    std::fs::write(&gateway_config_fragment_path, "[user_correction]\nenabled = true\n").unwrap();
    let unlink_error = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap_err();

    assert!(unlink_error.to_string().contains("changed after the link or sync"));
    assert_eq!(
      std::fs::read_to_string(gateway_config_fragment_path).unwrap(),
      "[user_correction]\nenabled = true\n"
    );
  }

  #[test]
  fn final_checkpoint_validation_allows_runtime_auth_refresh_only() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_auth = dir.path().join("gateway/auth.yaml");
    let source_auth = dir.path().join("opencode/auth.json");
    let auth_shard = save_agent_shard_accounts(
      &gateway_auth,
      &source_auth,
      &[("opencode-openai", tokn_core::provider::ID_OPENAI, true)],
    );
    let config_fragment = dir.path().join("config.d/opencode.toml");
    std::fs::create_dir_all(config_fragment.parent().unwrap()).unwrap();
    std::fs::write(&config_fragment, "[agents.opencode]\nsync = true\n").unwrap();
    let initial_auth = std::fs::read(&auth_shard).unwrap();
    let migration = MigrationManifest {
      version: manifest::CURRENT_VERSION,
      completed: false,
      agent: AgentId::Opencode,
      timestamp: "20260729T000000Z".into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: Some(gateway_auth.clone()),
      gateway_auth_shard_path: Some(auth_shard.clone()),
      agent_auth_path: Some(source_auth),
      provider_routes: vec![ProviderRoute {
        source_provider_id: tokn_core::provider::ID_OPENAI.into(),
        gateway_provider_id: tokn_core::provider::ID_OPENAI.into(),
        account_id: "opencode-openai".into(),
        profile: "opencode-openai".into(),
        base_url: "http://127.0.0.1:4141/opencode-openai/v1".into(),
        transfer_source_auth: true,
      }],
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: false,
      imported_account_ids: vec!["opencode-openai".into()],
      files: vec![
        FileBackup {
          original: auth_shard.clone(),
          backup: None,
          existed: false,
          created_by_migration: true,
          applied_sha256: Some(manifest::sha256(&initial_auth)),
        },
        FileBackup {
          original: config_fragment.clone(),
          backup: None,
          existed: false,
          created_by_migration: true,
          applied_sha256: Some(manifest::sha256(b"[agents.opencode]\nsync = true\n")),
        },
      ],
    };

    let mut store = AuthStore::load(Some(&gateway_auth), None).unwrap();
    store.get_mut("opencode-openai").unwrap().label = Some("refreshed".into());
    store.save().unwrap();
    let refreshed_auth = std::fs::read(&auth_shard).unwrap();
    validate_reconcile_checkpoints(&migration).unwrap();

    std::fs::remove_file(&auth_shard).unwrap();
    let error = validate_reconcile_checkpoints(&migration).unwrap_err();
    assert!(error.to_string().contains("no longer contains transferred account"));

    std::fs::write(&auth_shard, b"not: [valid").unwrap();
    let error = validate_reconcile_checkpoints(&migration).unwrap_err();
    assert!(format!("{error:#}").contains("parsing"));

    std::fs::write(&auth_shard, refreshed_auth).unwrap();
    std::fs::write(&config_fragment, "[user_edit]\nenabled = true\n").unwrap();
    let error = validate_reconcile_checkpoints(&migration).unwrap_err();
    assert!(error.to_string().contains("changed after it was written"));
  }

  #[test]
  fn final_checkpoint_rejects_non_restorable_transferred_route_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_auth = dir.path().join("gateway/auth.yaml");
    let source_auth = dir.path().join("opencode/auth.json");
    let auth_shard = save_agent_shard_accounts(
      &gateway_auth,
      &source_auth,
      &[("opencode-openai", tokn_core::provider::ID_OPENAI, true)],
    );
    let route = ProviderRoute {
      source_provider_id: tokn_core::provider::ID_OPENAI.into(),
      gateway_provider_id: tokn_core::provider::ID_OPENAI.into(),
      account_id: "opencode-openai".into(),
      profile: "opencode-openai".into(),
      base_url: "http://127.0.0.1:4141/opencode-openai/v1".into(),
      transfer_source_auth: true,
    };
    let migration = MigrationManifest {
      version: manifest::CURRENT_VERSION,
      completed: false,
      agent: AgentId::Opencode,
      timestamp: "20260729T000000Z".into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: Some(gateway_auth.clone()),
      gateway_auth_shard_path: Some(auth_shard.clone()),
      agent_auth_path: Some(source_auth),
      provider_routes: vec![route],
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: false,
      imported_account_ids: vec!["opencode-openai".into()],
      files: Vec::new(),
    };

    let store = AuthStore::load(Some(&gateway_auth), None).unwrap();
    validate_transferred_route_accounts(&migration, &store, &auth_shard).unwrap();

    let mut missing_shard = migration.clone();
    missing_shard.gateway_auth_shard_path = None;
    let error = validate_reconcile_checkpoints(&missing_shard).unwrap_err();
    assert!(error.to_string().contains("without a managed auth shard"));

    let mut missing_import = migration.clone();
    missing_import.imported_account_ids.clear();
    let error = validate_transferred_route_accounts(&missing_import, &store, &auth_shard).unwrap_err();
    assert!(error.to_string().contains("not recorded as imported"));

    let mut wrong_gateway_provider = migration.clone();
    wrong_gateway_provider.provider_routes[0].gateway_provider_id = tokn_core::provider::ID_DEEPSEEK.into();
    let error = validate_transferred_route_accounts(&wrong_gateway_provider, &store, &auth_shard).unwrap_err();
    assert!(error.to_string().contains("but its route requires 'deepseek'"));

    let mut wrong_source_provider = migration.clone();
    wrong_source_provider.provider_routes[0].source_provider_id = tokn_core::provider::ID_DEEPSEEK.into();
    let error = validate_transferred_route_accounts(&wrong_source_provider, &store, &auth_shard).unwrap_err();
    assert!(error.to_string().contains("came from source provider 'openai'"));

    let mut not_gateway_owned = AuthStore::load(Some(&gateway_auth), None).unwrap();
    not_gateway_owned
      .get_mut("opencode-openai")
      .unwrap()
      .settings
      .get_mut("import")
      .and_then(toml::Value::as_table_mut)
      .unwrap()
      .remove("ownership");
    let error = validate_transferred_route_accounts(&migration, &not_gateway_owned, &auth_shard).unwrap_err();
    assert!(error.to_string().contains("no longer strictly gateway-owned"));

    let mut disabled = AuthStore::load(Some(&gateway_auth), None).unwrap();
    disabled.get_mut("opencode-openai").unwrap().enabled = false;
    let error = validate_transferred_route_accounts(&migration, &disabled, &auth_shard).unwrap_err();
    assert!(error.to_string().contains("is disabled"));

    let mut missing_source = AuthStore::load(Some(&gateway_auth), None).unwrap();
    missing_source
      .get_mut("opencode-openai")
      .unwrap()
      .settings
      .get_mut("import")
      .and_then(toml::Value::as_table_mut)
      .unwrap()
      .remove("source_provider");
    let error = validate_transferred_route_accounts(&migration, &missing_source, &auth_shard).unwrap_err();
    assert!(error.to_string().contains("missing its source provider metadata"));

    let mut missing_credential = AuthStore::load(Some(&gateway_auth), None).unwrap();
    missing_credential.get_mut("opencode-openai").unwrap().api_key = None;
    let error = validate_transferred_route_accounts(&migration, &missing_credential, &auth_shard).unwrap_err();
    assert!(error
      .to_string()
      .contains("no exportable API key or OAuth refresh token"));
    assert!(!error.to_string().contains("sk-opencode-openai"));
  }

  #[test]
  fn exportable_credentials_match_the_opencode_restore_contract() {
    let mut api = sample_account("opencode-openai", tokn_core::provider::ID_OPENAI);
    api.api_key = Some(tokn_core::util::secret::Secret::new("sk-api".into()));
    validate_exportable_transferred_credentials(&AgentId::Opencode, tokn_core::provider::ID_OPENAI, &api).unwrap();

    api.api_key = Some(tokn_core::util::secret::Secret::new("   ".into()));
    let error = validate_exportable_transferred_credentials(&AgentId::Opencode, tokn_core::provider::ID_OPENAI, &api)
      .unwrap_err();
    assert!(error.to_string().contains("empty API key"));
    assert!(!error.to_string().contains("sk-api"));

    let mut copilot = sample_account("opencode-github-copilot", tokn_core::provider::ID_GITHUB_COPILOT);
    copilot.refresh_token = Some(tokn_core::util::secret::Secret::new("ghu-refresh".into()));
    validate_exportable_transferred_credentials(&AgentId::Opencode, tokn_core::provider::ID_GITHUB_COPILOT, &copilot)
      .unwrap();

    let mut codex = sample_account("opencode-codex", tokn_core::provider::ID_CODEX);
    codex.refresh_token = Some(tokn_core::util::secret::Secret::new("rt-secret-value".into()));
    codex.access_token = Some(tokn_core::util::secret::Secret::new("at-secret-value".into()));
    codex.access_token_expires_at = Some(1);
    validate_exportable_transferred_credentials(&AgentId::Opencode, tokn_core::provider::ID_OPENAI, &codex).unwrap();

    codex.access_token = None;
    let error = validate_exportable_transferred_credentials(&AgentId::Opencode, tokn_core::provider::ID_OPENAI, &codex)
      .unwrap_err();
    assert!(error.to_string().contains("no exportable OAuth access token"));
    codex.access_token = Some(tokn_core::util::secret::Secret::new("at-secret-value".into()));

    codex.access_token_expires_at = None;
    let error = validate_exportable_transferred_credentials(&AgentId::Opencode, tokn_core::provider::ID_OPENAI, &codex)
      .unwrap_err();
    assert!(error.to_string().contains("no OAuth access-token expiry"));

    codex.access_token_expires_at = Some(-1);
    let error = validate_exportable_transferred_credentials(&AgentId::Opencode, tokn_core::provider::ID_OPENAI, &codex)
      .unwrap_err();
    assert!(error.to_string().contains("negative OAuth access-token expiry"));
    assert!(!error.to_string().contains("rt-secret-value"));
    assert!(!error.to_string().contains("at-secret-value"));
  }

  #[test]
  fn checkpoint_records_the_writer_post_image_without_adopting_a_later_edit() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    let managed_path = dir.path().join("opencode.json");
    std::fs::write(&managed_path, b"user edit after writer returned").unwrap();
    let mut migration = MigrationManifest {
      version: manifest::CURRENT_VERSION,
      completed: false,
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
        original: managed_path.clone(),
        backup: None,
        existed: false,
        created_by_migration: true,
        applied_sha256: None,
      }],
    };
    let writer_digest = manifest::sha256(b"exact bytes written by migration");

    let error = checkpoint_manifest_file(
      &manifest_path,
      &mut migration,
      &managed_path,
      writer_digest.clone(),
      true,
    )
    .unwrap_err();

    assert!(error.to_string().contains("changed after it was written"));
    let checkpoint = manifest::read_manifest(&manifest_path).unwrap();
    assert_eq!(
      checkpoint.files[0].applied_sha256.as_deref(),
      Some(writer_digest.as_str())
    );
  }

  #[test]
  fn unlink_restores_credentials_after_a_post_strip_apply_failure() {
    let dir = tempfile::tempdir().unwrap();
    let (_gateway_auth, shard_path, opencode_auth_path, manifest_path) =
      create_failed_post_strip_opencode_link(dir.path());

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap();

    let restored: Value = serde_json::from_str(&std::fs::read_to_string(opencode_auth_path).unwrap()).unwrap();
    assert_eq!(restored["openai"]["key"], "sk-post-strip");
    assert!(!shard_path.exists());
    let manifest = manifest::read_manifest(&manifest::inactive_manifest_path(&manifest_path).unwrap()).unwrap();
    assert!(manifest.credentials_handoff_complete);
    assert!(manifest.unlinked);
  }

  #[test]
  fn unlink_preserves_a_post_strip_shard_when_route_metadata_is_not_restorable() {
    let dir = tempfile::tempdir().unwrap();
    let (gateway_auth, shard_path, opencode_auth_path, manifest_path) =
      create_failed_post_strip_opencode_link(dir.path());
    let mut store = AuthStore::load(Some(&gateway_auth), None).unwrap();
    store
      .get_mut("opencode-openai")
      .unwrap()
      .settings
      .get_mut("import")
      .and_then(toml::Value::as_table_mut)
      .unwrap()
      .insert("source_provider".into(), toml::Value::String("deepseek".into()));
    store.save().unwrap();

    let error = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap_err();

    assert!(error.to_string().contains("came from source provider 'deepseek'"));
    assert!(shard_path.exists());
    assert!(
      serde_json::from_str::<Value>(&std::fs::read_to_string(opencode_auth_path).unwrap())
        .unwrap()
        .get("openai")
        .is_none()
    );
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert!(!manifest.credentials_handoff_complete);
    assert!(!manifest.unlinked);
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
        provider_filter: None,
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

    // Runtime credential refresh legitimately changes the managed shard
    // after its applied digest was recorded. Unlink must export that current
    // value instead of treating it as conflicting config drift.
    let mut store = AuthStore::load(Some(&gateway_auth_path), None).unwrap();
    store.get_mut("opencode-openai").unwrap().api_key = Some(tokn_core::util::secret::Secret::new("sk-rotated".into()));
    store.save().unwrap();

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
      serde_json::from_str::<Value>(&std::fs::read_to_string(&opencode_auth_path).unwrap()).unwrap()["openai"]["key"],
      "sk-rotated"
    );
  }

  #[test]
  fn unlink_rejects_post_link_edits_to_existing_opencode_config_before_restoring_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("opencode-link.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    let opencode_auth_path = agent_home.join(".local/share/opencode/auth.json");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_config_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(opencode_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nhost = \"127.0.0.1\"\nport = 4141\n").unwrap();
    std::fs::write(
      &opencode_config_path,
      "{\n  // Existing user config.\n  \"mcp\": {}\n}\n",
    )
    .unwrap();
    std::fs::write(
      &opencode_auth_path,
      serde_json::to_vec_pretty(&serde_json::json!({
        "openai": {"type": "api", "key": "sk-opencode"}
      }))
      .unwrap(),
    )
    .unwrap();

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: None,
        account_source: Some(AgentAccountSource::Agent),
        default_provider_id: None,
        provider_filter: None,
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path.clone(),
    )
    .unwrap();
    plan.timestamp = "20260729T040101Z".into();
    let gateway_auth_shard_path = plan.gateway_auth_shard_path.clone().unwrap();
    apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap();

    let linked_auth = std::fs::read(&opencode_auth_path).unwrap();
    assert!(serde_json::from_slice::<Value>(&linked_auth)
      .unwrap()
      .get("openai")
      .is_none());
    let linked_shard = std::fs::read(&gateway_auth_shard_path).unwrap();
    let fragment_path = tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "opencode");
    let linked_fragment = std::fs::read(&fragment_path).unwrap();
    let mut edited = crate::jsonc::read_jsonc(&opencode_config_path).unwrap();
    edited["theme"] = Value::String("user-theme".into());
    std::fs::write(&opencode_config_path, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    let edited_config = std::fs::read(&opencode_config_path).unwrap();

    let error = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
      diagnostic_starts_with_path(&message, &opencode_config_path, " changed after the link or sync"),
      "{message}"
    );
    assert!(message.contains("rollback would overwrite"));
    assert_eq!(std::fs::read(&opencode_config_path).unwrap(), edited_config);
    assert_eq!(std::fs::read(&opencode_auth_path).unwrap(), linked_auth);
    assert_eq!(std::fs::read(&gateway_auth_shard_path).unwrap(), linked_shard);
    assert_eq!(std::fs::read(&fragment_path).unwrap(), linked_fragment);
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert!(!manifest.credentials_handoff_complete);
    assert!(!manifest.unlinked);
  }

  #[test]
  fn unlink_rejects_post_link_edits_to_a_link_created_opencode_config() {
    let dir = tempfile::tempdir().unwrap();
    let agent_home = dir.path().join("home");
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let manifest_path = dir.path().join("opencode-main-link.json");
    let opencode_config_path = agent_home.join(".config/opencode/opencode.jsonc");
    std::fs::create_dir_all(gateway_config_path.parent().unwrap()).unwrap();
    std::fs::write(&gateway_config_path, "[server]\nhost = \"127.0.0.1\"\nport = 4141\n").unwrap();
    save_main_accounts(
      &gateway_auth_path,
      &gateway_config_path,
      &[("main-openai", tokn_core::provider::ID_OPENAI)],
    );

    let mut plan = plan_reconcile_with_gateway_auth_path(
      ReconcileRequest {
        agent: AgentId::Opencode,
        profile: None,
        mode: Some(RouteMode::Route),
        account_source: Some(AgentAccountSource::Main),
        default_provider_id: None,
        provider_filter: Some(Vec::new()),
        gateway_config_path: Some(gateway_config_path.clone()),
        agent_home: Some(agent_home),
      },
      gateway_auth_path,
    )
    .unwrap();
    plan.timestamp = "20260729T040102Z".into();
    apply_reconcile_to_manifest_path(plan, manifest_path.clone()).unwrap();

    assert!(opencode_config_path.exists());
    let fragment_path = tokn_config::paths::agent_config_fragment_path(&gateway_config_path, "opencode");
    let linked_fragment = std::fs::read(&fragment_path).unwrap();
    let mut edited = crate::jsonc::read_jsonc(&opencode_config_path).unwrap();
    edited["theme"] = Value::String("user-theme".into());
    std::fs::write(&opencode_config_path, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    let edited_config = std::fs::read(&opencode_config_path).unwrap();

    let error = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(
      diagnostic_starts_with_path(&message, &opencode_config_path, " changed after the link or sync"),
      "{message}"
    );
    assert!(message.contains("rollback would overwrite"));
    assert_eq!(std::fs::read(&opencode_config_path).unwrap(), edited_config);
    assert_eq!(std::fs::read(&fragment_path).unwrap(), linked_fragment);
    let manifest = manifest::read_manifest(&manifest_path).unwrap();
    assert!(manifest.files.iter().all(|file| file.applied_sha256.is_some()));
    assert!(!manifest.unlinked);
  }

  #[test]
  fn unlink_preflights_simulated_ancestor_post_images_before_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let original_backup_path = dir.path().join("opencode.json.original");
    let intervening_backup_path = dir.path().join("opencode.json.intervening");
    let first_manifest_path = dir.path().join("20260729T040101Z-opencode.json");
    let second_manifest_path = dir.path().join("20260729T040102Z-opencode.json");
    std::fs::write(&config_path, b"second applied image").unwrap();
    std::fs::write(&original_backup_path, b"original image").unwrap();
    std::fs::write(&intervening_backup_path, b"user edit between syncs").unwrap();
    let first = MigrationManifest {
      version: 5,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260729T040101Z".into(),
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
        original: config_path.clone(),
        backup: Some(original_backup_path),
        existed: true,
        created_by_migration: false,
        applied_sha256: Some(manifest::sha256(b"first applied image")),
      }],
    };
    let second = MigrationManifest {
      timestamp: "20260729T040102Z".into(),
      previous_manifest: Some(first_manifest_path.clone()),
      files: vec![FileBackup {
        original: config_path.clone(),
        backup: Some(intervening_backup_path),
        existed: true,
        created_by_migration: false,
        applied_sha256: Some(manifest::sha256(b"second applied image")),
      }],
      ..first.clone()
    };
    manifest::write_manifest(&first_manifest_path, &first).unwrap();
    manifest::write_manifest(&second_manifest_path, &second).unwrap();

    let error = unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(second_manifest_path.display().to_string()),
    })
    .unwrap_err();

    assert!(error.to_string().contains(&first_manifest_path.display().to_string()));
    assert_eq!(std::fs::read(&config_path).unwrap(), b"second applied image");
    assert!(!manifest::read_manifest(&first_manifest_path).unwrap().unlinked);
    assert!(!manifest::read_manifest(&second_manifest_path).unwrap().unlinked);
  }

  #[test]
  fn successor_cannot_skip_an_older_pending_opencode_credential_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("gateway/config.toml");
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let pending_manifest_path = dir.path().join("pending-opencode.json");
    let previous_manifest_path = dir.path().join("previous-opencode.json");
    let pending_manifest = MigrationManifest {
      version: 4,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260714T020101Z".into(),
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
    };
    manifest::write_manifest(&pending_manifest_path, &pending_manifest).unwrap();
    manifest::write_manifest(
      &previous_manifest_path,
      &MigrationManifest {
        timestamp: "20260714T020102Z".into(),
        agent_auth_path: None,
        previous_manifest: Some(pending_manifest_path.clone()),
        credentials_handoff_complete: true,
        ..pending_manifest
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
      previous_materialized_profile: None,
      binding_mode: RouteMode::Route,
      account_source: AgentAccountSource::Agent,
      provider: None,
      default_provider_id: None,
      provider_filter: None,
      published_provider_ids: Vec::new(),
      providers_without_models: Vec::new(),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      credential_routes: Vec::new(),
      imported_accounts: Vec::new(),
      provider_routes: Vec::new(),
      edits: Vec::new(),
      previous_manifest: Some(previous_manifest_path),
      opencode_preflight: None,
    };

    let error = reject_successor_without_pending_credentials(&plan).unwrap_err();

    assert!(error.to_string().contains("pending credential handoff"));
    assert!(error.to_string().contains(&pending_manifest_path.display().to_string()));
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
      provider_filter: None,
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
    assert_eq!(linked_config["model"], "tokn-router/gpt-5");
    assert_eq!(
      linked_config["provider"]["tokn-router"]["options"]["baseURL"],
      "http://127.0.0.1:4141/opencode/v1"
    );
    assert!(linked_config["provider"]["tokn-router"]["models"]["gpt-5"].is_object());
    assert!(linked_config["provider"].get("openai").is_none());
    assert!(linked_config["provider"].get("github-copilot").is_none());
    assert!(std::fs::read_to_string(&opencode_config_path)
      .unwrap()
      .contains("Preserve the user's global model choice"));

    let (linked_gateway_config, _) = Config::load(Some(&gateway_config_path)).unwrap();
    assert!(linked_gateway_config.profiles.contains_key("opencode-user"));
    assert!(!linked_gateway_config.profiles.contains_key("opencode-openai"));
    assert!(!linked_gateway_config.profiles.contains_key("opencode-github-copilot"));
    assert_eq!(
      linked_gateway_config.profiles["opencode"].accounts.as_deref(),
      Some(&["opencode-github-copilot".to_string(), "opencode-openai".to_string()][..])
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
    assert!(second_plan.agent_auth_path.is_none());
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
    assert!(second_manifest.credentials_handoff_complete);

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
    assert!(
      manifest::read_manifest(&manifest::inactive_manifest_path(&first_manifest_path).unwrap())
        .unwrap()
        .unlinked
    );
    let second_manifest =
      manifest::read_manifest(&manifest::inactive_manifest_path(&second_manifest_path).unwrap()).unwrap();
    assert!(second_manifest.unlinked);
    assert!(second_manifest.credentials_handoff_complete);
  }

  #[test]
  fn unlink_restores_mixed_manifest_chain_to_each_transfer_data_root() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let first_auth_path = dir.path().join("xdg-data-first/opencode/auth.json");
    let second_auth_path = dir.path().join("xdg-data-second/opencode/auth.json");
    let first_manifest_path = dir.path().join("manifests-first/20260604T153012Z-opencode.json");
    let second_manifest_path = dir.path().join("manifests-second/20260604T153013Z-opencode.json");
    std::fs::create_dir_all(first_auth_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(second_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&first_auth_path, "{}").unwrap();
    std::fs::write(&second_auth_path, "{}").unwrap();
    let shard_path = save_agent_shard_accounts(
      &gateway_auth_path,
      &first_auth_path,
      &[
        ("opencode-openai", tokn_core::provider::ID_OPENAI, true),
        ("opencode-deepseek", tokn_core::provider::ID_DEEPSEEK, true),
      ],
    );
    let route = |source_provider_id: &str, account_id: &str, transfer_source_auth: bool| ProviderRoute {
      source_provider_id: source_provider_id.into(),
      gateway_provider_id: source_provider_id.into(),
      account_id: account_id.into(),
      profile: format!("opencode-{source_provider_id}"),
      base_url: format!("http://127.0.0.1:4141/opencode-{source_provider_id}/v1"),
      transfer_source_auth,
    };
    let manifest = |version: u32,
                    timestamp: &str,
                    agent_auth_path: PathBuf,
                    provider_routes: Vec<ProviderRoute>,
                    imported_account_ids: Vec<String>,
                    previous_manifest: Option<PathBuf>| MigrationManifest {
      version,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: timestamp.into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: Some(gateway_auth_path.clone()),
      gateway_auth_shard_path: Some(shard_path.clone()),
      agent_auth_path: Some(agent_auth_path),
      provider_routes,
      previous_manifest,
      unlinked: false,
      credentials_handoff_complete: false,
      imported_account_ids,
      files: Vec::new(),
    };
    manifest::write_manifest(
      &first_manifest_path,
      &manifest(
        1,
        "20260604T153012Z",
        first_auth_path.clone(),
        Vec::new(),
        vec!["opencode-openai".into()],
        None,
      ),
    )
    .unwrap();
    manifest::write_manifest(
      &second_manifest_path,
      &manifest(
        4,
        "20260604T153013Z",
        second_auth_path.clone(),
        vec![
          route("openai", "opencode-openai", false),
          route("deepseek", "opencode-deepseek", true),
        ],
        vec!["opencode-deepseek".into(), "opencode-openai".into()],
        Some(first_manifest_path.clone()),
      ),
    )
    .unwrap();

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(second_manifest_path.display().to_string()),
    })
    .unwrap();

    let first_auth: Value = serde_json::from_str(&std::fs::read_to_string(first_auth_path).unwrap()).unwrap();
    assert_eq!(first_auth["openai"]["key"], "sk-opencode-openai");
    assert!(first_auth.get("deepseek").is_none());
    let second_auth: Value = serde_json::from_str(&std::fs::read_to_string(second_auth_path).unwrap()).unwrap();
    assert_eq!(second_auth["deepseek"]["key"], "sk-opencode-deepseek");
    assert!(second_auth.get("openai").is_none());
    assert!(
      manifest::read_manifest(&manifest::inactive_manifest_path(&first_manifest_path).unwrap())
        .unwrap()
        .credentials_handoff_complete
    );
    assert!(
      manifest::read_manifest(&manifest::inactive_manifest_path(&second_manifest_path).unwrap())
        .unwrap()
        .credentials_handoff_complete
    );
  }

  #[test]
  fn incomplete_successor_restores_available_ancestor_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_auth_path = dir.path().join("gateway/auth.yaml");
    let first_auth_path = dir.path().join("xdg-data-first/opencode/auth.json");
    let second_auth_path = dir.path().join("xdg-data-second/opencode/auth.json");
    let first_manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    let second_manifest_path = dir.path().join("20260604T153013Z-opencode.json");
    std::fs::create_dir_all(first_auth_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(second_auth_path.parent().unwrap()).unwrap();
    std::fs::write(&first_auth_path, "{}").unwrap();
    std::fs::write(
      &second_auth_path,
      serde_json::to_vec_pretty(&serde_json::json!({
        "deepseek": {"type": "api", "key": "sk-source-authoritative"}
      }))
      .unwrap(),
    )
    .unwrap();
    let shard_path = save_agent_shard_accounts(
      &gateway_auth_path,
      &first_auth_path,
      &[("opencode-openai", tokn_core::provider::ID_OPENAI, true)],
    );
    let route = |source_provider_id: &str, account_id: &str, transfer_source_auth: bool| ProviderRoute {
      source_provider_id: source_provider_id.into(),
      gateway_provider_id: source_provider_id.into(),
      account_id: account_id.into(),
      profile: format!("opencode-{source_provider_id}"),
      base_url: format!("http://127.0.0.1:4141/opencode-{source_provider_id}/v1"),
      transfer_source_auth,
    };
    let first_manifest = MigrationManifest {
      version: 4,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260604T153012Z".into(),
      profile: Some("opencode".into()),
      target_base_url: "http://127.0.0.1:4141/opencode/v1".into(),
      gateway_auth_path: Some(gateway_auth_path),
      gateway_auth_shard_path: Some(shard_path),
      agent_auth_path: Some(first_auth_path.clone()),
      provider_routes: vec![route("openai", "opencode-openai", true)],
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: false,
      imported_account_ids: vec!["opencode-openai".into()],
      files: Vec::new(),
    };
    let second_manifest = MigrationManifest {
      completed: false,
      timestamp: "20260604T153013Z".into(),
      agent_auth_path: Some(second_auth_path.clone()),
      provider_routes: vec![
        route("openai", "opencode-openai", false),
        route("deepseek", "opencode-deepseek", true),
      ],
      previous_manifest: Some(first_manifest_path.clone()),
      imported_account_ids: vec!["opencode-deepseek".into(), "opencode-openai".into()],
      ..first_manifest.clone()
    };
    manifest::write_manifest(&first_manifest_path, &first_manifest).unwrap();
    manifest::write_manifest(&second_manifest_path, &second_manifest).unwrap();

    unlink(UnlinkRequest {
      agent: AgentId::Opencode,
      backup_id: Some(second_manifest_path.display().to_string()),
    })
    .unwrap();

    let first_auth: Value = serde_json::from_str(&std::fs::read_to_string(first_auth_path).unwrap()).unwrap();
    assert_eq!(first_auth["openai"]["key"], "sk-opencode-openai");
    let second_auth: Value = serde_json::from_str(&std::fs::read_to_string(second_auth_path).unwrap()).unwrap();
    assert_eq!(second_auth["deepseek"]["key"], "sk-source-authoritative");
    assert!(second_auth.get("openai").is_none());
    for path in [&first_manifest_path, &second_manifest_path] {
      let path = manifest::inactive_manifest_path(path).unwrap();
      let restored = manifest::read_manifest(&path).unwrap();
      assert!(restored.credentials_handoff_complete);
      assert!(restored.unlinked);
    }
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
    assert!(
      manifest::read_manifest(&manifest::inactive_manifest_path(&manifest_path).unwrap())
        .unwrap()
        .unlinked
    );
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
        applied_sha256: None,
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
    let archived_manifest_path = manifest::inactive_manifest_path(&manifest_path).unwrap();
    assert_eq!(report.manifest_path, archived_manifest_path);
    assert!(!manifest_path.exists());
    assert!(manifest::read_manifest(&archived_manifest_path).unwrap().unlinked);
  }

  #[test]
  fn unlink_legacy_relative_manifest_requires_and_uses_explicit_root() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_root = dir.path().join("original-working-directory");
    let original = legacy_root.join("config.toml");
    let backup = legacy_root.join("config.toml.bak.20260604T153012Z");
    let manifest_path = dir.path().join("20260604T153012Z-codex-cli.json");
    std::fs::create_dir_all(&legacy_root).unwrap();
    std::fs::write(&original, "mutated").unwrap();
    std::fs::write(&backup, "original").unwrap();
    let manifest = MigrationManifest {
      version: 4,
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
      credentials_handoff_complete: true,
      imported_account_ids: Vec::new(),
      files: vec![FileBackup {
        original: "config.toml".into(),
        backup: Some("config.toml.bak.20260604T153012Z".into()),
        existed: true,
        created_by_migration: false,
        applied_sha256: None,
      }],
    };
    manifest::write_manifest(&manifest_path, &manifest).unwrap();

    let error = unlink(UnlinkRequest {
      agent: AgentId::CodexCli,
      backup_id: Some(manifest_path.display().to_string()),
    })
    .unwrap_err();
    assert!(error.to_string().contains("explicit legacy root"));
    assert_eq!(std::fs::read_to_string(&original).unwrap(), "mutated");

    let report = unlink_with_legacy_root(
      UnlinkRequest {
        agent: AgentId::CodexCli,
        backup_id: Some(manifest_path.display().to_string()),
      },
      &legacy_root,
    )
    .unwrap();

    assert_eq!(std::fs::read_to_string(original).unwrap(), "original");
    assert_eq!(report.actions.len(), 1);
  }

  #[test]
  fn unlink_legacy_relative_manifest_does_not_require_root_to_still_exist() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_root = dir.path().join("deleted-working-directory");
    let manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    let manifest = MigrationManifest {
      version: 4,
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
      credentials_handoff_complete: true,
      imported_account_ids: Vec::new(),
      files: vec![FileBackup {
        original: "config.d/opencode.toml".into(),
        backup: None,
        existed: false,
        created_by_migration: true,
        applied_sha256: None,
      }],
    };
    manifest::write_manifest(&manifest_path, &manifest).unwrap();

    let report = unlink_with_legacy_root(
      UnlinkRequest {
        agent: AgentId::Opencode,
        backup_id: Some(manifest_path.display().to_string()),
      },
      &legacy_root,
    )
    .unwrap();

    assert!(report.actions.is_empty());
    assert!(
      manifest::read_manifest(&manifest::inactive_manifest_path(&manifest_path).unwrap())
        .unwrap()
        .unlinked
    );
  }

  #[test]
  fn unlink_legacy_missing_root_normalizes_parent_components() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_root = dir.path().join("deleted-working-directory");
    let original = dir.path().join("opencode.toml");
    let backup = dir.path().join("opencode.toml.bak");
    let manifest_path = dir.path().join("20260604T153012Z-opencode.json");
    std::fs::write(&original, "mutated").unwrap();
    std::fs::write(&backup, "original").unwrap();
    let manifest = MigrationManifest {
      version: 4,
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
      credentials_handoff_complete: true,
      imported_account_ids: Vec::new(),
      files: vec![FileBackup {
        original: "../opencode.toml".into(),
        backup: Some("../opencode.toml.bak".into()),
        existed: true,
        created_by_migration: false,
        applied_sha256: None,
      }],
    };
    manifest::write_manifest(&manifest_path, &manifest).unwrap();

    unlink_with_legacy_root(
      UnlinkRequest {
        agent: AgentId::Opencode,
        backup_id: Some(manifest_path.display().to_string()),
      },
      &legacy_root,
    )
    .unwrap();

    assert_eq!(std::fs::read_to_string(original).unwrap(), "original");
  }

  #[test]
  fn unlink_refuses_one_root_for_multiple_relative_legacy_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_root = dir.path().join("latest-working-directory");
    let ancestor_path = dir.path().join("20260604T153012Z-opencode.json");
    let latest_path = dir.path().join("20260604T153013Z-opencode.json");
    let ancestor = sample_active_manifest(
      Some("opencode"),
      Path::new("config.d/opencode.toml"),
      AgentAccountSource::Main,
    );
    let mut latest = sample_active_manifest(
      Some("opencode"),
      Path::new("config.d/opencode.toml"),
      AgentAccountSource::Main,
    );
    latest.timestamp = "20260604T153013Z".into();
    latest.previous_manifest = Some(ancestor_path.clone());
    manifest::write_manifest(&ancestor_path, &ancestor).unwrap();
    manifest::write_manifest(&latest_path, &latest).unwrap();

    let error = unlink_with_legacy_root(
      UnlinkRequest {
        agent: AgentId::Opencode,
        backup_id: Some(latest_path.display().to_string()),
      },
      &legacy_root,
    )
    .unwrap_err();

    assert!(error.to_string().contains("one --legacy-root cannot safely resolve"));
    assert!(!manifest::read_manifest(&ancestor_path).unwrap().unlinked);
    assert!(!manifest::read_manifest(&latest_path).unwrap().unlinked);
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
        applied_sha256: None,
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

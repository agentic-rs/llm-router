pub mod error;
pub mod paths;

pub use error::{Error, Result};
pub use tokn_core::account::{Account, AccountConfig, AccountState, AccountTier, AuthType};
pub use tokn_core::AgentId;

use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tokn_core::provider::ID_GITHUB_COPILOT;

pub const DEFAULT_PORT: u16 = 4141;
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PROXY_PORT: u16 = 4142;
pub const DEFAULT_PROVIDER: &str = ID_GITHUB_COPILOT;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
  #[serde(default)]
  pub api_key: ApiKeyConfig,
  #[serde(default)]
  pub server: ServerConfig,
  #[serde(default)]
  pub pool: PoolConfig,
  #[serde(default, alias = "usage")]
  pub db: DbConfig,
  #[serde(default)]
  pub proxy: ProxyConfig,
  #[serde(default)]
  pub proxy_mode: ProxyModeConfig,
  #[serde(default)]
  pub logging: LoggingConfig,
  #[serde(default)]
  pub defaults: DefaultsConfig,
  #[serde(default)]
  pub agents: BTreeMap<String, AgentConfig>,
  #[serde(default)]
  pub profiles: BTreeMap<String, ProfileConfig>,
  #[serde(default)]
  pub model_families: Vec<ModelFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiKeyConfig {
  /// Require client API keys for gateway-managed API and intercepted proxy requests.
  /// Passthrough traffic always preserves client credentials and bypasses this check.
  #[serde(default)]
  pub enabled: bool,
}

/// Source files that contributed to an effective configuration.
///
/// Agent migration uses this to ensure no source changed between planning and
/// applying a reversible link operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSources {
  pub root: PathBuf,
  pub fragment_dir: PathBuf,
  pub fragments: Vec<PathBuf>,
}

/// An effective configuration together with its source files.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
  pub config: Config,
  pub sources: ConfigSources,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
  Passthrough,
  Switch,
  Exact,
  #[default]
  Route,
  Fuzzy,
}

/// Where an agent binding obtains its accounts.
///
/// `Agent` preserves the original migration behavior: discover and import the
/// linked agent's credentials. `Main` keeps the agent credentials untouched
/// and uses the gateway's existing default account pool instead.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentAccountSource {
  #[default]
  Agent,
  Main,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProviderMode {
  Passthrough,
  Switch,
}

impl ProxyProviderMode {
  pub fn as_route_mode(self) -> RouteMode {
    match self {
      Self::Passthrough => RouteMode::Passthrough,
      Self::Switch => RouteMode::Switch,
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelFamily {
  pub name: String,
  #[serde(default)]
  pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefaultsConfig {
  #[serde(default)]
  pub mode: RouteMode,
  #[serde(default)]
  pub agent_id: Option<AgentId>,
  #[serde(default)]
  pub default_provider_id: Option<String>,
  #[serde(default)]
  pub providers: Option<Vec<String>>,
  #[serde(default)]
  pub accounts: Option<Vec<String>>,
  #[serde(default)]
  pub model_families: Vec<ModelFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileConfig {
  #[serde(default)]
  pub mode: Option<RouteMode>,
  #[serde(default)]
  pub agent_id: Option<AgentId>,
  #[serde(default)]
  pub default_provider_id: Option<String>,
  #[serde(default)]
  pub providers: Option<Vec<String>>,
  #[serde(default)]
  pub accounts: Option<Vec<String>>,
  #[serde(default)]
  pub model_families: Option<Vec<ModelFamily>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
  #[serde(default)]
  pub mode: Option<RouteMode>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub profile: Option<String>,
  #[serde(default, skip_serializing_if = "is_agent_account_source")]
  pub account_source: AgentAccountSource,
  /// Agent-side provider identifiers redirected to this binding when it uses
  /// the gateway's main account pool.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub source_providers: Option<Vec<String>>,
  #[serde(default, skip_serializing_if = "is_false")]
  pub sync: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ConfigRaw {
  #[serde(flatten)]
  config: Config,
  #[serde(default)]
  copilot: Option<toml::Table>,
}

/// A deliberately narrow configuration overlay. Agent link state is kept out
/// of the primary config so it can be backed up and restored independently.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfigFragment {
  #[serde(default)]
  agents: BTreeMap<String, AgentConfig>,
  #[serde(default)]
  profiles: BTreeMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
  #[serde(default = "default_host")]
  pub host: String,
  #[serde(default = "default_port")]
  pub port: u16,
  #[serde(default)]
  pub route_mode: RouteMode,
  #[serde(default)]
  pub cors: CorsConfig,
}

impl Default for ServerConfig {
  fn default() -> Self {
    Self {
      host: default_host(),
      port: default_port(),
      route_mode: RouteMode::default(),
      cors: CorsConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub allow_localhost: bool,
  #[serde(default)]
  pub allowed_origins: Vec<String>,
}

impl CorsConfig {
  pub fn validate(&self) -> Result<()> {
    if self.enabled && !self.allow_localhost && self.allowed_origins.is_empty() {
      return error::CorsOriginsEmptySnafu.fail();
    }
    self.canonical_allowed_origins().map(|_| ())
  }

  pub fn canonical_allowed_origins(&self) -> Result<BTreeSet<String>> {
    self
      .allowed_origins
      .iter()
      .map(|origin| canonical_cors_origin(origin))
      .collect()
  }
}

fn canonical_cors_origin(origin: &str) -> Result<String> {
  let parsed = reqwest::Url::parse(origin).map_err(|error| Error::InvalidCorsOrigin {
    origin: origin.to_string(),
    message: error.to_string(),
  })?;
  if !matches!(parsed.scheme(), "http" | "https") {
    return Err(Error::InvalidCorsOrigin {
      origin: origin.to_string(),
      message: "scheme must be http or https".into(),
    });
  }
  if parsed.host().is_none()
    || !parsed.username().is_empty()
    || parsed.password().is_some()
    || parsed.path() != "/"
    || parsed.query().is_some()
    || parsed.fragment().is_some()
  {
    return Err(Error::InvalidCorsOrigin {
      origin: origin.to_string(),
      message: "expected only scheme, host, and optional port".into(),
    });
  }
  Ok(parsed.origin().ascii_serialization())
}

fn default_host() -> String {
  DEFAULT_HOST.to_string()
}

fn default_port() -> u16 {
  DEFAULT_PORT
}

fn default_proxy_port() -> u16 {
  DEFAULT_PROXY_PORT
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
  #[serde(default = "default_strategy")]
  pub strategy: String,
  #[serde(default = "default_cooldown")]
  pub failure_cooldown_secs: u64,
  /// How long a session id stays bound to its chosen account.
  /// Sliding window: refreshed on every successful use.
  #[serde(default = "default_session_ttl")]
  pub session_ttl_secs: u64,
  /// Configure how long to retain a session entry from its last successful use
  /// for debug/observability before eventually forgetting it.
  /// The effective retained TTL is clamped to at least `session_ttl_secs`.
  /// Set to `0` to retain entries exactly for the affinity TTL.
  #[serde(default = "default_session_tombstone")]
  pub session_tombstone_secs: u64,
}

impl Default for PoolConfig {
  fn default() -> Self {
    Self {
      strategy: default_strategy(),
      failure_cooldown_secs: default_cooldown(),
      session_ttl_secs: default_session_ttl(),
      session_tombstone_secs: default_session_tombstone(),
    }
  }
}

fn default_strategy() -> String {
  "round_robin".into()
}

fn default_cooldown() -> u64 {
  60
}

fn default_session_ttl() -> u64 {
  18000
}

fn default_session_tombstone() -> u64 {
  0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default, alias = "db_path")]
  pub usage_db_path: Option<PathBuf>,
  #[serde(default)]
  pub sessions_db_path: Option<PathBuf>,
  #[serde(default)]
  pub requests_dir: Option<PathBuf>,
  #[serde(default = "default_true")]
  pub record_sessions: bool,
  #[serde(default = "default_true")]
  pub record_request_bodies: bool,
  #[serde(default = "default_body_max_bytes")]
  pub body_max_bytes: usize,
  #[serde(default = "default_write_queue_capacity")]
  pub write_queue_capacity: usize,
  #[serde(default)]
  pub archive_extension: Option<String>,
}

impl Default for DbConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      usage_db_path: None,
      sessions_db_path: None,
      requests_dir: None,
      record_sessions: true,
      record_request_bodies: true,
      body_max_bytes: default_body_max_bytes(),
      write_queue_capacity: default_write_queue_capacity(),
      archive_extension: None,
    }
  }
}

impl DbConfig {
  pub fn resolve_paths(&self) -> Result<tokn_core::db::DbPaths> {
    Ok(tokn_core::db::DbPaths {
      usage_db: self
        .usage_db_path
        .clone()
        .map(Ok)
        .unwrap_or_else(paths::default_usage_db)?,
      sessions_db: self
        .sessions_db_path
        .clone()
        .map(Ok)
        .unwrap_or_else(paths::default_sessions_db)?,
      requests_dir: self
        .requests_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(paths::default_requests_dir)?,
    })
  }
}

fn default_true() -> bool {
  true
}

fn is_false(value: &bool) -> bool {
  !*value
}

fn is_agent_account_source(value: &AgentAccountSource) -> bool {
  *value == AgentAccountSource::Agent
}

fn default_body_max_bytes() -> usize {
  10 * 1024 * 1024
}

fn default_write_queue_capacity() -> usize {
  4096
}

/// Outbound HTTP/HTTPS/SOCKS proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
  #[serde(default)]
  pub url: Option<String>,
  #[serde(default)]
  pub no_proxy: Vec<String>,
  #[serde(default)]
  pub system: bool,
}

impl ProxyConfig {
  pub fn validate(&self) -> Result<()> {
    if let Some(u) = &self.url {
      let parsed = reqwest::Url::parse(u).map_err(|e| Error::ProxyUrl {
        url: u.clone(),
        message: e.to_string(),
      })?;
      match parsed.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        other => {
          return error::ProxySchemeSnafu {
            scheme: other.to_string(),
          }
          .fail()
        }
      }
    }
    Ok(())
  }

  pub fn to_http_options(&self) -> tokn_core::util::http::HttpClientOptions {
    tokn_core::util::http::HttpClientOptions {
      url: self.url.clone(),
      no_proxy: self.no_proxy.clone(),
      system: self.system,
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyModeConfig {
  #[serde(default = "default_host")]
  pub host: String,
  #[serde(default = "default_proxy_port")]
  pub port: u16,
  #[serde(default)]
  pub route_mode: RouteMode,
  #[serde(default)]
  pub ca_dir: Option<PathBuf>,
  #[serde(default)]
  pub intercept_hosts: Vec<String>,
  #[serde(default)]
  pub passthrough_hosts: Vec<String>,
  #[serde(default)]
  pub provider_modes: BTreeMap<String, ProxyProviderMode>,
}

impl Default for ProxyModeConfig {
  fn default() -> Self {
    Self {
      host: default_host(),
      port: default_proxy_port(),
      route_mode: RouteMode::default(),
      ca_dir: None,
      intercept_hosts: Vec::new(),
      passthrough_hosts: Vec::new(),
      provider_modes: BTreeMap::new(),
    }
  }
}

impl ProxyModeConfig {
  pub fn validate(&self) -> Result<()> {
    for host in &self.intercept_hosts {
      if !is_proxy_host(host) {
        return error::ProxyInterceptHostSnafu { host: host.clone() }.fail();
      }
    }
    for host in &self.passthrough_hosts {
      if !is_proxy_host(host) {
        return error::ProxyPassthroughHostSnafu { host: host.clone() }.fail();
      }
    }
    Ok(())
  }

  pub fn resolved_ca_dir(&self) -> Result<PathBuf> {
    self.ca_dir.clone().map(Ok).unwrap_or_else(paths::default_ca_dir)
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
  #[serde(default = "default_log_level")]
  pub level: String,
  #[serde(default)]
  pub format: LogFormat,
  #[serde(default)]
  pub target: LogTarget,
  #[serde(default)]
  pub dir: Option<PathBuf>,
  #[serde(default = "default_true")]
  pub ansi: bool,
  #[serde(default)]
  pub include_spans: bool,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      level: default_log_level(),
      format: LogFormat::default(),
      target: LogTarget::default(),
      dir: None,
      ansi: true,
      include_spans: false,
    }
  }
}

fn default_log_level() -> String {
  "info,tokn_router=info".into()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
  Pretty,
  #[default]
  Compact,
  Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogTarget {
  Stderr,
  File,
  #[default]
  Both,
}

impl Config {
  pub fn load(explicit: Option<&Path>) -> Result<(Self, PathBuf)> {
    let loaded = Self::load_with_sources(explicit)?;
    Ok((loaded.config, loaded.sources.root))
  }

  /// Load the primary configuration without applying `config.d` agent
  /// overlays. Use this only for commands which deliberately rewrite the
  /// primary config, such as `config init`.
  pub fn load_primary(explicit: Option<&Path>) -> Result<(Self, PathBuf)> {
    let path = resolve_config_path(explicit)?;
    let cfg = load_primary_config(&path)?;
    Ok((cfg, path))
  }

  /// Load the effective configuration, including the sorted agent-owned
  /// overlays from the matching `config.d` directory.
  pub fn load_with_sources(explicit: Option<&Path>) -> Result<LoadedConfig> {
    let path = resolve_config_path(explicit)?;
    let mut cfg = load_primary_config(&path)?;
    let fragment_dir = paths::config_fragment_dir(&path);
    let fragments = load_fragment_paths(&fragment_dir)?;
    let sources = ConfigSources {
      root: path.clone(),
      fragment_dir,
      fragments,
    };
    let mut fragment_profile_owners = BTreeMap::new();
    for fragment_path in &sources.fragments {
      let fragment = load_agent_fragment(fragment_path)?;
      apply_agent_fragment(&mut cfg, fragment_path, fragment, &mut fragment_profile_owners)?;
    }
    cfg.validate()?;
    tracing::debug!(path = %path.display(), fragments = sources.fragments.len(), "config loaded");
    Ok(LoadedConfig { config: cfg, sources })
  }

  pub fn validate(&self) -> Result<()> {
    self.server.cors.validate()?;
    self.proxy.validate()?;
    self.proxy_mode.validate()?;
    validate_model_families(&self.model_families)?;
    validate_model_families(&self.defaults.model_families)?;
    validate_provider_id(
      "defaults.default_provider_id",
      self.defaults.default_provider_id.as_deref(),
    )?;
    validate_providers("defaults.providers", self.defaults.providers.as_deref())?;
    validate_account_ids("defaults.accounts", self.defaults.accounts.as_deref())?;
    for (name, agent) in &self.agents {
      validate_profile_name(name)?;
      if let Some(profile) = agent.profile.as_deref() {
        validate_profile_name(profile)?;
      }
      validate_providers(
        &format!("agents.{name}.source_providers"),
        agent.source_providers.as_deref(),
      )?;
    }
    for (name, profile) in &self.profiles {
      validate_profile_name(name)?;
      if let Some(model_families) = profile.model_families.as_deref() {
        validate_model_families(model_families)?;
      }
      validate_provider_id(
        &format!("profiles.{name}.default_provider_id"),
        profile.default_provider_id.as_deref(),
      )?;
      validate_providers(&format!("profiles.{name}.providers"), profile.providers.as_deref())?;
      validate_account_ids(&format!("profiles.{name}.accounts"), profile.accounts.as_deref())?;
    }
    Ok(())
  }

  pub fn save(&self, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).context(error::CreateDirSnafu {
        path: parent.to_path_buf(),
      })?;
    }
    let toml = toml::to_string_pretty(self).context(error::SerializeSnafu)?;
    write_atomic(path, &toml)?;
    tracing::debug!(path = %path.display(), "config saved");
    Ok(())
  }

  pub fn edit_in_place<F>(path: &Path, f: F) -> Result<()>
  where
    F: FnOnce(&mut toml_edit::DocumentMut) -> Result<()>,
  {
    let raw = if path.exists() {
      std::fs::read_to_string(path).context(error::ReadSnafu {
        path: path.to_path_buf(),
      })?
    } else {
      String::new()
    };
    let mut doc: toml_edit::DocumentMut = raw.parse().context(error::ParseEditSnafu {
      path: path.to_path_buf(),
    })?;
    f(&mut doc)?;
    let serialised = doc.to_string();
    let cfg: Config = toml::from_str(&serialised).context(error::EditValidateSnafu)?;
    cfg.proxy.validate().map_err(|e| Error::EditValidateSection {
      section: "[proxy]",
      source: Box::new(e),
    })?;
    cfg.proxy_mode.validate().map_err(|e| Error::EditValidateSection {
      section: "[proxy_mode]",
      source: Box::new(e),
    })?;
    validate_model_families(&cfg.model_families).map_err(|e| Error::EditValidateSection {
      section: "[[model_families]]",
      source: Box::new(e),
    })?;
    cfg.validate().map_err(|e| Error::EditValidateSection {
      section: "[defaults]/[profiles]",
      source: Box::new(e),
    })?;
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent).context(error::CreateDirSnafu {
        path: parent.to_path_buf(),
      })?;
    }
    write_atomic(path, &serialised)
  }
}

fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf> {
  match explicit {
    Some(path) => Ok(path.to_path_buf()),
    None => paths::config_path(),
  }
}

fn load_primary_config(path: &Path) -> Result<Config> {
  if !path.exists() {
    return Ok(Config::default());
  }
  let raw = std::fs::read_to_string(path).context(error::ReadSnafu {
    path: path.to_path_buf(),
  })?;
  let raw_cfg: ConfigRaw = toml::from_str(&raw).context(error::ParseSnafu {
    path: path.to_path_buf(),
  })?;
  if raw_cfg.copilot.is_some() {
    tracing::warn!(
      "top-level [copilot] config is ignored by the new account schema; move values under [accounts.settings]"
    );
  }
  raw_cfg.config.validate()?;
  Ok(raw_cfg.config)
}

fn load_fragment_paths(fragment_dir: &Path) -> Result<Vec<PathBuf>> {
  let entries = match std::fs::read_dir(fragment_dir) {
    Ok(entries) => entries,
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
    Err(source) => {
      return Err(Error::Read {
        path: fragment_dir.to_path_buf(),
        source,
      });
    }
  };
  let mut fragments = Vec::new();
  for entry in entries {
    let entry = entry.map_err(|source| Error::Read {
      path: fragment_dir.to_path_buf(),
      source,
    })?;
    let path = entry.path();
    if path.is_file() && path.extension().is_some_and(|extension| extension == "toml") {
      fragments.push(path);
    }
  }
  fragments.sort();
  Ok(fragments)
}

fn load_agent_fragment(path: &Path) -> Result<AgentConfigFragment> {
  let raw = std::fs::read_to_string(path).context(error::ReadSnafu {
    path: path.to_path_buf(),
  })?;
  toml::from_str(&raw).context(error::ParseSnafu {
    path: path.to_path_buf(),
  })
}

fn apply_agent_fragment(
  cfg: &mut Config,
  path: &Path,
  fragment: AgentConfigFragment,
  fragment_profile_owners: &mut BTreeMap<String, AgentId>,
) -> Result<()> {
  let agent_name = path
    .file_stem()
    .and_then(|name| name.to_str())
    .filter(|name| !name.is_empty())
    .ok_or_else(|| Error::Other {
      message: format!("agent config fragment has no valid filename: {}", path.display()),
    })?;
  let agent = AgentId::from(agent_name);
  if agent.as_str() != agent_name {
    return Err(Error::Other {
      message: format!(
        "agent config fragment {} must use the canonical agent filename {}.toml",
        path.display(),
        agent.as_str()
      ),
    });
  }
  if fragment.agents.len() != 1 || !fragment.agents.contains_key(agent_name) {
    return Err(Error::Other {
      message: format!(
        "agent config fragment {} must define exactly [agents.{agent_name}]",
        path.display()
      ),
    });
  }

  for (profile_name, profile) in &fragment.profiles {
    if profile.agent_id.as_ref() != Some(&agent) {
      return Err(Error::Other {
        message: format!(
          "profile '{profile_name}' in {} must set agent_id = '{}'",
          path.display(),
          agent.as_str()
        ),
      });
    }
    if let Some(owner) = fragment_profile_owners.insert(profile_name.clone(), agent.clone()) {
      return Err(Error::Other {
        message: format!(
          "profile '{profile_name}' is managed by both {} and {} agent fragments",
          owner.as_str(),
          agent.as_str()
        ),
      });
    }
    if let Some(existing) = cfg.profiles.get(profile_name) {
      if existing.agent_id.as_ref() != Some(&agent) {
        return Err(Error::Other {
          message: format!(
            "profile '{profile_name}' in {} conflicts with a profile not owned by {}",
            path.display(),
            agent.as_str()
          ),
        });
      }
    }
  }

  let binding = fragment
    .agents
    .get(agent_name)
    .expect("fragment agent was checked above")
    .clone();
  if let Some(profile_name) = binding.profile.as_deref() {
    let Some(profile) = fragment.profiles.get(profile_name) else {
      return Err(Error::Other {
        message: format!(
          "agent config fragment {} must define [profiles.{profile_name}] for [agents.{agent_name}].profile",
          path.display()
        ),
      });
    };
    if profile.agent_id.as_ref() != Some(&agent) {
      return Err(Error::Other {
        message: format!(
          "profile '{profile_name}' in {} must set agent_id = '{}'",
          path.display(),
          agent.as_str()
        ),
      });
    }
  }

  // A legacy root binding materialized its base profile and provider-specific
  // children under the binding name. Mask precisely that set while the
  // sidecar is active, so an old route cannot remain reachable after a
  // relink without hiding unrelated profiles that merely share an agent
  // persona.
  let legacy_profile = cfg
    .agents
    .get(agent_name)
    .and_then(|existing| existing.profile.as_deref())
    .map(str::to_string);
  if let Some(legacy_profile) = legacy_profile.as_deref() {
    remove_legacy_agent_profiles(cfg, legacy_profile, &agent);
  }
  cfg.agents.insert(agent_name.to_string(), binding);
  cfg.profiles.extend(fragment.profiles);
  Ok(())
}

fn remove_legacy_agent_profiles(cfg: &mut Config, profile: &str, agent: &AgentId) {
  let prefix = format!("{profile}-");
  cfg.profiles.retain(|name, existing| {
    // Provider children created by the old link writer always carried their
    // account allow-list. Keep a same-persona, similarly named user profile
    // without that migration shape visible rather than treating `agent_id`
    // itself as ownership evidence.
    !(name == profile
      || (name.starts_with(&prefix)
        && existing.agent_id.as_ref() == Some(agent)
        && existing.accounts.as_ref().is_some_and(|accounts| !accounts.is_empty())))
  });
}

#[allow(dead_code)] // used by AuthStore validation in a follow-up cycle
fn validate_account_common(account: &AccountConfig) -> Result<()> {
  if account.id.trim().is_empty() {
    return error::InvalidAccountSnafu {
      id: account.id.clone(),
      message: "id must be non-empty".to_string(),
    }
    .fail();
  }
  if account.provider.trim().is_empty() {
    return error::InvalidAccountSnafu {
      id: account.id.clone(),
      message: "provider must be non-empty".to_string(),
    }
    .fail();
  }
  for name in account.headers.keys() {
    if !is_token(name) {
      return error::InvalidHeaderNameSnafu { name: name.clone() }.fail();
    }
  }
  Ok(())
}

fn validate_model_families(families: &[ModelFamily]) -> Result<()> {
  for family in families {
    if family.name.trim().is_empty() {
      return error::InvalidAccountSnafu {
        id: String::from("model_families"),
        message: String::from("model family name must be non-empty"),
      }
      .fail();
    }
    if family.members.is_empty() {
      return error::InvalidAccountSnafu {
        id: family.name.clone(),
        message: String::from("model family must have at least one member"),
      }
      .fail();
    }
    if family.members.iter().any(|member| member.trim().is_empty()) {
      return error::InvalidAccountSnafu {
        id: family.name.clone(),
        message: String::from("model family members must be non-empty"),
      }
      .fail();
    }
  }
  Ok(())
}

fn validate_profile_name(name: &str) -> Result<()> {
  if name.trim().is_empty() || name.contains('/') {
    return error::InvalidAccountSnafu {
      id: name.to_string(),
      message: String::from("profile name must be non-empty and must not contain '/'"),
    }
    .fail();
  }
  Ok(())
}

fn validate_providers(section: &str, providers: Option<&[String]>) -> Result<()> {
  validate_ids(section, providers, "provider ids must be non-empty")
}

fn validate_provider_id(section: &str, provider_id: Option<&str>) -> Result<()> {
  if matches!(provider_id, Some(id) if id.trim().is_empty()) {
    return error::InvalidAccountSnafu {
      id: section.to_string(),
      message: "provider id must be non-empty".to_string(),
    }
    .fail();
  }
  Ok(())
}

fn validate_account_ids(section: &str, ids: Option<&[String]>) -> Result<()> {
  validate_ids(section, ids, "account ids must be non-empty")
}

fn validate_ids(section: &str, ids: Option<&[String]>, message: &str) -> Result<()> {
  let Some(ids) = ids else {
    return Ok(());
  };
  for id in ids {
    if id.trim().is_empty() {
      return error::InvalidAccountSnafu {
        id: section.to_string(),
        message: message.to_string(),
      }
      .fail();
    }
  }
  Ok(())
}

#[allow(dead_code)]
fn is_token(s: &str) -> bool {
  !s.is_empty()
    && s.bytes().all(|b| {
      matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
            | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
    })
}

fn is_proxy_host(s: &str) -> bool {
  let trimmed = s.trim();
  !trimmed.is_empty()
    && trimmed
      .bytes()
      .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*'))
}

fn write_atomic(path: &Path, contents: &str) -> Result<()> {
  let tmp = path.with_extension("toml.tmp");
  std::fs::write(&tmp, contents).context(error::WriteSnafu { path: tmp.clone() })?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(&tmp, perm).context(error::SetPermissionsSnafu { path: tmp.clone() })?;
  }
  std::fs::rename(&tmp, path).context(error::RenameSnafu {
    from: tmp.clone(),
    to: path.to_path_buf(),
  })?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_paths_use_tokn_router_home() {
    let home = tokn_core::util::paths::router_home().expect("home directory should resolve");

    assert_eq!(paths::config_dir().unwrap(), home);
    assert_eq!(paths::config_path().unwrap(), home.join("config.toml"));
    assert_eq!(paths::data_dir().unwrap(), home);
    assert_eq!(paths::cache_dir().unwrap(), home.join("cache"));
    assert_eq!(paths::default_usage_db().unwrap(), home.join("usage.db"));
    assert_eq!(paths::default_sessions_db().unwrap(), home.join("sessions.db"));
    assert_eq!(paths::default_requests_dir().unwrap(), home.join("requests"));
    assert_eq!(paths::default_logs_dir().unwrap(), home.join("logs"));
    assert_eq!(paths::default_ca_dir().unwrap(), home.join("ca"));
  }

  #[test]
  fn proxy_mode_defaults_to_route_mode() {
    assert_eq!(ProxyModeConfig::default().route_mode, RouteMode::Route);
  }

  #[test]
  fn api_key_authentication_defaults_to_disabled() {
    assert!(!Config::default().api_key.enabled);
  }

  #[test]
  fn api_key_authentication_can_be_enabled() {
    let cfg: Config = toml::from_str(
      r#"
        [api_key]
        enabled = true
      "#,
    )
    .expect("config should deserialize");

    assert!(cfg.api_key.enabled);
  }

  #[test]
  fn cors_defaults_to_disabled() {
    let cors = &Config::default().server.cors;
    assert!(!cors.enabled);
    assert!(!cors.allow_localhost);
    assert!(cors.allowed_origins.is_empty());
  }

  #[test]
  fn enabled_cors_can_allow_localhost_without_exact_origins() {
    let cfg: Config = toml::from_str(
      r#"
        [server.cors]
        enabled = true
        allow_localhost = true
      "#,
    )
    .expect("config should deserialize");

    cfg.validate().unwrap();
  }

  #[test]
  fn cors_origins_are_validated_and_canonicalized() {
    let cfg: Config = toml::from_str(
      r#"
        [server.cors]
        enabled = true
        allowed_origins = ["https://EXAMPLE.com:443", "http://localhost:3000"]
      "#,
    )
    .expect("config should deserialize");

    cfg.validate().unwrap();
    assert_eq!(
      cfg.server.cors.canonical_allowed_origins().unwrap(),
      BTreeSet::from(["http://localhost:3000".into(), "https://example.com".into()])
    );
  }

  #[test]
  fn enabled_cors_requires_origins() {
    let cfg: Config = toml::from_str(
      r#"
        [server.cors]
        enabled = true
      "#,
    )
    .expect("config should deserialize");

    assert!(matches!(cfg.validate(), Err(Error::CorsOriginsEmpty)));
  }

  #[test]
  fn cors_rejects_urls_instead_of_origins() {
    let cfg: Config = toml::from_str(
      r#"
        [server.cors]
        enabled = true
        allowed_origins = ["https://example.com/app"]
      "#,
    )
    .expect("config should deserialize");

    assert!(matches!(cfg.validate(), Err(Error::InvalidCorsOrigin { .. })));
  }

  #[test]
  fn proxy_mode_route_mode_deserializes() {
    let cfg: Config = toml::from_str(
      r#"
        [proxy_mode]
        route_mode = "exact"
      "#,
    )
    .expect("config should deserialize");
    assert_eq!(cfg.proxy_mode.route_mode, RouteMode::Exact);
  }

  #[test]
  fn proxy_mode_provider_modes_deserialize() {
    let cfg: Config = toml::from_str(
      r#"
        [proxy_mode]
        route_mode = "route"

        [proxy_mode.provider_modes]
        github-copilot = "passthrough"
        openai = "switch"
      "#,
    )
    .expect("config should deserialize");
    assert_eq!(
      cfg.proxy_mode.provider_modes.get("github-copilot"),
      Some(&ProxyProviderMode::Passthrough)
    );
    assert_eq!(
      cfg.proxy_mode.provider_modes.get("openai"),
      Some(&ProxyProviderMode::Switch)
    );
  }

  #[test]
  fn proxy_mode_provider_modes_reject_invalid_mode_value() {
    let err = toml::from_str::<Config>(
      r#"
        [proxy_mode.provider_modes]
        openai = "route"
      "#,
    )
    .expect_err("invalid provider mode must fail deserialization");
    assert!(err.to_string().contains("unknown variant"));
    assert!(err.to_string().contains("route"));
  }

  #[test]
  fn profiles_deserialize_request_policy_overrides() {
    let cfg: Config = toml::from_str(
      r#"
        [defaults]
        mode = "route"
        default_provider_id = "github-copilot"
        providers = ["github-copilot"]

        [[defaults.model_families]]
        name = "sonnet"
        members = ["claude-sonnet-4"]

        [profiles.work]
        mode = "fuzzy"
        agent_id = "codex-cli"
        default_provider_id = "codex"
        providers = ["codex"]

        [[profiles.work.model_families]]
        name = "glm"
        members = ["glm-4.6"]
      "#,
    )
    .expect("config should deserialize");

    assert_eq!(cfg.defaults.mode, RouteMode::Route);
    assert_eq!(cfg.defaults.default_provider_id.as_deref(), Some("github-copilot"));
    assert_eq!(
      cfg.defaults.providers.as_deref(),
      Some(&["github-copilot".to_string()][..])
    );
    let work = cfg.profiles.get("work").expect("work profile");
    assert_eq!(work.mode, Some(RouteMode::Fuzzy));
    assert_eq!(work.agent_id, Some(AgentId::CodexCli));
    assert_eq!(work.default_provider_id.as_deref(), Some("codex"));
    assert_eq!(work.providers.as_deref(), Some(&["codex".to_string()][..]));
    assert_eq!(work.model_families.as_ref().unwrap()[0].name, "glm");
  }

  #[test]
  fn agents_deserialize_binding_policy() {
    let cfg: Config = toml::from_str(
      r#"
        [agents.opencode]
        mode = "switch"
        profile = "opencode"
        sync = true
      "#,
    )
    .expect("config should deserialize");

    let agent = cfg.agents.get("opencode").expect("opencode agent");
    assert_eq!(agent.mode, Some(RouteMode::Switch));
    assert_eq!(agent.profile.as_deref(), Some("opencode"));
    assert!(agent.sync);
    cfg.validate().expect("agent config should validate");
  }

  #[test]
  fn profiles_reject_invalid_names() {
    let cfg: Config = toml::from_str(
      r#"
        [profiles."bad/name"]
        mode = "route"
      "#,
    )
    .expect("config should deserialize before validation");
    let err = cfg
      .validate()
      .expect_err("profile names containing slash must fail validation");
    assert!(err.to_string().contains("profile name"));
  }

  #[test]
  fn provider_filters_reject_empty_ids() {
    let cfg: Config = toml::from_str(
      r#"
        [defaults]
        providers = ["openai", " "]
      "#,
    )
    .expect("config should deserialize before validation");
    let err = cfg.validate().expect_err("empty provider ids must fail validation");
    assert!(err.to_string().contains("provider ids must be non-empty"));
  }

  #[test]
  fn default_provider_id_rejects_empty_id() {
    let cfg: Config = toml::from_str(
      r#"
        [defaults]
        default_provider_id = " "
      "#,
    )
    .expect("config should deserialize before validation");
    let err = cfg.validate().expect_err("empty default provider id must fail");
    assert!(err.to_string().contains("provider id must be non-empty"));
  }

  #[test]
  fn loads_agent_fragment_without_rewriting_primary_config() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let root_contents = r#"
[server]
port = 9911

[agents.opencode]
profile = "opencode"
mode = "route"

[profiles.opencode]
agent_id = "opencode"
mode = "route"
providers = ["openai"]
accounts = ["legacy-opencode"]

[profiles.opencode-legacy]
agent_id = "opencode"
mode = "route"
providers = ["codex"]
accounts = ["legacy-opencode"]

[profiles.opencode-coding]
agent_id = "opencode"
mode = "route"
providers = ["openai"]

[profiles.coding]
agent_id = "opencode"
mode = "route"
providers = ["openai"]
"#;
    std::fs::write(&root, root_contents).unwrap();
    let fragment = paths::agent_config_fragment_path(&root, "opencode");
    std::fs::create_dir_all(fragment.parent().unwrap()).unwrap();
    std::fs::write(
      &fragment,
      r#"
[agents.opencode]
profile = "opencode"
mode = "switch"
account_source = "main"
sync = true

[profiles.opencode]
agent_id = "opencode"
mode = "switch"
default_provider_id = "openai"
providers = ["openai"]
"#,
    )
    .unwrap();

    let loaded = Config::load_with_sources(Some(&root)).unwrap();
    let agent = loaded.config.agents.get("opencode").unwrap();
    let profile = loaded.config.profiles.get("opencode").unwrap();

    assert_eq!(loaded.config.server.port, 9911);
    assert_eq!(agent.mode, Some(RouteMode::Switch));
    assert_eq!(agent.account_source, AgentAccountSource::Main);
    assert!(agent.sync);
    assert_eq!(profile.mode, Some(RouteMode::Switch));
    assert_eq!(profile.default_provider_id.as_deref(), Some("openai"));
    assert_eq!(profile.accounts, None);
    assert!(!loaded.config.profiles.contains_key("opencode-legacy"));
    assert!(loaded.config.profiles.contains_key("opencode-coding"));
    assert!(loaded.config.profiles.contains_key("coding"));
    assert_eq!(loaded.sources.fragments, vec![fragment]);
    assert_eq!(std::fs::read_to_string(&root).unwrap(), root_contents);
  }

  #[test]
  fn rejects_fragment_profile_owned_by_another_agent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(
      &root,
      r#"
[profiles.shared]
agent_id = "codex-cli"
mode = "route"
"#,
    )
    .unwrap();
    let fragment = paths::agent_config_fragment_path(&root, "opencode");
    std::fs::create_dir_all(fragment.parent().unwrap()).unwrap();
    std::fs::write(
      &fragment,
      r#"
[agents.opencode]
profile = "shared"

[profiles.shared]
agent_id = "opencode"
mode = "route"
"#,
    )
    .unwrap();

    let err = Config::load(Some(&root)).unwrap_err();
    assert!(err.to_string().contains("not owned by opencode"));
  }

  #[test]
  fn rejects_non_agent_settings_in_a_fragment() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let fragment = paths::agent_config_fragment_path(&root, "opencode");
    std::fs::create_dir_all(fragment.parent().unwrap()).unwrap();
    std::fs::write(
      &fragment,
      r#"
[server]
port = 9000

[agents.opencode]
profile = "opencode"
"#,
    )
    .unwrap();

    let err = Config::load(Some(&root)).unwrap_err();
    assert!(err.to_string().contains("parse config"));
  }

  #[test]
  fn explicit_config_uses_an_isolated_fragment_directory() {
    let dir = tempfile::tempdir().unwrap();
    let primary = dir.path().join("work.toml");

    assert_eq!(paths::config_fragment_dir(&primary), dir.path().join("work.d"));
    assert_eq!(
      paths::agent_config_fragment_path(&primary, "opencode"),
      dir.path().join("work.d/opencode.toml")
    );
  }
}

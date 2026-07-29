use crate::adapter::{adapter_for, source_provider_id, supported_agents, ProviderRoute};
use crate::adapters::opencode::projected_config_matches;
use crate::jsonc::read_jsonc;
#[cfg(test)]
use crate::projection::SHARED_PROVIDER_ID;
use crate::projection::{compile_opencode_publications, AgentConfigProjection};
use crate::reconcile::{imported_account_ids, is_source_managed_account};
use anyhow::{anyhow, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tokn_auth::{AuthSource, AuthStore};
use tokn_config::{Account, AgentAccountSource, AgentConfig, Config, RouteMode};
use tokn_core::AgentId;

#[derive(Debug, Clone)]
pub struct AgentStatus {
  pub agent: AgentId,
  pub supported: bool,
  pub detected: bool,
  pub auth_path: PathBuf,
  pub config_path: PathBuf,
  pub binding: Option<AgentBindingStatus>,
  pub imported_account_ids: Vec<String>,
  /// Whether the materialized profiles, generated agent configuration,
  /// credential boundary, and active manifest match the declarative binding.
  pub link_in_sync: bool,
}

#[derive(Debug, Clone)]
pub struct AgentBindingStatus {
  pub profile: Option<String>,
  pub mode: RouteMode,
  pub account_source: AgentAccountSource,
  pub provider: Option<String>,
  pub provider_filter: Option<Vec<String>>,
  /// Legacy OpenCode namespaces retained only so status callers can explain
  /// why an old binding must be unlinked before migration.
  pub source_providers: Option<Vec<String>>,
  pub sync: bool,
}

pub fn list_agents(
  gateway_config_path: Option<&Path>,
  gateway_auth_path: Option<&Path>,
  agent_home: Option<&Path>,
) -> Result<Vec<AgentStatus>> {
  let (cfg, config_path) = Config::load(gateway_config_path)?;
  let auth_path = resolve_gateway_auth_path(gateway_auth_path)?;
  let store = AuthStore::load(Some(&auth_path), Some(&config_path))?;
  let home = resolve_home(agent_home)?;
  let mut statuses = supported_agents()
    .into_iter()
    .map(|agent| status_for_agent(&cfg, &store, &config_path, &home, agent))
    .collect::<Result<Vec<_>>>()?;
  statuses.sort_by(|a, b| a.agent.as_str().cmp(b.agent.as_str()));
  Ok(statuses)
}

pub fn show_agent(
  gateway_config_path: Option<&Path>,
  gateway_auth_path: Option<&Path>,
  agent_home: Option<&Path>,
  agent: AgentId,
) -> Result<AgentStatus> {
  let (cfg, config_path) = Config::load(gateway_config_path)?;
  let auth_path = resolve_gateway_auth_path(gateway_auth_path)?;
  let store = AuthStore::load(Some(&auth_path), Some(&config_path))?;
  let home = resolve_home(agent_home)?;
  status_for_agent(&cfg, &store, &config_path, &home, agent)
}

fn status_for_agent(
  cfg: &Config,
  store: &AuthStore,
  gateway_config_path: &Path,
  home: &Path,
  agent: AgentId,
) -> Result<AgentStatus> {
  let supported = adapter_for(&agent).is_some();
  let adapter = adapter_for(&agent);
  let (auth_path, config_path, detected, link_in_sync) = if let Some(adapter) = adapter {
    let auth_path = adapter.auth_path(home);
    let config_path = adapter.config_path(home);
    let detected = auth_path.exists() || config_path.exists();
    let link_in_sync = linked_config_points_at_gateway(&config_path, gateway_config_path, home, &agent, cfg, store);
    (auth_path, config_path, detected, link_in_sync)
  } else {
    let base = home.join(format!(".unsupported/{}", agent.as_str()));
    (base.join("auth"), base.join("config"), false, false)
  };
  let binding = cfg.agents.get(agent.as_str()).map(|binding| AgentBindingStatus {
    profile: binding.profile.clone(),
    mode: binding.mode.unwrap_or(RouteMode::Route),
    account_source: binding.account_source,
    provider: binding.provider.clone(),
    provider_filter: binding.provider_filter.clone(),
    source_providers: binding.source_providers.clone(),
    sync: binding.sync,
  });
  let imported_account_ids = imported_account_ids(store, &agent);
  Ok(AgentStatus {
    agent,
    supported,
    detected,
    auth_path,
    config_path,
    binding,
    imported_account_ids,
    link_in_sync,
  })
}

fn linked_config_points_at_gateway(
  config_path: &Path,
  gateway_config_path: &Path,
  home: &Path,
  agent: &AgentId,
  cfg: &Config,
  store: &AuthStore,
) -> bool {
  let Some(binding) = cfg.agents.get(agent.as_str()) else {
    return false;
  };
  if !active_manifest_boundary_matches(gateway_config_path, agent, binding.account_source) {
    return false;
  }
  if !config_points_at_gateway(config_path, agent, cfg, store) {
    return false;
  }
  if !opencode_source_auth_is_absent(home, agent, cfg, store) {
    return false;
  }
  if *agent != AgentId::Opencode {
    return true;
  }
  let mode = binding.mode.unwrap_or(RouteMode::Route);
  with_opencode_projection(cfg, store, agent, binding, mode, |projection| {
    crate::opencode_markdown::OpenCodePreflight::new(home, config_path, binding.account_source, projection).validate()
  })
  .is_ok()
}

fn active_manifest_boundary_matches(
  gateway_config_path: &Path,
  agent: &AgentId,
  account_source: AgentAccountSource,
) -> bool {
  let manifest_path = match crate::manifest::latest_active_manifest(agent) {
    Ok(Some(path)) => path,
    Ok(None) => return true,
    Err(_) => return false,
  };
  let Ok(manifest) = crate::manifest::read_manifest(&manifest_path) else {
    return false;
  };
  manifest_boundary_matches(Some(&manifest), gateway_config_path, agent, account_source)
}

fn manifest_boundary_matches(
  manifest: Option<&crate::manifest::MigrationManifest>,
  gateway_config_path: &Path,
  agent: &AgentId,
  account_source: AgentAccountSource,
) -> bool {
  let Some(manifest) = manifest else {
    return true;
  };
  if !manifest.completed || manifest.unlinked || manifest.agent != *agent {
    return false;
  }
  let Ok(gateway_config_path) = std::path::absolute(gateway_config_path) else {
    return false;
  };
  let gateway_config_fragment_path =
    tokn_config::paths::agent_config_fragment_path(&gateway_config_path, agent.as_str());
  manifest
    .files
    .iter()
    .any(|file| same_path(&file.original, &gateway_config_fragment_path))
    && manifest_account_source(manifest) == account_source
}

fn manifest_account_source(manifest: &crate::manifest::MigrationManifest) -> AgentAccountSource {
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

fn same_path(left: &Path, right: &Path) -> bool {
  left == right
    || left
      .canonicalize()
      .ok()
      .zip(right.canonicalize().ok())
      .map(|(left, right)| left == right)
      .unwrap_or(false)
}

fn config_points_at_gateway(config_path: &Path, agent: &AgentId, cfg: &Config, store: &AuthStore) -> bool {
  if !config_path.exists() {
    return false;
  }
  let default_base = format!("http://{}:{}/v1", cfg.server.host, cfg.server.port);
  let Some(binding) = cfg.agents.get(agent.as_str()) else {
    return false;
  };
  let mode = binding.mode.unwrap_or(RouteMode::Route);
  let Some(adapter) = adapter_for(agent) else {
    return false;
  };
  if binding.account_source == AgentAccountSource::Main && !adapter.supports_main_accounts() {
    return false;
  }
  if mode == RouteMode::Exact && !adapter.supports_exact_mode() {
    return false;
  }
  if cfg.api_key.enabled {
    return false;
  }
  if !materialized_profile_matches_binding(cfg, store, agent, binding, mode) {
    return false;
  }
  let expected = match binding.profile.as_deref() {
    Some(profile) => format!("http://{}:{}/{profile}/v1", cfg.server.host, cfg.server.port),
    None => default_base.clone(),
  };
  match agent {
    AgentId::Opencode => {
      if read_jsonc(config_path).is_err() {
        return false;
      }
      let Ok(raw) = std::fs::read_to_string(config_path) else {
        return false;
      };
      with_opencode_projection(cfg, store, agent, binding, mode, |projection| {
        projected_config_matches(&raw, config_path, projection)
      })
      .unwrap_or(false)
    }
    AgentId::CodexCli => std::fs::read_to_string(config_path)
      .ok()
      .and_then(|raw| raw.parse::<toml_edit::DocumentMut>().ok())
      .is_some_and(|doc| codex_config_matches(&doc, &expected)),
    _ => false,
  }
}

fn opencode_source_auth_is_absent(home: &Path, agent: &AgentId, cfg: &Config, store: &AuthStore) -> bool {
  if *agent != AgentId::Opencode
    || cfg
      .agents
      .get(agent.as_str())
      .is_none_or(|binding| binding.account_source != AgentAccountSource::Agent)
  {
    return true;
  }
  let transferred_sources = linked_agent_accounts(store, agent)
    .into_iter()
    .filter_map(source_provider_id)
    .collect::<BTreeSet<_>>();
  if transferred_sources.is_empty() {
    return true;
  }
  let auth_path = crate::opencode_markdown::opencode_data_root(home).join("auth.json");
  if !auth_path.exists() {
    return true;
  }
  let Ok(raw) = std::fs::read_to_string(&auth_path) else {
    return false;
  };
  let Ok(auth) = serde_json::from_str::<serde_json::Value>(&raw) else {
    return false;
  };
  auth
    .as_object()
    .is_some_and(|auth| transferred_sources.iter().all(|provider| !auth.contains_key(*provider)))
}

fn with_opencode_projection<T>(
  cfg: &Config,
  store: &AuthStore,
  agent: &AgentId,
  binding: &AgentConfig,
  mode: RouteMode,
  inspect: impl FnOnce(&AgentConfigProjection<'_>) -> Result<T>,
) -> Result<T> {
  let profile_name = binding.profile.as_deref().ok_or_else(|| {
    anyhow!(
      "OpenCode binding is missing its generated profile; unlink and relink {}",
      agent
    )
  })?;
  let profile = cfg
    .profiles
    .get(profile_name)
    .ok_or_else(|| anyhow!("OpenCode binding profile '{profile_name}' is missing"))?;
  let provider_ids = profile
    .providers
    .clone()
    .or_else(|| {
      profile
        .default_provider_id
        .as_ref()
        .map(|provider| vec![provider.clone()])
    })
    .ok_or_else(|| anyhow!("OpenCode binding profile '{profile_name}' has no provider scope"))?;
  let target_base_url = gateway_profile_base_url(cfg, profile_name);

  let (accounts, publication_routes, credential_routes) = match binding.account_source {
    AgentAccountSource::Main => {
      let effective_accounts = effective_main_accounts(cfg, store);
      let provider_scope = provider_ids.iter().map(String::as_str).collect::<BTreeSet<_>>();
      if provider_scope
        .iter()
        .any(|provider| !effective_accounts.iter().any(|account| account.provider == *provider))
      {
        return Err(anyhow!(
          "OpenCode main-account binding has no effective account for every materialized provider"
        ));
      }
      let accounts = effective_accounts
        .into_iter()
        .filter(|account| provider_scope.contains(account.provider.as_str()))
        .collect::<Vec<_>>();
      let default_provider = is_verbatim_mode(mode)
        .then(|| {
          binding
            .provider
            .as_deref()
            .ok_or_else(|| anyhow!("OpenCode verbatim binding has no desired provider"))
        })
        .transpose()?;
      let routes: Vec<ProviderRoute> = provider_ids
        .iter()
        .map(|provider| ProviderRoute {
          source_provider_id: crate::adapters::opencode::source_namespace_for_gateway(provider).to_string(),
          gateway_provider_id: default_provider.unwrap_or(provider).to_string(),
          account_id: String::new(),
          profile: profile_name.to_string(),
          base_url: target_base_url.clone(),
          transfer_source_auth: false,
        })
        .collect();
      (accounts, routes.clone(), routes)
    }
    AgentAccountSource::Agent => {
      let linked_accounts = linked_agent_accounts(store, agent);
      let accounts = linked_accounts
        .iter()
        .filter(|account| account.enabled)
        .map(|account| (*account).clone())
        .collect::<Vec<_>>();
      if accounts.is_empty() {
        return Err(anyhow!("OpenCode agent-account binding has no enabled linked accounts"));
      }
      if is_verbatim_mode(mode) {
        for provider in accounts
          .iter()
          .map(|account| account.provider.as_str())
          .collect::<BTreeSet<_>>()
        {
          let account_ids = accounts
            .iter()
            .filter(|account| account.provider == provider)
            .map(|account| account.id.as_str())
            .collect::<BTreeSet<_>>();
          if !materialized_provider_profile_matches_binding(cfg, agent, binding, mode, provider, &account_ids) {
            return Err(anyhow!(
              "OpenCode provider profile for '{provider}' does not match its linked accounts"
            ));
          }
        }
      }
      let routes_for = |accounts: &[&Account]| {
        accounts
          .iter()
          .map(|account| {
            let source_provider_id = source_provider_id(account)
              .ok_or_else(|| anyhow!("linked OpenCode account '{}' has no source provider", account.id))?;
            let route_profile = format!("{profile_name}-{}", account.provider);
            Ok(ProviderRoute {
              source_provider_id: source_provider_id.to_string(),
              gateway_provider_id: account.provider.clone(),
              account_id: account.id.clone(),
              profile: route_profile.clone(),
              base_url: gateway_profile_base_url(cfg, &route_profile),
              transfer_source_auth: false,
            })
          })
          .collect::<Result<Vec<_>>>()
      };
      let credential_routes = routes_for(&linked_accounts)?;
      let enabled_accounts = linked_accounts
        .iter()
        .copied()
        .filter(|account| account.enabled)
        .collect::<Vec<_>>();
      let publication_routes = routes_for(&enabled_accounts)?;
      (accounts, publication_routes, credential_routes)
    }
  };
  let publication_plan = compile_opencode_publications(
    mode,
    Some(mode),
    Some(&provider_ids),
    &target_base_url,
    &accounts,
    &publication_routes,
    tokn_core::provider::Endpoint::ChatCompletions,
  )?;
  inspect(&AgentConfigProjection {
    target_base_url: &target_base_url,
    mode,
    previous_mode: Some(mode),
    credential_routes: &credential_routes,
    publications: &publication_plan.publications,
    model_reference_rules: &publication_plan.model_reference_rules,
  })
}

fn gateway_profile_base_url(cfg: &Config, profile: &str) -> String {
  format!("http://{}:{}/{profile}/v1", cfg.server.host, cfg.server.port)
}

fn materialized_profile_matches_binding(
  cfg: &Config,
  store: &AuthStore,
  agent: &AgentId,
  binding: &AgentConfig,
  mode: RouteMode,
) -> bool {
  let Some(profile_name) = binding.profile.as_deref() else {
    return false;
  };
  let Some(profile) = cfg.profiles.get(profile_name) else {
    return false;
  };
  if profile.agent_id.as_ref() != Some(agent) || profile.mode != Some(mode) {
    return false;
  }
  if binding.account_source == AgentAccountSource::Main {
    if profile.accounts.is_some() {
      return false;
    }
    if is_verbatim_mode(mode) {
      let Some(provider) = binding.provider.as_deref() else {
        return false;
      };
      return profile.default_provider_id.as_deref() == Some(provider)
        && option_string_set(profile.providers.as_deref()) == Some(BTreeSet::from([provider]));
    }
    let expected_provider_ids = binding
      .provider_filter
      .as_deref()
      .filter(|providers| !providers.is_empty())
      .map(|providers| providers.iter().map(String::as_str).collect())
      .unwrap_or_else(|| effective_main_provider_ids(cfg, store));
    return binding.provider.is_none()
      && profile.default_provider_id.is_none()
      && option_string_set(profile.providers.as_deref()) == Some(expected_provider_ids);
  }

  let accounts = linked_agent_accounts(store, agent)
    .into_iter()
    .filter(|account| account.enabled)
    .collect::<Vec<_>>();
  if accounts.is_empty() {
    return false;
  }
  let expected_account_ids = Some(accounts.iter().map(|account| account.id.as_str()).collect());
  let expected_provider_ids: Option<BTreeSet<&str>> =
    Some(accounts.iter().map(|account| account.provider.as_str()).collect());
  let default_provider_matches = if is_verbatim_mode(mode) {
    profile.default_provider_id.as_deref().is_some_and(|provider| {
      expected_provider_ids
        .as_ref()
        .is_some_and(|providers| providers.contains(provider))
    })
  } else {
    profile.default_provider_id.is_none()
  };
  default_provider_matches
    && option_string_set(profile.accounts.as_deref()) == expected_account_ids
    && option_string_set(profile.providers.as_deref()) == expected_provider_ids
}

fn linked_agent_accounts<'a>(store: &'a AuthStore, agent: &AgentId) -> Vec<&'a tokn_config::Account> {
  store
    .accounts
    .iter()
    .filter(|account| is_source_managed_account(account, agent))
    .filter(|account| store.account_source(&account.id) == Some(AuthSource::Shard(agent.as_str().to_string())))
    .collect()
}

fn effective_main_provider_ids<'a>(cfg: &Config, store: &'a AuthStore) -> BTreeSet<&'a str> {
  store
    .accounts
    .iter()
    .filter(|account| account.enabled)
    .filter(|account| {
      cfg
        .defaults
        .providers
        .as_ref()
        .map(|providers| providers.contains(&account.provider))
        .unwrap_or(true)
    })
    .filter(|account| {
      cfg
        .defaults
        .accounts
        .as_ref()
        .map(|accounts| accounts.contains(&account.id))
        .unwrap_or(true)
    })
    .map(|account| account.provider.as_str())
    .collect()
}

fn effective_main_accounts(cfg: &Config, store: &AuthStore) -> Vec<Account> {
  store
    .accounts
    .iter()
    .filter(|account| account.enabled)
    .filter(|account| {
      cfg
        .defaults
        .providers
        .as_ref()
        .map(|providers| providers.contains(&account.provider))
        .unwrap_or(true)
    })
    .filter(|account| {
      cfg
        .defaults
        .accounts
        .as_ref()
        .map(|accounts| accounts.contains(&account.id))
        .unwrap_or(true)
    })
    .cloned()
    .collect()
}

fn option_string_set(values: Option<&[String]>) -> Option<BTreeSet<&str>> {
  values.map(|values| values.iter().map(String::as_str).collect())
}

fn materialized_provider_profile_matches_binding(
  cfg: &Config,
  agent: &AgentId,
  binding: &AgentConfig,
  mode: RouteMode,
  provider: &str,
  account_ids: &BTreeSet<&str>,
) -> bool {
  let Some(profile_name) = binding.profile.as_deref() else {
    return false;
  };
  let provider_profile_name = format!("{profile_name}-{provider}");
  cfg.profiles.get(&provider_profile_name).is_some_and(|profile| {
    profile.agent_id.as_ref() == Some(agent)
      && profile.mode == Some(mode)
      && profile.default_provider_id.as_deref() == Some(provider)
      && option_string_set(profile.providers.as_deref()) == Some(BTreeSet::from([provider]))
      && option_string_set(profile.accounts.as_deref()) == Some(account_ids.clone())
  })
}

fn is_verbatim_mode(mode: RouteMode) -> bool {
  matches!(mode, RouteMode::Passthrough | RouteMode::Switch)
}

fn codex_config_matches(doc: &toml_edit::DocumentMut, expected_base_url: &str) -> bool {
  if doc.get("model_provider").and_then(toml_edit::Item::as_str) != Some("tokn-router") {
    return false;
  }
  let Some(provider) = doc
    .get("model_providers")
    .and_then(toml_edit::Item::as_table_like)
    .and_then(|providers| providers.get("tokn-router"))
    .and_then(toml_edit::Item::as_table_like)
  else {
    return false;
  };
  provider.get("name").and_then(toml_edit::Item::as_str) == Some("tokn-router")
    && provider.get("base_url").and_then(toml_edit::Item::as_str) == Some(expected_base_url)
    && provider.get("env_key").and_then(toml_edit::Item::as_str) == Some("OPENAI_API_KEY")
    && provider.get("wire_api").and_then(toml_edit::Item::as_str) == Some("responses")
}

fn resolve_home(agent_home: Option<&Path>) -> Result<PathBuf> {
  match agent_home {
    Some(home) => Ok(home.to_path_buf()),
    None => directories::BaseDirs::new()
      .map(|dirs| dirs.home_dir().to_path_buf())
      .ok_or_else(|| anyhow::anyhow!("cannot resolve home directory")),
  }
}

fn resolve_gateway_auth_path(gateway_auth_path: Option<&Path>) -> Result<PathBuf> {
  match gateway_auth_path {
    Some(path) => Ok(path.to_path_buf()),
    None => tokn_auth::default_auth_path(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_account(id: &str, provider: &str) -> tokn_config::Account {
    tokn_config::Account {
      id: id.into(),
      provider: provider.into(),
      enabled: true,
      tier: tokn_core::account::AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: Some(tokn_config::AuthType::Bearer),
      username: None,
      api_key: Some(tokn_core::util::secret::Secret::new("test-key".into())),
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

  fn mark_imported(account: &mut tokn_config::Account, source_provider: &str) {
    account.tags.push("source:opencode".into());
    let mut import = toml::Table::new();
    import.insert("source_agent".into(), toml::Value::String("opencode".into()));
    import.insert("source_provider".into(), toml::Value::String(source_provider.into()));
    import.insert("ownership".into(), toml::Value::String("gateway".into()));
    account.settings.insert("import".into(), toml::Value::Table(import));
  }

  fn config_with_opencode_binding(
    mode: RouteMode,
    account_source: AgentAccountSource,
    default_provider_id: Option<&str>,
    account_ids: &[&str],
  ) -> Config {
    let mut cfg = Config::default();
    let provider_filter = (account_source != AgentAccountSource::Main || !is_verbatim_mode(mode))
      .then(|| vec![tokn_core::provider::ID_OPENAI.to_string()]);
    let profile_providers = match account_source {
      AgentAccountSource::Main if is_verbatim_mode(mode) => {
        default_provider_id.map(|provider| vec![provider.to_string()])
      }
      AgentAccountSource::Main => provider_filter.clone(),
      AgentAccountSource::Agent if account_ids.is_empty() => Some(vec![tokn_core::provider::ID_OPENAI.to_string()]),
      AgentAccountSource::Agent => Some(
        account_ids
          .iter()
          .filter_map(|account_id| account_id.strip_prefix("opencode-"))
          .map(str::to_string)
          .collect(),
      ),
    };
    cfg.agents.insert(
      AgentId::Opencode.as_str().into(),
      AgentConfig {
        mode: Some(mode),
        profile: Some("work".into()),
        account_source,
        provider: (account_source == AgentAccountSource::Main && is_verbatim_mode(mode)).then(|| {
          default_provider_id
            .expect("raw main binding needs a provider")
            .to_string()
        }),
        provider_filter,
        source_providers: None,
        sync: true,
      },
    );
    cfg.profiles.insert(
      "work".into(),
      tokn_config::ProfileConfig {
        mode: Some(mode),
        agent_id: Some(AgentId::Opencode),
        default_provider_id: default_provider_id.map(str::to_string),
        providers: profile_providers,
        accounts: (!account_ids.is_empty()).then(|| account_ids.iter().map(|id| (*id).into()).collect()),
        model_families: None,
      },
    );
    cfg
  }

  fn write_synced_opencode_config(path: &Path, cfg: &Config, store: &AuthStore) {
    let binding = cfg.agents.get(AgentId::Opencode.as_str()).unwrap();
    let mode = binding.mode.unwrap_or(RouteMode::Route);
    let rewritten = with_opencode_projection(cfg, store, &AgentId::Opencode, binding, mode, |projection| {
      crate::adapters::opencode::rewrite_projected_config_text("{}\n", path, projection)
    })
    .unwrap();
    std::fs::write(path, rewritten).unwrap();
  }

  fn mutate_opencode_config(path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let mut json = crate::jsonc::read_jsonc(path).unwrap();
    mutate(&mut json);
    std::fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
  }

  fn add_generated_provider_profile(cfg: &mut Config, mode: RouteMode, provider: &str) {
    cfg.profiles.insert(
      format!("work-{provider}"),
      tokn_config::ProfileConfig {
        mode: Some(mode),
        agent_id: Some(AgentId::Opencode),
        default_provider_id: Some(provider.into()),
        providers: Some(vec![provider.into()]),
        accounts: Some(vec![format!("opencode-{provider}")]),
        model_families: None,
      },
    );
  }

  fn status_manifest(
    gateway_config_fragment_path: &Path,
    account_source: AgentAccountSource,
  ) -> crate::manifest::MigrationManifest {
    crate::manifest::MigrationManifest {
      version: 4,
      completed: true,
      agent: AgentId::Opencode,
      timestamp: "20260729T000000Z".into(),
      profile: Some("work".into()),
      target_base_url: "http://127.0.0.1:4141/work/v1".into(),
      gateway_auth_path: None,
      gateway_auth_shard_path: (account_source == AgentAccountSource::Agent)
        .then(|| gateway_config_fragment_path.with_file_name("opencode-auth.yaml")),
      agent_auth_path: None,
      provider_routes: Vec::new(),
      previous_manifest: None,
      unlinked: false,
      credentials_handoff_complete: true,
      imported_account_ids: Vec::new(),
      files: vec![crate::manifest::FileBackup {
        original: gateway_config_fragment_path.to_path_buf(),
        backup: None,
        existed: false,
        created_by_migration: true,
        applied_sha256: None,
      }],
    }
  }

  #[test]
  fn status_without_a_manifest_preserves_legacy_semantic_checks() {
    assert!(manifest_boundary_matches(
      None,
      Path::new("config.toml"),
      &AgentId::Opencode,
      AgentAccountSource::Agent,
    ));
  }

  #[test]
  fn active_manifest_account_source_must_match_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let fragment_path =
      tokn_config::paths::agent_config_fragment_path(&gateway_config_path, AgentId::Opencode.as_str());

    let main_manifest = status_manifest(&fragment_path, AgentAccountSource::Main);
    assert!(manifest_boundary_matches(
      Some(&main_manifest),
      &gateway_config_path,
      &AgentId::Opencode,
      AgentAccountSource::Main,
    ));
    assert!(!manifest_boundary_matches(
      Some(&main_manifest),
      &gateway_config_path,
      &AgentId::Opencode,
      AgentAccountSource::Agent,
    ));

    let agent_manifest = status_manifest(&fragment_path, AgentAccountSource::Agent);
    assert!(manifest_boundary_matches(
      Some(&agent_manifest),
      &gateway_config_path,
      &AgentId::Opencode,
      AgentAccountSource::Agent,
    ));
    assert!(!manifest_boundary_matches(
      Some(&agent_manifest),
      &gateway_config_path,
      &AgentId::Opencode,
      AgentAccountSource::Main,
    ));
  }

  #[test]
  fn active_manifest_must_be_complete_and_scoped_to_the_gateway_config() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_config_path = dir.path().join("config.toml");
    let fragment_path =
      tokn_config::paths::agent_config_fragment_path(&gateway_config_path, AgentId::Opencode.as_str());
    let manifest = status_manifest(&fragment_path, AgentAccountSource::Main);

    let incomplete = crate::manifest::MigrationManifest {
      completed: false,
      ..manifest.clone()
    };
    assert!(!manifest_boundary_matches(
      Some(&incomplete),
      &gateway_config_path,
      &AgentId::Opencode,
      AgentAccountSource::Main,
    ));

    let different_gateway_config_path = dir.path().join("other.toml");
    assert!(!manifest_boundary_matches(
      Some(&manifest),
      &different_gateway_config_path,
      &AgentId::Opencode,
      AgentAccountSource::Main,
    ));

    let different_agent = crate::manifest::MigrationManifest {
      agent: AgentId::CodexCli,
      ..manifest
    };
    assert!(!manifest_boundary_matches(
      Some(&different_agent),
      &gateway_config_path,
      &AgentId::Opencode,
      AgentAccountSource::Main,
    ));
  }

  #[test]
  fn list_agents_reports_binding_detection_and_imported_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let auth_path = dir.path().join("auth.yaml");
    let home = dir.path().join("home");
    std::fs::write(
      &config_path,
      r#"
[agents.opencode]
profile = "work"
mode = "route"
sync = true

[profiles.work]
mode = "route"
agent_id = "opencode"
providers = ["openai"]
accounts = ["opencode-openai"]
"#,
    )
    .unwrap();
    let opencode_config = home.join(".config/opencode/opencode.jsonc");
    std::fs::create_dir_all(opencode_config.parent().unwrap()).unwrap();
    let mut store = AuthStore::load(Some(&auth_path), Some(&config_path)).unwrap();
    let mut account = sample_account("opencode-openai", "openai");
    mark_imported(&mut account, "openai");
    store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();
    let mut historical = sample_account("opencode-codex", "codex");
    historical.enabled = false;
    historical.tags.push("source:opencode".into());
    let mut historical_import = toml::Table::new();
    historical_import.insert("source_agent".into(), toml::Value::String("opencode".into()));
    historical_import.insert("source_provider".into(), toml::Value::String("openai".into()));
    historical
      .settings
      .insert("import".into(), toml::Value::Table(historical_import));
    store.upsert(historical);
    store.save().unwrap();
    let cfg = Config::load(Some(&config_path)).unwrap().0;
    write_synced_opencode_config(&opencode_config, &cfg, &store);
    let raw = std::fs::read_to_string(&opencode_config).unwrap();
    std::fs::write(
      &opencode_config,
      raw.replacen('{', "{\n  // opencode may store this as JSONC.", 1),
    )
    .unwrap();

    assert!(config_points_at_gateway(
      &opencode_config,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
    let statuses = list_agents(Some(&config_path), Some(&auth_path), Some(&home)).unwrap();
    let opencode = statuses
      .iter()
      .find(|status| status.agent == AgentId::Opencode)
      .unwrap();
    assert!(opencode.detected);
    assert_eq!(opencode.config_path, opencode_config);
    assert_eq!(opencode.binding.as_ref().unwrap().profile.as_deref(), Some("work"));
    assert_eq!(opencode.imported_account_ids, vec!["opencode-codex", "opencode-openai"]);
  }

  #[test]
  fn normalized_modes_expect_one_shared_provider_at_the_binding_profile() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("opencode-openai", "openai");
    mark_imported(&mut account, "openai");
    store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();

    for mode in [RouteMode::Route, RouteMode::Fuzzy, RouteMode::Exact] {
      let cfg = config_with_opencode_binding(mode, AgentAccountSource::Agent, None, &["opencode-openai"]);
      write_synced_opencode_config(&config_path, &cfg, &store);
      assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));
    }

    let cfg = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Agent, None, &["opencode-openai"]);
    write_synced_opencode_config(&config_path, &cfg, &store);
    mutate_opencode_config(&config_path, |json| {
      let provider = json["provider"]
        .as_object_mut()
        .unwrap()
        .remove(SHARED_PROVIDER_ID)
        .unwrap();
      json["provider"]["openai"] = provider;
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn semantic_status_detects_model_and_managed_provider_drift() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.jsonc");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    store.upsert(sample_account("main-openai", "openai"));
    let cfg = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Main, None, &[]);

    write_synced_opencode_config(&config_path, &cfg, &store);
    let model_id = crate::jsonc::read_jsonc(&config_path).unwrap()["provider"][SHARED_PROVIDER_ID]["models"]
      .as_object()
      .unwrap()
      .keys()
      .next()
      .unwrap()
      .clone();
    mutate_opencode_config(&config_path, |json| {
      json["provider"][SHARED_PROVIDER_ID]["models"]
        .as_object_mut()
        .unwrap()
        .remove(&model_id);
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    write_synced_opencode_config(&config_path, &cfg, &store);
    mutate_opencode_config(&config_path, |json| {
      json["provider"][SHARED_PROVIDER_ID]["models"]["unselected-custom"] =
        serde_json::json!({"name": "unselected-custom"});
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    write_synced_opencode_config(&config_path, &cfg, &store);
    mutate_opencode_config(&config_path, |json| {
      json["model"] = "tokn-router/selected-custom".into();
      json["provider"][SHARED_PROVIDER_ID]["models"]["selected-custom"] =
        serde_json::json!({"name": "selected-custom"});
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    write_synced_opencode_config(&config_path, &cfg, &store);
    mutate_opencode_config(&config_path, |json| {
      let mut stale = json["provider"][SHARED_PROVIDER_ID].clone();
      stale["name"] = "Tokn Router (DeepSeek)".into();
      stale["options"]["baseURL"] = "http://127.0.0.1:4141/work-deepseek/v1".into();
      json["provider"]["tokn-router-deepseek"] = stale;
      json["enabled_providers"] = serde_json::json!(["tokn-router", "tokn-router-deepseek"]);
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn main_normalized_profile_provider_scope_must_match_the_binding_filter() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    store.upsert(sample_account("main-openai", "openai"));
    let mut cfg = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Main, None, &[]);
    write_synced_opencode_config(&config_path, &cfg, &store);
    assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));

    store.accounts[0].enabled = false;
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
    store.accounts[0].enabled = true;

    cfg.profiles.get_mut("work").unwrap().providers = Some(vec!["deepseek".into()]);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn main_normalized_auto_discovery_matches_the_effective_account_providers() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    store.upsert(sample_account("main-openai", "openai"));
    store.upsert(sample_account("main-deepseek", "deepseek"));

    let mut cfg = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Main, None, &[]);
    cfg.agents.get_mut(AgentId::Opencode.as_str()).unwrap().provider_filter = None;
    cfg.profiles.get_mut("work").unwrap().providers = Some(vec!["deepseek".into(), "openai".into()]);
    write_synced_opencode_config(&config_path, &cfg, &store);
    assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));

    cfg.agents.get_mut(AgentId::Opencode.as_str()).unwrap().provider_filter = Some(Vec::new());
    assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));

    cfg.defaults.accounts = Some(vec!["main-openai".into()]);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn agent_base_profile_allowlists_must_match_the_linked_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("opencode-openai", "openai");
    mark_imported(&mut account, "openai");
    store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();
    let mut disabled = sample_account("opencode-deepseek", "deepseek");
    disabled.enabled = false;
    mark_imported(&mut disabled, "deepseek");
    store.upsert_in_shard(AgentId::Opencode.as_str(), disabled).unwrap();

    let mut cfg = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Agent, None, &["opencode-openai"]);
    write_synced_opencode_config(&config_path, &cfg, &store);
    assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));

    mutate_opencode_config(&config_path, |json| {
      json["enabled_providers"] = serde_json::json!(["deepseek", "tokn-router"]);
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
    write_synced_opencode_config(&config_path, &cfg, &store);

    let openai = store
      .accounts
      .iter()
      .position(|account| account.id == "opencode-openai")
      .unwrap();
    store.accounts[openai].enabled = false;
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
    store.accounts[openai].enabled = true;

    let profile = cfg.profiles.get_mut("work").unwrap();
    profile.accounts = Some(vec!["opencode-deepseek".into(), "opencode-openai".into()]);
    profile.providers = Some(vec!["deepseek".into(), "openai".into()]);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    let profile = cfg.profiles.get_mut("work").unwrap();
    profile.accounts = Some(vec!["opencode-openai".into()]);
    profile.providers = Some(vec!["deepseek".into()]);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn generated_profile_mode_and_owner_must_match_the_binding() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("opencode-openai", "openai");
    mark_imported(&mut account, "openai");
    store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();

    let mut cfg = config_with_opencode_binding(RouteMode::Exact, AgentAccountSource::Agent, None, &["opencode-openai"]);
    write_synced_opencode_config(&config_path, &cfg, &store);
    assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));

    cfg.profiles.get_mut("work").unwrap().mode = Some(RouteMode::Route);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    let profile = cfg.profiles.get_mut("work").unwrap();
    profile.mode = Some(RouteMode::Exact);
    profile.agent_id = Some(AgentId::CodexCli);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    cfg.profiles.remove("work");
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn binding_without_a_profile_is_not_a_materialized_link() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let store = AuthStore::load(Some(&auth_path), None).unwrap();
    std::fs::write(&config_path, "{}").unwrap();

    let mut cfg = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Agent, None, &[]);
    cfg.agents.get_mut(AgentId::Opencode.as_str()).unwrap().profile = None;
    cfg.profiles.clear();

    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn main_account_verbatim_modes_expect_the_pinned_default_provider() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    store.upsert(sample_account("main-deepseek", "deepseek"));

    for mode in [RouteMode::Switch, RouteMode::Passthrough] {
      let cfg = config_with_opencode_binding(mode, AgentAccountSource::Main, Some("deepseek"), &[]);
      write_synced_opencode_config(&config_path, &cfg, &store);
      assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));
    }

    let cfg = config_with_opencode_binding(RouteMode::Switch, AgentAccountSource::Main, Some("deepseek"), &[]);
    write_synced_opencode_config(&config_path, &cfg, &store);
    mutate_opencode_config(&config_path, |json| {
      let provider = json["provider"]
        .as_object_mut()
        .unwrap()
        .remove("tokn-router-deepseek")
        .unwrap();
      json["provider"]["tokn-router-openai"] = provider;
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    let mut cfg = config_with_opencode_binding(RouteMode::Switch, AgentAccountSource::Main, Some("deepseek"), &[]);
    write_synced_opencode_config(&config_path, &cfg, &store);
    cfg.agents.get_mut(AgentId::Opencode.as_str()).unwrap().provider = None;
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    cfg.agents.get_mut(AgentId::Opencode.as_str()).unwrap().provider = Some("openai".into());
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn agent_account_verbatim_modes_expect_each_canonical_provider_profile() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut openai = sample_account("opencode-openai", "openai");
    mark_imported(&mut openai, "openai-compatible");
    store.upsert_in_shard(AgentId::Opencode.as_str(), openai).unwrap();
    let mut deepseek = sample_account("opencode-deepseek", "deepseek");
    mark_imported(&mut deepseek, "legacy-deepseek");
    store.upsert_in_shard(AgentId::Opencode.as_str(), deepseek).unwrap();

    for mode in [RouteMode::Switch, RouteMode::Passthrough] {
      let mut cfg = config_with_opencode_binding(
        mode,
        AgentAccountSource::Agent,
        Some("openai"),
        &["opencode-openai", "opencode-deepseek"],
      );
      add_generated_provider_profile(&mut cfg, mode, "openai");
      add_generated_provider_profile(&mut cfg, mode, "deepseek");
      write_synced_opencode_config(&config_path, &cfg, &store);
      assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));
    }

    let mut cfg = config_with_opencode_binding(
      RouteMode::Switch,
      AgentAccountSource::Agent,
      Some("openai"),
      &["opencode-openai", "opencode-deepseek"],
    );
    add_generated_provider_profile(&mut cfg, RouteMode::Switch, "openai");
    add_generated_provider_profile(&mut cfg, RouteMode::Switch, "deepseek");
    write_synced_opencode_config(&config_path, &cfg, &store);
    mutate_opencode_config(&config_path, |json| {
      json["provider"]["tokn-router-deepseek"]["options"]["baseURL"] = "http://127.0.0.1:4141/work/v1".into();
    });
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn agent_account_verbatim_modes_validate_generated_provider_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("opencode-deepseek", "deepseek");
    mark_imported(&mut account, "deepseek");
    store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();

    let mut cfg = config_with_opencode_binding(
      RouteMode::Switch,
      AgentAccountSource::Agent,
      Some("deepseek"),
      &["opencode-deepseek"],
    );
    add_generated_provider_profile(&mut cfg, RouteMode::Switch, "deepseek");
    write_synced_opencode_config(&config_path, &cfg, &store);
    assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));

    cfg.profiles.remove("work-deepseek");
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    add_generated_provider_profile(&mut cfg, RouteMode::Switch, "deepseek");
    cfg.profiles.get_mut("work-deepseek").unwrap().agent_id = Some(AgentId::CodexCli);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    add_generated_provider_profile(&mut cfg, RouteMode::Switch, "deepseek");
    cfg.profiles.get_mut("work-deepseek").unwrap().mode = Some(RouteMode::Passthrough);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    add_generated_provider_profile(&mut cfg, RouteMode::Switch, "deepseek");
    cfg.profiles.get_mut("work-deepseek").unwrap().default_provider_id = Some("openai".into());
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn raw_provider_profile_allowlists_must_match_the_provider_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("opencode-deepseek", "deepseek");
    mark_imported(&mut account, "deepseek");
    store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();

    let mut cfg = config_with_opencode_binding(
      RouteMode::Switch,
      AgentAccountSource::Agent,
      Some("deepseek"),
      &["opencode-deepseek"],
    );
    add_generated_provider_profile(&mut cfg, RouteMode::Switch, "deepseek");
    write_synced_opencode_config(&config_path, &cfg, &store);
    assert!(config_points_at_gateway(&config_path, &AgentId::Opencode, &cfg, &store));

    cfg.profiles.get_mut("work-deepseek").unwrap().providers = Some(vec!["openai".into()]);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));

    let profile = cfg.profiles.get_mut("work-deepseek").unwrap();
    profile.providers = Some(vec!["deepseek".into()]);
    profile.accounts = Some(vec!["opencode-openai".into()]);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &cfg,
      &store
    ));
  }

  #[test]
  fn codex_status_requires_the_selected_provider_and_wire_api() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("codex-linked", tokn_core::provider::ID_CODEX);
    account.tags.push(format!("source:{}", AgentId::CodexCli.as_str()));
    let mut import = toml::Table::new();
    import.insert(
      "source_agent".into(),
      toml::Value::String(AgentId::CodexCli.as_str().into()),
    );
    import.insert("source_provider".into(), toml::Value::String("openai".into()));
    import.insert("ownership".into(), toml::Value::String("gateway".into()));
    account.settings.insert("import".into(), toml::Value::Table(import));
    store.upsert_in_shard(AgentId::CodexCli.as_str(), account).unwrap();
    let mut cfg = Config::default();
    cfg.agents.insert(
      AgentId::CodexCli.as_str().into(),
      AgentConfig {
        mode: Some(RouteMode::Route),
        profile: Some("work".into()),
        account_source: AgentAccountSource::Agent,
        provider: None,
        provider_filter: None,
        source_providers: None,
        sync: true,
      },
    );
    cfg.profiles.insert(
      "work".into(),
      tokn_config::ProfileConfig {
        mode: Some(RouteMode::Route),
        agent_id: Some(AgentId::CodexCli),
        default_provider_id: None,
        providers: Some(vec![tokn_core::provider::ID_CODEX.into()]),
        accounts: Some(vec!["codex-linked".into()]),
        model_families: None,
      },
    );
    let valid = r#"
model_provider = "tokn-router"

[model_providers.tokn-router]
name = "tokn-router"
base_url = "http://127.0.0.1:4141/work/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
"#;
    std::fs::write(&config_path, valid).unwrap();
    assert!(config_points_at_gateway(&config_path, &AgentId::CodexCli, &cfg, &store));

    cfg.agents.get_mut(AgentId::CodexCli.as_str()).unwrap().account_source = AgentAccountSource::Main;
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::CodexCli,
      &cfg,
      &store
    ));
    cfg.agents.get_mut(AgentId::CodexCli.as_str()).unwrap().account_source = AgentAccountSource::Agent;
    cfg.agents.get_mut(AgentId::CodexCli.as_str()).unwrap().mode = Some(RouteMode::Exact);
    cfg.profiles.get_mut("work").unwrap().mode = Some(RouteMode::Exact);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::CodexCli,
      &cfg,
      &store
    ));
    cfg.agents.get_mut(AgentId::CodexCli.as_str()).unwrap().mode = Some(RouteMode::Route);
    cfg.profiles.get_mut("work").unwrap().mode = Some(RouteMode::Route);

    cfg.agents.get_mut(AgentId::CodexCli.as_str()).unwrap().profile = None;
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::CodexCli,
      &cfg,
      &store
    ));
    cfg.agents.get_mut(AgentId::CodexCli.as_str()).unwrap().profile = Some("work".into());

    std::fs::write(
      &config_path,
      valid.replacen("model_provider = \"tokn-router\"\n", "", 1),
    )
    .unwrap();
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::CodexCli,
      &cfg,
      &store
    ));

    std::fs::write(&config_path, valid.replacen("wire_api = \"responses\"\n", "", 1)).unwrap();
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::CodexCli,
      &cfg,
      &store
    ));
  }

  #[test]
  fn generated_managed_clients_are_not_in_sync_with_api_key_enforcement() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("opencode.json");
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    store.upsert(sample_account("main-deepseek", "deepseek"));

    let mut managed = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Main, None, &[]);
    managed.api_key.enabled = true;
    managed.profiles.get_mut("work").unwrap().providers = Some(vec!["deepseek".into()]);
    managed
      .agents
      .get_mut(AgentId::Opencode.as_str())
      .unwrap()
      .provider_filter = Some(vec!["deepseek".into()]);
    write_synced_opencode_config(&config_path, &managed, &store);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &managed,
      &store
    ));

    let mut passthrough =
      config_with_opencode_binding(RouteMode::Passthrough, AgentAccountSource::Main, Some("deepseek"), &[]);
    passthrough.api_key.enabled = true;
    write_synced_opencode_config(&config_path, &passthrough, &store);
    assert!(!config_points_at_gateway(
      &config_path,
      &AgentId::Opencode,
      &passthrough,
      &store
    ));
  }

  #[test]
  fn agent_owned_status_detects_reintroduced_opencode_source_auth() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let auth_path = dir.path().join("gateway-auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("opencode-openai", "openai");
    mark_imported(&mut account, "openai");
    store.upsert_in_shard(AgentId::Opencode.as_str(), account).unwrap();
    let cfg = config_with_opencode_binding(RouteMode::Route, AgentAccountSource::Agent, None, &["opencode-openai"]);
    let source_auth_path = crate::opencode_markdown::opencode_data_root(&home).join("auth.json");
    std::fs::create_dir_all(source_auth_path.parent().unwrap()).unwrap();

    std::fs::write(&source_auth_path, r#"{"anthropic":{"type":"api","key":"retained"}}"#).unwrap();
    assert!(opencode_source_auth_is_absent(&home, &AgentId::Opencode, &cfg, &store));

    std::fs::write(&source_auth_path, r#"{"openai":{"type":"api","key":"reconnected"}}"#).unwrap();
    assert!(!opencode_source_auth_is_absent(&home, &AgentId::Opencode, &cfg, &store));
  }

  #[test]
  fn show_agent_reports_unbound_defaults_case() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let auth_path = dir.path().join("auth.yaml");
    let home = dir.path().join("home");
    let status = show_agent(Some(&config_path), Some(&auth_path), Some(&home), AgentId::CodexCli).unwrap();
    assert_eq!(status.agent, AgentId::CodexCli);
    assert!(status.binding.is_none());
    assert!(status.imported_account_ids.is_empty());
  }

  #[test]
  fn imported_account_helper_matches_source_markers() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.yaml");
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();
    let mut account = sample_account("x", "openai");
    account.tags.push("source:opencode".into());
    let mut import = toml::Table::new();
    import.insert("source_agent".into(), toml::Value::String("opencode".into()));
    account.settings.insert("import".into(), toml::Value::Table(import));
    store.upsert(account.clone());
    assert!(crate::reconcile::is_source_managed_account(
      &account,
      &AgentId::Opencode
    ));
    assert_eq!(imported_account_ids(&store, &AgentId::Opencode), vec!["x"]);
  }
}

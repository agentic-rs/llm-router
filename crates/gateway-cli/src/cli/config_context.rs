use crate::auth_registry::{known_providers, provider_auth_for, provider_descriptor_for};
use crate::config::Config;
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tokn_auth::ProviderAuth;
use tokn_core::account::AccountConfig;
use tokn_core::provider::official_provider_preset;
use tokn_policy::{AccountPoolPlan, GatewayPlan, RelayCredentials, RoutePlan};

/// The configuration details needed by account and credential commands.
///
/// This intentionally does not expose either complete schema. Account
/// management only needs the auth store location, outbound HTTP policy,
/// configured-provider mapping, and read-only account selection views.
pub struct ConfigContext {
  path: PathBuf,
  source: ConfigSource,
}

enum ConfigSource {
  Legacy(Box<Config>),
  V2(Box<tokn_config::v2::CompiledConfig>),
}

impl ConfigContext {
  pub(crate) fn from_v2(path: PathBuf, config: tokn_config::v2::CompiledConfig) -> Self {
    Self {
      path,
      source: ConfigSource::V2(Box::new(config)),
    }
  }

  pub fn load(explicit_path: Option<&Path>) -> Result<Self> {
    let path = explicit_path
      .map(Path::to_path_buf)
      .map(Ok)
      .unwrap_or_else(tokn_config::paths::config_path)?;
    let source = match tokn_config::detect_config_schema(&path)? {
      tokn_config::ConfigSchema::Legacy => {
        let (config, resolved_path) = Config::load(Some(&path))?;
        debug_assert_eq!(resolved_path, path);
        ConfigSource::Legacy(Box::new(config))
      }
      tokn_config::ConfigSchema::V2 => ConfigSource::V2(Box::new(tokn_config::v2::load_config(&path)?)),
    };
    Ok(Self { path, source })
  }

  pub fn path(&self) -> &Path {
    &self.path
  }

  pub fn build_http_client(&self, no_proxy: bool) -> Result<reqwest::Client> {
    tokn_core::util::http::build_client(&self.http_client_options(no_proxy))
  }

  fn http_client_options(&self, no_proxy: bool) -> tokn_core::util::http::HttpClientOptions {
    if no_proxy {
      tokn_core::util::http::HttpClientOptions::default()
    } else {
      match &self.source {
        ConfigSource::Legacy(config) => config.proxy.to_http_options(),
        ConfigSource::V2(config) => config.service().outbound().to_http_client_options(),
      }
    }
  }

  /// Provider ids available for onboarding. Disabled v2 presets are omitted.
  pub fn provider_ids(&self) -> Vec<String> {
    match &self.source {
      ConfigSource::Legacy(_) => known_providers().into_iter().map(str::to_string).collect(),
      ConfigSource::V2(config) => config
        .gateway()
        .providers()
        .iter()
        .filter_map(|(provider_id, provider)| {
          provider_descriptor_for(provider_id.as_str(), provider.driver().as_str())
            .and_then(|descriptor| descriptor.provider_auth())
            .map(|_| provider_id.to_string())
        })
        .collect(),
    }
  }

  /// Resolve an enabled provider for onboarding a new account.
  pub fn resolve_provider(&self, provider_id: &str) -> Result<ResolvedProviderAuth> {
    match &self.source {
      ConfigSource::Legacy(_) => ResolvedProviderAuth::legacy(provider_id),
      ConfigSource::V2(config) => {
        let Some((_, provider)) = config
          .gateway()
          .providers()
          .iter()
          .find(|(id, _)| id.as_str() == provider_id)
        else {
          bail!(
            "provider '{provider_id}' is not enabled by the v2 config. Try one of: {}",
            self.provider_ids().join(" | ")
          );
        };
        ResolvedProviderAuth::v2(
          provider_id,
          provider.driver().as_str(),
          provider.base_url().map(str::to_string),
        )
      }
    }
  }

  /// Resolve the provider attached to an existing stored account. An
  /// explicitly disabled official v2 provider remains resolvable so the CLI
  /// can inspect, refresh, or remove its stored accounts even though the
  /// serving runtime will not bind them.
  pub fn resolve_account_provider(&self, account: &AccountConfig) -> Result<ResolvedProviderAuth> {
    match self.resolve_provider(&account.provider) {
      Ok(provider) => Ok(provider),
      Err(error) => match &self.source {
        ConfigSource::V2(_) => {
          let Some(preset) = official_provider_preset(&account.provider) else {
            return Err(error);
          };
          ResolvedProviderAuth::v2(&account.provider, preset.driver, account.base_url.clone())
        }
        ConfigSource::Legacy(_) => Err(error),
      },
    }
  }

  /// Resolve a read-only account view against the effective configuration.
  ///
  /// Legacy profiles own account/provider filters directly. V2 profiles are
  /// deliberately indirect, so they resolve through their route to the pool
  /// that owns account selection.
  pub fn resolve_account_view(&self, pool: Option<&str>, profile: Option<&str>) -> Result<Option<AccountView>> {
    if pool.is_some() && profile.is_some() {
      bail!("`--pool` and `--profile` are mutually exclusive");
    }

    match (&self.source, pool, profile) {
      (_, None, None) => Ok(None),
      (ConfigSource::Legacy(_), Some(_), None) => {
        bail!("`--pool` requires a schema_version = 2 configuration")
      }
      (ConfigSource::Legacy(config), None, Some(profile_id)) => {
        let profile = config
          .profiles
          .get(profile_id)
          .ok_or_else(|| anyhow!("unknown profile '{profile_id}'"))?;
        Ok(Some(AccountView {
          description: format!("profile '{profile_id}'"),
          accounts: profile
            .accounts
            .clone()
            .or_else(|| config.defaults.accounts.clone())
            .map(|accounts| accounts.into_iter().collect()),
          providers: profile
            .providers
            .clone()
            .or_else(|| config.defaults.providers.clone())
            .map(|providers| providers.into_iter().collect()),
        }))
      }
      (ConfigSource::V2(config), Some(pool_id), None) => {
        let gateway = config.gateway();
        let (canonical_id, pool) = find_pool(gateway, pool_id)?;
        Ok(Some(v2_account_view(gateway, pool, format!("pool '{canonical_id}'"))))
      }
      (ConfigSource::V2(config), None, Some(profile_id)) => {
        let gateway = config.gateway();
        let (canonical_profile_id, profile) = gateway
          .profiles()
          .iter()
          .find(|(id, _)| id.as_str() == profile_id)
          .ok_or_else(|| anyhow!("unknown profile '{profile_id}'"))?;
        let route_id = profile.route();
        let route = gateway
          .route(route_id)
          .expect("compiled v2 profile references an existing route");
        let pool_id = route_account_pool(route)
          .ok_or_else(|| anyhow!("profile '{canonical_profile_id}' uses client credentials and has no account pool"))?;
        let pool = gateway
          .account_pool(pool_id)
          .expect("compiled v2 route references an existing account pool");
        Ok(Some(v2_account_view(
          gateway,
          pool,
          format!("profile '{canonical_profile_id}' -> route '{route_id}' -> pool '{pool_id}'"),
        )))
      }
      _ => unreachable!("pool/profile exclusivity checked above"),
    }
  }
}

/// A configuration-derived filter for read-only account commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountView {
  description: String,
  accounts: Option<BTreeSet<String>>,
  providers: Option<BTreeSet<String>>,
}

impl AccountView {
  pub fn description(&self) -> &str {
    &self.description
  }

  pub fn contains(&self, account: &AccountConfig) -> bool {
    self
      .accounts
      .as_ref()
      .is_none_or(|accounts| accounts.contains(&account.id))
      && self
        .providers
        .as_ref()
        .is_none_or(|providers| providers.contains(&account.provider))
  }
}

fn find_pool<'a>(gateway: &'a GatewayPlan, requested_id: &str) -> Result<(&'a str, &'a AccountPoolPlan)> {
  gateway
    .account_pools()
    .iter()
    .find(|(id, _)| id.as_str() == requested_id)
    .map(|(id, pool)| (id.as_str(), pool))
    .ok_or_else(|| anyhow!("unknown account pool '{requested_id}'"))
}

fn v2_account_view(gateway: &GatewayPlan, pool: &AccountPoolPlan, description: String) -> AccountView {
  let selector = pool.selector();
  let accounts = selector
    .accounts()
    .map(|accounts| accounts.iter().map(ToString::to_string).collect());
  let providers = selector
    .providers()
    .map(|providers| providers.iter().map(ToString::to_string).collect())
    .unwrap_or_else(|| gateway.providers().keys().map(ToString::to_string).collect());
  AccountView {
    description,
    accounts,
    providers: Some(providers),
  }
}

fn route_account_pool(route: &RoutePlan) -> Option<&tokn_policy::AccountPoolId> {
  match route {
    RoutePlan::Managed(route) => Some(route.target().account_pool()),
    RoutePlan::Relay(route) => match route.credentials() {
      RelayCredentials::Client => None,
      RelayCredentials::AccountPool(account_pool) => Some(account_pool),
    },
  }
}

/// Auth behavior resolved for one configured provider destination.
///
/// `provider_id` is the v2 destination identity stored in `auth.yaml`.
/// `auth` is supplied by the reusable driver. `base_url` is applied only to
/// temporary copies used for credential verification; v2 keeps destination
/// ownership in config rather than duplicating it into stored accounts.
#[derive(Clone)]
pub struct ResolvedProviderAuth {
  provider_id: String,
  auth: &'static dyn ProviderAuth,
  base_url: Option<String>,
  provider_owns_base_url: bool,
}

impl ResolvedProviderAuth {
  pub fn legacy(provider_id: &str) -> Result<Self> {
    let auth = provider_auth_for(provider_id).ok_or_else(|| anyhow!("unknown provider '{provider_id}'"))?;
    Ok(Self {
      provider_id: provider_id.to_string(),
      auth,
      base_url: auth.default_base_url().map(str::to_string),
      provider_owns_base_url: false,
    })
  }

  fn v2(provider_id: &str, driver_id: &str, configured_base_url: Option<String>) -> Result<Self> {
    let descriptor = provider_descriptor_for(provider_id, driver_id)
      .ok_or_else(|| anyhow!("provider '{provider_id}' uses unknown driver '{driver_id}'"))?;
    let auth = descriptor
      .provider_auth()
      .ok_or_else(|| anyhow!("provider '{provider_id}' does not support account credentials"))?;
    Ok(Self {
      provider_id: provider_id.to_string(),
      auth,
      base_url: Some(configured_base_url.unwrap_or_else(|| descriptor.base_url.to_string())),
      provider_owns_base_url: true,
    })
  }

  pub fn provider_id(&self) -> &str {
    &self.provider_id
  }

  pub fn auth(&self) -> &'static dyn ProviderAuth {
    self.auth
  }

  fn prepare_for_auth(&self, account: &mut AccountConfig) {
    account.provider = self.auth.id().to_string();
    if self.provider_owns_base_url || account.base_url.is_none() {
      account.base_url.clone_from(&self.base_url);
    }
  }

  pub fn account_for_auth(&self, account: &AccountConfig) -> AccountConfig {
    let mut account = account.clone();
    self.prepare_for_auth(&mut account);
    account
  }

  /// Restore the configured provider identity before persistence. In v2 the
  /// provider config remains the sole owner of the destination URL.
  pub fn finish_account(&self, account: &mut AccountConfig) {
    account.provider.clone_from(&self.provider_id);
    if self.provider_owns_base_url {
      account.base_url = None;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::account::{AccountTier, AuthType};

  fn account(provider: &str, base_url: Option<&str>) -> AccountConfig {
    AccountConfig {
      id: "test".into(),
      provider: provider.into(),
      enabled: true,
      tier: AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: base_url.map(str::to_string),
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

  #[test]
  fn v2_custom_provider_uses_driver_for_auth_but_preserves_destination_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
      &path,
      r#"
schema_version = 2

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[providers.company-openai]
driver = "openai"
base_url = "https://llm.example.test/v1"
"#,
    )
    .unwrap();
    let context = ConfigContext::load(Some(&path)).unwrap();
    let provider = context.resolve_provider("company-openai").unwrap();
    let stored = account("company-openai", None);

    let auth_account = provider.account_for_auth(&stored);
    assert_eq!(provider.auth().id(), "openai");
    assert_eq!(auth_account.provider, "openai");
    assert_eq!(auth_account.base_url.as_deref(), Some("https://llm.example.test/v1/"));

    let mut newly_created = auth_account;
    provider.finish_account(&mut newly_created);
    assert_eq!(newly_created.provider, "company-openai");
    assert_eq!(newly_created.base_url, None);

    let defaulted = ResolvedProviderAuth::v2("company-openai", "openai", None).unwrap();
    assert_eq!(
      defaulted.account_for_auth(&stored).base_url.as_deref(),
      Some("https://api.openai.com/v1")
    );
    assert!(ResolvedProviderAuth::v2("company-openai", "missing", None).is_err());
  }

  #[test]
  fn v2_disabled_official_provider_is_not_offered_but_existing_accounts_resolve() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
      &path,
      r#"
schema_version = 2

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[providers.openai]
enable = false
"#,
    )
    .unwrap();
    let context = ConfigContext::load(Some(&path)).unwrap();

    assert!(!context.provider_ids().contains(&"openai".to_string()));
    assert!(context.resolve_provider("openai").is_err());
    let stored = account("openai", Some("https://stored.example.test/v1"));
    let provider = context.resolve_account_provider(&stored).unwrap();
    assert_eq!(provider.auth().id(), "openai");
    assert_eq!(
      provider.account_for_auth(&stored).base_url.as_deref(),
      Some("https://stored.example.test/v1")
    );

    let unknown = account("missing", None);
    assert!(context.resolve_account_provider(&unknown).is_err());
  }

  #[test]
  fn legacy_auth_preserves_an_account_level_base_url() {
    let provider = ResolvedProviderAuth::legacy("openai").unwrap();
    let stored = account("openai", Some("https://legacy.example.test/v1"));

    let mut auth_account = provider.account_for_auth(&stored);
    assert_eq!(auth_account.base_url.as_deref(), Some("https://legacy.example.test/v1"));
    provider.finish_account(&mut auth_account);
    assert_eq!(auth_account.provider, "openai");
    assert_eq!(auth_account.base_url.as_deref(), Some("https://legacy.example.test/v1"));
  }

  #[test]
  fn legacy_context_uses_defaults_and_rejects_unknown_account_providers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing-config.toml");
    let context = ConfigContext::load(Some(&path)).unwrap();

    assert_eq!(context.path(), path);
    assert!(context.http_client_options(false).url.is_none());
    assert!(context.provider_ids().contains(&"openai".to_string()));
    assert_eq!(context.resolve_provider("openai").unwrap().auth().id(), "openai");

    let unknown = account("missing", None);
    assert!(context.resolve_account_provider(&unknown).is_err());
  }

  #[test]
  fn v2_outbound_settings_are_used_for_account_http_clients() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
      &path,
      r#"
schema_version = 2

[service.outbound]
proxy_url = "http://127.0.0.1:8888"
no_proxy = ["auth.example.test"]

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }
"#,
    )
    .unwrap();
    let context = ConfigContext::load(Some(&path)).unwrap();

    let options = context.http_client_options(false);
    assert_eq!(options.url.as_deref(), Some("http://127.0.0.1:8888/"));
    assert_eq!(options.no_proxy, ["auth.example.test"]);
    assert!(!options.system);

    let no_proxy = context.http_client_options(true);
    assert_eq!(no_proxy.url, None);
    assert!(no_proxy.no_proxy.is_empty());
    assert!(!no_proxy.system);
  }

  #[test]
  fn v2_account_views_resolve_pools_and_profiles() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
      &path,
      r#"
schema_version = 2

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "coding" }

[profiles.coding]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "primary"
provider = { kind = "any" }
model = { kind = "capability" }
operation = "preserve"

[account_pools.primary]
accounts = ["primary"]
providers = ["company-openai"]

[providers.company-openai]
driver = "openai"
base_url = "https://llm.example.test/v1"
"#,
    )
    .unwrap();
    let context = ConfigContext::load(Some(&path)).unwrap();
    let selected = AccountConfig {
      id: "primary".into(),
      ..account("company-openai", None)
    };
    let other_account = AccountConfig {
      id: "other".into(),
      ..selected.clone()
    };
    let other_provider = account("openai", None);

    let pool = context.resolve_account_view(Some("primary"), None).unwrap().unwrap();
    assert_eq!(pool.description(), "pool 'primary'");
    assert!(pool.contains(&selected));
    assert!(!pool.contains(&other_account));
    assert!(!pool.contains(&other_provider));

    let profile = context.resolve_account_view(None, Some("coding")).unwrap().unwrap();
    assert_eq!(
      profile.description(),
      "profile 'coding' -> route 'managed' -> pool 'primary'"
    );
    assert!(profile.contains(&selected));
    assert!(context.resolve_account_view(Some("missing"), None).is_err());
    assert!(context.resolve_account_view(Some("primary"), Some("coding")).is_err());
  }

  #[test]
  fn legacy_profile_account_view_applies_inherited_filters() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
      &path,
      r#"
[defaults]
providers = ["openai"]
accounts = ["default"]

[profiles.batch]
accounts = ["batch"]
"#,
    )
    .unwrap();
    let context = ConfigContext::load(Some(&path)).unwrap();
    let selected = AccountConfig {
      id: "batch".into(),
      ..account("openai", None)
    };
    let wrong_account = AccountConfig {
      id: "default".into(),
      ..account("openai", None)
    };
    let wrong_provider = AccountConfig {
      id: "batch".into(),
      ..account("zai", None)
    };

    let profile = context.resolve_account_view(None, Some("batch")).unwrap().unwrap();
    assert_eq!(profile.description(), "profile 'batch'");
    assert!(profile.contains(&selected));
    assert!(!profile.contains(&wrong_account));
    assert!(!profile.contains(&wrong_provider));
    assert!(context.resolve_account_view(Some("primary"), None).is_err());
  }
}

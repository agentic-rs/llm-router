//! Interactive onboarding helpers shared by `account add`, `login`, and
//! `import`.
//!
//! All provider-specific work — device-flow OAuth, key verification —
//! is delegated to the [`ProviderAuth`] trait via [`auth_registry`]. The
//! CLI's job is purely to gather user input, render progress, and
//! assemble the resulting [`Account`].
//!
//! [`auth_registry`]: crate::auth_registry

use crate::auth_registry::known_providers;
use crate::cli::config_context::ResolvedProviderAuth;
use crate::config::{Account, AuthType};
use crate::util::secret::Secret;
use anyhow::{anyhow, Context, Result};
use tokn_auth::{CredentialResult, ProviderAuth, RefreshOutcome};

// Re-export so existing call sites continue to use
// `crate::cli::onboarding::CredentialSource`. New code should import it
// directly from `tokn_auth`.
pub use tokn_auth::CredentialSource;

pub fn validate_provider(provider: &str) -> Result<()> {
  ResolvedProviderAuth::legacy(provider).map(|_| ()).map_err(|_| {
    anyhow!(
      "unknown provider '{provider}'. Try one of: {}",
      known_providers().join(" | ")
    )
  })
}

pub fn validate_provider_source(provider: &ResolvedProviderAuth, source: &CredentialSource) -> Result<()> {
  let auth = provider.auth();
  if auth.supports_credential_source(source) {
    return Ok(());
  }
  // Provider-specific hint for the most common mistake. We can't enumerate
  // every custom source here, so just list the supported `--from` values.
  let supported: Vec<String> = auth
    .credential_sources()
    .iter()
    .map(|k| k.as_str().to_string())
    .collect();
  Err(anyhow!(
    "credential source not supported by provider '{}' — try one of: {}",
    provider.provider_id(),
    supported.join("|")
  ))
}

pub async fn resolve_account(
  client: &reqwest::Client,
  provider: &ResolvedProviderAuth,
  id_override: Option<String>,
  source: CredentialSource,
) -> Result<Account> {
  validate_provider_source(provider, &source)?;
  let auth = provider.auth();

  let mut account = match source {
    CredentialSource::Login => {
      if auth.supports_device_flow() {
        device_flow_login(client, provider, id_override).await
      } else {
        // Static-key provider: prompt for the key, verify, build account.
        static_key_login(client, provider, id_override).await
      }
    }
    // Every non-Login source goes through the trait. The provider tells
    // us — via `CredentialResult` — which account shape to build.
    other => {
      let result = auth
        .import_from(&other)
        .await
        .map_err(|e| anyhow!("import failed: {e}"))?;
      match result {
        CredentialResult::Refresh(token) => oauth_account_from_token(client, provider, id_override, token).await,
        CredentialResult::ApiKey(key) => static_key_account(client, provider, id_override, key).await,
      }
    }
  }?;
  provider.finish_account(&mut account);
  Ok(account)
}

/// Build an [`Account`] for an OAuth provider given a long-lived refresh
/// token, then validate it with a live refresh when the provider supports it.
async fn oauth_account_from_token(
  client: &reqwest::Client,
  provider: &ResolvedProviderAuth,
  id_override: Option<String>,
  token: String,
) -> Result<Account> {
  let auth = provider.auth();
  let mut account = Account {
    id: id_override.clone().unwrap_or_else(|| "imported".into()),
    provider: auth.id().into(),
    enabled: true,
    tier: tokn_core::account::AccountTier::Active,
    tags: Vec::new(),
    label: None,
    base_url: auth.default_base_url().map(str::to_string),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: None,
    api_key_expires_at: None,
    access_token: None,
    access_token_expires_at: None,
    id_token: None,
    refresh_token: Some(Secret::new(token)),
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: auth.default_refresh_url().map(str::to_string),
    last_refresh: None,
    settings: toml::Table::new(),
  };
  let auth_account = provider.account_for_auth(&account);

  let refresh = auth
    .refresh_credential(client, &auth_account)
    .await
    .map_err(|e| anyhow!("refresh token verification failed: {e}"))?;
  let mut username = match refresh {
    RefreshOutcome::Refreshed {
      access_token,
      expires_at,
      username,
      provider_account_id,
    } => {
      account.access_token = Some(Secret::new(access_token));
      account.access_token_expires_at = Some(expires_at);
      account.last_refresh = Some(time::OffsetDateTime::now_utc().unix_timestamp());
      if provider_account_id.is_some() {
        account.provider_account_id = provider_account_id;
      }
      username
    }
    RefreshOutcome::NotApplicable => None,
  };
  if username.is_none() {
    username = auth
      .verify_credential(client, &auth_account)
      .await
      .ok()
      .and_then(|v| v.username);
  }
  if id_override.is_none() {
    if let Some(name) = username.as_ref().filter(|name| !name.trim().is_empty()) {
      account.id = name.trim().to_string();
    }
  }
  account.username = username;

  Ok(account)
}

/// Build an [`Account`] for a static-API-key provider given the raw key.
async fn static_key_account(
  client: &reqwest::Client,
  provider: &ResolvedProviderAuth,
  id_override: Option<String>,
  key: String,
) -> Result<Account> {
  let auth = provider.auth();
  let mut account = static_key_account_unverified(auth, id_override.clone(), key)?;
  let auth_account = provider.account_for_auth(&account);
  let outcome = auth
    .verify_credential(client, &auth_account)
    .await
    .map_err(|e| anyhow!("key verification failed: {e}"))?;
  if id_override
    .as_deref()
    .map(str::trim)
    .filter(|id| !id.is_empty() && *id != "imported")
    .is_none()
  {
    if let Some(name) = outcome.username.as_ref().filter(|name| !name.trim().is_empty()) {
      account.id = name.trim().to_string();
    }
  }
  account.username = outcome.username;
  Ok(account)
}

fn static_key_account_unverified(auth: &dyn ProviderAuth, id_override: Option<String>, key: String) -> Result<Account> {
  let id = resolve_static_key_account_id(id_override, &key);
  Ok(Account {
    id,
    provider: auth.id().into(),
    enabled: true,
    tier: tokn_core::account::AccountTier::Active,
    tags: Vec::new(),
    label: None,
    base_url: auth.default_base_url().map(str::to_string),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: Some(Secret::new(key)),
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
  })
}

fn resolve_static_key_account_id(id_override: Option<String>, key: &str) -> String {
  match id_override.map(|id| id.trim().to_string()) {
    Some(id) if !id.is_empty() && id != "imported" => id,
    _ => account_id_from_api_key(key),
  }
}

fn account_id_from_api_key(key: &str) -> String {
  let last4: String = key
    .trim()
    .chars()
    .rev()
    .take(4)
    .collect::<Vec<_>>()
    .into_iter()
    .rev()
    .collect();
  format!("account_{last4}")
}

/// Run a provider's device-flow login interactively. Splits the trait's
/// request/poll calls so the user code can be displayed *between* the
/// two — the polling step blocks for ~minutes waiting on the browser.
async fn device_flow_login(
  client: &reqwest::Client,
  provider: &ResolvedProviderAuth,
  id_override: Option<String>,
) -> Result<Account> {
  let auth = provider.auth();
  println!("Requesting device code from {} …", auth.id());
  let handle = auth
    .request_device_code(client)
    .await
    .map_err(|e| anyhow!("device code request failed: {e}"))?;
  println!();
  println!("  Open: {}", handle.verification_uri);
  println!("  Code: {}", handle.user_code);
  println!();
  println!("Waiting for authorization (expires in {}s) …", handle.expires_in);

  let outcome = auth
    .poll_device_code(client, handle)
    .await
    .map_err(|e| anyhow!("device-flow polling failed: {e}"))?;
  println!("Got token. ");

  let id = id_override
    .or(outcome.username)
    .unwrap_or_else(|| auth.default_account_id().to_string());

  let account = Account {
    id,
    provider: auth.id().into(),
    enabled: true,
    tier: tokn_core::account::AccountTier::Active,
    tags: Vec::new(),
    label: None,
    base_url: auth.default_base_url().map(str::to_string),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: None,
    api_key_expires_at: None,
    access_token: Some(Secret::new(outcome.access_token)),
    access_token_expires_at: Some(outcome.access_token_expires_at),
    id_token: None,
    refresh_token: Some(Secret::new(outcome.refresh_token)),
    provider_account_id: outcome.provider_account_id,
    extra: Default::default(),
    refresh_url: auth.default_refresh_url().map(str::to_string),
    last_refresh: Some(time::OffsetDateTime::now_utc().unix_timestamp()),
    settings: toml::Table::new(),
  };
  Ok(account)
}

/// Prompt for a static API key, verify it via the provider's
/// [`ProviderAuth::verify_credential`], and return the assembled account.
async fn static_key_login(
  client: &reqwest::Client,
  provider: &ResolvedProviderAuth,
  id_override: Option<String>,
) -> Result<Account> {
  let auth = provider.auth();
  println!("{} uses a static API key. Paste your key below.", auth.id());
  let key = rpassword::prompt_password("API key: ")
    .context("reading API key from stdin")?
    .trim()
    .to_string();
  if key.is_empty() {
    return Err(anyhow!("empty API key"));
  }

  // Build a throwaway Account so the trait can verify against it.
  let probe = static_key_account_unverified(auth, Some("__probe__".into()), key.clone())?;
  let auth_probe = provider.account_for_auth(&probe);
  println!(
    "Verifying key against {} …",
    auth_probe.base_url.as_deref().unwrap_or("upstream")
  );
  let outcome = auth
    .verify_credential(client, &auth_probe)
    .await
    .map_err(|e| anyhow!("key verification failed: {e}"))?;
  println!("Key OK.");

  let mut account = static_key_account_unverified(auth, id_override.clone(), key)?;
  if id_override
    .as_deref()
    .map(str::trim)
    .filter(|id| !id.is_empty() && *id != "imported")
    .is_none()
  {
    if let Some(name) = outcome.username.as_ref().filter(|name| !name.trim().is_empty()) {
      account.id = name.trim().to_string();
    }
  }
  account.username = outcome.username;
  Ok(account)
}

// ---------------------------------------------------------------------------
// Interactive helpers (used by `account add` and `config init`).
// ---------------------------------------------------------------------------

/// One-shot interactive flow: pick provider → pick credential source →
/// pick id → resolve account. Caller is responsible for upserting +
/// saving the resulting [`Account`].
pub(crate) async fn interactive_add_account(
  client: &reqwest::Client,
  provider: &ResolvedProviderAuth,
  id_override: Option<String>,
) -> Result<Account> {
  let source = pick_source_interactive(provider)?;
  let id = match id_override {
    Some(s) => Some(s),
    None => pick_account_id(provider, &source)?,
  };
  resolve_account(client, provider, id, source).await
}

pub(crate) fn pick_provider(provider_ids: &[String]) -> Result<String> {
  let options = provider_ids.to_vec();
  let selected = inquire::Select::new("Pick account provider:", options)
    .with_starting_cursor(0)
    .prompt()
    .context("provider selection cancelled")?;
  Ok(selected.to_string())
}

pub(crate) fn pick_source_interactive(provider: &ResolvedProviderAuth) -> Result<CredentialSource> {
  // Build the menu from the trait's advertised credential sources, so
  // any new provider's options surface automatically.
  let auth = provider.auth();
  let kinds = auth.credential_sources();
  let options: Vec<String> = kinds.iter().map(|k| k.as_str().to_string()).collect();

  let picked = inquire::Select::new("Credential source:", options)
    .with_starting_cursor(0)
    .prompt()
    .context("credential source selection cancelled")?;

  match picked.as_str() {
    "login" => Ok(CredentialSource::Login),
    "env" => {
      let flavor = pick_flavor_interactive(auth)?;
      let default_name = crate::cli::import::default_env_var_name(provider.provider_id(), flavor);
      let env_var = inquire::Text::new("Environment variable name:")
        .with_initial_value(&default_name)
        .prompt()
        .context("env var prompt cancelled")?;
      Ok(CredentialSource::Env { env_var, flavor })
    }
    "string" => {
      let flavor = pick_flavor_interactive(auth)?;
      let label = match flavor {
        tokn_auth::CredentialFlavor::ApiKey => "Paste API key:",
        tokn_auth::CredentialFlavor::RefreshToken => "Paste refresh token:",
      };
      let value = inquire::Password::new(label)
        .without_confirmation()
        .prompt()
        .context("credential prompt cancelled")?;
      Ok(CredentialSource::String { value, flavor })
    }
    "file" => {
      let flavor = pick_flavor_interactive(auth)?;
      let path_str = inquire::Text::new("Path to credential file:")
        .prompt()
        .context("file path prompt cancelled")?;
      Ok(CredentialSource::File {
        path: std::path::PathBuf::from(path_str),
        flavor,
      })
    }
    // Anything else is a provider-defined Custom source. Look up the
    // matching `&'static str` from the provider's advertised list so
    // CredentialSource::Custom can hold a true static key.
    other => {
      let key = auth
        .custom_credential_sources()
        .iter()
        .copied()
        .find(|k| *k == other)
        .ok_or_else(|| anyhow!("unsupported credential source `{other}`"))?;
      Ok(CredentialSource::Custom { key, value: None })
    }
  }
}

/// Ask the user whether the credential is an API key or a refresh
/// token. If the provider only accepts one flavor, return it without
/// prompting.
fn pick_flavor_interactive(auth: &dyn tokn_auth::ProviderAuth) -> Result<tokn_auth::CredentialFlavor> {
  use tokn_auth::CredentialFlavor::*;
  let api = auth.supports_auth_flavor(ApiKey);
  let refresh = auth.supports_auth_flavor(RefreshToken);
  match (api, refresh) {
    (true, false) => Ok(ApiKey),
    (false, true) => Ok(RefreshToken),
    (true, true) => {
      let default_idx = if matches!(auth.default_auth_flavor(), RefreshToken) {
        1
      } else {
        0
      };
      let picked = inquire::Select::new("Credential flavor:", vec!["api-key", "refresh-token"])
        .with_starting_cursor(default_idx)
        .prompt()
        .context("flavor selection cancelled")?;
      Ok(if picked == "refresh-token" {
        RefreshToken
      } else {
        ApiKey
      })
    }
    (false, false) => Err(anyhow!(
      "provider '{}' does not accept any credential flavor",
      auth.id()
    )),
  }
}

pub(crate) fn pick_account_id(provider: &ResolvedProviderAuth, source: &CredentialSource) -> Result<Option<String>> {
  let auth = provider.auth();
  let default_id = auth.default_account_id();
  let supports_auto_api_key = auth.supports_auth_flavor(tokn_auth::CredentialFlavor::ApiKey)
    && matches!(source.flavor(), Some(tokn_auth::CredentialFlavor::ApiKey) | None);
  let supports_auto_id = matches!(source, CredentialSource::Login) || supports_auto_api_key;
  let prompt = match source {
    CredentialSource::Login => "Account id (leave empty for auto):",
    _ if supports_auto_api_key => "Account id (leave empty for auto):",
    _ => "Account id:",
  };
  let mut prompt = inquire::Text::new(prompt);
  if !supports_auto_id {
    prompt = prompt.with_initial_value(default_id);
  }
  let text = prompt.prompt().context("account id prompt cancelled")?;
  let trimmed = text.trim().to_string();
  if trimmed.is_empty() {
    return Ok(None);
  }
  Ok(Some(trimmed))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::config_context::ConfigContext;
  use tokn_auth::CredentialFlavor;
  use tokn_mock_server::{MockAuthConfig, MockLlmConfig, MockLlmServer};

  fn write_v2_openai_config(path: &std::path::Path, base_url: &str) {
    std::fs::write(
      path,
      format!(
        r#"
schema_version = 2

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"

[providers.company-openai]
driver = "openai"
base_url = "{base_url}"
"#
      ),
    )
    .unwrap();
  }

  #[test]
  fn api_key_account_id_uses_last_four_when_missing() {
    assert_eq!(resolve_static_key_account_id(None, "sk-abcdef"), "account_cdef");
  }

  #[test]
  fn api_key_account_id_treats_imported_as_auto() {
    assert_eq!(
      resolve_static_key_account_id(Some("imported".into()), "sk-abcdef"),
      "account_cdef"
    );
  }

  #[test]
  fn api_key_account_id_preserves_explicit_override() {
    assert_eq!(
      resolve_static_key_account_id(Some("custom".into()), "sk-abcdef"),
      "custom"
    );
  }

  #[test]
  fn provider_validation_reports_unknown_and_unsupported_sources() {
    assert!(validate_provider("openai").is_ok());
    assert!(validate_provider("missing").is_err());

    let provider = ResolvedProviderAuth::legacy("openai").unwrap();
    let source = CredentialSource::String {
      value: "refresh-token".into(),
      flavor: CredentialFlavor::RefreshToken,
    };
    let error = validate_provider_source(&provider, &source).unwrap_err();
    assert!(error.to_string().contains("credential source not supported"));
  }

  #[tokio::test]
  async fn v2_static_key_import_verifies_configured_destination_and_finishes_identity() {
    let server = MockLlmServer::start(MockLlmConfig::default().with_auth(MockAuthConfig::bearer(["sk-test"]))).await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    write_v2_openai_config(&path, server.base_url());
    let context = ConfigContext::load(Some(&path)).unwrap();
    let provider = context.resolve_provider("company-openai").unwrap();
    let client = context.build_http_client(true).unwrap();

    let account = resolve_account(
      &client,
      &provider,
      None,
      CredentialSource::String {
        value: "sk-test".into(),
        flavor: CredentialFlavor::ApiKey,
      },
    )
    .await
    .unwrap();

    assert_eq!(account.id, "account_test");
    assert_eq!(account.provider, "company-openai");
    assert_eq!(account.base_url, None);
    let request = server.last_request().unwrap();
    assert_eq!(request.path, "/models");
    assert_eq!(request.header("authorization"), Some("Bearer sk-test"));
    server.shutdown().await;
  }
}

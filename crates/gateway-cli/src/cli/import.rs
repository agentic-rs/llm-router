use crate::cli::onboarding::{resolve_account, CredentialSource};
use anyhow::{anyhow, bail, Result};
use clap::Args;
use std::io::Read;
use std::path::PathBuf;
use tokn_auth::{AuthStore, CredentialFlavor};
use tokn_core::util::http::{build_client, HttpClientOptions};

use super::command_config::CommandConfig;

/// `account import` — non-interactive credential import.
///
/// `--from <name>` selects the source of the credential bytes:
///   * `env` (default) — read from the env var named by `--env-var`
///     (default: `${PROVIDER}_API_KEY` or `${PROVIDER}_REFRESH_TOKEN`,
///     uppercased with `-` → `_`)
///   * `string` — read literal value from `--credential VALUE`
///   * `file` — read from the path named by `--file PATH`
///   * `stdin` — read from stdin until EOF
///   * `<custom-key>` — provider-defined source (e.g. `gh`,
///     `copilot-plugin` for github-copilot)
///
/// The credential flavor (refresh token vs API key) is decided in this
/// order:
///   1. `--refresh-token` switch → `RefreshToken`
///   2. `--api-key` switch → `ApiKey`
///   3. provider's `default_auth_flavor()` (RefreshToken for OAuth
///      providers, ApiKey otherwise)
#[derive(Args, Debug)]
pub struct ImportArgs {
  /// Where to fetch the credential from.
  #[arg(long, default_value = "env")]
  pub from: String,

  /// Provider to associate the imported credential with.
  #[arg(long)]
  pub provider: String,

  /// Environment variable name for `--from env`. Defaults to
  /// `${PROVIDER}_API_KEY` or `${PROVIDER}_REFRESH_TOKEN` based on the
  /// provider's default auth flavor (or the `--refresh-token`/
  /// `--api-key` switch if given).
  #[arg(long)]
  pub env_var: Option<String>,

  /// Literal credential bytes for `--from string`.
  #[arg(long)]
  pub credential: Option<String>,

  /// Path to read credential bytes from for `--from file`.
  #[arg(long)]
  pub file: Option<PathBuf>,

  /// Treat the imported credential as an OAuth refresh token. Mutually
  /// exclusive with `--api-key`.
  #[arg(long, conflicts_with = "api_key")]
  pub refresh_token: bool,

  /// Treat the imported credential as a static API key. Mutually
  /// exclusive with `--refresh-token`.
  #[arg(long)]
  pub api_key: bool,

  /// ID for the imported account.
  #[arg(long)]
  pub id: Option<String>,
}

pub async fn run(config: &CommandConfig, args: ImportArgs) -> Result<()> {
  let source = build_source(&args)?;
  let client = build_client(&HttpClientOptions::default())?;
  let account = resolve_account(&client, &args.provider, args.id.clone(), source).await?;

  let mut store = AuthStore::load(None, Some(config.path()))?;
  let id = account.id.clone();
  let provider = account.provider.clone();
  store.upsert_in_main(account)?;
  store.save()?;
  tracing::info!(
    account = %id,
    %provider,
    from = %args.from,
    path = %store.path().display(),
    "account imported"
  );
  println!("Saved account '{id}' to {}", store.path().display());
  Ok(())
}

/// Translate the user's `--from <name>` plus auxiliary flags into a
/// [`CredentialSource`]. Provider-defined keys are resolved against
/// [`ProviderAuth::custom_credential_sources`] so the resulting
/// `CredentialSource::Custom` carries a `&'static str`.
pub(crate) fn build_source(args: &ImportArgs) -> Result<CredentialSource> {
  let auth = crate::auth_registry::provider_auth_for(&args.provider)
    .ok_or_else(|| anyhow!("unknown provider '{}'", args.provider))?;
  let flavor = resolve_flavor(args, auth);

  // Validate provider accepts this flavor before doing real work.
  if !auth.supports_auth_flavor(flavor) {
    bail!(
      "provider '{}' does not accept {} credentials",
      args.provider,
      flavor_name(flavor)
    );
  }

  match args.from.as_str() {
    "login" => Err(anyhow!("from=login is interactive-only; use `account login` instead")),
    "env" => {
      let env_var = args
        .env_var
        .clone()
        .unwrap_or_else(|| default_env_var_name(&args.provider, flavor));
      Ok(CredentialSource::Env { env_var, flavor })
    }
    "string" => {
      let value = args
        .credential
        .clone()
        .ok_or_else(|| anyhow!("--from string requires --credential VALUE"))?;
      Ok(CredentialSource::String { value, flavor })
    }
    "file" => {
      let path = args
        .file
        .clone()
        .ok_or_else(|| anyhow!("--from file requires --file PATH"))?;
      Ok(CredentialSource::File { path, flavor })
    }
    "stdin" => {
      let mut buf = String::new();
      std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| anyhow!("read stdin: {e}"))?;
      Ok(CredentialSource::String { value: buf, flavor })
    }
    other => {
      let key = auth
        .custom_credential_sources()
        .iter()
        .copied()
        .find(|k| *k == other)
        .ok_or_else(|| {
          anyhow!(
            "unsupported --from `{other}` for provider `{}`; expected one of: env|string|file|stdin{}",
            args.provider,
            format_custom_keys(auth.custom_credential_sources())
          )
        })?;
      Ok(CredentialSource::Custom { key, value: None })
    }
  }
}

fn resolve_flavor(args: &ImportArgs, auth: &dyn tokn_auth::ProviderAuth) -> CredentialFlavor {
  if args.refresh_token {
    CredentialFlavor::RefreshToken
  } else if args.api_key {
    CredentialFlavor::ApiKey
  } else {
    auth.default_auth_flavor()
  }
}

fn flavor_name(f: CredentialFlavor) -> &'static str {
  match f {
    CredentialFlavor::ApiKey => "API key",
    CredentialFlavor::RefreshToken => "refresh token",
  }
}

fn format_custom_keys(keys: &[&'static str]) -> String {
  if keys.is_empty() {
    String::new()
  } else {
    format!("|{}", keys.join("|"))
  }
}

/// Default env var name for `--from env` when `--env-var` is omitted.
/// e.g. `github-copilot` + `RefreshToken` → `GITHUB_COPILOT_REFRESH_TOKEN`;
/// `zai` + `ApiKey` → `ZAI_API_KEY`.
pub(crate) fn default_env_var_name(provider: &str, flavor: CredentialFlavor) -> String {
  let base = provider.to_uppercase().replace('-', "_");
  let suffix = match flavor {
    CredentialFlavor::ApiKey => "API_KEY",
    CredentialFlavor::RefreshToken => "REFRESH_TOKEN",
  };
  format!("{base}_{suffix}")
}

#[cfg(test)]
mod tests {
  use super::*;

  fn args() -> ImportArgs {
    ImportArgs {
      from: "env".to_string(),
      provider: "github-copilot".to_string(),
      env_var: None,
      credential: None,
      file: None,
      refresh_token: false,
      api_key: false,
      id: None,
    }
  }

  #[test]
  fn default_env_var_for_copilot_is_refresh_token() {
    let name = default_env_var_name("github-copilot", CredentialFlavor::RefreshToken);
    assert_eq!(name, "GITHUB_COPILOT_REFRESH_TOKEN");
  }

  #[test]
  fn default_env_var_for_zai_is_api_key() {
    let name = default_env_var_name("zai", CredentialFlavor::ApiKey);
    assert_eq!(name, "ZAI_API_KEY");
  }

  #[test]
  fn build_source_env_default_uses_provider_default_flavor() {
    let a = args();
    let src = build_source(&a).unwrap();
    match src {
      CredentialSource::Env { env_var, flavor } => {
        assert_eq!(env_var, "GITHUB_COPILOT_REFRESH_TOKEN");
        assert!(matches!(flavor, CredentialFlavor::RefreshToken));
      }
      other => panic!("expected Env, got {other:?}"),
    }
  }

  #[test]
  fn build_source_string_requires_credential() {
    let mut a = args();
    a.from = "string".to_string();
    let err = build_source(&a).unwrap_err().to_string();
    assert!(err.contains("--credential"), "got: {err}");
  }

  #[test]
  fn build_source_string_with_credential_uses_default_flavor() {
    let mut a = args();
    a.from = "string".to_string();
    a.credential = Some("rtok".into());
    let src = build_source(&a).unwrap();
    assert!(matches!(
      src,
      CredentialSource::String {
        flavor: CredentialFlavor::RefreshToken,
        ..
      }
    ));
  }

  #[test]
  fn build_source_api_key_switch_flips_flavor() {
    let mut a = args();
    a.provider = "zai".to_string();
    a.api_key = true;
    a.from = "string".to_string();
    a.credential = Some("k".into());
    let src = build_source(&a).unwrap();
    assert!(matches!(
      src,
      CredentialSource::String {
        flavor: CredentialFlavor::ApiKey,
        ..
      }
    ));
  }

  #[test]
  fn build_source_resolves_known_custom_key() {
    let mut a = args();
    a.from = "gh".to_string();
    let src = build_source(&a).unwrap();
    assert!(matches!(src, CredentialSource::Custom { key: "gh", .. }));
  }

  #[test]
  fn build_source_rejects_unknown_custom_key() {
    let mut a = args();
    a.from = "no-such-source".to_string();
    let err = build_source(&a).unwrap_err().to_string();
    assert!(err.contains("unsupported"), "got: {err}");
  }

  #[test]
  fn build_source_rejects_login() {
    let mut a = args();
    a.from = "login".to_string();
    let err = build_source(&a).unwrap_err().to_string();
    assert!(err.contains("interactive-only"), "got: {err}");
  }

  #[test]
  fn build_source_rejects_unsupported_flavor() {
    let mut a = args();
    a.provider = "zai".to_string();
    a.refresh_token = true;
    let err = build_source(&a).unwrap_err().to_string();
    assert!(err.contains("does not accept"), "got: {err}");
  }
}

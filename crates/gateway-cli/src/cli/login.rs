use crate::cli::config_context::ConfigContext;
use crate::cli::onboarding::{resolve_account, CredentialSource};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::io::IsTerminal;
use tokn_auth::AuthStore;

#[derive(Args, Debug)]
pub struct LoginArgs {
  /// Provider to log in to. If omitted and stdin is a TTY, you'll be
  /// prompted to pick one.
  ///
  /// Accepted provider ids are shown by the interactive picker. Z.ai aliases
  /// route to the same backend; whichever you pick is preserved verbatim.
  #[arg(long)]
  pub provider: Option<String>,

  /// ID to assign to the new account. Defaults to the GitHub username for
  /// `github-copilot`, or to the provider id for static-key providers.
  #[arg(long)]
  pub id: Option<String>,

  /// Skip outbound proxy for this command (e.g. captive networks).
  #[arg(long)]
  pub no_proxy: bool,
}

pub(crate) async fn run_with_context(context: &ConfigContext, store: &mut AuthStore, args: LoginArgs) -> Result<()> {
  let client = context.build_http_client(args.no_proxy)?;

  let provider_id = match args.provider {
    Some(p) => p,
    None => pick_provider_interactive(&context.provider_ids())?,
  };
  let provider = context.resolve_provider(&provider_id)?;
  let account = resolve_account(&client, &provider, args.id, CredentialSource::Login).await?;

  let id = account.id.clone();
  let provider = account.provider.clone();
  store.upsert_in_main(account)?;
  store.save()?;
  tracing::info!(account = %id, %provider, path = %store.path().display(), "account saved");
  println!("Saved account '{id}' to {}", store.path().display());
  Ok(())
}

/// Show an arrow-key picker over the configured provider ids. Errors out
/// (rather than silently defaulting) when stdin isn't a TTY — scripted use
/// must pass `--provider` explicitly.
fn pick_provider_interactive(provider_ids: &[String]) -> Result<String> {
  if !std::io::stdin().is_terminal() {
    return Err(anyhow!(
      "no --provider given and stdin is not a TTY; pass --provider <id> (one of: {})",
      provider_ids.join(" | ")
    ));
  }
  if provider_ids.is_empty() {
    return Err(anyhow!(
      "the config has no enabled providers that support account credentials"
    ));
  }
  let options = provider_ids.to_vec();

  let pick = inquire::Select::new("Pick a provider:", options)
    .with_starting_cursor(0)
    .with_help_message("↑/↓ to move · enter to select · esc to cancel")
    .prompt()
    .context("provider selection cancelled")?;
  Ok(pick.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn unknown_provider_is_rejected_before_login_starts() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    let context = ConfigContext::load(Some(&config_path)).unwrap();
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();

    let error = run_with_context(
      &context,
      &mut store,
      LoginArgs {
        provider: Some("unknown".into()),
        id: None,
        no_proxy: true,
      },
    )
    .await
    .unwrap_err();

    assert_eq!(error.to_string(), "unknown provider 'unknown'");
    assert!(!auth_path.exists());
  }

  #[tokio::test]
  async fn v2_login_rejects_a_provider_outside_the_config() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    let auth_path = directory.path().join("auth.yaml");
    std::fs::write(
      &config_path,
      r#"
schema_version = 2

[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[providers.openai]
"#,
    )
    .unwrap();
    let context = ConfigContext::load(Some(&config_path)).unwrap();
    let mut store = AuthStore::load(Some(&auth_path), None).unwrap();

    let error = run_with_context(
      &context,
      &mut store,
      LoginArgs {
        provider: Some("missing".into()),
        id: None,
        no_proxy: false,
      },
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("provider 'missing' is not enabled"));
    assert!(!auth_path.exists());
  }
}

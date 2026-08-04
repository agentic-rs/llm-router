use anyhow::{anyhow, Result};
use clap::Args;
use std::path::PathBuf;
use tokn_auth::AuthStore;

#[derive(Args, Debug)]
pub struct HeadersArgs {
  /// Show resolved headers for a specific account.
  #[arg(long)]
  pub account: Option<String>,
}

pub async fn run(cfg_path: Option<PathBuf>, args: HeadersArgs) -> Result<()> {
  let config = super::command_config::CommandConfig::load(cfg_path.as_deref())?;
  let store = AuthStore::load(None, Some(config.path()))?;
  let headers = match args.account {
    None => tokn_provider_copilot::config::CopilotHeaders::default(),
    Some(id) => {
      let a = store.get(&id).ok_or_else(|| anyhow!("no account with id '{id}'"))?;
      if a.provider != crate::provider::ID_GITHUB_COPILOT {
        println!(
          "Account '{id}' uses provider '{}', which does not send Copilot identity headers.",
          a.provider
        );
        println!("(headers are only relevant for the github-copilot provider)");
        return Ok(());
      }
      let value = serde_json::to_value(&a.settings)?;
      let mut headers = tokn_provider_copilot::config::CopilotHeaders::from_value(&value)?;
      for (k, v) in &a.headers {
        headers.extra_headers.insert(k.clone(), v.clone());
      }
      headers
    }
  };
  println!("editor-version:         {}", headers.editor_version);
  println!("editor-plugin-version:  {}", headers.editor_plugin_version);
  println!("user-agent:             {}", headers.user_agent);
  println!("copilot-integration-id: {}", headers.copilot_integration_id);
  println!("openai-intent:          {}", headers.openai_intent);
  println!("initiator_mode:         {:?}", headers.initiator_mode);
  if !headers.extra_headers.is_empty() {
    println!("extra:");
    for (k, v) in &headers.extra_headers {
      println!("  {k}: {v}");
    }
  }
  Ok(())
}

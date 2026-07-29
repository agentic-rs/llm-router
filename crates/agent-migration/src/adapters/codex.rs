use crate::adapter::AgentAdapter;
use crate::projection::AgentConfigProjection;
use crate::reconcile::{annotate_imported_account, EditKind, PlannedEdit};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokn_config::{Account, AuthType};
use tokn_core::account::AccountTier;
use tokn_core::provider::ID_CODEX;
use tokn_core::util::secret::Secret;
use tokn_core::AgentId;

pub(crate) struct CodexAdapter;

impl AgentAdapter for CodexAdapter {
  fn default_provider_id(&self) -> &'static str {
    ID_CODEX
  }

  fn auth_path(&self, home: &Path) -> PathBuf {
    home.join(".codex/auth.json")
  }

  fn config_path(&self, home: &Path) -> PathBuf {
    home.join(".codex/config.toml")
  }

  fn discover_accounts(&self, home: &Path, timestamp: &str) -> Result<Vec<Account>> {
    let auth_path = self.auth_path(home);
    if !auth_path.exists() {
      return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&auth_path).with_context(|| format!("reading {}", auth_path.display()))?;
    let json: Value = serde_json::from_str(&raw).with_context(|| format!("parsing {}", auth_path.display()))?;
    Ok(
      account_from_auth_json(&json)
        .map(|account| annotate_imported_account(account, AgentId::CodexCli, &auth_path, "auth.tokens", timestamp))
        .into_iter()
        .collect(),
    )
  }

  fn switch_endpoint(&self) -> tokn_core::provider::Endpoint {
    tokn_core::provider::Endpoint::Responses
  }

  fn rewrite_config(&self, home: &Path, projection: &AgentConfigProjection<'_>) -> Result<Vec<PlannedEdit>> {
    let auth_path = self.auth_path(home);
    let config_path = self.config_path(home);
    let mut edits = Vec::new();

    if auth_path.exists() {
      let raw = std::fs::read_to_string(&auth_path).with_context(|| format!("reading {}", auth_path.display()))?;
      let mut json: Value = serde_json::from_str(&raw).with_context(|| format!("parsing {}", auth_path.display()))?;
      if let Some(obj) = json.as_object_mut() {
        obj.insert("auth_mode".into(), Value::String("api_key".into()));
        obj.insert("OPENAI_API_KEY".into(), Value::String("tokn-router".into()));
      }
      edits.push(PlannedEdit::new(
        auth_path,
        EditKind::Json(json),
        true,
        Some(raw.into_bytes()),
      ));
    }

    let (mut doc, config_source) = if config_path.exists() {
      let raw = std::fs::read_to_string(&config_path).with_context(|| format!("reading {}", config_path.display()))?;
      let doc = raw
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("parsing {}", config_path.display()))?;
      (doc, Some(raw.into_bytes()))
    } else {
      (toml_edit::DocumentMut::new(), None)
    };
    rewrite_config(&mut doc, projection.target_base_url);
    edits.push(PlannedEdit::new(config_path, EditKind::Toml(doc), true, config_source));
    Ok(edits)
  }
}

fn rewrite_config(doc: &mut toml_edit::DocumentMut, target_base_url: &str) {
  doc["model_provider"] = toml_edit::value("tokn-router");
  let providers = doc["model_providers"].or_insert(toml_edit::table());
  let provider = providers["tokn-router"].or_insert(toml_edit::table());
  provider["name"] = toml_edit::value("tokn-router");
  provider["base_url"] = toml_edit::value(target_base_url);
  provider["env_key"] = toml_edit::value("OPENAI_API_KEY");
  provider["wire_api"] = toml_edit::value("responses");
}

fn account_from_auth_json(json: &Value) -> Option<Account> {
  let tokens = json.get("tokens")?;
  let refresh = tokens.get("refresh_token").and_then(Value::as_str)?.trim();
  if refresh.is_empty() {
    return None;
  }
  let access = tokens
    .get("access_token")
    .and_then(Value::as_str)
    .filter(|s| !s.trim().is_empty());
  let account_id = tokens
    .get("account_id")
    .and_then(Value::as_str)
    .filter(|s| !s.trim().is_empty());
  let username = tokens
    .get("email")
    .and_then(Value::as_str)
    .filter(|s| !s.trim().is_empty());
  Some(Account {
    id: "codex-cli-codex".into(),
    provider: ID_CODEX.into(),
    enabled: true,
    tier: AccountTier::Active,
    tags: vec!["agent-migrated".into(), "codex-cli".into()],
    label: Some("Codex CLI migration".into()),
    base_url: Some(tokn_provider_openai::codex::CODEX_BASE_URL.into()),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: username.map(str::to_string),
    api_key: None,
    api_key_expires_at: None,
    access_token: access.map(|value| Secret::new(value.to_string())),
    access_token_expires_at: None,
    id_token: tokens
      .get("id_token")
      .and_then(Value::as_str)
      .filter(|s| !s.trim().is_empty())
      .map(|value| Secret::new(value.to_string())),
    refresh_token: Some(Secret::new(refresh.to_string())),
    provider_account_id: account_id.map(str::to_string),
    extra: Default::default(),
    refresh_url: Some(tokn_provider_openai::CODEX_OAUTH_TOKEN_URL.into()),
    last_refresh: None,
    settings: toml::Table::new(),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn account_imports_refresh_and_account_id() {
    let account = account_from_auth_json(&serde_json::json!({
      "tokens": {
        "refresh_token": "rt",
        "access_token": "at",
        "id_token": "id",
        "account_id": "acc"
      }
    }))
    .unwrap();
    assert_eq!(account.id, "codex-cli-codex");
    assert_eq!(account.provider, "codex");
    assert_eq!(account.provider_account_id.as_deref(), Some("acc"));
    assert_eq!(account.refresh_token.unwrap().expose(), "rt");
  }

  #[test]
  fn config_rewrite_preserves_existing_keys() {
    let mut doc: toml_edit::DocumentMut = "model = \"gpt-5\"\n".parse().unwrap();
    rewrite_config(&mut doc, "http://127.0.0.1:4141/codex/v1");
    assert_eq!(doc["model"].as_str(), Some("gpt-5"));
    assert_eq!(doc["model_provider"].as_str(), Some("tokn-router"));
    assert_eq!(
      doc["model_providers"]["tokn-router"]["base_url"].as_str(),
      Some("http://127.0.0.1:4141/codex/v1")
    );
  }

  #[test]
  fn account_import_ignores_missing_refresh_token() {
    assert!(account_from_auth_json(&serde_json::json!({"tokens": {}})).is_none());
    assert!(account_from_auth_json(&serde_json::json!({"tokens": {"refresh_token": "  "}})).is_none());
  }

  #[test]
  fn adapter_reads_existing_auth_and_config() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = CodexAdapter;
    let auth_path = adapter.auth_path(dir.path());
    let config_path = adapter.config_path(dir.path());
    std::fs::create_dir_all(auth_path.parent().unwrap()).unwrap();
    std::fs::write(
      &auth_path,
      serde_json::json!({
        "tokens": {
          "refresh_token": "rt",
          "access_token": "at",
          "email": "user@example.test"
        }
      })
      .to_string(),
    )
    .unwrap();
    std::fs::write(&config_path, "model = \"gpt-5\"\n").unwrap();

    let accounts = adapter.discover_accounts(dir.path(), "20260604T153012Z").unwrap();
    let edits = adapter
      .rewrite_config(
        dir.path(),
        &AgentConfigProjection {
          target_base_url: "http://127.0.0.1:4141/codex/v1",
          mode: tokn_config::RouteMode::Route,
          previous_mode: None,
          credential_routes: &[],
          publications: &[],
          model_reference_rules: &[],
        },
      )
      .unwrap();

    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].username.as_deref(), Some("user@example.test"));
    assert_eq!(edits.len(), 2);
    assert!(edits.iter().any(|edit| edit.path == auth_path));
    assert!(edits.iter().any(|edit| edit.path == config_path));
  }
}

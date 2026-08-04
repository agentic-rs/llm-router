use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tokn_core::account::AccountConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaAction {
  ExtractLegacyAccounts {
    config: PathBuf,
    auth: PathBuf,
    count: usize,
  },
}

const CURRENT_AUTH_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthFile {
  #[serde(default = "default_auth_version")]
  version: u32,
  #[serde(default)]
  accounts: Vec<AccountConfig>,
}

fn default_auth_version() -> u32 {
  CURRENT_AUTH_VERSION
}

#[derive(Deserialize)]
struct LegacyAccounts {
  #[serde(default)]
  accounts: Vec<AccountConfig>,
}

pub fn migrate_home(home: &Path) -> Result<Vec<SchemaAction>> {
  let config = home.join("config.toml");
  let auth = home.join("auth.yaml");
  let mut actions = Vec::new();
  if auth.exists() || has_auth_shards(&home.join("auth.d"))? {
    return Ok(actions);
  }
  if let Some(accounts) = load_legacy_accounts(&config)? {
    write_auth(&auth, &accounts)?;
    actions.push(SchemaAction::ExtractLegacyAccounts {
      config,
      auth,
      count: accounts.len(),
    });
  }
  Ok(actions)
}

/// A sidecar-only credential installation is already using the current auth
/// layout. Do not resurrect legacy `[accounts]` into a new root file: doing
/// so could collide with an account id owned by one of the sidecars.
fn has_auth_shards(dir: &Path) -> Result<bool> {
  if !dir.exists() {
    return Ok(false);
  }
  for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
    let path = entry?.path();
    if path.is_file()
      && path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "yaml")
    {
      return Ok(true);
    }
  }
  Ok(false)
}

pub fn load_legacy_accounts(config_path: &Path) -> Result<Option<Vec<AccountConfig>>> {
  if !config_path.exists() {
    return Ok(None);
  }
  let raw = fs::read(config_path).with_context(|| format!("reading {}", config_path.display()))?;
  parse_legacy_accounts(&raw, config_path)
}

/// Parse embedded legacy accounts from an exact config-file snapshot.
///
/// Migration transactions use this entry point so credentials are derived
/// from the same bytes that are later backed up and guarded as the config
/// replacement preimage.
pub fn parse_legacy_accounts(raw: &[u8], source: &Path) -> Result<Option<Vec<AccountConfig>>> {
  let raw = std::str::from_utf8(raw).with_context(|| format!("reading {} as UTF-8", source.display()))?;
  let parsed: LegacyAccounts = toml::from_str(raw).with_context(|| format!("parsing legacy {}", source.display()))?;
  if parsed.accounts.is_empty() {
    Ok(None)
  } else {
    Ok(Some(parsed.accounts))
  }
}

fn write_auth(auth_path: &Path, accounts: &[AccountConfig]) -> Result<()> {
  if let Some(parent) = auth_path.parent() {
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
  }
  let file = AuthFile {
    version: CURRENT_AUTH_VERSION,
    accounts: accounts.to_vec(),
  };
  let yaml = serde_yaml::to_string(&file).with_context(|| "serialising auth.yaml")?;
  write_secured(auth_path, yaml.as_bytes()).with_context(|| format!("writing {}", auth_path.display()))
}

#[cfg(unix)]
fn write_secured(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  use std::io::Write;
  use std::os::unix::fs::OpenOptionsExt;
  let mut f = fs::OpenOptions::new()
    .create(true)
    .truncate(true)
    .write(true)
    .mode(0o600)
    .open(path)?;
  f.write_all(bytes)?;
  Ok(())
}

#[cfg(not(unix))]
fn write_secured(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn migrate_home_extracts_legacy_accounts_when_auth_missing() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
      dir.path().join("config.toml"),
      r#"
[[accounts]]
id = "legacy"
provider = "github-copilot"
enabled = true
"#,
    )
    .unwrap();

    let actions = migrate_home(dir.path()).unwrap();

    assert_eq!(actions.len(), 1);
    assert!(matches!(
      &actions[0],
      SchemaAction::ExtractLegacyAccounts { count: 1, .. }
    ));
    let auth = fs::read_to_string(dir.path().join("auth.yaml")).unwrap();
    assert!(auth.contains("version: 1"));
    assert!(auth.contains("id: legacy"));
  }

  #[test]
  fn migrate_home_keeps_existing_auth() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("auth.yaml"), "version: 1\naccounts: []\n").unwrap();
    fs::write(
      dir.path().join("config.toml"),
      r#"
[[accounts]]
id = "legacy"
provider = "github-copilot"
"#,
    )
    .unwrap();

    let actions = migrate_home(dir.path()).unwrap();

    assert!(actions.is_empty());
    assert_eq!(
      fs::read_to_string(dir.path().join("auth.yaml")).unwrap(),
      "version: 1\naccounts: []\n"
    );
  }

  #[test]
  fn migrate_home_keeps_sidecar_only_auth() {
    let dir = tempfile::tempdir().unwrap();
    let auth_dir = dir.path().join("auth.d");
    fs::create_dir_all(&auth_dir).unwrap();
    fs::write(auth_dir.join("opencode.yaml"), "version: 1\naccounts: []\n").unwrap();
    fs::write(
      dir.path().join("config.toml"),
      r#"
[[accounts]]
id = "legacy"
provider = "github-copilot"
"#,
    )
    .unwrap();

    assert!(migrate_home(dir.path()).unwrap().is_empty());
    assert!(!dir.path().join("auth.yaml").exists());
  }

  #[test]
  fn migrate_home_noops_without_legacy_accounts() {
    let missing = tempfile::tempdir().unwrap();
    assert!(migrate_home(missing.path()).unwrap().is_empty());

    let empty = tempfile::tempdir().unwrap();
    fs::write(empty.path().join("config.toml"), "[server]\nport = 4141\n").unwrap();
    assert!(migrate_home(empty.path()).unwrap().is_empty());
    assert!(!empty.path().join("auth.yaml").exists());
  }

  #[test]
  fn load_legacy_accounts_reports_missing_empty_and_present() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    assert!(load_legacy_accounts(&missing).unwrap().is_none());

    let empty = dir.path().join("empty.toml");
    fs::write(&empty, "[server]\nport = 4141\n").unwrap();
    assert!(load_legacy_accounts(&empty).unwrap().is_none());

    let present = dir.path().join("present.toml");
    fs::write(
      &present,
      r#"
[[accounts]]
id = "legacy"
provider = "github-copilot"
enabled = true
"#,
    )
    .unwrap();
    let accounts = load_legacy_accounts(&present).unwrap().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, "legacy");
  }

  #[test]
  fn parse_legacy_accounts_uses_the_supplied_snapshot() {
    let source = Path::new("captured-config.toml");
    let captured = br#"
[[accounts]]
id = "captured"
provider = "openai"
enabled = true
"#;

    let accounts = parse_legacy_accounts(captured, source).unwrap().unwrap();

    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, "captured");
  }

  #[test]
  fn parse_legacy_accounts_reports_the_snapshot_source() {
    let source = Path::new("captured-config.toml");

    let error = parse_legacy_accounts(&[0xff], source).unwrap_err();

    assert!(format!("{error:#}").contains("captured-config.toml"));
    assert!(format!("{error:#}").contains("UTF-8"));
  }
}

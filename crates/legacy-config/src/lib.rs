pub mod locations;
pub mod schema;
pub mod v2;

use anyhow::Result;
use std::path::Path;

#[derive(Debug, Default)]
pub struct MigrationReport {
  pub location_actions: Vec<locations::LocationAction>,
  pub schema_actions: Vec<schema::SchemaAction>,
}

impl MigrationReport {
  pub fn is_empty(&self) -> bool {
    self.location_actions.is_empty() && self.schema_actions.is_empty()
  }
}

/// Bring legacy router state into the current home and then run schema
/// migrations inside that home.
pub fn ensure_latest_home(home: &Path) -> Result<MigrationReport> {
  ensure_latest_home_with(home, locations::migrate)
}

fn ensure_latest_home_with(
  home: &Path,
  migrate_locations: impl FnOnce(&Path) -> Result<Vec<locations::LocationAction>>,
) -> Result<MigrationReport> {
  let location_actions = migrate_locations(home)?;
  let schema_actions = schema::migrate_home(home)?;
  Ok(MigrationReport {
    location_actions,
    schema_actions,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;

  #[test]
  fn report_is_empty_only_when_no_actions_exist() {
    assert!(MigrationReport::default().is_empty());
    assert!(!MigrationReport {
      location_actions: vec![locations::LocationAction::CopyFile {
        from: "old/config.toml".into(),
        to: "config.toml".into(),
      }],
      schema_actions: Vec::new(),
    }
    .is_empty());
    assert!(!MigrationReport {
      location_actions: Vec::new(),
      schema_actions: vec![schema::SchemaAction::ExtractLegacyAccounts {
        config: "config.toml".into(),
        auth: "auth.yaml".into(),
        count: 1,
      }],
    }
    .is_empty());
  }

  #[test]
  fn ensure_latest_home_runs_schema_migration() {
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

    let report = ensure_latest_home_with(dir.path(), |_| Ok(Vec::new())).unwrap();

    assert!(report.location_actions.is_empty());
    assert!(matches!(
      report.schema_actions.as_slice(),
      [schema::SchemaAction::ExtractLegacyAccounts { count: 1, .. }]
    ));
    assert!(dir.path().join("auth.yaml").exists());
  }
}

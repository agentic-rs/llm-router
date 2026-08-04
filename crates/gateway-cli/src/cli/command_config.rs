use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokn_config::v2::{CompiledConfig, PersistencePaths};
use tokn_config::{Config, LoggingConfig};
use tokn_core::util::http::HttpClientOptions;

/// The small, schema-independent configuration surface used by CLI commands.
///
/// Runtime routing remains v2-only. Transitional CLI commands still accept an
/// unversioned config so operators can inspect credentials and persistence
/// before activating v2, but callers consume only the capabilities they need
/// instead of depending on the legacy runtime model.
pub struct CommandConfig {
  path: PathBuf,
  source: CommandConfigSource,
}

enum CommandConfigSource {
  Legacy(Box<Config>),
  V2(Box<CompiledConfig>),
}

impl CommandConfig {
  pub fn uses_versioned_schema(explicit: Option<&Path>) -> Result<bool> {
    let path = tokn_config::paths::resolve_config_path(explicit).context("resolve the gateway config path")?;
    if !path.exists() {
      return Ok(false);
    }
    has_schema_marker(&path)
  }

  pub fn load(explicit: Option<&Path>) -> Result<Self> {
    let path = tokn_config::paths::resolve_config_path(explicit).context("resolve the gateway config path")?;
    let source = if path.exists() && has_schema_marker(&path)? {
      CommandConfigSource::V2(Box::new(
        tokn_config::v2::load(&path).with_context(|| format!("load version 2 config `{}`", path.display()))?,
      ))
    } else {
      let (config, resolved) = Config::load(Some(&path)).context("load legacy command configuration")?;
      debug_assert_eq!(resolved, path);
      CommandConfigSource::Legacy(Box::new(config))
    };
    Ok(Self { path, source })
  }

  pub fn path(&self) -> &Path {
    &self.path
  }

  pub fn is_v2(&self) -> bool {
    matches!(self.source, CommandConfigSource::V2(_))
  }

  pub fn outbound_http_options(&self) -> HttpClientOptions {
    match &self.source {
      CommandConfigSource::Legacy(config) => config.proxy.to_http_options(),
      CommandConfigSource::V2(config) => config.service().outbound().to_http_client_options(),
    }
  }

  pub fn legacy_logging(&self) -> Option<&LoggingConfig> {
    match &self.source {
      CommandConfigSource::Legacy(config) => Some(&config.logging),
      CommandConfigSource::V2(_) => None,
    }
  }

  pub fn persistence_paths(&self) -> Result<PersistencePaths> {
    match &self.source {
      CommandConfigSource::Legacy(config) => {
        let paths = config.db.resolve_paths()?;
        Ok(PersistencePaths {
          usage_db: paths.usage_db,
          sessions_db: paths.sessions_db,
          requests_dir: paths.requests_dir,
        })
      }
      CommandConfigSource::V2(config) => config.service().persistence().resolve_paths().map_err(Into::into),
    }
  }
}

fn has_schema_marker(path: &Path) -> Result<bool> {
  let contents = std::fs::read_to_string(path).with_context(|| format!("read config `{}`", path.display()))?;
  let document: toml::Value =
    toml::from_str(&contents).with_context(|| format!("parse config `{}`", path.display()))?;
  Ok(document.get("schema_version").is_some())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn exposes_the_same_command_capabilities_for_legacy_and_v2() {
    let directory = tempfile::tempdir().unwrap();
    let legacy_path = directory.path().join("legacy.toml");
    std::fs::write(
      &legacy_path,
      r#"
[proxy]
url = "http://127.0.0.1:8080"
no_proxy = ["legacy.example"]

[db]
usage_db_path = "legacy-usage.db"
sessions_db_path = "legacy-sessions.db"
requests_dir = "legacy-requests"
"#,
    )
    .unwrap();
    let legacy = CommandConfig::load(Some(&legacy_path)).unwrap();
    assert!(!legacy.is_v2());
    assert_eq!(legacy.path(), legacy_path);
    assert_eq!(
      legacy.outbound_http_options().url.as_deref(),
      Some("http://127.0.0.1:8080")
    );
    assert_eq!(legacy.outbound_http_options().no_proxy, ["legacy.example"]);
    assert_eq!(
      legacy.persistence_paths().unwrap().usage_db,
      PathBuf::from("legacy-usage.db")
    );

    let v2_path = directory.path().join("v2.toml");
    std::fs::write(
      &v2_path,
      r#"
schema_version = 2

[service.outbound]
proxy_url = "http://127.0.0.1:8181"
no_proxy = ["v2.example"]

[service.persistence]
usage_db_path = "v2-usage.db"
sessions_db_path = "v2-sessions.db"
requests_dir = "v2-requests"
"#,
    )
    .unwrap();
    let v2 = CommandConfig::load(Some(&v2_path)).unwrap();
    assert!(v2.is_v2());
    assert_eq!(v2.path(), v2_path);
    assert_eq!(
      v2.outbound_http_options().url.as_deref(),
      Some("http://127.0.0.1:8181/")
    );
    assert_eq!(v2.outbound_http_options().no_proxy, ["v2.example"]);
    assert_eq!(v2.persistence_paths().unwrap().usage_db, PathBuf::from("v2-usage.db"));
  }

  #[test]
  fn a_versioned_document_never_falls_back_to_the_legacy_loader() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "schema_version = 3\n").unwrap();

    let Err(error) = CommandConfig::load(Some(&path)) else {
      panic!("unsupported schema unexpectedly loaded")
    };
    assert!(error.to_string().contains("load version 2 config"));
  }
}

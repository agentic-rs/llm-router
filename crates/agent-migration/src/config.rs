use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokn_config::{AgentConfig, Config};

pub const AGENT_CONFIG_SCHEMA_VERSION: u32 = 1;

/// Agent-integration intent, kept separate from the router runtime config.
///
/// Generated router profiles are derived material. This file is the source of
/// truth used by `agent link`, `agent sync`, and status inspection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIntegrationConfig {
  pub schema_version: u32,
  #[serde(default)]
  pub agents: BTreeMap<String, AgentConfig>,
}

impl AgentIntegrationConfig {
  pub fn empty() -> Self {
    Self {
      schema_version: AGENT_CONFIG_SCHEMA_VERSION,
      agents: BTreeMap::new(),
    }
  }

  pub fn validate(&self) -> Result<()> {
    if self.schema_version != AGENT_CONFIG_SCHEMA_VERSION {
      bail!(
        "unsupported agent config schema version {}; expected {}",
        self.schema_version,
        AGENT_CONFIG_SCHEMA_VERSION
      );
    }

    for name in self.agents.keys() {
      let Some(agent) = tokn_core::AgentId::from_slug(name) else {
        bail!("unsupported agent config entry '{name}'");
      };
      if agent.as_str() != name {
        bail!(
          "agent config entry '{name}' must use canonical name '{}'",
          agent.as_str()
        );
      }
      if crate::adapter::adapter_for(&agent).is_none() {
        bail!(
          "agent '{}' is recognized but not supported by agent integration",
          agent.as_str()
        );
      }
    }

    // Reuse the established binding validation while agent configuration is
    // still hosted in this workspace. Router fields remain at their defaults.
    let mut config = Config::default();
    config.agents.clone_from(&self.agents);
    config.validate().context("validating agent integration config")
  }

  pub fn to_yaml(&self) -> Result<Vec<u8>> {
    self.validate()?;
    let mut yaml = serde_yaml::to_string(self).context("serializing agent integration config")?;
    if !yaml.ends_with('\n') {
      yaml.push('\n');
    }
    Ok(yaml.into_bytes())
  }
}

impl Default for AgentIntegrationConfig {
  fn default() -> Self {
    Self::empty()
  }
}

#[derive(Clone, Debug)]
pub(crate) struct AgentConfigSnapshot {
  pub path: PathBuf,
  pub contents: Option<Vec<u8>>,
  pub config: AgentIntegrationConfig,
  pub imported_legacy: bool,
}

impl AgentConfigSnapshot {
  pub fn load(gateway_config_path: &Path, legacy: &Config) -> Result<Self> {
    let path = agent_config_path(gateway_config_path);
    let contents = read_optional(&path)?;
    let (config, imported_legacy) = match contents.as_deref() {
      Some(contents) => (parse(contents, &path)?, false),
      None if !legacy.agents.is_empty() => (
        AgentIntegrationConfig {
          schema_version: AGENT_CONFIG_SCHEMA_VERSION,
          agents: legacy.agents.clone(),
        },
        true,
      ),
      None => (AgentIntegrationConfig::empty(), false),
    };
    config.validate()?;
    Ok(Self {
      path,
      contents,
      config,
      imported_legacy,
    })
  }

  pub fn validate_unchanged(&self) -> Result<()> {
    if read_optional(&self.path)? != self.contents {
      bail!(
        "{} changed after the agent migration plan was created; rerun the command",
        self.path.display()
      );
    }
    Ok(())
  }
}

pub fn agent_config_path(gateway_config_path: &Path) -> PathBuf {
  if gateway_config_path
    .file_name()
    .is_some_and(|name| name == "config.toml")
  {
    return gateway_config_path
      .parent()
      .unwrap_or_else(|| Path::new("."))
      .join("agent.yaml");
  }
  gateway_config_path.with_extension("agent.yaml")
}

pub fn load_agent_config(gateway_config_path: &Path) -> Result<AgentIntegrationConfig> {
  let path = agent_config_path(gateway_config_path);
  Ok(load_agent_config_file(&path)?.unwrap_or_default())
}

/// Load `agent.yaml`, falling back to legacy `[agents.*]` state only when the
/// sidecar has not been created yet.
pub fn load_agent_config_with_legacy(gateway_config_path: &Path, legacy: &Config) -> Result<AgentIntegrationConfig> {
  Ok(AgentConfigSnapshot::load(gateway_config_path, legacy)?.config)
}

pub(crate) fn load_agent_config_file(path: &Path) -> Result<Option<AgentIntegrationConfig>> {
  read_optional(path)?.map(|contents| parse(&contents, path)).transpose()
}

pub(crate) fn read_agent_config_file(path: &Path) -> Result<Option<Vec<u8>>> {
  read_optional(path)
}

fn parse(contents: &[u8], path: &Path) -> Result<AgentIntegrationConfig> {
  let config: AgentIntegrationConfig =
    serde_yaml::from_slice(contents).with_context(|| format!("parsing agent config {}", path.display()))?;
  config.validate()?;
  Ok(config)
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
  match std::fs::read(path) {
    Ok(contents) => Ok(Some(contents)),
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
    Err(source) => Err(anyhow!(source)).with_context(|| format!("reading agent config {}", path.display())),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_config::{AgentAccountSource, RouteMode};

  #[test]
  fn default_and_explicit_gateway_paths_have_independent_agent_configs() {
    assert_eq!(
      agent_config_path(Path::new("/tmp/router/config.toml")),
      Path::new("/tmp/router/agent.yaml")
    );
    assert_eq!(
      agent_config_path(Path::new("/tmp/router/work.toml")),
      Path::new("/tmp/router/work.agent.yaml")
    );
  }

  #[test]
  fn yaml_round_trip_is_strict_and_uses_canonical_fields() {
    let mut config = AgentIntegrationConfig::empty();
    config.agents.insert(
      "opencode".into(),
      AgentConfig {
        mode: Some(RouteMode::Route),
        profile: Some("opencode".into()),
        account_source: AgentAccountSource::Main,
        provider_filter: Some(vec!["openai".into()]),
        sync: true,
        ..AgentConfig::default()
      },
    );
    let yaml = String::from_utf8(config.to_yaml().unwrap()).unwrap();
    assert!(yaml.starts_with("schema_version: 1\nagents:\n"));
    assert!(yaml.contains("  opencode:\n"));
    assert!(yaml.contains("    account_source: main\n"));
    assert_eq!(parse(yaml.as_bytes(), Path::new("agent.yaml")).unwrap(), config);

    let error = parse(b"schema_version: 1\nunknown: true\n", Path::new("agent.yaml")).unwrap_err();
    assert!(error.to_string().contains("parsing agent config"));
  }

  #[test]
  fn legacy_bindings_are_imported_only_when_sidecar_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = dir.path().join("config.toml");
    let mut legacy = Config::default();
    legacy.agents.insert("opencode".into(), AgentConfig::default());

    let snapshot = AgentConfigSnapshot::load(&gateway, &legacy).unwrap();
    assert!(snapshot.imported_legacy);
    assert!(snapshot.config.agents.contains_key("opencode"));

    std::fs::write(agent_config_path(&gateway), "schema_version: 1\nagents: {}\n").unwrap();
    let snapshot = AgentConfigSnapshot::load(&gateway, &legacy).unwrap();
    assert!(!snapshot.imported_legacy);
    assert!(snapshot.config.agents.is_empty());
  }

  #[test]
  fn snapshot_rejects_a_sidecar_created_or_edited_after_loading() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = dir.path().join("config.toml");
    let snapshot = AgentConfigSnapshot::load(&gateway, &Config::default()).unwrap();
    std::fs::write(agent_config_path(&gateway), "schema_version: 1\nagents: {}\n").unwrap();

    let error = snapshot.validate_unchanged().unwrap_err();

    assert!(error.to_string().contains("changed after"));
    assert!(error.to_string().contains("agent.yaml"));
  }
}

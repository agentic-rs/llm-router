use super::Result;
use std::path::{Path, PathBuf};

pub fn config_path() -> Result<PathBuf> {
  Ok(config_dir()?.join("config.toml"))
}

/// Resolve an explicitly selected config path or the standard default.
///
/// Explicit paths are returned lexically unchanged. This function does not
/// require the selected file to exist and does not canonicalize it.
pub fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf> {
  match explicit {
    Some(path) => Ok(path.to_path_buf()),
    None => config_path(),
  }
}

/// Directory containing agent-owned overlays for a primary configuration file.
///
/// The standard `config.toml` uses the conventional sibling `config.d/`
/// directory. Explicitly selected configurations use a matching sibling
/// directory instead (`work.toml` -> `work.d/`) so independent configurations
/// cannot accidentally load one another's agent bindings.
pub fn config_fragment_dir(config_path: &Path) -> PathBuf {
  if config_path.file_name().is_some_and(|name| name == "config.toml") {
    return config_path.parent().unwrap_or_else(|| Path::new(".")).join("config.d");
  }
  config_path.with_extension("d")
}

/// Path for the managed overlay of one agent.
pub fn agent_config_fragment_path(config_path: &Path, agent: &str) -> PathBuf {
  config_fragment_dir(config_path).join(format!("{agent}.toml"))
}

pub fn config_dir() -> Result<PathBuf> {
  tokn_core::util::paths::config_dir().ok_or(super::Error::NoProjectDirs)
}

pub fn data_dir() -> Result<PathBuf> {
  tokn_core::util::paths::data_dir().ok_or(super::Error::NoProjectDirs)
}

pub fn cache_dir() -> Result<PathBuf> {
  tokn_core::util::paths::cache_dir().ok_or(super::Error::NoProjectDirs)
}

pub fn default_usage_db() -> Result<PathBuf> {
  Ok(data_dir()?.join("usage.db"))
}

pub fn default_sessions_db() -> Result<PathBuf> {
  Ok(data_dir()?.join("sessions.db"))
}

pub fn default_requests_dir() -> Result<PathBuf> {
  Ok(data_dir()?.join("requests"))
}

pub fn default_logs_dir() -> Result<PathBuf> {
  Ok(data_dir()?.join("logs"))
}

pub fn default_ca_dir() -> Result<PathBuf> {
  Ok(config_dir()?.join("ca"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn explicit_config_path_is_returned_unchanged() {
    let explicit = Path::new("relative/../selected.toml");

    assert_eq!(resolve_config_path(Some(explicit)).unwrap(), explicit);
  }

  #[test]
  fn absent_explicit_config_path_uses_the_standard_default() {
    assert_eq!(resolve_config_path(None).unwrap(), config_path().unwrap());
  }
}

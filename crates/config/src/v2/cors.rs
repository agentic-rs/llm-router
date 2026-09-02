use crate::CorsConfig;
use serde::{Deserialize, Serialize};
use tokn_policy::CorsPlan;

use super::CompileError;

/// Strict v2 CORS syntax; permissions and validation match legacy CORS.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawCors {
  pub enabled: bool,
  pub allow_localhost: bool,
  pub allowed_origins: Vec<String>,
}

impl From<&CorsConfig> for RawCors {
  fn from(config: &CorsConfig) -> Self {
    Self {
      enabled: config.enabled,
      allow_localhost: config.allow_localhost,
      allowed_origins: config.allowed_origins.clone(),
    }
  }
}

impl RawCors {
  /// Validate even disabled policy so enabling it later cannot expose bad origins.
  pub(super) fn compile(&self, listener_id: &str) -> Result<CorsPlan, CompileError> {
    let config = CorsConfig {
      enabled: self.enabled,
      allow_localhost: self.allow_localhost,
      allowed_origins: self.allowed_origins.clone(),
    };
    let invalid = |error: crate::Error| CompileError::InvalidValue {
      location: format!("listeners.{listener_id}.cors"),
      message: error.to_string(),
    };
    config.validate().map_err(invalid)?;
    if !config.enabled {
      return Ok(CorsPlan::default());
    }
    Ok(CorsPlan::new(
      config.canonical_allowed_origins().map_err(invalid)?,
      config.allow_localhost,
    ))
  }
}

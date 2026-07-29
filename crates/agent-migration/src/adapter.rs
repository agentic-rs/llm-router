//! Per-agent adapters: discovery of credentials and rewriting of an agent's own
//! config so it routes through a gateway profile. Everything agent-specific
//! lives behind the [`AgentAdapter`] trait; the rest of the crate is generic.

use crate::adapters::{codex::CodexAdapter, opencode::OpencodeAdapter};
use crate::projection::AgentConfigProjection;
use crate::reconcile::PlannedEdit;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokn_config::Account;
use tokn_core::provider::Endpoint;
use tokn_core::AgentId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProviderRoute {
  pub source_provider_id: String,
  pub gateway_provider_id: String,
  pub account_id: String,
  pub profile: String,
  pub base_url: String,
  #[serde(default)]
  pub transfer_source_auth: bool,
}

pub(crate) fn source_provider_id(account: &Account) -> Option<&str> {
  account
    .settings
    .get("import")
    .and_then(toml::Value::as_table)
    .and_then(|import| import.get("source_provider"))
    .and_then(toml::Value::as_str)
}

/// A local agent the gateway can bind to: import credentials from it and point
/// its own config at a gateway profile.
pub trait AgentAdapter {
  /// Provider id used to scope a materialised profile that has no imported
  /// accounts of its own.
  fn default_provider_id(&self) -> &'static str;

  /// Absolute path to the agent's credential store for a given home dir.
  fn auth_path(&self, home: &Path) -> PathBuf;

  /// Absolute path to the agent's own config file for a given home dir.
  fn config_path(&self, home: &Path) -> PathBuf;

  /// Best-effort credential discovery. An empty vec means "nothing importable
  /// found" and is **not** an error.
  fn discover_accounts(&self, home: &Path, timestamp: &str) -> Result<Vec<Account>>;

  /// Whether linking transfers credential ownership from the agent to the
  /// gateway instead of maintaining a source-managed copy.
  fn transfers_credentials(&self) -> bool {
    false
  }

  /// Whether the adapter can be linked without reading or rewriting the
  /// agent's credential store. Agents that need a local token bootstrap must
  /// opt in only after they have a configuration-only solution.
  fn supports_main_accounts(&self) -> bool {
    false
  }

  /// Wire endpoint emitted by the generated agent configuration. Verbatim
  /// modes must select a provider that supports this exact endpoint.
  fn switch_endpoint(&self) -> Endpoint;

  /// Whether the agent can express provider-qualified model ids required by
  /// exact routing. The default is conservative because a bare model would
  /// make an exact profile unusable.
  fn supports_exact_mode(&self) -> bool {
    false
  }

  /// Produce the edits that point the agent's own config at the gateway.
  fn rewrite_config(&self, home: &Path, projection: &AgentConfigProjection<'_>) -> Result<Vec<PlannedEdit>>;

  /// Export the gateway-owned credentials back into the agent during unlink.
  fn restore_transferred_credentials(&self, _auth_path: &Path, _accounts: &[Account]) -> Result<()> {
    Ok(())
  }
}

/// Resolve the adapter for an agent, if the agent is supported.
pub fn adapter_for(agent: &AgentId) -> Option<Box<dyn AgentAdapter>> {
  match agent {
    AgentId::Opencode => Some(Box::new(OpencodeAdapter)),
    AgentId::CodexCli => Some(Box::new(CodexAdapter)),
    _ => None,
  }
}

/// All agents with a built-in adapter, in stable display order.
pub fn supported_agents() -> Vec<AgentId> {
  vec![AgentId::Opencode, AgentId::CodexCli]
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn supported_agents_have_adapters() {
    for agent in supported_agents() {
      assert!(adapter_for(&agent).is_some(), "{} should be supported", agent.as_str());
    }
  }

  #[test]
  fn unknown_agents_are_unsupported() {
    assert!(adapter_for(&AgentId::ClaudeCode).is_none());
    assert!(adapter_for(&AgentId::from("bespoke")).is_none());
  }
}

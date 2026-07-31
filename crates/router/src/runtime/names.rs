//! Strict runtime resolution for policy-owned symbolic names.
//!
//! Configuration compilation validates identifier syntax and graph-local
//! references. This registry owns the runtime boundary where operation names,
//! wire identities, and provider defaults become executable core values.
//! Unknown names remain unresolved unless a plugin registers them explicitly.

use snafu::Snafu;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use tokn_accounts::registry::Registry as ProviderRegistry;
use tokn_core::provider::Endpoint;
use tokn_core::AgentId;
use tokn_policy::{OperationId, ProviderId, WireIdentityId};

/// Runtime values attached to names referenced by a compiled gateway plan.
#[derive(Clone, Debug, Default)]
pub struct RuntimeNameRegistry {
  operations: BTreeMap<OperationId, Endpoint>,
  wire_identities: BTreeMap<WireIdentityId, AgentId>,
  provider_defaults: BTreeMap<ProviderId, AgentId>,
}

impl RuntimeNameRegistry {
  /// Construct an empty registry for a fully custom runtime.
  pub fn new() -> Self {
    Self::default()
  }

  /// Construct the built-in runtime namespace.
  ///
  /// Named identities include canonical names and the aliases already
  /// recognized by the header identity layer. Aliases resolve to canonical
  /// [`AgentId`] variants; arbitrary names never become [`AgentId::Other`]
  /// implicitly.
  pub fn builtin() -> Self {
    let mut registry = Self::new();

    for (name, endpoint) in [
      ("chat_completions", Endpoint::ChatCompletions),
      ("responses", Endpoint::Responses),
      ("messages", Endpoint::Messages),
    ] {
      registry
        .register_operation(operation_id(name), endpoint)
        .expect("built-in operation ids must be unique");
    }

    for (name, agent_id) in [
      ("opencode", AgentId::Opencode),
      ("codex-cli", AgentId::CodexCli),
      ("codex_exec", AgentId::CodexCli),
      ("codex-tui", AgentId::CodexCli),
      ("codex", AgentId::CodexCli),
      ("claude-code", AgentId::ClaudeCode),
      ("claude-cli", AgentId::ClaudeCode),
      ("cline", AgentId::Cline),
      ("copilot-cli", AgentId::CopilotCli),
      ("copilot", AgentId::CopilotCli),
    ] {
      registry
        .register_wire_identity(wire_identity_id(name), agent_id)
        .expect("built-in wire identity ids must be unique");
    }

    for provider in ProviderRegistry::builtin().ids() {
      let agent_id = AgentId::provider_default(provider)
        .unwrap_or_else(|| panic!("built-in provider '{provider}' must declare a default wire identity"));
      registry
        .register_provider_default(provider_id(provider), agent_id)
        .expect("built-in provider ids must be unique");
    }

    registry
  }

  pub fn register_operation(&mut self, id: OperationId, endpoint: Endpoint) -> RuntimeNameResult<()> {
    match self.operations.entry(id) {
      Entry::Vacant(entry) => {
        entry.insert(endpoint);
        Ok(())
      }
      Entry::Occupied(entry) => Err(RuntimeNameError::DuplicateOperation {
        id: entry.key().clone(),
        existing: *entry.get(),
        attempted: endpoint,
      }),
    }
  }

  pub fn register_wire_identity(&mut self, id: WireIdentityId, agent_id: AgentId) -> RuntimeNameResult<()> {
    match self.wire_identities.entry(id) {
      Entry::Vacant(entry) => {
        entry.insert(agent_id);
        Ok(())
      }
      Entry::Occupied(entry) => Err(RuntimeNameError::DuplicateWireIdentity {
        id: entry.key().clone(),
        existing: entry.get().clone(),
        attempted: agent_id,
      }),
    }
  }

  pub fn register_provider_default(&mut self, id: ProviderId, agent_id: AgentId) -> RuntimeNameResult<()> {
    match self.provider_defaults.entry(id) {
      Entry::Vacant(entry) => {
        entry.insert(agent_id);
        Ok(())
      }
      Entry::Occupied(entry) => Err(RuntimeNameError::DuplicateProviderDefault {
        id: entry.key().clone(),
        existing: entry.get().clone(),
        attempted: agent_id,
      }),
    }
  }

  pub fn resolve_operation(&self, id: &OperationId) -> Option<Endpoint> {
    self.operations.get(id).copied()
  }

  pub fn resolve_wire_identity(&self, id: &WireIdentityId) -> Option<&AgentId> {
    self.wire_identities.get(id)
  }

  pub fn resolve_provider_default(&self, id: &ProviderId) -> Option<&AgentId> {
    self.provider_defaults.get(id)
  }

  pub fn operations(&self) -> impl ExactSizeIterator<Item = (&OperationId, Endpoint)> {
    self.operations.iter().map(|(id, endpoint)| (id, *endpoint))
  }

  pub fn wire_identities(&self) -> impl ExactSizeIterator<Item = (&WireIdentityId, &AgentId)> {
    self.wire_identities.iter()
  }

  pub fn provider_defaults(&self) -> impl ExactSizeIterator<Item = (&ProviderId, &AgentId)> {
    self.provider_defaults.iter()
  }
}

#[derive(Clone, Debug, Eq, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum RuntimeNameError {
  #[snafu(display("operation id '{id}' is already registered as '{existing}', cannot register it as '{attempted}'"))]
  DuplicateOperation {
    id: OperationId,
    existing: Endpoint,
    attempted: Endpoint,
  },

  #[snafu(display(
    "wire identity id '{id}' is already registered as '{existing}', cannot register it as '{attempted}'"
  ))]
  DuplicateWireIdentity {
    id: WireIdentityId,
    existing: AgentId,
    attempted: AgentId,
  },

  #[snafu(display(
    "provider id '{id}' already has default wire identity '{existing}', cannot register '{attempted}'"
  ))]
  DuplicateProviderDefault {
    id: ProviderId,
    existing: AgentId,
    attempted: AgentId,
  },
}

pub type RuntimeNameResult<T> = std::result::Result<T, RuntimeNameError>;

fn operation_id(value: &str) -> OperationId {
  OperationId::new(value).expect("built-in operation id must be canonical")
}

fn wire_identity_id(value: &str) -> WireIdentityId {
  WireIdentityId::new(value).expect("built-in wire identity id must be canonical")
}

fn provider_id(value: &str) -> ProviderId {
  ProviderId::new(value).expect("built-in provider id must be canonical")
}

#[cfg(test)]
mod tests {
  use super::*;
  use smol_str::SmolStr;

  #[test]
  fn builtins_cover_canonical_operations_identities_and_provider_defaults() {
    let registry = RuntimeNameRegistry::builtin();

    assert_eq!(
      registry.resolve_operation(&operation_id("chat_completions")),
      Some(Endpoint::ChatCompletions)
    );
    assert_eq!(
      registry.resolve_operation(&operation_id("responses")),
      Some(Endpoint::Responses)
    );
    assert_eq!(
      registry.resolve_operation(&operation_id("messages")),
      Some(Endpoint::Messages)
    );

    for (name, expected) in [
      ("opencode", AgentId::Opencode),
      ("codex-cli", AgentId::CodexCli),
      ("claude-code", AgentId::ClaudeCode),
      ("cline", AgentId::Cline),
      ("copilot-cli", AgentId::CopilotCli),
    ] {
      assert_eq!(registry.resolve_wire_identity(&wire_identity_id(name)), Some(&expected));
    }

    let providers = ProviderRegistry::builtin();
    for provider in providers.iter() {
      let expected = AgentId::provider_default(provider.id).unwrap();
      assert_eq!(
        registry.resolve_provider_default(&provider_id(provider.id)),
        Some(&expected)
      );
    }

    assert_eq!(registry.operations().len(), 3);
    assert_eq!(registry.wire_identities().len(), 10);
    assert_eq!(registry.provider_defaults().len(), providers.ids().len());
  }

  #[test]
  fn identity_aliases_normalize_to_canonical_agent_ids() {
    let registry = RuntimeNameRegistry::builtin();

    for alias in ["codex_exec", "codex-tui", "codex"] {
      assert_eq!(
        registry.resolve_wire_identity(&wire_identity_id(alias)),
        Some(&AgentId::CodexCli)
      );
    }
    assert_eq!(
      registry.resolve_wire_identity(&wire_identity_id("claude-cli")),
      Some(&AgentId::ClaudeCode)
    );
    assert_eq!(
      registry.resolve_wire_identity(&wire_identity_id("copilot")),
      Some(&AgentId::CopilotCli)
    );
  }

  #[test]
  fn unknown_names_remain_strictly_unresolved() {
    let registry = RuntimeNameRegistry::builtin();

    assert_eq!(registry.resolve_operation(&operation_id("chat")), None);
    assert_eq!(registry.resolve_wire_identity(&wire_identity_id("custom-agent")), None);
    assert_eq!(registry.resolve_provider_default(&provider_id("custom-provider")), None);
    assert_eq!(registry.resolve_provider_default(&provider_id("copilot")), None);
  }

  #[test]
  fn duplicate_registration_reports_existing_and_attempted_values() {
    let mut registry = RuntimeNameRegistry::builtin();

    assert_eq!(
      registry.register_operation(operation_id("responses"), Endpoint::Messages),
      Err(RuntimeNameError::DuplicateOperation {
        id: operation_id("responses"),
        existing: Endpoint::Responses,
        attempted: Endpoint::Messages,
      })
    );
    assert_eq!(
      registry.register_wire_identity(wire_identity_id("codex"), AgentId::Cline),
      Err(RuntimeNameError::DuplicateWireIdentity {
        id: wire_identity_id("codex"),
        existing: AgentId::CodexCli,
        attempted: AgentId::Cline,
      })
    );
    assert_eq!(
      registry.register_provider_default(provider_id("openai"), AgentId::ClaudeCode),
      Err(RuntimeNameError::DuplicateProviderDefault {
        id: provider_id("openai"),
        existing: AgentId::Opencode,
        attempted: AgentId::ClaudeCode,
      })
    );

    assert_eq!(
      registry.resolve_operation(&operation_id("responses")),
      Some(Endpoint::Responses)
    );
    assert_eq!(
      registry.resolve_wire_identity(&wire_identity_id("codex")),
      Some(&AgentId::CodexCli)
    );
    assert_eq!(
      registry.resolve_provider_default(&provider_id("openai")),
      Some(&AgentId::Opencode)
    );
  }

  #[test]
  fn explicit_custom_registration_supports_other_agent_ids() {
    let mut registry = RuntimeNameRegistry::new();
    let custom_agent = AgentId::Other(SmolStr::new("acme-agent-runtime"));
    let custom_identity = wire_identity_id("acme-agent");
    let custom_provider = provider_id("acme-provider");

    registry
      .register_operation(operation_id("acme_generate"), Endpoint::Responses)
      .unwrap();
    registry
      .register_wire_identity(custom_identity.clone(), custom_agent.clone())
      .unwrap();
    registry
      .register_provider_default(custom_provider.clone(), custom_agent.clone())
      .unwrap();

    assert_eq!(
      registry.resolve_operation(&operation_id("acme_generate")),
      Some(Endpoint::Responses)
    );
    assert_eq!(registry.resolve_wire_identity(&custom_identity), Some(&custom_agent));
    assert_eq!(registry.resolve_provider_default(&custom_provider), Some(&custom_agent));
  }
}

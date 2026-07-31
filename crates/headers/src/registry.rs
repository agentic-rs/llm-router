//! Registry mapping `(provider, agent_id)` to the typed header schema pair.
//!
//! Each successful lookup yields a [`ResolvedSchema`] describing which header
//! struct and (optional) overlay struct should be applied. Composition is
//! overlay-wins via [`HeaderMap::merge_replacing`]: any name set by both the
//! client-id headers and the overlay takes the overlay's value.
//!
//! Unknown agents for a known provider fall back to [`AgentKind::Opencode`]
//! as a sensible default base. Unknown providers return [`None`].

use crate::agent::{build_agent_headers, AgentKind};
use crate::map::HeaderMap;
use crate::schemas::{CodexOverlay, CopilotOverlay};
use crate::{HeaderSchema, TemplateVars};

/// Closed enum of provider transport overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OverlayKind {
  Copilot,
  Codex,
}

/// The schema pair selected for a given `(provider, persona)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSchema {
  pub agent: AgentKind,
  pub overlay: Option<OverlayKind>,
}

impl ResolvedSchema {
  /// Compose persona-built and overlay-built maps into a single map. Overlay
  /// values win on name conflict; otherwise persona ordering is preserved.
  pub fn compose(persona_map: HeaderMap, overlay_map: Option<HeaderMap>) -> HeaderMap {
    let mut out = persona_map;
    if let Some(o) = overlay_map {
      out.merge_replacing(o);
    }
    out
  }
}

/// Look up the schema pair for a given `(provider, agent_id)`. Returns `None`
/// for unknown providers; for known providers, falls back to
/// [`AgentKind::Opencode`] as the base agent when `agent_id` is unknown.
pub fn lookup(provider: &str, agent_id: &str) -> Option<ResolvedSchema> {
  let base = AgentKind::from_agent_id(agent_id).unwrap_or(AgentKind::Opencode);
  match provider {
    "openai" => Some(ResolvedSchema {
      agent: base,
      overlay: matches!(base, AgentKind::CodexCli).then_some(OverlayKind::Codex),
    }),
    "copilot" | "github-copilot" => Some(ResolvedSchema {
      agent: base,
      overlay: Some(OverlayKind::Copilot),
    }),
    "deepseek" | "zai" | "zai-coding-plan" | "zhipuai" | "zhipuai-coding-plan" | "codex" => Some(ResolvedSchema {
      agent: base,
      overlay: matches!(provider, "codex").then_some(OverlayKind::Codex),
    }),
    _ => None,
  }
}

/// Build the provider-aware headers for one explicit wire identity.
///
/// Unknown providers still receive headers from a known agent identity, while
/// known providers may add their transport overlay. Callers decide whether
/// these headers replace or overlay a sanitized inbound map.
pub fn build_wire_identity_headers(
  provider: &str,
  agent_id: &str,
  vars: &TemplateVars,
  inbound: &HeaderMap,
) -> HeaderMap {
  let Some(schema) = lookup(provider, agent_id) else {
    return build_agent_headers(agent_id, vars, inbound);
  };
  let persona = schema.agent.build_outbound(vars, inbound);
  let overlay = schema.overlay.map(|kind| match kind {
    OverlayKind::Copilot => CopilotOverlay::build(vars, inbound).dump(),
    OverlayKind::Codex => CodexOverlay::build(vars, inbound).dump(),
  });
  ResolvedSchema::compose(persona, overlay)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::keys;
  use crate::name::HeaderName;
  use crate::value::HeaderValue;

  #[test]
  fn lookup_known_pairs() {
    assert_eq!(
      lookup("openai", "codex-cli"),
      Some(ResolvedSchema {
        agent: AgentKind::CodexCli,
        overlay: Some(OverlayKind::Codex)
      })
    );
    assert_eq!(
      lookup("copilot", "opencode"),
      Some(ResolvedSchema {
        agent: AgentKind::Opencode,
        overlay: Some(OverlayKind::Copilot)
      })
    );
    assert_eq!(
      lookup("deepseek", "claude-code"),
      Some(ResolvedSchema {
        agent: AgentKind::ClaudeCode,
        overlay: None
      })
    );
  }

  #[test]
  fn unknown_agent_falls_back_to_opencode() {
    let r = lookup("copilot", "my-tool").unwrap();
    assert_eq!(r.agent, AgentKind::Opencode);
    assert_eq!(r.overlay, Some(OverlayKind::Copilot));
  }

  #[test]
  fn unknown_provider_returns_none() {
    assert!(lookup("nonesuch", "opencode").is_none());
  }

  #[test]
  fn openai_with_non_codex_persona_has_no_overlay() {
    let r = lookup("openai", "opencode").unwrap();
    assert!(r.overlay.is_none());
  }

  #[test]
  fn copilot_cli_resolves_with_copilot_overlay() {
    let r = lookup("copilot", "copilot-cli").unwrap();
    assert_eq!(r.agent, AgentKind::CopilotCli);
    assert_eq!(r.overlay, Some(OverlayKind::Copilot));
  }

  #[test]
  fn compose_overlay_wins_on_conflict() {
    let mut persona_map = HeaderMap::new();
    persona_map.insert(
      HeaderName::new("X-Session-Id"),
      HeaderValue::from_string("from-persona".into()),
    );
    persona_map.insert("X-Persona-Only", HeaderValue::from_string("p".into()));
    let mut overlay_map = HeaderMap::new();
    overlay_map.insert(
      HeaderName::new("x-session-id"),
      HeaderValue::from_string("from-overlay".into()),
    );
    overlay_map.insert("X-Overlay-Only", HeaderValue::from_string("o".into()));

    let composed = ResolvedSchema::compose(persona_map, Some(overlay_map));
    assert_eq!(composed.get(&keys::X_SESSION_ID).unwrap().as_str(), "from-overlay");
    assert_eq!(composed.get("X-Persona-Only").unwrap().as_str(), "p");
    assert_eq!(composed.get("X-Overlay-Only").unwrap().as_str(), "o");
  }

  #[test]
  fn compose_without_overlay_is_identity() {
    let mut persona_map = HeaderMap::new();
    persona_map.insert("A", HeaderValue::from_string("1".into()));
    let composed = ResolvedSchema::compose(persona_map.clone(), None);
    assert_eq!(composed, persona_map);
  }

  #[test]
  fn wire_identity_builder_applies_provider_overlay() {
    let headers = build_wire_identity_headers(
      "github-copilot",
      "opencode",
      &TemplateVars::default(),
      &HeaderMap::new(),
    );

    assert!(headers.contains_key(&keys::EDITOR_VERSION));
    assert!(headers.contains_key(&keys::COPILOT_INTEGRATION_ID));
  }
}

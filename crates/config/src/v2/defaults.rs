//! Opt-in authoring shorthand, expanded before the existing graph compiler.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use super::{
  CompileError, RawAccountPool, RawConfig, RawModelSelector, RawOperationPolicy, RawProfile, RawProviderSelector,
  RawRoute, RawRouteRetry, RawWireIdentity,
};

const DEFAULT_ID: &str = "default";

/// A recipe for `profiles.default`, `routes.default`, and `account_pools.default`.
///
/// This is not inheritance: other named resources are never modified. Listener
/// bindings and fallbacks must explicitly select the generated default profile.
/// Retries remain disabled unless a policy is explicitly referenced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawDefaultPolicy {
  pub provider: RawProviderSelector,
  pub model: RawModelSelector,
  pub operation: RawOperationPolicy,
  pub wire_identity: RawWireIdentity,
  pub retry: RawRouteRetry,
  pub account_pool: RawAccountPool,
}

impl Default for RawDefaultPolicy {
  fn default() -> Self {
    Self {
      provider: RawProviderSelector::Any {},
      model: RawModelSelector::Capability {},
      operation: RawOperationPolicy::TranslateCompatible,
      wire_identity: RawWireIdentity::default(),
      retry: RawRouteRetry::default(),
      account_pool: RawAccountPool::default(),
    }
  }
}

pub(super) fn expand(raw: &RawConfig) -> Result<Cow<'_, RawConfig>, CompileError> {
  let Some(defaults) = &raw.defaults else {
    return Ok(Cow::Borrowed(raw));
  };

  // Never silently replace, merge, or choose a different resource id. These
  // names are part of the visible routing graph and own independent pool state.
  for (resource, exists) in [
    ("profiles", raw.profiles.contains_key(DEFAULT_ID)),
    ("routes", raw.routes.contains_key(DEFAULT_ID)),
    ("account_pools", raw.account_pools.contains_key(DEFAULT_ID)),
  ] {
    if exists {
      return Err(CompileError::InvalidValue {
        location: "defaults".into(),
        message: format!(
          "cannot combine [defaults] with [{resource}.{DEFAULT_ID}]; configure the default policy in one form only"
        ),
      });
    }
  }

  let mut expanded = raw.clone();
  expanded.defaults = None;
  expanded.profiles.insert(
    DEFAULT_ID.into(),
    RawProfile {
      route: DEFAULT_ID.into(),
      wire_identity: defaults.wire_identity.clone(),
    },
  );
  expanded.routes.insert(
    DEFAULT_ID.into(),
    RawRoute::Managed {
      account_pool: DEFAULT_ID.into(),
      provider: defaults.provider.clone(),
      model: defaults.model.clone(),
      operation: defaults.operation,
      retry: defaults.retry.clone(),
    },
  );
  expanded
    .account_pools
    .insert(DEFAULT_ID.into(), defaults.account_pool.clone());
  Ok(Cow::Owned(expanded))
}

/// Point value diagnostics back to the authored shorthand, rather than asking
/// users to edit a generated resource that is not present in their document.
pub(super) fn source_error(raw: &RawConfig, mut error: CompileError) -> CompileError {
  if let CompileError::InvalidValue { location, .. } = &mut error {
    // Identifiers may contain dots. If an explicit resource could own this
    // path (for example account_pools."default.other"), keep the original
    // diagnostic instead of mistaking it for a generated default resource.
    let mut explicit_paths = raw
      .profiles
      .keys()
      .map(|id| format!("profiles.{id}."))
      .chain(raw.routes.keys().map(|id| format!("routes.{id}.")))
      .chain(raw.account_pools.keys().map(|id| format!("account_pools.{id}.")));
    if explicit_paths.any(|prefix| location.starts_with(&prefix)) {
      return error;
    }
    for (generated, authored) in [
      ("profiles.default.", "defaults."),
      ("routes.default.", "defaults."),
      ("account_pools.default.", "defaults.account_pool."),
    ] {
      if let Some(field) = location.strip_prefix(generated) {
        *location = format!("{authored}{field}");
        break;
      }
    }
  }
  error
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rust_defaults_match_serde_defaults() {
    assert_eq!(
      toml::from_str::<RawDefaultPolicy>("").unwrap(),
      RawDefaultPolicy::default()
    );
    assert_eq!(toml::from_str::<RawAccountPool>("").unwrap(), RawAccountPool::default());
  }

  #[test]
  fn expansion_is_idempotent_and_leaves_the_input_unchanged() {
    let raw: RawConfig = toml::from_str("schema_version = 2\n[defaults]\n").unwrap();
    let before = raw.clone();
    let expanded = expand(&raw).unwrap();
    assert_eq!(raw, before);
    assert!(expanded.defaults.is_none());
    assert!(matches!(expand(&expanded).unwrap(), Cow::Borrowed(_)));
    assert_eq!(*expand(&expanded).unwrap(), *expanded);
  }
}

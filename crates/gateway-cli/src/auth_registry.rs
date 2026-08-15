//! Provider-id → [`ProviderAuth`] dispatch.
//!
//! Both the dispatch table and the list of known providers are derived
//! from the [`tokn_router::accounts::registry::Registry`] descriptor list,
//! which now carries `build_auth: Option<fn() -> &'static dyn ProviderAuth>`
//! on every [`tokn_auth::ProviderDescriptor`]. Adding a new provider only
//! requires registering its descriptor; this module needs no edits.

use std::sync::OnceLock;
use tokn_auth::{descriptor::ProviderDescriptor, ProviderAuth};
use tokn_router::accounts::registry::Registry;

fn registry() -> &'static Registry {
  static R: OnceLock<Registry> = OnceLock::new();
  R.get_or_init(Registry::builtin)
}

/// Resolve the [`ProviderAuth`] impl for a provider id, or `None` if no
/// known provider matches.
pub fn provider_auth_for(id: &str) -> Option<&'static dyn ProviderAuth> {
  registry().resolve(id).and_then(|d| d.provider_auth())
}

/// Resolve the descriptor that supplies a configured provider's auth
/// behavior. Official destinations preserve their own descriptor, while a
/// custom v2 provider inherits its reusable driver's descriptor.
pub fn provider_descriptor_for(provider_id: &str, driver_id: &str) -> Option<&'static ProviderDescriptor> {
  registry().resolve_provider_descriptor(provider_id, driver_id)
}

/// All provider ids known to the registry, sorted alphabetically (stable
/// for CLI pickers).
pub fn known_providers() -> Vec<&'static str> {
  let mut ids = registry()
    .iter()
    .filter(|descriptor| descriptor.build_auth.is_some())
    .map(|descriptor| descriptor.id)
    .collect::<Vec<_>>();
  ids.sort_unstable();
  ids
}

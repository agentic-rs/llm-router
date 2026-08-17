//! Static, declarative metadata about a provider — the single source of
//! truth for the registry.
//!
//! Each provider crate exports one or more [`ProviderDescriptor`]
//! `static`s. The registry in `tokn-router::accounts::registry` walks the
//! built-in list and uses the data here to:
//!
//! * resolve provider id ↔ host(s) ↔ canonical base URL,
//! * dispatch HTTP intercept rules in the `mitm` proxy,
//! * rewrite well-known inbound paths to the canonical `/v1/*` shape,
//! * look up the [`ProviderAuth`] impl for credential lifecycle calls,
//! * declare which auth URLs the provider talks to (device flow, OAuth
//!   token endpoint, …) so they live in one place instead of being
//!   sprinkled across `auth_*.rs` modules.
//!
//! `ProviderDescriptor` lives in `tokn-auth` (rather than `tokn-core`) so it
//! can carry a `build_auth: fn() -> &'static dyn ProviderAuth` field
//! without creating a `core ↔ auth` dependency cycle.

use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::provider::{Endpoint, EndpointRule, Provider, ProviderTarget, Result};

use crate::provider::{CredentialFlavor, ProviderAuth};

/// One canonical endpoint exposed by a provider, paired with its path
/// under [`ProviderDescriptor::base_url`].
///
/// Used by the proxy to (a) recognise canonical paths as already-rewritten
/// (no-op rewrite), and (b) by future routing logic to enumerate which
/// endpoints a provider serves without calling [`Provider::supports`].
#[derive(Copy, Clone, Debug)]
pub struct EndpointSpec {
  pub endpoint: Endpoint,
  pub method: &'static str,
  pub path: &'static str,
  pub aliases: &'static [&'static str],
}

/// A non-canonical inbound path that the proxy should rewrite to the
/// matching canonical [`EndpointSpec::path`] before dispatching.
///
/// Example: `chatgpt.com POST /backend-api/codex/responses` →
/// `POST /v1/responses`.
#[derive(Copy, Clone, Debug)]
pub struct PathRewrite {
  pub method: &'static str,
  pub src: &'static str,
  pub path: &'static str,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RewriteTarget {
  Endpoint(Endpoint),
  Path(&'static str),
}

/// All metadata a provider statically exports. Constructed once per
/// provider id and registered with the global registry.
pub struct ProviderDescriptor {
  pub id: &'static str,
  pub display_name: &'static str,
  /// Hosts the proxy should intercept on behalf of this provider. The
  /// first entry is treated as canonical for display purposes.
  pub hosts: &'static [&'static str],
  /// Default upstream base URL (no trailing slash). Runtime construction
  /// canonicalizes this into a [`ProviderTarget`] when no explicit target
  /// is selected.
  pub base_url: &'static str,
  /// Credential flavors this provider accepts during onboarding. Listed
  /// in priority order — the CLI picker presents them in this sequence.
  pub credentials: &'static [CredentialFlavor],
  /// Endpoints this provider serves and their canonical paths.
  pub endpoints: &'static [EndpointSpec],
  /// Per-model endpoint rules. First-match-wins glob patterns mapping a
  /// model id (or pattern like `"claude-*"`) to the subset of endpoints
  /// from [`Self::endpoints`] that the model supports. Empty means
  /// "every model is allowed on every endpoint in [`Self::endpoints`]".
  ///
  /// Consumed by the default [`Provider::supports`] impl via
  /// [`Provider::endpoint_rules`].
  pub model_endpoint_rules: Option<&'static [EndpointRule]>,
  /// Resolve one supported LLM operation against an explicitly configured
  /// provider target without requiring an account-bound [`Provider`]
  /// instance. Opaque client-credential routes use this to keep destination
  /// selection independent from account selection.
  pub operation_url: fn(&ProviderTarget, Endpoint) -> Result<reqwest::Url>,
  /// Non-canonical inbound paths the proxy should rewrite. The proxy
  /// also short-circuits when an inbound path already matches an entry
  /// in [`Self::endpoints`], so canonical paths do not need to appear
  /// here.
  pub rewrites: &'static [PathRewrite],
  /// Named auth URLs (e.g. `("device_token", "https://…")`). Empty for
  /// static-key providers. Looked up via [`Self::auth_url`].
  pub auth_urls: &'static [(&'static str, &'static str)],
  /// Disambiguates between multiple descriptors that share a host (e.g.
  /// the four Z.ai aliases on `api.z.ai` / `open.bigmodel.cn`, or
  /// `chatgpt.com` shared between codex and a future passthrough).
  pub matches_url: fn(&str, &str, &'static str) -> bool,
  /// Validates an [`AccountConfig`] before it is built into a `Provider`.
  pub validate: fn(&AccountConfig) -> Result<()>,
  /// Constructs the runtime [`Provider`] for a validated account at the
  /// explicitly selected upstream target.
  pub build: fn(Arc<AccountConfig>, ProviderTarget) -> Result<Arc<dyn Provider>>,
  /// Accessor for the [`ProviderAuth`] impl, or `None` for hypothetical
  /// passive-intercept providers that need no credentials.
  pub build_auth: Option<fn() -> &'static dyn ProviderAuth>,
}

impl ProviderDescriptor {
  pub fn matches(&self, id: &str) -> bool {
    self.id == id
  }

  pub fn matches_host(&self, host: &str) -> bool {
    self.hosts.contains(&host)
  }

  pub fn matches_url(&self, host: &str, path: &str) -> bool {
    (self.matches_url)(host, path, self.id)
  }

  pub fn supports_credential(&self, flavor: CredentialFlavor) -> bool {
    self.credentials.contains(&flavor)
  }

  pub fn endpoint_path(&self, endpoint: Endpoint) -> Option<&'static str> {
    self.endpoints.iter().find(|e| e.endpoint == endpoint).map(|e| e.path)
  }

  pub fn operation_url(&self, target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
    (self.operation_url)(target, endpoint)
  }

  /// Look up a named auth URL.
  pub fn auth_url(&self, name: &str) -> Option<&'static str> {
    self.auth_urls.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
  }

  /// Convenience: same as `auth_url` but panics with a descriptive
  /// message. Use only in code paths where the URL is statically known
  /// to be present (verified by registry tests).
  pub fn auth_url_required(&self, name: &str) -> &'static str {
    self
      .auth_url(name)
      .unwrap_or_else(|| panic!("provider {} is missing required auth_url '{name}'", self.id))
  }

  /// Resolve `(method, path)` against [`Self::endpoints`] then
  /// [`Self::rewrites`]. Endpoint-backed routes return the matched
  /// [`Endpoint`] so the local proxy can derive the canonical API path;
  /// raw non-endpoint rewrites return a replacement path string.
  pub fn rewrite(&self, method: &str, path: &str) -> Option<RewriteTarget> {
    if let Some(spec) = self
      .endpoints
      .iter()
      .find(|e| e.method.eq_ignore_ascii_case(method) && (e.path == path || e.aliases.contains(&path)))
    {
      return Some(RewriteTarget::Endpoint(spec.endpoint));
    }
    self
      .rewrites
      .iter()
      .find(|r| r.method.eq_ignore_ascii_case(method) && r.src == path)
      .map(|r| RewriteTarget::Path(r.path))
  }

  pub fn provider_auth(&self) -> Option<&'static dyn ProviderAuth> {
    self.build_auth.map(|f| f())
  }
}

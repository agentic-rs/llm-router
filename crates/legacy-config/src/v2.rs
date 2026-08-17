//! Pure, in-memory projection from an effective legacy configuration to v2.
//!
//! This module deliberately owns no filesystem behavior. It neither reads nor
//! writes config or auth files, and it does not change runtime schema
//! selection. A caller supplies the already-merged legacy config and aggregate
//! auth store, then receives a compiled v2 plan plus ephemeral account copies.

use std::net::SocketAddr;

use thiserror::Error;
use tokn_config::RouteMode;

mod analysis;
mod compose;
mod resources;

pub use compose::{project_v2_config, V2Projection};

/// Explicit choices that can relax a safety check during projection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct V2ProjectionOptions {
  /// Permit a projected provider to send account credentials over
  /// non-loopback cleartext HTTP.
  pub allow_insecure_http: bool,
}

/// The effective legacy policy whose behavior cannot be represented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyPolicyLocation {
  Default,
  Profile(String),
}

impl std::fmt::Display for LegacyPolicyLocation {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Default => formatter.write_str("defaults"),
      Self::Profile(name) => write!(formatter, "profile `{name}`"),
    }
  }
}

/// Known behavior differences callers must review before activating a
/// projection as a replacement runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2BehaviorChange {
  AuxiliaryApiEndpoints,
  RequestModeOverrides,
  ManagedSelectionOrder,
  RetryPolicy,
  OperationalSettings,
  Cors,
  AgentBindings,
  PercentDecodedProfileAliases,
  HttpRejectionBehavior,
}

/// A non-fatal diagnostic produced with a projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2ProjectionWarning {
  BehaviorChange(V2BehaviorChange),
  LegacyServerRouteModeUsed {
    mode: RouteMode,
  },
  ProfileResourceRenamed {
    profile: String,
    resource_id: String,
  },
  AccountBaseUrlPromoted {
    provider: String,
    accounts: Vec<String>,
    base_url: String,
  },
  CleartextProviderAllowed {
    provider: String,
    accounts: Vec<String>,
    base_url: String,
  },
  LegacyPoolStrategyIgnored {
    strategy: String,
  },
  LegacySystemProxyShadowedByExplicitProxy,
  LegacyNoProxyWithoutExplicitProxyIgnored,
}

#[derive(Debug, Error)]
pub enum V2ProjectionError {
  #[error("legacy config is invalid: {source}")]
  InvalidLegacyConfig {
    #[source]
    source: tokn_config::Error,
  },
  #[error("cannot project {policy}: legacy route mode {mode:?} has no exact v2 recipe")]
  UnsupportedRouteMode {
    policy: LegacyPolicyLocation,
    mode: RouteMode,
  },
  #[error("cannot project managed or switch API policies without supplied accounts")]
  NoAccounts,
  #[error("supplied accounts contain duplicate id `{account_id}`")]
  DuplicateAccountId { account_id: String },
  #[error("account `{account_id}` uses unknown legacy provider `{provider}`")]
  UnknownAccountProvider { account_id: String, provider: String },
  #[error("{policy} references unknown account `{account_id}`")]
  UnknownPolicyAccount {
    policy: LegacyPolicyLocation,
    account_id: String,
  },
  #[error("{policy} references unknown provider `{provider}`")]
  UnknownPolicyProvider {
    policy: LegacyPolicyLocation,
    provider: String,
  },
  #[error("{policy} has an empty `{field}` selector, which has no compilable v2 equivalent")]
  EmptyPolicySelector {
    policy: LegacyPolicyLocation,
    field: &'static str,
  },
  #[error("{policy} uses legacy wildcard selector `{field} = [\"*\"]`, whose meaning differs in v2")]
  UnsupportedWildcardSelector {
    policy: LegacyPolicyLocation,
    field: &'static str,
  },
  #[error("{policy} uses switch mode without an effective default_provider_id")]
  MissingDefaultProvider { policy: LegacyPolicyLocation },
  #[error("legacy API bind host `{host}` is not an IP address and cannot be represented by a v2 listener")]
  UnsupportedApiBindHost { host: String },
  #[error("legacy API bind `{bind}` is non-loopback and requires an explicit public-listener review")]
  UnsupportedRemoteApiBind { bind: SocketAddr },
  #[error("legacy session_ttl_secs=0 with session_tombstone_secs={session_tombstone_secs} has no v2 equivalent")]
  UnsupportedSessionAffinity { session_tombstone_secs: u64 },
  #[error("legacy profile `{profile}` cannot be represented as a canonical v2 path segment")]
  UnsupportedProfilePath { profile: String },
  #[error("account `{account_id}` has invalid base_url `{base_url}`: {source}")]
  InvalidAccountBaseUrl {
    account_id: String,
    base_url: String,
    #[source]
    source: tokn_core::upstream_url::InvalidUpstreamUrl,
  },
  #[error("provider `{provider}` has conflicting account destinations: {destinations:?}")]
  ConflictingProviderDestinations {
    provider: String,
    destinations: Vec<String>,
  },
  #[error("provider `{provider}` for accounts {accounts:?} uses non-loopback cleartext HTTP at `{base_url}`; enable allow_insecure_http to accept it")]
  InsecureProviderRequiresOptIn {
    provider: String,
    accounts: Vec<String>,
    base_url: String,
  },
  #[error("legacy outbound proxy URL is invalid")]
  InvalidLegacyProxyUrl,
  #[error("cannot safely project a credential-bearing outbound proxy URL; remove embedded proxy credentials first")]
  CredentialedOutboundProxyUnsupported,
  #[error("generated v2 config failed semantic compilation: {source}")]
  InvalidGeneratedConfig {
    #[source]
    source: tokn_config::v2::Error,
  },
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn policy_locations_have_human_readable_names() {
    assert_eq!(LegacyPolicyLocation::Default.to_string(), "defaults");
    assert_eq!(
      LegacyPolicyLocation::Profile("work".into()).to_string(),
      "profile `work`"
    );
  }
}

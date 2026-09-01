//! Pure, in-memory projection from an effective legacy configuration to v2.
//!
//! This module deliberately owns no filesystem behavior. It neither reads nor
//! writes config or auth files, and it does not change runtime schema
//! selection. A caller supplies the already-merged legacy config and a slice of
//! account configurations, then receives a compiled v2 plan plus ephemeral
//! account copies.

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
  /// Permit projection of a non-loopback API listener. The generated listener
  /// still has to satisfy v2 authentication requirements during compilation.
  pub allow_insecure_public_listener: bool,
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

impl std::fmt::Display for V2BehaviorChange {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(match self {
      Self::AuxiliaryApiEndpoints => "auxiliary legacy API endpoints are not projected",
      Self::RequestModeOverrides => "per-request legacy route-mode overrides are not projected",
      Self::ManagedSelectionOrder => "managed account and provider selection follows v2 ordering",
      Self::RetryPolicy => "legacy retry policy is not projected",
      Self::OperationalSettings => "legacy operational settings not represented by v2 use v2 defaults",
      Self::Cors => "legacy CORS settings are not projected",
      Self::AgentBindings => "legacy agent bindings are not projected",
      Self::PercentDecodedProfileAliases => "profile paths use canonical v2 percent-encoding semantics",
      Self::HttpRejectionBehavior => "HTTP rejection behavior follows v2 listener rules",
    })
  }
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
  RemoteApiBindAllowed {
    bind: SocketAddr,
  },
  LegacyPoolStrategyIgnored {
    strategy: String,
  },
  LegacySystemProxyShadowedByExplicitProxy,
  LegacyNoProxyWithoutExplicitProxyIgnored,
}

impl std::fmt::Display for V2ProjectionWarning {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::BehaviorChange(change) => change.fmt(formatter),
      Self::LegacyServerRouteModeUsed { mode } => {
        write!(formatter, "legacy server route mode {mode:?} became the effective default")
      }
      Self::ProfileResourceRenamed { profile, resource_id } => {
        write!(formatter, "legacy profile `{profile}` was projected as v2 resource `{resource_id}`")
      }
      Self::AccountBaseUrlPromoted {
        provider,
        accounts,
        base_url,
      } => write!(
        formatter,
        "account-level base URL `{base_url}` for provider `{provider}` and accounts {accounts:?} was promoted to the provider"
      ),
      Self::CleartextProviderAllowed {
        provider,
        accounts,
        base_url,
      } => write!(
        formatter,
        "provider `{provider}` for accounts {accounts:?} is allowed to send credentials over cleartext HTTP to `{base_url}`"
      ),
      Self::RemoteApiBindAllowed { bind } => {
        write!(formatter, "non-loopback API listener `{bind}` was explicitly allowed")
      }
      Self::LegacyPoolStrategyIgnored { strategy } => {
        write!(formatter, "legacy pool strategy `{strategy}` is not available; v2 uses round_robin")
      }
      Self::LegacySystemProxyShadowedByExplicitProxy => {
        formatter.write_str("the explicit outbound proxy takes precedence over legacy system-proxy discovery")
      }
      Self::LegacyNoProxyWithoutExplicitProxyIgnored => {
        formatter.write_str("legacy no_proxy entries have no effect without an explicit outbound proxy")
      }
    }
  }
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
  #[error("cannot project a legacy configuration without supplied accounts")]
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
  #[error("account `{account_id}` has an invalid base_url: {source}")]
  InvalidAccountBaseUrl {
    account_id: String,
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

  #[test]
  fn projection_warnings_have_operator_facing_messages() {
    assert_eq!(
      V2ProjectionWarning::BehaviorChange(V2BehaviorChange::RetryPolicy).to_string(),
      "legacy retry policy is not projected"
    );
    assert_eq!(
      V2ProjectionWarning::RemoteApiBindAllowed {
        bind: "0.0.0.0:4141".parse().unwrap(),
      }
      .to_string(),
      "non-loopback API listener `0.0.0.0:4141` was explicitly allowed"
    );
  }
}

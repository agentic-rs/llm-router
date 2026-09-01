//! Pure, in-memory projection from an effective legacy configuration to v2.
//!
//! This module deliberately owns no filesystem behavior. It neither reads nor
//! writes config or auth files, and it does not change runtime schema
//! selection. A caller supplies the already-merged legacy config and a slice of
//! account configurations, then receives a compiled v2 plan plus ephemeral
//! account copies.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use thiserror::Error;
use tokn_config::RouteMode;

mod analysis;
mod compose;
mod resources;

pub use compose::{project_v2_config, V2Projection};

/// Explicit choices that can relax a safety check during projection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V2ProjectionOptions {
  /// Permit a projected provider to send account credentials over
  /// non-loopback cleartext HTTP.
  pub allow_insecure_http: bool,
  /// Permit projection of non-loopback API or forward-proxy listeners. Every
  /// generated public listener still has to satisfy v2 authentication rules.
  pub allow_insecure_public_listener: bool,
  /// Emit a v2 forward-proxy listener from legacy `[proxy_mode]` settings.
  pub forward_proxy: Option<V2ForwardProxyProjectionOptions>,
}

/// Runtime-owned inputs needed to project the legacy proxy without making the
/// pure config projector depend on provider implementations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V2ForwardProxyProjectionOptions {
  /// Effective static route mode after applying the CLI override.
  pub route_mode: RouteMode,
  /// Built-in hosts intercepted by the legacy proxy before config overrides.
  pub default_intercept_hosts: Vec<String>,
  /// Provider descriptor hosts used by `[proxy_mode.provider_modes]`.
  pub provider_hosts: BTreeMap<String, Vec<String>>,
}

/// The effective legacy policy whose behavior cannot be represented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyPolicyLocation {
  Default,
  Profile(String),
  ForwardProxy,
}

impl std::fmt::Display for LegacyPolicyLocation {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Default => formatter.write_str("defaults"),
      Self::Profile(name) => write!(formatter, "profile `{name}`"),
      Self::ForwardProxy => formatter.write_str("forward proxy"),
    }
  }
}

/// Known behavior differences callers must review before activating a
/// projection as a replacement runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2BehaviorChange {
  AdminReloadAuthentication,
  RequestModeOverrides,
  ManagedSelectionOrder,
  Cors,
  AgentBindings,
  PercentDecodedProfileAliases,
  HttpRejectionBehavior,
  ProxyRequestModeOverrides,
  ProxyAuthentication,
  ProxyLanBootstrap,
}

impl std::fmt::Display for V2BehaviorChange {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(match self {
      Self::AdminReloadAuthentication => {
        "the admin config reload endpoint follows v2 listener authentication instead of legacy unauthenticated access"
      }
      Self::RequestModeOverrides => "per-request legacy route-mode overrides are not projected",
      Self::ManagedSelectionOrder => "managed account and provider selection follows v2 ordering",
      Self::Cors => "legacy CORS settings are not projected",
      Self::AgentBindings => "legacy agent bindings are not projected",
      Self::PercentDecodedProfileAliases => "profile paths use canonical v2 percent-encoding semantics",
      Self::HttpRejectionBehavior => "HTTP rejection behavior follows v2 listener rules",
      Self::ProxyRequestModeOverrides => {
        "legacy proxy route-mode headers and Basic-auth username overrides are not projected"
      }
      Self::ProxyAuthentication => {
        "authenticated proxy listeners use Proxy-Authorization Bearer credentials at connection admission"
      }
      Self::ProxyLanBootstrap => "legacy LAN proxy bootstrap helper responses are not projected",
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
  RemoteForwardProxyBindAllowed {
    bind: SocketAddr,
  },
  UnknownProxyProviderModeIgnored {
    provider: String,
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
      Self::RemoteForwardProxyBindAllowed { bind } => {
        write!(formatter, "non-loopback forward-proxy listener `{bind}` was explicitly allowed")
      }
      Self::UnknownProxyProviderModeIgnored { provider } => {
        write!(formatter, "legacy proxy provider-mode entry `{provider}` has no runtime host mapping and was ignored")
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
  #[error("legacy forward-proxy bind host `{host}` is not an IP address and cannot be represented by a v2 listener")]
  UnsupportedForwardProxyBindHost { host: String },
  #[error("legacy forward-proxy bind `{bind}` is non-loopback and requires an explicit public-listener review")]
  UnsupportedRemoteForwardProxyBind { bind: SocketAddr },
  #[error("legacy proxy host pattern `{host}` contains wildcard syntax whose v1 and v2 meanings differ")]
  UnsupportedProxyHostPattern { host: String },
  #[error(
    "legacy proxy provider mode for `{provider}` cannot be projected by host `{host}` because providers {owners:?} share it"
  )]
  AmbiguousProxyProviderHost {
    provider: String,
    host: String,
    owners: Vec<String>,
  },
  #[error("cannot resolve the legacy forward-proxy CA directory: {source}")]
  ResolveForwardProxyCaDir {
    #[source]
    source: tokn_config::Error,
  },
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
    assert_eq!(LegacyPolicyLocation::ForwardProxy.to_string(), "forward proxy");
  }

  #[test]
  fn projection_warnings_have_operator_facing_messages() {
    assert_eq!(
      V2ProjectionWarning::BehaviorChange(V2BehaviorChange::AdminReloadAuthentication).to_string(),
      "the admin config reload endpoint follows v2 listener authentication instead of legacy unauthenticated access"
    );
    assert_eq!(
      V2ProjectionWarning::RemoteApiBindAllowed {
        bind: "0.0.0.0:4141".parse().unwrap(),
      }
      .to_string(),
      "non-loopback API listener `0.0.0.0:4141` was explicitly allowed"
    );
    assert_eq!(
      V2ProjectionWarning::BehaviorChange(V2BehaviorChange::ProxyAuthentication).to_string(),
      "authenticated proxy listeners use Proxy-Authorization Bearer credentials at connection admission"
    );
  }
}

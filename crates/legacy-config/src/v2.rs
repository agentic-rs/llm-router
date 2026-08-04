use std::net::SocketAddr;

use thiserror::Error;
use tokn_config::RouteMode;

mod analysis;
mod compose;
mod resources;

pub use compose::{plan_v2_migration, V2MigrationPlan};

/// Which legacy listener surface should be represented in a v2 plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2ListenerSelection {
  Api,
  Proxy,
  ApiAndProxy,
}

/// Options for producing a pure legacy-to-v2 migration plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V2MigrationOptions {
  pub listener_selection: V2ListenerSelection,
  /// Permit non-loopback `http://` account base URLs in the generated v2
  /// upstreams. This must be an explicit migration decision.
  pub allow_insecure_upstreams: bool,
}

impl V2MigrationOptions {
  pub const fn api_only() -> Self {
    Self {
      listener_selection: V2ListenerSelection::Api,
      allow_insecure_upstreams: false,
    }
  }

  pub const fn proxy_only() -> Self {
    Self {
      listener_selection: V2ListenerSelection::Proxy,
      allow_insecure_upstreams: false,
    }
  }

  pub const fn api_and_proxy() -> Self {
    Self {
      listener_selection: V2ListenerSelection::ApiAndProxy,
      allow_insecure_upstreams: false,
    }
  }
}

impl Default for V2MigrationOptions {
  fn default() -> Self {
    Self::api_only()
  }
}

/// The legacy policy whose effective behavior cannot be represented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyPolicyLocation {
  Default,
  Proxy,
  Profile(String),
}

impl std::fmt::Display for LegacyPolicyLocation {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Default => formatter.write_str("defaults"),
      Self::Proxy => formatter.write_str("proxy mode"),
      Self::Profile(name) => write!(formatter, "profile `{name}`"),
    }
  }
}

/// Known behavioral gaps in the first v2 migration slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2BehaviorChange {
  /// V2 listener routing currently exposes only the three managed LLM
  /// operations, not the legacy models/providers discovery endpoints.
  AuxiliaryApiEndpoints,
  /// Legacy route mode groups selection by provider; v2 selects from the
  /// compiled pool/upstream graph and may distribute equivalent candidates
  /// differently.
  ManagedSelectionOrder,
  /// Legacy request-pipeline retries are not expressible by the current v2
  /// raw managed-route recipe.
  ManagedRetryPolicy,
  /// Logging remains a process concern outside the current v2 service schema.
  OperationalSettings,
  /// Legacy CORS settings have no current v2 listener representation.
  Cors,
  /// Agent link-management metadata is not part of the v2 routing graph.
  AgentBindings,
  /// Legacy named-profile routing accepted percent-decoded aliases. V2
  /// matches one canonical raw-encoded path and rejects those aliases.
  PercentDecodedProfileAliases,
  /// V2 listener rejection uses a different status/body contract from the
  /// legacy Axum router for unmatched paths, methods, and operations.
  HttpRejectionBehavior,
  /// A v2 proxy profile is fixed by the compiled listener graph. The legacy
  /// proxy also accepted request-time mode overrides in proxy headers.
  ProxyRequestModeOverrides,
  /// V2 authenticates a forward-proxy client before deciding whether a
  /// CONNECT will be intercepted or tunneled. Legacy API-key enforcement
  /// applied only after interception and exempted passthrough requests.
  ProxyClientAuthentication,
  /// V2 forward-proxy HTTP bindings also match absolute-form cleartext HTTP.
  /// The legacy proxy routed only requests decoded after HTTPS interception.
  ProxyCleartextHttpRouting,
}

/// A non-fatal migration diagnostic that must be shown before applying a
/// future filesystem migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2MigrationWarning {
  BehaviorChange(V2BehaviorChange),
  LegacyServerRouteModeUsed { mode: RouteMode },
  ProfileResourceRenamed { profile: String, resource_id: String },
  CleartextUpstreamAllowed { accounts: Vec<String>, base_url: String },
  LegacyPoolStrategyIgnored { strategy: String },
  LegacySystemProxyShadowedByExplicitProxy,
  LegacyNoProxyWithoutExplicitProxyIgnored,
}

#[derive(Debug, Error)]
pub enum V2MigrationError {
  #[error("legacy config is invalid: {source}")]
  InvalidLegacyConfig {
    #[source]
    source: tokn_config::Error,
  },
  #[error("legacy outbound proxy URL is invalid")]
  InvalidLegacyProxyUrl,
  #[error("cannot safely render a credential-bearing legacy outbound proxy URL; remove embedded proxy credentials before migration")]
  CredentialedOutboundProxyUnsupported,
  #[error("cannot migrate {policy}: legacy route mode {mode:?} has no exact v2 recipe")]
  UnsupportedRouteMode {
    policy: LegacyPolicyLocation,
    mode: RouteMode,
  },
  #[error(
    "cannot migrate proxy mode: provider-specific mode overrides for {providers:?} do not have exact v2 recipes"
  )]
  UnsupportedProxyProviderModes { providers: Vec<String> },
  #[error("cannot migrate managed listeners without supplied accounts")]
  NoAccounts,
  #[error("{policy} selects no enabled supplied account")]
  NoEnabledAccountsForPolicy { policy: LegacyPolicyLocation },
  #[error("supplied accounts contain duplicate id `{account_id}`")]
  DuplicateAccountId { account_id: String },
  #[error("{policy} references unknown account `{account_id}`")]
  UnknownPolicyAccount {
    policy: LegacyPolicyLocation,
    account_id: String,
  },
  #[error("{policy} uses legacy wildcard selector `{field} = [\"*\"]`, whose meaning differs in v2")]
  UnsupportedWildcardSelector {
    policy: LegacyPolicyLocation,
    field: &'static str,
  },
  #[error("legacy API bind host `{host}` is not an IP address and cannot be represented by a v2 listener")]
  UnsupportedApiBindHost { host: String },
  #[error("legacy API bind `{bind}` is non-loopback and requires an explicit v2 public-listener review")]
  UnsupportedRemoteApiBind { bind: SocketAddr },
  #[error("legacy proxy bind host `{host}` is not an IP address and cannot be represented by a v2 listener")]
  UnsupportedProxyBindHost { host: String },
  #[error("legacy proxy bind `{bind}` is non-loopback and requires an explicit v2 public-listener review")]
  UnsupportedRemoteProxyBind { bind: SocketAddr },
  #[error("legacy proxy {field} entry `{host}` contains a wildcard that was ineffective in the legacy proxy and cannot be activated safely during migration")]
  UnsupportedProxyWildcardHost { field: &'static str, host: String },
  #[error("legacy proxy {field} entry `{host}` is not canonical; the legacy proxy matched it literally, so migration refuses to normalize it into an active v2 rule")]
  UnsupportedProxyNonCanonicalHost { field: &'static str, host: String },
  #[error("cannot resolve the legacy default proxy CA directory: {source}")]
  ResolveDefaultProxyCaDir {
    #[source]
    source: tokn_config::Error,
  },
  #[error("legacy session_ttl_secs=0 with session_tombstone_secs={session_tombstone_secs} has no v2 equivalent")]
  UnsupportedSessionAffinity { session_tombstone_secs: u64 },
  #[error("{policy} uses custom wire identity `{agent_id}`, which the built-in v2 runtime cannot resolve")]
  UnsupportedWireIdentity {
    policy: LegacyPolicyLocation,
    agent_id: String,
  },
  #[error("legacy profile `{profile}` cannot be represented as a canonical v2 path segment")]
  UnsupportedProfilePath { profile: String },
  #[error(
    "upstream `{base_url}` for accounts {accounts:?} uses non-loopback cleartext HTTP; set allow_insecure_upstreams to accept it"
  )]
  InsecureUpstreamRequiresOptIn { accounts: Vec<String>, base_url: String },
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
  fn options_default_to_api_only_without_insecure_upstreams() {
    assert_eq!(V2MigrationOptions::default(), V2MigrationOptions::api_only());
    assert_eq!(
      V2MigrationOptions::api_only().listener_selection,
      V2ListenerSelection::Api
    );
    assert_eq!(
      V2MigrationOptions::proxy_only().listener_selection,
      V2ListenerSelection::Proxy
    );
    assert_eq!(
      V2MigrationOptions::api_and_proxy().listener_selection,
      V2ListenerSelection::ApiAndProxy
    );
    assert!(!V2MigrationOptions::api_only().allow_insecure_upstreams);
    assert!(!V2MigrationOptions::proxy_only().allow_insecure_upstreams);
    assert!(!V2MigrationOptions::api_and_proxy().allow_insecure_upstreams);
  }
}

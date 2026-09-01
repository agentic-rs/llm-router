//! Strict, serde-facing representation of a version 2 configuration file.
//!
//! These types describe syntax only. Identifier validation, reference
//! resolution, listener-specific action rules, URL normalization, and other
//! semantic checks belong to the v2 compiler.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const SCHEMA_VERSION: u32 = crate::schema::V2_SCHEMA_VERSION as u32;
pub const DEFAULT_MAX_WIRE_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_MAX_DECODED_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_BODY_MAX_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_WRITE_QUEUE_CAPACITY: u64 = 4_096;
pub const DEFAULT_ARCHIVE_AFTER_DAYS: u64 = 7;
pub const DEFAULT_PRUNE_AFTER_DAYS: u64 = 10;
pub const DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES: usize =
  tokn_policy::DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES;

fn default_forward_proxy_request_body_max_bytes() -> usize {
  DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES
}

/// The complete on-disk version 2 configuration.
///
/// Registries default to empty because different listener and action graphs do
/// not need every resource class. The compiler decides which registries are
/// required by the references that are actually used.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
  pub schema_version: u32,
  #[serde(default)]
  pub service: RawService,
  #[serde(default)]
  pub listeners: BTreeMap<String, RawListener>,
  /// Bindings are evaluated in source order. A map would silently destroy
  /// that routing precedence, so this intentionally remains a vector.
  #[serde(default)]
  pub bindings: Vec<RawBinding>,
  /// Forward-proxy CONNECT rules are separate from decoded HTTP bindings so
  /// transport interception and request routing cannot be confused.
  #[serde(default)]
  pub connect_rules: Vec<RawConnectRule>,
  #[serde(default)]
  pub profiles: BTreeMap<String, RawProfile>,
  #[serde(default)]
  pub routes: BTreeMap<String, RawRoute>,
  #[serde(default)]
  pub retry_policies: BTreeMap<String, RawRetryPolicy>,
  #[serde(default)]
  pub account_pools: BTreeMap<String, RawAccountPool>,
  #[serde(default)]
  pub providers: BTreeMap<String, RawProvider>,
}

/// Process-wide settings consumed while constructing one serving runtime.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawService {
  #[serde(default)]
  pub outbound: RawOutbound,
  #[serde(default)]
  pub request_limits: RawRequestLimits,
  #[serde(default)]
  pub persistence: RawPersistence,
}

/// Shared outbound proxy settings for managed, opaque, and tunnel clients.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawOutbound {
  #[serde(default)]
  pub proxy_url: Option<String>,
  #[serde(default)]
  pub no_proxy: Vec<String>,
  #[serde(default)]
  pub use_system_proxy: bool,
}

/// Independent bounds for bytes received on the wire and produced by decoding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawRequestLimits {
  #[serde(default = "default_max_wire_bytes")]
  pub max_wire_bytes: u64,
  #[serde(default = "default_max_decoded_bytes")]
  pub max_decoded_bytes: u64,
}

impl Default for RawRequestLimits {
  fn default() -> Self {
    Self {
      max_wire_bytes: default_max_wire_bytes(),
      max_decoded_bytes: default_max_decoded_bytes(),
    }
  }
}

/// Persistence behavior without changing database schemas or path resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawPersistence {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default, alias = "db_path")]
  pub usage_db_path: Option<PathBuf>,
  #[serde(default)]
  pub sessions_db_path: Option<PathBuf>,
  #[serde(default)]
  pub requests_dir: Option<PathBuf>,
  #[serde(default = "default_true")]
  pub record_sessions: bool,
  #[serde(default = "default_true")]
  pub record_request_bodies: bool,
  #[serde(default = "default_body_max_bytes")]
  pub body_max_bytes: u64,
  #[serde(default = "default_write_queue_capacity")]
  pub write_queue_capacity: u64,
  #[serde(default)]
  pub archive_extension: Option<String>,
  #[serde(default = "default_archive_after_days")]
  pub archive_after_days: u64,
  #[serde(default = "default_prune_after_days")]
  pub prune_after_days: u64,
}

impl Default for RawPersistence {
  fn default() -> Self {
    Self {
      enabled: true,
      usage_db_path: None,
      sessions_db_path: None,
      requests_dir: None,
      record_sessions: true,
      record_request_bodies: true,
      body_max_bytes: default_body_max_bytes(),
      write_queue_capacity: default_write_queue_capacity(),
      archive_extension: None,
      archive_after_days: default_archive_after_days(),
      prune_after_days: default_prune_after_days(),
    }
  }
}

const fn default_max_wire_bytes() -> u64 {
  DEFAULT_MAX_WIRE_BYTES
}

const fn default_max_decoded_bytes() -> u64 {
  DEFAULT_MAX_DECODED_BYTES
}

const fn default_body_max_bytes() -> u64 {
  DEFAULT_BODY_MAX_BYTES
}

const fn default_write_queue_capacity() -> u64 {
  DEFAULT_WRITE_QUEUE_CAPACITY
}

const fn default_archive_after_days() -> u64 {
  DEFAULT_ARCHIVE_AFTER_DAYS
}

const fn default_prune_after_days() -> u64 {
  DEFAULT_PRUNE_AFTER_DAYS
}

/// A network ingress and its listener-level fallback behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawListener {
  LlmApi {
    bind: String,
    client_auth: RawClientAuth,
    /// Explicitly acknowledge plaintext client traffic on a non-loopback
    /// bind. Remote listeners must still use `local_keys`; unauthenticated
    /// public listeners are never accepted.
    #[serde(default)]
    allow_insecure_public: bool,
    default_http_action: RawBindingAction,
  },
  ForwardProxy {
    bind: String,
    client_auth: RawClientAuth,
    /// Explicitly acknowledge plaintext proxy authentication on a
    /// non-loopback bind. Remote listeners must still use `local_keys`.
    #[serde(default)]
    allow_insecure_public: bool,
    /// Maximum HTTP message-body bytes buffered before dispatch.
    #[serde(default = "default_forward_proxy_request_body_max_bytes")]
    request_body_max_bytes: usize,
    default_http_action: RawBindingAction,
    default_connect: RawConnectAction,
    #[serde(default)]
    ca_dir: Option<PathBuf>,
  },
}

/// Authentication applied to clients entering a listener.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawClientAuth {
  None,
  LocalKeys,
}

/// One ordered match rule. Matcher dimensions are combined with AND, while
/// values inside a dimension are alternatives. Empty-dimension and wildcard
/// semantics are validated and canonicalized by the compiler. On a forward
/// proxy, `hosts` matches the immutable ingress authority (the CONNECT target
/// for intercepted traffic), not an inner Host header. `path_prefixes` are
/// canonical raw encoded URI paths and are never percent-decoded across `/`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawBinding {
  pub id: String,
  pub listener: String,
  pub action: RawBindingAction,
  #[serde(default)]
  pub hosts: Vec<String>,
  #[serde(default)]
  pub path_prefixes: Vec<String>,
  #[serde(default)]
  pub methods: Vec<String>,
  /// Runtime/plugin-owned operation ids. The config compiler validates their
  /// syntax; the runtime linker rejects names it cannot materialize.
  #[serde(default)]
  pub operations: Vec<String>,
}

/// What a listener does after a binding matches, or when its default is used.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawBindingAction {
  Route { profile: String },
  // An empty struct variant, rather than a unit variant, makes Serde enforce
  // `deny_unknown_fields` while retaining `{ kind = "reject" }` syntax.
  Reject {},
}

/// One ordered forward-proxy CONNECT negotiation rule. Matcher dimensions
/// are combined with AND, while entries inside a dimension are alternatives.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawConnectRule {
  pub id: String,
  pub listener: String,
  pub action: RawConnectAction,
  #[serde(default)]
  pub hosts: Vec<String>,
  #[serde(default)]
  pub ports: Vec<u16>,
}

/// Transport-level handling for an HTTP CONNECT request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawConnectAction {
  /// Terminate TLS, then select a profile through the listener's normal HTTP
  /// bindings after the inner request is decoded.
  Intercept,
  Tunnel,
  Reject,
}

/// Client-facing policy selection. A profile deliberately contains no
/// account, provider, matching, or retry controls.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawProfile {
  pub route: String,
  #[serde(default)]
  pub wire_identity: RawWireIdentity,
}

/// Wire identity is a string for built-ins and an externally tagged value for
/// a runtime/plugin-owned identity, for example `{ named = "codex-cli" }`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawWireIdentity {
  #[default]
  Auto,
  None,
  ProviderDefault,
  Named(String),
}

/// Request-handling policy. Managed routes decode supported LLM operations;
/// relay routes preserve payload bytes and choose destination and credentials
/// independently.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawRoute {
  Managed {
    account_pool: String,
    provider: RawProviderSelector,
    model: RawModelSelector,
    operation: RawOperationPolicy,
    #[serde(default)]
    retry: RawRouteRetry,
  },
  Relay {
    destination: RawRelayDestination,
    credentials: RawRelayCredentials,
    #[serde(default)]
    retry: RawRouteRetry,
  },
}

/// One reusable exponential-backoff policy. Route-specific replay safety is
/// selected by the route's `retry.kind`, not by this timing resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawRetryPolicy {
  pub max_retries: u32,
  pub initial_backoff_ms: u64,
}

/// Retry and replay-safety behavior selected by a route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawRouteRetry {
  Never {},
  Recoverable { policy: String },
  SafeMethods { policy: String },
  Buffered { policy: String },
}

impl Default for RawRouteRetry {
  fn default() -> Self {
    Self::Never {}
  }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawProviderSelector {
  Any {},
  Fixed { provider: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawModelSelector {
  Capability {},
  Qualified { namespace: RawQualificationNamespace },
  Family { families: BTreeMap<String, Vec<String>> },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawQualificationNamespace {
  Driver,
  Provider,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawOperationPolicy {
  Preserve,
  TranslateCompatible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawRelayDestination {
  Original {},
  FixedProvider { provider: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawRelayCredentials {
  Client {},
  AccountPool { account_pool: String },
}

/// Account selection and affinity settings for one independently managed
/// pool. Omitted selectors mean unrestricted; an explicit `"*"` is retained
/// for the compiler to canonicalize and validate against mixed selectors.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawAccountPool {
  #[serde(default)]
  pub accounts: Option<Vec<String>>,
  #[serde(default)]
  pub providers: Option<Vec<String>>,
  #[serde(default)]
  pub strategy: RawPoolStrategy,
  #[serde(default = "default_failure_cooldown_secs")]
  pub failure_cooldown_secs: u64,
  #[serde(default = "default_session_ttl_secs")]
  pub session_ttl_secs: u64,
  /// Additional observability retention after session affinity expires.
  #[serde(default)]
  pub session_expired_retention_secs: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPoolStrategy {
  #[default]
  RoundRobin,
}

const fn default_failure_cooldown_secs() -> u64 {
  60
}

const fn default_session_ttl_secs() -> u64 {
  18_000
}

/// A configured provider endpoint. An omitted `base_url` is retained so the
/// runtime linker can resolve the driver's official default. The compiler
/// canonicalizes an explicit base URL as a trailing-slash path prefix;
/// managed endpoint paths and fixed-relay inbound paths append to that prefix.
/// Additional origins let an origin-preserving relay identify the same
/// provider through aliases.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawProvider {
  /// Whether this provider is available to routes and account pools. Official
  /// provider presets default to enabled and may be disabled with
  /// `enable = false`. Custom providers cannot be disabled because removing
  /// them would also remove the runtime metadata needed to identify them.
  #[serde(default = "default_true")]
  pub enable: bool,
  /// Runtime driver implementation. Official provider presets supply this
  /// automatically; custom providers must configure it explicitly.
  #[serde(default)]
  pub driver: Option<String>,
  #[serde(default)]
  pub base_url: Option<String>,
  #[serde(default)]
  pub origins: Vec<String>,
  /// Explicitly acknowledge that this provider may send account credentials
  /// over non-loopback cleartext HTTP. Loopback HTTP never needs the escape.
  #[serde(default)]
  pub allow_insecure_http: bool,
}

const fn default_true() -> bool {
  true
}

#[cfg(test)]
mod tests {
  use super::*;

  const MINIMAL_MANAGED: &str = r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "route", profile = "default" }

[profiles.default]
route = "default"
wire_identity = "auto"

[routes.default]
kind = "managed"
account_pool = "default"
provider = { kind = "any" }
model = { kind = "capability" }
operation = "translate_compatible"

[account_pools.default]
accounts = ["*"]
providers = ["*"]
strategy = "round_robin"

[providers.default]
driver = "openai"
"#;

  #[test]
  fn parses_a_minimal_managed_configuration() {
    let config: RawConfig = toml::from_str(MINIMAL_MANAGED).unwrap();

    assert_eq!(config.schema_version, SCHEMA_VERSION);
    assert_eq!(config.listeners.len(), 1);
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.account_pools["default"].failure_cooldown_secs, 60);
    assert_eq!(config.account_pools["default"].session_ttl_secs, 18_000);
  }

  #[test]
  fn serialized_config_round_trips_through_the_strict_schema() {
    let config: RawConfig = toml::from_str(MINIMAL_MANAGED).unwrap();
    let encoded = toml::to_string(&config).unwrap();

    assert_eq!(toml::from_str::<RawConfig>(&encoded).unwrap(), config);
  }

  #[test]
  fn preserves_binding_and_model_family_order() {
    let config: RawConfig = toml::from_str(
      r#"
schema_version = 2

[[bindings]]
id = "first"
listener = "proxy"
action = { kind = "route", profile = "managed" }
hosts = ["*.example.com"]

[[bindings]]
id = "second"
listener = "proxy"
action = { kind = "reject" }
methods = ["POST"]

[[connect_rules]]
id = "intercept"
listener = "proxy"
action = "intercept"
hosts = ["api.example.com"]

[[connect_rules]]
id = "tunnel"
listener = "proxy"
action = "tunnel"
ports = [443]

[routes.coding]
kind = "managed"
account_pool = "default"
provider = { kind = "any" }
model = { kind = "family", families = { coding = ["claude-sonnet-4", "gpt-5"] } }
operation = "translate_compatible"
"#,
    )
    .unwrap();

    assert_eq!(config.bindings[0].id, "first");
    assert_eq!(config.bindings[1].id, "second");
    assert_eq!(config.connect_rules[0].id, "intercept");
    assert_eq!(config.connect_rules[1].id, "tunnel");
    let RawRoute::Managed {
      model: RawModelSelector::Family { families },
      ..
    } = &config.routes["coding"]
    else {
      panic!("expected family model selector");
    };
    assert_eq!(families["coding"], ["claude-sonnet-4", "gpt-5"]);
  }

  #[test]
  fn parses_named_wire_identity() {
    let profile: RawProfile = toml::from_str(
      r#"
route = "coding"
wire_identity = { named = "codex-cli" }
"#,
    )
    .unwrap();

    assert_eq!(profile.wire_identity, RawWireIdentity::Named("codex-cli".into()));
  }

  #[test]
  fn rejects_unknown_fields_at_each_structural_level() {
    let top_level = MINIMAL_MANAGED.replacen("schema_version = 2", "schema_version = 2\nunknown = true", 1);
    assert!(toml::from_str::<RawConfig>(&top_level).is_err());

    let listener = MINIMAL_MANAGED.replace("bind =", "unknown = true\nbind =");
    assert!(toml::from_str::<RawConfig>(&listener).is_err());

    let selector = MINIMAL_MANAGED.replace(
      "provider = { kind = \"any\" }",
      "provider = { kind = \"any\", unknown = true }",
    );
    assert!(toml::from_str::<RawConfig>(&selector).is_err());
  }
}

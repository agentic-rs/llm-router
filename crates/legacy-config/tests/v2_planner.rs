use std::path::Path;

use tokn_config::v2::{
  RawAccountPool, RawBindingAction, RawConfig, RawHttpPathPattern, RawModelSelector, RawOperationPolicy,
  RawQualificationNamespace, RawRoute, RawWireIdentity,
};
use tokn_config::{Config, ProfileConfig, RouteMode};
use tokn_core::account::{AccountConfig, AccountTier};
use tokn_core::AgentId;
use tokn_router_legacy_config::v2::{
  plan_v2_migration, LegacyPolicyLocation, V2BehaviorChange, V2MigrationError, V2MigrationOptions, V2MigrationWarning,
};

fn account(id: &str, provider: &str, tier: AccountTier, base_url: Option<&str>) -> AccountConfig {
  let mut account: AccountConfig =
    toml::from_str(&format!("id = {id:?}\nprovider = {provider:?}\nenabled = true\n")).unwrap();
  account.tier = tier;
  account.base_url = base_url.map(str::to_string);
  account
}

fn active(id: &str) -> AccountConfig {
  account(id, "openai", AccountTier::Active, None)
}

fn profile_for_path<'a>(raw: &'a RawConfig, path: &str) -> &'a str {
  let binding = raw
    .bindings
    .iter()
    .find(|binding| {
      matches!(
        binding.paths.as_slice(),
        [RawHttpPathPattern::Exact { path: binding_path }] if binding_path == path
      )
    })
    .expect("exact path binding");
  match &binding.action {
    RawBindingAction::Route { profile } => profile,
    RawBindingAction::Reject {} => panic!("expected routed path binding"),
  }
}

fn pool_for_path<'a>(raw: &'a RawConfig, path: &str) -> (&'a str, &'a RawAccountPool) {
  let profile = profile_for_path(raw, path);
  let route = &raw.profiles[profile].route;
  let RawRoute::Managed { account_pool, .. } = &raw.routes[route] else {
    panic!("expected managed route")
  };
  (account_pool, &raw.account_pools[account_pool])
}

fn assert_serializes_and_compiles(raw: &RawConfig) {
  let rendered = toml::to_string(raw).unwrap();
  tokn_config::v2::parse(&rendered, Path::new("migration.toml")).unwrap();
}

#[test]
fn effective_inheritance_keeps_pools_independent_and_inherits_wire_identity() {
  let mut legacy = Config::default();
  legacy.server.route_mode = RouteMode::Exact;
  legacy.defaults.mode = RouteMode::Route;
  legacy.defaults.providers = Some(vec!["openai".into()]);
  legacy.defaults.agent_id = Some(AgentId::CodexCli);
  legacy.pool.session_ttl_secs = 100;
  legacy.pool.session_tombstone_secs = 140;
  legacy.profiles.insert("inherited".into(), ProfileConfig::default());
  legacy.profiles.insert(
    "focused".into(),
    ProfileConfig {
      mode: Some(RouteMode::Route),
      agent_id: Some(AgentId::ClaudeCode),
      accounts: Some(vec!["custom".into()]),
      ..Default::default()
    },
  );
  let accounts = vec![
    active("active"),
    account("fallback", "openai", AccountTier::Fallback, None),
    account(
      "custom",
      "openai",
      AccountTier::Active,
      Some("https://custom.example/v1"),
    ),
  ];

  let plan = plan_v2_migration(&legacy, &accounts, V2MigrationOptions::default()).unwrap();
  let raw = plan.raw_config();
  assert_serializes_and_compiles(raw);

  let default_profile = profile_for_path(raw, "/v1/responses");
  let inherited_profile = profile_for_path(raw, "/inherited/v1/responses");
  let focused_profile = profile_for_path(raw, "/focused/v1/responses");
  let (default_pool_id, default_pool) = pool_for_path(raw, "/v1/responses");
  let (inherited_pool_id, inherited_pool) = pool_for_path(raw, "/inherited/v1/responses");
  let (focused_pool_id, focused_pool) = pool_for_path(raw, "/focused/v1/responses");
  assert_ne!(default_pool_id, inherited_pool_id);
  assert_ne!(default_pool_id, focused_pool_id);
  assert_ne!(inherited_pool_id, focused_pool_id);

  for pool in [default_pool, inherited_pool] {
    assert_eq!(pool.active_accounts, None);
    assert_eq!(pool.fallback_accounts, ["fallback"]);
    assert_eq!(pool.providers.as_deref().unwrap(), ["openai"]);
    assert_eq!(pool.session_expired_retention_secs, 40);
  }
  assert_eq!(focused_pool.active_accounts.as_deref().unwrap(), ["custom"]);
  assert!(focused_pool.fallback_accounts.is_empty());

  for profile in [default_profile, inherited_profile] {
    assert_eq!(
      raw.profiles[profile].wire_identity,
      RawWireIdentity::Named("codex-cli".into())
    );
    assert!(matches!(
      raw.routes[&raw.profiles[profile].route],
      RawRoute::Managed {
        model: RawModelSelector::Qualified {
          namespace: RawQualificationNamespace::Provider
        },
        ..
      }
    ));
  }
  assert_eq!(
    raw.profiles[focused_profile].wire_identity,
    RawWireIdentity::Named("claude-code".into())
  );
  assert!(matches!(
    raw.routes[&raw.profiles[focused_profile].route],
    RawRoute::Managed {
      model: RawModelSelector::Capability {},
      operation: RawOperationPolicy::TranslateCompatible,
      ..
    }
  ));
  assert!(plan
    .warnings()
    .contains(&V2MigrationWarning::LegacyServerRouteModeUsed { mode: RouteMode::Exact }));
}

#[test]
fn canonical_profile_paths_preserve_distinct_collision_safe_resources() {
  let mut legacy = Config::default();
  for profile in ["Default", "default", "team blue β"] {
    legacy.profiles.insert(profile.into(), ProfileConfig::default());
  }

  let plan = plan_v2_migration(&legacy, &[active("account")], V2MigrationOptions::default()).unwrap();
  let raw = plan.raw_config();
  assert_serializes_and_compiles(raw);

  assert_eq!(profile_for_path(raw, "/Default/v1/responses"), "default-2");
  assert_eq!(profile_for_path(raw, "/default/v1/responses"), "default-3");
  assert_eq!(profile_for_path(raw, "/team%20blue%20%CE%B2/v1/responses"), "team-blue");
  assert_eq!(raw.profiles.len(), 4);
  assert!(plan.warnings().contains(&V2MigrationWarning::BehaviorChange(
    V2BehaviorChange::PercentDecodedProfileAliases
  )));
  assert!(plan.warnings().contains(&V2MigrationWarning::ProfileResourceRenamed {
    profile: "default".into(),
    resource_id: "default-3".into(),
  }));
}

#[test]
fn cleartext_opt_in_preserves_upstream_grouping_and_emits_a_warning() {
  let remote_url = "http://upstream.example/v1";
  let custom_url = "https://custom.example/v1";
  let accounts = vec![
    active("provider-default"),
    account("custom-a", "openai", AccountTier::Active, Some(custom_url)),
    account("custom-b", "openai", AccountTier::Fallback, Some(custom_url)),
    account("cleartext", "openai", AccountTier::Active, Some(remote_url)),
  ];

  assert!(matches!(
    plan_v2_migration(&Config::default(), &accounts, V2MigrationOptions::default()),
    Err(V2MigrationError::InsecureUpstreamRequiresOptIn {
      accounts: blocked_accounts,
      base_url
    }) if blocked_accounts == ["cleartext"] && base_url == remote_url
  ));

  let plan = plan_v2_migration(
    &Config::default(),
    &accounts,
    V2MigrationOptions {
      allow_insecure_upstreams: true,
      ..V2MigrationOptions::default()
    },
  )
  .unwrap();
  let raw = plan.raw_config();
  assert_serializes_and_compiles(raw);
  assert_eq!(raw.upstreams.len(), 3);

  let provider_default = raw
    .upstreams
    .values()
    .find(|upstream| upstream.base_url.is_none())
    .unwrap();
  assert_eq!(provider_default.accounts.as_deref().unwrap(), ["provider-default"]);
  let custom = raw
    .upstreams
    .values()
    .find(|upstream| upstream.base_url.as_deref() == Some(custom_url))
    .unwrap();
  assert_eq!(custom.accounts.as_deref().unwrap(), ["custom-a", "custom-b"]);
  let cleartext = raw
    .upstreams
    .values()
    .find(|upstream| upstream.base_url.as_deref() == Some(remote_url))
    .unwrap();
  assert_eq!(cleartext.accounts.as_deref().unwrap(), ["cleartext"]);
  assert!(cleartext.allow_insecure_http);
  assert!(plan.warnings().contains(&V2MigrationWarning::CleartextUpstreamAllowed {
    accounts: vec!["cleartext".into()],
    base_url: remote_url.into(),
  }));
}

#[test]
fn every_effective_policy_must_have_a_viable_enabled_account() {
  let supplied = active("supplied");

  let mut explicit_empty = Config::default();
  explicit_empty.defaults.accounts = Some(Vec::new());
  assert_no_viable_policy(
    &explicit_empty,
    std::slice::from_ref(&supplied),
    LegacyPolicyLocation::Default,
  );

  let mut provider_mismatch = Config::default();
  provider_mismatch.defaults.providers = Some(vec!["different-provider".into()]);
  assert_no_viable_policy(
    &provider_mismatch,
    std::slice::from_ref(&supplied),
    LegacyPolicyLocation::Default,
  );

  let mut disabled = active("disabled");
  disabled.enabled = false;
  let mut disabled_profile = Config::default();
  disabled_profile.profiles.insert(
    "disabled-only".into(),
    ProfileConfig {
      accounts: Some(vec![disabled.id.clone()]),
      ..Default::default()
    },
  );
  assert_no_viable_policy(
    &disabled_profile,
    &[supplied, disabled],
    LegacyPolicyLocation::Profile("disabled-only".into()),
  );
}

fn assert_no_viable_policy(legacy: &Config, accounts: &[AccountConfig], expected: LegacyPolicyLocation) {
  assert!(matches!(
    plan_v2_migration(legacy, accounts, V2MigrationOptions::default()),
    Err(V2MigrationError::NoEnabledAccountsForPolicy { policy }) if policy == expected
  ));
}

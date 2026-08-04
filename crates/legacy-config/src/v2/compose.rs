use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tokn_config::v2::{
  RawBinding, RawBindingAction, RawClientAuth, RawConfig, RawConnectAction, RawConnectRule, RawHttpPathPattern,
  RawListener, RawModelSelector, RawOperationPolicy, RawOutbound, RawPersistence, RawProfile,
  RawQualificationNamespace, RawRequestLimits, RawRoute, RawService, RawUpstreamSelector, SCHEMA_VERSION,
};
use tokn_config::{Config, RouteMode};
use tokn_core::account::AccountConfig;

use super::analysis::{
  api_bind, base_warnings, effective_policies, effective_proxy_policy, profile_path, proxy_bind, wire_identity,
  EffectivePolicy, IdentifierAllocator,
};
use super::resources::{build_upstreams, index_accounts, raw_pool_for_policy};
use super::{
  LegacyPolicyLocation, V2BehaviorChange, V2ListenerSelection, V2MigrationError, V2MigrationOptions, V2MigrationWarning,
};

const API_LISTENER_ID: &str = "api";
const DEFAULT_POLICY_ID: &str = "default";
const PROXY_LISTENER_ID: &str = "proxy";
const PROXY_POLICY_ID: &str = "proxy";
const GENERATED_SOURCE: &str = "migrated-v2.toml";
// Frozen legacy defaults belong to the migration recipe rather than the v2
// runtime. Keep this list aligned with the retired proxy's effective set.
const LEGACY_PROXY_INTERCEPT_HOSTS: &[&str] = &[
  "api.openai.com",
  "api.githubcopilot.com",
  "api.z.ai",
  "open.bigmodel.cn",
  "chatgpt.com",
  "api.deepseek.com",
  "openrouter.ai",
  "api.anthropic.com",
  "opencode.ai",
];
const LLM_ENDPOINTS: [(&str, &str, &str); 3] = [
  ("chat-completions", "chat/completions", "chat_completions"),
  ("responses", "responses", "responses"),
  ("messages", "messages", "messages"),
];

/// A filesystem-independent migration result containing the complete raw v2
/// document and all non-fatal behavior diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2MigrationPlan {
  raw_config: RawConfig,
  warnings: Vec<V2MigrationWarning>,
}

impl V2MigrationPlan {
  pub fn raw_config(&self) -> &RawConfig {
    &self.raw_config
  }

  pub fn warnings(&self) -> &[V2MigrationWarning] {
    &self.warnings
  }

  pub fn into_parts(self) -> (RawConfig, Vec<V2MigrationWarning>) {
    (self.raw_config, self.warnings)
  }
}

/// Produce a filesystem-independent v2 migration plan.
///
/// `legacy` must be the effective merged [`Config`] returned by the legacy
/// loader, including any `config.d` overlays. `accounts` must likewise be the
/// complete aggregate auth store. The planner never reads or writes either
/// source itself.
///
/// The generated raw document is semantically compiled before this function
/// returns. That is not a complete startup preflight: before applying the
/// migration, the caller must serialize and parse the exact document at its
/// destination path and runtime-link it with the provider, wire-identity, and
/// account registries that will serve it.
pub fn plan_v2_migration(
  legacy: &Config,
  accounts: &[AccountConfig],
  options: V2MigrationOptions,
) -> Result<V2MigrationPlan, V2MigrationError> {
  legacy
    .validate()
    .map_err(|source| V2MigrationError::InvalidLegacyConfig { source })?;
  let include_api = matches!(
    options.listener_selection,
    V2ListenerSelection::Api | V2ListenerSelection::ApiAndProxy
  );
  let include_proxy = matches!(
    options.listener_selection,
    V2ListenerSelection::Proxy | V2ListenerSelection::ApiAndProxy
  );
  if accounts.is_empty() {
    return Err(V2MigrationError::NoAccounts);
  }

  let account_index = index_accounts(accounts)?;
  let mut warnings = base_warnings(legacy);
  let outbound = migrated_outbound(legacy, &mut warnings)?;
  let proxy_host_rules = include_proxy.then(|| legacy_proxy_host_rules(legacy)).transpose()?;
  let mut policies = if include_api {
    effective_policies(legacy, &mut warnings)?
  } else {
    Vec::new()
  };
  if include_proxy {
    policies.push(effective_proxy_policy(legacy, &mut warnings)?);
    warnings.push(V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ProxyRequestModeOverrides,
    ));
    warnings.push(V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ProxyCleartextHttpRouting,
    ));
    if legacy.api_key.enabled {
      warnings.push(V2MigrationWarning::BehaviorChange(
        V2BehaviorChange::ProxyClientAuthentication,
      ));
    }
  }
  let upstreams = build_upstreams(accounts, &policies, options.allow_insecure_upstreams, &mut warnings)?;

  let mut ids = IdentifierAllocator::with_reserved(DEFAULT_POLICY_ID);
  if include_proxy {
    ids.reserve(PROXY_POLICY_ID);
  }
  let mut profiles = BTreeMap::new();
  let mut routes = BTreeMap::new();
  let mut account_pools = BTreeMap::new();
  let mut bindings = Vec::new();

  for policy in policies {
    let resource_id = match (&policy.location, policy.legacy_profile.as_deref()) {
      (LegacyPolicyLocation::Proxy, _) => PROXY_POLICY_ID.to_string(),
      (LegacyPolicyLocation::Default, None) => DEFAULT_POLICY_ID.to_string(),
      (LegacyPolicyLocation::Profile(_), Some(profile)) => {
        let allocated = ids.allocate(profile);
        if allocated != profile {
          warnings.push(V2MigrationWarning::ProfileResourceRenamed {
            profile: profile.to_string(),
            resource_id: allocated.clone(),
          });
        }
        allocated
      }
      _ => unreachable!("effective policies retain their legacy location"),
    };
    let model = managed_model_recipe(&policy)?;
    let wire_identity = wire_identity(&policy)?;
    let pool = raw_pool_for_policy(legacy, &policy, accounts, &account_index)?;

    profiles.insert(
      resource_id.clone(),
      RawProfile {
        route: resource_id.clone(),
        wire_identity,
      },
    );
    routes.insert(
      resource_id.clone(),
      RawRoute::Managed {
        account_pool: resource_id.clone(),
        upstream: RawUpstreamSelector::Any {},
        model,
        operation: RawOperationPolicy::TranslateCompatible,
      },
    );
    account_pools.insert(resource_id.clone(), pool);

    if policy.location == LegacyPolicyLocation::Proxy {
      let (_, intercept_hosts) = proxy_host_rules.as_ref().expect("proxy selection has host rules");
      append_proxy_bindings(&mut bindings, &resource_id, intercept_hosts);
    } else {
      let path_prefix = match policy.legacy_profile.as_deref() {
        Some(profile) => profile_path(profile)?,
        None => "/v1/".to_string(),
      };
      append_api_bindings(&mut bindings, &resource_id, &path_prefix);
    }
  }

  let mut listeners = BTreeMap::new();
  let mut connect_rules = Vec::new();
  if include_api {
    listeners.insert(
      API_LISTENER_ID.to_string(),
      RawListener::LlmApi {
        bind: api_bind(legacy)?.to_string(),
        client_auth: migrated_client_auth(legacy),
        allow_insecure_public: false,
        default_http_action: RawBindingAction::Reject {},
      },
    );
  }
  if include_proxy {
    let (passthrough_hosts, intercept_hosts) = proxy_host_rules.expect("proxy selection has host rules");
    if !passthrough_hosts.is_empty() {
      connect_rules.push(RawConnectRule {
        id: "proxy-passthrough".to_string(),
        listener: PROXY_LISTENER_ID.to_string(),
        action: RawConnectAction::Tunnel,
        hosts: passthrough_hosts,
        ports: vec![443],
      });
    }
    if !intercept_hosts.is_empty() {
      connect_rules.push(RawConnectRule {
        id: "proxy-intercept".to_string(),
        listener: PROXY_LISTENER_ID.to_string(),
        action: RawConnectAction::Intercept,
        hosts: intercept_hosts,
        ports: vec![443],
      });
    }
    listeners.insert(
      PROXY_LISTENER_ID.to_string(),
      RawListener::ForwardProxy {
        bind: proxy_bind(legacy)?.to_string(),
        client_auth: migrated_client_auth(legacy),
        allow_insecure_public: false,
        default_http_action: RawBindingAction::Reject {},
        // Legacy proxy mode tunneled every destination outside its explicit
        // interception set. Preserve that behavior in migration output even
        // though new configurations should normally default to reject.
        default_connect: RawConnectAction::Tunnel,
        // Retain this even when passthrough rules remove every intercept host:
        // legacy proxy startup resolved and loaded its CA unconditionally.
        ca_dir: Some(
          legacy
            .proxy_mode
            .resolved_ca_dir()
            .map_err(|source| V2MigrationError::ResolveDefaultProxyCaDir { source })?,
        ),
      },
    );
  }

  let raw_config = RawConfig {
    schema_version: SCHEMA_VERSION,
    service: RawService {
      outbound,
      request_limits: RawRequestLimits::default(),
      persistence: RawPersistence {
        enabled: legacy.db.enabled,
        usage_db_path: legacy.db.usage_db_path.clone(),
        sessions_db_path: legacy.db.sessions_db_path.clone(),
        requests_dir: legacy.db.requests_dir.clone(),
        record_sessions: legacy.db.record_sessions,
        record_request_bodies: legacy.db.record_request_bodies,
        body_max_bytes: u64::try_from(legacy.db.body_max_bytes).expect("usize always fits u64 on supported targets"),
        write_queue_capacity: u64::try_from(legacy.db.write_queue_capacity)
          .expect("usize always fits u64 on supported targets"),
        archive_extension: legacy.db.archive_extension.clone(),
      },
    },
    listeners,
    bindings,
    connect_rules,
    profiles,
    routes,
    account_pools,
    upstreams,
    model_groups: BTreeMap::new(),
  };

  tokn_config::v2::compile(&raw_config, Path::new(GENERATED_SOURCE))
    .map_err(|source| V2MigrationError::InvalidGeneratedConfig { source })?;

  Ok(V2MigrationPlan { raw_config, warnings })
}

fn migrated_client_auth(legacy: &Config) -> RawClientAuth {
  if legacy.api_key.enabled {
    RawClientAuth::LocalKeys
  } else {
    RawClientAuth::None
  }
}

fn append_api_bindings(bindings: &mut Vec<RawBinding>, resource_id: &str, path_prefix: &str) {
  for (id_suffix, path_suffix, operation) in LLM_ENDPOINTS {
    bindings.push(RawBinding {
      id: format!("{resource_id}-{id_suffix}"),
      listener: API_LISTENER_ID.to_string(),
      action: RawBindingAction::Route {
        profile: resource_id.to_string(),
      },
      hosts: Vec::new(),
      paths: vec![RawHttpPathPattern::Exact {
        path: format!("{path_prefix}{path_suffix}"),
      }],
      methods: vec!["POST".to_string()],
      operations: vec![operation.to_string()],
    });
  }
}

fn append_proxy_bindings(bindings: &mut Vec<RawBinding>, resource_id: &str, intercept_hosts: &[String]) {
  if intercept_hosts.is_empty() {
    return;
  }
  for (id_suffix, _, operation) in LLM_ENDPOINTS {
    bindings.push(RawBinding {
      id: format!("{resource_id}-{id_suffix}"),
      listener: PROXY_LISTENER_ID.to_string(),
      action: RawBindingAction::Route {
        profile: resource_id.to_string(),
      },
      hosts: intercept_hosts.to_vec(),
      paths: Vec::new(),
      methods: vec!["POST".to_string()],
      operations: vec![operation.to_string()],
    });
  }
}

fn legacy_proxy_host_rules(legacy: &Config) -> Result<(Vec<String>, Vec<String>), V2MigrationError> {
  validate_legacy_proxy_hosts("passthrough_hosts", &legacy.proxy_mode.passthrough_hosts)?;
  validate_legacy_proxy_hosts("intercept_hosts", &legacy.proxy_mode.intercept_hosts)?;

  let passthrough = normalized_hosts(legacy.proxy_mode.passthrough_hosts.iter().map(String::as_str));
  let intercept = normalized_hosts(
    LEGACY_PROXY_INTERCEPT_HOSTS
      .iter()
      .copied()
      .chain(legacy.proxy_mode.intercept_hosts.iter().map(String::as_str)),
  )
  .into_iter()
  .filter(|candidate| !passthrough.contains(candidate))
  .collect();
  Ok((passthrough.into_iter().collect(), intercept))
}

fn validate_legacy_proxy_hosts(field: &'static str, hosts: &[String]) -> Result<(), V2MigrationError> {
  if let Some(host) = hosts.iter().find(|host| host.contains('*')) {
    return Err(V2MigrationError::UnsupportedProxyWildcardHost {
      field,
      host: host.clone(),
    });
  }
  if let Some(host) = hosts
    .iter()
    .find(|host| host.as_str() != host.trim() || host.ends_with('.'))
  {
    return Err(V2MigrationError::UnsupportedProxyNonCanonicalHost {
      field,
      host: host.clone(),
    });
  }
  Ok(())
}

fn normalized_hosts<'a>(hosts: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
  hosts.into_iter().map(str::to_ascii_lowercase).collect()
}

fn migrated_outbound(legacy: &Config, warnings: &mut Vec<V2MigrationWarning>) -> Result<RawOutbound, V2MigrationError> {
  let Some(proxy_url) = legacy.proxy.url.as_deref() else {
    if !legacy.proxy.no_proxy.is_empty() {
      warnings.push(V2MigrationWarning::LegacyNoProxyWithoutExplicitProxyIgnored);
    }
    return Ok(RawOutbound {
      proxy_url: None,
      no_proxy: Vec::new(),
      use_system_proxy: legacy.proxy.system,
    });
  };

  let parsed = reqwest::Url::parse(proxy_url).map_err(|_| V2MigrationError::InvalidLegacyProxyUrl)?;
  if !parsed.username().is_empty() || parsed.password().is_some() {
    return Err(V2MigrationError::CredentialedOutboundProxyUnsupported);
  }
  if legacy.proxy.system {
    warnings.push(V2MigrationWarning::LegacySystemProxyShadowedByExplicitProxy);
  }
  Ok(RawOutbound {
    proxy_url: Some(proxy_url.to_string()),
    no_proxy: legacy.proxy.no_proxy.clone(),
    use_system_proxy: false,
  })
}

fn managed_model_recipe(policy: &EffectivePolicy) -> Result<RawModelSelector, V2MigrationError> {
  match policy.mode {
    RouteMode::Route => Ok(RawModelSelector::Capability {}),
    RouteMode::Exact => Ok(RawModelSelector::Qualified {
      namespace: RawQualificationNamespace::Provider,
    }),
    mode => Err(V2MigrationError::UnsupportedRouteMode {
      policy: policy.location.clone(),
      mode,
    }),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_config::ProfileConfig;

  fn account(base_url: Option<&str>) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
id = "account"
provider = "openai"
enabled = true
"#,
    )
    .unwrap();
    account.base_url = base_url.map(str::to_string);
    account
  }

  fn binding_for_path<'a>(raw: &'a RawConfig, path: &str) -> &'a RawBinding {
    raw
      .bindings
      .iter()
      .find(|binding| {
        matches!(
          binding.paths.as_slice(),
          [RawHttpPathPattern::Exact { path: binding_path }] if binding_path == path
        )
      })
      .expect("exact path binding")
  }

  fn profile_for_path<'a>(raw: &'a RawConfig, path: &str) -> &'a str {
    match &binding_for_path(raw, path).action {
      RawBindingAction::Route { profile } => profile,
      RawBindingAction::Reject {} => panic!("expected routed binding"),
    }
  }

  #[test]
  fn composes_a_compilable_managed_graph_with_exact_post_bindings() {
    let mut legacy = Config::default();
    legacy.profiles.insert(
      "team blue".into(),
      ProfileConfig {
        mode: Some(RouteMode::Exact),
        ..Default::default()
      },
    );

    let plan = plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::default()).unwrap();
    let raw = plan.raw_config();
    tokn_config::v2::compile(raw, Path::new("smoke.toml")).unwrap();

    assert_eq!(raw.listeners.len(), 1);
    assert_eq!(raw.profiles.len(), 2);
    assert_eq!(raw.routes.len(), 2);
    assert_eq!(raw.account_pools.len(), 2);
    assert_eq!(raw.bindings.len(), 6);

    let expected = [
      ("/v1/chat/completions", "chat_completions"),
      ("/v1/responses", "responses"),
      ("/v1/messages", "messages"),
      ("/team%20blue/v1/chat/completions", "chat_completions"),
      ("/team%20blue/v1/responses", "responses"),
      ("/team%20blue/v1/messages", "messages"),
    ];
    for (path, operation) in expected {
      let binding = binding_for_path(raw, path);
      assert_eq!(binding.methods, ["POST"]);
      assert_eq!(binding.operations, [operation]);
    }

    let default_profile = profile_for_path(raw, "/v1/responses");
    let exact_profile = profile_for_path(raw, "/team%20blue/v1/responses");
    assert!(matches!(
      raw.routes[&raw.profiles[default_profile].route],
      RawRoute::Managed {
        model: RawModelSelector::Capability {},
        operation: RawOperationPolicy::TranslateCompatible,
        ..
      }
    ));
    assert!(matches!(
      raw.routes[&raw.profiles[exact_profile].route],
      RawRoute::Managed {
        model: RawModelSelector::Qualified {
          namespace: RawQualificationNamespace::Provider
        },
        operation: RawOperationPolicy::TranslateCompatible,
        ..
      }
    ));
  }

  #[test]
  fn preserves_legacy_persistence_configuration_exactly() {
    let mut legacy = Config::default();
    legacy.db.enabled = false;
    legacy.db.usage_db_path = Some("state/usage-custom.db".into());
    legacy.db.sessions_db_path = Some("state/sessions-custom.db".into());
    legacy.db.requests_dir = Some("state/requests-custom".into());
    legacy.db.record_sessions = false;
    legacy.db.record_request_bodies = false;
    legacy.db.body_max_bytes = 12_345;
    legacy.db.write_queue_capacity = 678;
    legacy.db.archive_extension = Some("db.zstd".into());

    let plan = plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::default()).unwrap();
    let persistence = &plan.raw_config().service.persistence;

    assert!(!persistence.enabled);
    assert_eq!(
      persistence.usage_db_path.as_deref(),
      Some(Path::new("state/usage-custom.db"))
    );
    assert_eq!(
      persistence.sessions_db_path.as_deref(),
      Some(Path::new("state/sessions-custom.db"))
    );
    assert_eq!(
      persistence.requests_dir.as_deref(),
      Some(Path::new("state/requests-custom"))
    );
    assert!(!persistence.record_sessions);
    assert!(!persistence.record_request_bodies);
    assert_eq!(persistence.body_max_bytes, 12_345);
    assert_eq!(persistence.write_queue_capacity, 678);
    assert_eq!(persistence.archive_extension.as_deref(), Some("db.zstd"));
  }

  #[test]
  fn rejects_semantically_invalid_output() {
    assert!(matches!(
      plan_v2_migration(
        &Config::default(),
        &[account(Some("https://user:secret@example.com/v1"))],
        V2MigrationOptions::default()
      ),
      Err(V2MigrationError::InvalidGeneratedConfig { .. })
    ));
  }

  #[test]
  fn proxy_selection_preserves_connect_policy_and_uses_its_own_route() {
    let mut legacy = Config::default();
    legacy.defaults.mode = RouteMode::Route;
    legacy.proxy_mode.route_mode = RouteMode::Exact;
    legacy.proxy_mode.port = 4242;
    legacy.proxy_mode.ca_dir = Some(Path::new("relative-ca").to_path_buf());
    legacy.proxy_mode.intercept_hosts = vec!["Custom.Example".into(), "api.example.net".into()];
    legacy.proxy_mode.passthrough_hosts = vec!["api.openai.com".into(), "safe.example.net".into()];

    let plan = plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::proxy_only()).unwrap();
    let raw = plan.raw_config();
    tokn_config::v2::compile(raw, Path::new("etc/migrated.toml")).unwrap();

    assert_eq!(raw.listeners.len(), 1);
    let RawListener::ForwardProxy {
      bind,
      default_http_action,
      default_connect,
      ca_dir,
      ..
    } = &raw.listeners[PROXY_LISTENER_ID]
    else {
      panic!("expected forward proxy listener")
    };
    assert_eq!(bind, "127.0.0.1:4242");
    assert_eq!(default_http_action, &RawBindingAction::Reject {});
    assert_eq!(default_connect, &RawConnectAction::Tunnel);
    assert_eq!(ca_dir.as_deref(), Some(Path::new("relative-ca")));

    assert_eq!(raw.connect_rules.len(), 2);
    assert_eq!(raw.connect_rules[0].id, "proxy-passthrough");
    assert_eq!(raw.connect_rules[0].action, RawConnectAction::Tunnel);
    assert!(raw.connect_rules[0].hosts.contains(&"api.openai.com".into()));
    assert_eq!(raw.connect_rules[1].id, "proxy-intercept");
    assert_eq!(raw.connect_rules[1].action, RawConnectAction::Intercept);
    assert!(!raw.connect_rules[1].hosts.contains(&"api.openai.com".into()));
    assert!(raw.connect_rules[1].hosts.contains(&"custom.example".into()));
    assert!(raw.connect_rules[1].hosts.contains(&"api.example.net".into()));

    assert_eq!(raw.profiles.keys().map(String::as_str).collect::<Vec<_>>(), ["proxy"]);
    assert!(matches!(
      raw.routes[PROXY_POLICY_ID],
      RawRoute::Managed {
        model: RawModelSelector::Qualified {
          namespace: RawQualificationNamespace::Provider
        },
        ..
      }
    ));
    assert_eq!(raw.bindings.len(), 3);
    assert!(raw.bindings.iter().all(|binding| {
      binding.listener == PROXY_LISTENER_ID
        && matches!(&binding.action, RawBindingAction::Route { profile } if profile == PROXY_POLICY_ID)
    }));
    assert!(plan.warnings().contains(&V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ProxyRequestModeOverrides
    )));
    assert!(plan.warnings().contains(&V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ProxyCleartextHttpRouting
    )));
  }

  #[test]
  fn both_selection_keeps_api_and_proxy_policies_independent() {
    let mut legacy = Config::default();
    legacy.defaults.mode = RouteMode::Route;
    legacy.proxy_mode.route_mode = RouteMode::Exact;
    legacy.profiles.insert("proxy".into(), ProfileConfig::default());

    let plan = plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::api_and_proxy()).unwrap();
    let raw = plan.raw_config();
    tokn_config::v2::compile(raw, Path::new("migration.toml")).unwrap();

    assert!(matches!(raw.listeners[API_LISTENER_ID], RawListener::LlmApi { .. }));
    assert!(matches!(
      raw.listeners[PROXY_LISTENER_ID],
      RawListener::ForwardProxy { .. }
    ));
    assert!(raw.profiles.contains_key(DEFAULT_POLICY_ID));
    assert!(raw.profiles.contains_key(PROXY_POLICY_ID));
    assert!(raw.profiles.contains_key("proxy-2"));
    assert!(matches!(
      raw.routes[DEFAULT_POLICY_ID],
      RawRoute::Managed {
        model: RawModelSelector::Capability {},
        ..
      }
    ));
    assert!(matches!(
      raw.routes[PROXY_POLICY_ID],
      RawRoute::Managed {
        model: RawModelSelector::Qualified { .. },
        ..
      }
    ));
    assert_eq!(raw.bindings.len(), 9);
  }

  #[test]
  fn proxy_selection_refuses_dynamic_provider_modes_without_an_exact_recipe() {
    let mut legacy = Config::default();
    legacy
      .proxy_mode
      .provider_modes
      .insert("openai".into(), tokn_config::ProxyProviderMode::Passthrough);

    assert!(matches!(
      plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::proxy_only()),
      Err(V2MigrationError::UnsupportedProxyProviderModes { providers }) if providers == ["openai"]
    ));
  }

  #[test]
  fn proxy_selection_refuses_to_activate_legacy_wildcard_hosts() {
    for field in ["intercept_hosts", "passthrough_hosts"] {
      let mut legacy = Config::default();
      match field {
        "intercept_hosts" => legacy.proxy_mode.intercept_hosts.push("*.example.com".into()),
        "passthrough_hosts" => legacy.proxy_mode.passthrough_hosts.push("*.example.com".into()),
        _ => unreachable!(),
      }

      assert!(matches!(
        plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::proxy_only()),
        Err(V2MigrationError::UnsupportedProxyWildcardHost {
          field: found,
          host
        }) if found == field && host == "*.example.com"
      ));
    }
  }

  #[test]
  fn proxy_selection_refuses_to_normalize_ineffective_exact_hosts() {
    for (field, host) in [
      ("intercept_hosts", " api.example.com"),
      ("intercept_hosts", "api.example.com "),
      ("passthrough_hosts", "api.example.com."),
    ] {
      let mut legacy = Config::default();
      match field {
        "intercept_hosts" => legacy.proxy_mode.intercept_hosts.push(host.into()),
        "passthrough_hosts" => legacy.proxy_mode.passthrough_hosts.push(host.into()),
        _ => unreachable!(),
      }

      assert!(matches!(
        plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::proxy_only()),
        Err(V2MigrationError::UnsupportedProxyNonCanonicalHost {
          field: found,
          host: found_host
        }) if found == field && found_host == host
      ));
    }
  }

  #[test]
  fn tunnel_only_proxy_retains_the_legacy_ca_startup_precondition() {
    let mut legacy = Config::default();
    legacy.proxy_mode.passthrough_hosts = LEGACY_PROXY_INTERCEPT_HOSTS
      .iter()
      .map(|host| (*host).to_string())
      .collect();

    let plan = plan_v2_migration(&legacy, &[account(None)], V2MigrationOptions::proxy_only()).unwrap();
    let raw = plan.raw_config();
    let RawListener::ForwardProxy { ca_dir, .. } = &raw.listeners[PROXY_LISTENER_ID] else {
      panic!("expected forward proxy listener")
    };

    assert!(ca_dir.is_some());
    assert!(raw
      .connect_rules
      .iter()
      .all(|rule| rule.action == RawConnectAction::Tunnel));
    assert!(raw.bindings.is_empty());
  }

  #[test]
  fn migrates_effective_proxy_behavior_without_rendering_credentials() {
    let mut explicit = Config::default();
    explicit.proxy.url = Some("http://proxy.example:8080".into());
    explicit.proxy.no_proxy = vec!["localhost".into()];
    explicit.proxy.system = true;

    let plan = plan_v2_migration(&explicit, &[account(None)], V2MigrationOptions::default()).unwrap();
    let outbound = &plan.raw_config().service.outbound;
    assert_eq!(outbound.proxy_url.as_deref(), Some("http://proxy.example:8080"));
    assert_eq!(outbound.no_proxy, ["localhost"]);
    assert!(!outbound.use_system_proxy);
    assert!(plan
      .warnings()
      .contains(&V2MigrationWarning::LegacySystemProxyShadowedByExplicitProxy));

    let mut system = Config::default();
    system.proxy.system = true;
    system.proxy.no_proxy = vec!["ignored.example".into()];
    let plan = plan_v2_migration(&system, &[account(None)], V2MigrationOptions::default()).unwrap();
    let outbound = &plan.raw_config().service.outbound;
    assert_eq!(outbound.proxy_url, None);
    assert!(outbound.no_proxy.is_empty());
    assert!(outbound.use_system_proxy);
    assert!(plan
      .warnings()
      .contains(&V2MigrationWarning::LegacyNoProxyWithoutExplicitProxyIgnored));

    let mut credentialed = Config::default();
    credentialed.proxy.url = Some("http://user:sentinel-password@proxy.example".into());
    let error = plan_v2_migration(&credentialed, &[account(None)], V2MigrationOptions::default()).unwrap_err();
    assert!(matches!(error, V2MigrationError::CredentialedOutboundProxyUnsupported));
    assert!(!error.to_string().contains("sentinel-password"));
  }
}

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tokn_config::v2::{
  CompiledConfig, RawAccountPool, RawBinding, RawBindingAction, RawClientAuth, RawConfig, RawConnectAction,
  RawConnectRule, RawListener, RawModelSelector, RawOperationPolicy, RawOutbound, RawPersistence, RawProfile,
  RawProfileBinding, RawProviderSelector, RawQualificationNamespace, RawRelayCredentials, RawRelayDestination,
  RawRequestLimits, RawRetryPolicy, RawRoute, RawRouteRetry, RawService, RawWireIdentity,
  DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES, SCHEMA_VERSION,
};
use tokn_config::{Config, ProxyProviderMode, RouteMode};
use tokn_core::account::AccountConfig;

use super::analysis::{
  api_bind, base_warnings, effective_policies, forward_proxy_bind, profile_path, wire_identity, EffectivePolicy,
  IdentifierAllocator,
};
use super::resources::{index_accounts, project_accounts_and_providers, raw_pool_for_policy};
use super::{
  LegacyPolicyLocation, V2BehaviorChange, V2ForwardProxyProjectionOptions, V2ProjectionError, V2ProjectionOptions,
  V2ProjectionWarning,
};

const API_LISTENER_ID: &str = "api";
const FORWARD_PROXY_LISTENER_ID: &str = "proxy";
const DEFAULT_POLICY_ID: &str = "default";
const LEGACY_RETRY_POLICY_ID: &str = "legacy-recoverable";
const LEGACY_MAX_RETRIES: u32 = 2;
const LEGACY_INITIAL_BACKOFF_MS: u64 = 100;
const GENERATED_SOURCE: &str = "in-memory-v1-projection.toml";

/// A read-only projection ready for the v2 runtime path.
#[derive(Clone, Debug)]
pub struct V2Projection {
  raw_config: RawConfig,
  compiled_config: CompiledConfig,
  accounts: Vec<AccountConfig>,
  warnings: Vec<V2ProjectionWarning>,
}

impl V2Projection {
  pub fn raw_config(&self) -> &RawConfig {
    &self.raw_config
  }

  pub fn compiled_config(&self) -> &CompiledConfig {
    &self.compiled_config
  }

  /// Ephemeral account copies normalized for the v2 provider model.
  ///
  /// Enabled account-level `base_url` fields are cleared after an equivalent
  /// provider destination has been synthesized. Disabled accounts retain their
  /// inert destination metadata; callers must project again before enabling
  /// one. The caller's original accounts are never mutated.
  pub fn accounts(&self) -> &[AccountConfig] {
    &self.accounts
  }

  pub fn warnings(&self) -> &[V2ProjectionWarning] {
    &self.warnings
  }

  pub fn into_parts(self) -> (RawConfig, CompiledConfig, Vec<AccountConfig>, Vec<V2ProjectionWarning>) {
    (self.raw_config, self.compiled_config, self.accounts, self.warnings)
  }
}

/// Project an effective merged v1 configuration into an in-memory v2 graph.
///
/// This function performs no I/O. It does not modify the legacy config,
/// account store, startup schema selection, or any backup. The returned raw
/// document is semantically compiled before success, but callers must still
/// runtime-link it against the provider registry before serving traffic.
pub fn project_v2_config(
  legacy: &Config,
  accounts: &[AccountConfig],
  options: V2ProjectionOptions,
) -> Result<V2Projection, V2ProjectionError> {
  legacy
    .validate()
    .map_err(|source| V2ProjectionError::InvalidLegacyConfig { source })?;

  let mut warnings = base_warnings(legacy);
  let policies = effective_policies(legacy, &mut warnings)?;
  let default_policy = policies
    .first()
    .expect("effective legacy policies always include defaults")
    .clone();
  if accounts.is_empty() {
    return Err(V2ProjectionError::NoAccounts);
  }
  let account_index = index_accounts(accounts)?;
  let (projected_accounts, providers) = project_accounts_and_providers(accounts, &options, &mut warnings)?;
  let api_bind = api_bind(legacy, options.allow_insecure_public_listener)?;
  if !api_bind.ip().is_loopback() {
    warnings.push(V2ProjectionWarning::RemoteApiBindAllowed { bind: api_bind });
  }

  let mut ids = IdentifierAllocator::with_reserved(DEFAULT_POLICY_ID);
  let mut profiles = BTreeMap::new();
  let mut routes = BTreeMap::new();
  let mut bindings = Vec::new();
  let mut connect_rules = Vec::new();

  for policy in policies {
    let resource_id = match policy.legacy_profile.as_deref() {
      None => DEFAULT_POLICY_ID.to_string(),
      Some(profile) => {
        let allocated = ids.allocate(profile);
        if allocated != profile {
          warnings.push(V2ProjectionWarning::ProfileResourceRenamed {
            profile: profile.to_string(),
            resource_id: allocated.clone(),
          });
        }
        allocated
      }
    };
    let mut pool = raw_pool_for_policy(legacy, &policy, &account_index)?;
    let route = route_recipe(&policy, pool.providers.take())?;
    let path = match policy.legacy_profile.as_deref() {
      Some(profile) => profile_path(profile)?,
      None => "/v1/".to_string(),
    };
    let default_path = if resource_id == DEFAULT_POLICY_ID {
      "/v1/".to_string()
    } else {
      format!("/{resource_id}/v1/")
    };
    profiles.insert(
      resource_id.clone(),
      RawProfile {
        route: resource_id.clone(),
        wire_identity: wire_identity(&policy),
        account_pool: Some(pool),
        binding: (path != default_path).then(|| RawProfileBinding {
          path: Some(path.trim_end_matches('/').to_string()),
          endpoints: None,
        }),
      },
    );
    routes.insert(resource_id.clone(), route);
  }

  let mut listeners = BTreeMap::from([(
    API_LISTENER_ID.to_string(),
    RawListener::LlmApi {
      bind: api_bind.to_string(),
      cors: (&legacy.server.cors).into(),
      client_auth: if legacy.api_key.enabled {
        RawClientAuth::LocalKeys
      } else {
        RawClientAuth::None
      },
      allow_insecure_public: options.allow_insecure_public_listener,
      default_http_action: RawBindingAction::Reject {},
    },
  )]);
  if let Some(proxy_options) = options.forward_proxy.as_ref() {
    let proxy = project_forward_proxy(
      legacy,
      proxy_options,
      &default_policy,
      &account_index,
      &mut ids,
      options.allow_insecure_public_listener,
    )?;
    listeners.insert(FORWARD_PROXY_LISTENER_ID.to_string(), proxy.listener);
    profiles.extend(proxy.profiles);
    routes.extend(proxy.routes);
    bindings.extend(proxy.bindings);
    connect_rules.extend(proxy.connect_rules);
    warnings.extend(proxy.warnings);
  }

  let raw_config = RawConfig {
    schema_version: SCHEMA_VERSION,
    defaults: None,
    service: RawService {
      logging: legacy.logging.clone().into(),
      outbound: projected_outbound(legacy, &mut warnings)?,
      request_limits: RawRequestLimits::default(),
      persistence: RawPersistence {
        enabled: legacy.db.enabled,
        usage_db_path: legacy.db.usage_db_path.clone(),
        sessions_db_path: legacy.db.sessions_db_path.clone(),
        requests_dir: legacy.db.requests_dir.clone(),
        record_sessions: legacy.db.record_sessions,
        record_request_bodies: legacy.db.record_request_bodies,
        body_max_bytes: u64::try_from(legacy.db.body_max_bytes).expect("usize fits u64 on supported targets"),
        write_queue_capacity: u64::try_from(legacy.db.write_queue_capacity)
          .expect("usize fits u64 on supported targets"),
        archive_extension: legacy.db.archive_extension.clone(),
        ..RawPersistence::default()
      },
    },
    listeners,
    bindings,
    connect_rules,
    profiles,
    routes,
    retry_policies: BTreeMap::from([(
      LEGACY_RETRY_POLICY_ID.to_string(),
      RawRetryPolicy {
        max_retries: LEGACY_MAX_RETRIES,
        initial_backoff_ms: LEGACY_INITIAL_BACKOFF_MS,
      },
    )]),
    account_pools: BTreeMap::new(),
    providers,
  };
  let compiled_config = tokn_config::v2::compile_config(&raw_config, Path::new(GENERATED_SOURCE))
    .map_err(|source| V2ProjectionError::InvalidGeneratedConfig { source })?;

  Ok(V2Projection {
    raw_config,
    compiled_config,
    accounts: projected_accounts,
    warnings,
  })
}

struct ProjectedForwardProxy {
  listener: RawListener,
  bindings: Vec<RawBinding>,
  connect_rules: Vec<RawConnectRule>,
  profiles: BTreeMap<String, RawProfile>,
  routes: BTreeMap<String, RawRoute>,
  warnings: Vec<V2ProjectionWarning>,
}

fn project_forward_proxy(
  legacy: &Config,
  options: &V2ForwardProxyProjectionOptions,
  default_policy: &EffectivePolicy,
  account_index: &BTreeMap<&str, &AccountConfig>,
  ids: &mut IdentifierAllocator,
  allow_insecure_public: bool,
) -> Result<ProjectedForwardProxy, V2ProjectionError> {
  let bind = forward_proxy_bind(legacy, allow_insecure_public)?;
  let mut warnings = vec![V2ProjectionWarning::BehaviorChange(
    V2BehaviorChange::ProxyRequestModeOverrides,
  )];
  if legacy.api_key.enabled {
    warnings.push(V2ProjectionWarning::BehaviorChange(
      V2BehaviorChange::ProxyAuthentication,
    ));
  }
  if !bind.ip().is_loopback() {
    warnings.push(V2ProjectionWarning::RemoteForwardProxyBindAllowed { bind });
    warnings.push(V2ProjectionWarning::BehaviorChange(V2BehaviorChange::ProxyLanBootstrap));
  }

  let mut policy = default_policy.clone();
  policy.location = LegacyPolicyLocation::ForwardProxy;
  policy.legacy_profile = None;
  policy.mode = options.route_mode;

  let account_pool = raw_pool_for_policy(legacy, &policy, account_index)?;
  let mut profiles = BTreeMap::new();
  let mut routes = BTreeMap::new();
  let default_profile_id = insert_proxy_profile(
    &policy,
    options.route_mode,
    &account_pool,
    "proxy-default",
    ids,
    &mut profiles,
    &mut routes,
  )?;
  let mut mode_profiles = vec![(options.route_mode, default_profile_id.clone())];

  let mut provider_host_owners = BTreeMap::<String, Vec<String>>::new();
  for (provider, hosts) in &options.provider_hosts {
    for host in hosts {
      let owners = provider_host_owners.entry(canonical_proxy_host(host)?).or_default();
      if !owners.contains(provider) {
        owners.push(provider.clone());
      }
    }
  }
  let mut host_assignments = BTreeMap::<String, (ProxyProviderMode, Vec<String>)>::new();
  for (provider, mode) in &legacy.proxy_mode.provider_modes {
    let Some(hosts) = options.provider_hosts.get(provider) else {
      warnings.push(V2ProjectionWarning::UnknownProxyProviderModeIgnored {
        provider: provider.clone(),
      });
      continue;
    };
    for host in hosts {
      let host = canonical_proxy_host(host)?;
      if let Some(owners) = provider_host_owners.get(&host).filter(|owners| owners.len() > 1) {
        return Err(V2ProjectionError::AmbiguousProxyProviderHost {
          provider: provider.clone(),
          host,
          owners: owners.clone(),
        });
      }
      host_assignments
        .entry(host)
        .and_modify(|(_, providers)| providers.push(provider.clone()))
        .or_insert_with(|| (*mode, vec![provider.clone()]));
    }
  }

  let mut bindings = Vec::new();
  for mode in [ProxyProviderMode::Passthrough, ProxyProviderMode::Switch] {
    let hosts = host_assignments
      .iter()
      .filter_map(|(host, (assigned_mode, _))| (*assigned_mode == mode).then_some(host.clone()))
      .collect::<Vec<_>>();
    if hosts.is_empty() {
      continue;
    }
    let route_mode = mode.as_route_mode();
    let profile_id = if let Some((_, profile_id)) = mode_profiles.iter().find(|(found, _)| *found == route_mode) {
      profile_id.clone()
    } else {
      let profile_id = insert_proxy_profile(
        &policy,
        route_mode,
        &account_pool,
        &format!("proxy-{}", route_mode_name(route_mode)),
        ids,
        &mut profiles,
        &mut routes,
      )?;
      mode_profiles.push((route_mode, profile_id.clone()));
      profile_id
    };
    bindings.push(RawBinding {
      id: format!("proxy-provider-{}", route_mode_name(route_mode)),
      listener: FORWARD_PROXY_LISTENER_ID.to_string(),
      action: RawBindingAction::Route { profile: profile_id },
      hosts,
      path_prefixes: Vec::new(),
      methods: Vec::new(),
      operations: Vec::new(),
    });
  }

  let mut intercept_hosts = BTreeSet::new();
  for host in options
    .default_intercept_hosts
    .iter()
    .chain(legacy.proxy_mode.intercept_hosts.iter())
  {
    intercept_hosts.insert(canonical_proxy_host(host)?);
  }
  for host in &legacy.proxy_mode.passthrough_hosts {
    intercept_hosts.remove(&canonical_proxy_host(host)?);
  }
  let connect_rules = (!intercept_hosts.is_empty())
    .then(|| RawConnectRule {
      id: "proxy-intercept".to_string(),
      listener: FORWARD_PROXY_LISTENER_ID.to_string(),
      action: RawConnectAction::Intercept,
      hosts: intercept_hosts.into_iter().collect(),
      ports: Vec::new(),
    })
    .into_iter()
    .collect();

  let ca_dir = legacy
    .proxy_mode
    .resolved_ca_dir()
    .map_err(|source| V2ProjectionError::ResolveForwardProxyCaDir { source })?;
  let listener = RawListener::ForwardProxy {
    bind: bind.to_string(),
    client_auth: if legacy.api_key.enabled {
      RawClientAuth::LocalKeys
    } else {
      RawClientAuth::None
    },
    allow_insecure_public,
    request_body_max_bytes: DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES,
    default_http_action: RawBindingAction::Route {
      profile: default_profile_id,
    },
    default_connect: RawConnectAction::Tunnel,
    ca_dir: Some(ca_dir),
  };

  Ok(ProjectedForwardProxy {
    listener,
    bindings,
    connect_rules,
    profiles,
    routes,
    warnings,
  })
}

fn insert_proxy_profile(
  policy: &EffectivePolicy,
  mode: RouteMode,
  account_pool: &RawAccountPool,
  requested_id: &str,
  ids: &mut IdentifierAllocator,
  profiles: &mut BTreeMap<String, RawProfile>,
  routes: &mut BTreeMap<String, RawRoute>,
) -> Result<String, V2ProjectionError> {
  let resource_id = ids.allocate(requested_id);
  let mut pool = account_pool.clone();
  let route = proxy_route_recipe(policy, mode, pool.providers.take())?;
  let wire_identity = if mode == RouteMode::Passthrough {
    RawWireIdentity::None
  } else {
    wire_identity(policy)
  };
  profiles.insert(
    resource_id.clone(),
    RawProfile {
      route: resource_id.clone(),
      wire_identity,
      account_pool: (mode != RouteMode::Passthrough).then_some(pool),
      binding: None,
    },
  );
  routes.insert(resource_id.clone(), route);
  Ok(resource_id)
}

fn proxy_route_recipe(
  policy: &EffectivePolicy,
  mode: RouteMode,
  providers: Option<Vec<String>>,
) -> Result<RawRoute, V2ProjectionError> {
  match mode {
    RouteMode::Passthrough => Ok(RawRoute::Relay {
      providers: None,
      destination: RawRelayDestination::Original {},
      credentials: RawRelayCredentials::Client {},
      retry: RawRouteRetry::Never {},
    }),
    RouteMode::Switch => Ok(RawRoute::Relay {
      providers,
      destination: RawRelayDestination::Original {},
      credentials: RawRelayCredentials::AccountPool { account_pool: None },
      retry: RawRouteRetry::Never {},
    }),
    RouteMode::Route | RouteMode::Exact | RouteMode::Fuzzy => {
      let mut policy = policy.clone();
      policy.mode = mode;
      route_recipe(&policy, providers)
    }
  }
}

fn canonical_proxy_host(host: &str) -> Result<String, V2ProjectionError> {
  let host = host.trim().to_ascii_lowercase();
  if host.contains('*') {
    return Err(V2ProjectionError::UnsupportedProxyHostPattern { host });
  }
  Ok(host)
}

fn route_mode_name(mode: RouteMode) -> &'static str {
  match mode {
    RouteMode::Passthrough => "passthrough",
    RouteMode::Switch => "switch",
    RouteMode::Exact => "exact",
    RouteMode::Route => "route",
    RouteMode::Fuzzy => "fuzzy",
  }
}

fn route_recipe(policy: &EffectivePolicy, providers: Option<Vec<String>>) -> Result<RawRoute, V2ProjectionError> {
  match policy.mode {
    RouteMode::Route => Ok(RawRoute::Managed {
      account_pool: None,
      providers,
      provider: RawProviderSelector::Any {},
      model: RawModelSelector::Capability {},
      operation: RawOperationPolicy::TranslateCompatible,
      retry: RawRouteRetry::Recoverable {
        policy: LEGACY_RETRY_POLICY_ID.to_string(),
      },
    }),
    RouteMode::Exact => Ok(RawRoute::Managed {
      account_pool: None,
      providers,
      provider: RawProviderSelector::Any {},
      model: RawModelSelector::Qualified {
        namespace: RawQualificationNamespace::Provider,
      },
      operation: RawOperationPolicy::TranslateCompatible,
      retry: RawRouteRetry::Recoverable {
        policy: LEGACY_RETRY_POLICY_ID.to_string(),
      },
    }),
    RouteMode::Fuzzy => Ok(RawRoute::Managed {
      account_pool: None,
      providers,
      provider: RawProviderSelector::Any {},
      model: RawModelSelector::Family {
        families: policy
          .model_families
          .iter()
          .map(|family| (family.name.clone(), family.members.clone()))
          .collect(),
      },
      operation: RawOperationPolicy::TranslateCompatible,
      retry: RawRouteRetry::Recoverable {
        policy: LEGACY_RETRY_POLICY_ID.to_string(),
      },
    }),
    RouteMode::Switch => {
      let provider = policy
        .default_provider_id
        .clone()
        .ok_or_else(|| V2ProjectionError::MissingDefaultProvider {
          policy: policy.location.clone(),
        })?;
      Ok(RawRoute::Relay {
        providers,
        destination: RawRelayDestination::FixedProvider { provider },
        credentials: RawRelayCredentials::AccountPool { account_pool: None },
        retry: RawRouteRetry::Buffered {
          policy: LEGACY_RETRY_POLICY_ID.to_string(),
        },
      })
    }
    RouteMode::Passthrough => Err(V2ProjectionError::UnsupportedRouteMode {
      policy: policy.location.clone(),
      mode: policy.mode,
    }),
  }
}

fn projected_outbound(
  legacy: &Config,
  warnings: &mut Vec<V2ProjectionWarning>,
) -> Result<RawOutbound, V2ProjectionError> {
  let Some(proxy_url) = legacy.proxy.url.as_deref() else {
    if !legacy.proxy.no_proxy.is_empty() {
      warnings.push(V2ProjectionWarning::LegacyNoProxyWithoutExplicitProxyIgnored);
    }
    return Ok(RawOutbound {
      proxy_url: None,
      no_proxy: Vec::new(),
      use_system_proxy: legacy.proxy.system,
    });
  };

  let parsed = reqwest::Url::parse(proxy_url).map_err(|_| V2ProjectionError::InvalidLegacyProxyUrl)?;
  if !parsed.username().is_empty() || parsed.password().is_some() {
    return Err(V2ProjectionError::CredentialedOutboundProxyUnsupported);
  }
  if legacy.proxy.system {
    warnings.push(V2ProjectionWarning::LegacySystemProxyShadowedByExplicitProxy);
  }
  Ok(RawOutbound {
    proxy_url: Some(proxy_url.to_string()),
    no_proxy: legacy.proxy.no_proxy.clone(),
    use_system_proxy: false,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::v2::LegacyPolicyLocation;
  use tokn_accounts::link::{link_account_pools, link_provider_graph};
  use tokn_accounts::registry::Registry;
  use tokn_config::{ModelFamily, ProfileConfig};
  use tokn_policy::{ManagedRetry, ModelSelector, RelayRetry, RetryPolicyId, RouteKind, RoutePlan, WireIdentity};

  fn account(id: &str, provider: &str, base_url: Option<&str>) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(&format!(
      "id = {id:?}\nprovider = {provider:?}\nenabled = true\napi_key = \"test-key\"\n"
    ))
    .unwrap();
    account.base_url = base_url.map(str::to_string);
    account
  }

  fn forward_proxy_options(route_mode: RouteMode) -> V2ProjectionOptions {
    V2ProjectionOptions {
      forward_proxy: Some(V2ForwardProxyProjectionOptions {
        route_mode,
        default_intercept_hosts: vec!["api.openai.com".into(), "chatgpt.com".into()],
        provider_hosts: BTreeMap::from([
          ("openai".into(), vec!["api.openai.com".into()]),
          ("codex".into(), vec!["chatgpt.com".into()]),
          ("github-copilot".into(), vec!["api.githubcopilot.com".into()]),
        ]),
      }),
      ..V2ProjectionOptions::default()
    }
  }

  #[test]
  fn projects_route_exact_and_profile_inheritance_into_a_compiled_graph() {
    let mut legacy = Config::default();
    legacy.defaults.agent_id = Some(tokn_config::AgentId::CodexCli);
    legacy.profiles.insert(
      "team blue".into(),
      ProfileConfig {
        mode: Some(RouteMode::Exact),
        ..Default::default()
      },
    );
    let projection = project_v2_config(
      &legacy,
      &[account("primary", "openai", None)],
      V2ProjectionOptions::default(),
    )
    .unwrap();
    let raw = projection.raw_config();

    assert_eq!(raw.listeners.len(), 1);
    assert_eq!(raw.profiles.len(), 2);
    assert_eq!(raw.routes.len(), 2);
    assert!(raw.account_pools.is_empty());
    assert!(raw.bindings.is_empty());
    assert!(raw.profiles.values().all(|profile| profile.account_pool.is_some()));
    assert_eq!(
      raw.retry_policies[LEGACY_RETRY_POLICY_ID].max_retries,
      LEGACY_MAX_RETRIES
    );
    assert_eq!(
      raw.retry_policies[LEGACY_RETRY_POLICY_ID].initial_backoff_ms,
      LEGACY_INITIAL_BACKOFF_MS
    );
    for (profile, path) in [("default", "/v1"), ("team-blue", "/team%20blue/v1")] {
      let binding = projection.compiled_config().gateway().profiles()[profile]
        .api_binding()
        .unwrap();
      assert_eq!(binding.path(), path);
      assert_eq!(
        binding.endpoints().iter().map(|id| id.as_str()).collect::<Vec<_>>(),
        ["chat_completions", "messages", "responses"]
      );
    }
    assert!(matches!(
      raw.routes["default"],
      RawRoute::Managed {
        model: RawModelSelector::Capability {},
        retry: RawRouteRetry::Recoverable { ref policy },
        ..
      } if policy == LEGACY_RETRY_POLICY_ID
    ));
    assert!(matches!(
      raw.routes["team-blue"],
      RawRoute::Managed {
        model: RawModelSelector::Qualified {
          namespace: RawQualificationNamespace::Provider,
        },
        ..
      }
    ));

    let plan = projection.compiled_config().gateway();
    let retry_id = RetryPolicyId::new(LEGACY_RETRY_POLICY_ID).unwrap();
    assert!(matches!(
      plan.routes()["default"],
      RoutePlan::Managed(ref route) if route.retry() == &ManagedRetry::Recoverable(retry_id)
    ));
    let profile_id = tokn_policy::ProfileId::new("team-blue").unwrap();
    assert_eq!(
      plan.profile(&profile_id).unwrap().wire_identity(),
      &WireIdentity::Named(tokn_policy::WireIdentityId::new("codex-cli").unwrap())
    );
  }

  #[test]
  fn projects_switch_as_fixed_provider_relay() {
    let mut legacy = Config::default();
    legacy.defaults.mode = RouteMode::Switch;
    legacy.defaults.default_provider_id = Some("openai".into());
    let projection = project_v2_config(
      &legacy,
      &[account("primary", "openai", None)],
      V2ProjectionOptions::default(),
    )
    .unwrap();

    assert!(matches!(
      projection.raw_config().routes["default"],
      RawRoute::Relay {
        destination: RawRelayDestination::FixedProvider { ref provider },
        credentials: RawRelayCredentials::AccountPool { .. },
        retry: RawRouteRetry::Buffered { ref policy },
        ..
      } if provider == "openai" && policy == LEGACY_RETRY_POLICY_ID
    ));
    assert_eq!(
      projection
        .compiled_config()
        .gateway()
        .routes()
        .values()
        .next()
        .unwrap()
        .kind(),
      RouteKind::Relay
    );
  }

  #[test]
  fn projects_static_forward_proxy_listener_and_host_policy() {
    let mut legacy = Config::default();
    legacy.proxy_mode.intercept_hosts = vec!["custom.example".into()];
    legacy.proxy_mode.passthrough_hosts = vec!["API.OPENAI.COM".into()];

    let projection = project_v2_config(
      &legacy,
      &[account("primary", "openai", None)],
      forward_proxy_options(RouteMode::Exact),
    )
    .unwrap();
    let raw = projection.raw_config();
    let RawListener::ForwardProxy {
      bind,
      default_http_action,
      default_connect,
      ca_dir,
      ..
    } = &raw.listeners[FORWARD_PROXY_LISTENER_ID]
    else {
      panic!("forward proxy listener")
    };
    assert_eq!(bind, "127.0.0.1:4142");
    assert_eq!(*default_connect, RawConnectAction::Tunnel);
    assert!(ca_dir.is_some());
    let RawBindingAction::Route { profile } = default_http_action else {
      panic!("proxy default route")
    };
    assert!(matches!(
      raw.routes[profile],
      RawRoute::Managed {
        model: RawModelSelector::Qualified { .. },
        ..
      }
    ));
    assert_eq!(raw.connect_rules.len(), 1);
    assert_eq!(raw.connect_rules[0].action, RawConnectAction::Intercept);
    assert_eq!(raw.connect_rules[0].hosts, ["chatgpt.com", "custom.example"]);
    assert!(projection
      .compiled_config()
      .gateway()
      .listeners()
      .contains_key(FORWARD_PROXY_LISTENER_ID));
  }

  #[test]
  fn projects_provider_specific_passthrough_and_switch_modes() {
    let mut legacy = Config::default();
    legacy
      .proxy_mode
      .provider_modes
      .insert("openai".into(), ProxyProviderMode::Passthrough);
    legacy
      .proxy_mode
      .provider_modes
      .insert("github-copilot".into(), ProxyProviderMode::Switch);

    let projection = project_v2_config(
      &legacy,
      &[
        account("openai", "openai", None),
        account("copilot", "github-copilot", None),
      ],
      forward_proxy_options(RouteMode::Route),
    )
    .unwrap();
    let raw = projection.raw_config();
    let passthrough = raw
      .bindings
      .iter()
      .find(|binding| binding.id == "proxy-provider-passthrough")
      .unwrap();
    let switch = raw
      .bindings
      .iter()
      .find(|binding| binding.id == "proxy-provider-switch")
      .unwrap();
    assert_eq!(passthrough.hosts, ["api.openai.com"]);
    assert_eq!(switch.hosts, ["api.githubcopilot.com"]);

    let RawBindingAction::Route {
      profile: passthrough_profile,
    } = &passthrough.action
    else {
      panic!("passthrough profile")
    };
    let RawBindingAction::Route {
      profile: switch_profile,
    } = &switch.action
    else {
      panic!("switch profile")
    };
    assert!(matches!(
      raw.routes[passthrough_profile],
      RawRoute::Relay {
        destination: RawRelayDestination::Original {},
        credentials: RawRelayCredentials::Client {},
        retry: RawRouteRetry::Never {},
        providers: None,
      }
    ));
    assert!(matches!(
      raw.routes[switch_profile],
      RawRoute::Relay {
        destination: RawRelayDestination::Original {},
        credentials: RawRelayCredentials::AccountPool { .. },
        retry: RawRouteRetry::Never {},
        providers: _,
      }
    ));

    let plan = projection.compiled_config().gateway();
    assert!(matches!(
      plan.routes()[passthrough_profile.as_str()],
      RoutePlan::Relay(ref route) if route.retry() == &RelayRetry::Never
    ));
    assert!(matches!(
      plan.routes()[switch_profile.as_str()],
      RoutePlan::Relay(ref route) if route.retry() == &RelayRetry::Never
    ));
  }

  #[test]
  fn rejects_ambiguous_or_semantically_different_proxy_host_patterns() {
    let mut legacy = Config::default();
    legacy.proxy_mode.intercept_hosts = vec!["*.example.com".into()];
    assert!(matches!(
      project_v2_config(
        &legacy,
        &[account("primary", "openai", None)],
        forward_proxy_options(RouteMode::Route),
      ),
      Err(V2ProjectionError::UnsupportedProxyHostPattern { .. })
    ));

    legacy.proxy_mode.intercept_hosts.clear();
    legacy
      .proxy_mode
      .provider_modes
      .insert("openai".into(), ProxyProviderMode::Passthrough);
    legacy
      .proxy_mode
      .provider_modes
      .insert("codex".into(), ProxyProviderMode::Switch);
    let mut options = forward_proxy_options(RouteMode::Route);
    let proxy = options.forward_proxy.as_mut().unwrap();
    proxy
      .provider_hosts
      .insert("openai".into(), vec!["shared.example".into()]);
    proxy
      .provider_hosts
      .insert("codex".into(), vec!["shared.example".into()]);
    assert!(matches!(
      project_v2_config(&legacy, &[account("primary", "openai", None)], options),
      Err(V2ProjectionError::AmbiguousProxyProviderHost { host, .. }) if host == "shared.example"
    ));
  }

  #[test]
  fn projects_fuzzy_families_into_each_managed_route() {
    let mut legacy = Config::default();
    legacy.defaults.mode = RouteMode::Fuzzy;
    legacy.model_families = vec![ModelFamily {
      name: "smart".into(),
      members: vec!["gpt-5".into(), "gpt-4o".into()],
    }];
    legacy.profiles.insert(
      "work".into(),
      ProfileConfig {
        mode: Some(RouteMode::Fuzzy),
        model_families: Some(vec![ModelFamily {
          name: "smart".into(),
          members: vec!["gpt-4o-mini".into()],
        }]),
        ..Default::default()
      },
    );

    let projection = project_v2_config(
      &legacy,
      &[account("primary", "openai", None)],
      V2ProjectionOptions::default(),
    )
    .unwrap();
    let RawRoute::Managed {
      model: RawModelSelector::Family { families: default },
      ..
    } = &projection.raw_config().routes["default"]
    else {
      panic!("expected default family route");
    };
    let RawRoute::Managed {
      model: RawModelSelector::Family { families: work },
      ..
    } = &projection.raw_config().routes["work"]
    else {
      panic!("expected profile family route");
    };
    assert_eq!(default["smart"], ["gpt-5", "gpt-4o"]);
    assert_eq!(work["smart"], ["gpt-4o-mini"]);

    let plan = projection.compiled_config().gateway();
    let RoutePlan::Managed(route) = &plan.routes()["work"] else {
      panic!("expected compiled managed route");
    };
    let ModelSelector::Family(families) = route.target().model() else {
      panic!("expected compiled family selector");
    };
    assert_eq!(families[0].name(), "smart");
    assert_eq!(families[0].members(), ["gpt-4o-mini"]);
  }

  #[test]
  fn normalized_accounts_runtime_link_against_promoted_provider_destination() {
    let accounts = [account("primary", "openai", Some("https://gateway.example/v1"))];
    let projection = project_v2_config(&Config::default(), &accounts, V2ProjectionOptions::default()).unwrap();
    let plan = projection.compiled_config().gateway();
    let providers = link_provider_graph(plan, projection.accounts(), &Registry::builtin()).unwrap();
    let pools = link_account_pools(plan, &providers).unwrap();

    assert_eq!(pools.len(), 1);
    assert_eq!(accounts[0].base_url.as_deref(), Some("https://gateway.example/v1"));
    assert!(projection.accounts()[0].base_url.is_none());
  }

  #[test]
  fn rejects_passthrough_until_client_credential_projection_is_added() {
    let mut legacy = Config::default();
    legacy.defaults.mode = RouteMode::Passthrough;
    assert!(matches!(
      project_v2_config(
        &legacy,
        &[account("primary", "openai", None)],
        V2ProjectionOptions::default()
      ),
      Err(V2ProjectionError::UnsupportedRouteMode {
        policy: LegacyPolicyLocation::Default,
        mode: RouteMode::Passthrough,
      })
    ));
  }

  #[test]
  fn preserves_enabled_and_disabled_cors_without_a_behavior_warning() {
    for (enabled, allow_localhost) in [(false, true), (true, false), (true, true)] {
      let mut legacy = Config::default();
      legacy.server.cors = tokn_config::CorsConfig {
        enabled,
        allow_localhost,
        allowed_origins: vec!["https://APP.example:443/".into()],
      };
      let projection = project_v2_config(
        &legacy,
        &[account("primary", "openai", None)],
        V2ProjectionOptions::default(),
      )
      .unwrap();
      let raw = projection.raw_config();
      let RawListener::LlmApi { cors, .. } = &raw.listeners["api"] else {
        panic!("API listener");
      };
      assert_eq!(*cors, (&legacy.server.cors).into());
      let rendered = toml::to_string_pretty(raw).unwrap();
      let compiled = tokn_config::v2::parse_config(&rendered, std::path::Path::new("cors.toml")).unwrap();
      let tokn_policy::ListenerPlan::LlmApi(listener) = &compiled.gateway().listeners()["api"] else {
        panic!("compiled API listener");
      };
      assert_eq!(listener.cors().allow_localhost(), enabled && allow_localhost);
      assert_eq!(
        listener.cors().allowed_origins().contains("https://app.example"),
        enabled
      );
      assert!(projection
        .warnings()
        .iter()
        .all(|warning| !warning.to_string().contains("CORS")));
    }
  }

  #[test]
  fn preserves_service_pool_listener_and_outbound_settings() {
    let mut legacy = Config {
      logging: tokn_config::LoggingConfig {
        level: "warn,tokn_router=debug".into(),
        format: tokn_config::LogFormat::Json,
        target: tokn_config::LogTarget::File,
        dir: Some("state/logs".into()),
        ansi: false,
        include_spans: true,
      },
      ..Config::default()
    };
    legacy.api_key.enabled = true;
    legacy.server.port = 5151;
    legacy.pool.failure_cooldown_secs = 12;
    legacy.pool.session_ttl_secs = 100;
    legacy.pool.session_tombstone_secs = 130;
    legacy.db.enabled = false;
    legacy.db.usage_db_path = Some("state/usage.db".into());
    legacy.db.sessions_db_path = Some("state/sessions.db".into());
    legacy.db.requests_dir = Some("state/requests".into());
    legacy.db.record_sessions = false;
    legacy.db.record_request_bodies = false;
    legacy.db.body_max_bytes = 1234;
    legacy.db.write_queue_capacity = 56;
    legacy.db.archive_extension = Some("xz".into());
    legacy.proxy.url = Some("http://proxy.example:8080".into());
    legacy.proxy.no_proxy = vec!["localhost".into()];
    legacy.proxy.system = true;

    let projection = project_v2_config(
      &legacy,
      &[account("primary", "openai", None)],
      V2ProjectionOptions::default(),
    )
    .unwrap();
    let raw = projection.raw_config();
    let RawListener::LlmApi { bind, client_auth, .. } = &raw.listeners["api"] else {
      panic!("API listener")
    };
    assert_eq!(bind, "127.0.0.1:5151");
    assert_eq!(*client_auth, RawClientAuth::LocalKeys);
    let pool = raw.profiles["default"].account_pool.as_ref().unwrap();
    assert_eq!(pool.failure_cooldown_secs, 12);
    assert_eq!(pool.session_expired_retention_secs, 30);
    assert_eq!(raw.service.outbound.proxy_url.as_deref(), legacy.proxy.url.as_deref());
    assert_eq!(raw.service.outbound.no_proxy, ["localhost"]);
    assert!(!raw.service.outbound.use_system_proxy);
    assert!(!raw.service.persistence.enabled);
    assert_eq!(raw.service.persistence.body_max_bytes, 1234);
    assert_eq!(raw.service.persistence.write_queue_capacity, 56);
    assert_eq!(raw.service.persistence.archive_extension.as_deref(), Some("xz"));
    assert!(projection
      .warnings()
      .contains(&V2ProjectionWarning::LegacySystemProxyShadowedByExplicitProxy));

    let (raw, compiled, accounts, warnings) = projection.into_parts();
    assert_eq!(raw.schema_version, SCHEMA_VERSION);
    assert_eq!(compiled.service().persistence().body_max_bytes(), 1234);
    assert_eq!(compiled.service().logging(), &legacy.logging);
    assert_eq!(accounts.len(), 1);
    assert!(!warnings.is_empty());
  }

  #[test]
  fn explicitly_projects_an_authenticated_remote_listener() {
    let mut legacy = Config::default();
    legacy.api_key.enabled = true;
    legacy.server.host = "0.0.0.0".into();

    let projection = project_v2_config(
      &legacy,
      &[account("primary", "openai", None)],
      V2ProjectionOptions {
        allow_insecure_public_listener: true,
        ..V2ProjectionOptions::default()
      },
    )
    .unwrap();
    let RawListener::LlmApi {
      bind,
      client_auth,
      allow_insecure_public,
      ..
    } = &projection.raw_config().listeners["api"]
    else {
      panic!("API listener")
    };
    assert_eq!(bind, "0.0.0.0:4141");
    assert_eq!(*client_auth, RawClientAuth::LocalKeys);
    assert!(*allow_insecure_public);
    assert!(projection
      .warnings()
      .contains(&V2ProjectionWarning::RemoteApiBindAllowed {
        bind: "0.0.0.0:4141".parse().unwrap(),
      }));
  }

  #[test]
  fn reports_unrepresentable_inputs_before_runtime_activation() {
    let primary = account("primary", "openai", None);
    let no_accounts = project_v2_config(&Config::default(), &[], V2ProjectionOptions::default()).unwrap_err();
    assert!(matches!(&no_accounts, V2ProjectionError::NoAccounts));
    assert_eq!(
      no_accounts.to_string(),
      "cannot project a legacy configuration without supplied accounts"
    );

    let mut switch = Config::default();
    switch.defaults.mode = RouteMode::Switch;
    assert!(matches!(
      project_v2_config(&switch, std::slice::from_ref(&primary), V2ProjectionOptions::default()),
      Err(V2ProjectionError::MissingDefaultProvider { .. })
    ));

    let mut invalid = Config::default();
    invalid.server.cors.enabled = true;
    assert!(matches!(
      project_v2_config(&invalid, std::slice::from_ref(&primary), V2ProjectionOptions::default()),
      Err(V2ProjectionError::InvalidLegacyConfig { .. })
    ));

    let mut credentialed_proxy = Config::default();
    credentialed_proxy.proxy.url = Some("http://user:password@proxy.example:8080".into());
    assert!(matches!(
      project_v2_config(
        &credentialed_proxy,
        std::slice::from_ref(&primary),
        V2ProjectionOptions::default()
      ),
      Err(V2ProjectionError::CredentialedOutboundProxyUnsupported)
    ));
  }

  #[test]
  fn normalizes_outbound_settings_that_legacy_transport_ignored() {
    let mut legacy = Config::default();
    legacy.proxy.no_proxy = vec!["localhost".into()];
    legacy.proxy.system = true;
    let mut warnings = Vec::new();
    let outbound = projected_outbound(&legacy, &mut warnings).unwrap();
    assert!(outbound.proxy_url.is_none());
    assert!(outbound.no_proxy.is_empty());
    assert!(outbound.use_system_proxy);
    assert_eq!(
      warnings,
      [V2ProjectionWarning::LegacyNoProxyWithoutExplicitProxyIgnored]
    );

    legacy.proxy.url = Some("not a URL".into());
    assert!(matches!(
      projected_outbound(&legacy, &mut Vec::new()),
      Err(V2ProjectionError::InvalidLegacyProxyUrl)
    ));
  }
}

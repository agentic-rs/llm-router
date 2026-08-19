use std::collections::BTreeMap;
use std::path::Path;

use tokn_config::v2::{
  CompiledConfig, RawBinding, RawBindingAction, RawClientAuth, RawConfig, RawListener, RawModelSelector,
  RawOperationPolicy, RawOutbound, RawPersistence, RawProfile, RawProviderSelector, RawQualificationNamespace,
  RawRelayCredentials, RawRelayDestination, RawRequestLimits, RawRoute, RawService, SCHEMA_VERSION,
};
use tokn_config::{Config, RouteMode};
use tokn_core::account::AccountConfig;

use super::analysis::{
  api_bind, base_warnings, effective_policies, profile_path, wire_identity, EffectivePolicy, IdentifierAllocator,
};
use super::resources::{index_accounts, project_accounts_and_providers, raw_pool_for_policy};
use super::{V2ProjectionError, V2ProjectionOptions, V2ProjectionWarning};

const API_LISTENER_ID: &str = "api";
const DEFAULT_POLICY_ID: &str = "default";
const GENERATED_SOURCE: &str = "in-memory-v1-projection.toml";
const LLM_ENDPOINTS: [(&str, &str, &str); 3] = [
  ("chat-completions", "chat/completions", "chat_completions"),
  ("responses", "responses", "responses"),
  ("messages", "messages", "messages"),
];

/// A read-only projection ready for a future opt-in v2 runtime path.
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
  if accounts.is_empty() {
    return Err(V2ProjectionError::NoAccounts);
  }
  let account_index = index_accounts(accounts)?;
  let (projected_accounts, providers) = project_accounts_and_providers(accounts, options, &mut warnings)?;

  let mut ids = IdentifierAllocator::with_reserved(DEFAULT_POLICY_ID);
  let mut profiles = BTreeMap::new();
  let mut routes = BTreeMap::new();
  let mut account_pools = BTreeMap::new();
  let mut bindings = Vec::new();

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
    let pool = raw_pool_for_policy(legacy, &policy, &account_index)?;
    let route = route_recipe(&policy, &resource_id)?;
    profiles.insert(
      resource_id.clone(),
      RawProfile {
        route: resource_id.clone(),
        wire_identity: wire_identity(&policy),
      },
    );
    routes.insert(resource_id.clone(), route);
    account_pools.insert(resource_id.clone(), pool);

    let path_prefix = match policy.legacy_profile.as_deref() {
      Some(profile) => profile_path(profile)?,
      None => "/v1/".to_string(),
    };
    append_api_bindings(&mut bindings, &resource_id, &path_prefix);
  }

  let raw_config = RawConfig {
    schema_version: SCHEMA_VERSION,
    service: RawService {
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
    listeners: BTreeMap::from([(
      API_LISTENER_ID.to_string(),
      RawListener::LlmApi {
        bind: api_bind(legacy)?.to_string(),
        client_auth: if legacy.api_key.enabled {
          RawClientAuth::LocalKeys
        } else {
          RawClientAuth::None
        },
        allow_insecure_public: false,
        default_http_action: RawBindingAction::Reject {},
      },
    )]),
    bindings,
    connect_rules: Vec::new(),
    profiles,
    routes,
    account_pools,
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

fn route_recipe(policy: &EffectivePolicy, account_pool: &str) -> Result<RawRoute, V2ProjectionError> {
  match policy.mode {
    RouteMode::Route => Ok(RawRoute::Managed {
      account_pool: account_pool.to_string(),
      provider: RawProviderSelector::Any {},
      model: RawModelSelector::Capability {},
      operation: RawOperationPolicy::TranslateCompatible,
    }),
    RouteMode::Exact => Ok(RawRoute::Managed {
      account_pool: account_pool.to_string(),
      provider: RawProviderSelector::Any {},
      model: RawModelSelector::Qualified {
        namespace: RawQualificationNamespace::Provider,
      },
      operation: RawOperationPolicy::TranslateCompatible,
    }),
    RouteMode::Fuzzy => Ok(RawRoute::Managed {
      account_pool: account_pool.to_string(),
      provider: RawProviderSelector::Any {},
      model: RawModelSelector::Family {
        families: policy
          .model_families
          .iter()
          .map(|family| (family.name.clone(), family.members.clone()))
          .collect(),
      },
      operation: RawOperationPolicy::TranslateCompatible,
    }),
    RouteMode::Switch => {
      let provider = policy
        .default_provider_id
        .clone()
        .ok_or_else(|| V2ProjectionError::MissingDefaultProvider {
          policy: policy.location.clone(),
        })?;
      Ok(RawRoute::Relay {
        destination: RawRelayDestination::FixedProvider { provider },
        credentials: RawRelayCredentials::AccountPool {
          account_pool: account_pool.to_string(),
        },
      })
    }
    RouteMode::Passthrough => Err(V2ProjectionError::UnsupportedRouteMode {
      policy: policy.location.clone(),
      mode: policy.mode,
    }),
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
      path_prefixes: vec![format!("{path_prefix}{path_suffix}")],
      methods: vec!["POST".to_string()],
      operations: vec![operation.to_string()],
    });
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
  use tokn_policy::{ModelSelector, RouteKind, RoutePlan, WireIdentity};

  fn account(id: &str, provider: &str, base_url: Option<&str>) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(&format!(
      "id = {id:?}\nprovider = {provider:?}\nenabled = true\napi_key = \"test-key\"\n"
    ))
    .unwrap();
    account.base_url = base_url.map(str::to_string);
    account
  }

  fn binding_for_path<'a>(raw: &'a RawConfig, path: &str) -> &'a RawBinding {
    raw
      .bindings
      .iter()
      .find(|binding| binding.path_prefixes == [path])
      .expect("binding for path")
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
    assert_eq!(raw.account_pools.len(), 2);
    assert_eq!(raw.bindings.len(), 6);
    for (path, operation) in [
      ("/v1/chat/completions", "chat_completions"),
      ("/v1/responses", "responses"),
      ("/v1/messages", "messages"),
      ("/team%20blue/v1/chat/completions", "chat_completions"),
      ("/team%20blue/v1/responses", "responses"),
      ("/team%20blue/v1/messages", "messages"),
    ] {
      let binding = binding_for_path(raw, path);
      assert_eq!(binding.methods, ["POST"]);
      assert_eq!(binding.operations, [operation]);
    }
    assert!(matches!(
      raw.routes["default"],
      RawRoute::Managed {
        model: RawModelSelector::Capability {},
        ..
      }
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
        credentials: RawRelayCredentials::AccountPool { .. }
      } if provider == "openai"
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
  fn preserves_service_pool_listener_and_outbound_settings() {
    let mut legacy = Config::default();
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
    assert_eq!(raw.account_pools["default"].failure_cooldown_secs, 12);
    assert_eq!(raw.account_pools["default"].session_expired_retention_secs, 30);
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
    assert_eq!(accounts.len(), 1);
    assert!(!warnings.is_empty());
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

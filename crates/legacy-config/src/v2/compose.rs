use std::collections::BTreeMap;
use std::path::Path;

use tokn_config::v2::{
  RawBinding, RawBindingAction, RawClientAuth, RawConfig, RawHttpPathPattern, RawListener, RawModelSelector,
  RawOperationPolicy, RawOutbound, RawProfile, RawQualificationNamespace, RawRequestLimits, RawRoute, RawService,
  RawUpstreamSelector, SCHEMA_VERSION,
};
use tokn_config::{Config, RouteMode};
use tokn_core::account::AccountConfig;

use super::analysis::{
  api_bind, base_warnings, effective_policies, profile_path, wire_identity, EffectivePolicy, IdentifierAllocator,
};
use super::resources::{build_upstreams, index_accounts, raw_pool_for_policy};
use super::{V2ListenerSelection, V2MigrationError, V2MigrationOptions, V2MigrationWarning};

const API_LISTENER_ID: &str = "api";
const DEFAULT_POLICY_ID: &str = "default";
const GENERATED_SOURCE: &str = "migrated-v2.toml";
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
  if options.listener_selection != V2ListenerSelection::Api {
    return Err(V2MigrationError::UnsupportedListenerSelection {
      selection: options.listener_selection,
    });
  }
  if accounts.is_empty() {
    return Err(V2MigrationError::NoAccounts);
  }

  let account_index = index_accounts(accounts)?;
  let mut warnings = base_warnings(legacy);
  let outbound = migrated_outbound(legacy, &mut warnings)?;
  let policies = effective_policies(legacy, &mut warnings)?;
  let upstreams = build_upstreams(accounts, &policies, options.allow_insecure_upstreams, &mut warnings)?;
  let bind = api_bind(legacy)?;

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
          warnings.push(V2MigrationWarning::ProfileResourceRenamed {
            profile: profile.to_string(),
            resource_id: allocated.clone(),
          });
        }
        allocated
      }
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

    let path_prefix = match policy.legacy_profile.as_deref() {
      Some(profile) => profile_path(profile)?,
      None => "/v1/".to_string(),
    };
    for (id_suffix, path_suffix, operation) in LLM_ENDPOINTS {
      bindings.push(RawBinding {
        id: format!("{resource_id}-{id_suffix}"),
        listener: API_LISTENER_ID.to_string(),
        action: RawBindingAction::Route {
          profile: resource_id.clone(),
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

  let raw_config = RawConfig {
    schema_version: SCHEMA_VERSION,
    service: RawService {
      outbound,
      request_limits: RawRequestLimits::default(),
    },
    listeners: BTreeMap::from([(
      API_LISTENER_ID.to_string(),
      RawListener::LlmApi {
        bind: bind.to_string(),
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
    upstreams,
    model_groups: BTreeMap::new(),
  };

  tokn_config::v2::compile(&raw_config, Path::new(GENERATED_SOURCE))
    .map_err(|source| V2MigrationError::InvalidGeneratedConfig { source })?;

  Ok(V2MigrationPlan { raw_config, warnings })
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
  fn rejects_unsupported_listeners_and_semantically_invalid_output() {
    let valid_account = account(None);
    for selection in [V2ListenerSelection::Proxy, V2ListenerSelection::ApiAndProxy] {
      assert!(matches!(
        plan_v2_migration(
          &Config::default(),
          std::slice::from_ref(&valid_account),
          V2MigrationOptions {
            listener_selection: selection,
            allow_insecure_upstreams: false,
          }
        ),
        Err(V2MigrationError::UnsupportedListenerSelection { selection: found }) if found == selection
      ));
    }

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

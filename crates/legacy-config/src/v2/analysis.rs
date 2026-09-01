use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use tokn_config::v2::RawWireIdentity;
use tokn_config::{AgentId, Config, ModelFamily, RouteMode};

use super::{LegacyPolicyLocation, V2BehaviorChange, V2ProjectionError, V2ProjectionWarning};

#[derive(Clone, Debug)]
pub(super) struct EffectivePolicy {
  pub(super) location: LegacyPolicyLocation,
  pub(super) legacy_profile: Option<String>,
  pub(super) mode: RouteMode,
  pub(super) agent_id: Option<AgentId>,
  pub(super) default_provider_id: Option<String>,
  pub(super) providers: Option<Vec<String>>,
  pub(super) accounts: Option<Vec<String>>,
  pub(super) model_families: Vec<ModelFamily>,
}

pub(super) fn base_warnings(legacy: &Config) -> Vec<V2ProjectionWarning> {
  let mut warnings = vec![
    V2ProjectionWarning::BehaviorChange(V2BehaviorChange::AuxiliaryApiEndpoints),
    V2ProjectionWarning::BehaviorChange(V2BehaviorChange::RequestModeOverrides),
    V2ProjectionWarning::BehaviorChange(V2BehaviorChange::RetryPolicy),
    V2ProjectionWarning::BehaviorChange(V2BehaviorChange::HttpRejectionBehavior),
  ];
  if legacy.server.cors.enabled {
    warnings.push(V2ProjectionWarning::BehaviorChange(V2BehaviorChange::Cors));
  }
  if !legacy.agents.is_empty() {
    warnings.push(V2ProjectionWarning::BehaviorChange(V2BehaviorChange::AgentBindings));
  }
  if !legacy.profiles.is_empty() {
    warnings.push(V2ProjectionWarning::BehaviorChange(
      V2BehaviorChange::PercentDecodedProfileAliases,
    ));
  }
  if legacy.pool.strategy != "round_robin" {
    warnings.push(V2ProjectionWarning::LegacyPoolStrategyIgnored {
      strategy: legacy.pool.strategy.clone(),
    });
  }
  warnings
}

pub(super) fn effective_policies(
  legacy: &Config,
  warnings: &mut Vec<V2ProjectionWarning>,
) -> Result<Vec<EffectivePolicy>, V2ProjectionError> {
  let default_mode = if legacy.defaults.mode == RouteMode::Route && legacy.server.route_mode != RouteMode::Route {
    warnings.push(V2ProjectionWarning::LegacyServerRouteModeUsed {
      mode: legacy.server.route_mode,
    });
    legacy.server.route_mode
  } else {
    legacy.defaults.mode
  };
  ensure_supported_mode(&LegacyPolicyLocation::Default, default_mode)?;
  let default_model_families = if legacy.defaults.model_families.is_empty() {
    legacy.model_families.clone()
  } else {
    legacy.defaults.model_families.clone()
  };

  let mut policies = vec![EffectivePolicy {
    location: LegacyPolicyLocation::Default,
    legacy_profile: None,
    mode: default_mode,
    agent_id: legacy.defaults.agent_id.clone(),
    default_provider_id: legacy.defaults.default_provider_id.clone(),
    providers: legacy.defaults.providers.clone(),
    accounts: legacy.defaults.accounts.clone(),
    model_families: default_model_families.clone(),
  }];
  for (name, profile) in &legacy.profiles {
    let location = LegacyPolicyLocation::Profile(name.clone());
    let mode = profile.mode.unwrap_or(default_mode);
    ensure_supported_mode(&location, mode)?;
    policies.push(EffectivePolicy {
      location,
      legacy_profile: Some(name.clone()),
      mode,
      agent_id: profile.agent_id.clone().or_else(|| legacy.defaults.agent_id.clone()),
      default_provider_id: profile
        .default_provider_id
        .clone()
        .or_else(|| legacy.defaults.default_provider_id.clone()),
      providers: profile.providers.clone().or_else(|| legacy.defaults.providers.clone()),
      accounts: profile.accounts.clone().or_else(|| legacy.defaults.accounts.clone()),
      model_families: profile
        .model_families
        .clone()
        .unwrap_or_else(|| default_model_families.clone()),
    });
  }

  if policies
    .iter()
    .any(|policy| matches!(policy.mode, RouteMode::Route | RouteMode::Exact | RouteMode::Fuzzy))
  {
    warnings.push(V2ProjectionWarning::BehaviorChange(
      V2BehaviorChange::ManagedSelectionOrder,
    ));
  }
  Ok(policies)
}

fn ensure_supported_mode(location: &LegacyPolicyLocation, mode: RouteMode) -> Result<(), V2ProjectionError> {
  match mode {
    RouteMode::Route | RouteMode::Exact | RouteMode::Switch | RouteMode::Fuzzy => Ok(()),
    RouteMode::Passthrough => Err(V2ProjectionError::UnsupportedRouteMode {
      policy: location.clone(),
      mode,
    }),
  }
}

pub(super) fn wire_identity(policy: &EffectivePolicy) -> RawWireIdentity {
  policy
    .agent_id
    .as_ref()
    .map(|agent_id| RawWireIdentity::Named(agent_id.as_str().to_string()))
    .unwrap_or(RawWireIdentity::Auto)
}

pub(super) fn api_bind(legacy: &Config, allow_insecure_public: bool) -> Result<SocketAddr, V2ProjectionError> {
  let ip = legacy
    .server
    .host
    .parse::<IpAddr>()
    .map_err(|_| V2ProjectionError::UnsupportedApiBindHost {
      host: legacy.server.host.clone(),
    })?;
  let bind = SocketAddr::new(ip, legacy.server.port);
  if !ip.is_loopback() && !allow_insecure_public {
    return Err(V2ProjectionError::UnsupportedRemoteApiBind { bind });
  }
  Ok(bind)
}

pub(super) fn forward_proxy_bind(
  legacy: &Config,
  allow_insecure_public: bool,
) -> Result<SocketAddr, V2ProjectionError> {
  let ip =
    legacy
      .proxy_mode
      .host
      .parse::<IpAddr>()
      .map_err(|_| V2ProjectionError::UnsupportedForwardProxyBindHost {
        host: legacy.proxy_mode.host.clone(),
      })?;
  let bind = SocketAddr::new(ip, legacy.proxy_mode.port);
  if !ip.is_loopback() && !allow_insecure_public {
    return Err(V2ProjectionError::UnsupportedRemoteForwardProxyBind { bind });
  }
  Ok(bind)
}

pub(super) fn profile_path(profile: &str) -> Result<String, V2ProjectionError> {
  if matches!(profile, "." | "..") {
    return Err(V2ProjectionError::UnsupportedProfilePath {
      profile: profile.to_string(),
    });
  }
  let mut encoded = String::with_capacity(profile.len());
  for byte in profile.as_bytes() {
    if is_rfc3986_pchar(*byte) && *byte != b'%' {
      encoded.push(char::from(*byte));
    } else {
      use std::fmt::Write;
      write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
    }
  }
  Ok(format!("/{encoded}/v1/"))
}

fn is_rfc3986_pchar(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&byte)
}

pub(super) struct IdentifierAllocator {
  used: BTreeSet<String>,
}

impl IdentifierAllocator {
  pub(super) fn with_reserved(reserved: &str) -> Self {
    Self {
      used: BTreeSet::from([reserved.to_string()]),
    }
  }

  pub(super) fn allocate(&mut self, source: &str) -> String {
    let base = sanitized_identifier(source);
    if self.used.insert(base.clone()) {
      return base;
    }
    for suffix in 2.. {
      let candidate = format!("{base}-{suffix}");
      if self.used.insert(candidate.clone()) {
        return candidate;
      }
    }
    unreachable!("identifier suffix space is unbounded")
  }
}

fn sanitized_identifier(source: &str) -> String {
  let mut output = String::with_capacity(source.len());
  let mut separator = false;
  for byte in source.bytes() {
    if byte.is_ascii_alphanumeric() {
      output.push(char::from(byte.to_ascii_lowercase()));
      separator = false;
    } else if !output.is_empty() && !separator {
      output.push('-');
      separator = true;
    }
  }
  while output.ends_with('-') {
    output.pop();
  }
  if output.is_empty() {
    "profile".to_string()
  } else {
    output
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_config::{AgentConfig, ProfileConfig};

  #[test]
  fn computes_effective_policy_inheritance() {
    let mut legacy = Config::default();
    legacy.server.route_mode = RouteMode::Exact;
    legacy.defaults.agent_id = Some(AgentId::CodexCli);
    legacy.defaults.providers = Some(vec!["openai".into()]);
    legacy.defaults.accounts = Some(vec!["primary".into()]);
    legacy.defaults.default_provider_id = Some("openai".into());
    legacy.model_families = vec![ModelFamily {
      name: "smart".into(),
      members: vec!["gpt-5".into(), "gpt-4o".into()],
    }];
    legacy.profiles.insert("work".into(), ProfileConfig::default());

    let mut warnings = Vec::new();
    let policies = effective_policies(&legacy, &mut warnings).unwrap();
    let profile = &policies[1];
    assert_eq!(policies[0].mode, RouteMode::Exact);
    assert_eq!(profile.mode, RouteMode::Exact);
    assert_eq!(profile.agent_id, Some(AgentId::CodexCli));
    assert_eq!(profile.providers.as_deref().unwrap(), ["openai"]);
    assert_eq!(profile.accounts.as_deref().unwrap(), ["primary"]);
    assert_eq!(profile.default_provider_id.as_deref(), Some("openai"));
    assert_eq!(profile.model_families[0].name, "smart");
    assert_eq!(profile.model_families[0].members, ["gpt-5", "gpt-4o"]);
    assert!(warnings.contains(&V2ProjectionWarning::LegacyServerRouteModeUsed { mode: RouteMode::Exact }));
  }

  #[test]
  fn allocates_stable_canonical_resource_ids() {
    let mut allocator = IdentifierAllocator::with_reserved("default");
    assert_eq!(allocator.allocate("Team Blue"), "team-blue");
    assert_eq!(allocator.allocate("team_blue"), "team-blue-2");
    assert_eq!(allocator.allocate("default"), "default-2");
    assert_eq!(allocator.allocate("---"), "profile");
    assert_eq!(allocator.allocate("trailing---"), "trailing");
  }

  #[test]
  fn reports_conditional_behavior_warnings() {
    let mut legacy = Config::default();
    legacy.server.cors.enabled = true;
    legacy.agents.insert("codex".into(), AgentConfig::default());
    legacy.profiles.insert("work".into(), ProfileConfig::default());
    legacy.pool.strategy = "random".into();

    let warnings = base_warnings(&legacy);
    assert!(warnings.contains(&V2ProjectionWarning::BehaviorChange(V2BehaviorChange::Cors)));
    assert!(warnings.contains(&V2ProjectionWarning::BehaviorChange(V2BehaviorChange::AgentBindings)));
    assert!(warnings.contains(&V2ProjectionWarning::BehaviorChange(
      V2BehaviorChange::PercentDecodedProfileAliases
    )));
    assert!(warnings.contains(&V2ProjectionWarning::LegacyPoolStrategyIgnored {
      strategy: "random".into()
    }));
  }

  #[test]
  fn validates_api_bind_and_profile_path_safety() {
    let mut legacy = Config::default();
    legacy.server.host = "localhost".into();
    assert!(matches!(
      api_bind(&legacy, false),
      Err(V2ProjectionError::UnsupportedApiBindHost { .. })
    ));

    legacy.server.host = "0.0.0.0".into();
    assert!(matches!(
      api_bind(&legacy, false),
      Err(V2ProjectionError::UnsupportedRemoteApiBind { .. })
    ));
    assert_eq!(
      api_bind(&legacy, true).unwrap(),
      "0.0.0.0:4141".parse::<SocketAddr>().unwrap()
    );
    assert!(matches!(
      profile_path(".."),
      Err(V2ProjectionError::UnsupportedProfilePath { .. })
    ));
    assert_eq!(profile_path("team blue").unwrap(), "/team%20blue/v1/");
  }

  #[test]
  fn validates_forward_proxy_bind_safety() {
    let mut legacy = Config::default();
    legacy.proxy_mode.host = "localhost".into();
    assert!(matches!(
      forward_proxy_bind(&legacy, false),
      Err(V2ProjectionError::UnsupportedForwardProxyBindHost { .. })
    ));

    legacy.proxy_mode.host = "0.0.0.0".into();
    assert!(matches!(
      forward_proxy_bind(&legacy, false),
      Err(V2ProjectionError::UnsupportedRemoteForwardProxyBind { .. })
    ));
    assert_eq!(
      forward_proxy_bind(&legacy, true).unwrap(),
      "0.0.0.0:4142".parse::<SocketAddr>().unwrap()
    );
  }
}

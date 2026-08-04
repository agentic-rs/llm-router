use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use tokn_config::v2::RawWireIdentity;
use tokn_config::{Config, RouteMode};
use tokn_core::AgentId;

use super::{LegacyPolicyLocation, V2BehaviorChange, V2MigrationError, V2MigrationWarning};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EffectivePolicy {
  pub(super) location: LegacyPolicyLocation,
  pub(super) legacy_profile: Option<String>,
  pub(super) mode: RouteMode,
  pub(super) agent_id: Option<AgentId>,
  pub(super) providers: Option<Vec<String>>,
  pub(super) accounts: Option<Vec<String>>,
}

pub(super) fn base_warnings(legacy: &Config) -> Vec<V2MigrationWarning> {
  let mut warnings = vec![
    V2MigrationWarning::BehaviorChange(V2BehaviorChange::AuxiliaryApiEndpoints),
    V2MigrationWarning::BehaviorChange(V2BehaviorChange::ManagedRetryPolicy),
    V2MigrationWarning::BehaviorChange(V2BehaviorChange::OperationalSettings),
    V2MigrationWarning::BehaviorChange(V2BehaviorChange::HttpRejectionBehavior),
  ];
  if legacy.server.cors.enabled {
    warnings.push(V2MigrationWarning::BehaviorChange(V2BehaviorChange::Cors));
  }
  if !legacy.agents.is_empty() {
    warnings.push(V2MigrationWarning::BehaviorChange(V2BehaviorChange::AgentBindings));
  }
  if !legacy.profiles.is_empty() {
    warnings.push(V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::PercentDecodedProfileAliases,
    ));
  }
  if legacy.pool.strategy != "round_robin" {
    warnings.push(V2MigrationWarning::LegacyPoolStrategyIgnored {
      strategy: legacy.pool.strategy.clone(),
    });
  }
  warnings
}

pub(super) fn effective_policies(
  legacy: &Config,
  warnings: &mut Vec<V2MigrationWarning>,
) -> Result<Vec<EffectivePolicy>, V2MigrationError> {
  let default_mode = if legacy.defaults.mode == RouteMode::Route && legacy.server.route_mode != RouteMode::Route {
    warnings.push(V2MigrationWarning::LegacyServerRouteModeUsed {
      mode: legacy.server.route_mode,
    });
    legacy.server.route_mode
  } else {
    legacy.defaults.mode
  };
  ensure_supported_mode(&LegacyPolicyLocation::Default, default_mode)?;

  let mut policies = vec![EffectivePolicy {
    location: LegacyPolicyLocation::Default,
    legacy_profile: None,
    mode: default_mode,
    agent_id: legacy.defaults.agent_id.clone(),
    providers: legacy.defaults.providers.clone(),
    accounts: legacy.defaults.accounts.clone(),
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
      providers: profile.providers.clone().or_else(|| legacy.defaults.providers.clone()),
      accounts: profile.accounts.clone().or_else(|| legacy.defaults.accounts.clone()),
    });
  }

  if policies.iter().any(|policy| policy.mode == RouteMode::Route) {
    warnings.push(V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ManagedSelectionOrder,
    ));
  }
  Ok(policies)
}

pub(super) fn effective_proxy_policy(
  legacy: &Config,
  warnings: &mut Vec<V2MigrationWarning>,
) -> Result<EffectivePolicy, V2MigrationError> {
  let mode = legacy.proxy_mode.route_mode;
  ensure_supported_mode(&LegacyPolicyLocation::Proxy, mode)?;
  if mode == RouteMode::Route
    && !warnings.contains(&V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ManagedSelectionOrder,
    ))
  {
    warnings.push(V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ManagedSelectionOrder,
    ));
  }
  if !legacy.proxy_mode.provider_modes.is_empty() {
    return Err(V2MigrationError::UnsupportedProxyProviderModes {
      providers: legacy.proxy_mode.provider_modes.keys().cloned().collect(),
    });
  }

  Ok(EffectivePolicy {
    location: LegacyPolicyLocation::Proxy,
    legacy_profile: None,
    mode,
    agent_id: legacy.defaults.agent_id.clone(),
    providers: legacy.defaults.providers.clone(),
    accounts: legacy.defaults.accounts.clone(),
  })
}

fn ensure_supported_mode(location: &LegacyPolicyLocation, mode: RouteMode) -> Result<(), V2MigrationError> {
  match mode {
    RouteMode::Route | RouteMode::Exact => Ok(()),
    RouteMode::Fuzzy | RouteMode::Switch | RouteMode::Passthrough => Err(V2MigrationError::UnsupportedRouteMode {
      policy: location.clone(),
      mode,
    }),
  }
}

pub(super) fn wire_identity(policy: &EffectivePolicy) -> Result<RawWireIdentity, V2MigrationError> {
  match policy.agent_id.as_ref() {
    None => Ok(RawWireIdentity::Auto),
    Some(AgentId::Other(agent_id)) => Err(V2MigrationError::UnsupportedWireIdentity {
      policy: policy.location.clone(),
      agent_id: agent_id.to_string(),
    }),
    Some(agent_id) => Ok(RawWireIdentity::Named(agent_id.as_str().to_string())),
  }
}

pub(super) fn api_bind(legacy: &Config) -> Result<SocketAddr, V2MigrationError> {
  let ip = legacy
    .server
    .host
    .parse::<IpAddr>()
    .map_err(|_| V2MigrationError::UnsupportedApiBindHost {
      host: legacy.server.host.clone(),
    })?;
  let bind = SocketAddr::new(ip, legacy.server.port);
  if !ip.is_loopback() {
    return Err(V2MigrationError::UnsupportedRemoteApiBind { bind });
  }
  Ok(bind)
}

pub(super) fn proxy_bind(legacy: &Config) -> Result<SocketAddr, V2MigrationError> {
  let ip = legacy
    .proxy_mode
    .host
    .parse::<IpAddr>()
    .map_err(|_| V2MigrationError::UnsupportedProxyBindHost {
      host: legacy.proxy_mode.host.clone(),
    })?;
  let bind = SocketAddr::new(ip, legacy.proxy_mode.port);
  if !ip.is_loopback() {
    return Err(V2MigrationError::UnsupportedRemoteProxyBind { bind });
  }
  Ok(bind)
}

pub(super) fn profile_path(profile: &str) -> Result<String, V2MigrationError> {
  if matches!(profile, "." | "..") {
    return Err(V2MigrationError::UnsupportedProfilePath {
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

  pub(super) fn reserve(&mut self, reserved: &str) {
    self.used.insert(reserved.to_string());
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
  use tokn_config::ProfileConfig;

  fn policy(agent_id: Option<AgentId>) -> EffectivePolicy {
    EffectivePolicy {
      location: LegacyPolicyLocation::Profile("test".into()),
      legacy_profile: Some("test".into()),
      mode: RouteMode::Route,
      agent_id,
      providers: None,
      accounts: None,
    }
  }

  fn find_profile<'a>(policies: &'a [EffectivePolicy], name: &str) -> &'a EffectivePolicy {
    policies
      .iter()
      .find(|policy| policy.legacy_profile.as_deref() == Some(name))
      .expect("effective profile")
  }

  #[test]
  fn computes_effective_default_and_profile_inheritance() {
    let mut legacy = Config::default();
    legacy.server.route_mode = RouteMode::Exact;
    legacy.defaults.mode = RouteMode::Route;
    legacy.defaults.agent_id = Some(AgentId::CodexCli);
    legacy.defaults.providers = Some(vec!["openai".into()]);
    legacy.defaults.accounts = Some(vec!["default-account".into()]);
    legacy.profiles.insert("inherited".into(), ProfileConfig::default());
    legacy.profiles.insert(
      "overridden".into(),
      ProfileConfig {
        mode: Some(RouteMode::Route),
        agent_id: Some(AgentId::ClaudeCode),
        providers: Some(vec!["zai".into()]),
        accounts: Some(vec!["focused-account".into()]),
        ..Default::default()
      },
    );

    let mut warnings = base_warnings(&legacy);
    let policies = effective_policies(&legacy, &mut warnings).unwrap();
    assert_eq!(policies.len(), 3);

    let defaults = &policies[0];
    assert_eq!(defaults.location, LegacyPolicyLocation::Default);
    assert_eq!(defaults.mode, RouteMode::Exact);
    assert_eq!(defaults.agent_id, Some(AgentId::CodexCli));
    assert_eq!(defaults.providers.as_deref().unwrap(), ["openai"]);
    assert_eq!(defaults.accounts.as_deref().unwrap(), ["default-account"]);

    let inherited = find_profile(&policies, "inherited");
    assert_eq!(inherited.mode, RouteMode::Exact);
    assert_eq!(inherited.agent_id, Some(AgentId::CodexCli));
    assert_eq!(inherited.providers.as_deref().unwrap(), ["openai"]);
    assert_eq!(inherited.accounts.as_deref().unwrap(), ["default-account"]);

    let overridden = find_profile(&policies, "overridden");
    assert_eq!(overridden.mode, RouteMode::Route);
    assert_eq!(overridden.agent_id, Some(AgentId::ClaudeCode));
    assert_eq!(overridden.providers.as_deref().unwrap(), ["zai"]);
    assert_eq!(overridden.accounts.as_deref().unwrap(), ["focused-account"]);

    assert!(warnings.contains(&V2MigrationWarning::LegacyServerRouteModeUsed { mode: RouteMode::Exact }));
    assert!(warnings.contains(&V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::ManagedSelectionOrder
    )));
    assert!(warnings.contains(&V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::PercentDecodedProfileAliases
    )));
    assert!(warnings.contains(&V2MigrationWarning::BehaviorChange(
      V2BehaviorChange::HttpRejectionBehavior
    )));
  }

  #[test]
  fn rejects_each_unsupported_effective_mode_with_policy_context() {
    for mode in [RouteMode::Fuzzy, RouteMode::Switch, RouteMode::Passthrough] {
      let mut legacy = Config::default();
      legacy.defaults.mode = mode;
      assert!(matches!(
        effective_policies(&legacy, &mut Vec::new()),
        Err(V2MigrationError::UnsupportedRouteMode {
          policy: LegacyPolicyLocation::Default,
          mode: found
        }) if found == mode
      ));

      let mut legacy = Config::default();
      legacy.profiles.insert(
        "unsupported".into(),
        ProfileConfig {
          mode: Some(mode),
          ..Default::default()
        },
      );
      assert!(matches!(
        effective_policies(&legacy, &mut Vec::new()),
        Err(V2MigrationError::UnsupportedRouteMode {
          policy: LegacyPolicyLocation::Profile(profile),
          mode: found
        }) if profile == "unsupported" && found == mode
      ));
    }

    for mode in [RouteMode::Fuzzy, RouteMode::Switch, RouteMode::Passthrough] {
      let mut legacy = Config::default();
      legacy.proxy_mode.route_mode = mode;
      assert!(matches!(
        effective_proxy_policy(&legacy, &mut Vec::new()),
        Err(V2MigrationError::UnsupportedRouteMode {
          policy: LegacyPolicyLocation::Proxy,
          mode: found
        }) if found == mode
      ));
    }
  }

  #[test]
  fn maps_builtin_wire_identities_and_rejects_custom_ones() {
    assert_eq!(wire_identity(&policy(None)).unwrap(), RawWireIdentity::Auto);
    assert_eq!(
      wire_identity(&policy(Some(AgentId::CodexCli))).unwrap(),
      RawWireIdentity::Named("codex-cli".into())
    );
    assert!(matches!(
      wire_identity(&policy(Some(AgentId::from("custom-agent")))),
      Err(V2MigrationError::UnsupportedWireIdentity {
        policy: LegacyPolicyLocation::Profile(profile),
        agent_id
      }) if profile == "test" && agent_id == "custom-agent"
    ));
  }

  #[test]
  fn accepts_only_explicit_loopback_listener_binds() {
    let legacy = Config::default();
    assert_eq!(
      api_bind(&legacy).unwrap(),
      SocketAddr::new(IpAddr::from([127, 0, 0, 1]), legacy.server.port)
    );
    assert_eq!(
      proxy_bind(&legacy).unwrap(),
      SocketAddr::new(IpAddr::from([127, 0, 0, 1]), legacy.proxy_mode.port)
    );

    let mut hostname = Config::default();
    hostname.server.host = "localhost".into();
    assert!(matches!(
      api_bind(&hostname),
      Err(V2MigrationError::UnsupportedApiBindHost { host }) if host == "localhost"
    ));

    let mut public = Config::default();
    public.server.host = "0.0.0.0".into();
    assert!(matches!(
      api_bind(&public),
      Err(V2MigrationError::UnsupportedRemoteApiBind { bind }) if bind.ip().is_unspecified()
    ));

    let mut proxy_hostname = Config::default();
    proxy_hostname.proxy_mode.host = "localhost".into();
    assert!(matches!(
      proxy_bind(&proxy_hostname),
      Err(V2MigrationError::UnsupportedProxyBindHost { host }) if host == "localhost"
    ));

    let mut public_proxy = Config::default();
    public_proxy.proxy_mode.host = "::".into();
    assert!(matches!(
      proxy_bind(&public_proxy),
      Err(V2MigrationError::UnsupportedRemoteProxyBind { bind }) if bind.ip().is_unspecified()
    ));
  }

  #[test]
  fn encodes_profile_paths_and_allocates_collision_safe_ids() {
    assert_eq!(profile_path("v1").unwrap(), "/v1/v1/");
    assert_eq!(profile_path("team blue β").unwrap(), "/team%20blue%20%CE%B2/v1/");
    assert_eq!(profile_path("percent%name").unwrap(), "/percent%25name/v1/");
    for profile in [".", ".."] {
      assert!(matches!(
        profile_path(profile),
        Err(V2MigrationError::UnsupportedProfilePath { profile: rejected }) if rejected == profile
      ));
    }

    let mut ids = IdentifierAllocator::with_reserved("default");
    ids.reserve("proxy");
    assert_eq!(ids.allocate("Default"), "default-2");
    assert_eq!(ids.allocate("default"), "default-3");
    assert_eq!(ids.allocate("proxy"), "proxy-2");
    assert_eq!(ids.allocate("Team Blue β"), "team-blue");
    assert_eq!(ids.allocate("β"), "profile");
    assert_eq!(ids.allocate("γ"), "profile-2");
  }
}

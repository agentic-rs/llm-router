//! Reachability and strict runtime linking for client-facing profiles.
//!
//! Listener policy is scanned before route materialization so only reachable
//! profiles and routes participate in startup. Profile identities are then
//! linked against the exact runtime route graph, without resolving unreachable
//! symbolic names.

use super::{LinkedRoute, LinkedRoutes, RuntimeNameRegistry};
use snafu::Snafu;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use tokn_core::AgentId;
use tokn_policy::{
  BindingId, GatewayPlan, HttpAction, ListenerId, ProfileId, ProviderId, RouteId, RouteKind, WireIdentity,
  WireIdentityId,
};

/// The HTTP action that owns a profile reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileReferenceSite {
  Binding(BindingId),
  DefaultHttpAction,
}

impl fmt::Display for ProfileReferenceSite {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Binding(binding) => write!(formatter, "binding '{binding}'"),
      Self::DefaultHttpAction => formatter.write_str("default HTTP action"),
    }
  }
}

/// The exact profile and route subgraph reachable from listener HTTP actions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProfileReachability {
  profile_ids: BTreeSet<ProfileId>,
  route_ids: BTreeSet<RouteId>,
}

impl ProfileReachability {
  pub fn profile_ids(&self) -> &BTreeSet<ProfileId> {
    &self.profile_ids
  }

  pub fn route_ids(&self) -> &BTreeSet<RouteId> {
    &self.route_ids
  }

  pub fn is_empty(&self) -> bool {
    self.profile_ids.is_empty()
  }
}

/// Explicit profile roots requested by an in-process runtime consumer.
///
/// Listener serving keeps its existing reachability pruning. Embedded callers
/// add only the profiles they are prepared to execute, so unrelated plugin
/// identities and dormant routes remain outside their linked generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EmbeddedProfileRoots {
  profile_ids: BTreeSet<ProfileId>,
}

impl EmbeddedProfileRoots {
  pub fn new(profile_ids: impl IntoIterator<Item = ProfileId>) -> Self {
    Self {
      profile_ids: profile_ids.into_iter().collect(),
    }
  }

  pub fn one(profile_id: ProfileId) -> Self {
    Self::new([profile_id])
  }

  pub fn profile_ids(&self) -> &BTreeSet<ProfileId> {
    &self.profile_ids
  }

  pub fn is_empty(&self) -> bool {
    self.profile_ids.is_empty()
  }
}

/// Scan listener HTTP actions in deterministic evaluation order.
///
/// Bindings are visited in their configured order, followed by the listener's
/// default action. CONNECT rules have no profile action and are intentionally
/// outside this scan.
pub fn scan_profile_reachability(plan: &GatewayPlan) -> ProfileLinkResult<ProfileReachability> {
  let mut reachable = ProfileReachability::default();

  for (listener_id, listener) in plan.listeners() {
    for binding in listener.http_bindings() {
      scan_action(
        plan,
        listener_id,
        ProfileReferenceSite::Binding(binding.id().clone()),
        binding.action(),
        &mut reachable,
      )?;
    }
    scan_action(
      plan,
      listener_id,
      ProfileReferenceSite::DefaultHttpAction,
      listener.default_http_action(),
      &mut reachable,
    )?;
  }

  Ok(reachable)
}

/// Add explicitly requested embedded profiles to listener-derived
/// reachability without inventing a listener or binding site.
pub fn include_embedded_profile_roots(
  plan: &GatewayPlan,
  roots: &EmbeddedProfileRoots,
  reachable: &mut ProfileReachability,
) -> ProfileLinkResult<()> {
  for profile_id in roots.profile_ids() {
    let profile = plan
      .profile(profile_id)
      .ok_or_else(|| ProfileLinkError::UnknownEmbeddedProfile {
        profile: profile_id.clone(),
      })?;
    if plan.route(profile.route()).is_none() {
      return Err(ProfileLinkError::UnknownEmbeddedRoute {
        profile: profile_id.clone(),
        route: profile.route().clone(),
      });
    }
    reachable.profile_ids.insert(profile_id.clone());
    reachable.route_ids.insert(profile.route().clone());
  }
  Ok(())
}

fn scan_action(
  plan: &GatewayPlan,
  listener: &ListenerId,
  site: ProfileReferenceSite,
  action: &HttpAction,
  reachable: &mut ProfileReachability,
) -> ProfileLinkResult<()> {
  let HttpAction::Route(profile_id) = action else {
    return Ok(());
  };
  let profile = plan
    .profile(profile_id)
    .ok_or_else(|| ProfileLinkError::UnknownProfileReference {
      listener: listener.clone(),
      site: site.clone(),
      profile: profile_id.clone(),
    })?;
  if plan.route(profile.route()).is_none() {
    return Err(ProfileLinkError::UnknownRouteReference {
      listener: listener.clone(),
      site,
      profile: profile_id.clone(),
      route: profile.route().clone(),
    });
  }

  reachable.profile_ids.insert(profile_id.clone());
  reachable.route_ids.insert(profile.route().clone());
  Ok(())
}

/// Every linked profile in the reachable runtime subgraph.
#[derive(Clone, Debug)]
pub struct LinkedProfiles {
  profiles: BTreeMap<ProfileId, Arc<LinkedProfile>>,
}

impl LinkedProfiles {
  pub fn profile(&self, profile_id: &ProfileId) -> Option<&Arc<LinkedProfile>> {
    self.profiles.get(profile_id)
  }

  pub fn profiles(&self) -> impl ExactSizeIterator<Item = (&ProfileId, &Arc<LinkedProfile>)> {
    self.profiles.iter()
  }

  pub fn len(&self) -> usize {
    self.profiles.len()
  }

  pub fn is_empty(&self) -> bool {
    self.profiles.is_empty()
  }
}

/// One reachable profile with its exact shared linked route.
#[derive(Clone, Debug)]
pub struct LinkedProfile {
  id: ProfileId,
  route: Arc<LinkedRoute>,
  wire_identity: LinkedWireIdentity,
}

impl LinkedProfile {
  pub fn id(&self) -> &ProfileId {
    &self.id
  }

  pub fn route(&self) -> &Arc<LinkedRoute> {
    &self.route
  }

  pub fn wire_identity(&self) -> &LinkedWireIdentity {
    &self.wire_identity
  }
}

/// Runtime identity behavior after all symbolic names and provider defaults
/// have been resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkedWireIdentity {
  None,
  Fixed(AgentId),
  ProviderDefaults(BTreeMap<ProviderId, AgentId>),
}

impl LinkedWireIdentity {
  pub fn resolve(&self, provider: &ProviderId) -> Option<&AgentId> {
    match self {
      Self::None => None,
      Self::Fixed(identity) => Some(identity),
      Self::ProviderDefaults(defaults) => defaults.get(provider),
    }
  }
}

/// Link only profiles returned by [`scan_profile_reachability`].
pub fn link_profiles(
  plan: &GatewayPlan,
  reachable: &ProfileReachability,
  routes: &LinkedRoutes,
  names: &RuntimeNameRegistry,
) -> ProfileLinkResult<LinkedProfiles> {
  let mut profiles = BTreeMap::new();

  for profile_id in reachable.profile_ids() {
    let profile = plan
      .profile(profile_id)
      .ok_or_else(|| ProfileLinkError::MissingReachableProfile {
        profile: profile_id.clone(),
      })?;
    let route = routes
      .route(profile.route())
      .cloned()
      .ok_or_else(|| ProfileLinkError::MissingLinkedRoute {
        profile: profile_id.clone(),
        route: profile.route().clone(),
      })?;
    let wire_identity = link_wire_identity(profile_id, &route, profile.wire_identity(), names)?;
    profiles.insert(
      profile_id.clone(),
      Arc::new(LinkedProfile {
        id: profile_id.clone(),
        route,
        wire_identity,
      }),
    );
  }

  Ok(LinkedProfiles { profiles })
}

fn link_wire_identity(
  profile_id: &ProfileId,
  route: &LinkedRoute,
  wire_identity: &WireIdentity,
  names: &RuntimeNameRegistry,
) -> ProfileLinkResult<LinkedWireIdentity> {
  if route.route_kind() == RouteKind::Transparent && !matches!(wire_identity, WireIdentity::None) {
    return Err(ProfileLinkError::TransparentWireIdentity {
      profile: profile_id.clone(),
      route: route.id().clone(),
    });
  }

  match wire_identity {
    WireIdentity::None => Ok(LinkedWireIdentity::None),
    WireIdentity::Named(identity) => names
      .resolve_wire_identity(identity)
      .cloned()
      .map(LinkedWireIdentity::Fixed)
      .ok_or_else(|| ProfileLinkError::UnknownWireIdentity {
        profile: profile_id.clone(),
        identity: identity.clone(),
      }),
    WireIdentity::ProviderDefault => {
      let mut defaults = BTreeMap::new();
      for provider in route.possible_provider_ids() {
        let identity = names.resolve_provider_default(&provider).cloned().ok_or_else(|| {
          ProfileLinkError::MissingProviderDefault {
            profile: profile_id.clone(),
            route: route.id().clone(),
            provider: provider.clone(),
          }
        })?;
        defaults.insert(provider, identity);
      }
      Ok(LinkedWireIdentity::ProviderDefaults(defaults))
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum ProfileLinkError {
  #[snafu(display("listener '{listener}' {site} references unknown profile '{profile}'"))]
  UnknownProfileReference {
    listener: ListenerId,
    site: ProfileReferenceSite,
    profile: ProfileId,
  },

  #[snafu(display("listener '{listener}' {site} profile '{profile}' references unknown route '{route}'"))]
  UnknownRouteReference {
    listener: ListenerId,
    site: ProfileReferenceSite,
    profile: ProfileId,
    route: RouteId,
  },

  #[snafu(display("embedded profile root '{profile}' does not exist in the gateway plan"))]
  UnknownEmbeddedProfile { profile: ProfileId },

  #[snafu(display("embedded profile root '{profile}' references unknown route '{route}'"))]
  UnknownEmbeddedRoute { profile: ProfileId, route: RouteId },

  #[snafu(display("reachable profile '{profile}' disappeared from the gateway plan during linking"))]
  MissingReachableProfile { profile: ProfileId },

  #[snafu(display("reachable profile '{profile}' route '{route}' has no linked runtime route"))]
  MissingLinkedRoute { profile: ProfileId, route: RouteId },

  #[snafu(display("profile '{profile}' references unknown wire identity '{identity}'"))]
  UnknownWireIdentity {
    profile: ProfileId,
    identity: WireIdentityId,
  },

  #[snafu(display("profile '{profile}' route '{route}' has no default wire identity for provider '{provider}'"))]
  MissingProviderDefault {
    profile: ProfileId,
    route: RouteId,
    provider: ProviderId,
  },

  #[snafu(display("transparent profile '{profile}' route '{route}' must use wire identity 'none'"))]
  TransparentWireIdentity { profile: ProfileId, route: RouteId },
}

pub type ProfileLinkResult<T> = std::result::Result<T, ProfileLinkError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::link_routes;
  use smol_str::SmolStr;
  use std::net::{Ipv4Addr, SocketAddr};
  use std::time::Duration;
  use tokn_accounts::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph};
  use tokn_accounts::registry::Registry;
  use tokn_core::account::AccountConfig;
  use tokn_core::provider::{ID_LLAMA_CPP, ID_OPENAI};
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, CanonicalHost, ClientAuthPlan,
    ConnectAction, ConnectMatch, ConnectRulePlan, FallbackSelector, ForwardProxyListenerPlan, HostPattern,
    HttpBindingPlan, HttpMatch, LlmApiListenerPlan, ManagedRetry, ManagedRoute, ManagedTarget, ModelCandidate,
    ModelGroupId, ModelGroupPlan, ModelSelector, OperationPolicy, ProfilePlan, RoutePlan, UpstreamId, UpstreamPlan,
    UpstreamSelector,
  };

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn binding_id(value: &str) -> BindingId {
    BindingId::new(value).unwrap()
  }

  fn profile_id(value: &str) -> ProfileId {
    ProfileId::new(value).unwrap()
  }

  fn route_id(value: &str) -> RouteId {
    RouteId::new(value).unwrap()
  }

  fn pool_id(value: &str) -> AccountPoolId {
    AccountPoolId::new(value).unwrap()
  }

  fn upstream_id(value: &str) -> UpstreamId {
    UpstreamId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
  }

  fn group_id(value: &str) -> ModelGroupId {
    ModelGroupId::new(value).unwrap()
  }

  fn wire_identity_id(value: &str) -> WireIdentityId {
    WireIdentityId::new(value).unwrap()
  }

  fn http_match() -> HttpMatch {
    HttpMatch::new(
      vec![HostPattern::exact(CanonicalHost::parse("api.example.com").unwrap())].into_boxed_slice(),
      Box::default(),
      Box::default(),
      Box::default(),
    )
    .unwrap()
  }

  fn binding(id: &str, action: HttpAction) -> HttpBindingPlan {
    HttpBindingPlan::new(binding_id(id), http_match(), action)
  }

  fn llm_listener(bindings: Vec<HttpBindingPlan>, default: HttpAction) -> tokn_policy::ListenerPlan {
    tokn_policy::ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
      ClientAuthPlan::None,
      bindings.into_boxed_slice(),
      default,
    ))
  }

  fn proxy_listener_with_connect_only() -> tokn_policy::ListenerPlan {
    let connect_match = ConnectMatch::new(
      vec![HostPattern::exact(CanonicalHost::parse("api.example.com").unwrap())].into_boxed_slice(),
      Box::default(),
    )
    .unwrap();
    tokn_policy::ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
      ClientAuthPlan::None,
      vec![binding("http-reject", HttpAction::Reject)].into_boxed_slice(),
      HttpAction::Reject,
      vec![ConnectRulePlan::new(
        binding_id("connect-intercept"),
        connect_match,
        ConnectAction::Intercept,
      )]
      .into_boxed_slice(),
      ConnectAction::Tunnel,
      None,
    ))
  }

  fn gateway(
    listeners: BTreeMap<ListenerId, tokn_policy::ListenerPlan>,
    profiles: BTreeMap<ProfileId, ProfilePlan>,
    routes: BTreeMap<RouteId, RoutePlan>,
    pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
    groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(listeners, profiles, routes, pools, upstreams, groups)
  }

  fn transparent_route() -> RoutePlan {
    RoutePlan::Transparent(Default::default())
  }

  fn link_routes_for(plan: &GatewayPlan, route_ids: &BTreeSet<RouteId>, accounts: &[AccountConfig]) -> LinkedRoutes {
    let registry = Registry::builtin();
    let providers = link_provider_graph(plan, accounts, &registry).unwrap();
    let pools = link_account_pools(plan, &providers, &registry).unwrap();
    let runtimes = build_account_pool_runtimes(&pools);
    link_routes(plan, route_ids, &providers, &runtimes).unwrap()
  }

  fn account(id: &str, provider: &str) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.id = id.to_string();
    account.provider = provider.to_string();
    if provider == ID_OPENAI {
      account.api_key = Some("test-key".to_string().into());
    }
    account
  }

  fn upstream(provider: &str, base_url: &str) -> UpstreamPlan {
    UpstreamPlan::new(provider_id(provider), Some(base_url.into()), Box::default(), false)
  }

  fn managed_route(model: ModelSelector) -> RoutePlan {
    RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(pool_id("all"), UpstreamSelector::Any, model),
      OperationPolicy::TranslateCompatible,
      None,
      ManagedRetry::Never,
    ))
  }

  fn provider_gateway(reachable_profile: &str, wire_identity: WireIdentity) -> GatewayPlan {
    let capability = route_id("capability");
    let fallback = route_id("fallback");
    let fallback_group = group_id("openai-only");
    gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(Vec::new(), HttpAction::Route(profile_id(reachable_profile))),
      )]),
      BTreeMap::from([
        (
          profile_id("multi"),
          ProfilePlan::new(capability.clone(), wire_identity.clone()),
        ),
        (
          profile_id("fallback-only"),
          ProfilePlan::new(fallback.clone(), wire_identity),
        ),
      ]),
      BTreeMap::from([
        (capability, managed_route(ModelSelector::Capability)),
        (
          fallback,
          managed_route(ModelSelector::Fallback(FallbackSelector::Fixed(fallback_group.clone()))),
        ),
      ]),
      BTreeMap::from([(
        pool_id("all"),
        AccountPoolPlan::new(
          AccountSelector::all(),
          AccountSelectionStrategy::RoundRobin,
          Duration::from_secs(5),
          None,
        ),
      )]),
      BTreeMap::from([
        (
          upstream_id("llama-a"),
          upstream(ID_LLAMA_CPP, "https://llama-a.example/v1/"),
        ),
        (
          upstream_id("llama-z"),
          upstream(ID_LLAMA_CPP, "https://llama-z.example/v1/"),
        ),
        (upstream_id("openai"), upstream(ID_OPENAI, "https://openai.example/v1/")),
      ]),
      BTreeMap::from([(
        fallback_group,
        ModelGroupPlan::new(vec![ModelCandidate::new(Some(upstream_id("openai")), "gpt-test")].into_boxed_slice()),
      )]),
    )
  }

  fn provider_accounts() -> Vec<AccountConfig> {
    vec![account("llama", ID_LLAMA_CPP), account("openai", ID_OPENAI)]
  }

  fn register_provider_default(names: &mut RuntimeNameRegistry, provider: &str, identity: &str) {
    names
      .register_provider_default(provider_id(provider), AgentId::Other(SmolStr::new(identity)))
      .unwrap();
  }

  #[test]
  fn scan_collects_only_http_route_actions_and_deduplicates_exact_sets() {
    let first_profile = profile_id("first");
    let default_profile = profile_id("default");
    let unused_profile = profile_id("connect-only");
    let first_route = route_id("first-route");
    let default_route = route_id("default-route");
    let unused_route = route_id("unused-route");
    let plan = gateway(
      BTreeMap::from([
        (
          listener_id("api"),
          llm_listener(
            vec![
              binding("first", HttpAction::Route(first_profile.clone())),
              binding("reject", HttpAction::Reject),
              binding("repeat", HttpAction::Route(first_profile.clone())),
            ],
            HttpAction::Route(default_profile.clone()),
          ),
        ),
        (listener_id("proxy"), proxy_listener_with_connect_only()),
      ]),
      BTreeMap::from([
        (
          first_profile.clone(),
          ProfilePlan::new(first_route.clone(), WireIdentity::None),
        ),
        (
          default_profile.clone(),
          ProfilePlan::new(default_route.clone(), WireIdentity::None),
        ),
        (
          unused_profile,
          ProfilePlan::new(unused_route.clone(), WireIdentity::None),
        ),
      ]),
      BTreeMap::from([
        (first_route.clone(), transparent_route()),
        (default_route.clone(), transparent_route()),
        (unused_route, transparent_route()),
      ]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );

    let reachable = scan_profile_reachability(&plan).unwrap();
    assert_eq!(
      reachable.profile_ids(),
      &BTreeSet::from([default_profile, first_profile])
    );
    assert_eq!(reachable.route_ids(), &BTreeSet::from([default_route, first_route]));
  }

  #[test]
  fn scan_reports_missing_profile_and_route_with_binding_or_default_context() {
    let missing_profile = profile_id("missing");
    let missing_profile_plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(
          vec![binding("broken", HttpAction::Route(missing_profile.clone()))],
          HttpAction::Reject,
        ),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    assert!(matches!(
      scan_profile_reachability(&missing_profile_plan),
      Err(ProfileLinkError::UnknownProfileReference {
        listener,
        site: ProfileReferenceSite::Binding(binding),
        profile,
      }) if listener.as_str() == "api" && binding.as_str() == "broken" && profile == missing_profile
    ));

    let profile = profile_id("default");
    let missing_route = route_id("missing-route");
    let missing_route_plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(Vec::new(), HttpAction::Route(profile.clone())),
      )]),
      BTreeMap::from([(
        profile.clone(),
        ProfilePlan::new(missing_route.clone(), WireIdentity::None),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    assert!(matches!(
      scan_profile_reachability(&missing_route_plan),
      Err(ProfileLinkError::UnknownRouteReference {
        listener,
        site: ProfileReferenceSite::DefaultHttpAction,
        profile: error_profile,
        route,
      }) if listener.as_str() == "api" && error_profile == profile && route == missing_route
    ));
  }

  #[test]
  fn unreachable_named_identity_is_not_resolved() {
    let route = route_id("transparent");
    let reachable_profile = profile_id("reachable");
    let unreachable_profile = profile_id("unreachable");
    let plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(Vec::new(), HttpAction::Route(reachable_profile.clone())),
      )]),
      BTreeMap::from([
        (
          reachable_profile.clone(),
          ProfilePlan::new(route.clone(), WireIdentity::None),
        ),
        (
          unreachable_profile.clone(),
          ProfilePlan::new(route.clone(), WireIdentity::Named(wire_identity_id("not-registered"))),
        ),
      ]),
      BTreeMap::from([(route, transparent_route())]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let reachable = scan_profile_reachability(&plan).unwrap();
    let routes = link_routes_for(&plan, reachable.route_ids(), &[]);
    let linked = link_profiles(&plan, &reachable, &routes, &RuntimeNameRegistry::new()).unwrap();

    assert_eq!(linked.len(), 1);
    assert!(matches!(
      linked.profile(&reachable_profile).unwrap().wire_identity(),
      LinkedWireIdentity::None
    ));
    assert!(linked.profile(&unreachable_profile).is_none());
  }

  #[test]
  fn reachable_unknown_named_identity_fails_strictly() {
    let plan = provider_gateway("multi", WireIdentity::Named(wire_identity_id("not-registered")));
    let reachable = scan_profile_reachability(&plan).unwrap();
    let routes = link_routes_for(&plan, reachable.route_ids(), &provider_accounts());

    assert!(matches!(
      link_profiles(&plan, &reachable, &routes, &RuntimeNameRegistry::builtin()),
      Err(ProfileLinkError::UnknownWireIdentity { profile, identity })
        if profile.as_str() == "multi" && identity.as_str() == "not-registered"
    ));

    let known = provider_gateway("multi", WireIdentity::Named(wire_identity_id("opencode")));
    let known_reachable = scan_profile_reachability(&known).unwrap();
    let linked = link_profiles(&known, &known_reachable, &routes, &RuntimeNameRegistry::builtin()).unwrap();
    let identity = linked.profile(&profile_id("multi")).unwrap().wire_identity();
    assert_eq!(identity.resolve(&provider_id(ID_LLAMA_CPP)), Some(&AgentId::Opencode));
    assert_eq!(identity.resolve(&provider_id(ID_OPENAI)), Some(&AgentId::Opencode));
  }

  #[test]
  fn provider_defaults_are_sorted_deduplicated_and_strict() {
    let plan = provider_gateway("multi", WireIdentity::ProviderDefault);
    let reachable = scan_profile_reachability(&plan).unwrap();
    let routes = link_routes_for(&plan, reachable.route_ids(), &provider_accounts());
    let mut names = RuntimeNameRegistry::new();
    register_provider_default(&mut names, ID_LLAMA_CPP, "llama-agent");
    register_provider_default(&mut names, ID_OPENAI, "openai-agent");

    let linked = link_profiles(&plan, &reachable, &routes, &names).unwrap();
    let profile = linked.profile(&profile_id("multi")).unwrap();
    let LinkedWireIdentity::ProviderDefaults(defaults) = profile.wire_identity() else {
      panic!("expected provider defaults");
    };
    assert_eq!(
      defaults.keys().map(ProviderId::as_str).collect::<Vec<_>>(),
      [ID_LLAMA_CPP, ID_OPENAI]
    );
    assert_eq!(defaults[&provider_id(ID_LLAMA_CPP)].as_str(), "llama-agent");
    assert_eq!(defaults[&provider_id(ID_OPENAI)].as_str(), "openai-agent");
    assert_eq!(
      profile
        .wire_identity()
        .resolve(&provider_id(ID_OPENAI))
        .map(AgentId::as_str),
      Some("openai-agent")
    );
    assert_eq!(
      profile
        .route()
        .possible_provider_ids()
        .iter()
        .map(ProviderId::as_str)
        .collect::<Vec<_>>(),
      [ID_LLAMA_CPP, ID_OPENAI]
    );

    let mut missing = RuntimeNameRegistry::new();
    register_provider_default(&mut missing, ID_LLAMA_CPP, "llama-agent");
    assert!(matches!(
      link_profiles(&plan, &reachable, &routes, &missing),
      Err(ProfileLinkError::MissingProviderDefault {
        profile,
        route,
        provider,
      }) if profile.as_str() == "multi" && route.as_str() == "capability" && provider.as_str() == ID_OPENAI
    ));
  }

  #[test]
  fn fallback_provider_defaults_use_only_surviving_candidate_upstreams() {
    let plan = provider_gateway("fallback-only", WireIdentity::ProviderDefault);
    let reachable = scan_profile_reachability(&plan).unwrap();
    let routes = link_routes_for(&plan, reachable.route_ids(), &provider_accounts());
    let mut names = RuntimeNameRegistry::new();
    register_provider_default(&mut names, ID_OPENAI, "openai-agent");

    let linked = link_profiles(&plan, &reachable, &routes, &names).unwrap();
    let profile = linked.profile(&profile_id("fallback-only")).unwrap();
    let LinkedWireIdentity::ProviderDefaults(defaults) = profile.wire_identity() else {
      panic!("expected provider defaults");
    };
    assert_eq!(defaults.keys().map(ProviderId::as_str).collect::<Vec<_>>(), [ID_OPENAI]);
    assert_eq!(
      profile
        .route()
        .possible_provider_ids()
        .iter()
        .map(ProviderId::as_str)
        .collect::<Vec<_>>(),
      [ID_OPENAI]
    );
  }

  #[test]
  fn transparent_routes_reject_every_non_none_identity() {
    for identity in [
      WireIdentity::Named(wire_identity_id("opencode")),
      WireIdentity::ProviderDefault,
    ] {
      let route = route_id("transparent");
      let profile = profile_id("transparent");
      let plan = gateway(
        BTreeMap::from([(
          listener_id("api"),
          llm_listener(Vec::new(), HttpAction::Route(profile.clone())),
        )]),
        BTreeMap::from([(profile.clone(), ProfilePlan::new(route.clone(), identity))]),
        BTreeMap::from([(route.clone(), transparent_route())]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
      );
      let reachable = scan_profile_reachability(&plan).unwrap();
      let routes = link_routes_for(&plan, reachable.route_ids(), &[]);

      assert!(matches!(
        link_profiles(&plan, &reachable, &routes, &RuntimeNameRegistry::builtin()),
        Err(ProfileLinkError::TransparentWireIdentity {
          profile: error_profile,
          route: error_route,
        }) if error_profile == profile && error_route == route
      ));
    }
  }

  #[test]
  fn linked_profiles_share_profile_and_exact_route_arcs() {
    let route = route_id("shared");
    let first = profile_id("first");
    let second = profile_id("second");
    let plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(
          vec![
            binding("first", HttpAction::Route(first.clone())),
            binding("first-again", HttpAction::Route(first.clone())),
          ],
          HttpAction::Route(second.clone()),
        ),
      )]),
      BTreeMap::from([
        (first.clone(), ProfilePlan::new(route.clone(), WireIdentity::None)),
        (second.clone(), ProfilePlan::new(route.clone(), WireIdentity::None)),
      ]),
      BTreeMap::from([(route.clone(), transparent_route())]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let reachable = scan_profile_reachability(&plan).unwrap();
    let routes = link_routes_for(&plan, reachable.route_ids(), &[]);
    let linked = link_profiles(&plan, &reachable, &routes, &RuntimeNameRegistry::new()).unwrap();
    let first_profile = linked.profile(&first).unwrap();
    let second_profile = linked.profile(&second).unwrap();

    assert_eq!(linked.len(), 2);
    assert!(Arc::ptr_eq(first_profile.route(), second_profile.route()));
    assert!(Arc::ptr_eq(first_profile.route(), routes.route(&route).unwrap()));
    assert!(Arc::ptr_eq(first_profile, linked.profile(&first).unwrap()));
  }
}

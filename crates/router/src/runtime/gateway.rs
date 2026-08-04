//! Composed runtime ownership for one fully linked gateway plan.
//!
//! Linking is intentionally phased. Global provider/account/pool resources are
//! validated before listener reachability narrows route materialization, and
//! every later phase reuses the exact `Arc` nodes produced by the earlier one.

use super::{
  include_embedded_profile_roots, link_listeners, link_profiles, link_routes, scan_profile_reachability,
  EmbeddedProfileRoots, LinkedListeners, LinkedProfiles, LinkedRoutes, ListenerLinkError, ProfileLinkError,
  RouteLinkError, RuntimeNameRegistry,
};
use snafu::Snafu;
use tokn_accounts::link::{
  build_account_pool_runtimes, link_account_pools, link_provider_graph, AccountPoolRuntimes, LinkError,
  LinkedAccountPools, PoolLinkError, ProviderGraph,
};
use tokn_accounts::registry::Registry;
use tokn_core::account::AccountConfig;
use tokn_policy::GatewayPlan;

/// The complete linked runtime graph required before any listener binds.
#[derive(Debug)]
pub struct LinkedGatewayRuntime {
  provider_graph: ProviderGraph,
  account_pools: LinkedAccountPools,
  account_pool_runtimes: AccountPoolRuntimes,
  routes: LinkedRoutes,
  profiles: LinkedProfiles,
  listeners: LinkedListeners,
}

impl LinkedGatewayRuntime {
  pub fn provider_graph(&self) -> &ProviderGraph {
    &self.provider_graph
  }

  pub fn account_pools(&self) -> &LinkedAccountPools {
    &self.account_pools
  }

  pub fn account_pool_runtimes(&self) -> &AccountPoolRuntimes {
    &self.account_pool_runtimes
  }

  pub fn routes(&self) -> &LinkedRoutes {
    &self.routes
  }

  pub fn profiles(&self) -> &LinkedProfiles {
    &self.profiles
  }

  pub fn listeners(&self) -> &LinkedListeners {
    &self.listeners
  }
}

/// Link a compiled gateway plan with the providers, operations, and wire
/// identities shipped by the gateway binary.
///
/// This is the production default for callers that do not install runtime
/// extensions. Keeping registry construction beside the linker ensures
/// startup and preflight validation use the same built-in namespace.
pub fn link_builtin_gateway_runtime(
  plan: &GatewayPlan,
  accounts: &[AccountConfig],
) -> GatewayLinkResult<LinkedGatewayRuntime> {
  link_builtin_gateway_runtime_with_profile_roots(plan, accounts, &EmbeddedProfileRoots::default())
}

/// Link the listener graph plus explicit profiles used by an in-process
/// consumer with the registries shipped by the gateway binary.
pub fn link_builtin_gateway_runtime_with_profile_roots(
  plan: &GatewayPlan,
  accounts: &[AccountConfig],
  embedded_profiles: &EmbeddedProfileRoots,
) -> GatewayLinkResult<LinkedGatewayRuntime> {
  let registry = Registry::builtin();
  let names = RuntimeNameRegistry::builtin();
  link_gateway_runtime_with_profile_roots(plan, accounts, &registry, &names, embedded_profiles)
}

/// Link a compiled gateway plan and account snapshot into one runtime graph.
///
/// The plan, account slice, and registries are no longer needed after this
/// function returns: linked nodes own the account configs and every resolved
/// runtime value they require.
pub fn link_gateway_runtime(
  plan: &GatewayPlan,
  accounts: &[AccountConfig],
  registry: &Registry,
  names: &RuntimeNameRegistry,
) -> GatewayLinkResult<LinkedGatewayRuntime> {
  link_gateway_runtime_with_profile_roots(plan, accounts, registry, names, &EmbeddedProfileRoots::default())
}

/// Link one runtime generation from listener roots plus explicit embedded
/// profile roots.
pub fn link_gateway_runtime_with_profile_roots(
  plan: &GatewayPlan,
  accounts: &[AccountConfig],
  registry: &Registry,
  names: &RuntimeNameRegistry,
  embedded_profiles: &EmbeddedProfileRoots,
) -> GatewayLinkResult<LinkedGatewayRuntime> {
  let provider_graph =
    link_provider_graph(plan, accounts, registry).map_err(|source| GatewayLinkError::ProviderGraph { source })?;
  let account_pools =
    link_account_pools(plan, &provider_graph, registry).map_err(|source| GatewayLinkError::AccountPools { source })?;
  let account_pool_runtimes = build_account_pool_runtimes(&account_pools);

  let mut reachable =
    scan_profile_reachability(plan).map_err(|source| GatewayLinkError::ProfileReachability { source })?;
  include_embedded_profile_roots(plan, embedded_profiles, &mut reachable)
    .map_err(|source| GatewayLinkError::ProfileReachability { source })?;
  let routes = link_routes(plan, reachable.route_ids(), &provider_graph, &account_pool_runtimes)
    .map_err(|source| GatewayLinkError::Routes { source })?;
  let profiles =
    link_profiles(plan, &reachable, &routes, names).map_err(|source| GatewayLinkError::Profiles { source })?;
  let listeners = link_listeners(plan, &profiles, names).map_err(|source| GatewayLinkError::Listeners { source })?;

  Ok(LinkedGatewayRuntime {
    provider_graph,
    account_pools,
    account_pool_runtimes,
    routes,
    profiles,
    listeners,
  })
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum GatewayLinkError {
  #[snafu(display("failed to link the provider graph: {source}"))]
  ProviderGraph { source: LinkError },

  #[snafu(display("failed to link account pools: {source}"))]
  AccountPools { source: PoolLinkError },

  #[snafu(display("failed to scan profile reachability: {source}"))]
  ProfileReachability { source: ProfileLinkError },

  #[snafu(display("failed to link reachable routes: {source}"))]
  Routes { source: RouteLinkError },

  #[snafu(display("failed to link reachable profiles: {source}"))]
  Profiles { source: ProfileLinkError },

  #[snafu(display("failed to link listeners: {source}"))]
  Listeners { source: ListenerLinkError },
}

pub type GatewayLinkResult<T> = std::result::Result<T, GatewayLinkError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{LinkedHttpAction, LinkedRouteKind};
  use std::collections::{BTreeMap, BTreeSet};
  use std::net::{Ipv4Addr, SocketAddr};
  use std::sync::Arc;
  use std::time::Duration;
  use tokn_accounts::link::{LinkError as ProviderGraphLinkError, PoolLinkError, TargetLinkError};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, ClientAuthPlan, ConnectAction,
    ForwardProxyListenerPlan, LlmApiListenerPlan, ManagedRetry, ManagedRoute, ManagedTarget, ModelGroupId,
    ModelSelector, OperationPolicy, ProfileId, ProfilePlan, ProviderId, RouteId, RoutePlan, UpstreamId, UpstreamPlan,
    UpstreamSelector, WireIdentity,
  };

  fn listener_id(value: &str) -> tokn_policy::ListenerId {
    tokn_policy::ListenerId::new(value).unwrap()
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

  fn gateway(
    listeners: BTreeMap<tokn_policy::ListenerId, tokn_policy::ListenerPlan>,
    profiles: BTreeMap<ProfileId, ProfilePlan>,
    routes: BTreeMap<RouteId, RoutePlan>,
    pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(
      listeners,
      profiles,
      routes,
      pools,
      upstreams,
      BTreeMap::<ModelGroupId, _>::new(),
    )
  }

  fn llm_listener(port: u16, default: tokn_policy::HttpAction) -> tokn_policy::ListenerPlan {
    tokn_policy::ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
      ClientAuthPlan::None,
      Box::default(),
      default,
    ))
  }

  fn proxy_listener(port: u16, default: tokn_policy::HttpAction) -> tokn_policy::ListenerPlan {
    tokn_policy::ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
      ClientAuthPlan::None,
      Box::default(),
      default,
      Box::default(),
      ConnectAction::Tunnel,
      None,
    ))
  }

  fn account(id: &str) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.id = id.to_string();
    account
  }

  fn managed_route(pool: &str, upstream: UpstreamSelector) -> RoutePlan {
    RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(pool_id(pool), upstream, ModelSelector::Capability),
      OperationPolicy::TranslateCompatible,
      None,
      ManagedRetry::Never,
    ))
  }

  fn empty_pool() -> AccountPoolPlan {
    AccountPoolPlan::new(
      AccountSelector::all(),
      AccountSelectionStrategy::RoundRobin,
      Duration::from_secs(5),
      None,
    )
  }

  fn builtin_managed_gateway(wire_identity: WireIdentity) -> (GatewayPlan, ProfileId, ProviderId) {
    let profile = profile_id("default");
    let route = route_id("managed");
    let pool = pool_id("all");
    let upstream = upstream_id("local");
    let provider = provider_id(ID_LLAMA_CPP);
    let plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_000, tokn_policy::HttpAction::Route(profile.clone())),
      )]),
      BTreeMap::from([(profile.clone(), ProfilePlan::new(route.clone(), wire_identity))]),
      BTreeMap::from([(route, managed_route("all", UpstreamSelector::Fixed(upstream.clone())))]),
      BTreeMap::from([(pool, empty_pool())]),
      BTreeMap::from([(
        upstream,
        UpstreamPlan::new(
          provider.clone(),
          Some("https://llama.example/v1/".into()),
          Box::default(),
          false,
        ),
      )]),
    );
    (plan, profile, provider)
  }

  #[test]
  fn builtin_linker_resolves_shipped_provider_and_wire_identity() {
    let (plan, profile, provider) = builtin_managed_gateway(WireIdentity::Named(
      tokn_policy::WireIdentityId::new("opencode").unwrap(),
    ));

    let runtime = link_builtin_gateway_runtime(&plan, &[account("main")]).unwrap();

    assert!(runtime
      .provider_graph()
      .binding(&upstream_id("local"), "main")
      .is_some());
    assert_eq!(
      runtime
        .profiles()
        .profile(&profile)
        .unwrap()
        .wire_identity()
        .resolve(&provider),
      Some(&tokn_core::AgentId::Opencode)
    );
  }

  #[test]
  fn builtin_linker_rejects_unregistered_wire_identity() {
    let unknown = tokn_policy::WireIdentityId::new("not-installed").unwrap();
    let (plan, profile, _) = builtin_managed_gateway(WireIdentity::Named(unknown.clone()));

    assert!(matches!(
      link_builtin_gateway_runtime(&plan, &[account("main")]),
      Err(GatewayLinkError::Profiles {
        source: ProfileLinkError::UnknownWireIdentity {
          profile: failed_profile,
          identity,
        },
      }) if failed_profile == profile && identity == unknown
    ));
  }

  #[test]
  fn managed_gateway_preserves_arc_identity_across_every_linked_phase() {
    let listener_key = listener_id("api");
    let profile_key = profile_id("default");
    let route_key = route_id("managed");
    let pool_key = pool_id("all");
    let upstream_key = upstream_id("local");
    let plan = gateway(
      BTreeMap::from([(
        listener_key.clone(),
        llm_listener(41_001, tokn_policy::HttpAction::Route(profile_key.clone())),
      )]),
      BTreeMap::from([(
        profile_key.clone(),
        ProfilePlan::new(route_key.clone(), WireIdentity::ProviderDefault),
      )]),
      BTreeMap::from([(
        route_key.clone(),
        managed_route("all", UpstreamSelector::Fixed(upstream_key.clone())),
      )]),
      BTreeMap::from([(pool_key.clone(), empty_pool())]),
      BTreeMap::from([(
        upstream_key.clone(),
        UpstreamPlan::new(
          provider_id(ID_LLAMA_CPP),
          Some("https://llama.example/v1/".into()),
          Box::default(),
          false,
        ),
      )]),
    );

    let runtime = link_gateway_runtime(
      &plan,
      &[account("main")],
      &Registry::builtin(),
      &RuntimeNameRegistry::builtin(),
    )
    .unwrap();

    let listener = runtime.listeners().listener(&listener_key).unwrap();
    let LinkedHttpAction::Route(action_profile) = listener.http().default_action() else {
      panic!("expected linked route action");
    };
    let stored_profile = runtime.profiles().profile(&profile_key).unwrap();
    let stored_route = runtime.routes().route(&route_key).unwrap();
    let LinkedRouteKind::Managed(managed) = stored_route.kind() else {
      panic!("expected managed route");
    };
    let stored_runtime = runtime.account_pool_runtimes().runtime(&pool_key).unwrap();
    let stored_pool = runtime.account_pools().pool(&pool_key).unwrap();
    let graph_binding = runtime.provider_graph().binding(&upstream_key, "main").unwrap();
    let pool_binding = stored_pool.active()[0].binding(&upstream_key).unwrap();

    assert!(Arc::ptr_eq(action_profile, stored_profile));
    assert!(Arc::ptr_eq(stored_profile.route(), stored_route));
    assert!(Arc::ptr_eq(managed.target().pool(), stored_runtime));
    assert!(Arc::ptr_eq(stored_runtime.pool(), stored_pool));
    assert!(Arc::ptr_eq(graph_binding, pool_binding));
  }

  #[test]
  fn reject_and_tunnel_listener_links_with_an_empty_provider_account_graph() {
    let listener_key = listener_id("proxy");
    let plan = gateway(
      BTreeMap::from([(
        listener_key.clone(),
        proxy_listener(41_002, tokn_policy::HttpAction::Reject),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );

    let runtime = link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::new()).unwrap();
    let listener = runtime.listeners().listener(&listener_key).unwrap();

    assert!(runtime.provider_graph().is_empty());
    assert!(runtime.account_pools().is_empty());
    assert!(runtime.account_pool_runtimes().is_empty());
    assert!(runtime.routes().is_empty());
    assert!(runtime.profiles().is_empty());
    assert!(matches!(listener.http().default_action(), LinkedHttpAction::Reject));
    assert_eq!(
      listener.forward_proxy().unwrap().connect().default_action(),
      ConnectAction::Tunnel
    );
  }

  #[test]
  fn transparent_only_proxy_links_with_an_empty_provider_account_graph() {
    let listener_key = listener_id("proxy");
    let profile_key = profile_id("transparent");
    let route_key = route_id("transparent");
    let plan = gateway(
      BTreeMap::from([(
        listener_key.clone(),
        proxy_listener(41_003, tokn_policy::HttpAction::Route(profile_key.clone())),
      )]),
      BTreeMap::from([(
        profile_key.clone(),
        ProfilePlan::new(route_key.clone(), WireIdentity::None),
      )]),
      BTreeMap::from([(route_key.clone(), RoutePlan::Transparent(Default::default()))]),
      BTreeMap::new(),
      BTreeMap::new(),
    );

    let runtime = link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::new()).unwrap();
    let listener = runtime.listeners().listener(&listener_key).unwrap();
    let LinkedHttpAction::Route(action_profile) = listener.http().default_action() else {
      panic!("expected transparent route action");
    };

    assert!(runtime.provider_graph().is_empty());
    assert!(runtime.account_pools().is_empty());
    assert!(runtime.account_pool_runtimes().is_empty());
    assert_eq!(runtime.routes().len(), 1);
    assert_eq!(runtime.profiles().len(), 1);
    assert!(Arc::ptr_eq(
      action_profile,
      runtime.profiles().profile(&profile_key).unwrap()
    ));
    assert!(Arc::ptr_eq(
      action_profile.route(),
      runtime.routes().route(&route_key).unwrap()
    ));
  }

  #[test]
  fn unreachable_nonviable_route_is_not_materialized() {
    let broken_route = route_id("broken");
    let plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_004, tokn_policy::HttpAction::Reject),
      )]),
      BTreeMap::new(),
      BTreeMap::from([(
        broken_route.clone(),
        managed_route("missing-pool", UpstreamSelector::Fixed(upstream_id("missing-upstream"))),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
    );

    let runtime = link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::new()).unwrap();

    assert!(runtime.routes().is_empty());
    assert!(runtime.routes().route(&broken_route).is_none());
  }

  #[test]
  fn embedded_profile_roots_extend_listener_reachability_explicitly() {
    let profile = profile_id("embedded");
    let route = route_id("embedded");
    let pool = pool_id("embedded");
    let upstream = upstream_id("embedded");
    let plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_005, tokn_policy::HttpAction::Reject),
      )]),
      BTreeMap::from([(profile.clone(), ProfilePlan::new(route.clone(), WireIdentity::None))]),
      BTreeMap::from([(
        route.clone(),
        managed_route("embedded", UpstreamSelector::Fixed(upstream.clone())),
      )]),
      BTreeMap::from([(pool, empty_pool())]),
      BTreeMap::from([(
        upstream,
        UpstreamPlan::new(
          provider_id(ID_LLAMA_CPP),
          Some("https://llama.example/v1/".into()),
          Box::default(),
          false,
        ),
      )]),
    );
    let accounts = [account("main")];

    let listener_only = link_builtin_gateway_runtime(&plan, &accounts).unwrap();
    assert!(listener_only.profiles().is_empty());
    assert!(listener_only.routes().is_empty());

    let roots = EmbeddedProfileRoots::one(profile.clone());
    let embedded = link_builtin_gateway_runtime_with_profile_roots(&plan, &accounts, &roots).unwrap();
    assert!(embedded.profiles().profile(&profile).is_some());
    assert!(embedded.routes().route(&route).is_some());
  }

  #[test]
  fn unknown_embedded_profile_root_has_no_synthetic_listener_site() {
    let missing = profile_id("missing");
    let plan = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_006, tokn_policy::HttpAction::Reject),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let roots = EmbeddedProfileRoots::one(missing.clone());

    assert!(matches!(
      link_builtin_gateway_runtime_with_profile_roots(&plan, &[], &roots),
      Err(GatewayLinkError::ProfileReachability {
        source: ProfileLinkError::UnknownEmbeddedProfile { profile },
      }) if profile == missing
    ));
  }

  #[test]
  fn wrapper_errors_retain_the_exact_failing_phase_and_source() {
    let registry = Registry::builtin();
    let names = RuntimeNameRegistry::builtin();

    let unknown_provider = provider_id("not-installed");
    let provider_error = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_005, tokn_policy::HttpAction::Reject),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::from([(
        upstream_id("unused"),
        UpstreamPlan::new(
          unknown_provider.clone(),
          Some("https://unused.example/v1/".into()),
          Box::default(),
          false,
        ),
      )]),
    );
    assert!(matches!(
      link_gateway_runtime(&provider_error, &[], &registry, &names),
      Err(GatewayLinkError::ProviderGraph {
        source: ProviderGraphLinkError::UnknownProvider { provider, .. },
      }) if provider == unknown_provider
    ));

    let pool_error = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_006, tokn_policy::HttpAction::Reject),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::from([(
        pool_id("broken"),
        AccountPoolPlan::new(
          AccountSelector::new(
            Some(BTreeSet::from([provider_id("not-installed")])),
            None,
            BTreeSet::new(),
          ),
          AccountSelectionStrategy::RoundRobin,
          Duration::from_secs(5),
          None,
        ),
      )]),
      BTreeMap::new(),
    );
    assert!(matches!(
      link_gateway_runtime(&pool_error, &[], &registry, &names),
      Err(GatewayLinkError::AccountPools {
        source: PoolLinkError::UnknownProvider { pool, provider },
      }) if pool.as_str() == "broken" && provider.as_str() == "not-installed"
    ));

    let missing_profile = profile_id("missing");
    let reachability_error = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_007, tokn_policy::HttpAction::Route(missing_profile.clone())),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    assert!(matches!(
      link_gateway_runtime(&reachability_error, &[], &registry, &names),
      Err(GatewayLinkError::ProfileReachability {
        source: ProfileLinkError::UnknownProfileReference { profile, .. },
      }) if profile == missing_profile
    ));

    let route_profile = profile_id("route-error");
    let route_key = route_id("route-error");
    let route_error = gateway(
      BTreeMap::from([(
        listener_id("api"),
        llm_listener(41_008, tokn_policy::HttpAction::Route(route_profile.clone())),
      )]),
      BTreeMap::from([(route_profile, ProfilePlan::new(route_key.clone(), WireIdentity::None))]),
      BTreeMap::from([(route_key, managed_route("missing-pool", UpstreamSelector::Any))]),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    assert!(matches!(
      link_gateway_runtime(&route_error, &[], &registry, &names),
      Err(GatewayLinkError::Routes {
        source: RouteLinkError::Target {
          source: TargetLinkError::MissingPoolRuntime { pool },
          ..
        },
      }) if pool.as_str() == "missing-pool"
    ));

    let transparent_profile = profile_id("transparent");
    let transparent_route = route_id("transparent");
    let profile_error = gateway(
      BTreeMap::from([(
        listener_id("proxy"),
        proxy_listener(41_009, tokn_policy::HttpAction::Route(transparent_profile.clone())),
      )]),
      BTreeMap::from([(
        transparent_profile.clone(),
        ProfilePlan::new(
          transparent_route.clone(),
          WireIdentity::Named(tokn_policy::WireIdentityId::new("opencode").unwrap()),
        ),
      )]),
      BTreeMap::from([(transparent_route, RoutePlan::Transparent(Default::default()))]),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    assert!(matches!(
      link_gateway_runtime(&profile_error, &[], &registry, &names),
      Err(GatewayLinkError::Profiles {
        source: ProfileLinkError::TransparentWireIdentity { profile, .. },
      }) if profile == transparent_profile
    ));

    let listener_error = gateway(
      BTreeMap::from([(listener_id("api"), llm_listener(0, tokn_policy::HttpAction::Reject))]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    assert!(matches!(
      link_gateway_runtime(&listener_error, &[], &registry, &names),
      Err(GatewayLinkError::Listeners {
        source: ListenerLinkError::InvalidBindPort { listener, .. },
      }) if listener.as_str() == "api"
    ));
  }
}

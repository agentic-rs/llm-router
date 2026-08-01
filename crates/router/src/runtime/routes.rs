//! Router-owned linked route graph over account-owned target domains.
//!
//! Listener/profile reachability belongs to the router. This module accepts
//! the resulting route-id set and materializes the outer route wrappers.
//! Account selection, upstream identity, and model fallback data are linked
//! independently by the accounts target domain.
//! Header-patch and retry references remain future policy vocabulary; this
//! linker rejects them until matching registries and execution exist.

use snafu::Snafu;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokn_accounts::link::{
  link_managed_target, link_relay_target, AccountPoolRuntimes, LinkedManagedTarget, LinkedRelayTarget, ProviderGraph,
  TargetLinkError,
};
use tokn_policy::{
  DestinationPolicy, GatewayPlan, HeaderPatchSetId, ManagedRetry, ManagedRoute, OperationPolicy, ProviderId,
  RelayRetry, RelayRoute, RetryPolicyId, RouteId, RouteKind, RoutePlan,
};

/// Runtime materialization of the reachable route subgraph.
#[derive(Clone, Debug)]
pub struct LinkedRoutes {
  routes: BTreeMap<RouteId, Arc<LinkedRoute>>,
}

impl LinkedRoutes {
  pub fn route(&self, route_id: &RouteId) -> Option<&Arc<LinkedRoute>> {
    self.routes.get(route_id)
  }

  pub fn routes(&self) -> impl ExactSizeIterator<Item = (&RouteId, &Arc<LinkedRoute>)> {
    self.routes.iter()
  }

  pub fn len(&self) -> usize {
    self.routes.len()
  }

  pub fn is_empty(&self) -> bool {
    self.routes.is_empty()
  }
}

/// One reachable route with its stable policy identity.
#[derive(Clone, Debug)]
pub struct LinkedRoute {
  id: RouteId,
  kind: LinkedRouteKind,
}

impl LinkedRoute {
  pub fn id(&self) -> &RouteId {
    &self.id
  }

  pub fn kind(&self) -> &LinkedRouteKind {
    &self.kind
  }

  pub fn route_kind(&self) -> RouteKind {
    match self.kind {
      LinkedRouteKind::Managed(_) => RouteKind::Managed,
      LinkedRouteKind::Relay(_) => RouteKind::Relay,
      LinkedRouteKind::Transparent(_) => RouteKind::Transparent,
    }
  }

  /// Whether request execution selects an upstream or preserves the ingress
  /// destination. This is derived from the linked route so startup consumers
  /// do not need to retain the policy graph.
  pub fn destination_policy(&self) -> DestinationPolicy {
    match &self.kind {
      LinkedRouteKind::Managed(_) => DestinationPolicy::SelectedUpstream,
      LinkedRouteKind::Relay(route) if !route.target().preserves_original_destination() => {
        DestinationPolicy::SelectedUpstream
      }
      LinkedRouteKind::Relay(_) | LinkedRouteKind::Transparent(_) => DestinationPolicy::Original,
    }
  }

  /// Provider ids that this linked route can select at request time.
  ///
  /// Results are sorted and deduplicated. Managed fallback routes are narrowed
  /// to surviving linked candidates rather than the wider base upstream
  /// domain, which keeps startup identity requirements exact.
  pub fn possible_provider_ids(&self) -> Box<[ProviderId]> {
    match &self.kind {
      LinkedRouteKind::Managed(route) => route.target().possible_provider_ids(),
      LinkedRouteKind::Relay(route) => route.target().possible_provider_ids(),
      LinkedRouteKind::Transparent(_) => Box::default(),
    }
  }
}

/// Linked route families remain distinct so account-less transparent traffic
/// cannot accidentally flow through a credential-bearing path.
#[derive(Clone, Debug)]
pub enum LinkedRouteKind {
  Managed(LinkedManagedRoute),
  Relay(LinkedRelayRoute),
  Transparent(LinkedTransparentRoute),
}

/// Runtime-linked managed route.
#[derive(Clone, Debug)]
pub struct LinkedManagedRoute {
  target: LinkedManagedTarget,
  operation: OperationPolicy,
}

impl LinkedManagedRoute {
  pub fn target(&self) -> &LinkedManagedTarget {
    &self.target
  }

  pub fn operation(&self) -> OperationPolicy {
    self.operation
  }
}

/// Runtime-linked opaque relay route.
#[derive(Clone, Debug)]
pub struct LinkedRelayRoute {
  target: LinkedRelayTarget,
}

impl LinkedRelayRoute {
  pub fn target(&self) -> &LinkedRelayTarget {
    &self.target
  }
}

/// Runtime-linked transparent route. It intentionally owns no account or
/// provider state.
#[derive(Clone, Debug)]
pub struct LinkedTransparentRoute;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum RouteLinkError {
  #[snafu(display("reachable route '{route}' does not exist in the gateway plan"))]
  UnknownRoute { route: RouteId },

  #[snafu(display("route '{route}' has an invalid target: {source}"))]
  Target { route: RouteId, source: TargetLinkError },

  #[snafu(display(
    "route '{route}' references header patch set '{header_patch_set}', but route header patches are not implemented"
  ))]
  UnsupportedHeaderPatchSet {
    route: RouteId,
    header_patch_set: HeaderPatchSetId,
  },

  #[snafu(display(
    "managed route '{route}' references retry policy '{retry_policy}', but managed route retries are not implemented"
  ))]
  UnsupportedManagedRetry {
    route: RouteId,
    retry_policy: RetryPolicyId,
  },

  #[snafu(display(
    "relay route '{route}' references retry policy '{retry_policy}', but relay route retries are not implemented"
  ))]
  UnsupportedRelayRetry {
    route: RouteId,
    retry_policy: RetryPolicyId,
  },
}

pub type RouteLinkResult<T> = std::result::Result<T, RouteLinkError>;

/// Link only the route ids reachable from router-owned HTTP actions.
pub fn link_routes(
  plan: &GatewayPlan,
  reachable: &BTreeSet<RouteId>,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
) -> RouteLinkResult<LinkedRoutes> {
  let mut routes = BTreeMap::new();
  for route_id in reachable {
    let route = plan.route(route_id).ok_or_else(|| RouteLinkError::UnknownRoute {
      route: route_id.clone(),
    })?;
    validate_route_policies(route_id, route)?;
    let kind = match route {
      RoutePlan::Managed(route) => {
        LinkedRouteKind::Managed(link_managed_route(route_id, route, plan, providers, pools)?)
      }
      RoutePlan::Relay(route) => LinkedRouteKind::Relay(link_relay_route(route_id, route, plan, providers, pools)?),
      RoutePlan::Transparent(_) => LinkedRouteKind::Transparent(LinkedTransparentRoute),
    };
    routes.insert(
      route_id.clone(),
      Arc::new(LinkedRoute {
        id: route_id.clone(),
        kind,
      }),
    );
  }
  Ok(LinkedRoutes { routes })
}

fn validate_route_policies(route_id: &RouteId, route: &RoutePlan) -> RouteLinkResult<()> {
  if let Some(header_patch_set) = route.header_patches() {
    return Err(RouteLinkError::UnsupportedHeaderPatchSet {
      route: route_id.clone(),
      header_patch_set: header_patch_set.clone(),
    });
  }

  match route {
    RoutePlan::Managed(route) => match route.retry() {
      ManagedRetry::Never => Ok(()),
      ManagedRetry::Recoverable(retry_policy) => Err(RouteLinkError::UnsupportedManagedRetry {
        route: route_id.clone(),
        retry_policy: retry_policy.clone(),
      }),
    },
    RoutePlan::Relay(route) => match route.retry() {
      RelayRetry::Never => Ok(()),
      RelayRetry::SafeMethods(retry_policy) | RelayRetry::Buffered(retry_policy) => {
        Err(RouteLinkError::UnsupportedRelayRetry {
          route: route_id.clone(),
          retry_policy: retry_policy.clone(),
        })
      }
    },
    RoutePlan::Transparent(_) => Ok(()),
  }
}

fn link_managed_route(
  route_id: &RouteId,
  route: &ManagedRoute,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
) -> RouteLinkResult<LinkedManagedRoute> {
  let target =
    link_managed_target(route.target(), plan, providers, pools).map_err(|source| RouteLinkError::Target {
      route: route_id.clone(),
      source,
    })?;
  Ok(LinkedManagedRoute {
    target,
    operation: route.operation(),
  })
}

fn link_relay_route(
  route_id: &RouteId,
  route: &RelayRoute,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
) -> RouteLinkResult<LinkedRelayRoute> {
  let target = link_relay_target(route.target(), plan, providers, pools).map_err(|source| RouteLinkError::Target {
    route: route_id.clone(),
    source,
  })?;
  Ok(LinkedRelayRoute { target })
}

#[cfg(test)]
mod tests {
  use super::*;
  use smol_str::SmolStr;
  use std::time::Duration;
  use tokn_accounts::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph, TargetLinkError};
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, ManagedTarget, ModelGroupId,
    ModelGroupPlan, ModelSelector, RelayRetry, RelayTarget, RetryPolicyId, TransparentRoute, UpstreamId,
    UpstreamOrigin, UpstreamPlan, UpstreamSelector,
  };

  struct Inputs {
    providers: ProviderGraph,
    runtimes: AccountPoolRuntimes,
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

  fn patch_id(value: &str) -> HeaderPatchSetId {
    HeaderPatchSetId::new(value).unwrap()
  }

  fn retry_id(value: &str) -> RetryPolicyId {
    RetryPolicyId::new(value).unwrap()
  }

  fn account(id: &str, tier: AccountTier) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.id = id.to_string();
    account.tier = tier;
    account
  }

  fn account_pool(account_ids: Option<&[&str]>) -> AccountPoolPlan {
    AccountPoolPlan::new(
      AccountSelector::new(
        None,
        account_ids.map(|ids| ids.iter().map(SmolStr::new).collect()),
        BTreeSet::new(),
      ),
      AccountSelectionStrategy::RoundRobin,
      Duration::from_secs(5),
      None,
    )
  }

  fn upstream(base_url: Option<&str>, eligible_accounts: Option<&[&str]>, origins: &[&str]) -> UpstreamPlan {
    UpstreamPlan::new(
      provider_id(ID_LLAMA_CPP),
      base_url.map(Into::into),
      origins
        .iter()
        .map(UpstreamOrigin::new)
        .collect::<Vec<_>>()
        .into_boxed_slice(),
      false,
    )
    .with_eligible_accounts(eligible_accounts.map(|ids| ids.iter().map(SmolStr::new).collect()))
  }

  fn managed(pool: &str, upstream: UpstreamSelector, model: ModelSelector) -> RoutePlan {
    RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(pool_id(pool), upstream, model),
      OperationPolicy::TranslateCompatible,
      None,
      ManagedRetry::Never,
    ))
  }

  fn managed_with_policies(header_patches: Option<HeaderPatchSetId>, retry: ManagedRetry) -> RoutePlan {
    RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(
        pool_id("all"),
        UpstreamSelector::Fixed(upstream_id("upstream")),
        ModelSelector::Capability,
      ),
      OperationPolicy::Preserve,
      header_patches,
      retry,
    ))
  }

  fn relay_with_policies(header_patches: Option<HeaderPatchSetId>, retry: RelayRetry) -> RoutePlan {
    RoutePlan::Relay(RelayRoute::new(
      RelayTarget::FixedUpstream {
        upstream: upstream_id("upstream"),
        account_pool: pool_id("all"),
      },
      header_patches,
      retry,
    ))
  }

  fn plan(
    routes: BTreeMap<RouteId, RoutePlan>,
    pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
    groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(BTreeMap::new(), BTreeMap::new(), routes, pools, upstreams, groups)
  }

  fn inputs(plan: &GatewayPlan, accounts: &[AccountConfig]) -> Inputs {
    let registry = Registry::builtin();
    let providers = link_provider_graph(plan, accounts, &registry).unwrap();
    let pools = link_account_pools(plan, &providers, &registry).unwrap();
    let runtimes = build_account_pool_runtimes(&pools);
    Inputs { providers, runtimes }
  }

  fn reachable(ids: &[&str]) -> BTreeSet<RouteId> {
    ids.iter().map(|id| route_id(id)).collect()
  }

  fn link_single_route(id: &str, route_plan: RoutePlan) -> RouteLinkResult<LinkedRoutes> {
    let route = route_id(id);
    let gateway = plan(
      BTreeMap::from([(route.clone(), route_plan)]),
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream(Some("https://upstream.example/v1/"), None, &[]),
      )]),
      BTreeMap::new(),
    );
    let inputs = inputs(&gateway, &[account("account", AccountTier::Active)]);
    link_routes(&gateway, &BTreeSet::from([route]), &inputs.providers, &inputs.runtimes)
  }

  fn linked_managed(route: &LinkedRoute) -> &LinkedManagedRoute {
    match route.kind() {
      LinkedRouteKind::Managed(route) => route,
      other => panic!("expected managed route, got {other:?}"),
    }
  }

  fn linked_relay(route: &LinkedRoute) -> &LinkedRelayRoute {
    match route.kind() {
      LinkedRouteKind::Relay(route) => route,
      other => panic!("expected relay route, got {other:?}"),
    }
  }

  #[test]
  fn links_only_reachable_routes_and_reports_unknown_reachable_ids() {
    let gateway = plan(
      BTreeMap::from([
        (route_id("transparent"), RoutePlan::Transparent(Default::default())),
        (
          route_id("patched-unreachable"),
          RoutePlan::Transparent(TransparentRoute::new(Some(patch_id("unused-patch")))),
        ),
        (
          route_id("broken-unreachable"),
          managed(
            "missing-pool",
            UpstreamSelector::Fixed(upstream_id("missing-upstream")),
            ModelSelector::Capability,
          ),
        ),
      ]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let inputs = inputs(&gateway, &[]);

    let linked = link_routes(
      &gateway,
      &reachable(&["transparent"]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();

    assert_eq!(linked.len(), 1);
    assert_eq!(
      linked.route(&route_id("transparent")).unwrap().route_kind(),
      RouteKind::Transparent
    );
    assert!(linked.route(&route_id("broken-unreachable")).is_none());
    assert!(linked.route(&route_id("patched-unreachable")).is_none());

    let error = link_routes(
      &gateway,
      &reachable(&["not-defined"]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap_err();
    assert!(matches!(error, RouteLinkError::UnknownRoute { route } if route.as_str() == "not-defined"));
  }

  #[test]
  fn rejects_managed_header_patch_set() {
    let header_patch_set = patch_id("managed-patch");
    let error = link_single_route(
      "managed",
      managed_with_policies(Some(header_patch_set.clone()), ManagedRetry::Never),
    )
    .unwrap_err();

    assert!(matches!(
      error,
      RouteLinkError::UnsupportedHeaderPatchSet {
        route,
        header_patch_set: found,
      } if route.as_str() == "managed" && found == header_patch_set
    ));
  }

  #[test]
  fn rejects_relay_header_patch_set() {
    let header_patch_set = patch_id("relay-patch");
    let error = link_single_route(
      "relay",
      relay_with_policies(Some(header_patch_set.clone()), RelayRetry::Never),
    )
    .unwrap_err();

    assert!(matches!(
      error,
      RouteLinkError::UnsupportedHeaderPatchSet {
        route,
        header_patch_set: found,
      } if route.as_str() == "relay" && found == header_patch_set
    ));
  }

  #[test]
  fn rejects_transparent_header_patch_set() {
    let header_patch_set = patch_id("transparent-patch");
    let error = link_single_route(
      "transparent",
      RoutePlan::Transparent(TransparentRoute::new(Some(header_patch_set.clone()))),
    )
    .unwrap_err();

    assert!(matches!(
      error,
      RouteLinkError::UnsupportedHeaderPatchSet {
        route,
        header_patch_set: found,
      } if route.as_str() == "transparent" && found == header_patch_set
    ));
  }

  #[test]
  fn rejects_managed_retry_policy() {
    let retry_policy = retry_id("managed-retry");
    let error = link_single_route(
      "managed",
      managed_with_policies(None, ManagedRetry::Recoverable(retry_policy.clone())),
    )
    .unwrap_err();

    assert!(matches!(
      error,
      RouteLinkError::UnsupportedManagedRetry {
        route,
        retry_policy: found,
      } if route.as_str() == "managed" && found == retry_policy
    ));
  }

  #[test]
  fn rejects_every_nontrivial_relay_retry_policy() {
    for (route, retry, retry_policy) in [
      {
        let retry_policy = retry_id("safe-methods");
        (
          "relay-safe-methods",
          RelayRetry::SafeMethods(retry_policy.clone()),
          retry_policy,
        )
      },
      {
        let retry_policy = retry_id("buffered");
        (
          "relay-buffered",
          RelayRetry::Buffered(retry_policy.clone()),
          retry_policy,
        )
      },
    ] {
      let error = link_single_route(route, relay_with_policies(None, retry)).unwrap_err();

      assert!(matches!(
        error,
        RouteLinkError::UnsupportedRelayRetry {
          route: found_route,
          retry_policy: found_policy,
        } if found_route.as_str() == route && found_policy == retry_policy
      ));
    }
  }

  #[test]
  fn target_link_errors_include_the_reachable_route_id() {
    let fixed_id = route_id("fixed-dead");
    let any_id = route_id("any-empty");
    let dead = upstream_id("dead");
    let gateway = plan(
      BTreeMap::from([
        (
          fixed_id.clone(),
          managed(
            "empty",
            UpstreamSelector::Fixed(dead.clone()),
            ModelSelector::Capability,
          ),
        ),
        (
          any_id.clone(),
          managed("empty", UpstreamSelector::Any, ModelSelector::Capability),
        ),
      ]),
      BTreeMap::from([(pool_id("empty"), account_pool(None))]),
      BTreeMap::from([(dead.clone(), upstream(Some("https://dead.example/v1/"), None, &[]))]),
      BTreeMap::new(),
    );
    let inputs = inputs(&gateway, &[]);

    let fixed_error = link_routes(
      &gateway,
      &BTreeSet::from([fixed_id]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap_err();
    assert!(matches!(
      fixed_error,
      RouteLinkError::Target {
        route,
        source: TargetLinkError::FixedUpstreamUnavailable { pool, upstream },
      }
        if route.as_str() == "fixed-dead" && pool.as_str() == "empty" && upstream == dead
    ));

    let any_error = link_routes(&gateway, &BTreeSet::from([any_id]), &inputs.providers, &inputs.runtimes).unwrap_err();
    assert!(matches!(
      any_error,
      RouteLinkError::Target {
        route,
        source: TargetLinkError::NoUsableUpstream { pool },
      }
        if route.as_str() == "any-empty" && pool.as_str() == "empty"
    ));
  }

  #[test]
  fn transparent_routes_need_no_accounts_or_provider_targets() {
    let route = route_id("transparent");
    let gateway = plan(
      BTreeMap::from([(route.clone(), RoutePlan::Transparent(Default::default()))]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let inputs = inputs(&gateway, &[]);

    let linked = link_routes(
      &gateway,
      &BTreeSet::from([route.clone()]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();

    assert!(matches!(
      linked.route(&route).unwrap().kind(),
      LinkedRouteKind::Transparent(_)
    ));
    assert_eq!(
      linked.route(&route).unwrap().destination_policy(),
      DestinationPolicy::Original
    );
    assert!(linked.route(&route).unwrap().possible_provider_ids().is_empty());
  }

  #[test]
  fn links_supported_managed_and_relay_execution_axes() {
    let managed_id = route_id("managed");
    let relay_id = route_id("relay");
    let upstream_key = upstream_id("upstream");
    let managed_plan = RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(
        pool_id("all"),
        UpstreamSelector::Fixed(upstream_key.clone()),
        ModelSelector::Capability,
      ),
      OperationPolicy::Preserve,
      None,
      ManagedRetry::Never,
    ));
    let relay_plan = RoutePlan::Relay(RelayRoute::new(
      RelayTarget::FixedUpstream {
        upstream: upstream_key.clone(),
        account_pool: pool_id("all"),
      },
      None,
      RelayRetry::Never,
    ));
    let gateway = plan(
      BTreeMap::from([(managed_id.clone(), managed_plan), (relay_id.clone(), relay_plan)]),
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(upstream_key, upstream(Some("https://upstream.example/v1/"), None, &[]))]),
      BTreeMap::new(),
    );
    let inputs = inputs(&gateway, &[account("account", AccountTier::Active)]);

    let linked = link_routes(
      &gateway,
      &BTreeSet::from([managed_id.clone(), relay_id.clone()]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();
    let managed = linked_managed(linked.route(&managed_id).unwrap());
    let relay = linked_relay(linked.route(&relay_id).unwrap());

    assert_eq!(
      linked.route(&managed_id).unwrap().destination_policy(),
      DestinationPolicy::SelectedUpstream
    );
    assert_eq!(
      linked.route(&relay_id).unwrap().destination_policy(),
      DestinationPolicy::SelectedUpstream
    );
    assert_eq!(
      linked
        .route(&managed_id)
        .unwrap()
        .possible_provider_ids()
        .iter()
        .map(ProviderId::as_str)
        .collect::<Vec<_>>(),
      [ID_LLAMA_CPP]
    );
    assert_eq!(
      linked
        .route(&relay_id)
        .unwrap()
        .possible_provider_ids()
        .iter()
        .map(ProviderId::as_str)
        .collect::<Vec<_>>(),
      [ID_LLAMA_CPP]
    );
    assert_eq!(managed.operation(), OperationPolicy::Preserve);
    assert!(!relay.target().preserves_original_destination());
  }
}

//! Runtime-linked route targets over configured upstreams and account pools.
//!
//! Listener/profile reachability belongs to the router. This module accepts
//! the resulting route-id set and materializes only those routes, keeping
//! account selection, upstream identity, and model fallback data typed and
//! immutable. Per-pool cursors, cooldowns, and affinity remain shared through
//! [`AccountPoolRuntime`].

use super::{AccountPoolRuntime, AccountPoolRuntimes, ProviderGraph};
use smol_str::SmolStr;
use snafu::Snafu;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::sync::Arc;
use tokn_core::provider::ProviderTarget;
use tokn_core::upstream_url::{CanonicalHttpOrigin, CleartextHttpPolicy, InvalidUpstreamUrl};
use tokn_policy::{
  AccountPoolId, DestinationPolicy, FallbackSelector, GatewayPlan, HeaderPatchSetId, ManagedRetry, ManagedRoute,
  ModelGroupId, ModelSelector, OperationPolicy, ProviderId, QualificationNamespace, RelayRetry, RelayRoute,
  RelayTarget, RouteId, RouteKind, RoutePlan, UpstreamId, UpstreamSelector,
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

  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    match &self.kind {
      LinkedRouteKind::Managed(route) => route.header_patches(),
      LinkedRouteKind::Relay(route) => route.header_patches(),
      LinkedRouteKind::Transparent(route) => route.header_patches(),
    }
  }

  /// Whether request execution selects an upstream or preserves the ingress
  /// destination. This is derived from the linked route so startup consumers
  /// do not need to retain the policy graph.
  pub fn destination_policy(&self) -> DestinationPolicy {
    match &self.kind {
      LinkedRouteKind::Managed(_)
      | LinkedRouteKind::Relay(LinkedRelayRoute {
        target: LinkedRelayTarget::Fixed { .. },
        ..
      }) => DestinationPolicy::SelectedUpstream,
      LinkedRouteKind::Relay(LinkedRelayRoute {
        target: LinkedRelayTarget::FromOrigin { .. },
        ..
      })
      | LinkedRouteKind::Transparent(_) => DestinationPolicy::Original,
    }
  }

  /// Provider ids that this linked route can select at request time.
  ///
  /// Results are sorted and deduplicated. Managed fallback routes are narrowed
  /// to surviving linked candidates rather than the wider base upstream
  /// domain, which keeps startup identity requirements exact.
  pub fn possible_provider_ids(&self) -> Box<[ProviderId]> {
    let mut providers = BTreeSet::new();
    match &self.kind {
      LinkedRouteKind::Managed(route) => match route.model() {
        LinkedModelSelector::Capability | LinkedModelSelector::Qualified { .. } => {
          providers.extend(
            route
              .upstreams()
              .upstreams()
              .iter()
              .map(|upstream| upstream.provider_id().clone()),
          );
        }
        LinkedModelSelector::Fallback(fallback) => {
          for upstream_id in fallback
            .groups()
            .iter()
            .flat_map(LinkedModelGroup::candidates)
            .flat_map(|candidate| candidate.upstream_ids())
          {
            let upstream = route
              .upstreams()
              .upstream(upstream_id)
              .expect("linked fallback candidate upstream must belong to the managed route domain");
            providers.insert(upstream.provider_id().clone());
          }
        }
      },
      LinkedRouteKind::Relay(route) => {
        providers.extend(
          route
            .target()
            .upstreams()
            .iter()
            .map(|upstream| upstream.provider_id().clone()),
        );
      }
      LinkedRouteKind::Transparent(_) => {}
    }
    providers.into_iter().collect()
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

/// A configured upstream with its resolved target and provider identity.
#[derive(Clone, Debug)]
pub struct LinkedUpstream {
  id: UpstreamId,
  provider_id: ProviderId,
  target: ProviderTarget,
}

impl LinkedUpstream {
  pub fn id(&self) -> &UpstreamId {
    &self.id
  }

  pub fn provider_id(&self) -> &ProviderId {
    &self.provider_id
  }

  pub fn target(&self) -> &ProviderTarget {
    &self.target
  }
}

/// Materialized upstream selector for a managed route.
#[derive(Clone, Debug)]
pub enum LinkedUpstreamDomain {
  Fixed(LinkedUpstream),
  Any(Box<[LinkedUpstream]>),
}

impl LinkedUpstreamDomain {
  pub fn upstreams(&self) -> &[LinkedUpstream] {
    match self {
      Self::Fixed(upstream) => std::slice::from_ref(upstream),
      Self::Any(upstreams) => upstreams,
    }
  }

  pub fn upstream(&self, upstream_id: &UpstreamId) -> Option<&LinkedUpstream> {
    self
      .upstreams()
      .binary_search_by(|upstream| upstream.id().cmp(upstream_id))
      .ok()
      .map(|index| &self.upstreams()[index])
  }

  pub fn contains(&self, upstream_id: &UpstreamId) -> bool {
    self.upstream(upstream_id).is_some()
  }

  pub fn len(&self) -> usize {
    self.upstreams().len()
  }

  pub fn is_empty(&self) -> bool {
    self.upstreams().is_empty()
  }
}

/// Runtime-linked managed route.
#[derive(Clone, Debug)]
pub struct LinkedManagedRoute {
  pool: Arc<AccountPoolRuntime>,
  upstreams: LinkedUpstreamDomain,
  model: LinkedModelSelector,
  operation: OperationPolicy,
  header_patches: Option<HeaderPatchSetId>,
  retry: ManagedRetry,
}

impl LinkedManagedRoute {
  pub fn pool(&self) -> &Arc<AccountPoolRuntime> {
    &self.pool
  }

  pub fn upstreams(&self) -> &LinkedUpstreamDomain {
    &self.upstreams
  }

  pub fn model(&self) -> &LinkedModelSelector {
    &self.model
  }

  pub fn operation(&self) -> OperationPolicy {
    self.operation
  }

  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    self.header_patches.as_ref()
  }

  pub fn retry(&self) -> &ManagedRetry {
    &self.retry
  }
}

/// Request-time model interpretation with all static references resolved.
#[derive(Clone, Debug)]
pub enum LinkedModelSelector {
  Capability,
  Qualified { namespace: QualificationNamespace },
  Fallback(LinkedFallbackSelector),
}

/// Runtime-linked model-group choice.
#[derive(Clone, Debug)]
pub enum LinkedFallbackSelector {
  Fixed(LinkedModelGroup),
  ByRequested(Box<[LinkedModelGroup]>),
}

impl LinkedFallbackSelector {
  /// Resolve the group selected for a request without introducing fuzzy or
  /// substring matching. The first configured `ByRequested` group wins.
  pub fn group_for_requested(&self, requested_model: &str) -> Option<&LinkedModelGroup> {
    match self {
      Self::Fixed(group) => Some(group),
      Self::ByRequested(groups) => groups.iter().find(|group| group.matches_requested(requested_model)),
    }
  }

  pub fn groups(&self) -> &[LinkedModelGroup] {
    match self {
      Self::Fixed(group) => std::slice::from_ref(group),
      Self::ByRequested(groups) => groups,
    }
  }
}

/// One route-local model group. `request_models` retains every configured
/// member name, including members whose unusable candidate was pruned, so a
/// request for that member can still enter the group and use later fallbacks.
#[derive(Clone, Debug)]
pub struct LinkedModelGroup {
  id: ModelGroupId,
  request_models: BTreeSet<SmolStr>,
  candidates: Box<[LinkedModelCandidate]>,
}

impl LinkedModelGroup {
  pub fn id(&self) -> &ModelGroupId {
    &self.id
  }

  pub fn request_models(&self) -> &BTreeSet<SmolStr> {
    &self.request_models
  }

  pub fn candidates(&self) -> &[LinkedModelCandidate] {
    &self.candidates
  }

  pub fn matches_requested(&self, requested_model: &str) -> bool {
    self.id.as_str() == requested_model || self.request_models.contains(requested_model)
  }
}

/// One materializable fallback attempt and its effective upstream domain.
#[derive(Clone, Debug)]
pub struct LinkedModelCandidate {
  model: SmolStr,
  upstream_ids: Box<[UpstreamId]>,
}

impl LinkedModelCandidate {
  pub fn model(&self) -> &str {
    self.model.as_str()
  }

  pub fn upstream_ids(&self) -> &[UpstreamId] {
    &self.upstream_ids
  }

  pub fn permits_upstream(&self, upstream_id: &UpstreamId) -> bool {
    self.upstream_ids.binary_search(upstream_id).is_ok()
  }
}

/// Runtime-linked opaque relay route.
#[derive(Clone, Debug)]
pub struct LinkedRelayRoute {
  target: LinkedRelayTarget,
  header_patches: Option<HeaderPatchSetId>,
  retry: RelayRetry,
}

impl LinkedRelayRoute {
  pub fn target(&self) -> &LinkedRelayTarget {
    &self.target
  }

  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    self.header_patches.as_ref()
  }

  pub fn retry(&self) -> &RelayRetry {
    &self.retry
  }
}

/// Resolved relay destination selection.
#[derive(Clone, Debug)]
pub enum LinkedRelayTarget {
  Fixed {
    pool: Arc<AccountPoolRuntime>,
    upstream: LinkedUpstream,
  },
  FromOrigin {
    pool: Arc<AccountPoolRuntime>,
    upstreams: Box<[LinkedUpstream]>,
    origins: BTreeMap<CanonicalHttpOrigin, UpstreamId>,
  },
}

impl LinkedRelayTarget {
  pub fn pool(&self) -> &Arc<AccountPoolRuntime> {
    match self {
      Self::Fixed { pool, .. } | Self::FromOrigin { pool, .. } => pool,
    }
  }

  pub fn upstreams(&self) -> &[LinkedUpstream] {
    match self {
      Self::Fixed { upstream, .. } => std::slice::from_ref(upstream),
      Self::FromOrigin { upstreams, .. } => upstreams,
    }
  }

  pub fn origins(&self) -> Option<&BTreeMap<CanonicalHttpOrigin, UpstreamId>> {
    match self {
      Self::Fixed { .. } => None,
      Self::FromOrigin { origins, .. } => Some(origins),
    }
  }

  pub fn upstream_for_origin(&self, origin: &CanonicalHttpOrigin) -> Option<&LinkedUpstream> {
    let Self::FromOrigin { upstreams, origins, .. } = self else {
      return None;
    };
    let upstream_id = origins.get(origin)?;
    upstreams
      .binary_search_by(|upstream| upstream.id().cmp(upstream_id))
      .ok()
      .map(|index| &upstreams[index])
  }
}

/// Runtime-linked transparent route. It intentionally owns no account or
/// provider state.
#[derive(Clone, Debug)]
pub struct LinkedTransparentRoute {
  header_patches: Option<HeaderPatchSetId>,
}

impl LinkedTransparentRoute {
  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    self.header_patches.as_ref()
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum RouteLinkError {
  #[snafu(display("reachable route '{route}' does not exist in the gateway plan"))]
  UnknownRoute { route: RouteId },

  #[snafu(display("route '{route}' references account pool '{pool}' without a linked runtime"))]
  MissingPoolRuntime { route: RouteId, pool: AccountPoolId },

  #[snafu(display("route '{route}' references unknown upstream '{upstream}'"))]
  MissingUpstream { route: RouteId, upstream: UpstreamId },

  #[snafu(display("route '{route}' references upstream '{upstream}' without a linked provider target"))]
  MissingProviderTarget { route: RouteId, upstream: UpstreamId },

  #[snafu(display("route '{route}' has no configured upstream with a binding in account pool '{pool}'"))]
  NoUsableUpstream { route: RouteId, pool: AccountPoolId },

  #[snafu(display("route '{route}' fixes upstream '{upstream}', but account pool '{pool}' has no binding for it"))]
  FixedUpstreamUnavailable {
    route: RouteId,
    pool: AccountPoolId,
    upstream: UpstreamId,
  },

  #[snafu(display("route '{route}' references unknown model group '{group}'"))]
  MissingModelGroup { route: RouteId, group: ModelGroupId },

  #[snafu(display("route '{route}' model group '{group}' candidate {index} has invalid model '{model}'"))]
  InvalidModelCandidate {
    route: RouteId,
    group: ModelGroupId,
    index: usize,
    model: String,
  },

  #[snafu(display("route '{route}' references model group '{group}', but none of its candidates are materializable"))]
  NoMaterializableCandidates { route: RouteId, group: ModelGroupId },

  #[snafu(display("route '{route}' has a by-requested fallback selector without any model groups"))]
  EmptyFallbackSelector { route: RouteId },

  #[snafu(display("route '{route}' upstream '{upstream}' has invalid origin '{origin}': {source}"))]
  InvalidOrigin {
    route: RouteId,
    upstream: UpstreamId,
    origin: String,
    source: InvalidUpstreamUrl,
  },

  #[snafu(display(
    "route '{route}' maps canonical origin '{origin}' to both upstream '{first_upstream}' and upstream '{second_upstream}'"
  ))]
  AmbiguousOrigin {
    route: RouteId,
    origin: CanonicalHttpOrigin,
    first_upstream: UpstreamId,
    second_upstream: UpstreamId,
  },

  #[snafu(display("route '{route}' has no origin-bearing upstream with a binding in account pool '{pool}'"))]
  NoUsableOrigin { route: RouteId, pool: AccountPoolId },
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
    let kind = match route {
      RoutePlan::Managed(route) => {
        LinkedRouteKind::Managed(link_managed_route(route_id, route, plan, providers, pools)?)
      }
      RoutePlan::Relay(route) => LinkedRouteKind::Relay(link_relay_route(route_id, route, plan, providers, pools)?),
      RoutePlan::Transparent(route) => LinkedRouteKind::Transparent(LinkedTransparentRoute {
        header_patches: route.header_patches().cloned(),
      }),
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

fn link_managed_route(
  route_id: &RouteId,
  route: &ManagedRoute,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
) -> RouteLinkResult<LinkedManagedRoute> {
  let target = route.target();
  let pool = require_pool(route_id, target.account_pool(), pools)?;
  let upstreams = link_upstream_domain(route_id, target.upstream(), &pool, plan, providers)?;
  let model = link_model_selector(route_id, target.model(), &upstreams, plan)?;
  Ok(LinkedManagedRoute {
    pool,
    upstreams,
    model,
    operation: route.operation(),
    header_patches: route.header_patches().cloned(),
    retry: route.retry().clone(),
  })
}

fn link_relay_route(
  route_id: &RouteId,
  route: &RelayRoute,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
) -> RouteLinkResult<LinkedRelayRoute> {
  let target = match route.target() {
    RelayTarget::FixedUpstream { upstream, account_pool } => {
      let pool = require_pool(route_id, account_pool, pools)?;
      let linked_upstream = link_upstream(route_id, upstream, plan, providers)?;
      if !pool_has_upstream(&pool, upstream) {
        return Err(RouteLinkError::FixedUpstreamUnavailable {
          route: route_id.clone(),
          pool: account_pool.clone(),
          upstream: upstream.clone(),
        });
      }
      LinkedRelayTarget::Fixed {
        pool,
        upstream: linked_upstream,
      }
    }
    RelayTarget::UpstreamFromOrigin { account_pool } => {
      let pool = require_pool(route_id, account_pool, pools)?;
      link_origin_relay_target(route_id, pool, plan, providers)?
    }
  };
  Ok(LinkedRelayRoute {
    target,
    header_patches: route.header_patches().cloned(),
    retry: route.retry().clone(),
  })
}

fn require_pool(
  route_id: &RouteId,
  pool_id: &AccountPoolId,
  pools: &AccountPoolRuntimes,
) -> RouteLinkResult<Arc<AccountPoolRuntime>> {
  pools
    .runtime(pool_id)
    .cloned()
    .ok_or_else(|| RouteLinkError::MissingPoolRuntime {
      route: route_id.clone(),
      pool: pool_id.clone(),
    })
}

fn link_upstream_domain(
  route_id: &RouteId,
  selector: &UpstreamSelector,
  pool: &AccountPoolRuntime,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
) -> RouteLinkResult<LinkedUpstreamDomain> {
  match selector {
    UpstreamSelector::Fixed(upstream_id) => {
      let upstream = link_upstream(route_id, upstream_id, plan, providers)?;
      if !pool_has_upstream(pool, upstream_id) {
        return Err(RouteLinkError::FixedUpstreamUnavailable {
          route: route_id.clone(),
          pool: pool.pool().id().clone(),
          upstream: upstream_id.clone(),
        });
      }
      Ok(LinkedUpstreamDomain::Fixed(upstream))
    }
    UpstreamSelector::Any => {
      let mut upstreams = Vec::new();
      for upstream_id in plan.upstreams().keys() {
        if pool_has_upstream(pool, upstream_id) {
          upstreams.push(link_upstream(route_id, upstream_id, plan, providers)?);
        }
      }
      if upstreams.is_empty() {
        return Err(RouteLinkError::NoUsableUpstream {
          route: route_id.clone(),
          pool: pool.pool().id().clone(),
        });
      }
      Ok(LinkedUpstreamDomain::Any(upstreams.into_boxed_slice()))
    }
  }
}

fn link_upstream(
  route_id: &RouteId,
  upstream_id: &UpstreamId,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
) -> RouteLinkResult<LinkedUpstream> {
  let upstream = plan
    .upstream(upstream_id)
    .ok_or_else(|| RouteLinkError::MissingUpstream {
      route: route_id.clone(),
      upstream: upstream_id.clone(),
    })?;
  let target = providers
    .target(upstream_id)
    .cloned()
    .ok_or_else(|| RouteLinkError::MissingProviderTarget {
      route: route_id.clone(),
      upstream: upstream_id.clone(),
    })?;
  Ok(LinkedUpstream {
    id: upstream_id.clone(),
    provider_id: upstream.provider().clone(),
    target,
  })
}

fn pool_has_upstream(pool: &AccountPoolRuntime, upstream_id: &UpstreamId) -> bool {
  pool
    .pool()
    .active()
    .iter()
    .chain(pool.pool().fallback())
    .any(|account| account.binding(upstream_id).is_some())
}

fn link_model_selector(
  route_id: &RouteId,
  selector: &ModelSelector,
  upstreams: &LinkedUpstreamDomain,
  plan: &GatewayPlan,
) -> RouteLinkResult<LinkedModelSelector> {
  match selector {
    ModelSelector::Capability => Ok(LinkedModelSelector::Capability),
    ModelSelector::Qualified { namespace } => Ok(LinkedModelSelector::Qualified { namespace: *namespace }),
    ModelSelector::Fallback(fallback) => {
      let linked = match fallback {
        FallbackSelector::Fixed(group_id) => {
          LinkedFallbackSelector::Fixed(link_model_group(route_id, group_id, upstreams, plan)?)
        }
        FallbackSelector::ByRequested(group_ids) => {
          if group_ids.is_empty() {
            return Err(RouteLinkError::EmptyFallbackSelector {
              route: route_id.clone(),
            });
          }
          let groups = group_ids
            .iter()
            .map(|group_id| link_model_group(route_id, group_id, upstreams, plan))
            .collect::<RouteLinkResult<Vec<_>>>()?;
          LinkedFallbackSelector::ByRequested(groups.into_boxed_slice())
        }
      };
      Ok(LinkedModelSelector::Fallback(linked))
    }
  }
}

fn link_model_group(
  route_id: &RouteId,
  group_id: &ModelGroupId,
  upstreams: &LinkedUpstreamDomain,
  plan: &GatewayPlan,
) -> RouteLinkResult<LinkedModelGroup> {
  let group = plan
    .model_group(group_id)
    .ok_or_else(|| RouteLinkError::MissingModelGroup {
      route: route_id.clone(),
      group: group_id.clone(),
    })?;
  let mut request_models = BTreeSet::new();
  let mut candidates = Vec::new();
  for (index, candidate) in group.candidates().iter().enumerate() {
    let model = candidate.model();
    if model.is_empty() || model.trim() != model {
      return Err(RouteLinkError::InvalidModelCandidate {
        route: route_id.clone(),
        group: group_id.clone(),
        index,
        model: model.to_string(),
      });
    }
    request_models.insert(SmolStr::new(model));
    let upstream_ids = match candidate.upstream() {
      Some(upstream_id) => {
        if plan.upstream(upstream_id).is_none() {
          return Err(RouteLinkError::MissingUpstream {
            route: route_id.clone(),
            upstream: upstream_id.clone(),
          });
        }
        if !upstreams.contains(upstream_id) {
          continue;
        }
        vec![upstream_id.clone()]
      }
      None => upstreams
        .upstreams()
        .iter()
        .map(|upstream| upstream.id().clone())
        .collect(),
    };
    if !upstream_ids.is_empty() {
      candidates.push(LinkedModelCandidate {
        model: SmolStr::new(model),
        upstream_ids: upstream_ids.into_boxed_slice(),
      });
    }
  }
  if candidates.is_empty() {
    return Err(RouteLinkError::NoMaterializableCandidates {
      route: route_id.clone(),
      group: group_id.clone(),
    });
  }
  Ok(LinkedModelGroup {
    id: group_id.clone(),
    request_models,
    candidates: candidates.into_boxed_slice(),
  })
}

fn link_origin_relay_target(
  route_id: &RouteId,
  pool: Arc<AccountPoolRuntime>,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
) -> RouteLinkResult<LinkedRelayTarget> {
  let mut upstreams = Vec::new();
  let mut origins = BTreeMap::new();
  for (upstream_id, upstream_plan) in plan.upstreams() {
    if !pool_has_upstream(&pool, upstream_id) {
      continue;
    }
    let upstream = link_upstream(route_id, upstream_id, plan, providers)?;
    let cleartext = if upstream_plan.allow_insecure_http() {
      CleartextHttpPolicy::Allow
    } else {
      CleartextHttpPolicy::LoopbackOnly
    };
    let mut claimed = BTreeSet::new();
    claimed.insert(upstream.target().base_url().origin());
    for configured in upstream_plan.origins() {
      let origin =
        CanonicalHttpOrigin::parse(configured.as_str(), cleartext).map_err(|source| RouteLinkError::InvalidOrigin {
          route: route_id.clone(),
          upstream: upstream_id.clone(),
          origin: configured.to_string(),
          source,
        })?;
      claimed.insert(origin);
    }
    for origin in claimed {
      match origins.entry(origin.clone()) {
        Entry::Vacant(entry) => {
          entry.insert(upstream_id.clone());
        }
        Entry::Occupied(entry) if entry.get() == upstream_id => {}
        Entry::Occupied(entry) => {
          return Err(RouteLinkError::AmbiguousOrigin {
            route: route_id.clone(),
            origin,
            first_upstream: entry.get().clone(),
            second_upstream: upstream_id.clone(),
          });
        }
      }
    }
    upstreams.push(upstream);
  }
  if origins.is_empty() {
    return Err(RouteLinkError::NoUsableOrigin {
      route: route_id.clone(),
      pool: pool.pool().id().clone(),
    });
  }
  Ok(LinkedRelayTarget::FromOrigin {
    pool,
    upstreams: upstreams.into_boxed_slice(),
    origins,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph};
  use crate::registry::Registry;
  use std::time::Duration;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_policy::{
    AccountPoolPlan, AccountSelectionStrategy, AccountSelector, ManagedTarget, ModelCandidate, ModelGroupPlan,
    RelayRetry, RetryPolicyId, UpstreamOrigin, UpstreamPlan,
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

  fn group_id(value: &str) -> ModelGroupId {
    ModelGroupId::new(value).unwrap()
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

  fn fixed_relay(pool: &str, upstream: &str) -> RoutePlan {
    RoutePlan::Relay(RelayRoute::new(
      RelayTarget::FixedUpstream {
        upstream: upstream_id(upstream),
        account_pool: pool_id(pool),
      },
      None,
      RelayRetry::Never,
    ))
  }

  fn origin_relay(pool: &str) -> RoutePlan {
    RoutePlan::Relay(RelayRoute::new(
      RelayTarget::UpstreamFromOrigin {
        account_pool: pool_id(pool),
      },
      None,
      RelayRetry::Never,
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
  fn fixed_and_any_domains_use_pool_bindings_and_share_one_runtime() {
    let fixed_id = route_id("fixed");
    let any_id = route_id("any");
    let a = upstream_id("a-live");
    let z = upstream_id("z-live");
    let dead = upstream_id("m-dead");
    let gateway = plan(
      BTreeMap::from([
        (
          fixed_id.clone(),
          managed(
            "selected",
            UpstreamSelector::Fixed(z.clone()),
            ModelSelector::Capability,
          ),
        ),
        (
          any_id.clone(),
          managed("selected", UpstreamSelector::Any, ModelSelector::Capability),
        ),
      ]),
      BTreeMap::from([(pool_id("selected"), account_pool(Some(&["selected"])))]),
      BTreeMap::from([
        (
          a.clone(),
          upstream(Some("https://a.example/v1/"), Some(&["selected"]), &[]),
        ),
        (
          dead,
          upstream(Some("https://dead.example/v1/"), Some(&["excluded"]), &[]),
        ),
        (
          z.clone(),
          upstream(Some("https://z.example/v1/"), Some(&["selected"]), &[]),
        ),
      ]),
      BTreeMap::new(),
    );
    let inputs = inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );

    let linked = link_routes(
      &gateway,
      &BTreeSet::from([fixed_id.clone(), any_id.clone()]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();
    let fixed = linked_managed(linked.route(&fixed_id).unwrap());
    let any = linked_managed(linked.route(&any_id).unwrap());

    assert_eq!(
      fixed
        .upstreams()
        .upstreams()
        .iter()
        .map(|upstream| upstream.id().as_str())
        .collect::<Vec<_>>(),
      ["z-live"]
    );
    assert_eq!(
      any
        .upstreams()
        .upstreams()
        .iter()
        .map(|upstream| upstream.id().as_str())
        .collect::<Vec<_>>(),
      ["a-live", "z-live"]
    );
    assert!(Arc::ptr_eq(fixed.pool(), any.pool()));
    assert!(Arc::ptr_eq(
      any.pool(),
      inputs.runtimes.runtime(&pool_id("selected")).unwrap()
    ));
    for upstream in any.upstreams().upstreams() {
      assert!(Arc::ptr_eq(
        upstream.target().model_cache(),
        inputs.providers.target(upstream.id()).unwrap().model_cache()
      ));
    }
  }

  #[test]
  fn unusable_fixed_and_any_domains_fail_with_route_context() {
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
      RouteLinkError::FixedUpstreamUnavailable { route, pool, upstream }
        if route.as_str() == "fixed-dead" && pool.as_str() == "empty" && upstream == dead
    ));

    let any_error = link_routes(&gateway, &BTreeSet::from([any_id]), &inputs.providers, &inputs.runtimes).unwrap_err();
    assert!(matches!(
      any_error,
      RouteLinkError::NoUsableUpstream { route, pool }
        if route.as_str() == "any-empty" && pool.as_str() == "empty"
    ));
  }

  #[test]
  fn fallback_prunes_dead_candidates_but_preserves_order_and_request_names() {
    let route = route_id("fallback");
    let live = upstream_id("live");
    let dead = upstream_id("dead");
    let group = group_id("coding");
    let gateway = plan(
      BTreeMap::from([(
        route.clone(),
        managed(
          "selected",
          UpstreamSelector::Any,
          ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
        ),
      )]),
      BTreeMap::from([(pool_id("selected"), account_pool(Some(&["selected"])))]),
      BTreeMap::from([
        (
          dead.clone(),
          upstream(Some("https://dead.example/v1/"), Some(&["excluded"]), &[]),
        ),
        (
          live.clone(),
          upstream(Some("https://live.example/v1/"), Some(&["selected"]), &[]),
        ),
      ]),
      BTreeMap::from([(
        group.clone(),
        ModelGroupPlan::new(
          vec![
            ModelCandidate::new(Some(dead), "dead-model"),
            ModelCandidate::new(None, "first-live"),
            ModelCandidate::new(Some(live.clone()), "second-live"),
          ]
          .into_boxed_slice(),
        ),
      )]),
    );
    let inputs = inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );

    let linked = link_routes(
      &gateway,
      &BTreeSet::from([route.clone()]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();
    let LinkedModelSelector::Fallback(LinkedFallbackSelector::Fixed(group)) =
      linked_managed(linked.route(&route).unwrap()).model()
    else {
      panic!("expected fixed fallback group");
    };

    assert_eq!(
      group
        .candidates()
        .iter()
        .map(LinkedModelCandidate::model)
        .collect::<Vec<_>>(),
      ["first-live", "second-live"]
    );
    assert!(group.matches_requested("dead-model"));
    assert_eq!(group.candidates()[0].upstream_ids(), std::slice::from_ref(&live));
    assert_eq!(group.candidates()[1].upstream_ids(), &[live]);
  }

  #[test]
  fn fallback_fails_only_when_a_referenced_group_has_no_live_candidate() {
    let route = route_id("fallback-empty");
    let dead = upstream_id("dead");
    let group = group_id("dead-group");
    let gateway = plan(
      BTreeMap::from([(
        route.clone(),
        managed(
          "selected",
          UpstreamSelector::Any,
          ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
        ),
      )]),
      BTreeMap::from([(pool_id("selected"), account_pool(Some(&["selected"])))]),
      BTreeMap::from([
        (
          dead.clone(),
          upstream(Some("https://dead.example/v1/"), Some(&["excluded"]), &[]),
        ),
        (
          upstream_id("live"),
          upstream(Some("https://live.example/v1/"), Some(&["selected"]), &[]),
        ),
      ]),
      BTreeMap::from([(
        group.clone(),
        ModelGroupPlan::new(vec![ModelCandidate::new(Some(dead), "dead-model")].into_boxed_slice()),
      )]),
    );
    let inputs = inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );

    let error = link_routes(&gateway, &BTreeSet::from([route]), &inputs.providers, &inputs.runtimes).unwrap_err();
    assert!(matches!(
      error,
      RouteLinkError::NoMaterializableCandidates { route, group: error_group }
        if route.as_str() == "fallback-empty" && error_group == group
    ));
  }

  #[test]
  fn origin_relay_unions_target_and_configured_origins_and_filters_by_pool() {
    let route = route_id("origin");
    let live = upstream_id("live");
    let excluded = upstream_id("excluded");
    let gateway = plan(
      BTreeMap::from([(route.clone(), origin_relay("selected"))]),
      BTreeMap::from([(pool_id("selected"), account_pool(Some(&["selected"])))]),
      BTreeMap::from([
        (
          excluded,
          upstream(
            Some("https://excluded.example/v1/"),
            Some(&["excluded"]),
            &["https://excluded-alias.example"],
          ),
        ),
        (
          live,
          upstream(
            Some("https://base.example/v1/"),
            Some(&["selected"]),
            &["https://base.example", "https://alias.example"],
          ),
        ),
      ]),
      BTreeMap::new(),
    );
    let inputs = inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );

    let linked = link_routes(
      &gateway,
      &BTreeSet::from([route.clone()]),
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();
    let target = linked_relay(linked.route(&route).unwrap()).target();
    let origins = target.origins().unwrap();
    let base = CanonicalHttpOrigin::parse("https://base.example", CleartextHttpPolicy::LoopbackOnly).unwrap();
    let alias = CanonicalHttpOrigin::parse("https://alias.example", CleartextHttpPolicy::LoopbackOnly).unwrap();

    assert_eq!(target.upstreams().len(), 1);
    assert_eq!(
      linked.route(&route).unwrap().destination_policy(),
      DestinationPolicy::Original
    );
    assert_eq!(origins.len(), 2);
    assert!(origins.contains_key(&base));
    assert!(origins.contains_key(&alias));
    assert!(target.upstream_for_origin(&alias).is_some());
  }

  #[test]
  fn origin_relay_rejects_runtime_default_ambiguity_and_empty_pools() {
    let ambiguous_route = route_id("ambiguous");
    let ambiguous = plan(
      BTreeMap::from([(ambiguous_route.clone(), origin_relay("all"))]),
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([
        (upstream_id("first"), upstream(None, None, &[])),
        (upstream_id("second"), upstream(None, None, &[])),
      ]),
      BTreeMap::new(),
    );
    let ambiguous_inputs = inputs(&ambiguous, &[account("account", AccountTier::Active)]);

    let ambiguity = link_routes(
      &ambiguous,
      &BTreeSet::from([ambiguous_route]),
      &ambiguous_inputs.providers,
      &ambiguous_inputs.runtimes,
    )
    .unwrap_err();
    assert!(matches!(
      ambiguity,
      RouteLinkError::AmbiguousOrigin {
        first_upstream,
        second_upstream,
        ..
      } if first_upstream.as_str() == "first" && second_upstream.as_str() == "second"
    ));

    let empty_route = route_id("empty");
    let empty = plan(
      BTreeMap::from([(empty_route.clone(), origin_relay("empty"))]),
      BTreeMap::from([(pool_id("empty"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream(Some("https://upstream.example/v1/"), None, &[]),
      )]),
      BTreeMap::new(),
    );
    let empty_inputs = inputs(&empty, &[]);
    let error = link_routes(
      &empty,
      &BTreeSet::from([empty_route]),
      &empty_inputs.providers,
      &empty_inputs.runtimes,
    )
    .unwrap_err();
    assert!(matches!(
      error,
      RouteLinkError::NoUsableOrigin { route, pool }
        if route.as_str() == "empty" && pool.as_str() == "empty"
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
  fn preserves_managed_and_relay_execution_axes() {
    let managed_id = route_id("managed");
    let relay_id = route_id("relay");
    let upstream_key = upstream_id("upstream");
    let managed_patch = patch_id("managed-patch");
    let managed_retry = retry_id("managed-retry");
    let relay_patch = patch_id("relay-patch");
    let relay_retry = retry_id("relay-retry");
    let managed_plan = RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(
        pool_id("all"),
        UpstreamSelector::Fixed(upstream_key.clone()),
        ModelSelector::Capability,
      ),
      OperationPolicy::Preserve,
      Some(managed_patch.clone()),
      ManagedRetry::Recoverable(managed_retry.clone()),
    ));
    let relay_plan = RoutePlan::Relay(RelayRoute::new(
      RelayTarget::FixedUpstream {
        upstream: upstream_key.clone(),
        account_pool: pool_id("all"),
      },
      Some(relay_patch.clone()),
      RelayRetry::Buffered(relay_retry.clone()),
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
    assert_eq!(managed.header_patches(), Some(&managed_patch));
    assert_eq!(managed.retry(), &ManagedRetry::Recoverable(managed_retry));
    assert_eq!(relay.header_patches(), Some(&relay_patch));
    assert_eq!(relay.retry(), &RelayRetry::Buffered(relay_retry));
  }

  #[test]
  fn malformed_gateway_references_fail_with_the_reachable_route() {
    let missing_pool_route = route_id("missing-pool");
    let missing_pool = plan(
      BTreeMap::from([(
        missing_pool_route.clone(),
        managed("absent", UpstreamSelector::Any, ModelSelector::Capability),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let missing_pool_inputs = inputs(&missing_pool, &[]);
    assert!(matches!(
      link_routes(
        &missing_pool,
        &BTreeSet::from([missing_pool_route]),
        &missing_pool_inputs.providers,
        &missing_pool_inputs.runtimes,
      ),
      Err(RouteLinkError::MissingPoolRuntime { pool, .. }) if pool.as_str() == "absent"
    ));

    let missing_upstream_route = route_id("missing-upstream");
    let missing_upstream = plan(
      BTreeMap::from([(missing_upstream_route.clone(), fixed_relay("empty", "absent"))]),
      BTreeMap::from([(pool_id("empty"), account_pool(None))]),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let missing_upstream_inputs = inputs(&missing_upstream, &[]);
    assert!(matches!(
      link_routes(
        &missing_upstream,
        &BTreeSet::from([missing_upstream_route]),
        &missing_upstream_inputs.providers,
        &missing_upstream_inputs.runtimes,
      ),
      Err(RouteLinkError::MissingUpstream { upstream, .. }) if upstream.as_str() == "absent"
    ));

    let missing_group_route = route_id("missing-group");
    let missing_group = plan(
      BTreeMap::from([(
        missing_group_route.clone(),
        managed(
          "all",
          UpstreamSelector::Any,
          ModelSelector::Fallback(FallbackSelector::Fixed(group_id("absent"))),
        ),
      )]),
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("live"),
        upstream(Some("https://live.example/v1/"), None, &[]),
      )]),
      BTreeMap::new(),
    );
    let missing_group_inputs = inputs(&missing_group, &[account("account", AccountTier::Active)]);
    assert!(matches!(
      link_routes(
        &missing_group,
        &BTreeSet::from([missing_group_route]),
        &missing_group_inputs.providers,
        &missing_group_inputs.runtimes,
      ),
      Err(RouteLinkError::MissingModelGroup { group, .. }) if group.as_str() == "absent"
    ));
  }

  #[test]
  fn unknown_candidate_upstreams_error_while_known_dead_candidates_prune() {
    let route = route_id("unknown-candidate");
    let group = group_id("group");
    let gateway = plan(
      BTreeMap::from([(
        route.clone(),
        managed(
          "all",
          UpstreamSelector::Any,
          ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
        ),
      )]),
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("live"),
        upstream(Some("https://live.example/v1/"), None, &[]),
      )]),
      BTreeMap::from([(
        group,
        ModelGroupPlan::new(
          vec![
            ModelCandidate::new(Some(upstream_id("absent")), "broken"),
            ModelCandidate::new(None, "live"),
          ]
          .into_boxed_slice(),
        ),
      )]),
    );
    let inputs = inputs(&gateway, &[account("account", AccountTier::Active)]);

    let error = link_routes(&gateway, &BTreeSet::from([route]), &inputs.providers, &inputs.runtimes).unwrap_err();
    assert!(matches!(
      error,
      RouteLinkError::MissingUpstream { upstream, .. } if upstream.as_str() == "absent"
    ));
  }

  #[test]
  fn malformed_model_candidates_and_empty_fallback_selectors_are_rejected() {
    let invalid_route = route_id("invalid-model");
    let invalid_group = group_id("invalid-group");
    let invalid = plan(
      BTreeMap::from([(
        invalid_route.clone(),
        managed(
          "all",
          UpstreamSelector::Any,
          ModelSelector::Fallback(FallbackSelector::Fixed(invalid_group.clone())),
        ),
      )]),
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("live"),
        upstream(Some("https://live.example/v1/"), None, &[]),
      )]),
      BTreeMap::from([(
        invalid_group.clone(),
        ModelGroupPlan::new(vec![ModelCandidate::new(None, " bad-model")].into_boxed_slice()),
      )]),
    );
    let invalid_inputs = inputs(&invalid, &[account("account", AccountTier::Active)]);
    let invalid_error = link_routes(
      &invalid,
      &BTreeSet::from([invalid_route]),
      &invalid_inputs.providers,
      &invalid_inputs.runtimes,
    )
    .unwrap_err();
    assert!(matches!(
      invalid_error,
      RouteLinkError::InvalidModelCandidate {
        group,
        index: 0,
        model,
        ..
      } if group == invalid_group && model == " bad-model"
    ));

    let empty_route = route_id("empty-selector");
    let empty = plan(
      BTreeMap::from([(
        empty_route.clone(),
        managed(
          "all",
          UpstreamSelector::Any,
          ModelSelector::Fallback(FallbackSelector::ByRequested(Box::default())),
        ),
      )]),
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("live"),
        upstream(Some("https://live.example/v1/"), None, &[]),
      )]),
      BTreeMap::new(),
    );
    let empty_inputs = inputs(&empty, &[account("account", AccountTier::Active)]);
    let empty_error = link_routes(
      &empty,
      &BTreeSet::from([empty_route]),
      &empty_inputs.providers,
      &empty_inputs.runtimes,
    )
    .unwrap_err();
    assert!(matches!(
      empty_error,
      RouteLinkError::EmptyFallbackSelector { route } if route.as_str() == "empty-selector"
    ));
  }
}

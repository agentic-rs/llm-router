//! Account-owned target domains linked from symbolic gateway policy.
//!
//! A linked target resolves the account pool, upstream domain, provider
//! targets, and managed model-selection data needed at request time. Route
//! identity and execution policy remain outside this module so the router can
//! own the outer linked route graph independently.

use super::{AccountPoolRuntime, AccountPoolRuntimes, ProviderGraph};
use smol_str::SmolStr;
use snafu::Snafu;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::sync::Arc;
use tokn_core::provider::ProviderTarget;
use tokn_core::upstream_url::{CanonicalHttpOrigin, CleartextHttpPolicy, InvalidUpstreamUrl};
use tokn_policy::{
  AccountPoolId, FallbackSelector, GatewayPlan, ManagedTarget, ModelGroupId, ModelSelector, ProviderId,
  QualificationNamespace, RelayTarget, UpstreamId, UpstreamSelector,
};

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

/// Materialized upstream selector for a managed target.
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

/// Linked account-selection domain for one managed target.
#[derive(Clone, Debug)]
pub struct LinkedManagedTarget {
  pool: Arc<AccountPoolRuntime>,
  upstreams: LinkedUpstreamDomain,
  model: LinkedModelSelector,
}

impl LinkedManagedTarget {
  pub fn pool(&self) -> &Arc<AccountPoolRuntime> {
    &self.pool
  }

  pub fn upstreams(&self) -> &LinkedUpstreamDomain {
    &self.upstreams
  }

  pub fn model(&self) -> &LinkedModelSelector {
    &self.model
  }

  /// Provider ids that this target can select at request time.
  ///
  /// Fallback targets are narrowed to surviving linked candidates rather than
  /// the wider base upstream domain.
  pub fn possible_provider_ids(&self) -> Box<[ProviderId]> {
    let mut providers = BTreeSet::new();
    match self.model() {
      LinkedModelSelector::Capability | LinkedModelSelector::Qualified { .. } => {
        providers.extend(
          self
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
          let upstream = self
            .upstreams()
            .upstream(upstream_id)
            .expect("linked fallback candidate upstream must belong to the managed target domain");
          providers.insert(upstream.provider_id().clone());
        }
      }
    }
    providers.into_iter().collect()
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

/// One target-local model group. `request_models` retains every configured
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

/// Linked account-selection domain for one opaque relay target.
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

  pub fn preserves_original_destination(&self) -> bool {
    matches!(self, Self::FromOrigin { .. })
  }

  pub fn possible_provider_ids(&self) -> Box<[ProviderId]> {
    self
      .upstreams()
      .iter()
      .map(|upstream| upstream.provider_id().clone())
      .collect::<BTreeSet<_>>()
      .into_iter()
      .collect()
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

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum TargetLinkError {
  #[snafu(display("account pool '{pool}' has no linked runtime"))]
  MissingPoolRuntime { pool: AccountPoolId },

  #[snafu(display("unknown upstream '{upstream}'"))]
  MissingUpstream { upstream: UpstreamId },

  #[snafu(display("upstream '{upstream}' has no linked provider target"))]
  MissingProviderTarget { upstream: UpstreamId },

  #[snafu(display("no configured upstream has a binding in account pool '{pool}'"))]
  NoUsableUpstream { pool: AccountPoolId },

  #[snafu(display("upstream '{upstream}' has no binding in account pool '{pool}'"))]
  FixedUpstreamUnavailable { pool: AccountPoolId, upstream: UpstreamId },

  #[snafu(display("unknown model group '{group}'"))]
  MissingModelGroup { group: ModelGroupId },

  #[snafu(display("model group '{group}' candidate {index} has invalid model '{model}'"))]
  InvalidModelCandidate {
    group: ModelGroupId,
    index: usize,
    model: String,
  },

  #[snafu(display("model group '{group}' has no materializable candidates"))]
  NoMaterializableCandidates { group: ModelGroupId },

  #[snafu(display("by-requested fallback selector has no model groups"))]
  EmptyFallbackSelector,

  #[snafu(display("upstream '{upstream}' has invalid origin '{origin}': {source}"))]
  InvalidOrigin {
    upstream: UpstreamId,
    origin: String,
    source: InvalidUpstreamUrl,
  },

  #[snafu(display(
    "canonical origin '{origin}' maps to both upstream '{first_upstream}' and upstream '{second_upstream}'"
  ))]
  AmbiguousOrigin {
    origin: CanonicalHttpOrigin,
    first_upstream: UpstreamId,
    second_upstream: UpstreamId,
  },

  #[snafu(display("account pool '{pool}' has no origin-bearing upstream"))]
  NoUsableOrigin { pool: AccountPoolId },
}

pub type TargetLinkResult<T> = std::result::Result<T, TargetLinkError>;

/// Link one managed target independently of its outer route policy.
pub fn link_managed_target(
  target: &ManagedTarget,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
) -> TargetLinkResult<LinkedManagedTarget> {
  let pool = require_pool(target.account_pool(), pools)?;
  let upstreams = link_upstream_domain(target.upstream(), &pool, plan, providers)?;
  let model = link_model_selector(target.model(), &upstreams, plan)?;
  Ok(LinkedManagedTarget { pool, upstreams, model })
}

/// Link one relay target independently of its outer route policy.
pub fn link_relay_target(
  target: &RelayTarget,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  pools: &AccountPoolRuntimes,
) -> TargetLinkResult<LinkedRelayTarget> {
  match target {
    RelayTarget::FixedUpstream { upstream, account_pool } => {
      let pool = require_pool(account_pool, pools)?;
      let linked_upstream = link_upstream(upstream, plan, providers)?;
      if !pool_has_upstream(&pool, upstream) {
        return Err(TargetLinkError::FixedUpstreamUnavailable {
          pool: account_pool.clone(),
          upstream: upstream.clone(),
        });
      }
      Ok(LinkedRelayTarget::Fixed {
        pool,
        upstream: linked_upstream,
      })
    }
    RelayTarget::UpstreamFromOrigin { account_pool } => {
      let pool = require_pool(account_pool, pools)?;
      link_origin_relay_target(pool, plan, providers)
    }
  }
}

fn require_pool(pool_id: &AccountPoolId, pools: &AccountPoolRuntimes) -> TargetLinkResult<Arc<AccountPoolRuntime>> {
  pools
    .runtime(pool_id)
    .cloned()
    .ok_or_else(|| TargetLinkError::MissingPoolRuntime { pool: pool_id.clone() })
}

fn link_upstream_domain(
  selector: &UpstreamSelector,
  pool: &AccountPoolRuntime,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
) -> TargetLinkResult<LinkedUpstreamDomain> {
  match selector {
    UpstreamSelector::Fixed(upstream_id) => {
      let upstream = link_upstream(upstream_id, plan, providers)?;
      if !pool_has_upstream(pool, upstream_id) {
        return Err(TargetLinkError::FixedUpstreamUnavailable {
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
          upstreams.push(link_upstream(upstream_id, plan, providers)?);
        }
      }
      if upstreams.is_empty() {
        return Err(TargetLinkError::NoUsableUpstream {
          pool: pool.pool().id().clone(),
        });
      }
      Ok(LinkedUpstreamDomain::Any(upstreams.into_boxed_slice()))
    }
  }
}

fn link_upstream(
  upstream_id: &UpstreamId,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
) -> TargetLinkResult<LinkedUpstream> {
  let upstream = plan
    .upstream(upstream_id)
    .ok_or_else(|| TargetLinkError::MissingUpstream {
      upstream: upstream_id.clone(),
    })?;
  let target = providers
    .target(upstream_id)
    .cloned()
    .ok_or_else(|| TargetLinkError::MissingProviderTarget {
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
  selector: &ModelSelector,
  upstreams: &LinkedUpstreamDomain,
  plan: &GatewayPlan,
) -> TargetLinkResult<LinkedModelSelector> {
  match selector {
    ModelSelector::Capability => Ok(LinkedModelSelector::Capability),
    ModelSelector::Qualified { namespace } => Ok(LinkedModelSelector::Qualified { namespace: *namespace }),
    ModelSelector::Fallback(fallback) => {
      let linked = match fallback {
        FallbackSelector::Fixed(group_id) => {
          LinkedFallbackSelector::Fixed(link_model_group(group_id, upstreams, plan)?)
        }
        FallbackSelector::ByRequested(group_ids) => {
          if group_ids.is_empty() {
            return Err(TargetLinkError::EmptyFallbackSelector);
          }
          let groups = group_ids
            .iter()
            .map(|group_id| link_model_group(group_id, upstreams, plan))
            .collect::<TargetLinkResult<Vec<_>>>()?;
          LinkedFallbackSelector::ByRequested(groups.into_boxed_slice())
        }
      };
      Ok(LinkedModelSelector::Fallback(linked))
    }
  }
}

fn link_model_group(
  group_id: &ModelGroupId,
  upstreams: &LinkedUpstreamDomain,
  plan: &GatewayPlan,
) -> TargetLinkResult<LinkedModelGroup> {
  let group = plan
    .model_group(group_id)
    .ok_or_else(|| TargetLinkError::MissingModelGroup {
      group: group_id.clone(),
    })?;
  let mut request_models = BTreeSet::new();
  let mut candidates = Vec::new();
  for (index, candidate) in group.candidates().iter().enumerate() {
    let model = candidate.model();
    if model.is_empty() || model.trim() != model {
      return Err(TargetLinkError::InvalidModelCandidate {
        group: group_id.clone(),
        index,
        model: model.to_string(),
      });
    }
    request_models.insert(SmolStr::new(model));
    let upstream_ids = match candidate.upstream() {
      Some(upstream_id) => {
        if plan.upstream(upstream_id).is_none() {
          return Err(TargetLinkError::MissingUpstream {
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
    return Err(TargetLinkError::NoMaterializableCandidates {
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
  pool: Arc<AccountPoolRuntime>,
  plan: &GatewayPlan,
  providers: &ProviderGraph,
) -> TargetLinkResult<LinkedRelayTarget> {
  let mut upstreams = Vec::new();
  let mut origins = BTreeMap::new();
  for (upstream_id, upstream_plan) in plan.upstreams() {
    if !pool_has_upstream(&pool, upstream_id) {
      continue;
    }
    let upstream = link_upstream(upstream_id, plan, providers)?;
    let cleartext = if upstream_plan.allow_insecure_http() {
      CleartextHttpPolicy::Allow
    } else {
      CleartextHttpPolicy::LoopbackOnly
    };
    let mut claimed = BTreeSet::new();
    claimed.insert(upstream.target().base_url().origin());
    for configured in upstream_plan.origins() {
      let origin = CanonicalHttpOrigin::parse(configured.as_str(), cleartext).map_err(|source| {
        TargetLinkError::InvalidOrigin {
          upstream: upstream_id.clone(),
          origin: configured.to_string(),
          source,
        }
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
          return Err(TargetLinkError::AmbiguousOrigin {
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
    return Err(TargetLinkError::NoUsableOrigin {
      pool: pool.pool().id().clone(),
    });
  }
  Ok(LinkedRelayTarget::FromOrigin {
    pool,
    upstreams: upstreams.into_boxed_slice(),
    origins,
  })
}

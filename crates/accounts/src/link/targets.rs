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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph};
  use crate::registry::Registry;
  use smol_str::SmolStr;
  use std::time::Duration;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_policy::{
    AccountPoolPlan, AccountSelectionStrategy, AccountSelector, ModelCandidate, ModelGroupPlan, UpstreamOrigin,
    UpstreamPlan,
  };

  struct Inputs {
    providers: ProviderGraph,
    runtimes: AccountPoolRuntimes,
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

  fn plan(
    pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
    groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      pools,
      upstreams,
      groups,
    )
  }

  fn build_inputs(plan: &GatewayPlan, accounts: &[AccountConfig]) -> Inputs {
    let registry = Registry::builtin();
    let providers = link_provider_graph(plan, accounts, &registry).unwrap();
    let pools = link_account_pools(plan, &providers, &registry).unwrap();
    let runtimes = build_account_pool_runtimes(&pools);
    Inputs { providers, runtimes }
  }

  #[test]
  fn managed_domains_follow_pool_bindings_and_share_the_pool_runtime() {
    let a = upstream_id("a-live");
    let z = upstream_id("z-live");
    let gateway = plan(
      BTreeMap::from([(pool_id("selected"), account_pool(Some(&["selected"])))]),
      BTreeMap::from([
        (
          a.clone(),
          upstream(Some("https://a.example/v1/"), Some(&["selected"]), &[]),
        ),
        (
          upstream_id("m-dead"),
          upstream(Some("https://dead.example/v1/"), Some(&["excluded"]), &[]),
        ),
        (
          z.clone(),
          upstream(Some("https://z.example/v1/"), Some(&["selected"]), &[]),
        ),
      ]),
      BTreeMap::new(),
    );
    let inputs = build_inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );
    let fixed = link_managed_target(
      &ManagedTarget::new(
        pool_id("selected"),
        UpstreamSelector::Fixed(z),
        ModelSelector::Capability,
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();
    let any = link_managed_target(
      &ManagedTarget::new(pool_id("selected"), UpstreamSelector::Any, ModelSelector::Capability),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();

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
  fn managed_domains_reject_unusable_pool_bindings() {
    let dead = upstream_id("dead");
    let gateway = plan(
      BTreeMap::from([(pool_id("empty"), account_pool(None))]),
      BTreeMap::from([(dead.clone(), upstream(Some("https://dead.example/v1/"), None, &[]))]),
      BTreeMap::new(),
    );
    let inputs = build_inputs(&gateway, &[]);

    let fixed = link_managed_target(
      &ManagedTarget::new(
        pool_id("empty"),
        UpstreamSelector::Fixed(dead.clone()),
        ModelSelector::Capability,
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      fixed,
      Err(TargetLinkError::FixedUpstreamUnavailable { pool, upstream })
        if pool.as_str() == "empty" && upstream == dead
    ));

    let any = link_managed_target(
      &ManagedTarget::new(pool_id("empty"), UpstreamSelector::Any, ModelSelector::Capability),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      any,
      Err(TargetLinkError::NoUsableUpstream { pool }) if pool.as_str() == "empty"
    ));
  }

  #[test]
  fn fallback_prunes_dead_candidates_but_preserves_order_and_request_names() {
    let live = upstream_id("live");
    let dead = upstream_id("dead");
    let group = group_id("coding");
    let gateway = plan(
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
    let inputs = build_inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );
    let target = link_managed_target(
      &ManagedTarget::new(
        pool_id("selected"),
        UpstreamSelector::Any,
        ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();
    let LinkedModelSelector::Fallback(LinkedFallbackSelector::Fixed(group)) = target.model() else {
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
  fn fallback_rejects_groups_without_live_candidates_and_unknown_upstreams() {
    let group = group_id("group");
    let gateway = plan(
      BTreeMap::from([(pool_id("selected"), account_pool(Some(&["selected"])))]),
      BTreeMap::from([
        (
          upstream_id("dead"),
          upstream(Some("https://dead.example/v1/"), Some(&["excluded"]), &[]),
        ),
        (
          upstream_id("live"),
          upstream(Some("https://live.example/v1/"), Some(&["selected"]), &[]),
        ),
      ]),
      BTreeMap::from([(
        group.clone(),
        ModelGroupPlan::new(vec![ModelCandidate::new(Some(upstream_id("dead")), "dead-model")].into_boxed_slice()),
      )]),
    );
    let inputs = build_inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );
    let result = link_managed_target(
      &ManagedTarget::new(
        pool_id("selected"),
        UpstreamSelector::Any,
        ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      result,
      Err(TargetLinkError::NoMaterializableCandidates { group: error_group }) if error_group == group
    ));

    let unknown_group = group_id("unknown-upstream");
    let gateway = plan(
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("live"),
        upstream(Some("https://live.example/v1/"), None, &[]),
      )]),
      BTreeMap::from([(
        unknown_group.clone(),
        ModelGroupPlan::new(
          vec![
            ModelCandidate::new(Some(upstream_id("absent")), "broken"),
            ModelCandidate::new(None, "live"),
          ]
          .into_boxed_slice(),
        ),
      )]),
    );
    let inputs = build_inputs(&gateway, &[account("account", AccountTier::Active)]);
    let result = link_managed_target(
      &ManagedTarget::new(
        pool_id("all"),
        UpstreamSelector::Any,
        ModelSelector::Fallback(FallbackSelector::Fixed(unknown_group)),
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      result,
      Err(TargetLinkError::MissingUpstream { upstream }) if upstream.as_str() == "absent"
    ));
  }

  #[test]
  fn fallback_rejects_malformed_candidates_and_empty_by_requested_selectors() {
    let invalid_group = group_id("invalid");
    let gateway = plan(
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
    let inputs = build_inputs(&gateway, &[account("account", AccountTier::Active)]);
    let invalid = link_managed_target(
      &ManagedTarget::new(
        pool_id("all"),
        UpstreamSelector::Any,
        ModelSelector::Fallback(FallbackSelector::Fixed(invalid_group.clone())),
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      invalid,
      Err(TargetLinkError::InvalidModelCandidate {
        group,
        index: 0,
        model,
      }) if group == invalid_group && model == " bad-model"
    ));

    let empty = link_managed_target(
      &ManagedTarget::new(
        pool_id("all"),
        UpstreamSelector::Any,
        ModelSelector::Fallback(FallbackSelector::ByRequested(Box::default())),
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(empty, Err(TargetLinkError::EmptyFallbackSelector)));
  }

  #[test]
  fn origin_relay_unions_target_and_configured_origins_and_filters_by_pool() {
    let live = upstream_id("live");
    let gateway = plan(
      BTreeMap::from([(pool_id("selected"), account_pool(Some(&["selected"])))]),
      BTreeMap::from([
        (
          upstream_id("excluded"),
          upstream(
            Some("https://excluded.example/v1/"),
            Some(&["excluded"]),
            &["https://excluded-alias.example"],
          ),
        ),
        (
          live.clone(),
          upstream(
            Some("https://base.example/v1/"),
            Some(&["selected"]),
            &["https://base.example", "https://alias.example"],
          ),
        ),
      ]),
      BTreeMap::new(),
    );
    let inputs = build_inputs(
      &gateway,
      &[
        account("selected", AccountTier::Active),
        account("excluded", AccountTier::Active),
      ],
    );
    let target = link_relay_target(
      &RelayTarget::UpstreamFromOrigin {
        account_pool: pool_id("selected"),
      },
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    )
    .unwrap();
    let origins = target.origins().unwrap();
    let base = CanonicalHttpOrigin::parse("https://base.example", CleartextHttpPolicy::LoopbackOnly).unwrap();
    let alias = CanonicalHttpOrigin::parse("https://alias.example", CleartextHttpPolicy::LoopbackOnly).unwrap();

    assert_eq!(target.upstreams().len(), 1);
    assert!(target.preserves_original_destination());
    assert_eq!(origins.len(), 2);
    assert_eq!(origins.get(&base), Some(&live));
    assert_eq!(origins.get(&alias), Some(&live));
    assert_eq!(target.upstream_for_origin(&alias).map(LinkedUpstream::id), Some(&live));
  }

  #[test]
  fn origin_relay_rejects_ambiguous_origins_and_empty_pools() {
    let gateway = plan(
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([
        (upstream_id("first"), upstream(None, None, &[])),
        (upstream_id("second"), upstream(None, None, &[])),
      ]),
      BTreeMap::new(),
    );
    let inputs = build_inputs(&gateway, &[account("account", AccountTier::Active)]);
    let ambiguous = link_relay_target(
      &RelayTarget::UpstreamFromOrigin {
        account_pool: pool_id("all"),
      },
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      ambiguous,
      Err(TargetLinkError::AmbiguousOrigin {
        first_upstream,
        second_upstream,
        ..
      }) if first_upstream.as_str() == "first" && second_upstream.as_str() == "second"
    ));

    let gateway = plan(
      BTreeMap::from([(pool_id("empty"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream(Some("https://upstream.example/v1/"), None, &[]),
      )]),
      BTreeMap::new(),
    );
    let inputs = build_inputs(&gateway, &[]);
    let empty = link_relay_target(
      &RelayTarget::UpstreamFromOrigin {
        account_pool: pool_id("empty"),
      },
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      empty,
      Err(TargetLinkError::NoUsableOrigin { pool }) if pool.as_str() == "empty"
    ));
  }

  #[test]
  fn target_linking_reports_missing_symbolic_references() {
    let empty = plan(BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let inputs = build_inputs(&empty, &[]);
    let missing_pool = link_managed_target(
      &ManagedTarget::new(pool_id("absent"), UpstreamSelector::Any, ModelSelector::Capability),
      &empty,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      missing_pool,
      Err(TargetLinkError::MissingPoolRuntime { pool }) if pool.as_str() == "absent"
    ));

    let gateway = plan(
      BTreeMap::from([(pool_id("empty"), account_pool(None))]),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let inputs = build_inputs(&gateway, &[]);
    let missing_upstream = link_relay_target(
      &RelayTarget::FixedUpstream {
        upstream: upstream_id("absent"),
        account_pool: pool_id("empty"),
      },
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      missing_upstream,
      Err(TargetLinkError::MissingUpstream { upstream }) if upstream.as_str() == "absent"
    ));

    let gateway = plan(
      BTreeMap::from([(pool_id("all"), account_pool(None))]),
      BTreeMap::from([(
        upstream_id("live"),
        upstream(Some("https://live.example/v1/"), None, &[]),
      )]),
      BTreeMap::new(),
    );
    let inputs = build_inputs(&gateway, &[account("account", AccountTier::Active)]);
    let missing_group = link_managed_target(
      &ManagedTarget::new(
        pool_id("all"),
        UpstreamSelector::Any,
        ModelSelector::Fallback(FallbackSelector::Fixed(group_id("absent"))),
      ),
      &gateway,
      &inputs.providers,
      &inputs.runtimes,
    );
    assert!(matches!(
      missing_group,
      Err(TargetLinkError::MissingModelGroup { group }) if group.as_str() == "absent"
    ));
  }
}

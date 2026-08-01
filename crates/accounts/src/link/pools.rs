//! Immutable account-pool views over the v2 provider graph.
//!
//! A pool selects logical accounts, not individual provider bindings. One
//! account can therefore expose several eligible upstream bindings without
//! receiving extra weight in later round-robin selection.

use super::{ProviderBinding, ProviderGraph};
use crate::registry::Registry;
use smol_str::SmolStr;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokn_policy::{AccountPoolId, AccountSelectionStrategy, GatewayPlan, ProviderId, SessionAffinityPlan, UpstreamId};

/// Every account pool linked from one compiled gateway plan.
pub struct LinkedAccountPools {
  pools: BTreeMap<AccountPoolId, Arc<LinkedAccountPool>>,
}

impl LinkedAccountPools {
  pub fn pool(&self, pool_id: &AccountPoolId) -> Option<&Arc<LinkedAccountPool>> {
    self.pools.get(pool_id)
  }

  pub fn pools(&self) -> impl ExactSizeIterator<Item = (&AccountPoolId, &Arc<LinkedAccountPool>)> {
    self.pools.iter()
  }

  pub fn len(&self) -> usize {
    self.pools.len()
  }

  pub fn is_empty(&self) -> bool {
    self.pools.is_empty()
  }
}

impl std::fmt::Debug for LinkedAccountPools {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.debug_map().entries(&self.pools).finish()
  }
}

/// One immutable pool definition split into pool-local active and fallback tiers.
pub struct LinkedAccountPool {
  id: AccountPoolId,
  strategy: AccountSelectionStrategy,
  failure_cooldown: Duration,
  session_affinity: Option<SessionAffinityPlan>,
  active: Box<[LinkedPoolAccount]>,
  fallback: Box<[LinkedPoolAccount]>,
}

impl LinkedAccountPool {
  pub fn id(&self) -> &AccountPoolId {
    &self.id
  }

  pub fn strategy(&self) -> AccountSelectionStrategy {
    self.strategy
  }

  pub fn failure_cooldown(&self) -> Duration {
    self.failure_cooldown
  }

  pub fn session_affinity(&self) -> Option<SessionAffinityPlan> {
    self.session_affinity
  }

  /// Accounts assigned to this pool's active tier, in original input order.
  pub fn active(&self) -> &[LinkedPoolAccount] {
    &self.active
  }

  /// Accounts assigned to this pool's fallback tier, in original input order.
  pub fn fallback(&self) -> &[LinkedPoolAccount] {
    &self.fallback
  }

  pub fn is_empty(&self) -> bool {
    self.active.is_empty() && self.fallback.is_empty()
  }
}

impl std::fmt::Debug for LinkedAccountPool {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("LinkedAccountPool")
      .field("id", &self.id)
      .field("strategy", &self.strategy)
      .field("failure_cooldown", &self.failure_cooldown)
      .field("session_affinity", &self.session_affinity)
      .field("active", &self.active)
      .field("fallback", &self.fallback)
      .finish()
  }
}

/// One logical account slot and all of its eligible upstream bindings.
pub struct LinkedPoolAccount {
  account_id: SmolStr,
  account_order: usize,
  bindings: BTreeMap<UpstreamId, Arc<ProviderBinding>>,
}

impl LinkedPoolAccount {
  pub fn account_id(&self) -> &str {
    self.account_id.as_str()
  }

  /// Zero-based position in the account input supplied to provider linking.
  pub fn account_order(&self) -> usize {
    self.account_order
  }

  /// Bindings ordered by typed upstream id.
  pub fn bindings(&self) -> &BTreeMap<UpstreamId, Arc<ProviderBinding>> {
    &self.bindings
  }

  pub fn binding(&self, upstream_id: &UpstreamId) -> Option<&Arc<ProviderBinding>> {
    self.bindings.get(upstream_id)
  }
}

impl std::fmt::Debug for LinkedPoolAccount {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("LinkedPoolAccount")
      .field("account_id", &self.account_id)
      .field("account_order", &self.account_order)
      .field("bindings", &self.bindings)
      .finish()
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum PoolLinkError {
  #[snafu(display("account pool '{pool}' references unknown provider '{provider}'"))]
  UnknownProvider { pool: AccountPoolId, provider: ProviderId },

  #[snafu(display("account pool '{pool}' references unknown account '{account_id}'"))]
  UnknownAccount { pool: AccountPoolId, account_id: SmolStr },

  #[snafu(display("account pool '{pool}' assigns account '{account_id}' to both active and fallback tiers"))]
  OverlappingAccountTiers { pool: AccountPoolId, account_id: SmolStr },
}

pub type PoolLinkResult<T> = std::result::Result<T, PoolLinkError>;

/// Materialize configured account selectors over an already-linked provider
/// graph.
///
/// Selector dimensions are intersected. Disabled accounts and enabled
/// accounts without a viable upstream binding are intentionally omitted, but
/// an explicitly named disabled account is still a valid reference.
pub fn link_account_pools(
  plan: &GatewayPlan,
  providers: &ProviderGraph,
  registry: &Registry,
) -> PoolLinkResult<LinkedAccountPools> {
  let mut pools = BTreeMap::new();

  for (pool_id, pool_plan) in plan.account_pools() {
    validate_selector(pool_id, pool_plan.selector(), providers, registry)?;

    let mut active = Vec::new();
    let mut fallback = Vec::new();
    for account in providers.accounts() {
      let config = account.config();
      let selector = pool_plan.selector();
      if !config.enabled
        || account.bindings().is_empty()
        || !selector
          .providers()
          .is_none_or(|provider_ids| provider_ids.contains(config.provider.as_str()))
      {
        continue;
      }

      let is_fallback = selector.fallback_accounts().contains(config.id.as_str());
      if !is_fallback
        && !selector
          .active_accounts()
          .is_none_or(|account_ids| account_ids.contains(config.id.as_str()))
      {
        continue;
      }

      let mut bindings = BTreeMap::new();
      for binding in account.bindings() {
        let previous = bindings.insert(binding.upstream_id().clone(), binding.clone());
        debug_assert!(
          previous.is_none(),
          "provider graph contains duplicate account/upstream binding"
        );
      }
      let linked = LinkedPoolAccount {
        account_id: SmolStr::new(&config.id),
        account_order: account.input_order(),
        bindings,
      };

      if is_fallback {
        fallback.push(linked);
      } else {
        active.push(linked);
      }
    }

    let pool = Arc::new(LinkedAccountPool {
      id: pool_id.clone(),
      strategy: pool_plan.strategy(),
      failure_cooldown: pool_plan.failure_cooldown(),
      session_affinity: pool_plan.session_affinity(),
      active: active.into_boxed_slice(),
      fallback: fallback.into_boxed_slice(),
    });
    pools.insert(pool_id.clone(), pool);
  }

  Ok(LinkedAccountPools { pools })
}

fn validate_selector(
  pool_id: &AccountPoolId,
  selector: &tokn_policy::AccountSelector,
  providers: &ProviderGraph,
  registry: &Registry,
) -> PoolLinkResult<()> {
  if let Some(account_id) = selector
    .active_accounts()
    .and_then(|active_accounts| active_accounts.intersection(selector.fallback_accounts()).next())
  {
    return Err(PoolLinkError::OverlappingAccountTiers {
      pool: pool_id.clone(),
      account_id: account_id.clone(),
    });
  }

  if let Some(provider_ids) = selector.providers() {
    for provider_id in provider_ids {
      if registry.resolve(provider_id.as_str()).is_none() {
        return Err(PoolLinkError::UnknownProvider {
          pool: pool_id.clone(),
          provider: provider_id.clone(),
        });
      }
    }
  }

  for account_id in selector
    .active_accounts()
    .into_iter()
    .flatten()
    .chain(selector.fallback_accounts())
  {
    if providers.account(account_id.as_str()).is_none() {
      return Err(PoolLinkError::UnknownAccount {
        pool: pool_id.clone(),
        account_id: account_id.clone(),
      });
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::link::link_provider_graph;
  use std::collections::BTreeMap;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::{ID_LLAMA_CPP, ID_OPENAI};
  use tokn_policy::{AccountPoolPlan, AccountSelector, UpstreamPlan};

  fn pool_id(value: &str) -> AccountPoolId {
    AccountPoolId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
  }

  fn upstream_id(value: &str) -> UpstreamId {
    UpstreamId::new(value).unwrap()
  }

  fn account(id: &str, provider: &str, tier: AccountTier) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.id = id.to_string();
    account.provider = provider.to_string();
    account.tier = tier;
    if provider == ID_OPENAI {
      account.api_key = Some("test-key".to_string().into());
    }
    account
  }

  fn upstream(provider: &str, eligible_accounts: Option<&[&str]>) -> UpstreamPlan {
    UpstreamPlan::new(
      provider_id(provider),
      Some("https://gateway.example/v1/".into()),
      Box::default(),
      false,
    )
    .with_eligible_accounts(eligible_accounts.map(|ids| ids.iter().map(SmolStr::new).collect()))
  }

  fn pool(providers: Option<&[&str]>, active_accounts: Option<&[&str]>, fallback_accounts: &[&str]) -> AccountPoolPlan {
    AccountPoolPlan::new(
      AccountSelector::new(
        providers.map(|ids| ids.iter().map(|id| provider_id(id)).collect()),
        active_accounts.map(|ids| ids.iter().map(SmolStr::new).collect()),
        fallback_accounts.iter().map(SmolStr::new).collect(),
      ),
      AccountSelectionStrategy::RoundRobin,
      Duration::from_secs(17),
      Some(SessionAffinityPlan::new(
        Duration::from_secs(23),
        Duration::from_secs(29),
      )),
    )
  }

  fn plan(
    pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      pools,
      upstreams,
      BTreeMap::new(),
    )
  }

  fn link(plan: &GatewayPlan, accounts: &[AccountConfig]) -> PoolLinkResult<(ProviderGraph, LinkedAccountPools)> {
    let registry = Registry::builtin();
    let providers = link_provider_graph(plan, accounts, &registry).unwrap();
    let pools = link_account_pools(plan, &providers, &registry)?;
    Ok((providers, pools))
  }

  #[test]
  fn groups_upstreams_by_logical_account_and_uses_pool_local_tier_order() {
    let primary = upstream_id("z-primary");
    let secondary = upstream_id("a-secondary");
    let plan = plan(
      BTreeMap::from([(pool_id("all"), pool(None, None, &["fallback-first"]))]),
      BTreeMap::from([
        (primary.clone(), upstream(ID_LLAMA_CPP, None)),
        (secondary.clone(), upstream(ID_LLAMA_CPP, None)),
      ]),
    );
    let accounts = [
      account("fallback-first", ID_LLAMA_CPP, AccountTier::Active),
      account("active-second", ID_LLAMA_CPP, AccountTier::Fallback),
      account("active-third", ID_LLAMA_CPP, AccountTier::Active),
    ];

    let (_, linked) = link(&plan, &accounts).unwrap();
    let pool = linked.pool(&pool_id("all")).unwrap();

    assert_eq!(
      pool
        .active()
        .iter()
        .map(LinkedPoolAccount::account_id)
        .collect::<Vec<_>>(),
      ["active-second", "active-third"]
    );
    assert_eq!(pool.active()[0].account_order(), 1);
    assert_eq!(
      pool
        .fallback()
        .iter()
        .map(LinkedPoolAccount::account_id)
        .collect::<Vec<_>>(),
      ["fallback-first"]
    );
    assert_eq!(pool.fallback()[0].account_order(), 0);
    assert_eq!(
      pool.active()[0]
        .bindings()
        .keys()
        .map(UpstreamId::as_str)
        .collect::<Vec<_>>(),
      ["a-secondary", "z-primary"]
    );
    assert_eq!(pool.strategy(), AccountSelectionStrategy::RoundRobin);
    assert_eq!(pool.failure_cooldown(), Duration::from_secs(17));
    assert_eq!(pool.session_affinity().unwrap().ttl(), Duration::from_secs(23));
  }

  #[test]
  fn intersects_provider_and_account_selectors() {
    let selected = account("selected", ID_LLAMA_CPP, AccountTier::Active);
    let omitted_by_account = account("omitted-account", ID_LLAMA_CPP, AccountTier::Active);
    let omitted_by_provider = account("omitted-provider", ID_OPENAI, AccountTier::Active);
    let plan = plan(
      BTreeMap::from([(
        pool_id("selected"),
        pool(Some(&[ID_LLAMA_CPP]), Some(&["selected", "omitted-provider"]), &[]),
      )]),
      BTreeMap::from([
        (upstream_id("llama"), upstream(ID_LLAMA_CPP, None)),
        (upstream_id("openai"), upstream(ID_OPENAI, None)),
      ]),
    );

    let (_, linked) = link(&plan, &[omitted_by_account, omitted_by_provider, selected]).unwrap();
    let selected = linked.pool(&pool_id("selected")).unwrap();

    assert_eq!(selected.active().len(), 1);
    assert_eq!(selected.active()[0].account_id(), "selected");
    assert_eq!(selected.active()[0].account_order(), 2);
  }

  #[test]
  fn pools_share_binding_arcs_without_sharing_logical_slots() {
    let upstream_id = upstream_id("local");
    let plan = plan(
      BTreeMap::from([
        (pool_id("first"), pool(None, None, &[])),
        (pool_id("second"), pool(None, Some(&["shared"]), &[])),
      ]),
      BTreeMap::from([(upstream_id.clone(), upstream(ID_LLAMA_CPP, None))]),
    );

    let (providers, linked) = link(&plan, &[account("shared", ID_LLAMA_CPP, AccountTier::Active)]).unwrap();
    let graph_binding = providers.binding(&upstream_id, "shared").unwrap();
    let first = linked.pool(&pool_id("first")).unwrap().active()[0]
      .binding(&upstream_id)
      .unwrap();
    let second = linked.pool(&pool_id("second")).unwrap().active()[0]
      .binding(&upstream_id)
      .unwrap();

    assert!(Arc::ptr_eq(graph_binding, first));
    assert!(Arc::ptr_eq(first, second));
  }

  #[test]
  fn the_same_account_can_have_different_tiers_in_different_pools() {
    let upstream_id = upstream_id("local");
    let plan = plan(
      BTreeMap::from([
        (pool_id("primary"), pool(None, Some(&["shared"]), &[])),
        (pool_id("backup"), pool(None, None, &["shared"])),
      ]),
      BTreeMap::from([(upstream_id.clone(), upstream(ID_LLAMA_CPP, None))]),
    );

    // Pool-local membership is authoritative even when the legacy account
    // record carries the opposite global tier.
    let (providers, linked) = link(&plan, &[account("shared", ID_LLAMA_CPP, AccountTier::Fallback)]).unwrap();
    let primary = linked.pool(&pool_id("primary")).unwrap();
    let backup = linked.pool(&pool_id("backup")).unwrap();

    assert_eq!(primary.active()[0].account_id(), "shared");
    assert!(primary.fallback().is_empty());
    assert!(backup.active().is_empty());
    assert_eq!(backup.fallback()[0].account_id(), "shared");
    assert!(Arc::ptr_eq(
      providers.binding(&upstream_id, "shared").unwrap(),
      backup.fallback()[0].binding(&upstream_id).unwrap()
    ));
  }

  #[test]
  fn validates_explicit_provider_and_account_names() {
    let unknown_provider_plan = plan(
      BTreeMap::from([(pool_id("invalid-provider"), pool(Some(&["not-installed"]), None, &[]))]),
      BTreeMap::new(),
    );
    let provider_error = link(&unknown_provider_plan, &[]).err().unwrap();
    assert!(matches!(
      provider_error,
      PoolLinkError::UnknownProvider { pool, provider }
        if pool.as_str() == "invalid-provider" && provider.as_str() == "not-installed"
    ));

    let unknown_account_plan = plan(
      BTreeMap::from([(pool_id("invalid-account"), pool(None, Some(&["missing"]), &[]))]),
      BTreeMap::new(),
    );
    let account_error = link(&unknown_account_plan, &[]).err().unwrap();
    assert!(matches!(
      account_error,
      PoolLinkError::UnknownAccount { pool, account_id }
        if pool.as_str() == "invalid-account" && account_id == "missing"
    ));

    let unknown_fallback_plan = plan(
      BTreeMap::from([(pool_id("invalid-fallback"), pool(None, None, &["missing-fallback"]))]),
      BTreeMap::new(),
    );
    let fallback_error = link(&unknown_fallback_plan, &[]).err().unwrap();
    assert!(matches!(
      fallback_error,
      PoolLinkError::UnknownAccount { pool, account_id }
        if pool.as_str() == "invalid-fallback" && account_id == "missing-fallback"
    ));

    let overlapping_tiers_plan = plan(
      BTreeMap::from([(pool_id("overlapping-tiers"), pool(None, Some(&["shared"]), &["shared"]))]),
      BTreeMap::new(),
    );
    let overlap_error = link(&overlapping_tiers_plan, &[]).err().unwrap();
    assert!(matches!(
      overlap_error,
      PoolLinkError::OverlappingAccountTiers { pool, account_id }
        if pool.as_str() == "overlapping-tiers" && account_id == "shared"
    ));
  }

  #[test]
  fn known_disabled_or_unbound_accounts_are_valid_but_omitted() {
    let mut disabled = account("disabled", ID_LLAMA_CPP, AccountTier::Active);
    disabled.enabled = false;
    let unbound = account("unbound", ID_OPENAI, AccountTier::Active);
    let plan = plan(
      BTreeMap::from([(pool_id("empty"), pool(None, Some(&["disabled", "unbound"]), &[]))]),
      BTreeMap::from([(upstream_id("llama"), upstream(ID_LLAMA_CPP, None))]),
    );

    let (_, linked) = link(&plan, &[disabled, unbound]).unwrap();
    let empty = linked.pool(&pool_id("empty")).unwrap();

    assert!(empty.is_empty());
  }

  #[test]
  fn upstream_eligibility_remains_enforced_in_pool_bindings() {
    let unrestricted = upstream_id("unrestricted");
    let restricted = upstream_id("restricted");
    let plan = plan(
      BTreeMap::from([(pool_id("all"), pool(None, None, &[]))]),
      BTreeMap::from([
        (unrestricted.clone(), upstream(ID_LLAMA_CPP, None)),
        (restricted.clone(), upstream(ID_LLAMA_CPP, Some(&["eligible"]))),
      ]),
    );

    let (_, linked) = link(
      &plan,
      &[
        account("eligible", ID_LLAMA_CPP, AccountTier::Active),
        account("ineligible", ID_LLAMA_CPP, AccountTier::Active),
      ],
    )
    .unwrap();
    let pool = linked.pool(&pool_id("all")).unwrap();
    let eligible = &pool.active()[0];
    let ineligible = &pool.active()[1];

    assert!(eligible.binding(&unrestricted).is_some());
    assert!(eligible.binding(&restricted).is_some());
    assert!(ineligible.binding(&unrestricted).is_some());
    assert!(ineligible.binding(&restricted).is_none());
  }
}

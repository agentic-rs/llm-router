//! Immutable account-pool views over the v2 provider graph.
//!
//! Each account already owns exactly one configured-provider binding. Pools
//! only filter and tier those logical accounts.

use super::{ProviderBinding, ProviderGraph};
use smol_str::SmolStr;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokn_core::account::AccountTier;
use tokn_policy::{AccountPoolId, AccountSelectionStrategy, GatewayPlan, SessionAffinityPlan};

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

/// One immutable pool definition split into global active and fallback tiers.
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

  /// Enabled active accounts in their original account-input order.
  pub fn active(&self) -> &[LinkedPoolAccount] {
    &self.active
  }

  /// Enabled fallback accounts in their original account-input order.
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

/// One logical account slot and its configured-provider binding.
pub struct LinkedPoolAccount {
  account_id: SmolStr,
  account_order: usize,
  binding: Arc<ProviderBinding>,
}

impl LinkedPoolAccount {
  pub fn account_id(&self) -> &str {
    self.account_id.as_str()
  }

  /// Zero-based position in the account input supplied to provider linking.
  pub fn account_order(&self) -> usize {
    self.account_order
  }

  pub fn binding(&self) -> &Arc<ProviderBinding> {
    &self.binding
  }
}

impl std::fmt::Debug for LinkedPoolAccount {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("LinkedPoolAccount")
      .field("account_id", &self.account_id)
      .field("account_order", &self.account_order)
      .field("binding", &self.binding)
      .finish()
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum PoolLinkError {
  #[snafu(display("account pool '{pool}' references unknown account '{account_id}'"))]
  UnknownAccount { pool: AccountPoolId, account_id: SmolStr },
}

pub type PoolLinkResult<T> = std::result::Result<T, PoolLinkError>;

/// Materialize configured account selectors over an already-linked provider
/// graph.
///
/// Selector dimensions are intersected. Disabled accounts and enabled
/// accounts without a viable provider binding are intentionally omitted, but
/// an explicitly named disabled account is still a valid reference.
pub fn link_account_pools(plan: &GatewayPlan, providers: &ProviderGraph) -> PoolLinkResult<LinkedAccountPools> {
  let mut pools = BTreeMap::new();

  for (pool_id, pool_plan) in plan.account_pools() {
    validate_selector(pool_id, pool_plan.selector(), providers)?;

    let mut active = Vec::new();
    let mut fallback = Vec::new();
    for account in providers.accounts() {
      let config = account.config();
      let selector = pool_plan.selector();
      let Some(binding) = account.binding() else {
        continue;
      };
      if !config.enabled
        || !selector
          .providers()
          .is_none_or(|provider_ids| provider_ids.contains(binding.provider_id()))
        || !selector
          .accounts()
          .is_none_or(|account_ids| account_ids.contains(config.id.as_str()))
      {
        continue;
      }

      let linked = LinkedPoolAccount {
        account_id: SmolStr::new(&config.id),
        account_order: account.input_order(),
        binding: binding.clone(),
      };

      match config.tier {
        AccountTier::Active => active.push(linked),
        AccountTier::Fallback => fallback.push(linked),
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
) -> PoolLinkResult<()> {
  if let Some(account_ids) = selector.accounts() {
    for account_id in account_ids {
      if providers.account(account_id.as_str()).is_none() {
        return Err(PoolLinkError::UnknownAccount {
          pool: pool_id.clone(),
          account_id: account_id.clone(),
        });
      }
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::link::link_provider_graph;
  use crate::registry::Registry;
  use std::collections::BTreeMap;
  use tokn_core::account::AccountConfig;
  use tokn_core::provider::{ID_LLAMA_CPP, ID_OPENAI};
  use tokn_policy::{AccountPoolPlan, AccountSelector, ProviderPlan};

  fn pool_id(value: &str) -> AccountPoolId {
    AccountPoolId::new(value).unwrap()
  }

  fn driver_id(value: &str) -> tokn_policy::DriverId {
    tokn_policy::DriverId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> tokn_policy::ProviderId {
    tokn_policy::ProviderId::new(value).unwrap()
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

  fn provider(driver: &str) -> ProviderPlan {
    ProviderPlan::new(
      driver_id(driver),
      Some("https://gateway.example/v1/".into()),
      Box::default(),
      false,
    )
  }

  fn pool(providers: Option<&[&str]>, accounts: Option<&[&str]>) -> AccountPoolPlan {
    AccountPoolPlan::new(
      AccountSelector::new(
        providers.map(|ids| ids.iter().map(|id| provider_id(id)).collect()),
        accounts.map(|ids| ids.iter().map(SmolStr::new).collect()),
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
    providers: BTreeMap<tokn_policy::ProviderId, ProviderPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      pools,
      providers,
    )
  }

  fn link(plan: &GatewayPlan, accounts: &[AccountConfig]) -> PoolLinkResult<(ProviderGraph, LinkedAccountPools)> {
    let registry = Registry::builtin();
    let providers = link_provider_graph(plan, accounts, &registry).unwrap();
    let pools = link_account_pools(plan, &providers)?;
    Ok((providers, pools))
  }

  #[test]
  fn preserves_account_and_tier_order_with_one_provider_per_account() {
    let primary = provider_id("z-primary");
    let secondary = provider_id("a-secondary");
    let plan = plan(
      BTreeMap::from([(pool_id("all"), pool(None, None))]),
      BTreeMap::from([
        (primary.clone(), provider(ID_LLAMA_CPP)),
        (secondary.clone(), provider(ID_LLAMA_CPP)),
      ]),
    );
    let accounts = [
      account("fallback-first", primary.as_str(), AccountTier::Fallback),
      account("active-second", secondary.as_str(), AccountTier::Active),
      account("active-third", primary.as_str(), AccountTier::Active),
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
    assert_eq!(pool.active()[0].binding().provider_id(), &secondary);
    assert_eq!(pool.active()[1].binding().provider_id(), &primary);
    assert_eq!(pool.strategy(), AccountSelectionStrategy::RoundRobin);
    assert_eq!(pool.failure_cooldown(), Duration::from_secs(17));
    assert_eq!(pool.session_affinity().unwrap().ttl(), Duration::from_secs(23));
  }

  #[test]
  fn intersects_provider_and_account_selectors() {
    let selected = account("selected", "llama", AccountTier::Active);
    let omitted_by_account = account("omitted-account", "llama", AccountTier::Active);
    let omitted_by_provider = account("omitted-provider", "openai", AccountTier::Active);
    let plan = plan(
      BTreeMap::from([(
        pool_id("selected"),
        pool(Some(&["llama"]), Some(&["selected", "omitted-provider"])),
      )]),
      BTreeMap::from([
        (provider_id("llama"), provider(ID_LLAMA_CPP)),
        (provider_id("openai"), provider(ID_OPENAI)),
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
    let provider_id = provider_id("local");
    let plan = plan(
      BTreeMap::from([
        (pool_id("first"), pool(None, None)),
        (pool_id("second"), pool(None, Some(&["shared"]))),
      ]),
      BTreeMap::from([(provider_id.clone(), provider(ID_LLAMA_CPP))]),
    );

    let (providers, linked) = link(&plan, &[account("shared", "local", AccountTier::Active)]).unwrap();
    let graph_binding = providers.binding(&provider_id, "shared").unwrap();
    let first = linked.pool(&pool_id("first")).unwrap().active()[0].binding();
    let second = linked.pool(&pool_id("second")).unwrap().active()[0].binding();

    assert!(Arc::ptr_eq(graph_binding, first));
    assert!(Arc::ptr_eq(first, second));
  }

  #[test]
  fn validates_explicit_account_names() {
    let unknown_account_plan = plan(
      BTreeMap::from([(pool_id("invalid-account"), pool(None, Some(&["missing"])))]),
      BTreeMap::new(),
    );
    let account_error = link(&unknown_account_plan, &[]).err().unwrap();
    assert!(matches!(
      account_error,
      PoolLinkError::UnknownAccount { pool, account_id }
        if pool.as_str() == "invalid-account" && account_id == "missing"
    ));
  }

  #[test]
  fn known_disabled_accounts_are_valid_but_omitted() {
    let mut disabled = account("disabled", "llama", AccountTier::Active);
    disabled.enabled = false;
    let plan = plan(
      BTreeMap::from([(pool_id("empty"), pool(None, Some(&["disabled"])))]),
      BTreeMap::from([(provider_id("llama"), provider(ID_LLAMA_CPP))]),
    );

    let (_, linked) = link(&plan, &[disabled]).unwrap();
    let empty = linked.pool(&pool_id("empty")).unwrap();

    assert!(empty.is_empty());
  }

  #[test]
  fn provider_selector_filters_account_bindings() {
    let first = provider_id("first");
    let second = provider_id("second");
    let plan = plan(
      BTreeMap::from([(pool_id("first-only"), pool(Some(&["first"]), None))]),
      BTreeMap::from([
        (first.clone(), provider(ID_LLAMA_CPP)),
        (second, provider(ID_LLAMA_CPP)),
      ]),
    );

    let (_, linked) = link(
      &plan,
      &[
        account("selected", "first", AccountTier::Active),
        account("omitted", "second", AccountTier::Active),
      ],
    )
    .unwrap();
    let pool = linked.pool(&pool_id("first-only")).unwrap();
    assert_eq!(pool.active().len(), 1);
    assert_eq!(pool.active()[0].account_id(), "selected");
    assert_eq!(pool.active()[0].binding().provider_id(), &first);
  }
}

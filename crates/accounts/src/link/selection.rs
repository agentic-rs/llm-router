//! Pool-local runtime selection for linked v2 account pools.
//!
//! Immutable provider bindings can be shared by many pools. Selection state
//! cannot: round-robin position, cooldown history, and session affinity all
//! have pool-local policy semantics. [`AccountPoolRuntimes`] therefore owns
//! exactly one shared runtime per linked pool for routes to reuse.

use super::{LinkedAccountPool, LinkedAccountPools, LinkedPoolAccount, ProviderBinding, ProviderBindingKey};
use crate::affinity::{Affinity, Lookup};
use parking_lot::Mutex;
use smol_str::SmolStr;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokn_policy::{AccountPoolId, UpstreamId};

const MAX_COOLDOWN_EXPONENT: u32 = 5;

/// Selection result for one request.
#[derive(Clone, Debug)]
pub enum PoolAcquire {
  Selected(Arc<ProviderBinding>),
  CoolingDown { retry_at: Instant },
  NoEligible,
}

/// Failures from mutating pool-local selection state.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum PoolRuntimeError {
  #[snafu(display(
    "account pool '{pool}' does not contain binding for upstream '{upstream}' and account '{account_id}'"
  ))]
  UnknownBinding {
    pool: AccountPoolId,
    upstream: UpstreamId,
    account_id: SmolStr,
  },
}

pub type PoolRuntimeResult<T> = std::result::Result<T, PoolRuntimeError>;

/// Shared runtime ownership for every linked account pool.
pub struct AccountPoolRuntimes {
  runtimes: BTreeMap<AccountPoolId, Arc<AccountPoolRuntime>>,
}

impl AccountPoolRuntimes {
  pub fn runtime(&self, pool_id: &AccountPoolId) -> Option<&Arc<AccountPoolRuntime>> {
    self.runtimes.get(pool_id)
  }

  pub fn runtimes(&self) -> impl ExactSizeIterator<Item = (&AccountPoolId, &Arc<AccountPoolRuntime>)> {
    self.runtimes.iter()
  }

  pub fn len(&self) -> usize {
    self.runtimes.len()
  }

  pub fn is_empty(&self) -> bool {
    self.runtimes.is_empty()
  }
}

impl std::fmt::Debug for AccountPoolRuntimes {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.debug_map().entries(&self.runtimes).finish()
  }
}

/// Create one shared runtime for every linked pool.
pub fn build_account_pool_runtimes(pools: &LinkedAccountPools) -> AccountPoolRuntimes {
  let runtimes = pools
    .pools()
    .map(|(pool_id, pool)| (pool_id.clone(), Arc::new(AccountPoolRuntime::new(pool.clone()))))
    .collect();
  AccountPoolRuntimes { runtimes }
}

/// Mutable selection state scoped to one linked account pool.
pub struct AccountPoolRuntime {
  pool: Arc<LinkedAccountPool>,
  bindings: BTreeMap<ProviderBindingKey, Arc<ProviderBinding>>,
  active_cursor: AtomicUsize,
  fallback_cursor: AtomicUsize,
  cooldowns: Mutex<BTreeMap<ProviderBindingKey, BindingCooldown>>,
  affinity: Option<Affinity<ProviderBindingKey>>,
}

impl AccountPoolRuntime {
  fn new(pool: Arc<LinkedAccountPool>) -> Self {
    let mut bindings = BTreeMap::new();
    for binding in pool
      .active()
      .iter()
      .chain(pool.fallback())
      .flat_map(|account| account.bindings().values())
    {
      let previous = bindings.insert(binding.key().clone(), binding.clone());
      debug_assert!(previous.is_none(), "linked pool contains a duplicate provider binding");
    }
    let cooldowns = bindings
      .keys()
      .cloned()
      .map(|key| (key, BindingCooldown::default()))
      .collect();
    let affinity = pool.session_affinity().map(Affinity::from_session_plan);

    Self {
      pool,
      bindings,
      active_cursor: AtomicUsize::new(0),
      fallback_cursor: AtomicUsize::new(0),
      cooldowns: Mutex::new(cooldowns),
      affinity,
    }
  }

  pub fn pool(&self) -> &Arc<LinkedAccountPool> {
    &self.pool
  }

  /// Select a binding while leaving affinity and cooldown state untouched.
  ///
  /// The predicate owns route-, operation-, and model-specific eligibility.
  /// It is evaluated synchronously and outside all selection-state locks.
  pub fn acquire<F>(&self, session_id: Option<&str>, eligible: F) -> PoolAcquire
  where
    F: Fn(&ProviderBinding) -> bool,
  {
    let now = Instant::now();
    let cooling_bindings = self.cooling_bindings(now);

    if let (Some(session_id), Some(affinity)) = (session_id, self.affinity.as_ref()) {
      if let Lookup::Hit(key) = affinity.lookup(session_id) {
        if let Some(binding) = self.bindings.get(&key) {
          if eligible(binding) && !cooling_bindings.contains_key(&key) {
            return PoolAcquire::Selected(binding.clone());
          }
        }
      }
    }

    let mut earliest_retry = None;
    if let Some(binding) = self.select_tier(
      self.pool.active(),
      &self.active_cursor,
      &eligible,
      &cooling_bindings,
      &mut earliest_retry,
    ) {
      return PoolAcquire::Selected(binding);
    }
    if let Some(binding) = self.select_tier(
      self.pool.fallback(),
      &self.fallback_cursor,
      &eligible,
      &cooling_bindings,
      &mut earliest_retry,
    ) {
      return PoolAcquire::Selected(binding);
    }

    match earliest_retry {
      Some(retry_at) => PoolAcquire::CoolingDown { retry_at },
      None => PoolAcquire::NoEligible,
    }
  }

  /// Commit a successful binding use.
  ///
  /// Success clears this pool's cooldown history for the exact tuple and, if
  /// configured, creates or refreshes affinity only after the caller confirms
  /// the upstream operation succeeded.
  pub fn record_success(&self, session_id: Option<&str>, key: &ProviderBindingKey) -> PoolRuntimeResult<()> {
    {
      let mut cooldowns = self.cooldowns.lock();
      let cooldown = cooldowns.get_mut(key).ok_or_else(|| self.unknown_binding(key))?;
      *cooldown = BindingCooldown::default();
    }

    if let (Some(session_id), Some(affinity)) = (session_id, self.affinity.as_ref()) {
      affinity.record(session_id, key.clone());
    }
    Ok(())
  }

  /// Record one failure and cool only this pool's exact account/upstream
  /// tuple. Returns the new retry deadline for logging or scheduling.
  pub fn record_failure(&self, key: &ProviderBindingKey) -> PoolRuntimeResult<Instant> {
    let mut cooldowns = self.cooldowns.lock();
    let cooldown = cooldowns.get_mut(key).ok_or_else(|| self.unknown_binding(key))?;
    cooldown.consecutive_failures = cooldown.consecutive_failures.saturating_add(1);
    let duration = cooldown_duration(self.pool.failure_cooldown(), cooldown.consecutive_failures);
    let retry_at = saturating_instant_add(Instant::now(), duration);
    cooldown.retry_at = Some(retry_at);
    Ok(retry_at)
  }

  fn select_tier<F>(
    &self,
    accounts: &[LinkedPoolAccount],
    cursor: &AtomicUsize,
    eligible: &F,
    cooling_bindings: &BTreeMap<ProviderBindingKey, Instant>,
    earliest_retry: &mut Option<Instant>,
  ) -> Option<Arc<ProviderBinding>>
  where
    F: Fn(&ProviderBinding) -> bool,
  {
    if accounts.is_empty() {
      return None;
    }

    let mut candidates = Vec::new();
    for account in accounts {
      for binding in account.bindings().values() {
        if !eligible(binding) {
          continue;
        }
        match cooling_bindings.get(binding.key()).copied() {
          Some(retry_at) => retain_earliest(earliest_retry, retry_at),
          None => {
            candidates.push(binding.clone());
            break;
          }
        }
      }
    }

    if candidates.is_empty() {
      return None;
    }
    let index = cursor.fetch_add(1, Ordering::Relaxed) % candidates.len();
    Some(candidates.swap_remove(index))
  }

  fn cooling_bindings(&self, now: Instant) -> BTreeMap<ProviderBindingKey, Instant> {
    self
      .cooldowns
      .lock()
      .iter()
      .filter_map(|(key, cooldown)| {
        cooldown
          .retry_at
          .filter(|retry_at| *retry_at > now)
          .map(|retry_at| (key.clone(), retry_at))
      })
      .collect()
  }

  fn unknown_binding(&self, key: &ProviderBindingKey) -> PoolRuntimeError {
    PoolRuntimeError::UnknownBinding {
      pool: self.pool.id().clone(),
      upstream: key.upstream_id().clone(),
      account_id: SmolStr::new(key.account_id()),
    }
  }
}

impl std::fmt::Debug for AccountPoolRuntime {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("AccountPoolRuntime")
      .field("pool", &self.pool.id())
      .field("binding_count", &self.bindings.len())
      .finish_non_exhaustive()
  }
}

#[derive(Clone, Copy, Debug, Default)]
struct BindingCooldown {
  consecutive_failures: u32,
  retry_at: Option<Instant>,
}

fn cooldown_duration(base: Duration, consecutive_failures: u32) -> Duration {
  let exponent = consecutive_failures.saturating_sub(1).min(MAX_COOLDOWN_EXPONENT);
  base.saturating_mul(1_u32 << exponent)
}

fn saturating_instant_add(now: Instant, duration: Duration) -> Instant {
  if let Some(deadline) = now.checked_add(duration) {
    return deadline;
  }

  let mut lower_nanos = 0_u128;
  let mut upper_nanos = duration.as_nanos();
  while lower_nanos < upper_nanos {
    let midpoint = lower_nanos + (upper_nanos - lower_nanos).div_ceil(2);
    if now.checked_add(duration_from_nanos(midpoint)).is_some() {
      lower_nanos = midpoint;
    } else {
      upper_nanos = midpoint - 1;
    }
  }
  now.checked_add(duration_from_nanos(lower_nanos)).unwrap_or(now)
}

fn duration_from_nanos(nanos: u128) -> Duration {
  const NANOS_PER_SECOND: u128 = 1_000_000_000;
  Duration::new((nanos / NANOS_PER_SECOND) as u64, (nanos % NANOS_PER_SECOND) as u32)
}

fn retain_earliest(earliest: &mut Option<Instant>, candidate: Instant) {
  if earliest.is_none_or(|current| candidate < current) {
    *earliest = Some(candidate);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::link::{link_account_pools, link_provider_graph};
  use crate::registry::Registry;
  use smol_str::SmolStr;
  use std::collections::{BTreeMap, BTreeSet};
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_policy::{
    AccountPoolPlan, AccountSelectionStrategy, AccountSelector, GatewayPlan, ProviderId, SessionAffinityPlan,
    UpstreamPlan,
  };

  fn pool_id(value: &str) -> AccountPoolId {
    AccountPoolId::new(value).unwrap()
  }

  fn upstream_id(value: &str) -> UpstreamId {
    UpstreamId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
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

  fn upstream(eligible_accounts: &[&str]) -> UpstreamPlan {
    UpstreamPlan::new(
      provider_id(ID_LLAMA_CPP),
      Some("https://gateway.example/v1/".into()),
      Box::default(),
      false,
    )
    .with_eligible_accounts(
      (!eligible_accounts.is_empty()).then(|| eligible_accounts.iter().map(SmolStr::new).collect::<BTreeSet<_>>()),
    )
  }

  fn pool(accounts: Option<&[&str]>, affinity: Option<SessionAffinityPlan>) -> AccountPoolPlan {
    AccountPoolPlan::new(
      AccountSelector::new(
        None,
        accounts.map(|account_ids| account_ids.iter().map(SmolStr::new).collect()),
      ),
      AccountSelectionStrategy::RoundRobin,
      Duration::from_secs(60),
      affinity,
    )
  }

  fn runtimes(
    pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
    accounts: &[AccountConfig],
  ) -> AccountPoolRuntimes {
    let plan = GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      pools,
      upstreams,
      BTreeMap::new(),
    );
    let registry = Registry::builtin();
    let providers = link_provider_graph(&plan, accounts, &registry).unwrap();
    let pools = link_account_pools(&plan, &providers, &registry).unwrap();
    build_account_pool_runtimes(&pools)
  }

  fn selected(result: PoolAcquire) -> Arc<ProviderBinding> {
    let PoolAcquire::Selected(binding) = result else {
      panic!("expected selected binding, got {result:?}");
    };
    binding
  }

  #[test]
  fn round_robin_weights_logical_accounts_and_uses_typed_binding_order() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::from([
        (upstream_id("z-upstream"), upstream(&["first", "second"])),
        (upstream_id("a-upstream"), upstream(&["first"])),
      ]),
      &[
        account("first", AccountTier::Active),
        account("second", AccountTier::Active),
      ],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();

    let selected = (0..4)
      .map(|_| selected(runtime.acquire(None, |_| true)))
      .collect::<Vec<_>>();

    assert_eq!(
      selected.iter().map(|binding| binding.account_id()).collect::<Vec<_>>(),
      ["first", "second", "first", "second"]
    );
    assert_eq!(selected[0].upstream_id().as_str(), "a-upstream");
    assert_eq!(selected[2].upstream_id().as_str(), "a-upstream");
  }

  #[test]
  fn round_robin_is_fair_across_eligible_accounts_with_ineligible_gaps() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::from([(upstream_id("local"), upstream(&[]))]),
      &[
        account("first", AccountTier::Active),
        account("ineligible-one", AccountTier::Active),
        account("ineligible-two", AccountTier::Active),
        account("fourth", AccountTier::Active),
      ],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();

    let account_ids = (0..6)
      .map(|_| selected(runtime.acquire(None, |binding| matches!(binding.account_id(), "first" | "fourth"))))
      .map(|binding| binding.account_id().to_string())
      .collect::<Vec<_>>();

    assert_eq!(account_ids, ["first", "fourth", "first", "fourth", "first", "fourth"]);
  }

  #[test]
  fn active_tier_precedes_fallback_until_active_binding_is_cooled() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::from([(upstream_id("local"), upstream(&[]))]),
      &[
        account("active", AccountTier::Active),
        account("fallback", AccountTier::Fallback),
      ],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();

    let active = selected(runtime.acquire(None, |_| true));
    assert_eq!(active.account_id(), "active");
    runtime.record_failure(active.key()).unwrap();

    let fallback = selected(runtime.acquire(None, |_| true));
    assert_eq!(fallback.account_id(), "fallback");
  }

  #[test]
  fn affinity_is_written_only_on_success_and_pins_the_exact_binding() {
    let affinity = SessionAffinityPlan::new(Duration::from_secs(300), Duration::from_secs(60));
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, Some(affinity)))]),
      BTreeMap::from([
        (upstream_id("a-upstream"), upstream(&[])),
        (upstream_id("z-upstream"), upstream(&[])),
      ]),
      &[
        account("first", AccountTier::Active),
        account("second", AccountTier::Active),
      ],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();

    let uncommitted = selected(runtime.acquire(Some("session"), |_| true));
    assert_eq!(uncommitted.account_id(), "first");
    let next = selected(runtime.acquire(Some("session"), |_| true));
    assert_eq!(next.account_id(), "second");

    let exact_key = ProviderBindingKey::new(upstream_id("z-upstream"), "second");
    runtime.record_success(Some("session"), &exact_key).unwrap();
    let affinity_hit = selected(runtime.acquire(Some("session"), |_| true));
    assert_eq!(affinity_hit.key(), &exact_key);

    let fallthrough = selected(runtime.acquire(Some("session"), |binding| binding.key() != &exact_key));
    assert_ne!(fallthrough.key(), &exact_key);

    runtime.record_failure(&exact_key).unwrap();
    let cooled_fallthrough = selected(runtime.acquire(Some("session"), |_| true));
    assert_ne!(cooled_fallthrough.key(), &exact_key);

    runtime.record_success(Some("session"), &exact_key).unwrap();
    let recovered_affinity = selected(runtime.acquire(Some("session"), |_| true));
    assert_eq!(recovered_affinity.key(), &exact_key);
  }

  #[test]
  fn expired_affinity_falls_through_without_sleeping() {
    let immediately_expired = SessionAffinityPlan::new(Duration::ZERO, Duration::from_secs(60));
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, Some(immediately_expired)))]),
      BTreeMap::from([(upstream_id("local"), upstream(&[]))]),
      &[
        account("first", AccountTier::Active),
        account("second", AccountTier::Active),
      ],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();

    let first = selected(runtime.acquire(Some("session"), |_| true));
    runtime.record_success(Some("session"), first.key()).unwrap();
    let rebound = selected(runtime.acquire(Some("session"), |_| true));

    assert_eq!(first.account_id(), "first");
    assert_eq!(rebound.account_id(), "second");
  }

  #[test]
  fn cooldown_is_exact_to_binding_and_isolated_between_pools() {
    let runtimes = runtimes(
      BTreeMap::from([
        (pool_id("first"), pool(None, None)),
        (pool_id("second"), pool(None, None)),
      ]),
      BTreeMap::from([
        (upstream_id("a-upstream"), upstream(&[])),
        (upstream_id("z-upstream"), upstream(&[])),
      ]),
      &[account("shared", AccountTier::Active)],
    );
    let first_runtime = runtimes.runtime(&pool_id("first")).unwrap();
    let second_runtime = runtimes.runtime(&pool_id("second")).unwrap();
    let first_key = ProviderBindingKey::new(upstream_id("a-upstream"), "shared");

    first_runtime.record_failure(&first_key).unwrap();
    let same_pool_alternative = selected(first_runtime.acquire(None, |_| true));
    let other_pool = selected(second_runtime.acquire(None, |_| true));

    assert_eq!(same_pool_alternative.upstream_id().as_str(), "z-upstream");
    assert_eq!(other_pool.key(), &first_key);
  }

  #[test]
  fn all_cooled_returns_the_globally_earliest_retry() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::from([
        (upstream_id("first"), upstream(&[])),
        (upstream_id("second"), upstream(&[])),
      ]),
      &[account("only", AccountTier::Active)],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();
    let first_key = ProviderBindingKey::new(upstream_id("first"), "only");
    let second_key = ProviderBindingKey::new(upstream_id("second"), "only");
    runtime.record_failure(&first_key).unwrap();
    let later_retry = runtime.record_failure(&first_key).unwrap();
    let earliest_retry = runtime.record_failure(&second_key).unwrap();

    assert!(earliest_retry < later_retry);
    assert!(matches!(
      runtime.acquire(None, |_| true),
      PoolAcquire::CoolingDown { retry_at } if retry_at == earliest_retry
    ));
  }

  #[test]
  fn success_clears_only_the_exact_binding_cooldown() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::from([
        (upstream_id("first"), upstream(&[])),
        (upstream_id("second"), upstream(&[])),
      ]),
      &[account("only", AccountTier::Active)],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();
    let first_key = ProviderBindingKey::new(upstream_id("first"), "only");
    let second_key = ProviderBindingKey::new(upstream_id("second"), "only");
    runtime.record_failure(&first_key).unwrap();
    let second_retry = runtime.record_failure(&second_key).unwrap();

    runtime.record_success(None, &first_key).unwrap();

    assert_eq!(
      selected(runtime.acquire(None, |binding| binding.key() == &first_key)).key(),
      &first_key
    );
    assert!(matches!(
      runtime.acquire(None, |binding| binding.key() == &second_key),
      PoolAcquire::CoolingDown { retry_at } if retry_at == second_retry
    ));
  }

  #[test]
  fn no_matching_binding_returns_no_eligible() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::from([(upstream_id("local"), upstream(&[]))]),
      &[account("only", AccountTier::Active)],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();

    assert!(matches!(runtime.acquire(None, |_| false), PoolAcquire::NoEligible));
  }

  #[test]
  fn unknown_keys_never_mutate_runtime_state() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::from([(upstream_id("known"), upstream(&[]))]),
      &[account("known", AccountTier::Active)],
    );
    let runtime = runtimes.runtime(&pool_id("default")).unwrap();
    let known = ProviderBindingKey::new(upstream_id("known"), "known");
    let unknown = ProviderBindingKey::new(upstream_id("missing"), "missing");
    let known_retry = runtime.record_failure(&known).unwrap();

    assert!(matches!(
      runtime.record_failure(&unknown),
      Err(PoolRuntimeError::UnknownBinding { .. })
    ));
    assert!(matches!(
      runtime.record_success(Some("session"), &unknown),
      Err(PoolRuntimeError::UnknownBinding { .. })
    ));
    assert!(matches!(
      runtime.acquire(None, |_| true),
      PoolAcquire::CoolingDown { retry_at } if retry_at == known_retry
    ));
    assert_eq!(runtime.cooldowns.lock().len(), 1);
  }

  #[test]
  fn cooldown_backoff_caps_at_thirty_two_times_the_base() {
    let base = Duration::from_secs(3);
    assert_eq!(cooldown_duration(base, 1), Duration::from_secs(3));
    assert_eq!(cooldown_duration(base, 2), Duration::from_secs(6));
    assert_eq!(cooldown_duration(base, 5), Duration::from_secs(48));
    assert_eq!(cooldown_duration(base, 6), Duration::from_secs(96));
    assert_eq!(cooldown_duration(base, 7), Duration::from_secs(96));
    assert_eq!(cooldown_duration(base, u32::MAX), Duration::from_secs(96));
  }

  #[test]
  fn runtime_set_shares_one_runtime_arc_per_pool_lookup() {
    let runtimes = runtimes(
      BTreeMap::from([(pool_id("default"), pool(None, None))]),
      BTreeMap::new(),
      &[],
    );

    let first = runtimes.runtime(&pool_id("default")).unwrap();
    let second = runtimes.runtime(&pool_id("default")).unwrap();
    assert!(Arc::ptr_eq(first, second));
  }
}

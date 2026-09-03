use super::affinity::{Affinity, Lookup};
use super::handle::AccountHandle;
use super::inventory::{AccountInventory, AccountPoolRuleset};
use crate::routing::{RouteResolution, RouteSelector};
use snafu::Snafu;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokn_config::Config;
use tokn_core::account::{AccountConfig, AccountTier};
use tokn_core::provider::{Endpoint, Provider};
use tracing::{debug, info};

/// Errors that can occur while constructing or querying an [`AccountPool`].
///
/// Runtime acquisition (`AccountPool::acquire`) signals "no supporting
/// account" via `Option::None` rather than an error variant - that case is
/// load-bearing for the dispatcher's 501 mapping and not a failure.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
  #[snafu(display("no accounts configured. Run `tokn-router account add` first."))]
  NoAccounts,

  #[snafu(display("failed to build provider for account `{id}`"))]
  BuildAccount {
    id: String,
    source: tokn_core::provider::Error,
  },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct AccountPool {
  buckets: BTreeMap<String, ProviderBucket>,
  accounts: Vec<Arc<AccountHandle>>,
  cooldown_base: Duration,
  affinity: Affinity<String>,
}

struct ProviderBucket {
  provider: Arc<dyn Provider>,
  /// Accounts whose effective state is `Active`. Tried first, round-robin.
  accounts: Vec<Arc<AccountHandle>>,
  cursor: AtomicUsize,
  /// Accounts whose effective state is `Fallback`. Only consulted when
  /// every `Active` account in this bucket is unhealthy / cooled down.
  fallback_accounts: Vec<Arc<AccountHandle>>,
  fallback_cursor: AtomicUsize,
}

#[allow(dead_code)]
pub enum SessionAcquire {
  Account(Arc<AccountHandle>),
  SessionExpired,
  None,
}

pub enum EndpointAcquire {
  Account {
    acct: Arc<AccountHandle>,
    endpoint: Endpoint,
  },
  SessionExpired,
  None,
}

impl AccountPool {
  pub fn empty(cfg: &Config) -> Arc<Self> {
    Arc::new(Self {
      buckets: BTreeMap::new(),
      accounts: Vec::new(),
      cooldown_base: Duration::from_secs(cfg.pool.failure_cooldown_secs),
      affinity: Affinity::with_legacy_absolute_retention(
        Duration::from_secs(cfg.pool.session_ttl_secs),
        Duration::from_secs(cfg.pool.session_tombstone_secs),
      ),
    })
  }

  pub fn from_accounts_with<F>(accounts_in: &[AccountConfig], cfg: &Config, build_provider: F) -> Result<Arc<Self>>
  where
    F: Fn(Arc<AccountConfig>) -> tokn_core::provider::Result<Arc<dyn Provider>>,
  {
    let inventory = AccountInventory::from_accounts_with(accounts_in, build_provider)?;
    Self::from_inventory(&inventory, cfg, &AccountPoolRuleset::all())
  }

  pub fn from_inventory(inventory: &AccountInventory, cfg: &Config, ruleset: &AccountPoolRuleset) -> Result<Arc<Self>> {
    let accounts = inventory.filtered(ruleset);
    if accounts.is_empty() {
      return Ok(Self::empty(cfg));
    }
    Self::from_handles(accounts, cfg)
  }

  fn from_handles(accounts: Vec<Arc<AccountHandle>>, cfg: &Config) -> Result<Arc<Self>> {
    if accounts.is_empty() {
      return NoAccountsSnafu.fail();
    }
    let mut buckets: BTreeMap<String, ProviderBucket> = BTreeMap::new();
    for acct in &accounts {
      let account_cfg = acct.config.load();
      let provider = acct.provider.clone();
      debug!(account = %account_cfg.id, provider = %provider.info().id, tier = ?account_cfg.tier, "pool: added account");
      let bucket_key = provider.info().id.clone();
      let bucket = buckets.entry(bucket_key).or_insert_with(|| ProviderBucket {
        provider: provider.clone(),
        accounts: Vec::new(),
        cursor: AtomicUsize::new(0),
        fallback_accounts: Vec::new(),
        fallback_cursor: AtomicUsize::new(0),
      });
      match account_cfg.tier {
        AccountTier::Active => bucket.accounts.push(acct.clone()),
        AccountTier::Fallback => bucket.fallback_accounts.push(acct.clone()),
      }
    }
    info!(
      accounts = accounts.len(),
      providers = buckets.len(),
      cooldown_base_secs = cfg.pool.failure_cooldown_secs,
      "account pool initialised"
    );
    Ok(Arc::new(Self {
      buckets,
      accounts,
      cooldown_base: Duration::from_secs(cfg.pool.failure_cooldown_secs),
      affinity: Affinity::with_legacy_absolute_retention(
        Duration::from_secs(cfg.pool.session_ttl_secs),
        Duration::from_secs(cfg.pool.session_tombstone_secs),
      ),
    }))
  }

  pub fn len(&self) -> usize {
    self.accounts.len()
  }

  pub fn is_empty(&self) -> bool {
    self.accounts.is_empty()
  }

  pub fn cooldown_base(&self) -> Duration {
    self.cooldown_base
  }

  #[allow(dead_code)]
  pub fn acquire_for_session(
    &self,
    session_id: Option<&str>,
    model: Option<&str>,
    endpoint: Endpoint,
  ) -> SessionAcquire {
    if let Some(id) = session_id {
      match self.affinity.lookup(id) {
        Lookup::Hit(account_id) => {
          if let Some(acct) = self.account_by_id(&account_id) {
            if acct.is_healthy() && self.account_matches(&acct, model, endpoint) {
              self.record_session(id, &acct.id());
              return SessionAcquire::Account(acct);
            }
          }
        }
        Lookup::Expired => {}
        Lookup::Unknown => {}
      }
    }

    match self.acquire_from_buckets(model, endpoint) {
      Some(acct) => {
        if let Some(id) = session_id {
          self.record_session(id, &acct.id());
        }
        SessionAcquire::Account(acct)
      }
      None => SessionAcquire::None,
    }
  }

  pub fn acquire_for_session_convertible(
    &self,
    session_id: Option<&str>,
    model: Option<&str>,
    requested: Endpoint,
  ) -> EndpointAcquire {
    if let Some(id) = session_id {
      match self.affinity.lookup(id) {
        Lookup::Hit(account_id) => {
          if let Some(acct) = self.account_by_id(&account_id) {
            if acct.is_healthy() {
              if let Some(endpoint) = self.account_matching_endpoint(&acct, model, requested) {
                self.record_session(id, &acct.id());
                return EndpointAcquire::Account { acct, endpoint };
              }
            }
          }
        }
        Lookup::Expired => {}
        Lookup::Unknown => {}
      }
    }

    match self.acquire_from_buckets_convertible(model, requested) {
      Some((acct, endpoint)) => {
        if let Some(id) = session_id {
          self.record_session(id, &acct.id());
        }
        EndpointAcquire::Account { acct, endpoint }
      }
      None => EndpointAcquire::None,
    }
  }

  pub fn acquire_for_route(
    &self,
    session_id: Option<&str>,
    route: &RouteResolution,
    requested: Endpoint,
  ) -> EndpointAcquire {
    self.acquire_for_route_with_providers(session_id, route, requested, None)
  }

  /// Acquire an account while constraining candidates to providers allowed
  /// by the authenticated client. `None` means every provider is allowed.
  pub fn acquire_for_route_with_providers(
    &self,
    session_id: Option<&str>,
    route: &RouteResolution,
    requested: Endpoint,
    allowed_providers: Option<&BTreeSet<String>>,
  ) -> EndpointAcquire {
    if let Some(id) = session_id {
      match self.affinity.lookup(id) {
        Lookup::Hit(account_id) => {
          if let Some(acct) = self.account_by_id(&account_id) {
            if provider_is_allowed(acct.provider.info().id.as_str(), allowed_providers) && acct.is_healthy() {
              if let Some(endpoint) = self.account_matching_route_endpoint(&acct, route, requested) {
                self.record_session(id, &acct.id());
                return EndpointAcquire::Account { acct, endpoint };
              }
            }
          }
        }
        Lookup::Expired => {}
        Lookup::Unknown => {}
      }
    }

    match self.acquire_from_route(route, requested, allowed_providers) {
      Some((acct, endpoint)) => {
        if let Some(id) = session_id {
          self.record_session(id, &acct.id());
        }
        EndpointAcquire::Account { acct, endpoint }
      }
      None => EndpointAcquire::None,
    }
  }

  pub fn has_route_for_providers(
    &self,
    route: &RouteResolution,
    requested: Endpoint,
    allowed_providers: Option<&BTreeSet<String>>,
  ) -> bool {
    route_endpoint_order(route, requested).into_iter().any(|endpoint| {
      self.buckets.iter().any(|(provider_id, bucket)| {
        provider_is_allowed(provider_id, allowed_providers)
          && provider_matches_route(bucket.provider.as_ref(), route, endpoint)
      })
    })
  }

  pub fn acquire_provider(&self, session_id: Option<&str>, provider_id: &str) -> SessionAcquire {
    if let Some(id) = session_id {
      match self.affinity.lookup(id) {
        Lookup::Hit(account_id) => {
          if let Some(acct) = self.account_by_id(&account_id) {
            if acct.provider.info().id == provider_id && acct.is_healthy() {
              self.record_session(id, &acct.id());
              return SessionAcquire::Account(acct);
            }
          }
        }
        Lookup::Expired => {}
        Lookup::Unknown => {}
      }
    }

    let Some(bucket) = self.buckets.get(provider_id) else {
      return SessionAcquire::None;
    };
    let acct = bucket
      .pick_healthy()
      .or_else(|| bucket.pick_earliest_cooldown().map(|(acct, _)| acct));
    match acct {
      Some(acct) => {
        if let Some(id) = session_id {
          self.record_session(id, &acct.id());
        }
        SessionAcquire::Account(acct)
      }
      None => SessionAcquire::None,
    }
  }

  pub fn record_session(&self, session_id: &str, account_id: &str) {
    self.affinity.record(session_id, account_id);
  }

  #[cfg(test)]
  fn rewind_session_for_test(&self, session_id: &str, delta: Duration) -> bool {
    self.affinity.rewind_live_entry(session_id, delta)
  }

  pub fn all(&self) -> &[Arc<AccountHandle>] {
    &self.accounts
  }

  #[allow(dead_code)]
  fn acquire_from_buckets(&self, model: Option<&str>, endpoint: Endpoint) -> Option<Arc<AccountHandle>> {
    let mut candidates = Vec::new();
    for bucket in self.buckets.values() {
      if bucket.matches(model, endpoint) {
        candidates.push(bucket);
      }
    }

    for bucket in &candidates {
      if let Some(acct) = bucket.pick_healthy() {
        return Some(acct);
      }
    }

    let mut best: Option<Arc<AccountHandle>> = None;
    let mut best_t: Option<Instant> = None;
    for bucket in candidates {
      if let Some((acct, t)) = bucket.pick_earliest_cooldown() {
        if best.is_none() || t < best_t {
          best = Some(acct);
          best_t = t;
        }
      }
    }
    best
  }

  fn acquire_from_buckets_convertible(
    &self,
    model: Option<&str>,
    requested: Endpoint,
  ) -> Option<(Arc<AccountHandle>, Endpoint)> {
    for endpoint in fallback_order(requested) {
      let mut candidates = Vec::new();
      for bucket in self.buckets.values() {
        if bucket.matches(model, endpoint) {
          candidates.push(bucket);
        }
      }

      for bucket in &candidates {
        if let Some(acct) = bucket.pick_healthy() {
          return Some((acct, endpoint));
        }
      }

      let mut best: Option<Arc<AccountHandle>> = None;
      let mut best_t: Option<Instant> = None;
      for bucket in candidates {
        if let Some((acct, t)) = bucket.pick_earliest_cooldown() {
          if best.is_none() || t < best_t {
            best = Some(acct);
            best_t = t;
          }
        }
      }
      if let Some(acct) = best {
        return Some((acct, endpoint));
      }
    }
    None
  }

  fn account_by_id(&self, id: &str) -> Option<Arc<AccountHandle>> {
    self.accounts.iter().find(|a| a.config.load().id == id).cloned()
  }

  fn account_matches(&self, acct: &AccountHandle, model: Option<&str>, endpoint: Endpoint) -> bool {
    // `Provider::supports` now layers identity (`has_model`) and endpoint
    // checks itself, so the pool no longer pre-gates on
    // `model_info(...).is_some()`. Empty model means "any" — supports()
    // short-circuits the identity check in that case.
    let model = model.unwrap_or("");
    acct.provider.supports(model, endpoint)
  }

  fn account_matching_endpoint(
    &self,
    acct: &AccountHandle,
    model: Option<&str>,
    requested: Endpoint,
  ) -> Option<Endpoint> {
    fallback_order(requested)
      .into_iter()
      .find(|endpoint| self.account_matches(acct, model, *endpoint))
  }

  fn account_matching_route_endpoint(
    &self,
    acct: &AccountHandle,
    route: &RouteResolution,
    requested: Endpoint,
  ) -> Option<Endpoint> {
    route_endpoint_order(route, requested)
      .into_iter()
      .find(|endpoint| self.account_matches_route(acct, route, *endpoint))
  }

  fn account_matches_route(&self, acct: &AccountHandle, route: &RouteResolution, endpoint: Endpoint) -> bool {
    provider_matches_route(acct.provider.as_ref(), route, endpoint)
  }

  fn acquire_from_route(
    &self,
    route: &RouteResolution,
    requested: Endpoint,
    allowed_providers: Option<&BTreeSet<String>>,
  ) -> Option<(Arc<AccountHandle>, Endpoint)> {
    for endpoint in route_endpoint_order(route, requested) {
      let candidates = self
        .buckets
        .iter()
        .filter(|(provider_id, bucket)| {
          provider_is_allowed(provider_id, allowed_providers)
            && provider_matches_route(bucket.provider.as_ref(), route, endpoint)
        })
        .map(|(_, bucket)| bucket)
        .collect::<Vec<_>>();

      for bucket in &candidates {
        if let Some(acct) = bucket.pick_healthy() {
          return Some((acct, endpoint));
        }
      }

      let mut best: Option<Arc<AccountHandle>> = None;
      let mut best_t: Option<Instant> = None;
      for bucket in candidates {
        if let Some((acct, t)) = bucket.pick_earliest_cooldown() {
          if best.is_none() || t < best_t {
            best = Some(acct);
            best_t = t;
          }
        }
      }
      if let Some(acct) = best {
        return Some((acct, endpoint));
      }
    }
    None
  }
}

fn provider_is_allowed(provider_id: &str, allowed_providers: Option<&BTreeSet<String>>) -> bool {
  allowed_providers
    .map(|providers| providers.contains(provider_id))
    .unwrap_or(true)
}

fn provider_matches_route(provider: &dyn Provider, route: &RouteResolution, endpoint: Endpoint) -> bool {
  let verbatim = matches!(
    route.mode,
    tokn_config::RouteMode::Passthrough | tokn_config::RouteMode::Switch
  );
  let supports = |model: &str| {
    if verbatim {
      // Raw routes deliberately accept models outside the local catalogue,
      // but still must obey provider model-specific wire endpoint rules.
      provider.has_endpoint(&route.upstream_model, endpoint)
    } else {
      provider.supports(model, endpoint)
    }
  };
  match &route.selector {
    RouteSelector::Any => supports(&route.upstream_model),
    RouteSelector::Provider(provider_id) => provider.info().id == *provider_id && supports(&route.upstream_model),
    RouteSelector::Model => supports(&route.upstream_model),
    RouteSelector::Fuzzy { candidates } => {
      if verbatim {
        supports(&route.upstream_model)
      } else {
        candidates.iter().any(|candidate| supports(candidate))
      }
    }
  }
}

fn fallback_order(requested: Endpoint) -> Vec<Endpoint> {
  match requested {
    Endpoint::ChatCompletions => vec![Endpoint::ChatCompletions, Endpoint::Responses, Endpoint::Messages],
    Endpoint::Responses => vec![Endpoint::Responses, Endpoint::ChatCompletions, Endpoint::Messages],
    Endpoint::Messages => vec![Endpoint::Messages, Endpoint::ChatCompletions, Endpoint::Responses],
  }
}

fn route_endpoint_order(route: &RouteResolution, requested: Endpoint) -> Vec<Endpoint> {
  if matches!(
    route.mode,
    tokn_config::RouteMode::Passthrough | tokn_config::RouteMode::Switch
  ) {
    return vec![requested];
  }
  fallback_order(requested)
}

impl ProviderBucket {
  fn matches(&self, model: Option<&str>, endpoint: Endpoint) -> bool {
    let model = model.unwrap_or("");
    self.provider.supports(model, endpoint)
  }

  fn pick_healthy(&self) -> Option<Arc<AccountHandle>> {
    pick_healthy_rr(&self.accounts, &self.cursor)
      .or_else(|| pick_healthy_rr(&self.fallback_accounts, &self.fallback_cursor))
  }

  fn pick_earliest_cooldown(&self) -> Option<(Arc<AccountHandle>, Option<Instant>)> {
    earliest_cooldown(&self.accounts).or_else(|| earliest_cooldown(&self.fallback_accounts))
  }
}

fn pick_healthy_rr(accounts: &[Arc<AccountHandle>], cursor: &AtomicUsize) -> Option<Arc<AccountHandle>> {
  let n = accounts.len();
  if n == 0 {
    return None;
  }
  let start = cursor.fetch_add(1, Ordering::Relaxed);
  for i in 0..n {
    let idx = (start + i) % n;
    let a = &accounts[idx];
    if a.is_healthy() {
      return Some(a.clone());
    }
  }
  None
}

fn earliest_cooldown(accounts: &[Arc<AccountHandle>]) -> Option<(Arc<AccountHandle>, Option<Instant>)> {
  let mut best: Option<Arc<AccountHandle>> = None;
  let mut best_t: Option<Instant> = None;
  for a in accounts {
    let t = a.cooldown_until();
    if best.is_none() || t < best_t {
      best = Some(a.clone());
      best_t = t;
    }
  }
  best.map(|acct| (acct, best_t))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::routing::{RouteResolution, RouteResolver, RouteSelector};
  use async_trait::async_trait;
  use serde_json::Value;
  use tokn_core::provider::{
    AuthKind, Capabilities, EndpointRule, Interleaved, Limits, Modalities, ModelCache, ModelInfo, ProviderInfo,
    RequestCtx,
  };

  struct MockProvider {
    info: ProviderInfo,
    endpoint_rules: &'static [EndpointRule],
  }

  impl MockProvider {
    fn new(id: &str, aliases: &'static [&'static str], models: &[&str]) -> Arc<Self> {
      Self::with_endpoints(id, aliases, models, &[Endpoint::ChatCompletions], &[])
    }

    fn with_endpoints(
      id: &str,
      aliases: &'static [&'static str],
      models: &[&str],
      default_endpoints: &'static [Endpoint],
      endpoint_rules: &'static [EndpointRule],
    ) -> Arc<Self> {
      Arc::new(Self {
        info: ProviderInfo {
          id: id.into(),
          aliases,
          display_name: "mock",
          upstream_url: "https://mock.invalid".into(),
          auth_kind: AuthKind::StaticApiKey,
          default_models: models.iter().map(|m| model(m)).collect(),
          default_endpoints,
          model_cache: Arc::new(ModelCache::default()),
        },
        endpoint_rules,
      })
    }
  }

  #[async_trait]
  impl Provider for MockProvider {
    fn id(&self) -> &str {
      &self.info.id
    }

    fn info(&self) -> &ProviderInfo {
      &self.info
    }

    fn endpoint_rules(&self) -> Option<&'static [EndpointRule]> {
      Some(self.endpoint_rules)
    }

    async fn list_models(&self, _http: &reqwest::Client) -> tokn_core::provider::Result<Value> {
      Ok(serde_json::json!({ "object": "list", "data": [] }))
    }

    async fn chat(&self, _ctx: RequestCtx<'_>) -> tokn_core::provider::Result<reqwest::Response> {
      unreachable!()
    }
  }

  fn model(id: &str) -> ModelInfo {
    ModelInfo {
      id: id.into(),
      name: id.into(),
      capabilities: Capabilities {
        temperature: true,
        reasoning: false,
        reasoning_efforts: None,
        attachment: false,
        toolcall: true,
        input: Modalities::TEXT_ONLY,
        output: Modalities::TEXT_ONLY,
        interleaved: Interleaved::Disabled(false),
      },
      cost: None,
      limit: Limits { context: 1, output: 1 },
      release_date: None,
    }
  }

  fn acct(id: &str, provider: Arc<dyn Provider>) -> Arc<AccountHandle> {
    acct_tier(id, provider, AccountTier::Active)
  }

  fn acct_tier(id: &str, provider: Arc<dyn Provider>, tier: AccountTier) -> Arc<AccountHandle> {
    Arc::new(AccountHandle::new(
      Arc::new(AccountConfig {
        id: id.into(),
        provider: provider.info().id.clone(),
        enabled: true,
        tier,
        tags: Vec::new(),
        label: None,
        base_url: None,
        headers: BTreeMap::new(),
        auth_type: None,
        username: None,
        api_key: None,
        api_key_expires_at: None,
        access_token: None,
        access_token_expires_at: None,
        id_token: None,
        refresh_token: None,
        provider_account_id: None,
        extra: BTreeMap::new(),
        refresh_url: None,
        last_refresh: None,
        settings: toml::Table::new(),
      }),
      provider,
    ))
  }

  fn pool() -> AccountPool {
    pool_with_ttls(Duration::from_secs(60), Duration::from_secs(120))
  }

  fn pool_with_ttls(session_ttl: Duration, tombstone_ttl: Duration) -> AccountPool {
    static A: &[&str] = &["provider-a"];
    static B: &[&str] = &["provider-b"];
    let pa = MockProvider::new("provider-a", A, &["model-a"]);
    let pb = MockProvider::new("provider-b", B, &["model-b"]);
    let a1 = acct("a1", pa.clone());
    let a2 = acct("a2", pa.clone());
    let b1 = acct("b1", pb.clone());
    let mut buckets = BTreeMap::new();
    buckets.insert(
      "provider-a".into(),
      ProviderBucket {
        provider: pa,
        accounts: vec![a1.clone(), a2.clone()],
        cursor: AtomicUsize::new(0),
        fallback_accounts: Vec::new(),
        fallback_cursor: AtomicUsize::new(0),
      },
    );
    buckets.insert(
      "provider-b".into(),
      ProviderBucket {
        provider: pb,
        accounts: vec![b1.clone()],
        cursor: AtomicUsize::new(0),
        fallback_accounts: Vec::new(),
        fallback_cursor: AtomicUsize::new(0),
      },
    );
    AccountPool {
      buckets,
      accounts: vec![a1, a2, b1],
      cooldown_base: Duration::from_secs(1),
      affinity: Affinity::with_legacy_absolute_retention(session_ttl, tombstone_ttl),
    }
  }

  fn pool_for_provider(provider: Arc<dyn Provider>) -> AccountPool {
    let account = acct("only", provider.clone());
    let provider_id = provider.info().id.clone();
    let mut buckets = BTreeMap::new();
    buckets.insert(
      provider_id,
      ProviderBucket {
        provider,
        accounts: vec![account.clone()],
        cursor: AtomicUsize::new(0),
        fallback_accounts: Vec::new(),
        fallback_cursor: AtomicUsize::new(0),
      },
    );
    AccountPool {
      buckets,
      accounts: vec![account],
      cooldown_base: Duration::from_secs(1),
      affinity: Affinity::with_legacy_absolute_retention(Duration::from_secs(60), Duration::from_secs(120)),
    }
  }

  #[test]
  fn routes_by_provider_model_catalogue() {
    let p = pool();
    for _ in 0..8 {
      let SessionAcquire::Account(a) = p.acquire_for_session(None, Some("model-a"), Endpoint::ChatCompletions) else {
        panic!("expected provider-a account");
      };
      assert!(a.id().starts_with('a'), "wrong account: {}", a.id());
    }
    for _ in 0..8 {
      let SessionAcquire::Account(a) = p.acquire_for_session(None, Some("model-b"), Endpoint::ChatCompletions) else {
        panic!("expected provider-b account");
      };
      assert_eq!(a.id(), "b1");
    }
    assert!(matches!(
      p.acquire_for_session(None, Some("unknown"), Endpoint::ChatCompletions),
      SessionAcquire::None
    ));
  }

  #[test]
  fn verbatim_routes_require_the_requested_endpoint_and_obey_model_endpoint_rules() {
    static RESPONSES_ONLY: &[Endpoint] = &[Endpoint::Responses];
    static MODEL_A_RESPONSES_ONLY: &[EndpointRule] = &[EndpointRule {
      pattern: "model-a",
      endpoints: RESPONSES_ONLY,
    }];
    static PROVIDER: &[&str] = &["provider-a"];

    // Route mode may convert OpenAI Chat traffic to a provider's Responses
    // endpoint. A raw switch must not do that conversion.
    let responses_only = MockProvider::with_endpoints("responses-only", PROVIDER, &["model-a"], RESPONSES_ONLY, &[]);
    let pool = pool_for_provider(responses_only);
    let route = RouteResolver::new(tokn_config::RouteMode::Route, &[])
      .resolve("model-a", None)
      .unwrap();
    assert!(matches!(
      pool.acquire_for_route(None, &route, Endpoint::ChatCompletions),
      EndpointAcquire::Account {
        endpoint: Endpoint::Responses,
        ..
      }
    ));
    let switch =
      RouteResolver::with_default_provider(tokn_config::RouteMode::Switch, Some("responses-only".into()), &[])
        .resolve("model-a", None)
        .unwrap();
    pool.record_session("switch-session", "only");
    assert!(matches!(
      pool.acquire_for_route(Some("switch-session"), &switch, Endpoint::ChatCompletions),
      EndpointAcquire::None
    ));

    // A raw provider selector intentionally skips catalogue identity checks,
    // but its model-specific endpoint restrictions still apply.
    let rule_bound = MockProvider::with_endpoints(
      "rule-bound",
      PROVIDER,
      &[],
      &[Endpoint::ChatCompletions],
      MODEL_A_RESPONSES_ONLY,
    );
    let pool = pool_for_provider(rule_bound);
    let provider_switch =
      RouteResolver::with_default_provider(tokn_config::RouteMode::Switch, Some("rule-bound".into()), &[])
        .resolve("model-a", None)
        .unwrap();
    assert!(matches!(
      pool.acquire_for_route(None, &provider_switch, Endpoint::ChatCompletions),
      EndpointAcquire::None
    ));

    // Keep manually constructed route resolutions subject to the same raw
    // endpoint guard; future resolver changes cannot reopen conversion here.
    for selector in [
      RouteSelector::Model,
      RouteSelector::Fuzzy {
        candidates: vec!["model-a".into()],
      },
      RouteSelector::Any,
    ] {
      let route = RouteResolution {
        mode: tokn_config::RouteMode::Switch,
        requested_model: "model-a".into(),
        upstream_model: "model-a".into(),
        selector,
      };
      assert!(matches!(
        pool.acquire_for_route(None, &route, Endpoint::ChatCompletions),
        EndpointAcquire::None
      ));
    }
  }

  #[test]
  fn session_affinity_reuses_recorded_account() {
    let p = pool();
    let SessionAcquire::Account(first) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
    else {
      panic!("expected account");
    };
    for _ in 0..4 {
      let SessionAcquire::Account(next) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
      else {
        panic!("expected account");
      };
      assert_eq!(next.id(), first.id());
    }
  }

  #[test]
  fn session_hit_refreshes_ttl() {
    let p = pool_with_ttls(Duration::from_millis(120), Duration::from_millis(240));
    let SessionAcquire::Account(first) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
    else {
      panic!("expected account");
    };

    assert!(p.rewind_session_for_test("s1", Duration::from_millis(80)));
    let SessionAcquire::Account(second) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
    else {
      panic!("expected refreshed account");
    };
    assert_eq!(second.id(), first.id());

    assert!(p.rewind_session_for_test("s1", Duration::from_millis(80)));
    let SessionAcquire::Account(third) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
    else {
      panic!("expected session to stay alive after refresh");
    };
    assert_eq!(third.id(), first.id());
  }

  #[test]
  fn expired_session_rebinds_instead_of_failing() {
    let p = pool_with_ttls(Duration::from_millis(60), Duration::from_millis(240));
    let SessionAcquire::Account(first) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
    else {
      panic!("expected account");
    };

    assert!(p.rewind_session_for_test("s1", Duration::from_millis(80)));
    let SessionAcquire::Account(second) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
    else {
      panic!("expected expired session to rebind");
    };
    assert_ne!(first.id(), second.id());

    let SessionAcquire::Account(third) = p.acquire_for_session(Some("s1"), Some("model-a"), Endpoint::ChatCompletions)
    else {
      panic!("expected rebound session affinity");
    };
    assert_eq!(third.id(), second.id());
  }

  #[test]
  fn expired_provider_session_rebinds_instead_of_failing() {
    let p = pool_with_ttls(Duration::from_millis(60), Duration::from_millis(240));
    let SessionAcquire::Account(first) = p.acquire_provider(Some("s1"), "provider-a") else {
      panic!("expected provider account");
    };

    assert!(p.rewind_session_for_test("s1", Duration::from_millis(80)));
    let SessionAcquire::Account(second) = p.acquire_provider(Some("s1"), "provider-a") else {
      panic!("expected expired provider session to rebind");
    };
    assert_ne!(first.id(), second.id());

    let SessionAcquire::Account(third) = p.acquire_provider(Some("s1"), "provider-a") else {
      panic!("expected rebound provider session affinity");
    };
    assert_eq!(third.id(), second.id());
  }

  #[test]
  fn ruleset_restricts_pool_to_allowed_account_ids() {
    let p = pool();
    let inventory = AccountInventory::from_handles_for_test(p.all().to_vec());
    let filtered = AccountPool::from_inventory(
      &inventory,
      &Config::default(),
      &AccountPoolRuleset {
        providers: None,
        accounts: Some(["a2".to_string()].into_iter().collect()),
      },
    )
    .unwrap();
    let route = RouteResolver::new(tokn_config::RouteMode::Route, &[])
      .resolve("model-a", None)
      .unwrap();

    for _ in 0..4 {
      let EndpointAcquire::Account { acct, .. } = filtered.acquire_for_route(None, &route, Endpoint::ChatCompletions)
      else {
        panic!("expected allowed account");
      };
      assert_eq!(acct.id(), "a2");
    }
  }

  #[test]
  fn ruleset_restricts_pool_to_allowed_provider_ids() {
    let p = pool();
    let inventory = AccountInventory::from_handles_for_test(p.all().to_vec());
    let filtered = AccountPool::from_inventory(
      &inventory,
      &Config::default(),
      &AccountPoolRuleset {
        providers: Some(["provider-b".to_string()].into_iter().collect()),
        accounts: None,
      },
    )
    .unwrap();
    let route = RouteResolver::new(tokn_config::RouteMode::Route, &[])
      .resolve("model-b", None)
      .unwrap();

    let EndpointAcquire::Account { acct, .. } = filtered.acquire_for_route(None, &route, Endpoint::ChatCompletions)
    else {
      panic!("expected provider-b account");
    };
    assert_eq!(acct.provider.info().id, "provider-b");
    assert_eq!(acct.id(), "b1");
    assert_eq!(filtered.len(), 1);
  }

  #[test]
  fn per_request_provider_allowlist_constrains_routing_and_affinity() {
    let p = pool();
    let route_a = RouteResolver::new(tokn_config::RouteMode::Route, &[])
      .resolve("model-a", None)
      .unwrap();
    let route_b = RouteResolver::new(tokn_config::RouteMode::Route, &[])
      .resolve("model-b", None)
      .unwrap();
    let only_a = ["provider-a".to_string()].into_iter().collect();
    let only_b = ["provider-b".to_string()].into_iter().collect();

    let EndpointAcquire::Account { acct, .. } = p.acquire_for_route_with_providers(
      Some("shared-session"),
      &route_a,
      Endpoint::ChatCompletions,
      Some(&only_a),
    ) else {
      panic!("expected provider-a account");
    };
    assert_eq!(acct.provider.info().id, "provider-a");

    assert!(matches!(
      p.acquire_for_route_with_providers(
        Some("shared-session"),
        &route_a,
        Endpoint::ChatCompletions,
        Some(&only_b),
      ),
      EndpointAcquire::None
    ));

    let EndpointAcquire::Account { acct, .. } = p.acquire_for_route_with_providers(
      Some("shared-session"),
      &route_b,
      Endpoint::ChatCompletions,
      Some(&only_b),
    ) else {
      panic!("expected provider-b account");
    };
    assert_eq!(acct.provider.info().id, "provider-b");
  }

  #[test]
  fn pools_built_from_inventory_share_account_health() {
    let p = pool();
    let inventory = AccountInventory::from_handles_for_test(p.all().to_vec());
    let all = AccountPool::from_inventory(&inventory, &Config::default(), &AccountPoolRuleset::all()).unwrap();
    let a1_only = AccountPool::from_inventory(
      &inventory,
      &Config::default(),
      &AccountPoolRuleset {
        providers: None,
        accounts: Some(["a1".to_string()].into_iter().collect()),
      },
    )
    .unwrap();
    let route = RouteResolver::new(tokn_config::RouteMode::Route, &[])
      .resolve("model-a", None)
      .unwrap();

    let EndpointAcquire::Account { acct: a1, .. } = a1_only.acquire_for_route(None, &route, Endpoint::ChatCompletions)
    else {
      panic!("expected a1 account");
    };
    assert_eq!(a1.id(), "a1");
    a1.mark_failure(Duration::from_secs(60));

    let EndpointAcquire::Account { acct, .. } = all.acquire_for_route(None, &route, Endpoint::ChatCompletions) else {
      panic!("expected fallback healthy account from shared inventory");
    };
    assert_eq!(acct.id(), "a2");
  }
}

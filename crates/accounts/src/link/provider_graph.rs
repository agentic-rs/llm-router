//! Runtime account bindings for the compiled v2 provider graph.
//!
//! This linker deliberately stops at `(provider, account)` bindings. Account
//! pools and routes are separate runtime-linking stages; folding them into this
//! graph would recreate the legacy inventory's loss of provider identity.

use crate::{registry::Registry, AccountHandle};
use smol_str::SmolStr;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::provider::{Error as ProviderError, Provider, ProviderTarget};
use tokn_core::upstream_url::{CleartextHttpPolicy, InvalidUpstreamUrl};
use tokn_policy::{DriverId, GatewayPlan, ProviderId};

/// The source of a provider URL selected during runtime linking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderUrlSource {
  Configured,
  DriverDefault,
}

impl std::fmt::Display for ProviderUrlSource {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Configured => formatter.write_str("configured"),
      Self::DriverDefault => formatter.write_str("driver default"),
    }
  }
}

/// Stable identity of one account binding under one configured provider.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderBindingKey {
  provider_id: ProviderId,
  account_id: SmolStr,
}

impl ProviderBindingKey {
  pub fn new(provider_id: ProviderId, account_id: impl AsRef<str>) -> Self {
    Self {
      provider_id,
      account_id: SmolStr::new(account_id.as_ref()),
    }
  }

  pub fn provider_id(&self) -> &ProviderId {
    &self.provider_id
  }

  pub fn account_id(&self) -> &str {
    self.account_id.as_str()
  }
}

/// A credential-bearing driver instance bound to one configured provider.
pub struct ProviderBinding {
  key: ProviderBindingKey,
  account: Arc<AccountConfig>,
  handle: Arc<AccountHandle>,
  account_order: usize,
}

impl ProviderBinding {
  pub fn key(&self) -> &ProviderBindingKey {
    &self.key
  }

  pub fn provider_id(&self) -> &ProviderId {
    self.key.provider_id()
  }

  pub fn account_id(&self) -> &str {
    self.key.account_id()
  }

  pub fn handle(&self) -> &Arc<AccountHandle> {
    &self.handle
  }

  pub fn account(&self) -> Arc<AccountConfig> {
    self.account.clone()
  }

  pub fn driver(&self) -> &Arc<dyn Provider> {
    &self.handle.provider
  }

  /// Zero-based position in the account input supplied to the linker.
  pub fn account_order(&self) -> usize {
    self.account_order
  }
}

impl std::fmt::Debug for ProviderBinding {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("ProviderBinding")
      .field("key", &self.key)
      .field("driver", &self.handle.provider.info().id)
      .field("account_order", &self.account_order)
      .finish()
  }
}

/// One loaded account and its single configured-provider binding, if enabled.
pub struct LinkedAccount {
  config: Arc<AccountConfig>,
  input_order: usize,
  binding: Option<Arc<ProviderBinding>>,
}

impl LinkedAccount {
  pub fn account_id(&self) -> &str {
    &self.config.id
  }

  pub fn config(&self) -> &Arc<AccountConfig> {
    &self.config
  }

  pub fn input_order(&self) -> usize {
    self.input_order
  }

  pub fn binding(&self) -> Option<&Arc<ProviderBinding>> {
    self.binding.as_ref()
  }
}

impl std::fmt::Debug for LinkedAccount {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("LinkedAccount")
      .field("account_id", &self.config.id)
      .field("input_order", &self.input_order)
      .field("binding", &self.binding)
      .finish()
  }
}

/// Immutable runtime ownership graph for provider targets and account bindings.
///
/// Binding identity is the complete `(provider id, account id)` tuple. Two
/// providers that happen to use the same driver or URL still own separate
/// targets and model caches, while all accounts under one provider share its
/// target.
pub struct ProviderGraph {
  targets: BTreeMap<ProviderId, ProviderTarget>,
  bindings: BTreeMap<ProviderBindingKey, Arc<ProviderBinding>>,
  accounts: Box<[LinkedAccount]>,
  account_indices: BTreeMap<SmolStr, usize>,
}

impl ProviderGraph {
  pub fn target(&self, provider: &ProviderId) -> Option<&ProviderTarget> {
    self.targets.get(provider)
  }

  pub fn targets(&self) -> impl ExactSizeIterator<Item = (&ProviderId, &ProviderTarget)> {
    self.targets.iter()
  }

  pub fn binding(&self, provider: &ProviderId, account_id: &str) -> Option<&Arc<ProviderBinding>> {
    self
      .bindings
      .get(&ProviderBindingKey::new(provider.clone(), account_id))
  }

  pub fn bindings(&self) -> impl ExactSizeIterator<Item = &Arc<ProviderBinding>> {
    self.bindings.values()
  }

  pub fn account(&self, account_id: &str) -> Option<&LinkedAccount> {
    self.account_indices.get(account_id).map(|index| &self.accounts[*index])
  }

  /// All loaded accounts in their original input order, including disabled or
  /// otherwise unbound accounts.
  pub fn accounts(&self) -> std::slice::Iter<'_, LinkedAccount> {
    self.accounts.iter()
  }

  pub fn target_count(&self) -> usize {
    self.targets.len()
  }

  pub fn binding_count(&self) -> usize {
    self.bindings.len()
  }

  pub fn is_empty(&self) -> bool {
    self.targets.is_empty()
  }
}

impl std::fmt::Debug for ProviderGraph {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("ProviderGraph")
      .field("targets", &self.targets)
      .field("bindings", &self.bindings)
      .field("accounts", &self.accounts)
      .finish()
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum LinkError {
  #[snafu(display("duplicate account id '{account_id}' at input positions {first_index} and {duplicate_index}"))]
  DuplicateAccountId {
    account_id: SmolStr,
    first_index: usize,
    duplicate_index: usize,
  },

  #[snafu(display("provider '{provider}' references unknown driver '{driver}'"))]
  UnknownDriver { provider: ProviderId, driver: DriverId },

  #[snafu(display("account '{account_id}' references unknown configured provider '{provider}'"))]
  UnknownAccountProvider { account_id: SmolStr, provider: SmolStr },

  #[snafu(display("provider '{provider}' has invalid {url_source} URL '{base_url}' for driver '{driver}': {source}"))]
  InvalidProviderUrl {
    provider: ProviderId,
    driver: DriverId,
    url_source: ProviderUrlSource,
    base_url: String,
    source: InvalidUpstreamUrl,
  },

  #[snafu(display("failed to bind account '{account_id}' to provider '{provider}' with driver '{driver}': {source}"))]
  BuildProvider {
    provider: ProviderId,
    account_id: SmolStr,
    driver: DriverId,
    source: Box<ProviderError>,
  },
}

pub type LinkResult<T> = std::result::Result<T, LinkError>;

/// Link each account to its single configured provider.
///
/// This function intentionally ignores `AccountConfig::base_url`: a v2
/// provider is the authoritative transport destination. It also does not
/// inspect routes or materialize account pools.
pub fn link_provider_graph(
  plan: &GatewayPlan,
  accounts: &[AccountConfig],
  registry: &Registry,
) -> LinkResult<ProviderGraph> {
  let mut accounts = prepare_accounts(accounts)?;
  let mut targets = BTreeMap::new();
  let mut bindings = BTreeMap::new();

  for (provider_id, provider) in plan.providers() {
    let driver_id = provider.driver();
    let descriptor = registry
      .resolve_driver(driver_id.as_str())
      .ok_or_else(|| LinkError::UnknownDriver {
        provider: provider_id.clone(),
        driver: driver_id.clone(),
      })?;
    let (base_url, url_source) = match provider.base_url() {
      Some(base_url) => (base_url, ProviderUrlSource::Configured),
      None => (descriptor.base_url, ProviderUrlSource::DriverDefault),
    };
    let cleartext_policy = if provider.allow_insecure_http() {
      CleartextHttpPolicy::Allow
    } else {
      CleartextHttpPolicy::LoopbackOnly
    };
    let target = ProviderTarget::parse(base_url, cleartext_policy).map_err(|source| LinkError::InvalidProviderUrl {
      provider: provider_id.clone(),
      driver: driver_id.clone(),
      url_source,
      base_url: base_url.to_string(),
      source,
    })?;
    targets.insert(provider_id.clone(), target);
  }

  for account in &mut accounts.entries {
    let provider_id = ProviderId::new(&account.config.provider).ok();
    let provider = provider_id.as_ref().and_then(|provider_id| plan.provider(provider_id));
    let (provider_id, provider) = provider_id
      .zip(provider)
      .ok_or_else(|| LinkError::UnknownAccountProvider {
        account_id: SmolStr::new(&account.config.id),
        provider: SmolStr::new(&account.config.provider),
      })?;
    if !account.config.enabled {
      continue;
    }

    let driver_id = provider.driver();
    let target = targets
      .get(&provider_id)
      .expect("every compiled provider target was linked")
      .clone();

    // Existing driver implementations inspect `AccountConfig::provider` as
    // their driver id. Keep the source config's named provider intact, while
    // presenting a normalized clone at the legacy driver boundary.
    let mut driver_config = (*account.config).clone();
    driver_config.provider = driver_id.to_string();
    let driver_config = Arc::new(driver_config);
    let driver = registry
      .build_at(driver_config.clone(), target)
      .map_err(|source| LinkError::BuildProvider {
        provider: provider_id.clone(),
        account_id: SmolStr::new(&account.config.id),
        driver: driver_id.clone(),
        source: Box::new(source),
      })?;
    let key = ProviderBindingKey::new(provider_id, &account.config.id);
    let binding = Arc::new(ProviderBinding {
      key: key.clone(),
      account: account.config.clone(),
      handle: Arc::new(AccountHandle::new(driver_config, driver)),
      account_order: account.input_order,
    });
    let previous = bindings.insert(key, binding.clone());
    debug_assert!(
      previous.is_none(),
      "duplicate provider binding passed account preflight"
    );
    account.binding = Some(binding);
  }

  let (accounts, account_indices) = accounts.finish();
  Ok(ProviderGraph {
    targets,
    bindings,
    accounts,
    account_indices,
  })
}

struct PreparedAccount {
  config: Arc<AccountConfig>,
  input_order: usize,
  binding: Option<Arc<ProviderBinding>>,
}

struct PreparedAccounts {
  entries: Vec<PreparedAccount>,
  indices: BTreeMap<SmolStr, usize>,
}

impl PreparedAccounts {
  fn finish(self) -> (Box<[LinkedAccount]>, BTreeMap<SmolStr, usize>) {
    let accounts = self
      .entries
      .into_iter()
      .map(|account| LinkedAccount {
        config: account.config,
        input_order: account.input_order,
        binding: account.binding,
      })
      .collect::<Vec<_>>()
      .into_boxed_slice();
    (accounts, self.indices)
  }
}

fn prepare_accounts(accounts: &[AccountConfig]) -> LinkResult<PreparedAccounts> {
  let mut indices = BTreeMap::<SmolStr, usize>::new();
  let mut entries = Vec::with_capacity(accounts.len());

  for (input_order, account) in accounts.iter().enumerate() {
    let account_id = SmolStr::new(&account.id);
    if let Some(first_index) = indices.insert(account_id.clone(), input_order) {
      return Err(LinkError::DuplicateAccountId {
        account_id,
        first_index,
        duplicate_index: input_order,
      });
    }
    entries.push(PreparedAccount {
      config: Arc::new(account.clone()),
      input_order,
      binding: None,
    });
  }

  Ok(PreparedAccounts { entries, indices })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::{BTreeMap, HashSet};
  use std::time::Duration;
  use tokn_auth::descriptor::ProviderDescriptor;
  use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
  use tokn_policy::ProviderPlan;

  fn id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
  }

  fn driver_id(value: &str) -> DriverId {
    DriverId::new(value).unwrap()
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

  fn plan(providers: BTreeMap<ProviderId, ProviderPlan>) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      providers,
      BTreeMap::new(),
    )
  }

  fn provider(base_url: Option<&str>) -> ProviderPlan {
    ProviderPlan::new(driver_id(ID_LLAMA_CPP), base_url.map(Into::into), Box::default(), false)
  }

  #[test]
  fn preserves_tuple_identity_and_target_cache_ownership() {
    let primary_id = id("primary");
    let secondary_id = id("secondary");
    let same_url = "https://gateway.example/v1/";
    let primary = provider(Some(same_url));
    let secondary = provider(Some(same_url));
    let gateway = plan(BTreeMap::from([
      (primary_id.clone(), primary),
      (secondary_id.clone(), secondary),
    ]));
    let mut first = account("first");
    first.provider = "primary".into();
    first.base_url = Some("https://ignored.example/v1".into());
    let mut second = account("second");
    second.provider = "primary".into();
    let mut other = account("other");
    other.provider = "secondary".into();
    let mut disabled = account("disabled");
    disabled.provider = "primary".into();
    disabled.enabled = false;

    let graph = link_provider_graph(&gateway, &[first, second, other, disabled], &Registry::builtin()).unwrap();

    assert_eq!(graph.target_count(), 2);
    assert_eq!(graph.binding_count(), 3);
    assert_eq!(graph.binding(&primary_id, "first").unwrap().account_order(), 0);
    assert_eq!(graph.binding(&primary_id, "second").unwrap().account_order(), 1);
    assert!(graph.binding(&secondary_id, "first").is_none());
    assert!(graph.binding(&secondary_id, "other").is_some());
    assert!(graph.binding(&primary_id, "disabled").is_none());
    assert_eq!(
      graph.accounts().map(LinkedAccount::account_id).collect::<Vec<_>>(),
      ["first", "second", "other", "disabled"]
    );
    assert!(graph.account("first").unwrap().binding().is_some());
    assert!(graph.account("second").unwrap().binding().is_some());
    assert!(graph.account("other").unwrap().binding().is_some());
    assert!(graph.account("disabled").unwrap().binding().is_none());

    let primary_target = graph.target(&primary_id).unwrap();
    let secondary_target = graph.target(&secondary_id).unwrap();
    let first_binding = graph.binding(&primary_id, "first").unwrap();
    let second_binding = graph.binding(&primary_id, "second").unwrap();
    let other_provider_binding = graph.binding(&secondary_id, "other").unwrap();
    let first_driver = first_binding.driver();
    let second_driver = second_binding.driver();
    let other_driver = other_provider_binding.driver();

    assert_eq!(first_binding.key().provider_id(), &primary_id);
    assert_eq!(first_binding.key().account_id(), "first");
    assert_eq!(first_driver.info().upstream_url, same_url);
    assert!(Arc::ptr_eq(
      &first_driver.info().model_cache,
      primary_target.model_cache()
    ));
    assert!(Arc::ptr_eq(
      &second_driver.info().model_cache,
      primary_target.model_cache()
    ));
    assert!(!Arc::ptr_eq(
      primary_target.model_cache(),
      secondary_target.model_cache()
    ));
    assert!(Arc::ptr_eq(
      &other_driver.info().model_cache,
      secondary_target.model_cache()
    ));

    primary_target
      .model_cache()
      .set(HashSet::from(["primary-only".to_string()]));
    assert!(primary_target.model_cache().contains("primary-only"));
    assert!(!secondary_target.model_cache().is_warm());

    assert!(!Arc::ptr_eq(second_binding.handle(), other_provider_binding.handle()));
    second_binding.handle().mark_failure(Duration::from_secs(60));
    assert!(!second_binding.handle().is_healthy());
    assert!(other_provider_binding.handle().is_healthy());

    let linked_first_config = graph.account("first").unwrap().config();
    let bound_first_config = first_binding.account();
    assert!(Arc::ptr_eq(linked_first_config, &bound_first_config));
    assert_eq!(bound_first_config.provider, "primary");
    assert_eq!(first_binding.handle().config.load().provider, ID_LLAMA_CPP);
  }

  #[test]
  fn rejects_duplicate_account_ids_before_building_bindings() {
    let gateway = plan(BTreeMap::from([(id("llama-cpp"), provider(None))]));
    let error = link_provider_graph(
      &gateway,
      &[account("duplicate"), account("duplicate")],
      &Registry::builtin(),
    )
    .err()
    .unwrap();

    assert!(matches!(
      error,
      LinkError::DuplicateAccountId {
        ref account_id,
        first_index: 0,
        duplicate_index: 1,
      } if account_id == "duplicate"
    ));
  }

  #[test]
  fn reports_unknown_driver_with_provider_context() {
    let provider_id = id("missing");
    let gateway = plan(BTreeMap::from([(
      provider_id.clone(),
      ProviderPlan::new(driver_id("not-installed"), None, Box::default(), false),
    )]));

    let error = link_provider_graph(&gateway, &[], &Registry::builtin()).err().unwrap();

    assert!(matches!(
      error,
      LinkError::UnknownDriver { provider, driver }
        if provider == provider_id && driver.as_str() == "not-installed"
    ));
  }

  #[test]
  fn rejects_unknown_account_providers_even_when_disabled_and_unbound() {
    let mut unknown = account("unknown");
    unknown.provider = "not-installed".into();
    unknown.enabled = false;

    let error = link_provider_graph(&plan(BTreeMap::new()), &[unknown], &Registry::builtin())
      .err()
      .unwrap();

    assert!(matches!(
      error,
      LinkError::UnknownAccountProvider {
        ref account_id,
        ref provider,
      } if account_id == "unknown" && provider == "not-installed"
    ));
  }

  #[test]
  fn retains_disabled_accounts_without_binding_them() {
    let provider_id = id("llama-cpp");
    let gateway = plan(BTreeMap::from([(provider_id.clone(), provider(None))]));
    let mut disabled = account("disabled");
    disabled.enabled = false;

    let graph = link_provider_graph(&gateway, &[disabled], &Registry::builtin()).unwrap();

    let linked = graph.account("disabled").unwrap();
    assert_eq!(linked.input_order(), 0);
    assert!(!linked.config().enabled);
    assert!(linked.binding().is_none());
    assert!(graph.binding(&provider_id, "disabled").is_none());
  }

  fn accept_account(_account: &AccountConfig) -> tokn_core::provider::Result<()> {
    Ok(())
  }

  fn unreachable_build(
    _account: Arc<AccountConfig>,
    _target: ProviderTarget,
  ) -> tokn_core::provider::Result<Arc<dyn Provider>> {
    unreachable!("invalid provider default must fail before provider construction")
  }

  fn never_matches(_host: &str, _path: &str, _id: &'static str) -> bool {
    false
  }

  static INVALID_DEFAULT: ProviderDescriptor = ProviderDescriptor {
    id: "invalid-default",
    display_name: "Invalid default fixture",
    hosts: &[],
    base_url: "http://upstream.example/v1",
    credentials: &[],
    endpoints: &[],
    model_endpoint_rules: Some(&[]),
    rewrites: &[],
    auth_urls: &[],
    matches_url: never_matches,
    validate: accept_account,
    build: unreachable_build,
    build_auth: None,
  };

  #[test]
  fn validates_driver_defaults_with_the_provider_cleartext_policy() {
    let provider_id = id("unsafe-default");
    let gateway = plan(BTreeMap::from([(
      provider_id.clone(),
      ProviderPlan::new(driver_id(INVALID_DEFAULT.id), None, Box::default(), false),
    )]));
    let mut registry = Registry::builtin();
    registry.register(&INVALID_DEFAULT);

    let error = link_provider_graph(&gateway, &[], &registry).err().unwrap();

    assert!(matches!(
      error,
      LinkError::InvalidProviderUrl {
        provider,
        url_source: ProviderUrlSource::DriverDefault,
        source: InvalidUpstreamUrl::InsecureHttp,
        ..
      } if provider == provider_id
    ));
  }

  #[test]
  fn allows_an_explicit_provider_url_to_override_an_invalid_driver_default() {
    let provider_id = id("safe-override");
    let gateway = plan(BTreeMap::from([(
      provider_id.clone(),
      ProviderPlan::new(
        driver_id(INVALID_DEFAULT.id),
        Some("https://safe.example/v1/".into()),
        Box::default(),
        false,
      ),
    )]));
    let mut registry = Registry::builtin();
    registry.register(&INVALID_DEFAULT);

    let graph = link_provider_graph(&gateway, &[], &registry).unwrap();

    assert_eq!(
      graph.target(&provider_id).unwrap().base_url().as_str(),
      "https://safe.example/v1/"
    );
  }

  #[test]
  fn rejects_accounts_owned_by_an_unknown_provider() {
    let provider_id = id("local");
    let gateway = plan(BTreeMap::from([(provider_id, provider(None))]));
    let mut other = account("other");
    other.provider = "openai".into();

    let error = link_provider_graph(&gateway, &[other], &Registry::builtin()).unwrap_err();
    assert!(matches!(error, LinkError::UnknownAccountProvider { .. }));
  }

  #[test]
  fn binding_provider_capabilities_remain_available() {
    let provider_id = id("llama-cpp");
    let gateway = plan(BTreeMap::from([(provider_id.clone(), provider(None))]));

    let graph = link_provider_graph(&gateway, &[account("local")], &Registry::builtin()).unwrap();

    assert!(graph
      .binding(&provider_id, "local")
      .unwrap()
      .driver()
      .supports("", Endpoint::ChatCompletions));
  }
}

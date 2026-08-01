//! Runtime provider bindings for the compiled v2 upstream graph.
//!
//! This linker deliberately stops at `(upstream, account)` bindings. Account
//! pools and routes are separate runtime-linking stages; folding them into this
//! graph would recreate the legacy inventory's loss of upstream identity.

use crate::{registry::Registry, AccountHandle};
use smol_str::SmolStr;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::provider::{Error as ProviderError, Provider, ProviderTarget};
use tokn_core::upstream_url::{CleartextHttpPolicy, InvalidUpstreamUrl};
use tokn_policy::{GatewayPlan, ProviderId, UpstreamId};

/// The source of an upstream URL selected during runtime linking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamUrlSource {
  Configured,
  ProviderDefault,
}

impl std::fmt::Display for UpstreamUrlSource {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Configured => formatter.write_str("configured"),
      Self::ProviderDefault => formatter.write_str("provider default"),
    }
  }
}

/// Stable identity of one account binding under one configured upstream.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderBindingKey {
  upstream_id: UpstreamId,
  account_id: SmolStr,
}

impl ProviderBindingKey {
  pub fn new(upstream_id: UpstreamId, account_id: impl AsRef<str>) -> Self {
    Self {
      upstream_id,
      account_id: SmolStr::new(account_id.as_ref()),
    }
  }

  pub fn upstream_id(&self) -> &UpstreamId {
    &self.upstream_id
  }

  pub fn account_id(&self) -> &str {
    self.account_id.as_str()
  }
}

/// A credential-bearing provider bound to one configured upstream.
pub struct ProviderBinding {
  key: ProviderBindingKey,
  handle: Arc<AccountHandle>,
  account_order: usize,
}

impl ProviderBinding {
  pub fn key(&self) -> &ProviderBindingKey {
    &self.key
  }

  pub fn upstream_id(&self) -> &UpstreamId {
    self.key.upstream_id()
  }

  pub fn account_id(&self) -> &str {
    self.key.account_id()
  }

  pub fn handle(&self) -> &Arc<AccountHandle> {
    &self.handle
  }

  pub fn account(&self) -> Arc<AccountConfig> {
    self.handle.config.load_full()
  }

  pub fn provider(&self) -> &Arc<dyn Provider> {
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
      .field("provider", &self.handle.provider.info().id)
      .field("account_order", &self.account_order)
      .finish()
  }
}

/// One loaded account and every upstream-specific binding derived from it.
pub struct LinkedAccount {
  config: Arc<AccountConfig>,
  input_order: usize,
  bindings: Box<[Arc<ProviderBinding>]>,
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

  pub fn bindings(&self) -> &[Arc<ProviderBinding>] {
    &self.bindings
  }
}

impl std::fmt::Debug for LinkedAccount {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("LinkedAccount")
      .field("account_id", &self.config.id)
      .field("input_order", &self.input_order)
      .field("bindings", &self.bindings)
      .finish()
  }
}

/// Immutable runtime ownership graph for provider targets and account bindings.
///
/// Binding identity is the complete `(upstream id, account id)` tuple. Two
/// upstreams that happen to use the same URL still own separate targets and
/// model caches, while all bindings under one upstream share its target.
pub struct ProviderGraph {
  targets: BTreeMap<UpstreamId, ProviderTarget>,
  bindings: BTreeMap<ProviderBindingKey, Arc<ProviderBinding>>,
  accounts: Box<[LinkedAccount]>,
  account_indices: BTreeMap<SmolStr, usize>,
}

impl ProviderGraph {
  pub fn target(&self, upstream: &UpstreamId) -> Option<&ProviderTarget> {
    self.targets.get(upstream)
  }

  pub fn targets(&self) -> impl ExactSizeIterator<Item = (&UpstreamId, &ProviderTarget)> {
    self.targets.iter()
  }

  pub fn binding(&self, upstream: &UpstreamId, account_id: &str) -> Option<&Arc<ProviderBinding>> {
    self
      .bindings
      .get(&ProviderBindingKey::new(upstream.clone(), account_id))
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

  #[snafu(display("upstream '{upstream}' references unknown provider '{provider}'"))]
  UnknownProvider { upstream: UpstreamId, provider: ProviderId },

  #[snafu(display("account '{account_id}' references unknown provider '{provider}'"))]
  UnknownAccountProvider { account_id: SmolStr, provider: SmolStr },

  #[snafu(display(
    "upstream '{upstream}' for provider '{provider}' references unknown eligible account '{account_id}'"
  ))]
  UnknownEligibleAccount {
    upstream: UpstreamId,
    provider: ProviderId,
    account_id: SmolStr,
  },

  #[snafu(display(
    "upstream '{upstream}' for provider '{provider}' references account '{account_id}' owned by provider '{account_provider}'"
  ))]
  EligibleAccountProviderMismatch {
    upstream: UpstreamId,
    provider: ProviderId,
    account_id: SmolStr,
    account_provider: SmolStr,
  },

  #[snafu(display(
    "upstream '{upstream}' has invalid {url_source} URL '{base_url}' for provider '{provider}': {source}"
  ))]
  InvalidUpstreamUrl {
    upstream: UpstreamId,
    provider: ProviderId,
    url_source: UpstreamUrlSource,
    base_url: String,
    source: InvalidUpstreamUrl,
  },

  #[snafu(display(
    "failed to bind account '{account_id}' to upstream '{upstream}' for provider '{provider}': {source}"
  ))]
  BuildProvider {
    upstream: UpstreamId,
    account_id: SmolStr,
    provider: ProviderId,
    source: Box<ProviderError>,
  },
}

pub type LinkResult<T> = std::result::Result<T, LinkError>;

/// Link configured upstreams to all enabled, eligible matching-provider
/// accounts.
///
/// This function intentionally ignores `AccountConfig::base_url`: a v2
/// upstream is the authoritative transport destination. It also does not
/// inspect routes or materialize account pools.
pub fn link_provider_graph(
  plan: &GatewayPlan,
  accounts: &[AccountConfig],
  registry: &Registry,
) -> LinkResult<ProviderGraph> {
  let mut accounts = prepare_accounts(accounts)?;
  validate_account_providers(&accounts, registry)?;
  let mut targets = BTreeMap::new();
  let mut bindings = BTreeMap::new();

  for (upstream_id, upstream) in plan.upstreams() {
    let provider_id = upstream.provider();
    let descriptor = registry
      .resolve(provider_id.as_str())
      .ok_or_else(|| LinkError::UnknownProvider {
        upstream: upstream_id.clone(),
        provider: provider_id.clone(),
      })?;
    validate_eligible_accounts(upstream_id, upstream, provider_id, &accounts)?;
    let (base_url, url_source) = match upstream.base_url() {
      Some(base_url) => (base_url, UpstreamUrlSource::Configured),
      None => (descriptor.base_url, UpstreamUrlSource::ProviderDefault),
    };
    let cleartext_policy = if upstream.allow_insecure_http() {
      CleartextHttpPolicy::Allow
    } else {
      CleartextHttpPolicy::LoopbackOnly
    };
    let target = ProviderTarget::parse(base_url, cleartext_policy).map_err(|source| LinkError::InvalidUpstreamUrl {
      upstream: upstream_id.clone(),
      provider: provider_id.clone(),
      url_source,
      base_url: base_url.to_string(),
      source,
    })?;

    for account in &mut accounts.entries {
      if !account.config.enabled
        || account.config.provider != provider_id.as_str()
        || !upstream.permits_account(&account.config.id)
      {
        continue;
      }

      let provider = registry
        .build_at(account.config.clone(), target.clone())
        .map_err(|source| LinkError::BuildProvider {
          upstream: upstream_id.clone(),
          account_id: SmolStr::new(&account.config.id),
          provider: provider_id.clone(),
          source: Box::new(source),
        })?;
      let key = ProviderBindingKey::new(upstream_id.clone(), &account.config.id);
      let binding = Arc::new(ProviderBinding {
        key: key.clone(),
        handle: Arc::new(AccountHandle::new(account.config.clone(), provider)),
        account_order: account.input_order,
      });
      let previous = bindings.insert(key, binding.clone());
      debug_assert!(
        previous.is_none(),
        "duplicate provider binding passed account preflight"
      );
      account.bindings.push(binding);
    }

    targets.insert(upstream_id.clone(), target);
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
  bindings: Vec<Arc<ProviderBinding>>,
}

struct PreparedAccounts {
  entries: Vec<PreparedAccount>,
  indices: BTreeMap<SmolStr, usize>,
}

impl PreparedAccounts {
  fn get(&self, account_id: &str) -> Option<&PreparedAccount> {
    self.indices.get(account_id).map(|index| &self.entries[*index])
  }

  fn finish(self) -> (Box<[LinkedAccount]>, BTreeMap<SmolStr, usize>) {
    let accounts = self
      .entries
      .into_iter()
      .map(|account| LinkedAccount {
        config: account.config,
        input_order: account.input_order,
        bindings: account.bindings.into_boxed_slice(),
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
      bindings: Vec::new(),
    });
  }

  Ok(PreparedAccounts { entries, indices })
}

fn validate_account_providers(accounts: &PreparedAccounts, registry: &Registry) -> LinkResult<()> {
  for account in &accounts.entries {
    if registry.resolve(&account.config.provider).is_none() {
      return Err(LinkError::UnknownAccountProvider {
        account_id: SmolStr::new(&account.config.id),
        provider: SmolStr::new(&account.config.provider),
      });
    }
  }
  Ok(())
}

fn validate_eligible_accounts(
  upstream_id: &UpstreamId,
  upstream: &tokn_policy::UpstreamPlan,
  provider_id: &ProviderId,
  accounts: &PreparedAccounts,
) -> LinkResult<()> {
  let Some(eligible_accounts) = upstream.eligible_accounts() else {
    return Ok(());
  };

  for account_id in eligible_accounts {
    let account = accounts
      .get(account_id.as_str())
      .ok_or_else(|| LinkError::UnknownEligibleAccount {
        upstream: upstream_id.clone(),
        provider: provider_id.clone(),
        account_id: account_id.clone(),
      })?;
    if account.config.provider != provider_id.as_str() {
      return Err(LinkError::EligibleAccountProviderMismatch {
        upstream: upstream_id.clone(),
        provider: provider_id.clone(),
        account_id: account_id.clone(),
        account_provider: SmolStr::new(&account.config.provider),
      });
    }
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::{BTreeMap, BTreeSet, HashSet};
  use tokn_auth::descriptor::ProviderDescriptor;
  use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
  use tokn_policy::UpstreamPlan;

  fn id(value: &str) -> UpstreamId {
    UpstreamId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
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

  fn plan(upstreams: BTreeMap<UpstreamId, UpstreamPlan>) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      upstreams,
      BTreeMap::new(),
    )
  }

  fn upstream(base_url: Option<&str>) -> UpstreamPlan {
    UpstreamPlan::new(
      provider_id(ID_LLAMA_CPP),
      base_url.map(Into::into),
      Box::default(),
      false,
    )
  }

  #[test]
  fn preserves_tuple_identity_and_target_cache_ownership() {
    let primary_id = id("primary");
    let secondary_id = id("secondary");
    let same_url = "https://gateway.example/v1/";
    let primary = upstream(Some(same_url));
    let secondary = upstream(Some(same_url)).with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("second")])));
    let gateway = plan(BTreeMap::from([
      (primary_id.clone(), primary),
      (secondary_id.clone(), secondary),
    ]));
    let mut first = account("first");
    first.base_url = Some("https://ignored.example/v1".into());
    let second = account("second");
    let mut disabled = account("disabled");
    disabled.enabled = false;

    let graph = link_provider_graph(&gateway, &[first, second, disabled], &Registry::builtin()).unwrap();

    assert_eq!(graph.target_count(), 2);
    assert_eq!(graph.binding_count(), 3);
    assert_eq!(graph.binding(&primary_id, "first").unwrap().account_order(), 0);
    assert_eq!(graph.binding(&primary_id, "second").unwrap().account_order(), 1);
    assert!(graph.binding(&secondary_id, "first").is_none());
    assert!(graph.binding(&secondary_id, "second").is_some());
    assert!(graph.binding(&primary_id, "disabled").is_none());
    assert_eq!(
      graph.accounts().map(LinkedAccount::account_id).collect::<Vec<_>>(),
      ["first", "second", "disabled"]
    );
    assert_eq!(graph.account("first").unwrap().bindings().len(), 1);
    assert_eq!(graph.account("second").unwrap().bindings().len(), 2);
    assert!(graph.account("disabled").unwrap().bindings().is_empty());

    let primary_target = graph.target(&primary_id).unwrap();
    let secondary_target = graph.target(&secondary_id).unwrap();
    let first_binding = graph.binding(&primary_id, "first").unwrap();
    let second_binding = graph.binding(&primary_id, "second").unwrap();
    let other_upstream_binding = graph.binding(&secondary_id, "second").unwrap();
    let first_provider = first_binding.provider();
    let second_provider = second_binding.provider();
    let other_upstream_provider = other_upstream_binding.provider();

    assert_eq!(first_binding.key().upstream_id(), &primary_id);
    assert_eq!(first_binding.key().account_id(), "first");
    assert_eq!(first_provider.info().upstream_url, same_url);
    assert!(Arc::ptr_eq(
      &first_provider.info().model_cache,
      primary_target.model_cache()
    ));
    assert!(Arc::ptr_eq(
      &second_provider.info().model_cache,
      primary_target.model_cache()
    ));
    assert!(!Arc::ptr_eq(
      primary_target.model_cache(),
      secondary_target.model_cache()
    ));
    assert!(Arc::ptr_eq(
      &other_upstream_provider.info().model_cache,
      secondary_target.model_cache()
    ));

    primary_target
      .model_cache()
      .set(HashSet::from(["primary-only".to_string()]));
    assert!(primary_target.model_cache().contains("primary-only"));
    assert!(!secondary_target.model_cache().is_warm());

    assert!(!Arc::ptr_eq(second_binding.handle(), other_upstream_binding.handle()));

    let linked_first_config = graph.account("first").unwrap().config();
    let bound_first_config = first_binding.account();
    assert!(Arc::ptr_eq(linked_first_config, &bound_first_config));
  }

  #[test]
  fn rejects_duplicate_account_ids_before_building_bindings() {
    let gateway = plan(BTreeMap::from([(id("local"), upstream(None))]));
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
  fn reports_unknown_upstream_provider_with_context() {
    let upstream_id = id("missing");
    let gateway = plan(BTreeMap::from([(
      upstream_id.clone(),
      UpstreamPlan::new(provider_id("not-installed"), None, Box::default(), false),
    )]));

    let error = link_provider_graph(&gateway, &[], &Registry::builtin()).err().unwrap();

    assert!(matches!(
      error,
      LinkError::UnknownProvider { upstream, provider }
        if upstream == upstream_id && provider.as_str() == "not-installed"
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
  fn rejects_unknown_explicitly_eligible_accounts() {
    let upstream_id = id("local");
    let selected = upstream(None).with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("typo")])));
    let gateway = plan(BTreeMap::from([(upstream_id.clone(), selected)]));

    let error = link_provider_graph(&gateway, &[account("known")], &Registry::builtin())
      .err()
      .unwrap();

    assert!(matches!(
      error,
      LinkError::UnknownEligibleAccount {
        upstream,
        ref account_id,
        ..
      } if upstream == upstream_id && account_id == "typo"
    ));
  }

  #[test]
  fn rejects_explicitly_eligible_accounts_owned_by_another_provider() {
    let upstream_id = id("local");
    let selected = upstream(None).with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("foreign")])));
    let gateway = plan(BTreeMap::from([(upstream_id.clone(), selected)]));
    let mut foreign = account("foreign");
    foreign.provider = "openai".into();

    let error = link_provider_graph(&gateway, &[foreign], &Registry::builtin())
      .err()
      .unwrap();

    assert!(matches!(
      error,
      LinkError::EligibleAccountProviderMismatch {
        upstream,
        ref account_id,
        ref account_provider,
        ..
      } if upstream == upstream_id && account_id == "foreign" && account_provider == "openai"
    ));
  }

  #[test]
  fn retains_disabled_eligible_accounts_without_binding_them() {
    let upstream_id = id("local");
    let selected = upstream(None).with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("disabled")])));
    let gateway = plan(BTreeMap::from([(upstream_id.clone(), selected)]));
    let mut disabled = account("disabled");
    disabled.enabled = false;

    let graph = link_provider_graph(&gateway, &[disabled], &Registry::builtin()).unwrap();

    let linked = graph.account("disabled").unwrap();
    assert_eq!(linked.input_order(), 0);
    assert!(!linked.config().enabled);
    assert!(linked.bindings().is_empty());
    assert!(graph.binding(&upstream_id, "disabled").is_none());
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
  fn validates_provider_defaults_with_the_upstream_cleartext_policy() {
    let upstream_id = id("unsafe-default");
    let gateway = plan(BTreeMap::from([(
      upstream_id.clone(),
      UpstreamPlan::new(provider_id(INVALID_DEFAULT.id), None, Box::default(), false),
    )]));
    let mut registry = Registry::builtin();
    registry.register(&INVALID_DEFAULT);

    let error = link_provider_graph(&gateway, &[], &registry).err().unwrap();

    assert!(matches!(
      error,
      LinkError::InvalidUpstreamUrl {
        upstream,
        url_source: UpstreamUrlSource::ProviderDefault,
        source: InvalidUpstreamUrl::InsecureHttp,
        ..
      } if upstream == upstream_id
    ));
  }

  #[test]
  fn allows_an_explicit_upstream_to_override_an_invalid_default() {
    let upstream_id = id("safe-override");
    let gateway = plan(BTreeMap::from([(
      upstream_id.clone(),
      UpstreamPlan::new(
        provider_id(INVALID_DEFAULT.id),
        Some("https://safe.example/v1/".into()),
        Box::default(),
        false,
      ),
    )]));
    let mut registry = Registry::builtin();
    registry.register(&INVALID_DEFAULT);

    let graph = link_provider_graph(&gateway, &[], &registry).unwrap();

    assert_eq!(
      graph.target(&upstream_id).unwrap().base_url().as_str(),
      "https://safe.example/v1/"
    );
  }

  #[test]
  fn skips_accounts_owned_by_another_provider() {
    let upstream_id = id("local");
    let gateway = plan(BTreeMap::from([(upstream_id.clone(), upstream(None))]));
    let mut other = account("other");
    other.provider = "openai".into();

    let graph = link_provider_graph(&gateway, &[other], &Registry::builtin()).unwrap();

    assert_eq!(graph.target_count(), 1);
    assert_eq!(graph.binding_count(), 0);
    assert!(graph.binding(&upstream_id, "other").is_none());
  }

  #[test]
  fn binding_provider_capabilities_remain_available() {
    let upstream_id = id("local");
    let gateway = plan(BTreeMap::from([(upstream_id.clone(), upstream(None))]));

    let graph = link_provider_graph(&gateway, &[account("local")], &Registry::builtin()).unwrap();

    assert!(graph
      .binding(&upstream_id, "local")
      .unwrap()
      .provider()
      .supports("", Endpoint::ChatCompletions));
  }
}

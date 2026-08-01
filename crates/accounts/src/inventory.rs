use super::handle::AccountHandle;
use crate::pool::{BuildAccountSnafu, NoAccountsSnafu, Result};
use snafu::ResultExt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::provider::Provider;
use tracing::debug;

#[derive(Clone, Debug, Default)]
pub struct AccountPoolRuleset {
  pub providers: Option<BTreeSet<String>>,
  pub accounts: Option<BTreeSet<String>>,
}

impl AccountPoolRuleset {
  pub fn all() -> Self {
    Self::default()
  }

  pub fn from_filters(providers: Option<Vec<String>>, accounts: Option<Vec<String>>) -> Self {
    Self {
      providers: providers.map(|ids| ids.into_iter().collect()),
      accounts: accounts.map(|ids| ids.into_iter().collect()),
    }
  }

  pub fn allows(&self, account: &AccountHandle) -> bool {
    let provider_id = account.provider.info().id.as_str();
    let account_config = account.config.load();
    let account_id = account_config.id.as_str();
    self
      .providers
      .as_ref()
      .map(|providers| providers.contains(provider_id))
      .unwrap_or(true)
      && self
        .accounts
        .as_ref()
        .map(|accounts| accounts.contains(account_id))
        .unwrap_or(true)
  }
}

pub struct AccountInventory {
  accounts: Vec<Arc<AccountHandle>>,
  by_id: BTreeMap<String, Arc<AccountHandle>>,
}

impl AccountInventory {
  pub fn from_accounts_with<F>(accounts_in: &[AccountConfig], build_provider: F) -> Result<Arc<Self>>
  where
    F: Fn(Arc<AccountConfig>) -> tokn_core::provider::Result<Arc<dyn Provider>>,
  {
    if accounts_in.is_empty() {
      return NoAccountsSnafu.fail();
    }

    let mut accounts = Vec::with_capacity(accounts_in.len());
    let mut by_id = BTreeMap::new();
    for account in accounts_in {
      if !account.enabled {
        debug!(account = %account.id, "inventory: skipped disabled account");
        continue;
      }

      let cfg = Arc::new(account.clone());
      let provider = build_provider(cfg.clone()).context(BuildAccountSnafu { id: account.id.clone() })?;
      debug!(
        account = %account.id,
        provider = %provider.info().id,
        tier = ?account.tier,
        "inventory: built account"
      );
      let handle = Arc::new(AccountHandle::new(cfg, provider));
      by_id.insert(account.id.clone(), handle.clone());
      accounts.push(handle);
    }

    if accounts.is_empty() {
      return NoAccountsSnafu.fail();
    }

    Ok(Arc::new(Self { accounts, by_id }))
  }

  #[cfg(test)]
  pub(crate) fn from_handles_for_test(accounts: Vec<Arc<AccountHandle>>) -> Self {
    let by_id = accounts
      .iter()
      .map(|account| (account.config.load().id.clone(), account.clone()))
      .collect();
    Self { accounts, by_id }
  }

  pub fn len(&self) -> usize {
    self.accounts.len()
  }

  pub fn is_empty(&self) -> bool {
    self.accounts.is_empty()
  }

  pub fn all(&self) -> &[Arc<AccountHandle>] {
    &self.accounts
  }

  pub fn account_by_id(&self, id: &str) -> Option<Arc<AccountHandle>> {
    self.by_id.get(id).cloned()
  }

  pub fn filtered(&self, ruleset: &AccountPoolRuleset) -> Vec<Arc<AccountHandle>> {
    self
      .accounts
      .iter()
      .filter(|account| ruleset.allows(account))
      .cloned()
      .collect()
  }
}

use std::collections::{BTreeMap, BTreeSet};

use tokn_config::v2::{RawAccountPool, RawPoolStrategy, RawUpstream};
use tokn_config::Config;
use tokn_core::account::{AccountConfig, AccountTier};
use tokn_core::upstream_url::{CanonicalUpstreamUrl, CleartextHttpPolicy};

use super::analysis::EffectivePolicy;
use super::{V2MigrationError, V2MigrationWarning};

pub(super) fn index_accounts(accounts: &[AccountConfig]) -> Result<BTreeMap<&str, &AccountConfig>, V2MigrationError> {
  let mut index = BTreeMap::new();
  for account in accounts {
    if index.insert(account.id.as_str(), account).is_some() {
      return Err(V2MigrationError::DuplicateAccountId {
        account_id: account.id.clone(),
      });
    }
  }
  Ok(index)
}

pub(super) fn raw_pool_for_policy(
  legacy: &Config,
  policy: &EffectivePolicy,
  accounts: &[AccountConfig],
  account_index: &BTreeMap<&str, &AccountConfig>,
) -> Result<RawAccountPool, V2MigrationError> {
  let providers = normalized_selector(policy, "providers", policy.providers.as_deref())?;
  let explicit_accounts = normalized_selector(policy, "accounts", policy.accounts.as_deref())?;
  if let Some(account_ids) = &explicit_accounts {
    for account_id in account_ids {
      if !account_index.contains_key(account_id.as_str()) {
        return Err(V2MigrationError::UnknownPolicyAccount {
          policy: policy.location.clone(),
          account_id: account_id.clone(),
        });
      }
    }
  }

  let provider_set = providers
    .as_ref()
    .map(|providers| providers.iter().map(String::as_str).collect::<BTreeSet<_>>());
  let explicit_set = explicit_accounts
    .as_ref()
    .map(|accounts| accounts.iter().map(String::as_str).collect::<BTreeSet<_>>());
  let mut has_enabled_account = false;
  let mut active = Vec::new();
  let mut fallback = Vec::new();
  for account in accounts {
    if provider_set
      .as_ref()
      .is_some_and(|providers| !providers.contains(account.provider.as_str()))
      || explicit_set
        .as_ref()
        .is_some_and(|account_ids| !account_ids.contains(account.id.as_str()))
    {
      continue;
    }
    has_enabled_account |= account.enabled;
    match account.tier {
      AccountTier::Active => active.push(account.id.clone()),
      AccountTier::Fallback => fallback.push(account.id.clone()),
    }
  }
  if !has_enabled_account {
    return Err(V2MigrationError::NoEnabledAccountsForPolicy {
      policy: policy.location.clone(),
    });
  }

  let provider_selector_is_explicitly_empty = providers.as_ref().is_some_and(Vec::is_empty);
  let active_accounts = if explicit_accounts.is_some() || provider_selector_is_explicitly_empty {
    Some(active)
  } else {
    None
  };
  let providers = match providers {
    Some(providers) if providers.is_empty() => None,
    providers => providers,
  };
  let session_expired_retention_secs = if legacy.pool.session_ttl_secs == 0 {
    if legacy.pool.session_tombstone_secs != 0 {
      return Err(V2MigrationError::UnsupportedSessionAffinity {
        session_tombstone_secs: legacy.pool.session_tombstone_secs,
      });
    }
    0
  } else {
    legacy
      .pool
      .session_tombstone_secs
      .saturating_sub(legacy.pool.session_ttl_secs)
  };

  Ok(RawAccountPool {
    active_accounts,
    fallback_accounts: fallback,
    providers,
    strategy: RawPoolStrategy::RoundRobin,
    failure_cooldown_secs: legacy.pool.failure_cooldown_secs,
    session_ttl_secs: legacy.pool.session_ttl_secs,
    session_expired_retention_secs,
  })
}

fn normalized_selector(
  policy: &EffectivePolicy,
  field: &'static str,
  values: Option<&[String]>,
) -> Result<Option<Vec<String>>, V2MigrationError> {
  let Some(values) = values else {
    return Ok(None);
  };
  if values.iter().any(|value| value == "*") {
    return Err(V2MigrationError::UnsupportedWildcardSelector {
      policy: policy.location.clone(),
      field,
    });
  }
  let mut seen = BTreeSet::new();
  Ok(Some(
    values
      .iter()
      .filter(|value| seen.insert(value.as_str()))
      .cloned()
      .collect(),
  ))
}

pub(super) fn build_upstreams(
  accounts: &[AccountConfig],
  policies: &[EffectivePolicy],
  allow_insecure_upstreams: bool,
  warnings: &mut Vec<V2MigrationWarning>,
) -> Result<BTreeMap<String, RawUpstream>, V2MigrationError> {
  let mut grouped = BTreeMap::<(String, Option<String>), Vec<String>>::new();
  for account in accounts {
    grouped
      .entry((account.provider.clone(), account.base_url.clone()))
      .or_default()
      .push(account.id.clone());
  }

  let represented = grouped
    .keys()
    .map(|(provider, _)| provider.clone())
    .collect::<BTreeSet<_>>();
  for provider in policies
    .iter()
    .flat_map(|policy| policy.providers.iter().flatten())
    .filter(|provider| provider.as_str() != "*")
  {
    if !represented.contains(provider) {
      grouped.entry((provider.clone(), None)).or_default();
    }
  }

  let mut upstreams = BTreeMap::new();
  for (index, ((provider, base_url), accounts)) in grouped.into_iter().enumerate() {
    let allow_insecure_http = base_url.as_deref().is_some_and(cleartext_requires_opt_in);
    if allow_insecure_http {
      let base_url = base_url.clone().expect("cleartext URL is present");
      if !allow_insecure_upstreams {
        return Err(V2MigrationError::InsecureUpstreamRequiresOptIn { accounts, base_url });
      }
      warnings.push(V2MigrationWarning::CleartextUpstreamAllowed {
        accounts: accounts.clone(),
        base_url,
      });
    }
    upstreams.insert(
      format!("upstream-{}", index + 1),
      RawUpstream {
        provider,
        accounts: (!accounts.is_empty()).then_some(accounts),
        base_url,
        origins: Vec::new(),
        allow_insecure_http,
      },
    );
  }
  Ok(upstreams)
}

fn cleartext_requires_opt_in(base_url: &str) -> bool {
  CanonicalUpstreamUrl::parse(base_url, CleartextHttpPolicy::LoopbackOnly).is_err()
    && CanonicalUpstreamUrl::parse(base_url, CleartextHttpPolicy::Allow).is_ok()
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_config::RouteMode;

  fn account(id: &str, provider: &str, tier: AccountTier, base_url: Option<&str>) -> AccountConfig {
    let mut account: AccountConfig =
      toml::from_str(&format!("id = {id:?}\nprovider = {provider:?}\nenabled = true\n")).unwrap();
    account.tier = tier;
    account.base_url = base_url.map(str::to_string);
    account
  }

  fn active(id: &str, provider: &str) -> AccountConfig {
    account(id, provider, AccountTier::Active, None)
  }

  fn policy(providers: Option<&[&str]>, accounts: Option<&[&str]>) -> EffectivePolicy {
    EffectivePolicy {
      location: super::super::LegacyPolicyLocation::Default,
      legacy_profile: None,
      mode: RouteMode::Route,
      agent_id: None,
      providers: providers.map(|values| values.iter().map(|value| (*value).to_string()).collect()),
      accounts: accounts.map(|values| values.iter().map(|value| (*value).to_string()).collect()),
    }
  }

  fn pool_for(
    legacy: &Config,
    policy: &EffectivePolicy,
    accounts: &[AccountConfig],
  ) -> Result<RawAccountPool, V2MigrationError> {
    let account_index = index_accounts(accounts)?;
    raw_pool_for_policy(legacy, policy, accounts, &account_index)
  }

  #[test]
  fn rejects_duplicate_account_ids() {
    let accounts = [active("duplicate", "openai"), active("duplicate", "zai")];

    assert!(matches!(
      index_accounts(&accounts),
      Err(V2MigrationError::DuplicateAccountId { account_id }) if account_id == "duplicate"
    ));
  }

  #[test]
  fn builds_pool_local_filters_and_tiers() {
    let mut disabled_active = active("disabled-active", "openai");
    disabled_active.enabled = false;
    let mut disabled_fallback = account("disabled-fallback", "openai", AccountTier::Fallback, None);
    disabled_fallback.enabled = false;
    let accounts = vec![
      active("selected-active", "openai"),
      disabled_active,
      account("selected-fallback", "openai", AccountTier::Fallback, None),
      disabled_fallback,
      active("unselected", "openai"),
      active("other-provider", "zai"),
    ];
    let legacy = Config::default();

    let selected = pool_for(
      &legacy,
      &policy(
        Some(&["openai"]),
        Some(&[
          "selected-active",
          "disabled-active",
          "selected-fallback",
          "disabled-fallback",
          "other-provider",
        ]),
      ),
      &accounts,
    )
    .unwrap();
    assert_eq!(
      selected.active_accounts.as_deref().unwrap(),
      ["selected-active", "disabled-active"]
    );
    assert_eq!(selected.fallback_accounts, ["selected-fallback", "disabled-fallback"]);
    assert_eq!(selected.providers.as_deref().unwrap(), ["openai"]);

    let provider_only = pool_for(&legacy, &policy(Some(&["openai"]), None), &accounts).unwrap();
    assert_eq!(provider_only.active_accounts, None);
    assert_eq!(
      provider_only.fallback_accounts,
      ["selected-fallback", "disabled-fallback"]
    );
    assert_eq!(provider_only.providers.as_deref().unwrap(), ["openai"]);

    let fallback_only = pool_for(&legacy, &policy(None, Some(&["selected-fallback"])), &accounts).unwrap();
    assert!(fallback_only.active_accounts.as_deref().unwrap().is_empty());
    assert_eq!(fallback_only.fallback_accounts, ["selected-fallback"]);
  }

  #[test]
  fn rejects_empty_disabled_wildcard_and_unknown_account_selections() {
    let enabled = active("enabled", "openai");
    let mut disabled = active("disabled", "openai");
    disabled.enabled = false;
    let legacy = Config::default();

    assert!(matches!(
      pool_for(&legacy, &policy(None, Some(&[])), std::slice::from_ref(&enabled)),
      Err(V2MigrationError::NoEnabledAccountsForPolicy {
        policy: super::super::LegacyPolicyLocation::Default
      })
    ));
    assert!(matches!(
      pool_for(&legacy, &policy(Some(&[]), None), std::slice::from_ref(&enabled)),
      Err(V2MigrationError::NoEnabledAccountsForPolicy {
        policy: super::super::LegacyPolicyLocation::Default
      })
    ));
    assert!(matches!(
      pool_for(
        &legacy,
        &policy(Some(&["zai"]), Some(&["enabled"])),
        std::slice::from_ref(&enabled)
      ),
      Err(V2MigrationError::NoEnabledAccountsForPolicy {
        policy: super::super::LegacyPolicyLocation::Default
      })
    ));
    assert!(matches!(
      pool_for(
        &legacy,
        &policy(None, Some(&["disabled"])),
        &[enabled.clone(), disabled]
      ),
      Err(V2MigrationError::NoEnabledAccountsForPolicy {
        policy: super::super::LegacyPolicyLocation::Default
      })
    ));
    assert!(matches!(
      pool_for(&legacy, &policy(None, Some(&["*"])), std::slice::from_ref(&enabled)),
      Err(V2MigrationError::UnsupportedWildcardSelector {
        policy: super::super::LegacyPolicyLocation::Default,
        field: "accounts"
      })
    ));
    assert!(matches!(
      pool_for(&legacy, &policy(Some(&["*"]), None), std::slice::from_ref(&enabled)),
      Err(V2MigrationError::UnsupportedWildcardSelector {
        policy: super::super::LegacyPolicyLocation::Default,
        field: "providers"
      })
    ));
    assert!(matches!(
      pool_for(
        &legacy,
        &policy(None, Some(&["enabled", "unknown"])),
        std::slice::from_ref(&enabled)
      ),
      Err(V2MigrationError::UnknownPolicyAccount {
        policy: super::super::LegacyPolicyLocation::Default,
        account_id
      }) if account_id == "unknown"
    ));
  }

  #[test]
  fn converts_absolute_session_tombstones_to_additional_retention() {
    let account = active("account", "openai");
    let mut legacy = Config::default();
    legacy.pool.session_ttl_secs = 100;
    legacy.pool.session_tombstone_secs = 140;

    let pool = pool_for(&legacy, &policy(None, None), std::slice::from_ref(&account)).unwrap();
    assert_eq!(pool.session_ttl_secs, 100);
    assert_eq!(pool.session_expired_retention_secs, 40);

    legacy.pool.session_tombstone_secs = 20;
    let clamped = pool_for(&legacy, &policy(None, None), std::slice::from_ref(&account)).unwrap();
    assert_eq!(clamped.session_expired_retention_secs, 0);

    legacy.pool.session_ttl_secs = 0;
    legacy.pool.session_tombstone_secs = 0;
    let disabled = pool_for(&legacy, &policy(None, None), std::slice::from_ref(&account)).unwrap();
    assert_eq!(disabled.session_ttl_secs, 0);
    assert_eq!(disabled.session_expired_retention_secs, 0);

    legacy.pool.session_tombstone_secs = 1;
    assert!(matches!(
      pool_for(&legacy, &policy(None, None), std::slice::from_ref(&account)),
      Err(V2MigrationError::UnsupportedSessionAffinity {
        session_tombstone_secs: 1
      })
    ));
  }

  #[test]
  fn groups_upstreams_by_provider_and_base_url() {
    let shared_url = "https://shared.example/v1";
    let accounts = vec![
      active("openai-default", "openai"),
      account("openai-custom-a", "openai", AccountTier::Active, Some(shared_url)),
      account("openai-custom-b", "openai", AccountTier::Fallback, Some(shared_url)),
      account("zai-custom", "zai", AccountTier::Active, Some(shared_url)),
    ];
    let mut warnings = Vec::new();

    let upstreams = build_upstreams(&accounts, &[policy(Some(&["deepseek"]), None)], false, &mut warnings).unwrap();
    assert!(warnings.is_empty());
    assert_eq!(upstreams.len(), 4);
    assert!(upstreams
      .values()
      .all(|upstream| upstream.origins.is_empty() && !upstream.allow_insecure_http));

    let openai_default = upstreams
      .values()
      .find(|upstream| upstream.provider == "openai" && upstream.base_url.is_none())
      .unwrap();
    assert_eq!(openai_default.accounts.as_deref().unwrap(), ["openai-default"]);
    let openai_custom = upstreams
      .values()
      .find(|upstream| upstream.provider == "openai" && upstream.base_url.as_deref() == Some(shared_url))
      .unwrap();
    assert_eq!(
      openai_custom.accounts.as_deref().unwrap(),
      ["openai-custom-a", "openai-custom-b"]
    );
    let zai_custom = upstreams
      .values()
      .find(|upstream| upstream.provider == "zai" && upstream.base_url.as_deref() == Some(shared_url))
      .unwrap();
    assert_eq!(zai_custom.accounts.as_deref().unwrap(), ["zai-custom"]);
    let provider_only = upstreams
      .values()
      .find(|upstream| upstream.provider == "deepseek")
      .unwrap();
    assert_eq!(provider_only.accounts, None);
    assert_eq!(provider_only.base_url, None);
  }

  #[test]
  fn accepts_loopback_http_and_requires_opt_in_for_remote_cleartext() {
    let loopback_url = "http://127.0.0.1:8080/v1";
    let loopback = [account("loopback", "openai", AccountTier::Active, Some(loopback_url))];
    let mut warnings = Vec::new();
    let upstreams = build_upstreams(&loopback, &[policy(None, None)], false, &mut warnings).unwrap();
    let upstream = upstreams.values().next().unwrap();
    assert!(!upstream.allow_insecure_http);
    assert!(warnings.is_empty());

    let remote_url = "http://upstream.example/v1";
    let remote = [account("remote", "openai", AccountTier::Active, Some(remote_url))];
    assert!(matches!(
      build_upstreams(&remote, &[policy(None, None)], false, &mut Vec::new()),
      Err(V2MigrationError::InsecureUpstreamRequiresOptIn { accounts, base_url })
        if accounts == ["remote"] && base_url == remote_url
    ));

    let mut warnings = Vec::new();
    let upstreams = build_upstreams(&remote, &[policy(None, None)], true, &mut warnings).unwrap();
    assert!(upstreams.values().next().unwrap().allow_insecure_http);
    assert_eq!(
      warnings,
      [V2MigrationWarning::CleartextUpstreamAllowed {
        accounts: vec!["remote".into()],
        base_url: remote_url.into(),
      }]
    );
  }
}

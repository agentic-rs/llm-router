use std::collections::{BTreeMap, BTreeSet};

use tokn_config::v2::{RawAccountPool, RawPoolStrategy, RawProvider};
use tokn_config::Config;
use tokn_core::account::AccountConfig;
use tokn_core::provider::official_provider_preset;
use tokn_core::upstream_url::{CanonicalUpstreamUrl, CleartextHttpPolicy, InvalidUpstreamUrl};

use super::analysis::EffectivePolicy;
use super::{V2ProjectionError, V2ProjectionOptions, V2ProjectionWarning};

pub(super) fn index_accounts(accounts: &[AccountConfig]) -> Result<BTreeMap<&str, &AccountConfig>, V2ProjectionError> {
  let mut index = BTreeMap::new();
  for account in accounts {
    if index.insert(account.id.as_str(), account).is_some() {
      return Err(V2ProjectionError::DuplicateAccountId {
        account_id: account.id.clone(),
      });
    }
    if official_provider_preset(&account.provider).is_none() {
      return Err(V2ProjectionError::UnknownAccountProvider {
        account_id: account.id.clone(),
        provider: account.provider.clone(),
      });
    }
  }
  Ok(index)
}

pub(super) fn project_accounts_and_providers(
  accounts: &[AccountConfig],
  options: V2ProjectionOptions,
  warnings: &mut Vec<V2ProjectionWarning>,
) -> Result<(Vec<AccountConfig>, BTreeMap<String, RawProvider>), V2ProjectionError> {
  let mut destinations = BTreeMap::<String, Vec<AccountDestination>>::new();
  for account in accounts.iter().filter(|account| account.enabled) {
    let base_url = account
      .base_url
      .as_deref()
      .map(|base_url| canonical_destination(account, base_url))
      .transpose()?;
    destinations
      .entry(account.provider.clone())
      .or_default()
      .push(AccountDestination {
        account_id: account.id.clone(),
        base_url,
      });
  }

  let mut providers = BTreeMap::new();
  for (provider, entries) in destinations {
    let unique = entries
      .iter()
      .map(|entry| entry.base_url.as_ref().map(|url| url.canonical.as_str()))
      .collect::<BTreeSet<_>>();
    if unique.len() > 1 {
      return Err(V2ProjectionError::ConflictingProviderDestinations {
        provider,
        destinations: entries
          .iter()
          .map(|entry| {
            let destination = entry
              .base_url
              .as_ref()
              .map(|url| url.canonical.as_str())
              .unwrap_or("<provider default>");
            format!("{}={destination}", entry.account_id)
          })
          .collect(),
      });
    }
    let Some(destination) = entries.first().and_then(|entry| entry.base_url.as_ref()) else {
      continue;
    };
    let account_ids = entries.iter().map(|entry| entry.account_id.clone()).collect::<Vec<_>>();
    if destination.requires_insecure_opt_in && !options.allow_insecure_http {
      return Err(V2ProjectionError::InsecureProviderRequiresOptIn {
        provider,
        accounts: account_ids,
        base_url: destination.canonical.clone(),
      });
    }
    warnings.push(V2ProjectionWarning::AccountBaseUrlPromoted {
      provider: provider.clone(),
      accounts: account_ids.clone(),
      base_url: destination.canonical.clone(),
    });
    if destination.requires_insecure_opt_in {
      warnings.push(V2ProjectionWarning::CleartextProviderAllowed {
        provider: provider.clone(),
        accounts: account_ids,
        base_url: destination.canonical.clone(),
      });
    }
    providers.insert(
      provider,
      RawProvider {
        enable: true,
        driver: None,
        base_url: Some(destination.canonical.clone()),
        origins: Vec::new(),
        allow_insecure_http: destination.requires_insecure_opt_in,
      },
    );
  }

  let projected_accounts = accounts
    .iter()
    .cloned()
    .map(|mut account| {
      account.base_url = None;
      account
    })
    .collect();
  Ok((projected_accounts, providers))
}

struct AccountDestination {
  account_id: String,
  base_url: Option<CanonicalDestination>,
}

struct CanonicalDestination {
  canonical: String,
  requires_insecure_opt_in: bool,
}

fn canonical_destination(account: &AccountConfig, base_url: &str) -> Result<CanonicalDestination, V2ProjectionError> {
  let canonical = CanonicalUpstreamUrl::parse(base_url, CleartextHttpPolicy::Allow).map_err(|source| {
    V2ProjectionError::InvalidAccountBaseUrl {
      account_id: account.id.clone(),
      base_url: base_url.to_string(),
      source,
    }
  })?;
  let requires_insecure_opt_in = matches!(
    CanonicalUpstreamUrl::parse(base_url, CleartextHttpPolicy::LoopbackOnly),
    Err(InvalidUpstreamUrl::InsecureHttp)
  );
  Ok(CanonicalDestination {
    canonical: canonical.to_string(),
    requires_insecure_opt_in,
  })
}

pub(super) fn raw_pool_for_policy(
  legacy: &Config,
  policy: &EffectivePolicy,
  account_index: &BTreeMap<&str, &AccountConfig>,
) -> Result<RawAccountPool, V2ProjectionError> {
  let providers = normalized_selector(policy, "providers", policy.providers.as_deref())?;
  if let Some(provider_ids) = &providers {
    for provider in provider_ids {
      if official_provider_preset(provider).is_none() {
        return Err(V2ProjectionError::UnknownPolicyProvider {
          policy: policy.location.clone(),
          provider: provider.clone(),
        });
      }
    }
  }
  let accounts = normalized_selector(policy, "accounts", policy.accounts.as_deref())?;
  if let Some(account_ids) = &accounts {
    for account_id in account_ids {
      if !account_index.contains_key(account_id.as_str()) {
        return Err(V2ProjectionError::UnknownPolicyAccount {
          policy: policy.location.clone(),
          account_id: account_id.clone(),
        });
      }
    }
  }

  let session_expired_retention_secs = if legacy.pool.session_ttl_secs == 0 {
    if legacy.pool.session_tombstone_secs != 0 {
      return Err(V2ProjectionError::UnsupportedSessionAffinity {
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
    accounts,
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
) -> Result<Option<Vec<String>>, V2ProjectionError> {
  let Some(values) = values else {
    return Ok(None);
  };
  if values.is_empty() {
    return Err(V2ProjectionError::EmptyPolicySelector {
      policy: policy.location.clone(),
      field,
    });
  }
  if values.iter().any(|value| value == "*") {
    return Err(V2ProjectionError::UnsupportedWildcardSelector {
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

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_config::RouteMode;

  fn account(id: &str, provider: &str, base_url: Option<&str>) -> AccountConfig {
    let mut account: AccountConfig =
      toml::from_str(&format!("id = {id:?}\nprovider = {provider:?}\nenabled = true\n")).unwrap();
    account.base_url = base_url.map(str::to_string);
    account
  }

  fn policy() -> EffectivePolicy {
    EffectivePolicy {
      location: super::super::LegacyPolicyLocation::Default,
      legacy_profile: None,
      mode: RouteMode::Route,
      agent_id: None,
      default_provider_id: None,
      providers: None,
      accounts: None,
    }
  }

  #[test]
  fn promotes_one_shared_account_destination_to_the_provider() {
    let accounts = vec![
      account("first", "openai", Some("https://gateway.example/v1")),
      account("second", "openai", Some("https://gateway.example/v1/")),
    ];
    let mut warnings = Vec::new();
    let (projected, providers) =
      project_accounts_and_providers(&accounts, V2ProjectionOptions::default(), &mut warnings).unwrap();

    assert!(projected.iter().all(|account| account.base_url.is_none()));
    assert_eq!(
      providers["openai"].base_url.as_deref(),
      Some("https://gateway.example/v1/")
    );
    assert!(warnings.iter().any(|warning| matches!(
      warning,
      V2ProjectionWarning::AccountBaseUrlPromoted { provider, .. } if provider == "openai"
    )));
    assert_eq!(accounts[0].base_url.as_deref(), Some("https://gateway.example/v1"));
  }

  #[test]
  fn rejects_mixed_provider_destinations() {
    let accounts = vec![
      account("official", "openai", None),
      account("custom", "openai", Some("https://gateway.example/v1")),
    ];

    assert!(matches!(
      project_accounts_and_providers(
        &accounts,
        V2ProjectionOptions::default(),
        &mut Vec::new()
      ),
      Err(V2ProjectionError::ConflictingProviderDestinations { provider, .. }) if provider == "openai"
    ));
  }

  #[test]
  fn converts_legacy_absolute_session_retention() {
    let account = account("primary", "openai", None);
    let index = index_accounts(std::slice::from_ref(&account)).unwrap();
    let mut legacy = Config::default();
    legacy.pool.session_ttl_secs = 100;
    legacy.pool.session_tombstone_secs = 140;

    let pool = raw_pool_for_policy(&legacy, &policy(), &index).unwrap();
    assert_eq!(pool.session_ttl_secs, 100);
    assert_eq!(pool.session_expired_retention_secs, 40);

    legacy.pool.session_ttl_secs = 0;
    legacy.pool.session_tombstone_secs = 1;
    assert!(matches!(
      raw_pool_for_policy(&legacy, &policy(), &index),
      Err(V2ProjectionError::UnsupportedSessionAffinity {
        session_tombstone_secs: 1
      })
    ));
  }

  #[test]
  fn validates_account_inventory_and_policy_selectors() {
    let primary = account("primary", "openai", None);
    assert!(matches!(
      index_accounts(&[primary.clone(), primary.clone()]),
      Err(V2ProjectionError::DuplicateAccountId { .. })
    ));
    assert!(matches!(
      index_accounts(&[account("custom", "unknown", None)]),
      Err(V2ProjectionError::UnknownAccountProvider { .. })
    ));

    let index = index_accounts(std::slice::from_ref(&primary)).unwrap();
    let legacy = Config::default();
    let mut selected = policy();
    selected.providers = Some(vec!["openai".into(), "openai".into()]);
    selected.accounts = Some(vec!["primary".into(), "primary".into()]);
    let pool = raw_pool_for_policy(&legacy, &selected, &index).unwrap();
    assert_eq!(pool.providers.as_deref().unwrap(), ["openai"]);
    assert_eq!(pool.accounts.as_deref().unwrap(), ["primary"]);

    for (field, providers, accounts) in [
      ("providers", Some(Vec::new()), None),
      ("accounts", None, Some(Vec::new())),
    ] {
      let mut invalid = policy();
      invalid.providers = providers;
      invalid.accounts = accounts;
      assert!(matches!(
        raw_pool_for_policy(&legacy, &invalid, &index),
        Err(V2ProjectionError::EmptyPolicySelector { field: found, .. }) if found == field
      ));
    }

    let mut wildcard = policy();
    wildcard.accounts = Some(vec!["*".into()]);
    assert!(matches!(
      raw_pool_for_policy(&legacy, &wildcard, &index),
      Err(V2ProjectionError::UnsupportedWildcardSelector { field: "accounts", .. })
    ));

    let mut unknown_account = policy();
    unknown_account.accounts = Some(vec!["missing".into()]);
    assert!(matches!(
      raw_pool_for_policy(&legacy, &unknown_account, &index),
      Err(V2ProjectionError::UnknownPolicyAccount { .. })
    ));

    let mut unknown_provider = policy();
    unknown_provider.providers = Some(vec!["missing".into()]);
    assert!(matches!(
      raw_pool_for_policy(&legacy, &unknown_provider, &index),
      Err(V2ProjectionError::UnknownPolicyProvider { .. })
    ));
  }

  #[test]
  fn validates_and_explicitly_allows_remote_cleartext_destinations() {
    let remote = [account("remote", "openai", Some("http://upstream.example/v1"))];
    assert!(matches!(
      project_accounts_and_providers(&remote, V2ProjectionOptions::default(), &mut Vec::new()),
      Err(V2ProjectionError::InsecureProviderRequiresOptIn { .. })
    ));

    let mut warnings = Vec::new();
    let (_, providers) = project_accounts_and_providers(
      &remote,
      V2ProjectionOptions {
        allow_insecure_http: true,
      },
      &mut warnings,
    )
    .unwrap();
    assert!(providers["openai"].allow_insecure_http);
    assert!(warnings.iter().any(|warning| matches!(
      warning,
      V2ProjectionWarning::CleartextProviderAllowed { provider, .. } if provider == "openai"
    )));

    assert!(matches!(
      project_accounts_and_providers(
        &[account("invalid", "openai", Some("not a URL"))],
        V2ProjectionOptions::default(),
        &mut Vec::new()
      ),
      Err(V2ProjectionError::InvalidAccountBaseUrl { .. })
    ));
  }
}

use crate::v2::{
  CompileError, RawAccountPool, RawConfig, RawModelSelector, RawOperationPolicy, RawPoolStrategy, RawProfile,
  RawProvider, RawProviderSelector, RawQualificationNamespace, RawRelayCredentials, RawRelayDestination,
  RawRetryPolicy, RawRoute, RawRouteRetry, RawWireIdentity,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokn_core::provider::{official_provider_preset, OFFICIAL_PROVIDER_PRESETS};
use tokn_core::upstream_url::{CanonicalHttpOrigin, CanonicalUpstreamUrl, CleartextHttpPolicy};
use tokn_policy::{
  AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, DriverId, ManagedRetry, ManagedRoute,
  ManagedTarget, ModelFamily, ModelSelector, OperationPolicy, ProfileId, ProfilePlan, ProviderId, ProviderOrigin,
  ProviderPlan, ProviderSelector, QualificationNamespace, RelayCredentials, RelayDestination, RelayRetry, RelayRoute,
  RetryPolicyId, RetryPolicyPlan, RouteId, RoutePlan, SessionAffinityPlan, WireIdentity, WireIdentityId,
};

const MAX_FAILURE_COOLDOWN_SECS: u64 = 86_400;
const MAX_SESSION_DURATION_SECS: u64 = 31_536_000;
const MAX_RETRIES: u32 = 10;
const MAX_INITIAL_BACKOFF_MS: u64 = 60_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompiledResources {
  pub(super) profiles: BTreeMap<ProfileId, ProfilePlan>,
  pub(super) routes: BTreeMap<RouteId, RoutePlan>,
  pub(super) retry_policies: BTreeMap<RetryPolicyId, RetryPolicyPlan>,
  pub(super) account_pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
  pub(super) providers: BTreeMap<ProviderId, ProviderPlan>,
}

pub(super) fn compile_resources(raw: &RawConfig) -> Result<CompiledResources, CompileError> {
  let providers = compile_providers(&raw.providers)?;
  let account_pools = compile_account_pools(&raw.account_pools, &providers)?;
  let retry_policies = compile_retry_policies(&raw.retry_policies)?;
  let routes = compile_routes(&raw.routes, &account_pools, &providers, &retry_policies)?;
  let profiles = compile_profiles(&raw.profiles, &routes)?;

  Ok(CompiledResources {
    profiles,
    routes,
    retry_policies,
    account_pools,
    providers,
  })
}

fn compile_retry_policies(
  raw_policies: &BTreeMap<String, RawRetryPolicy>,
) -> Result<BTreeMap<RetryPolicyId, RetryPolicyPlan>, CompileError> {
  raw_policies
    .iter()
    .map(|(raw_id, raw_policy)| {
      let id = parse_id::<RetryPolicyId>("retry policy id", raw_id)?;
      if raw_policy.max_retries == 0 || raw_policy.max_retries > MAX_RETRIES {
        return Err(invalid_value(
          format!("retry_policies.{raw_id}.max_retries"),
          format!("must be between 1 and {MAX_RETRIES}"),
        ));
      }
      if raw_policy.initial_backoff_ms > MAX_INITIAL_BACKOFF_MS {
        return Err(invalid_value(
          format!("retry_policies.{raw_id}.initial_backoff_ms"),
          format!("must not exceed {MAX_INITIAL_BACKOFF_MS}"),
        ));
      }
      Ok((
        id,
        RetryPolicyPlan::new(
          raw_policy.max_retries,
          Duration::from_millis(raw_policy.initial_backoff_ms),
        ),
      ))
    })
    .collect()
}

fn compile_account_pools(
  raw_pools: &BTreeMap<String, RawAccountPool>,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<BTreeMap<AccountPoolId, AccountPoolPlan>, CompileError> {
  raw_pools
    .iter()
    .map(|(raw_id, raw_pool)| {
      let id = parse_id::<AccountPoolId>("account pool id", raw_id)?;
      validate_duration(
        raw_id,
        "failure_cooldown_secs",
        raw_pool.failure_cooldown_secs,
        MAX_FAILURE_COOLDOWN_SECS,
      )?;
      validate_duration(
        raw_id,
        "session_ttl_secs",
        raw_pool.session_ttl_secs,
        MAX_SESSION_DURATION_SECS,
      )?;
      validate_duration(
        raw_id,
        "session_expired_retention_secs",
        raw_pool.session_expired_retention_secs,
        MAX_SESSION_DURATION_SECS,
      )?;
      let accounts = compile_account_filter(raw_pool.accounts.as_deref(), format!("account_pools.{raw_id}.accounts"))?
        .map(|accounts| accounts.into_iter().map(Into::into).collect());
      let providers = compile_provider_filter(raw_pool.providers.as_deref(), raw_id, providers)?;

      let session_affinity = if raw_pool.session_ttl_secs == 0 {
        if raw_pool.session_expired_retention_secs != 0 {
          return Err(invalid_value(
            format!("account_pools.{raw_id}.session_expired_retention_secs"),
            "must be zero when session_ttl_secs is zero",
          ));
        }
        None
      } else {
        Some(SessionAffinityPlan::new(
          Duration::from_secs(raw_pool.session_ttl_secs),
          Duration::from_secs(raw_pool.session_expired_retention_secs),
        ))
      };

      let strategy = match raw_pool.strategy {
        RawPoolStrategy::RoundRobin => AccountSelectionStrategy::RoundRobin,
      };
      let plan = AccountPoolPlan::new(
        AccountSelector::new(providers, accounts),
        strategy,
        Duration::from_secs(raw_pool.failure_cooldown_secs),
        session_affinity,
      );
      Ok((id, plan))
    })
    .collect()
}

fn validate_duration(pool_id: &str, field: &str, seconds: u64, maximum: u64) -> Result<(), CompileError> {
  if seconds > maximum {
    return Err(invalid_value(
      format!("account_pools.{pool_id}.{field}"),
      format!("must not exceed {maximum} seconds"),
    ));
  }
  Ok(())
}

fn compile_account_filter(
  raw_values: Option<&[String]>,
  location: String,
) -> Result<Option<BTreeSet<String>>, CompileError> {
  let Some(raw_values) = raw_values else {
    return Ok(None);
  };
  validate_selector_shape(raw_values, location.clone())?;
  if raw_values == ["*"] {
    return Ok(None);
  }

  let mut values = BTreeSet::new();
  for value in raw_values {
    if value.trim().is_empty() || value.trim() != value {
      return Err(invalid_value(
        location.clone(),
        "account ids must be non-empty and have no surrounding whitespace",
      ));
    }
    if !values.insert(value.clone()) {
      return Err(duplicate_value(location.clone(), value));
    }
  }
  Ok(Some(values))
}

fn compile_provider_filter(
  raw_values: Option<&[String]>,
  pool_id: &str,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<Option<BTreeSet<ProviderId>>, CompileError> {
  let Some(raw_values) = raw_values else {
    return Ok(None);
  };
  validate_selector_shape(raw_values, format!("account_pools.{pool_id}.providers"))?;
  if raw_values == ["*"] {
    return Ok(None);
  }

  let mut values = BTreeSet::new();
  for value in raw_values {
    let provider = parse_id::<ProviderId>("provider selector", value)?;
    require_reference(
      providers,
      &provider,
      "account pool",
      pool_id,
      "providers",
      "provider",
      value,
    )?;
    if !values.insert(provider) {
      return Err(duplicate_value(format!("account_pools.{pool_id}.providers"), value));
    }
  }
  Ok(Some(values))
}

fn validate_selector_shape(raw_values: &[String], location: String) -> Result<(), CompileError> {
  if raw_values.is_empty() {
    return Err(invalid_value(
      location,
      "must not be empty; omit the field or use [\"*\"] for an unrestricted selector",
    ));
  }
  if raw_values.iter().any(|value| value == "*") && raw_values != ["*"] {
    return Err(invalid_value(location, "wildcard `*` must be the only selector value"));
  }
  Ok(())
}

fn compile_providers(
  raw_providers: &BTreeMap<String, RawProvider>,
) -> Result<BTreeMap<ProviderId, ProviderPlan>, CompileError> {
  let mut plans = OFFICIAL_PROVIDER_PRESETS
    .iter()
    .map(|preset| {
      Ok((
        parse_id::<ProviderId>("provider id", preset.id)?,
        ProviderPlan::new(
          parse_id::<DriverId>("provider driver", preset.driver)?,
          None,
          Box::default(),
          false,
        ),
      ))
    })
    .collect::<Result<BTreeMap<_, _>, CompileError>>()?;

  for (raw_id, raw_provider) in raw_providers {
    let id = parse_id::<ProviderId>("provider id", raw_id)?;
    let preset = official_provider_preset(raw_id);
    if !raw_provider.enable {
      if preset.is_none() {
        return Err(invalid_value(
          format!("providers.{raw_id}.enable"),
          "only an official provider preset may be disabled",
        ));
      }
      plans.remove(&id);
      continue;
    }
    let raw_driver = raw_provider
      .driver
      .as_deref()
      .or_else(|| preset.map(|preset| preset.driver))
      .ok_or_else(|| {
        invalid_value(
          format!("providers.{raw_id}.driver"),
          "custom providers must configure a driver",
        )
      })?;
    let driver = parse_id::<DriverId>("provider driver", raw_driver)?;
    let effective_base_url = raw_provider.base_url.as_deref();
    let (base_url, base_origin) = effective_base_url
      .map(|value| {
        canonical_base_url(
          value,
          format!("providers.{raw_id}.base_url"),
          raw_provider.allow_insecure_http,
        )
      })
      .transpose()?
      .map_or((None, None), |(url, origin)| (Some(url), Some(origin)));

    let mut origins = Vec::new();
    let mut own_origins = BTreeSet::new();
    if let Some(origin) = base_origin {
      claim_origin(&mut own_origins, &mut origins, raw_id, origin)?;
    }
    for raw_origin in &raw_provider.origins {
      let origin = canonical_origin(
        raw_origin,
        format!("providers.{raw_id}.origins"),
        raw_provider.allow_insecure_http,
      )?;
      claim_origin(&mut own_origins, &mut origins, raw_id, origin)?;
    }

    let plan = ProviderPlan::new(
      driver,
      base_url.map(Into::into),
      origins.into_boxed_slice(),
      raw_provider.allow_insecure_http,
    );
    plans.insert(id, plan);
  }

  Ok(plans)
}

fn claim_origin(
  own_origins: &mut BTreeSet<String>,
  compiled: &mut Vec<ProviderOrigin>,
  provider: &str,
  origin: String,
) -> Result<(), CompileError> {
  if !own_origins.insert(origin.clone()) {
    return Err(invalid_value(
      format!("providers.{provider}.origins"),
      format!("contains duplicate canonical origin `{origin}`"),
    ));
  }

  compiled.push(ProviderOrigin::new(origin));
  Ok(())
}

fn canonical_base_url(
  value: &str,
  location: String,
  allow_insecure_http: bool,
) -> Result<(String, String), CompileError> {
  let parsed = CanonicalUpstreamUrl::parse(value, cleartext_policy(allow_insecure_http))
    .map_err(|error| invalid_value(location, error.to_string()))?;
  let origin = parsed.origin().to_string();
  Ok((parsed.to_string(), origin))
}

fn canonical_origin(value: &str, location: String, allow_insecure_http: bool) -> Result<String, CompileError> {
  CanonicalHttpOrigin::parse(value, cleartext_policy(allow_insecure_http))
    .map(|origin| origin.to_string())
    .map_err(|error| invalid_value(location, error.to_string()))
}

fn cleartext_policy(allow_insecure_http: bool) -> CleartextHttpPolicy {
  if allow_insecure_http {
    CleartextHttpPolicy::Allow
  } else {
    CleartextHttpPolicy::LoopbackOnly
  }
}

fn compile_routes(
  raw_routes: &BTreeMap<String, RawRoute>,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
  retry_policies: &BTreeMap<RetryPolicyId, RetryPolicyPlan>,
) -> Result<BTreeMap<RouteId, RoutePlan>, CompileError> {
  raw_routes
    .iter()
    .map(|(raw_id, raw_route)| {
      let id = parse_id::<RouteId>("route id", raw_id)?;
      let plan = match raw_route {
        RawRoute::Managed {
          account_pool,
          provider,
          model,
          operation,
          retry,
        } => {
          let pool_id = resolve_pool(raw_id, "account_pool", account_pool, pools)?;
          let provider_selector = match provider {
            RawProviderSelector::Any {} => {
              ensure_any_provider_viable(raw_id, &pool_id, pools, providers)?;
              ProviderSelector::Any
            }
            RawProviderSelector::Fixed { provider } => {
              let provider_id = resolve_provider("route", raw_id, "provider", provider, providers)?;
              ensure_fixed_provider_compatible(raw_id, "provider", &pool_id, &provider_id, pools)?;
              ProviderSelector::Fixed(provider_id)
            }
          };
          let model = compile_model_selector(raw_id, model)?;
          let operation = match operation {
            RawOperationPolicy::Preserve => OperationPolicy::Preserve,
            RawOperationPolicy::TranslateCompatible => OperationPolicy::TranslateCompatible,
          };
          let retry = compile_managed_retry(raw_id, retry, retry_policies)?;
          RoutePlan::Managed(ManagedRoute::new(
            ManagedTarget::new(pool_id, provider_selector, model),
            operation,
            None,
            retry,
          ))
        }
        RawRoute::Relay {
          destination,
          credentials,
          retry,
        } => {
          let destination = match destination {
            RawRelayDestination::Original {} => RelayDestination::Original,
            RawRelayDestination::FixedProvider { provider } => RelayDestination::FixedProvider(resolve_provider(
              "route",
              raw_id,
              "destination.provider",
              provider,
              providers,
            )?),
          };
          let credentials = match credentials {
            RawRelayCredentials::Client {} => RelayCredentials::Client,
            RawRelayCredentials::AccountPool { account_pool } => {
              RelayCredentials::AccountPool(resolve_pool(raw_id, "credentials.account_pool", account_pool, pools)?)
            }
          };
          match (&destination, &credentials) {
            (RelayDestination::FixedProvider(provider), RelayCredentials::AccountPool(pool)) => {
              ensure_fixed_provider_compatible(raw_id, "destination.provider", pool, provider, pools)?;
            }
            (RelayDestination::Original, RelayCredentials::AccountPool(pool)) => {
              ensure_origin_relay_viable(raw_id, pool, pools, providers)?;
            }
            (_, RelayCredentials::Client) => {}
          }
          let retry = compile_relay_retry(raw_id, retry, retry_policies)?;
          RoutePlan::Relay(RelayRoute::new(destination, credentials, None, retry))
        }
      };

      Ok((id, plan))
    })
    .collect()
}

fn compile_managed_retry(
  route_id: &str,
  raw: &RawRouteRetry,
  policies: &BTreeMap<RetryPolicyId, RetryPolicyPlan>,
) -> Result<ManagedRetry, CompileError> {
  match raw {
    RawRouteRetry::Never {} => Ok(ManagedRetry::Never),
    RawRouteRetry::Recoverable { policy } => {
      resolve_retry_policy(route_id, policy, policies).map(ManagedRetry::Recoverable)
    }
    RawRouteRetry::SafeMethods { .. } | RawRouteRetry::Buffered { .. } => Err(invalid_value(
      format!("routes.{route_id}.retry.kind"),
      "managed routes use `recoverable`; replay safety is guaranteed by structured request buffering",
    )),
  }
}

fn compile_relay_retry(
  route_id: &str,
  raw: &RawRouteRetry,
  policies: &BTreeMap<RetryPolicyId, RetryPolicyPlan>,
) -> Result<RelayRetry, CompileError> {
  match raw {
    RawRouteRetry::Never {} => Ok(RelayRetry::Never),
    RawRouteRetry::SafeMethods { policy } => {
      resolve_retry_policy(route_id, policy, policies).map(RelayRetry::SafeMethods)
    }
    RawRouteRetry::Buffered { policy } => resolve_retry_policy(route_id, policy, policies).map(RelayRetry::Buffered),
    RawRouteRetry::Recoverable { .. } => Err(invalid_value(
      format!("routes.{route_id}.retry.kind"),
      "relay routes must choose `safe_methods` or explicitly acknowledge buffered replay with `buffered`",
    )),
  }
}

fn resolve_retry_policy(
  route_id: &str,
  raw_policy: &str,
  policies: &BTreeMap<RetryPolicyId, RetryPolicyPlan>,
) -> Result<RetryPolicyId, CompileError> {
  let policy = parse_id::<RetryPolicyId>("retry policy reference", raw_policy)?;
  require_reference(
    policies,
    &policy,
    "route",
    route_id,
    "retry.policy",
    "retry policy",
    raw_policy,
  )?;
  Ok(policy)
}

fn resolve_pool(
  route_id: &str,
  field: &'static str,
  raw_pool: &str,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
) -> Result<AccountPoolId, CompileError> {
  let pool = parse_id::<AccountPoolId>("route account pool reference", raw_pool)?;
  require_reference(pools, &pool, "route", route_id, field, "account pool", raw_pool)?;
  Ok(pool)
}

fn resolve_provider(
  owner_kind: &'static str,
  owner: &str,
  field: &'static str,
  raw_provider: &str,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<ProviderId, CompileError> {
  let provider = parse_id::<ProviderId>("provider reference", raw_provider)?;
  require_reference(providers, &provider, owner_kind, owner, field, "provider", raw_provider)?;
  Ok(provider)
}

fn compile_model_selector(route_id: &str, raw: &RawModelSelector) -> Result<ModelSelector, CompileError> {
  match raw {
    RawModelSelector::Capability {} => Ok(ModelSelector::Capability),
    RawModelSelector::Qualified { namespace } => {
      let namespace = match namespace {
        RawQualificationNamespace::Driver => QualificationNamespace::Driver,
        RawQualificationNamespace::Provider => QualificationNamespace::Provider,
      };
      Ok(ModelSelector::Qualified { namespace })
    }
    RawModelSelector::Family { families } => {
      let aliases = families.keys().map(String::as_str).collect::<BTreeSet<_>>();
      let mut compiled = Vec::with_capacity(families.len());
      for (name, members) in families {
        validate_model_name(format!("routes.{route_id}.model.families.{name}"), name)?;
        if members.is_empty() {
          return Err(invalid_value(
            format!("routes.{route_id}.model.families.{name}"),
            "model family must contain at least one member",
          ));
        }
        let mut seen = BTreeSet::new();
        for (index, member) in members.iter().enumerate() {
          let location = format!("routes.{route_id}.model.families.{name}[{index}]");
          validate_model_name(location.clone(), member)?;
          if aliases.contains(member.as_str()) {
            return Err(invalid_value(
              location,
              format!("model `{member}` is also a family name; family names and concrete models must be distinct"),
            ));
          }
          if !seen.insert(member) {
            return Err(invalid_value(location, "duplicates an earlier family member"));
          }
        }
        compiled.push(ModelFamily::new(name, members));
      }
      Ok(ModelSelector::Family(compiled.into_boxed_slice()))
    }
  }
}

fn validate_model_name(location: String, model: &str) -> Result<(), CompileError> {
  if model.trim().is_empty() || model.trim() != model {
    return Err(invalid_value(
      location,
      "model names must be non-empty and have no surrounding whitespace",
    ));
  }
  Ok(())
}

fn ensure_fixed_provider_compatible(
  route_id: &str,
  field: &str,
  pool_id: &AccountPoolId,
  provider_id: &ProviderId,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
) -> Result<(), CompileError> {
  let pool = &pools[pool_id];
  if pool
    .selector()
    .providers()
    .is_some_and(|providers| !providers.contains(provider_id))
  {
    return Err(invalid_value(
      format!("routes.{route_id}.{field}"),
      format!("provider `{provider_id}` is excluded by account pool `{pool_id}`"),
    ));
  }
  Ok(())
}

fn ensure_any_provider_viable(
  route_id: &str,
  pool_id: &AccountPoolId,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<(), CompileError> {
  let allowed_providers = pools[pool_id].selector().providers();
  if providers
    .keys()
    .any(|provider_id| allowed_providers.is_none_or(|providers| providers.contains(provider_id)))
  {
    return Ok(());
  }

  Err(invalid_value(
    format!("routes.{route_id}.provider"),
    format!("no configured provider is compatible with account pool `{pool_id}`"),
  ))
}

fn ensure_origin_relay_viable(
  route_id: &str,
  pool_id: &AccountPoolId,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<(), CompileError> {
  let allowed_providers = pools[pool_id].selector().providers();
  let mut origin_owners = BTreeMap::<String, ProviderId>::new();
  let mut has_viable_provider = false;

  for (provider_id, provider) in providers {
    if allowed_providers.is_some_and(|allowed_providers| !allowed_providers.contains(provider_id)) {
      continue;
    }

    // With no configured base URL, the driver catalogue may supply a
    // default origin during final runtime linking.
    has_viable_provider |= provider.base_url().is_none() || !provider.origins().is_empty();
    for origin in provider.origins() {
      if let Some(first) = origin_owners.get(origin.as_str()) {
        return Err(CompileError::DuplicateOrigin {
          origin: origin.to_string(),
          first_provider: first.to_string(),
          second_provider: provider_id.to_string(),
        });
      }
      origin_owners.insert(origin.to_string(), provider_id.clone());
    }
  }

  if !has_viable_provider {
    return Err(invalid_value(
      format!("routes.{route_id}.destination"),
      format!(
        "origin-based relay requires a provider with a configured or driver-default origin compatible with account pool `{pool_id}`"
      ),
    ));
  }
  Ok(())
}

fn compile_profiles(
  raw_profiles: &BTreeMap<String, RawProfile>,
  routes: &BTreeMap<RouteId, RoutePlan>,
) -> Result<BTreeMap<ProfileId, ProfilePlan>, CompileError> {
  raw_profiles
    .iter()
    .map(|(raw_id, raw_profile)| {
      let id = parse_id::<ProfileId>("profile id", raw_id)?;
      let route_id = parse_id::<RouteId>("profile route reference", &raw_profile.route)?;
      let route = routes.get(&route_id).ok_or_else(|| CompileError::UnresolvedReference {
        owner_kind: "profile",
        owner: raw_id.clone(),
        field: "route",
        target_kind: "route",
        target: raw_profile.route.clone(),
      })?;
      let wire_identity = compile_wire_identity(raw_id, &raw_profile.wire_identity, route)?;
      Ok((id, ProfilePlan::new(route_id, wire_identity)))
    })
    .collect()
}

fn compile_wire_identity(
  profile_id: &str,
  raw: &RawWireIdentity,
  route: &RoutePlan,
) -> Result<WireIdentity, CompileError> {
  let location = format!("profiles.{profile_id}.wire_identity");
  match raw {
    RawWireIdentity::Auto if route.credential_policy() == tokn_policy::CredentialPolicy::Client => {
      Ok(WireIdentity::None)
    }
    RawWireIdentity::Auto => Ok(WireIdentity::ProviderDefault),
    RawWireIdentity::None => Ok(WireIdentity::None),
    RawWireIdentity::ProviderDefault => {
      reject_client_credentials_wire_identity(route, location)?;
      Ok(WireIdentity::ProviderDefault)
    }
    RawWireIdentity::Named(raw_id) => {
      reject_client_credentials_wire_identity(route, location)?;
      // Named identities are runtime/plugin-owned names, not references to a
      // config registry. The runtime linker must reject names it cannot
      // materialize before starting listeners.
      Ok(WireIdentity::Named(parse_id::<WireIdentityId>(
        "wire identity name",
        raw_id,
      )?))
    }
  }
}

fn reject_client_credentials_wire_identity(route: &RoutePlan, location: String) -> Result<(), CompileError> {
  if route.credential_policy() == tokn_policy::CredentialPolicy::Client {
    return Err(invalid_value(
      location,
      "routes with client credentials preserve client identity; use `auto` or `none`",
    ));
  }
  Ok(())
}

fn parse_id<T>(resource: &'static str, value: &str) -> Result<T, CompileError>
where
  T: TryFrom<String, Error = tokn_policy::InvalidIdentifier>,
{
  T::try_from(value.to_string()).map_err(|source| CompileError::InvalidIdentifier { resource, source })
}

fn require_reference<K, V>(
  registry: &BTreeMap<K, V>,
  key: &K,
  owner_kind: &'static str,
  owner: &str,
  field: &'static str,
  target_kind: &'static str,
  raw_target: &str,
) -> Result<(), CompileError>
where
  K: Ord,
{
  if registry.contains_key(key) {
    Ok(())
  } else {
    Err(CompileError::UnresolvedReference {
      owner_kind,
      owner: owner.to_string(),
      field,
      target_kind,
      target: raw_target.to_string(),
    })
  }
}

fn invalid_value(location: String, message: impl Into<String>) -> CompileError {
  CompileError::InvalidValue {
    location,
    message: message.into(),
  }
}

fn duplicate_value(location: String, value: &str) -> CompileError {
  invalid_value(location, format!("contains duplicate value `{value}`"))
}

#[cfg(test)]
mod tests;

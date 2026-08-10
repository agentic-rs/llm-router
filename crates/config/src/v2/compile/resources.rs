use crate::v2::{
  CompileError, RawAccountPool, RawConfig, RawFallbackSelector, RawModelCandidate, RawModelSelector,
  RawOperationPolicy, RawPoolStrategy, RawProfile, RawProvider, RawProviderSelector, RawQualificationNamespace,
  RawRelayTarget, RawRoute, RawWireIdentity,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokn_core::upstream_url::{CanonicalHttpOrigin, CanonicalUpstreamUrl, CleartextHttpPolicy};
use tokn_policy::{
  AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, DriverId, FallbackSelector, ManagedRetry,
  ManagedRoute, ManagedTarget, ModelCandidate, ModelGroupId, ModelGroupPlan, ModelSelector, OperationPolicy, ProfileId,
  ProfilePlan, ProviderId, ProviderOrigin, ProviderPlan, ProviderSelector, QualificationNamespace, RelayRetry,
  RelayRoute, RelayTarget, RouteId, RouteKind, RoutePlan, SessionAffinityPlan, WireIdentity, WireIdentityId,
};

const MAX_FAILURE_COOLDOWN_SECS: u64 = 86_400;
const MAX_SESSION_DURATION_SECS: u64 = 31_536_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompiledResources {
  pub(super) profiles: BTreeMap<ProfileId, ProfilePlan>,
  pub(super) routes: BTreeMap<RouteId, RoutePlan>,
  pub(super) account_pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
  pub(super) providers: BTreeMap<ProviderId, ProviderPlan>,
  pub(super) model_groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
}

pub(super) fn compile_resources(raw: &RawConfig) -> Result<CompiledResources, CompileError> {
  let providers = compile_providers(&raw.providers)?;
  let account_pools = compile_account_pools(&raw.account_pools, &providers)?;
  let model_groups = compile_model_groups(&raw.model_groups, &providers)?;
  let routes = compile_routes(&raw.routes, &account_pools, &providers, &model_groups)?;
  let profiles = compile_profiles(&raw.profiles, &routes)?;

  Ok(CompiledResources {
    profiles,
    routes,
    account_pools,
    providers,
    model_groups,
  })
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
  let mut plans = BTreeMap::new();

  for (raw_id, raw_provider) in raw_providers {
    let id = parse_id::<ProviderId>("provider id", raw_id)?;
    let driver = parse_id::<DriverId>("provider driver", &raw_provider.driver)?;
    let (base_url, base_origin) = raw_provider
      .base_url
      .as_deref()
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

fn compile_model_groups(
  raw_groups: &BTreeMap<String, Vec<RawModelCandidate>>,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<BTreeMap<ModelGroupId, ModelGroupPlan>, CompileError> {
  raw_groups
    .iter()
    .map(|(raw_id, raw_candidates)| {
      let id = parse_id::<ModelGroupId>("model group id", raw_id)?;
      if raw_candidates.is_empty() {
        return Err(invalid_value(
          format!("model_groups.{raw_id}"),
          "must contain at least one candidate",
        ));
      }

      let mut candidates = Vec::with_capacity(raw_candidates.len());
      let mut seen = BTreeSet::new();
      for (index, raw_candidate) in raw_candidates.iter().enumerate() {
        let candidate = compile_model_candidate(raw_id, index, raw_candidate, providers)?;
        let key = (candidate.provider().cloned(), candidate.model().to_string());
        if !seen.insert(key) {
          return Err(invalid_value(
            format!("model_groups.{raw_id}[{index}]"),
            "duplicates an earlier model candidate",
          ));
        }
        candidates.push(candidate);
      }

      Ok((id, ModelGroupPlan::new(candidates.into_boxed_slice())))
    })
    .collect()
}

fn compile_model_candidate(
  group_id: &str,
  index: usize,
  raw: &RawModelCandidate,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<ModelCandidate, CompileError> {
  if raw.model.trim().is_empty() || raw.model.trim() != raw.model {
    return Err(invalid_value(
      format!("model_groups.{group_id}[{index}].model"),
      "model must be non-empty and have no surrounding whitespace",
    ));
  }

  let provider = raw
    .provider
    .as_deref()
    .map(|raw_provider| {
      let provider = parse_id::<ProviderId>("model candidate provider reference", raw_provider)?;
      require_reference(
        providers,
        &provider,
        "model group",
        group_id,
        "provider",
        "provider",
        raw_provider,
      )?;
      Ok(provider)
    })
    .transpose()?;

  Ok(ModelCandidate::new(provider, &raw.model))
}

fn compile_routes(
  raw_routes: &BTreeMap<String, RawRoute>,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
  groups: &BTreeMap<ModelGroupId, ModelGroupPlan>,
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
          let model = compile_model_selector(raw_id, model, &pool_id, &provider_selector, pools, groups)?;
          let operation = match operation {
            RawOperationPolicy::Preserve => OperationPolicy::Preserve,
            RawOperationPolicy::TranslateCompatible => OperationPolicy::TranslateCompatible,
          };
          RoutePlan::Managed(ManagedRoute::new(
            ManagedTarget::new(pool_id, provider_selector, model),
            operation,
            None,
            ManagedRetry::Never,
          ))
        }
        RawRoute::Relay { target } => {
          let target = match target {
            RawRelayTarget::ProviderFromOrigin { account_pool } => {
              let pool_id = resolve_pool(raw_id, "target.account_pool", account_pool, pools)?;
              ensure_origin_relay_viable(raw_id, &pool_id, pools, providers)?;
              RelayTarget::ProviderFromOrigin { account_pool: pool_id }
            }
            RawRelayTarget::FixedProvider { provider, account_pool } => {
              let pool_id = resolve_pool(raw_id, "target.account_pool", account_pool, pools)?;
              let provider_id = resolve_provider("route", raw_id, "target.provider", provider, providers)?;
              ensure_fixed_provider_compatible(raw_id, "target.provider", &pool_id, &provider_id, pools)?;
              RelayTarget::FixedProvider {
                provider: provider_id,
                account_pool: pool_id,
              }
            }
          };
          RoutePlan::Relay(RelayRoute::new(target, None, RelayRetry::Never))
        }
        RawRoute::Transparent {} => RoutePlan::Transparent(Default::default()),
      };

      Ok((id, plan))
    })
    .collect()
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

fn compile_model_selector(
  route_id: &str,
  raw: &RawModelSelector,
  pool_id: &AccountPoolId,
  route_provider: &ProviderSelector,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  groups: &BTreeMap<ModelGroupId, ModelGroupPlan>,
) -> Result<ModelSelector, CompileError> {
  match raw {
    RawModelSelector::Capability {} => Ok(ModelSelector::Capability),
    RawModelSelector::Qualified { namespace } => {
      let namespace = match namespace {
        RawQualificationNamespace::Driver => QualificationNamespace::Driver,
        RawQualificationNamespace::Provider => QualificationNamespace::Provider,
      };
      Ok(ModelSelector::Qualified { namespace })
    }
    RawModelSelector::Fallback { selector } => {
      let selector = match selector {
        RawFallbackSelector::Fixed { group } => {
          let group_id = resolve_group(route_id, "model.selector.group", group, groups)?;
          validate_group_compatibility(route_id, &group_id, pool_id, route_provider, pools, groups)?;
          FallbackSelector::Fixed(group_id)
        }
        RawFallbackSelector::ByRequested { groups: raw_groups } => {
          if raw_groups.is_empty() {
            return Err(invalid_value(
              format!("routes.{route_id}.model.selector.groups"),
              "must contain at least one model group",
            ));
          }

          let mut group_ids = Vec::with_capacity(raw_groups.len());
          let mut seen = BTreeSet::new();
          for raw_group in raw_groups {
            let group = resolve_group(route_id, "model.selector.groups", raw_group, groups)?;
            if !seen.insert(group.clone()) {
              return Err(duplicate_value(
                format!("routes.{route_id}.model.selector.groups"),
                raw_group,
              ));
            }
            validate_group_compatibility(route_id, &group, pool_id, route_provider, pools, groups)?;
            group_ids.push(group);
          }
          FallbackSelector::ByRequested(group_ids.into_boxed_slice())
        }
      };
      Ok(ModelSelector::Fallback(selector))
    }
  }
}

fn resolve_group(
  route_id: &str,
  field: &'static str,
  raw_group: &str,
  groups: &BTreeMap<ModelGroupId, ModelGroupPlan>,
) -> Result<ModelGroupId, CompileError> {
  let group = parse_id::<ModelGroupId>("model group reference", raw_group)?;
  require_reference(groups, &group, "route", route_id, field, "model group", raw_group)?;
  Ok(group)
}

fn validate_group_compatibility(
  route_id: &str,
  group_id: &ModelGroupId,
  pool_id: &AccountPoolId,
  route_provider: &ProviderSelector,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  groups: &BTreeMap<ModelGroupId, ModelGroupPlan>,
) -> Result<(), CompileError> {
  let allowed_providers = pools[pool_id].selector().providers();
  let mut effective_candidates = BTreeSet::new();
  for (index, candidate) in groups[group_id].candidates().iter().enumerate() {
    if let Some(candidate_provider_id) = candidate.provider() {
      if let ProviderSelector::Fixed(route_provider_id) = route_provider {
        if candidate_provider_id != route_provider_id {
          return Err(invalid_value(
            format!("routes.{route_id}.model"),
            format!(
              "model group `{group_id}` candidate {index} pins provider `{candidate_provider_id}`, which conflicts with fixed route provider `{route_provider_id}`"
            ),
          ));
        }
      }

      if allowed_providers.is_some_and(|providers| !providers.contains(candidate_provider_id)) {
        return Err(invalid_value(
          format!("routes.{route_id}.model"),
          format!(
            "model group `{group_id}` candidate {index} pins provider `{candidate_provider_id}`, which account pool `{pool_id}` excludes"
          ),
        ));
      }
    }

    let effective_provider = candidate.provider().or(match route_provider {
      ProviderSelector::Any => None,
      ProviderSelector::Fixed(provider) => Some(provider),
    });
    if !effective_candidates.insert((effective_provider.cloned(), candidate.model())) {
      return Err(invalid_value(
        format!("routes.{route_id}.model"),
        format!("model group `{group_id}` candidate {index} duplicates an earlier effective candidate"),
      ));
    }
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
      format!("routes.{route_id}.target"),
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
      let wire_identity = compile_wire_identity(raw_id, &raw_profile.wire_identity, route.kind())?;
      Ok((id, ProfilePlan::new(route_id, wire_identity)))
    })
    .collect()
}

fn compile_wire_identity(
  profile_id: &str,
  raw: &RawWireIdentity,
  route_kind: RouteKind,
) -> Result<WireIdentity, CompileError> {
  let location = format!("profiles.{profile_id}.wire_identity");
  match raw {
    RawWireIdentity::Auto => match route_kind {
      RouteKind::Managed | RouteKind::Relay => Ok(WireIdentity::ProviderDefault),
      RouteKind::Transparent => Ok(WireIdentity::None),
    },
    RawWireIdentity::None => Ok(WireIdentity::None),
    RawWireIdentity::ProviderDefault => {
      reject_transparent_wire_identity(route_kind, location)?;
      Ok(WireIdentity::ProviderDefault)
    }
    RawWireIdentity::Named(raw_id) => {
      reject_transparent_wire_identity(route_kind, location)?;
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

fn reject_transparent_wire_identity(route_kind: RouteKind, location: String) -> Result<(), CompileError> {
  if route_kind == RouteKind::Transparent {
    return Err(invalid_value(
      location,
      "transparent routes preserve client identity; use `auto` or `none`",
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

use crate::v2::{
  CompileError, RawAccountPool, RawConfig, RawFallbackSelector, RawModelCandidate, RawModelSelector,
  RawOperationPolicy, RawPoolStrategy, RawProfile, RawQualificationNamespace, RawRelayTarget, RawRoute, RawUpstream,
  RawUpstreamSelector, RawWireIdentity,
};
use reqwest::Url;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokn_policy::{
  AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, FallbackSelector, ManagedRetry,
  ManagedRoute, ManagedTarget, ModelCandidate, ModelGroupId, ModelGroupPlan, ModelSelector, OperationPolicy, ProfileId,
  ProfilePlan, ProviderId, QualificationNamespace, RelayRetry, RelayRoute, RelayTarget, RouteId, RouteKind, RoutePlan,
  SessionAffinityPlan, UpstreamId, UpstreamOrigin, UpstreamPlan, UpstreamSelector, WireIdentity, WireIdentityId,
};

const MAX_FAILURE_COOLDOWN_SECS: u64 = 86_400;
const MAX_SESSION_DURATION_SECS: u64 = 31_536_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompiledResources {
  pub(super) profiles: BTreeMap<ProfileId, ProfilePlan>,
  pub(super) routes: BTreeMap<RouteId, RoutePlan>,
  pub(super) account_pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
  pub(super) upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
  pub(super) model_groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
}

pub(super) fn compile_resources(raw: &RawConfig) -> Result<CompiledResources, CompileError> {
  let account_pools = compile_account_pools(&raw.account_pools)?;
  let upstreams = compile_upstreams(&raw.upstreams)?;
  let model_groups = compile_model_groups(&raw.model_groups, &upstreams)?;
  let routes = compile_routes(&raw.routes, &account_pools, &upstreams, &model_groups)?;
  let profiles = compile_profiles(&raw.profiles, &routes)?;

  Ok(CompiledResources {
    profiles,
    routes,
    account_pools,
    upstreams,
    model_groups,
  })
}

fn compile_account_pools(
  raw_pools: &BTreeMap<String, RawAccountPool>,
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
      let accounts = compile_account_filter(raw_pool.accounts.as_deref(), raw_id)?
        .map(|accounts| accounts.into_iter().map(Into::into).collect());
      let providers = compile_provider_filter(raw_pool.providers.as_deref(), raw_id)?;

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
  pool_id: &str,
) -> Result<Option<BTreeSet<String>>, CompileError> {
  let Some(raw_values) = raw_values else {
    return Ok(None);
  };
  validate_selector_shape(raw_values, format!("account_pools.{pool_id}.accounts"))?;
  if raw_values == ["*"] {
    return Ok(None);
  }

  let mut values = BTreeSet::new();
  for value in raw_values {
    if value.trim().is_empty() || value.trim() != value {
      return Err(invalid_value(
        format!("account_pools.{pool_id}.accounts"),
        "account ids must be non-empty and have no surrounding whitespace",
      ));
    }
    if !values.insert(value.clone()) {
      return Err(duplicate_value(format!("account_pools.{pool_id}.accounts"), value));
    }
  }
  Ok(Some(values))
}

fn compile_provider_filter(
  raw_values: Option<&[String]>,
  pool_id: &str,
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

fn compile_upstreams(
  raw_upstreams: &BTreeMap<String, RawUpstream>,
) -> Result<BTreeMap<UpstreamId, UpstreamPlan>, CompileError> {
  let mut plans = BTreeMap::new();

  for (raw_id, raw_upstream) in raw_upstreams {
    let id = parse_id::<UpstreamId>("upstream id", raw_id)?;
    let provider = parse_id::<ProviderId>("upstream provider", &raw_upstream.provider)?;
    let (base_url, base_origin) = raw_upstream
      .base_url
      .as_deref()
      .map(|value| {
        canonical_base_url(
          value,
          format!("upstreams.{raw_id}.base_url"),
          raw_upstream.allow_insecure_http,
        )
      })
      .transpose()?
      .map_or((None, None), |(url, origin)| (Some(url), Some(origin)));

    let mut origins = Vec::new();
    let mut own_origins = BTreeSet::new();
    if let Some(origin) = base_origin {
      claim_origin(&mut own_origins, &mut origins, raw_id, origin)?;
    }
    for raw_origin in &raw_upstream.origins {
      let origin = canonical_origin(
        raw_origin,
        format!("upstreams.{raw_id}.origins"),
        raw_upstream.allow_insecure_http,
      )?;
      claim_origin(&mut own_origins, &mut origins, raw_id, origin)?;
    }

    let plan = UpstreamPlan::new(
      provider,
      base_url.map(Into::into),
      origins.into_boxed_slice(),
      raw_upstream.allow_insecure_http,
    );
    plans.insert(id, plan);
  }

  Ok(plans)
}

fn claim_origin(
  own_origins: &mut BTreeSet<String>,
  compiled: &mut Vec<UpstreamOrigin>,
  upstream: &str,
  origin: String,
) -> Result<(), CompileError> {
  if !own_origins.insert(origin.clone()) {
    return Err(invalid_value(
      format!("upstreams.{upstream}.origins"),
      format!("contains duplicate canonical origin `{origin}`"),
    ));
  }

  compiled.push(UpstreamOrigin::new(origin));
  Ok(())
}

fn canonical_base_url(
  value: &str,
  location: String,
  allow_insecure_http: bool,
) -> Result<(String, String), CompileError> {
  let parsed = parse_http_url(value, &location, allow_insecure_http)?;
  if parsed.query().is_some() || parsed.fragment().is_some() {
    return Err(invalid_value(location, "base URL must not contain a query or fragment"));
  }

  let origin = parsed.origin().ascii_serialization();
  let mut base_url = parsed.to_string();
  if !base_url.ends_with('/') {
    base_url.push('/');
  }
  Ok((base_url, origin))
}

fn canonical_origin(value: &str, location: String, allow_insecure_http: bool) -> Result<String, CompileError> {
  let parsed = parse_http_url(value, &location, allow_insecure_http)?;
  if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
    return Err(invalid_value(location, "expected only scheme, host, and optional port"));
  }
  Ok(parsed.origin().ascii_serialization())
}

fn parse_http_url(value: &str, location: &str, allow_insecure_http: bool) -> Result<Url, CompileError> {
  let raw_host = validate_raw_http_url(value, location)?;
  let parsed =
    Url::parse(value).map_err(|error| invalid_value(location.to_string(), format!("invalid URL: {error}")))?;
  if !matches!(parsed.scheme(), "http" | "https") {
    return Err(invalid_value(location.to_string(), "scheme must be http or https"));
  }
  if parsed.host().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
    return Err(invalid_value(
      location.to_string(),
      "URL must contain a host and must not contain credentials",
    ));
  }
  if parsed.port() == Some(0) {
    return Err(invalid_value(location.to_string(), "port zero is not allowed"));
  }
  let host = parsed.host_str().expect("host presence was checked");
  if host.trim_end_matches('.').len() != host.len() {
    return Err(invalid_value(
      location.to_string(),
      "DNS hosts must not have a trailing dot",
    ));
  }
  reject_noncanonical_ipv4_host(raw_host, host, location)?;
  if parsed.scheme() == "http" && !allow_insecure_http && !is_literal_loopback(host) {
    return Err(invalid_value(
      location.to_string(),
      "non-loopback HTTP can expose account credentials; use HTTPS or set allow_insecure_http = true",
    ));
  }
  Ok(parsed)
}

fn validate_raw_http_url<'a>(value: &'a str, location: &str) -> Result<&'a str, CompileError> {
  if !value.is_ascii() {
    return Err(invalid_value(
      location.to_string(),
      "URL must be ASCII; use an ASCII domain and percent-encoded path",
    ));
  }
  if value
    .bytes()
    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    || value.contains('\\')
  {
    return Err(invalid_value(
      location.to_string(),
      "URL must not contain whitespace, control characters, or backslashes",
    ));
  }

  let remainder = value
    .strip_prefix("https://")
    .or_else(|| value.strip_prefix("http://"))
    .ok_or_else(|| {
      invalid_value(
        location.to_string(),
        "scheme must use canonical `https://` or `http://` syntax",
      )
    })?;
  let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
  let authority = &remainder[..authority_end];
  if authority.is_empty() || authority.contains('@') || authority.contains('%') {
    return Err(invalid_value(
      location.to_string(),
      "URL must contain a plain host authority without credentials or escapes",
    ));
  }
  let raw_host = raw_authority_host(authority).ok_or_else(|| {
    invalid_value(
      location.to_string(),
      "URL authority must contain a valid host and optional port",
    )
  })?;
  if raw_host.ends_with('.') {
    return Err(invalid_value(
      location.to_string(),
      "DNS hosts must not have a trailing dot",
    ));
  }

  let raw_path_and_suffix = &remainder[authority_end..];
  let raw_path = raw_path_and_suffix
    .split(['?', '#'])
    .next()
    .unwrap_or(raw_path_and_suffix);
  if raw_path.split('/').any(is_raw_dot_segment) {
    return Err(invalid_value(
      location.to_string(),
      "URL path must not contain literal or percent-encoded `.` or `..` segments",
    ));
  }

  Ok(raw_host)
}

fn raw_authority_host(authority: &str) -> Option<&str> {
  if let Some(bracketed) = authority.strip_prefix('[') {
    let closing = bracketed.find(']')?;
    let host = &bracketed[..closing];
    let suffix = &bracketed[closing + 1..];
    if !suffix.is_empty()
      && !suffix
        .strip_prefix(':')
        .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
    {
      return None;
    }
    return (!host.is_empty()).then_some(host);
  }

  let host = match authority.rsplit_once(':') {
    Some((host, port)) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => host,
    Some(_) => return None,
    None => authority,
  };
  (!host.is_empty() && !host.contains(':')).then_some(host)
}

fn is_raw_dot_segment(segment: &str) -> bool {
  let bytes = segment.as_bytes();
  let mut dots = 0;
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'.' {
      dots += 1;
      index += 1;
    } else if bytes
      .get(index..index + 3)
      .is_some_and(|encoded| encoded[0] == b'%' && encoded[1] == b'2' && encoded[2].eq_ignore_ascii_case(&b'e'))
    {
      dots += 1;
      index += 3;
    } else {
      return false;
    }
  }
  matches!(dots, 1 | 2)
}

fn reject_noncanonical_ipv4_host(raw_host: &str, parsed_host: &str, location: &str) -> Result<(), CompileError> {
  let parsed_host = parsed_host
    .strip_prefix('[')
    .and_then(|value| value.strip_suffix(']'))
    .unwrap_or(parsed_host);
  let Ok(parsed_address) = parsed_host.parse::<std::net::Ipv4Addr>() else {
    return Ok(());
  };
  if raw_host.parse::<std::net::Ipv4Addr>().ok() != Some(parsed_address) {
    return Err(invalid_value(
      location.to_string(),
      format!("IPv4 host must use canonical dotted-decimal form `{parsed_address}`"),
    ));
  }
  Ok(())
}

fn is_literal_loopback(host: &str) -> bool {
  let host = host
    .strip_prefix('[')
    .and_then(|value| value.strip_suffix(']'))
    .unwrap_or(host);
  host
    .parse::<std::net::IpAddr>()
    .is_ok_and(|address| address.is_loopback())
}

fn compile_model_groups(
  raw_groups: &BTreeMap<String, Vec<RawModelCandidate>>,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
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
        let candidate = compile_model_candidate(raw_id, index, raw_candidate, upstreams)?;
        let key = (candidate.upstream().cloned(), candidate.model().to_string());
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
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
) -> Result<ModelCandidate, CompileError> {
  if raw.model.trim().is_empty() || raw.model.trim() != raw.model {
    return Err(invalid_value(
      format!("model_groups.{group_id}[{index}].model"),
      "model must be non-empty and have no surrounding whitespace",
    ));
  }

  let upstream = raw
    .upstream
    .as_deref()
    .map(|raw_upstream| {
      let upstream = parse_id::<UpstreamId>("model candidate upstream reference", raw_upstream)?;
      require_reference(
        upstreams,
        &upstream,
        "model group",
        group_id,
        "upstream",
        "upstream",
        raw_upstream,
      )?;
      Ok(upstream)
    })
    .transpose()?;

  Ok(ModelCandidate::new(upstream, &raw.model))
}

fn compile_routes(
  raw_routes: &BTreeMap<String, RawRoute>,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
  groups: &BTreeMap<ModelGroupId, ModelGroupPlan>,
) -> Result<BTreeMap<RouteId, RoutePlan>, CompileError> {
  raw_routes
    .iter()
    .map(|(raw_id, raw_route)| {
      let id = parse_id::<RouteId>("route id", raw_id)?;
      let plan = match raw_route {
        RawRoute::Managed {
          account_pool,
          upstream,
          model,
          operation,
        } => {
          let pool_id = resolve_pool(raw_id, "account_pool", account_pool, pools)?;
          let upstream_selector = match upstream {
            RawUpstreamSelector::Any {} => {
              ensure_any_upstream_viable(raw_id, &pool_id, pools, upstreams)?;
              UpstreamSelector::Any
            }
            RawUpstreamSelector::Fixed { upstream } => {
              let upstream_id = resolve_upstream("route", raw_id, "upstream", upstream, upstreams)?;
              ensure_fixed_upstream_compatible(raw_id, "upstream", &pool_id, &upstream_id, pools, upstreams)?;
              UpstreamSelector::Fixed(upstream_id)
            }
          };
          let model = compile_model_selector(raw_id, model, &pool_id, &upstream_selector, pools, upstreams, groups)?;
          let operation = match operation {
            RawOperationPolicy::Preserve => OperationPolicy::Preserve,
            RawOperationPolicy::TranslateCompatible => OperationPolicy::TranslateCompatible,
          };
          RoutePlan::Managed(ManagedRoute::new(
            ManagedTarget::new(pool_id, upstream_selector, model),
            operation,
            None,
            ManagedRetry::Never,
          ))
        }
        RawRoute::Relay { target } => {
          let target = match target {
            RawRelayTarget::UpstreamFromOrigin { account_pool } => {
              let pool_id = resolve_pool(raw_id, "target.account_pool", account_pool, pools)?;
              ensure_origin_relay_viable(raw_id, &pool_id, pools, upstreams)?;
              RelayTarget::UpstreamFromOrigin { account_pool: pool_id }
            }
            RawRelayTarget::FixedUpstream { upstream, account_pool } => {
              let pool_id = resolve_pool(raw_id, "target.account_pool", account_pool, pools)?;
              let upstream_id = resolve_upstream("route", raw_id, "target.upstream", upstream, upstreams)?;
              ensure_fixed_upstream_compatible(raw_id, "target.upstream", &pool_id, &upstream_id, pools, upstreams)?;
              RelayTarget::FixedUpstream {
                upstream: upstream_id,
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

fn resolve_upstream(
  owner_kind: &'static str,
  owner: &str,
  field: &'static str,
  raw_upstream: &str,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
) -> Result<UpstreamId, CompileError> {
  let upstream = parse_id::<UpstreamId>("upstream reference", raw_upstream)?;
  require_reference(upstreams, &upstream, owner_kind, owner, field, "upstream", raw_upstream)?;
  Ok(upstream)
}

fn compile_model_selector(
  route_id: &str,
  raw: &RawModelSelector,
  pool_id: &AccountPoolId,
  route_upstream: &UpstreamSelector,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
  groups: &BTreeMap<ModelGroupId, ModelGroupPlan>,
) -> Result<ModelSelector, CompileError> {
  match raw {
    RawModelSelector::Capability {} => Ok(ModelSelector::Capability),
    RawModelSelector::Qualified { namespace } => {
      let namespace = match namespace {
        RawQualificationNamespace::Provider => QualificationNamespace::Provider,
        RawQualificationNamespace::Upstream => QualificationNamespace::Upstream,
      };
      Ok(ModelSelector::Qualified { namespace })
    }
    RawModelSelector::Fallback { selector } => {
      let selector = match selector {
        RawFallbackSelector::Fixed { group } => {
          let group_id = resolve_group(route_id, "model.selector.group", group, groups)?;
          validate_group_compatibility(route_id, &group_id, pool_id, route_upstream, pools, upstreams, groups)?;
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
            validate_group_compatibility(route_id, &group, pool_id, route_upstream, pools, upstreams, groups)?;
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
  route_upstream: &UpstreamSelector,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
  groups: &BTreeMap<ModelGroupId, ModelGroupPlan>,
) -> Result<(), CompileError> {
  let allowed_providers = pools[pool_id].selector().providers();
  let mut effective_candidates = BTreeSet::new();
  for (index, candidate) in groups[group_id].candidates().iter().enumerate() {
    if let Some(candidate_upstream_id) = candidate.upstream() {
      if let UpstreamSelector::Fixed(route_upstream_id) = route_upstream {
        if candidate_upstream_id != route_upstream_id {
          return Err(invalid_value(
            format!("routes.{route_id}.model"),
            format!(
              "model group `{group_id}` candidate {index} pins upstream `{candidate_upstream_id}`, which conflicts with fixed route upstream `{route_upstream_id}`"
            ),
          ));
        }
      }

      let candidate_upstream = &upstreams[candidate_upstream_id];
      if allowed_providers.is_some_and(|providers| !providers.contains(candidate_upstream.provider())) {
        return Err(invalid_value(
          format!("routes.{route_id}.model"),
          format!(
            "model group `{group_id}` candidate {index} pins upstream `{candidate_upstream_id}` with provider `{}`, which account pool `{pool_id}` excludes",
            candidate_upstream.provider()
          ),
        ));
      }
    }

    let effective_upstream = candidate.upstream().or(match route_upstream {
      UpstreamSelector::Any => None,
      UpstreamSelector::Fixed(upstream) => Some(upstream),
    });
    if !effective_candidates.insert((effective_upstream.cloned(), candidate.model())) {
      return Err(invalid_value(
        format!("routes.{route_id}.model"),
        format!("model group `{group_id}` candidate {index} duplicates an earlier effective candidate"),
      ));
    }
  }
  Ok(())
}

fn ensure_fixed_upstream_compatible(
  route_id: &str,
  field: &str,
  pool_id: &AccountPoolId,
  upstream_id: &UpstreamId,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
) -> Result<(), CompileError> {
  let pool = &pools[pool_id];
  let upstream = &upstreams[upstream_id];
  if pool
    .selector()
    .providers()
    .is_some_and(|providers| !providers.contains(upstream.provider()))
  {
    return Err(invalid_value(
      format!("routes.{route_id}.{field}"),
      format!(
        "upstream `{upstream_id}` uses provider `{}`, which account pool `{pool_id}` excludes",
        upstream.provider()
      ),
    ));
  }
  Ok(())
}

fn ensure_any_upstream_viable(
  route_id: &str,
  pool_id: &AccountPoolId,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
) -> Result<(), CompileError> {
  let allowed_providers = pools[pool_id].selector().providers();
  if upstreams
    .values()
    .any(|upstream| allowed_providers.is_none_or(|providers| providers.contains(upstream.provider())))
  {
    return Ok(());
  }

  Err(invalid_value(
    format!("routes.{route_id}.upstream"),
    format!("no configured upstream is compatible with account pool `{pool_id}`"),
  ))
}

fn ensure_origin_relay_viable(
  route_id: &str,
  pool_id: &AccountPoolId,
  pools: &BTreeMap<AccountPoolId, AccountPoolPlan>,
  upstreams: &BTreeMap<UpstreamId, UpstreamPlan>,
) -> Result<(), CompileError> {
  let providers = pools[pool_id].selector().providers();
  let mut origin_owners = BTreeMap::<String, UpstreamId>::new();
  let mut has_viable_upstream = false;

  for (upstream_id, upstream) in upstreams {
    if providers.is_some_and(|allowed_providers| !allowed_providers.contains(upstream.provider())) {
      continue;
    }

    // With no configured base URL, the provider catalogue may supply a
    // default origin during final runtime linking.
    has_viable_upstream |= upstream.base_url().is_none() || !upstream.origins().is_empty();
    for origin in upstream.origins() {
      if let Some(first) = origin_owners.get(origin.as_str()) {
        return Err(CompileError::DuplicateOrigin {
          origin: origin.to_string(),
          first_upstream: first.to_string(),
          second_upstream: upstream_id.to_string(),
        });
      }
      origin_owners.insert(origin.to_string(), upstream_id.clone());
    }
  }

  if !has_viable_upstream {
    return Err(invalid_value(
      format!("routes.{route_id}.target"),
      format!(
        "origin-based relay requires an upstream with a configured or provider-default origin compatible with account pool `{pool_id}`"
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

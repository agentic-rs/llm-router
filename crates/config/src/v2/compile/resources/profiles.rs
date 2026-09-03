use super::*;
use crate::v2::RawProfileBinding;
use tokn_policy::{ApiBindingPlan, CredentialPolicy, DestinationPolicy, OperationId};

const GENERATION_ENDPOINTS: [&str; 3] = ["chat_completions", "responses", "messages"];

pub(super) fn compile_profiles(
  raw: &RawConfig,
  routes: &BTreeMap<RouteId, RoutePlan>,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
  pools: &mut BTreeMap<AccountPoolId, AccountPoolPlan>,
) -> Result<BTreeMap<ProfileId, ProfilePlan>, CompileError> {
  let mut profiles = BTreeMap::new();
  let mut mounts = BTreeMap::new();
  for (name, profile) in &raw.profiles {
    let id = parse_id::<ProfileId>("profile id", name)?;
    let route_id = parse_id::<RouteId>("profile route reference", &profile.route)?;
    let route = routes.get(&route_id).ok_or_else(|| CompileError::UnresolvedReference {
      owner_kind: "profile",
      owner: name.clone(),
      field: "route",
      target_kind: "route",
      target: profile.route.clone(),
    })?;
    let identity = compile_wire_identity(name, &profile.wire_identity, route)?;
    let mut plan = ProfilePlan::new(route_id, identity);
    if route.credential_policy() == CredentialPolicy::Account {
      let pool_id = parse_id::<AccountPoolId>("profile account pool", &format!("profile.{name}"))?;
      let pool = compile_account_pool(
        name,
        profile.account_pool.as_ref().unwrap_or(&RawAccountPool::default()),
      )?;
      pools.insert(pool_id.clone(), pool);
      validate_profile_providers(name, route, providers)?;
      plan = plan.with_account_pool(pool_id);
    } else if profile.account_pool.is_some() {
      return Err(invalid_value(
        format!("profiles.{name}.account_pool"),
        "client-credential relay profiles do not use an account pool",
      ));
    }

    if route.destination_policy() == DestinationPolicy::Original {
      if profile.binding.is_some() {
        return Err(invalid_value(
          format!("profiles.{name}.binding"),
          "an original-destination relay is proxy-only and cannot have an API binding",
        ));
      }
    } else {
      let binding = compile_binding(name, profile.binding.as_ref())?;
      if let Some(first) = mounts.insert(binding.path().to_string(), name.clone()) {
        return Err(invalid_value(
          format!("profiles.{name}.binding.path"),
          format!("API path `{}` is already owned by profile `{first}`", binding.path()),
        ));
      }
      plan = plan.with_api_binding(binding);
    }
    profiles.insert(id, plan);
  }
  Ok(profiles)
}

fn validate_profile_providers(
  name: &str,
  route: &RoutePlan,
  providers: &BTreeMap<ProviderId, ProviderPlan>,
) -> Result<(), CompileError> {
  let compatible = |id: &ProviderId| route.allows_provider(id);
  let viable = match route {
    RoutePlan::Managed(managed) => match managed.target().provider() {
      ProviderSelector::Any => providers.keys().any(compatible),
      ProviderSelector::Fixed(id) => compatible(id),
    },
    RoutePlan::Relay(relay) => match relay.destination() {
      RelayDestination::FixedProvider(id) => compatible(id),
      RelayDestination::Original => providers.keys().any(compatible),
    },
  };
  if !viable {
    return Err(invalid_value(
      format!("profiles.{name}.route"),
      "route provider restrictions allow no configured provider",
    ));
  }
  if route.destination_policy() == DestinationPolicy::Original {
    let allowed = providers
      .iter()
      .filter(|(id, _)| compatible(id))
      .map(|(id, provider)| (id.clone(), provider.clone()))
      .collect();
    ensure_origin_relay_viable(name, &allowed)?;
  }
  Ok(())
}

fn compile_binding(name: &str, raw: Option<&RawProfileBinding>) -> Result<ApiBindingPlan, CompileError> {
  let default = if name == "default" {
    "/v1".to_string()
  } else {
    format!("/{name}/v1")
  };
  let path = raw.and_then(|binding| binding.path.as_deref()).unwrap_or(&default);
  let location = format!("profiles.{name}.binding.path");
  let path = super::super::listeners::canonical_path_prefix(path, &location)?;
  let path = path.trim_end_matches('/');
  if path.is_empty() || path.contains("//") || path.split('/').any(|segment| segment.contains(['{', '}', '*'])) {
    return Err(invalid_value(
      location,
      "API bindings require a literal, non-root path without empty segments",
    ));
  }
  if path == "/healthz" || path.starts_with("/healthz/") || path == "/admin" || path.starts_with("/admin/") {
    return Err(invalid_value(
      location,
      "API binding overlaps a reserved health or admin path",
    ));
  }
  let values = raw.and_then(|binding| binding.endpoints.as_ref());
  let mut endpoints = BTreeSet::new();
  for endpoint in values
    .map(|values| values.iter().map(String::as_str).collect())
    .unwrap_or_else(|| GENERATION_ENDPOINTS.to_vec())
  {
    let location = format!("profiles.{name}.binding.endpoints");
    // Validation uses the profile's authoring path, not an operation registry.
    if !GENERATION_ENDPOINTS.contains(&endpoint) {
      return Err(invalid_value(
        location,
        format!("unknown generation endpoint `{endpoint}`; expected chat_completions, responses, or messages"),
      ));
    }
    let id = parse_id::<OperationId>("generation endpoint", endpoint)?;
    if !endpoints.insert(id) {
      return Err(duplicate_value(location, endpoint));
    }
  }
  Ok(ApiBindingPlan::new(path, endpoints))
}

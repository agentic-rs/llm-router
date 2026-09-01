use crate::api::error::ApiError;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use tokn_access::AccessContext;
use tokn_accounts::link::{LinkedAccountPools, ProviderBinding, ProviderBindingKey, ProviderGraph};
use tokn_accounts::registry::Registry;
use tokn_core::provider::{ModelInfo, Provider};
use tokn_policy::{
  GatewayPlan, ModelSelector, ProfileId, ProviderId, ProviderSelector, RelayCredentials, RelayDestination, RoutePlan,
};
use tracing::{debug, warn};

pub(super) struct DiscoveryRuntime {
  http: reqwest::Client,
  metadata: BTreeMap<ProviderId, ProviderMetadata>,
  profiles: BTreeMap<ProfileId, ProfileDiscovery>,
}

struct ProviderMetadata {
  driver_id: String,
  display_name: &'static str,
  upstream_url: String,
  auth_kind: Value,
  endpoints: Vec<&'static str>,
  models: Vec<ModelInfo>,
}

struct ProfileDiscovery {
  mode: &'static str,
  providers: BTreeMap<ProviderId, ProfileProvider>,
}

#[derive(Default)]
struct ProfileProvider {
  bindings: BTreeMap<ProviderBindingKey, Arc<ProviderBinding>>,
  plain_model_ids: bool,
  qualified_model_ids: bool,
}

#[derive(Default)]
struct ScopedProvider {
  bindings: BTreeMap<ProviderBindingKey, Arc<ProviderBinding>>,
  plain_model_ids: bool,
  qualified_model_ids: bool,
  modes: BTreeSet<&'static str>,
}

impl DiscoveryRuntime {
  pub(super) fn new(
    plan: &GatewayPlan,
    providers: &ProviderGraph,
    pools: &LinkedAccountPools,
    registry: &Registry,
    http: reqwest::Client,
    reachable_profiles: &BTreeSet<ProfileId>,
  ) -> anyhow::Result<Self> {
    let mut bindings_by_provider = BTreeMap::<ProviderId, Vec<Arc<ProviderBinding>>>::new();
    for binding in providers.bindings() {
      bindings_by_provider
        .entry(binding.provider_id().clone())
        .or_default()
        .push(binding.clone());
    }

    let mut metadata = BTreeMap::new();
    for (provider_id, destination) in providers.destinations() {
      let provider_plan = plan
        .provider(provider_id)
        .ok_or_else(|| anyhow::anyhow!("linked provider '{provider_id}' is missing from the compiled plan"))?;
      let descriptor = registry
        .resolve_provider_descriptor(provider_id.as_str(), provider_plan.driver().as_str())
        .ok_or_else(|| {
          anyhow::anyhow!(
            "linked provider '{provider_id}' references missing driver '{}'",
            provider_plan.driver()
          )
        })?;
      let first_binding = bindings_by_provider
        .get(provider_id)
        .and_then(|bindings| bindings.first());
      let auth_kind = first_binding
        .map(|binding| binding.driver().info().auth_kind)
        .map(|kind| serde_json::to_value(kind).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
      let models = first_binding
        .map(|binding| binding.driver().info().default_models.clone())
        .unwrap_or_else(|| catalogue_models(provider_id, provider_plan.driver().as_str()));
      metadata.insert(
        provider_id.clone(),
        ProviderMetadata {
          driver_id: provider_plan.driver().to_string(),
          display_name: descriptor.display_name,
          upstream_url: destination.target().base_url().to_string(),
          auth_kind,
          endpoints: descriptor
            .endpoints
            .iter()
            .map(|endpoint| endpoint.endpoint.as_str())
            .collect(),
          models,
        },
      );
    }

    let mut profiles = BTreeMap::new();
    for profile_id in reachable_profiles {
      let profile = plan
        .profile(profile_id)
        .ok_or_else(|| anyhow::anyhow!("reachable profile '{profile_id}' is missing from the compiled plan"))?;
      let route = plan.route(profile.route()).ok_or_else(|| {
        anyhow::anyhow!(
          "reachable profile '{profile_id}' references missing route '{}'",
          profile.route()
        )
      })?;
      let mut discovery = ProfileDiscovery {
        mode: super::request_record_mode(route),
        providers: BTreeMap::new(),
      };
      match route {
        RoutePlan::Managed(route) => {
          let pool = pools.pool(route.target().account_pool()).ok_or_else(|| {
            anyhow::anyhow!(
              "profile '{profile_id}' references missing account pool '{}'",
              route.target().account_pool()
            )
          })?;
          let qualified = matches!(route.target().model(), ModelSelector::Qualified { .. });
          for account in pool.active().iter().chain(pool.fallback()) {
            let binding = account.binding();
            if matches!(route.target().provider(), ProviderSelector::Fixed(provider) if provider != binding.provider_id())
            {
              continue;
            }
            add_binding(&mut discovery.providers, binding.clone(), !qualified, qualified);
          }
        }
        RoutePlan::Relay(route) => {
          let RelayDestination::FixedProvider(provider_id) = route.destination() else {
            profiles.insert(profile_id.clone(), discovery);
            continue;
          };
          match route.credentials() {
            RelayCredentials::Client => {
              discovery
                .providers
                .entry(provider_id.clone())
                .or_default()
                .plain_model_ids = true;
            }
            RelayCredentials::AccountPool(pool_id) => {
              let pool = pools
                .pool(pool_id)
                .ok_or_else(|| anyhow::anyhow!("profile '{profile_id}' references missing account pool '{pool_id}'"))?;
              for account in pool.active().iter().chain(pool.fallback()) {
                let binding = account.binding();
                if binding.provider_id() == provider_id {
                  add_binding(&mut discovery.providers, binding.clone(), true, false);
                }
              }
            }
          }
        }
      }
      profiles.insert(profile_id.clone(), discovery);
    }

    Ok(Self {
      http,
      metadata,
      profiles,
    })
  }

  pub(super) fn providers(&self, profile_ids: &BTreeSet<ProfileId>, access: &AccessContext) -> Value {
    let (modes, providers) = self.scope(profile_ids, access);
    let data = providers
      .iter()
      .filter_map(|(provider_id, provider)| {
        let metadata = self.metadata.get(provider_id)?;
        Some(json!({
          "id": provider_id.as_str(),
          "object": "provider",
          "display_name": metadata.display_name,
          "driver": metadata.driver_id,
          "auth_kind": metadata.auth_kind,
          "upstream_url": metadata.upstream_url,
          "accounts": provider.bindings.len(),
          "endpoints": metadata.endpoints,
          "route_modes": provider.modes,
        }))
      })
      .collect::<Vec<_>>();
    list_response(modes, data)
  }

  pub(super) async fn models(
    &self,
    profile_ids: &BTreeSet<ProfileId>,
    access: &AccessContext,
  ) -> Result<Value, ApiError> {
    let (modes, providers) = self.scope(profile_ids, access);
    let mut data = Vec::new();
    let mut seen = HashSet::new();
    let mut queried_account = false;
    let mut last_error = None;

    for (provider_id, provider) in providers {
      let Some(metadata) = self.metadata.get(&provider_id) else {
        continue;
      };
      let mut provider_models = Vec::new();
      if provider.bindings.is_empty() {
        provider_models.extend(local_models(&metadata.models));
      } else {
        queried_account = true;
        for binding in provider.bindings.values() {
          let driver = binding.driver();
          debug!(
            account = binding.account_id(),
            provider = %provider_id,
            driver = %metadata.driver_id,
            "v2 model discovery: querying account"
          );
          match remote_models(driver.as_ref(), &self.http).await {
            Ok(models) if !models.is_empty() => {
              warm_model_cache(driver.as_ref(), &models);
              provider_models.extend(models);
            }
            Ok(_) => provider_models.extend(local_models(&metadata.models)),
            Err(error) => {
              warn!(
                account = binding.account_id(),
                provider = %provider_id,
                driver = %metadata.driver_id,
                %error,
                "v2 model discovery: remote list failed; using local catalogue"
              );
              last_error = Some(error.to_string());
              provider_models.extend(local_models(&metadata.models));
            }
          }
        }
      }

      merge_models(
        &mut data,
        &mut seen,
        provider_models,
        &provider_id,
        metadata,
        provider.plain_model_ids,
        provider.qualified_model_ids,
      );
    }

    if data.is_empty() && queried_account {
      return Err(ApiError::upstream(
        axum::http::StatusCode::BAD_GATEWAY,
        last_error.unwrap_or_else(|| "no models available".into()),
      ));
    }
    Ok(list_response(modes, data))
  }

  fn scope(
    &self,
    profile_ids: &BTreeSet<ProfileId>,
    access: &AccessContext,
  ) -> (BTreeSet<&'static str>, BTreeMap<ProviderId, ScopedProvider>) {
    let mut modes = BTreeSet::new();
    let mut providers = BTreeMap::<ProviderId, ScopedProvider>::new();
    for profile_id in profile_ids {
      let Some(profile) = self.profiles.get(profile_id) else {
        continue;
      };
      modes.insert(profile.mode);
      for (provider_id, source) in &profile.providers {
        if !access.providers.allows(provider_id.as_str()) {
          continue;
        }
        let target = providers.entry(provider_id.clone()).or_default();
        target.plain_model_ids |= source.plain_model_ids;
        target.qualified_model_ids |= source.qualified_model_ids;
        target.modes.insert(profile.mode);
        target.bindings.extend(
          source
            .bindings
            .iter()
            .map(|(key, binding)| (key.clone(), binding.clone())),
        );
      }
    }
    (modes, providers)
  }
}

fn add_binding(
  providers: &mut BTreeMap<ProviderId, ProfileProvider>,
  binding: Arc<ProviderBinding>,
  plain_model_ids: bool,
  qualified_model_ids: bool,
) {
  let provider = providers.entry(binding.provider_id().clone()).or_default();
  provider.plain_model_ids |= plain_model_ids;
  provider.qualified_model_ids |= qualified_model_ids;
  provider.bindings.insert(binding.key().clone(), binding);
}

fn catalogue_models(provider_id: &ProviderId, driver_id: &str) -> Vec<ModelInfo> {
  let models = tokn_catalogue::catalogue::default_models_for(provider_id.as_str());
  if !models.is_empty() {
    return models;
  }
  let catalogue_driver = if driver_id == tokn_core::provider::ID_CODEX {
    tokn_core::provider::ID_OPENAI
  } else {
    driver_id
  };
  tokn_catalogue::catalogue::default_models_for(catalogue_driver)
}

async fn remote_models(provider: &dyn Provider, http: &reqwest::Client) -> tokn_core::provider::Result<Vec<Value>> {
  let response = provider.list_models(http).await?;
  Ok(
    response
      .get("data")
      .and_then(Value::as_array)
      .cloned()
      .unwrap_or_default(),
  )
}

fn local_models(models: &[ModelInfo]) -> Vec<Value> {
  models
    .iter()
    .map(|model| {
      json!({
        "id": model.id,
        "object": "model",
      })
    })
    .collect()
}

fn warm_model_cache(provider: &dyn Provider, models: &[Value]) {
  let ids = models
    .iter()
    .filter_map(|model| model.get("id").and_then(Value::as_str).map(str::to_string))
    .collect::<HashSet<_>>();
  if !ids.is_empty() {
    provider.info().model_cache.set(ids);
  }
}

#[allow(clippy::too_many_arguments)]
fn merge_models(
  output: &mut Vec<Value>,
  seen: &mut HashSet<String>,
  models: Vec<Value>,
  provider_id: &ProviderId,
  metadata: &ProviderMetadata,
  plain_model_ids: bool,
  qualified_model_ids: bool,
) {
  for model in models {
    let upstream_id = model.get("id").and_then(Value::as_str).unwrap_or("");
    if upstream_id.is_empty() {
      continue;
    }
    let rendered_ids = plain_model_ids
      .then(|| upstream_id.to_string())
      .into_iter()
      .chain(qualified_model_ids.then(|| format!("{provider_id}/{upstream_id}")));
    for rendered_id in rendered_ids {
      if !seen.insert(rendered_id.clone()) {
        continue;
      }
      let mut rendered = model.clone();
      if let Some(object) = rendered.as_object_mut() {
        object.insert("id".into(), Value::String(rendered_id.clone()));
      }
      enrich(&mut rendered, upstream_id, &rendered_id, provider_id, metadata);
      output.push(rendered);
    }
  }
}

fn enrich(
  entry: &mut Value,
  upstream_id: &str,
  rendered_id: &str,
  provider_id: &ProviderId,
  metadata: &ProviderMetadata,
) {
  let mut extension = Map::new();
  extension.insert("provider".into(), json!(provider_id.as_str()));
  extension.insert("provider_display_name".into(), json!(metadata.display_name));
  extension.insert("driver".into(), json!(metadata.driver_id));
  extension.insert("upstream_id".into(), json!(upstream_id));
  extension.insert("model_id".into(), json!(rendered_id));
  extension.insert("auth_kind".into(), metadata.auth_kind.clone());

  if let Some(model) = metadata.models.iter().find(|model| model.id == upstream_id) {
    extension.insert("name".into(), json!(model.name));
    extension.insert(
      "capabilities".into(),
      serde_json::to_value(&model.capabilities).unwrap_or(Value::Null),
    );
    if let Some(cost) = &model.cost {
      extension.insert("cost".into(), serde_json::to_value(cost).unwrap_or(Value::Null));
    }
    extension.insert(
      "limit".into(),
      serde_json::to_value(&model.limit).unwrap_or(Value::Null),
    );
    if let Some(release_date) = &model.release_date {
      extension.insert("release_date".into(), json!(release_date));
    }
  }

  if let Some(object) = entry.as_object_mut() {
    object.insert("x_tokn_router".into(), Value::Object(extension));
  }
}

fn list_response(modes: BTreeSet<&'static str>, data: Vec<Value>) -> Value {
  let route_mode = match modes.len() {
    0 => "none",
    1 => modes.first().copied().expect("one route mode"),
    _ => "mixed",
  };
  json!({
    "object": "list",
    "route_mode": route_mode,
    "route_modes": modes,
    "data": data,
  })
}

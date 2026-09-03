use super::error::ApiError;
use super::{AppState, LiveAppState, RequestPolicyRuntime};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::Arc;
use tokn_access::AccessContext;
use tokn_accounts::routing::route_mode_as_str;
use tokn_config::RouteMode;
use tracing::{debug, instrument, warn};

/// Union `data` arrays from every provider, dedup by `id`. For each entry,
/// overlay our static `ProviderInfo`/`ModelInfo` metadata under
/// `"x_tokn_router"` so OpenAI-shape stays intact for legacy clients while
/// richer consumers (TUIs, dashboards) can pick up capabilities/costs/limits.
#[instrument(name = "list_models", skip_all, fields(accounts = tracing::field::Empty, models = tracing::field::Empty))]
pub async fn list_models(
  State(s): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
) -> Result<Json<Value>, ApiError> {
  let s = s.current();
  let policy = s.default_policy.clone();
  list_models_for_policy(s, policy, &access).await
}

async fn list_models_for_policy(
  s: AppState,
  policy: Arc<RequestPolicyRuntime>,
  access: &AccessContext,
) -> Result<Json<Value>, ApiError> {
  let mut out: Vec<Value> = Vec::new();
  let mut seen: HashSet<String> = HashSet::new();
  let mut last_err: Option<String> = None;

  let accounts = model_accounts(policy.as_ref(), access);
  let span = tracing::Span::current();
  span.record("accounts", accounts.len());

  if accounts.is_empty() {
    return Ok(model_list(policy.mode, out));
  }

  for acct in accounts {
    let provider = acct.provider.clone();
    debug!(account = %acct.id(), provider = %provider.info().id, "list_models: querying account");

    let (arr, source) = match remote_models(provider.as_ref(), &s.http).await {
      Ok(arr) if !arr.is_empty() => {
        warm_model_cache(provider.as_ref(), &arr);
        (arr, "remote")
      }
      Ok(_) => {
        debug!(account = %acct.id(), provider = %provider.info().id, "remote models list was empty; using local catalogue");
        (local_models(provider.as_ref()), "local")
      }
      Err(e) => {
        warn!(account = %acct.id(), provider = %provider.info().id, error = %e, "remote models list failed; using local catalogue");
        last_err = Some(e.to_string());
        (local_models(provider.as_ref()), "local")
      }
    };

    let before = out.len();
    merge_models(&mut out, &mut seen, arr, policy.mode, provider.as_ref());
    debug!(
      account = %acct.id(),
      source,
      added = out.len() - before,
      "list_models: account models merged"
    );
  }

  span.record("models", out.len());

  if out.is_empty() {
    let msg = last_err.unwrap_or_else(|| "no models available".into());
    return Err(ApiError::upstream(StatusCode::BAD_GATEWAY, msg));
  }
  Ok(model_list(policy.mode, out))
}

fn model_list(mode: RouteMode, data: Vec<Value>) -> Json<Value> {
  Json(json!({
    "object": "list",
    "route_mode": route_mode_as_str(mode),
    "data": data,
  }))
}

fn model_accounts(
  policy: &RequestPolicyRuntime,
  access: &AccessContext,
) -> Vec<std::sync::Arc<tokn_accounts::AccountHandle>> {
  let default_provider_id = policy.default_provider_id.as_deref();
  policy
    .pool
    .all()
    .iter()
    .filter(|acct| access.providers.allows(acct.provider.info().id.as_str()))
    .filter(|acct| match policy.mode {
      RouteMode::Passthrough | RouteMode::Switch => default_provider_id
        .map(|provider_id| acct.provider.info().id == provider_id)
        .unwrap_or(true),
      _ => true,
    })
    .cloned()
    .collect()
}

async fn remote_models(
  provider: &dyn crate::provider::Provider,
  http: &reqwest::Client,
) -> crate::provider::Result<Vec<Value>> {
  let v = provider.list_models(http).await?;
  Ok(v.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default())
}

fn local_models(provider: &dyn crate::provider::Provider) -> Vec<Value> {
  provider
    .info()
    .default_models
    .iter()
    .map(|model| {
      json!({
        "id": model.id,
        "object": "model",
      })
    })
    .collect()
}

fn warm_model_cache(provider: &dyn crate::provider::Provider, arr: &[Value]) {
  provider.info().model_cache.set_models(arr);
}

fn merge_models(
  out: &mut Vec<Value>,
  seen: &mut HashSet<String>,
  arr: Vec<Value>,
  mode: RouteMode,
  provider: &dyn crate::provider::Provider,
) {
  for mut m in arr {
    let upstream_id = m.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if upstream_id.is_empty() {
      continue;
    }
    let id = model_id_for_policy(mode, provider, &upstream_id);
    if !seen.insert(id.clone()) {
      continue;
    }
    set_model_id(&mut m, &id);
    enrich(&mut m, &upstream_id, &id, provider);
    out.push(m);
  }
}

fn model_id_for_policy(mode: RouteMode, provider: &dyn crate::provider::Provider, upstream_id: &str) -> String {
  if matches!(mode, RouteMode::Exact) {
    format!("{}/{}", provider.info().id, upstream_id)
  } else {
    upstream_id.to_string()
  }
}

fn set_model_id(entry: &mut Value, id: &str) {
  if let Some(obj) = entry.as_object_mut() {
    obj.insert("id".into(), Value::String(id.to_string()));
  }
}

/// Attach an `x_tokn_router` block describing the provider and (when known)
/// the model's static capability/cost/limit metadata.
fn enrich(entry: &mut Value, upstream_id: &str, rendered_id: &str, provider: &dyn crate::provider::Provider) {
  let info = provider.info();
  let mut meta = Map::new();
  meta.insert("provider".into(), json!(info.id));
  meta.insert("provider_display_name".into(), json!(info.display_name));
  meta.insert("upstream_id".into(), json!(upstream_id));
  meta.insert("model_id".into(), json!(rendered_id));
  meta.insert(
    "auth_kind".into(),
    serde_json::to_value(info.auth_kind).unwrap_or(Value::Null),
  );

  if let Some(mi) = provider.model_info(upstream_id) {
    meta.insert("name".into(), json!(mi.name));
    meta.insert(
      "capabilities".into(),
      serde_json::to_value(&mi.capabilities).unwrap_or(Value::Null),
    );
    if let Some(cost) = &mi.cost {
      meta.insert("cost".into(), serde_json::to_value(cost).unwrap_or(Value::Null));
    }
    meta.insert("limit".into(), serde_json::to_value(&mi.limit).unwrap_or(Value::Null));
    if let Some(rd) = &mi.release_date {
      meta.insert("release_date".into(), json!(rd));
    }
  }

  let efforts =
    tokn_core::provider::upstream_reasoning_efforts(entry).or_else(|| provider.reasoning_efforts(upstream_id));
  let capabilities = meta.entry("capabilities").or_insert_with(|| json!({}));
  capabilities["reasoning_efforts"] = json!(efforts);

  if let Some(obj) = entry.as_object_mut() {
    obj.insert("x_tokn_router".into(), Value::Object(meta));
  }
}

/// Profile-prefixed variant: `/{profile}/v1/models`
pub async fn list_models_with_profile(
  State(s): State<LiveAppState>,
  Extension(access): Extension<AccessContext>,
  Path(profile): Path<String>,
) -> Result<Json<Value>, ApiError> {
  let s = s.current();
  let policy = s
    .profiles
    .get(&profile)
    .cloned()
    .ok_or_else(|| ApiError::bad_request(format!("unknown profile '{profile}'")))?;
  list_models_for_policy(s, policy, &access).await
}

use crate::adapter::{source_provider_id, AgentAdapter, ProviderRoute};
use crate::jsonc::{parse_cst, set_property};
use crate::projection::{
  publication_ids, AgentConfigProjection, ModelReferenceMatch, ModelReferenceRule, ProviderPublication, PublishedModel,
  SHARED_PROVIDER_ID,
};
use crate::reconcile::{annotate_imported_account, EditKind, PlannedEdit};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tokn_config::{Account, AuthType};
use tokn_core::account::AccountTier;
use tokn_core::util::secret::Secret;
use tokn_core::AgentId;

pub(crate) struct OpencodeAdapter;

const OPENCODE_CONFIG_JSON: &str = "opencode.json";
const OPENCODE_CONFIG_JSONC: &str = "opencode.jsonc";

/// OpenCode exposes Codex OAuth models through its `openai` provider
/// namespace, while the gateway keeps Codex as a distinct provider.
pub(crate) fn source_namespace_for_gateway(provider_id: &str) -> &str {
  if provider_id == tokn_core::provider::ID_CODEX {
    tokn_core::provider::ID_OPENAI
  } else {
    provider_id
  }
}

impl AgentAdapter for OpencodeAdapter {
  fn default_provider_id(&self) -> &'static str {
    tokn_core::provider::ID_OPENAI
  }

  fn auth_path(&self, home: &Path) -> PathBuf {
    crate::opencode_markdown::opencode_data_root(home).join("auth.json")
  }

  fn config_path(&self, home: &Path) -> PathBuf {
    opencode_config_path(home)
  }

  fn discover_accounts(&self, home: &Path, timestamp: &str) -> Result<Vec<Account>> {
    let auth_path = self.auth_path(home);
    if !auth_path.exists() {
      return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&auth_path).with_context(|| format!("reading {}", auth_path.display()))?;
    let json = serde_json::from_str(&raw).with_context(|| format!("parsing {}", auth_path.display()))?;
    Ok(accounts_from_auth_json(&json, &auth_path, timestamp))
  }

  fn transfers_credentials(&self) -> bool {
    true
  }

  fn supports_main_accounts(&self) -> bool {
    true
  }

  fn switch_endpoint(&self) -> tokn_core::provider::Endpoint {
    tokn_core::provider::Endpoint::ChatCompletions
  }

  fn supports_exact_mode(&self) -> bool {
    true
  }

  fn rewrite_config(&self, home: &Path, projection: &AgentConfigProjection<'_>) -> Result<Vec<PlannedEdit>> {
    let config_path = self.config_path(home);
    let config_existed = config_path.exists();
    let raw = if config_existed {
      std::fs::read_to_string(&config_path).with_context(|| format!("reading {}", config_path.display()))?
    } else {
      "{}\n".to_string()
    };
    let root = parse_cst(&raw, &config_path)?;
    rewrite_projected_config(&root, projection)?;

    let mut edits = Vec::new();
    if let Some(auth_edit) = remove_transferred_credentials(&self.auth_path(home), projection.credential_routes)? {
      edits.push(auth_edit);
    }
    edits.push(PlannedEdit::new(
      config_path,
      EditKind::Jsonc(root.to_string()),
      true,
      config_existed.then(|| raw.into_bytes()),
    ));
    Ok(edits)
  }

  fn restore_transferred_credentials(&self, auth_path: &Path, accounts: &[Account]) -> Result<()> {
    restore_transferred_credentials(auth_path, accounts)
  }
}

fn opencode_config_path(home: &Path) -> PathBuf {
  let root = crate::opencode_markdown::opencode_config_root(home);
  let jsonc = root.join(OPENCODE_CONFIG_JSONC);
  if jsonc.exists() {
    return jsonc;
  }
  let json = root.join(OPENCODE_CONFIG_JSON);
  if json.exists() {
    return json;
  }
  jsonc
}

fn rewrite_projected_config(
  root: &jsonc_parser::cst::CstRootNode,
  projection: &AgentConfigProjection<'_>,
) -> Result<()> {
  let Some(obj) = root.object_value() else {
    bail!("OpenCode config must contain a JSON object");
  };
  if obj.get("$schema").is_none() {
    set_property(&obj, "$schema", "https://opencode.ai/config.json");
  }
  let mut publications = projection.publications.to_vec();
  rewrite_selected_models(&obj, projection, &mut publications)?;
  if obj.get("provider").is_some() && obj.object_value("provider").is_none() {
    bail!("OpenCode config property 'provider' must contain an object");
  }
  let providers = obj.object_value_or_set("provider");
  preflight_publication_ownership(&providers, &publications)?;
  rewrite_provider_policies(&obj, &providers, projection, &publications)?;
  remove_stale_generated_providers(&obj, &providers, &publications)?;
  for publication in publications {
    set_property(&providers, &publication.provider_id, publication_value(&publication));
  }
  Ok(())
}

/// Dry-run the normal rewrite and compare semantic JSON so formatting and
/// comments do not count as drift.
pub(crate) fn projected_config_matches(raw: &str, path: &Path, projection: &AgentConfigProjection<'_>) -> Result<bool> {
  let before = crate::jsonc::parse_jsonc(raw, path)?;
  let rewritten = rewrite_projected_config_text(raw, path, projection)?;
  let after = crate::jsonc::parse_jsonc(&rewritten, path)?;
  Ok(before == after)
}

pub(crate) fn rewrite_projected_config_text(
  raw: &str,
  path: &Path,
  projection: &AgentConfigProjection<'_>,
) -> Result<String> {
  let root = parse_cst(raw, path)?;
  rewrite_projected_config(&root, projection)?;
  Ok(root.to_string())
}

fn rewrite_selected_models(
  obj: &jsonc_parser::cst::CstObject,
  projection: &AgentConfigProjection<'_>,
  publications: &mut [ProviderPublication],
) -> Result<()> {
  for selected_property in selected_model_properties(obj) {
    let Some(current) = selected_property
      .property
      .to_serde_value()
      .and_then(|value| value.as_str().map(str::to_string))
    else {
      continue;
    };
    let Some((source_provider_id, source_model_id)) = current.split_once('/') else {
      continue;
    };
    if source_model_id.is_empty()
      && projection
        .model_reference_rules
        .iter()
        .any(|rule| rule.source_provider_id == source_provider_id)
    {
      bail!(
        "OpenCode selection '{}' at {} has an empty model id",
        current,
        selected_property.path
      );
    }
    let rewritten = projection
      .model_reference_rules
      .iter()
      .filter(|rule| rule.source_provider_id == source_provider_id)
      .filter_map(|rule| {
        rewrite_model_reference(rule, source_model_id)
          .map(|rewritten| (model_match_rank(&rule.source_model_match), rewritten))
      })
      .max_by_key(|(rank, _)| *rank)
      .map(|(_, rewritten)| rewritten);
    let selected = rewritten
      .as_ref()
      .map(|(reference, _, _)| reference.as_str())
      .unwrap_or(&current);
    let Some((provider_id, model_id)) = selected.split_once('/') else {
      continue;
    };
    let target_is_published = publications
      .iter()
      .any(|publication| publication.provider_id == provider_id);
    if rewritten.is_some() && !target_is_published {
      bail!(
        "OpenCode selection '{}' at {} maps to unpublished gateway provider '{}'",
        current,
        selected_property.path,
        provider_id
      );
    }
    if managed_generated_provider_reference(obj, source_provider_id)
      && rewritten.is_none()
      && (!target_is_published
        || projection
          .previous_mode
          .is_some_and(|previous_mode| selection_topology(previous_mode) != selection_topology(projection.mode)))
    {
      bail!(
        "OpenCode selection '{}' at {} cannot be mapped safely while changing the gateway provider topology or target; select a model from the new generated provider and relink",
        current,
        selected_property.path
      );
    }
    let Some(publication) = publications
      .iter_mut()
      .find(|publication| publication.provider_id == provider_id)
    else {
      continue;
    };
    if projection.mode == tokn_config::RouteMode::Exact
      && source_provider_id == SHARED_PROVIDER_ID
      && rewritten.is_none()
      && !publication.models.contains_key(model_id)
    {
      bail!(
        "OpenCode exact selection '{}' at {} is not present in the generated gateway model catalogue; select a published provider-qualified model before relinking",
        current,
        selected_property.path
      );
    }
    if rewritten
      .as_ref()
      .is_some_and(|(_, _, allow_missing_model)| !allow_missing_model)
      && !publication.models.contains_key(model_id)
    {
      if provider_id == SHARED_PROVIDER_ID {
        bail!(
          "OpenCode selection '{}' at {} is not present in the new gateway model catalogue; select a published model before relinking",
          current,
          selected_property.path
        );
      } else {
        bail!(
          "OpenCode selection '{}' at {} is not published by the pinned gateway provider for this link; select a model published by that provider before relinking",
          current,
          selected_property.path
        );
      }
    }
    if rewritten.is_none() && !publication.models.contains_key(model_id) {
      bail!(
        "OpenCode selection '{}' at {} is not permitted by the generated gateway model catalogue; select a published model before relinking",
        current,
        selected_property.path
      );
    }
    let published_name = rewritten
      .as_ref()
      .map(|(_, source_model_id, _)| source_model_id.as_str())
      .unwrap_or(source_model_id);
    publication
      .models
      .entry(model_id.to_string())
      .or_insert_with(|| PublishedModel {
        name: published_name.to_string(),
      });
    if let Some((rewritten, _, _)) = rewritten {
      selected_property.property.set_value(rewritten.into());
    }
  }
  Ok(())
}

struct SelectedModelProperty {
  property: jsonc_parser::cst::CstObjectProp,
  path: String,
}

fn selected_model_properties(obj: &jsonc_parser::cst::CstObject) -> Vec<SelectedModelProperty> {
  let mut properties = Vec::new();
  for name in ["model", "small_model"] {
    if let Some(property) = obj.get(name) {
      properties.push(SelectedModelProperty {
        property,
        path: format!("$.{name}"),
      });
    }
  }
  collect_named_model_properties(obj, "agent", &mut properties);
  collect_named_model_properties(obj, "command", &mut properties);
  collect_named_model_properties(obj, "mode", &mut properties);
  properties
}

fn collect_named_model_properties(
  obj: &jsonc_parser::cst::CstObject,
  collection_name: &str,
  selected: &mut Vec<SelectedModelProperty>,
) {
  let Some(collection) = obj.object_value(collection_name) else {
    return;
  };
  for entry in collection.properties() {
    let Some(entry_name) = entry.name().and_then(|name| name.decoded_value().ok()) else {
      continue;
    };
    let Some(entry) = entry.value().and_then(|value| value.as_object()) else {
      continue;
    };
    if let Some(property) = entry.get("model") {
      selected.push(SelectedModelProperty {
        property,
        path: format!("$.{collection_name}.{entry_name}.model"),
      });
    }
  }
}

fn rewrite_model_reference(rule: &ModelReferenceRule, source_model_id: &str) -> Option<(String, String, bool)> {
  let source_model_id = match &rule.source_model_match {
    ModelReferenceMatch::Exact(model_id) if model_id == source_model_id => source_model_id,
    ModelReferenceMatch::Exact(_) => return None,
    ModelReferenceMatch::EndpointIncompatible(rules) => {
      let endpoint_rule = rules
        .iter()
        .find(|endpoint_rule| tokn_core::provider::glob_match(&endpoint_rule.pattern, source_model_id))?;
      if endpoint_rule.allows_endpoint {
        return None;
      }
      source_model_id
    }
    ModelReferenceMatch::Any => source_model_id,
    ModelReferenceMatch::Prefix(prefix) => source_model_id
      .strip_prefix(prefix)?
      .strip_prefix('/')
      .filter(|model_id| !model_id.is_empty())?,
  };
  let model_id = rule
    .target_model_prefix
    .as_deref()
    .map(|prefix| format!("{prefix}/{source_model_id}"))
    .unwrap_or_else(|| source_model_id.to_string());
  Some((
    format!("{}/{model_id}", rule.target_provider_id),
    source_model_id.to_string(),
    rule.allow_missing_model,
  ))
}

fn model_match_rank(model_match: &ModelReferenceMatch) -> usize {
  match model_match {
    ModelReferenceMatch::Exact(_) => 3,
    ModelReferenceMatch::EndpointIncompatible(_) => 2,
    ModelReferenceMatch::Prefix(_) => 1,
    ModelReferenceMatch::Any => 0,
  }
}

pub(crate) fn projected_model_reference(rules: &[ModelReferenceRule], current: &str) -> Option<(String, String, bool)> {
  let (source_provider_id, source_model_id) = current.split_once('/')?;
  rules
    .iter()
    .filter(|rule| rule.source_provider_id == source_provider_id)
    .filter_map(|rule| {
      rewrite_model_reference(rule, source_model_id)
        .map(|rewritten| (model_match_rank(&rule.source_model_match), rewritten))
    })
    .max_by_key(|(rank, _)| *rank)
    .map(|(_, rewritten)| rewritten)
}

fn selection_topology(mode: tokn_config::RouteMode) -> u8 {
  match mode {
    tokn_config::RouteMode::Exact => 1,
    tokn_config::RouteMode::Passthrough | tokn_config::RouteMode::Switch => 2,
    tokn_config::RouteMode::Route | tokn_config::RouteMode::Fuzzy => 0,
  }
}

pub(crate) fn generated_provider_id(provider_id: &str) -> bool {
  provider_id == SHARED_PROVIDER_ID || provider_id.starts_with(&format!("{SHARED_PROVIDER_ID}-"))
}

fn managed_generated_provider_reference(obj: &jsonc_parser::cst::CstObject, provider_id: &str) -> bool {
  if !generated_provider_id(provider_id) {
    return false;
  }
  let user_owns_namespace = obj
    .object_value("provider")
    .and_then(|providers| providers.get(provider_id))
    .and_then(|provider| provider.to_serde_value())
    .is_some_and(|provider| !managed_generated_provider(provider_id, &provider));
  !user_owns_namespace
}

fn publication_value(publication: &ProviderPublication) -> jsonc_parser::cst::CstInputValue {
  use jsonc_parser::cst::CstInputValue;

  let models = publication
    .models
    .iter()
    .map(|(model_id, model)| {
      (
        model_id.clone(),
        CstInputValue::Object(vec![("name".to_string(), model.name.clone().into())]),
      )
    })
    .collect();
  CstInputValue::Object(vec![
    ("name".to_string(), publication.display_name.clone().into()),
    ("npm".to_string(), "@ai-sdk/openai-compatible".into()),
    (
      "options".to_string(),
      CstInputValue::Object(vec![
        ("baseURL".to_string(), publication.base_url.clone().into()),
        ("apiKey".to_string(), "tokn-router".into()),
      ]),
    ),
    ("models".to_string(), CstInputValue::Object(models)),
  ])
}

fn preflight_publication_ownership(
  providers: &jsonc_parser::cst::CstObject,
  publications: &[ProviderPublication],
) -> Result<()> {
  for publication in publications {
    let Some(existing) = providers.get(&publication.provider_id) else {
      continue;
    };
    let Some(value) = existing.to_serde_value() else {
      bail!(
        "OpenCode provider '{}' is not an object and cannot be managed by the agent link",
        publication.provider_id
      );
    };
    if !value.is_object() {
      bail!(
        "OpenCode provider '{}' is not an object and cannot be managed by the agent link",
        publication.provider_id
      );
    }
    if !is_generated_provider(&publication.provider_id, &value) {
      bail!(
        "OpenCode provider '{}' already exists and is not managed by the agent link",
        publication.provider_id
      );
    }
  }
  Ok(())
}

fn rewrite_provider_policies(
  obj: &jsonc_parser::cst::CstObject,
  providers: &jsonc_parser::cst::CstObject,
  projection: &AgentConfigProjection<'_>,
  publications: &[ProviderPublication],
) -> Result<()> {
  let active = publication_ids(publications);
  let stale = managed_stale_provider_ids(providers, &active);
  let stale_generated_namespaces = stale
    .iter()
    .filter(|provider_id| generated_provider_id(provider_id))
    .map(String::as_str)
    .collect::<BTreeSet<_>>();
  let managed_source_ids = projection
    .credential_routes
    .iter()
    .filter(|route| route.transfer_source_auth || !route.account_id.is_empty())
    .map(|route| route.source_provider_id.as_str())
    .collect::<BTreeSet<_>>();

  if let Some(property) = obj.get("enabled_providers") {
    let values = provider_policy_values(&property, "enabled_providers")?;
    let mut rewritten = values
      .iter()
      .filter(|provider_id| {
        !stale_generated_namespaces.contains(provider_id.as_str()) && !managed_source_ids.contains(provider_id.as_str())
      })
      .cloned()
      .collect::<Vec<_>>();
    for publication in publications {
      if !rewritten.contains(&publication.provider_id) {
        rewritten.push(publication.provider_id.clone());
      }
    }
    if rewritten != values {
      property.set_value(rewritten.into());
    }
  }

  if let Some(property) = obj.get("disabled_providers") {
    let values = provider_policy_values(&property, "disabled_providers")?;
    if let Some(provider_id) = values.iter().find(|provider_id| {
      active.contains(provider_id.as_str())
        || stale_generated_namespaces.contains(provider_id.as_str())
        || managed_source_ids.contains(provider_id.as_str())
    }) {
      bail!("OpenCode disabled_providers contains gateway-managed provider '{provider_id}'; remove it before linking");
    }
  }
  Ok(())
}

fn provider_policy_values(property: &jsonc_parser::cst::CstObjectProp, name: &str) -> Result<Vec<String>> {
  let Some(Value::Array(values)) = property.to_serde_value() else {
    bail!("OpenCode config property '{name}' must contain an array of provider ids");
  };
  values
    .into_iter()
    .map(|value| {
      value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("OpenCode config property '{name}' must contain only provider ids"))
    })
    .collect()
}

fn managed_stale_provider_ids(providers: &jsonc_parser::cst::CstObject, active: &BTreeSet<&str>) -> BTreeSet<String> {
  let Some(Value::Object(values)) = providers.to_serde_value() else {
    return BTreeSet::new();
  };
  values
    .into_iter()
    .filter(|(provider_id, value)| {
      !active.contains(provider_id.as_str()) && managed_generated_provider(provider_id, value)
    })
    .map(|(provider_id, _)| provider_id)
    .collect()
}

fn remove_stale_generated_providers(
  obj: &jsonc_parser::cst::CstObject,
  providers: &jsonc_parser::cst::CstObject,
  publications: &[ProviderPublication],
) -> Result<()> {
  let active = publication_ids(publications);
  let Some(Value::Object(values)) = providers.to_serde_value() else {
    return Ok(());
  };
  for (provider_id, value) in values {
    if active.contains(provider_id.as_str()) || !managed_generated_provider(&provider_id, &value) {
      continue;
    }
    if config_references_provider(obj, &provider_id) {
      bail!("stale generated OpenCode provider '{provider_id}' is still referenced by the config");
    }
    if let Some(provider) = providers.get(&provider_id) {
      provider.remove();
    }
  }
  Ok(())
}

fn managed_generated_provider(provider_id: &str, value: &Value) -> bool {
  is_generated_provider(provider_id, value)
    && (provider_id == SHARED_PROVIDER_ID
      || provider_id.starts_with(&format!("{SHARED_PROVIDER_ID}-"))
      || is_legacy_source_provider(provider_id, value))
}

fn is_generated_provider(provider_id: &str, value: &Value) -> bool {
  let Some(provider) = value.as_object() else {
    return false;
  };
  if !provider
    .keys()
    .all(|key| matches!(key.as_str(), "name" | "npm" | "options" | "models"))
    || provider.get("npm").and_then(Value::as_str) != Some("@ai-sdk/openai-compatible")
    || !generated_provider_name(provider_id, provider.get("name").and_then(Value::as_str))
    || provider.get("models").is_some_and(|models| !models.is_object())
  {
    return false;
  }
  let Some(options) = provider.get("options").and_then(Value::as_object) else {
    return false;
  };
  options.len() == 2
    && options.get("apiKey").and_then(Value::as_str) == Some("tokn-router")
    && options
      .get("baseURL")
      .and_then(Value::as_str)
      .is_some_and(|base_url| base_url.starts_with("http://") || base_url.starts_with("https://"))
}

fn generated_provider_name(provider_id: &str, name: Option<&str>) -> bool {
  match name {
    Some("tokn-router") | Some("Tokn Router") if provider_id == SHARED_PROVIDER_ID => true,
    Some(name) if name == format!("tokn-router ({provider_id})") => true,
    Some(name) if provider_id.starts_with(&format!("{SHARED_PROVIDER_ID}-")) && name.starts_with("Tokn Router (") => {
      true
    }
    _ => false,
  }
}

fn is_legacy_source_provider(provider_id: &str, value: &Value) -> bool {
  value
    .get("name")
    .and_then(Value::as_str)
    .is_some_and(|name| name == format!("tokn-router ({provider_id})"))
}

fn config_references_provider(obj: &jsonc_parser::cst::CstObject, provider_id: &str) -> bool {
  selected_model_properties(obj).iter().any(|selected| {
    selected
      .property
      .to_serde_value()
      .and_then(|value| value.as_str().map(str::to_string))
      .is_some_and(|model| model.starts_with(&format!("{provider_id}/")))
  }) || ["enabled_providers", "disabled_providers"].iter().any(|name| {
    obj
      .get(name)
      .and_then(|property| property.to_serde_value())
      .and_then(|value| value.as_array().cloned())
      .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(provider_id)))
  })
}

fn remove_transferred_credentials(auth_path: &Path, routes: &[ProviderRoute]) -> Result<Option<PlannedEdit>> {
  let providers = routes
    .iter()
    .filter(|route| route.transfer_source_auth)
    .map(|route| route.source_provider_id.as_str())
    .collect::<BTreeSet<_>>();
  // Main-account links deliberately leave OpenCode's credentials alone. Do
  // not even parse the auth file when no source credential is being moved.
  if providers.is_empty() {
    return Ok(None);
  }
  if !auth_path.exists() {
    return Ok(None);
  }
  let raw = std::fs::read_to_string(auth_path).with_context(|| format!("reading {}", auth_path.display()))?;
  let mut json: Value = serde_json::from_str(&raw).with_context(|| format!("parsing {}", auth_path.display()))?;
  let Some(auth) = json.as_object_mut() else {
    bail!("{} must contain a JSON object", auth_path.display());
  };
  let mut changed = false;
  for provider in providers {
    changed |= auth.remove(provider).is_some();
  }
  Ok(changed.then(|| {
    PlannedEdit::new(
      auth_path.to_path_buf(),
      EditKind::Json(json),
      // The gateway-owned credentials are the rollback source of truth. Avoid
      // leaving adjacent plaintext token backups behind.
      false,
      Some(raw.into_bytes()),
    )
  }))
}

fn restore_transferred_credentials(auth_path: &Path, accounts: &[Account]) -> Result<()> {
  if accounts.is_empty() {
    return Ok(());
  }
  let mut json = if auth_path.exists() {
    let raw = std::fs::read_to_string(auth_path).with_context(|| format!("reading {}", auth_path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", auth_path.display()))?
  } else {
    Value::Object(serde_json::Map::new())
  };
  let Some(auth) = json.as_object_mut() else {
    bail!("{} must contain a JSON object", auth_path.display());
  };
  for account in accounts {
    let provider = source_provider_id(account)
      .with_context(|| format!("transferred account '{}' is missing its OpenCode provider", account.id))?;
    if auth.contains_key(provider) {
      continue;
    }
    auth.insert(provider.to_string(), opencode_auth_record(provider, account)?);
  }
  write_sensitive_json(auth_path, &json)
}

fn opencode_auth_record(source_provider: &str, account: &Account) -> Result<Value> {
  if let Some(api_key) = &account.api_key {
    return Ok(serde_json::json!({
      "type": "api",
      "key": api_key.expose()
    }));
  }
  let refresh = account
    .refresh_token
    .as_ref()
    .with_context(|| format!("transferred account '{}' has no refresh token", account.id))?;
  let mut record = serde_json::Map::new();
  record.insert("type".into(), Value::String("oauth".into()));
  record.insert("refresh".into(), Value::String(refresh.expose().to_string()));
  if source_provider == tokn_core::provider::ID_GITHUB_COPILOT {
    record.insert("access".into(), Value::String(refresh.expose().to_string()));
    record.insert("expires".into(), Value::Number(0.into()));
  } else {
    let access = account
      .access_token
      .as_ref()
      .with_context(|| format!("transferred account '{}' has no access token", account.id))?;
    let expires = account
      .access_token_expires_at
      .with_context(|| format!("transferred account '{}' has no access-token expiry", account.id))?;
    if expires < 0 {
      bail!(
        "transferred account '{}' has a negative access-token expiry",
        account.id
      );
    }
    record.insert("access".into(), Value::String(access.expose().to_string()));
    record.insert("expires".into(), Value::Number(expires.saturating_mul(1_000).into()));
  }
  if let Some(account_id) = &account.provider_account_id {
    record.insert("accountId".into(), Value::String(account_id.clone()));
  }
  Ok(Value::Object(record))
}

fn write_sensitive_json(path: &Path, value: &Value) -> Result<()> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
  }
  let bytes = serde_json::to_vec_pretty(value)?;
  write_sensitive(path, &bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(unix)]
fn write_sensitive(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  use std::io::Write;
  use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
  let mut file = std::fs::OpenOptions::new()
    .create(true)
    .truncate(true)
    .write(true)
    .mode(0o600)
    .open(path)?;
  file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
  file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_sensitive(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  std::fs::write(path, bytes)
}

fn accounts_from_auth_json(json: &Value, auth_path: &Path, timestamp: &str) -> Vec<Account> {
  let Some(providers) = json.as_object() else {
    return Vec::new();
  };

  providers
    .iter()
    .filter_map(|(provider, auth)| {
      account_from_provider_auth(provider, auth).map(|account| {
        let mut account = annotate_imported_account(
          account,
          AgentId::Opencode,
          auth_path,
          &format!("auth.{provider}"),
          timestamp,
        );
        account
          .settings
          .get_mut("import")
          .and_then(toml::Value::as_table_mut)
          .expect("import metadata inserted")
          .insert("source_provider".into(), toml::Value::String(provider.clone()));
        account
      })
    })
    .collect()
}

fn account_from_provider_auth(provider: &str, auth: &Value) -> Option<Account> {
  let auth = auth.as_object()?;
  match (provider, auth.get("type").and_then(Value::as_str)?) {
    (tokn_core::provider::ID_OPENAI, "api") => {
      let api_key = auth.get("key").and_then(Value::as_str)?.trim();
      if api_key.is_empty() {
        return None;
      }
      Some(openai_account_from_key(api_key))
    }
    (tokn_core::provider::ID_OPENAI, "oauth") => oauth_account_from_auth(
      "opencode-codex",
      tokn_core::provider::ID_CODEX,
      "opencode Codex migration",
      Some(tokn_provider_openai::codex::CODEX_BASE_URL),
      Some(tokn_provider_openai::CODEX_OAUTH_TOKEN_URL),
      auth,
      auth
        .get("accountId")
        .or_else(|| auth.get("account_id"))
        .and_then(Value::as_str),
    ),
    (tokn_core::provider::ID_GITHUB_COPILOT, "oauth") if !has_enterprise_url(auth) => oauth_account_from_auth(
      "opencode-github-copilot",
      tokn_core::provider::ID_GITHUB_COPILOT,
      "opencode GitHub Copilot migration",
      Some(tokn_provider_copilot::COPILOT_BASE_URL),
      Some(tokn_provider_copilot::COPILOT_TOKEN_EXCHANGE_URL),
      auth,
      None,
    ),
    (_, "api") => generic_api_key_account(provider, auth),
    _ => None,
  }
}

fn generic_api_key_account(provider: &str, auth: &serde_json::Map<String, Value>) -> Option<Account> {
  let api_key = auth.get("key").and_then(Value::as_str)?.trim();
  if api_key.is_empty() {
    return None;
  }
  let registry = tokn_accounts::registry::Registry::builtin();
  let descriptor = registry.resolve(provider)?;
  if !descriptor.supports_credential(tokn_auth::CredentialFlavor::ApiKey) {
    return None;
  }
  let account = Account {
    id: format!("opencode-{provider}"),
    provider: provider.to_string(),
    enabled: true,
    tier: AccountTier::Active,
    tags: vec!["agent-migrated".into(), "opencode".into()],
    label: Some(format!("opencode {} migration", descriptor.display_name)),
    base_url: Some(descriptor.base_url.to_string()),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: Some(Secret::new(api_key.to_string())),
    api_key_expires_at: None,
    access_token: None,
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: toml::Table::new(),
  };
  registry.validate(&account).ok()?;
  Some(account)
}

fn openai_account_from_key(api_key: &str) -> Account {
  Account {
    id: "opencode-openai".into(),
    provider: tokn_core::provider::ID_OPENAI.into(),
    enabled: true,
    tier: AccountTier::Active,
    tags: vec!["agent-migrated".into(), "opencode".into()],
    label: Some("opencode migration".into()),
    base_url: Some(tokn_provider_openai::openai::OPENAI_BASE_URL.into()),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: Some(Secret::new(api_key.to_string())),
    api_key_expires_at: None,
    access_token: None,
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: toml::Table::new(),
  }
}

fn oauth_account_from_auth(
  id: &str,
  provider: &str,
  label: &str,
  base_url: Option<&str>,
  refresh_url: Option<&str>,
  auth: &serde_json::Map<String, Value>,
  provider_account_id: Option<&str>,
) -> Option<Account> {
  let refresh = auth.get("refresh").and_then(Value::as_str)?.trim();
  if refresh.is_empty() {
    return None;
  }
  let access = auth.get("access").and_then(Value::as_str).and_then(non_empty_string)?;
  let expires = auth.get("expires").and_then(expires_at)?;
  Some(Account {
    id: id.into(),
    provider: provider.into(),
    enabled: true,
    tier: AccountTier::Active,
    tags: vec!["agent-migrated".into(), "opencode".into()],
    label: Some(label.into()),
    base_url: base_url.map(str::to_string),
    headers: Default::default(),
    auth_type: Some(AuthType::Bearer),
    username: None,
    api_key: None,
    api_key_expires_at: None,
    access_token: Some(Secret::new(access)),
    access_token_expires_at: Some(expires),
    id_token: None,
    refresh_token: Some(Secret::new(refresh.to_string())),
    provider_account_id: provider_account_id.and_then(non_empty_string),
    extra: Default::default(),
    refresh_url: refresh_url.map(str::to_string),
    last_refresh: None,
    settings: toml::Table::new(),
  })
}

fn non_empty_string(value: &str) -> Option<String> {
  let value = value.trim();
  (!value.is_empty()).then(|| value.to_string())
}

fn has_enterprise_url(auth: &serde_json::Map<String, Value>) -> bool {
  auth
    .get("enterpriseUrl")
    .or_else(|| auth.get("enterprise_url"))
    .and_then(Value::as_str)
    .is_some_and(|value| !value.trim().is_empty())
}

fn expires_at(value: &Value) -> Option<i64> {
  let expires = match value {
    Value::Number(n) => n
      .as_i64()
      .or_else(|| n.as_u64().and_then(|value| i64::try_from(value).ok())),
    Value::String(s) => s.trim().parse().ok(),
    _ => None,
  }?;
  if expires < 0 {
    return None;
  }
  Some(if expires > 10_000_000_000 {
    expires / 1_000
  } else {
    expires
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::projection::compile_opencode_publications;
  use std::collections::BTreeMap;
  use tokn_config::RouteMode;
  use tokn_core::provider::Endpoint;

  const BASE_URL: &str = "http://127.0.0.1:4141/opencode/v1";

  fn route(source: &str, provider: &str, account: &str, base_url: &str) -> ProviderRoute {
    ProviderRoute {
      source_provider_id: source.into(),
      gateway_provider_id: provider.into(),
      account_id: account.into(),
      profile: format!("opencode-{provider}"),
      base_url: base_url.into(),
      transfer_source_auth: true,
    }
  }

  fn publication(provider_id: &str, base_url: &str, models: &[(&str, &str)]) -> ProviderPublication {
    ProviderPublication {
      provider_id: provider_id.to_string(),
      display_name: if provider_id == SHARED_PROVIDER_ID {
        "Tokn Router".to_string()
      } else {
        format!("Tokn Router ({provider_id})")
      },
      base_url: base_url.to_string(),
      models: models
        .iter()
        .map(|(id, name)| {
          (
            (*id).to_string(),
            PublishedModel {
              name: (*name).to_string(),
            },
          )
        })
        .collect(),
    }
  }

  fn rule(source: &str, target: &str, model_prefix: Option<&str>) -> ModelReferenceRule {
    ModelReferenceRule {
      source_provider_id: source.to_string(),
      source_model_match: ModelReferenceMatch::Any,
      target_provider_id: target.to_string(),
      target_model_prefix: model_prefix.map(str::to_string),
      allow_missing_model: true,
    }
  }

  fn matched_rule(
    source: &str,
    source_model_match: ModelReferenceMatch,
    target: &str,
    target_model_prefix: Option<&str>,
  ) -> ModelReferenceRule {
    ModelReferenceRule {
      source_provider_id: source.to_string(),
      source_model_match,
      target_provider_id: target.to_string(),
      target_model_prefix: target_model_prefix.map(str::to_string),
      allow_missing_model: true,
    }
  }

  fn rewrite(
    raw: &str,
    mode: RouteMode,
    publications: &[ProviderPublication],
    rules: &[ModelReferenceRule],
  ) -> Result<(String, Value)> {
    rewrite_transition(raw, Some(mode), mode, publications, rules)
  }

  fn rewrite_transition(
    raw: &str,
    previous_mode: Option<RouteMode>,
    mode: RouteMode,
    publications: &[ProviderPublication],
    rules: &[ModelReferenceRule],
  ) -> Result<(String, Value)> {
    rewrite_transition_with_routes(raw, previous_mode, mode, publications, rules, &[])
  }

  fn rewrite_transition_with_routes(
    raw: &str,
    previous_mode: Option<RouteMode>,
    mode: RouteMode,
    publications: &[ProviderPublication],
    rules: &[ModelReferenceRule],
    routes: &[ProviderRoute],
  ) -> Result<(String, Value)> {
    let path = Path::new("opencode.jsonc");
    let root = parse_cst(raw, path)?;
    rewrite_projected_config(
      &root,
      &AgentConfigProjection {
        target_base_url: BASE_URL,
        mode,
        previous_mode,
        credential_routes: routes,
        publications,
        model_reference_rules: rules,
      },
    )?;
    let output = root.to_string();
    let json = crate::jsonc::parse_jsonc(&output, path)?;
    Ok((output, json))
  }

  #[test]
  fn normalized_modes_publish_one_synthetic_provider_and_rewrite_selections() {
    for mode in [RouteMode::Route, RouteMode::Fuzzy, RouteMode::Exact] {
      let exact = mode == RouteMode::Exact;
      let model_id = if exact { "openai/gpt-5" } else { "gpt-5" };
      let publications = [publication(
        SHARED_PROVIDER_ID,
        BASE_URL,
        &[(model_id, "GPT-5"), ("always-published", "Always published")],
      )];
      let rules = [rule("openai", SHARED_PROVIDER_ID, exact.then_some("openai"))];
      let (output, json) = rewrite(
        r#"{
  // project defaults remain readable.
  "model": "openai/gpt-5",
  "mcp": {"x": true},
  "provider": {
    "anthropic": {"options": {"apiKey": "keep"}}
  }
}"#,
        mode,
        &publications,
        &rules,
      )
      .unwrap();

      let expected_model = if exact {
        "tokn-router/openai/gpt-5"
      } else {
        "tokn-router/gpt-5"
      };
      assert!(output.contains("// project defaults remain readable."));
      assert_eq!(json["model"], expected_model);
      assert_eq!(json["mcp"]["x"], true);
      assert_eq!(json["provider"]["anthropic"]["options"]["apiKey"], "keep");
      assert_eq!(json["provider"]["tokn-router"]["name"], "Tokn Router");
      assert_eq!(json["provider"]["tokn-router"]["npm"], "@ai-sdk/openai-compatible");
      assert_eq!(json["provider"]["tokn-router"]["options"]["baseURL"], BASE_URL);
      assert_eq!(json["provider"]["tokn-router"]["options"]["apiKey"], "tokn-router");
      assert_eq!(json["provider"]["tokn-router"]["models"][model_id]["name"], "GPT-5");
      assert_eq!(
        json["provider"]["tokn-router"]["models"]["always-published"]["name"],
        "Always published"
      );
      assert_eq!(
        json["provider"]
          .as_object()
          .unwrap()
          .keys()
          .filter(|provider_id| provider_id.starts_with(SHARED_PROVIDER_ID))
          .count(),
        1
      );
    }
  }

  #[test]
  fn allow_missing_rules_publish_selected_models_missing_from_the_catalogue() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let rules = [
      rule("openai", SHARED_PROVIDER_ID, None),
      rule("deepseek", SHARED_PROVIDER_ID, None),
    ];
    let (_, json) = rewrite(
      r#"{
  "model": "openai/organization/custom-model",
  "small_model": "deepseek/deepseek-v4-flash"
}"#,
      RouteMode::Route,
      &publications,
      &rules,
    )
    .unwrap();

    assert_eq!(json["model"], "tokn-router/organization/custom-model");
    assert_eq!(json["small_model"], "tokn-router/deepseek-v4-flash");
    assert_eq!(
      json["provider"]["tokn-router"]["models"]["organization/custom-model"]["name"],
      "organization/custom-model"
    );
    assert_eq!(
      json["provider"]["tokn-router"]["models"]["deepseek-v4-flash"]["name"],
      "deepseek-v4-flash"
    );
  }

  #[test]
  fn compiled_catalogue_preserves_genuinely_unknown_custom_models() {
    let provider_id = tokn_core::provider::ID_LLAMA_CPP;
    let routes = [route(provider_id, provider_id, "", BASE_URL)];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Route),
      Some(&[provider_id.to_string()]),
      BASE_URL,
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    for selected in [
      "llama-cpp/organization/custom-model",
      "tokn-router/organization/custom-model",
    ] {
      let (_, json) = rewrite_transition(
        &format!(r#"{{"model": "{selected}"}}"#),
        Some(RouteMode::Route),
        RouteMode::Route,
        &plan.publications,
        &plan.model_reference_rules,
      )
      .unwrap();

      assert_eq!(json["model"], "tokn-router/organization/custom-model");
      assert_eq!(
        json["provider"]["tokn-router"]["models"]["organization/custom-model"]["name"],
        "organization/custom-model"
      );
    }
  }

  #[test]
  fn compiled_pinned_catalogue_preserves_custom_models_across_safe_relinks() {
    let provider_id = tokn_core::provider::ID_LLAMA_CPP;
    let generated_provider_id = format!("{SHARED_PROVIDER_ID}-{provider_id}");
    let routes = [route(
      provider_id,
      provider_id,
      "",
      "http://127.0.0.1:4141/opencode-llama-cpp/v1",
    )];

    for (previous_mode, previous_provider_id, selected) in [
      (RouteMode::Route, provider_id, "tokn-router/organization/custom-model"),
      (
        RouteMode::Switch,
        tokn_core::provider::ID_OPENAI,
        "tokn-router-openai/organization/custom-model",
      ),
    ] {
      let plan = compile_opencode_publications(
        RouteMode::Switch,
        Some(previous_mode),
        Some(&[previous_provider_id.to_string()]),
        BASE_URL,
        &[],
        &routes,
        Endpoint::ChatCompletions,
      )
      .unwrap();
      let (_, json) = rewrite_transition(
        &format!(r#"{{"model": "{selected}"}}"#),
        Some(previous_mode),
        RouteMode::Switch,
        &plan.publications,
        &plan.model_reference_rules,
      )
      .unwrap();

      assert_eq!(
        json["model"],
        format!("{generated_provider_id}/organization/custom-model")
      );
      assert_eq!(
        json["provider"][generated_provider_id.as_str()]["models"]["organization/custom-model"]["name"],
        "organization/custom-model"
      );
    }
  }

  #[test]
  fn compiled_normalized_catalogue_rejects_unknown_models_for_static_providers() {
    let provider_id = tokn_core::provider::ID_OPENAI;
    let routes = [route(provider_id, provider_id, "", BASE_URL)];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Route),
      Some(&[provider_id.to_string()]),
      BASE_URL,
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    for source_provider_id in [provider_id, SHARED_PROVIDER_ID] {
      let error = rewrite_transition(
        &format!(r#"{{"model": "{source_provider_id}/organization/custom-model"}}"#),
        Some(RouteMode::Route),
        RouteMode::Route,
        &plan.publications,
        &plan.model_reference_rules,
      )
      .unwrap_err();

      assert!(error
        .to_string()
        .contains("is not present in the new gateway model catalogue"));
    }
  }

  #[test]
  fn compiled_catalogue_rejects_known_embedding_and_image_models() {
    let routes = [route(
      tokn_core::provider::ID_OPENAI,
      tokn_core::provider::ID_OPENAI,
      "",
      BASE_URL,
    )];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Route),
      Some(&[tokn_core::provider::ID_OPENAI.to_string()]),
      BASE_URL,
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    for source_provider_id in [tokn_core::provider::ID_OPENAI, SHARED_PROVIDER_ID] {
      for model_id in ["text-embedding-3-large", "gpt-image-1"] {
        let error = rewrite_transition(
          &format!(r#"{{"model": "{source_provider_id}/{model_id}"}}"#),
          Some(RouteMode::Route),
          RouteMode::Route,
          &plan.publications,
          &plan.model_reference_rules,
        )
        .unwrap_err();

        assert!(
          error
            .to_string()
            .contains("is not present in the new gateway model catalogue"),
          "{source_provider_id}/{model_id}: {error:#}"
        );
      }
    }
  }

  #[test]
  fn compiled_raw_catalogue_rejects_models_incompatible_with_the_endpoint() {
    let provider_id = tokn_core::provider::ID_GITHUB_COPILOT;
    let routes = [route(
      provider_id,
      provider_id,
      "",
      "http://127.0.0.1:4141/opencode-github-copilot/v1",
    )];
    let plan = compile_opencode_publications(
      RouteMode::Switch,
      Some(RouteMode::Switch),
      Some(&[provider_id.to_string()]),
      BASE_URL,
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    for source_provider_id in [provider_id.to_string(), format!("{SHARED_PROVIDER_ID}-{provider_id}")] {
      let error = rewrite_transition(
        &format!(r#"{{"model": "{source_provider_id}/gpt-5"}}"#),
        Some(RouteMode::Switch),
        RouteMode::Switch,
        &plan.publications,
        &plan.model_reference_rules,
      )
      .unwrap_err();

      assert!(error
        .to_string()
        .contains("is not published by the pinned gateway provider"));
    }
  }

  #[test]
  fn compiled_raw_catalogue_preserves_unknown_custom_models() {
    let provider_id = tokn_core::provider::ID_OPENAI;
    let generated_provider_id = format!("{SHARED_PROVIDER_ID}-{provider_id}");
    let routes = [route(
      provider_id,
      provider_id,
      "",
      "http://127.0.0.1:4141/opencode-openai/v1",
    )];
    let plan = compile_opencode_publications(
      RouteMode::Switch,
      Some(RouteMode::Switch),
      Some(&[provider_id.to_string()]),
      BASE_URL,
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    for source_provider_id in [provider_id.to_string(), generated_provider_id.clone()] {
      let (_, json) = rewrite_transition(
        &format!(r#"{{"model": "{source_provider_id}/organization/custom-model"}}"#),
        Some(RouteMode::Switch),
        RouteMode::Switch,
        &plan.publications,
        &plan.model_reference_rules,
      )
      .unwrap();

      assert_eq!(
        json["model"],
        format!("{generated_provider_id}/organization/custom-model")
      );
      assert_eq!(
        json["provider"][generated_provider_id.as_str()]["models"]["organization/custom-model"]["name"],
        "organization/custom-model"
      );
    }
  }

  #[test]
  fn exact_mode_qualifies_selected_models_and_rejects_ambiguous_shared_references() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let rules = [
      rule("deepseek", SHARED_PROVIDER_ID, Some("deepseek")),
      matched_rule(
        SHARED_PROVIDER_ID,
        ModelReferenceMatch::Prefix("deepseek".to_string()),
        SHARED_PROVIDER_ID,
        Some("deepseek"),
      ),
    ];
    let (output, json) = rewrite(
      r#"{
  "model": "deepseek/deepseek-v4-flash"
}"#,
      RouteMode::Exact,
      &publications,
      &rules,
    )
    .unwrap();

    assert_eq!(json["model"], "tokn-router/deepseek/deepseek-v4-flash");
    assert_eq!(
      json["provider"]["tokn-router"]["models"]["deepseek/deepseek-v4-flash"]["name"],
      "deepseek-v4-flash"
    );

    let (_, synced) = rewrite(&output, RouteMode::Exact, &publications, &rules).unwrap();
    assert_eq!(synced["model"], "tokn-router/deepseek/deepseek-v4-flash");
    assert_eq!(
      synced["provider"]["tokn-router"]["models"]["deepseek/deepseek-v4-flash"]["name"],
      "deepseek-v4-flash"
    );

    let error = rewrite(
      r#"{"model": "tokn-router/gpt-5"}"#,
      RouteMode::Exact,
      &publications,
      &rules,
    )
    .unwrap_err();
    assert!(error
      .to_string()
      .contains("is not present in the generated gateway model catalogue"));
  }

  #[test]
  fn exact_main_routes_with_a_shared_source_namespace_leave_direct_selections_untouched() {
    let mut routes = [
      route(
        tokn_core::provider::ID_OPENAI,
        tokn_core::provider::ID_OPENAI,
        "",
        BASE_URL,
      ),
      route(
        tokn_core::provider::ID_OPENAI,
        tokn_core::provider::ID_CODEX,
        "",
        BASE_URL,
      ),
    ];
    for route in &mut routes {
      route.transfer_source_auth = false;
    }
    let plan = compile_opencode_publications(
      RouteMode::Exact,
      None,
      None,
      BASE_URL,
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    let (_, json) = rewrite_transition(
      r#"{"model": "openai/gpt-5"}"#,
      None,
      RouteMode::Exact,
      &plan.publications,
      &plan.model_reference_rules,
    )
    .unwrap();

    assert_eq!(json["model"], "openai/gpt-5");
    assert!(json["provider"][SHARED_PROVIDER_ID]["models"]["openai/gpt-5"].is_object());
  }

  #[test]
  fn ordered_model_rules_strip_qualified_prefixes_before_using_fallbacks() {
    let publications = [
      publication(
        "tokn-router-deepseek",
        "http://127.0.0.1:4141/opencode-deepseek/v1",
        &[("deepseek-v4-flash", "DeepSeek V4 Flash")],
      ),
      publication(
        "tokn-router-openai",
        "http://127.0.0.1:4141/opencode-openai/v1",
        &[("gpt-5", "GPT-5")],
      ),
    ];
    let rules = [
      matched_rule(
        SHARED_PROVIDER_ID,
        ModelReferenceMatch::Prefix("deepseek".to_string()),
        "tokn-router-deepseek",
        None,
      ),
      matched_rule(
        SHARED_PROVIDER_ID,
        ModelReferenceMatch::Exact("gpt-5".to_string()),
        "tokn-router-openai",
        None,
      ),
    ];
    let (_, json) = rewrite(
      r#"{
  "model": "tokn-router/deepseek/deepseek-v4-flash",
  "small_model": "tokn-router/gpt-5"
}"#,
      RouteMode::Switch,
      &publications,
      &rules,
    )
    .unwrap();

    assert_eq!(json["model"], "tokn-router-deepseek/deepseek-v4-flash");
    assert_eq!(json["small_model"], "tokn-router-openai/gpt-5");
  }

  #[test]
  fn relinking_from_pinned_to_exact_rewrites_the_selection_before_cleanup() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let rules = [matched_rule(
      "tokn-router-openai",
      ModelReferenceMatch::Any,
      SHARED_PROVIDER_ID,
      Some("openai"),
    )];
    let (_, json) = rewrite_transition(
      r#"{
  "model": "tokn-router-openai/custom-model",
  "provider": {
    "tokn-router-openai": {
      "name": "Tokn Router (OpenAI)",
      "npm": "@ai-sdk/openai-compatible",
      "models": {"custom-model": {"name": "Custom model"}},
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/opencode-openai/v1"
      }
    }
  }
}"#,
      Some(RouteMode::Switch),
      RouteMode::Exact,
      &publications,
      &rules,
    )
    .unwrap();

    assert_eq!(json["model"], "tokn-router/openai/custom-model");
    assert!(json["provider"].get("tokn-router-openai").is_none());
    assert_eq!(
      json["provider"]["tokn-router"]["models"]["openai/custom-model"]["name"],
      "custom-model"
    );
  }

  #[test]
  fn relinking_from_exact_to_route_removes_the_provider_qualifier() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[("gpt-5", "GPT-5")])];
    let rules = [
      matched_rule(
        SHARED_PROVIDER_ID,
        ModelReferenceMatch::Prefix("openai".to_string()),
        SHARED_PROVIDER_ID,
        None,
      ),
      matched_rule(SHARED_PROVIDER_ID, ModelReferenceMatch::Any, SHARED_PROVIDER_ID, None),
    ];
    let (_, json) = rewrite_transition(
      r#"{"model": "tokn-router/openai/gpt-5"}"#,
      Some(RouteMode::Exact),
      RouteMode::Route,
      &publications,
      &rules,
    )
    .unwrap();

    assert_eq!(json["model"], "tokn-router/gpt-5");
    assert!(json["provider"]["tokn-router"]["models"].get("openai/gpt-5").is_none());
  }

  #[test]
  fn slashful_route_model_ids_are_stable_across_syncs() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let rules = [
      rule("openai", SHARED_PROVIDER_ID, None),
      rule(SHARED_PROVIDER_ID, SHARED_PROVIDER_ID, None),
    ];
    let (output, first) = rewrite(
      r#"{"model": "openai/openai/custom"}"#,
      RouteMode::Route,
      &publications,
      &rules,
    )
    .unwrap();
    assert_eq!(first["model"], "tokn-router/openai/custom");

    let (_, synced) = rewrite(&output, RouteMode::Route, &publications, &rules).unwrap();
    assert_eq!(synced["model"], "tokn-router/openai/custom");
  }

  #[test]
  fn relinking_to_a_pinned_provider_rejects_models_outside_its_catalogue() {
    let publications = [publication(
      "tokn-router-openai",
      "http://127.0.0.1:4141/opencode-openai/v1",
      &[("gpt-5", "GPT-5")],
    )];
    let mut pinned_rule = matched_rule(SHARED_PROVIDER_ID, ModelReferenceMatch::Any, "tokn-router-openai", None);
    pinned_rule.allow_missing_model = false;

    let error = rewrite_transition(
      r#"{"model": "tokn-router/deepseek-v4-flash"}"#,
      Some(RouteMode::Route),
      RouteMode::Switch,
      &publications,
      &[pinned_rule],
    )
    .unwrap_err();
    assert!(error
      .to_string()
      .contains("is not published by the pinned gateway provider"));
  }

  #[test]
  fn provider_scope_narrowing_rejects_unknown_shared_models() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[("gpt-5", "GPT-5")])];
    let mut shared_rule = matched_rule(SHARED_PROVIDER_ID, ModelReferenceMatch::Any, SHARED_PROVIDER_ID, None);
    shared_rule.allow_missing_model = false;

    let error = rewrite_transition(
      r#"{"model": "tokn-router/private-model"}"#,
      Some(RouteMode::Route),
      RouteMode::Route,
      &publications,
      &[shared_rule],
    )
    .unwrap_err();

    assert!(error
      .to_string()
      .contains("is not present in the new gateway model catalogue"));
  }

  #[test]
  fn raw_provider_retarget_only_moves_models_published_by_the_new_target() {
    let publications = [publication(
      "tokn-router-deepseek",
      "http://127.0.0.1:4141/opencode/v1",
      &[("shared-model", "Shared model")],
    )];
    let mut retarget = matched_rule(
      "tokn-router-openai",
      ModelReferenceMatch::Any,
      "tokn-router-deepseek",
      None,
    );
    retarget.allow_missing_model = false;

    let (_, rewritten) = rewrite_transition(
      r#"{"model": "tokn-router-openai/shared-model"}"#,
      Some(RouteMode::Switch),
      RouteMode::Switch,
      &publications,
      &[retarget.clone()],
    )
    .unwrap();
    assert_eq!(rewritten["model"], "tokn-router-deepseek/shared-model");

    let error = rewrite_transition(
      r#"{"model": "tokn-router-openai/openai-only"}"#,
      Some(RouteMode::Switch),
      RouteMode::Switch,
      &publications,
      &[retarget],
    )
    .unwrap_err();
    assert!(error
      .to_string()
      .contains("is not published by the pinned gateway provider"));
  }

  #[test]
  fn dangling_generated_selection_blocks_a_topology_change() {
    let publications = [publication(
      "tokn-router-deepseek",
      "http://127.0.0.1:4141/opencode/v1",
      &[("deepseek-chat", "DeepSeek Chat")],
    )];

    let error = rewrite_transition(
      r#"{"model": "tokn-router/missing-model"}"#,
      Some(RouteMode::Route),
      RouteMode::Switch,
      &publications,
      &[],
    )
    .unwrap_err();

    assert!(error.to_string().contains("cannot be mapped safely"));
  }

  #[test]
  fn fresh_links_do_not_rewrite_user_owned_generated_looking_namespaces() {
    let shared_publication = [publication(SHARED_PROVIDER_ID, BASE_URL, &[("gpt-5", "GPT-5")])];
    let (_, shared) = rewrite_transition(
      r#"{
  "model": "tokn-router-openai/custom",
  "provider": {
    "tokn-router-openai": {
      "name": "User router",
      "npm": "@ai-sdk/openai-compatible",
      "options": {"apiKey": "user", "baseURL": "http://localhost:9999/v1"}
    }
  }
}"#,
      None,
      RouteMode::Route,
      &shared_publication,
      &[],
    )
    .unwrap();
    assert_eq!(shared["model"], "tokn-router-openai/custom");
    assert_eq!(shared["provider"]["tokn-router-openai"]["name"], "User router");

    let pinned_publication = [publication(
      "tokn-router-openai",
      "http://127.0.0.1:4141/opencode/v1",
      &[("gpt-5", "GPT-5")],
    )];
    let (_, pinned) = rewrite_transition(
      r#"{
  "model": "tokn-router/custom",
  "provider": {
    "tokn-router": {
      "name": "User router",
      "npm": "@ai-sdk/openai-compatible",
      "options": {"apiKey": "user", "baseURL": "http://localhost:9999/v1"}
    }
  }
}"#,
      None,
      RouteMode::Switch,
      &pinned_publication,
      &[],
    )
    .unwrap();
    assert_eq!(pinned["model"], "tokn-router/custom");
    assert_eq!(pinned["provider"]["tokn-router"]["name"], "User router");
  }

  #[test]
  fn managed_model_references_reject_an_empty_model_id() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let rules = [rule("openai", SHARED_PROVIDER_ID, None)];

    let error = rewrite(r#"{"model": "openai/"}"#, RouteMode::Route, &publications, &rules).unwrap_err();
    assert!(error.to_string().contains("has an empty model id"));
  }

  #[test]
  fn verbatim_modes_rewrite_to_the_pinned_provider() {
    for mode in [RouteMode::Switch, RouteMode::Passthrough] {
      let provider_id = "tokn-router-deepseek";
      let publications = [publication(
        provider_id,
        "http://127.0.0.1:4141/opencode-deepseek/v1",
        &[("deepseek-v4-flash", "DeepSeek V4 Flash")],
      )];
      let rules = [rule("deepseek", provider_id, None)];
      let (_, json) = rewrite(
        r#"{"model": "deepseek/deepseek-v4-flash"}"#,
        mode,
        &publications,
        &rules,
      )
      .unwrap();

      assert_eq!(json["model"], "tokn-router-deepseek/deepseek-v4-flash");
      assert!(json["provider"].get(SHARED_PROVIDER_ID).is_none());
      assert_eq!(
        json["provider"][provider_id]["options"]["baseURL"],
        "http://127.0.0.1:4141/opencode-deepseek/v1"
      );
      assert_eq!(
        json["provider"][provider_id]["models"]["deepseek-v4-flash"]["name"],
        "DeepSeek V4 Flash"
      );
    }
  }

  #[test]
  fn generated_active_provider_is_refreshed_from_the_projection() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[("gpt-5", "GPT-5")])];
    let (output, json) = rewrite(
      r#"{
  // Keep the rest of the user's config.
  "mcp": {"x": true},
  "provider": {
    "tokn-router": {
      "name": "tokn-router",
      "npm": "@ai-sdk/openai-compatible",
      "models": {"obsolete": {"name": "Obsolete"}},
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/v1"
      }
    },
    "anthropic": {"options": {"apiKey": "keep"}}
  }
}"#,
      RouteMode::Route,
      &publications,
      &[],
    )
    .unwrap();

    assert!(output.contains("// Keep the rest of the user's config."));
    assert_eq!(json["mcp"]["x"], true);
    assert_eq!(json["provider"]["anthropic"]["options"]["apiKey"], "keep");
    assert_eq!(json["provider"]["tokn-router"]["options"]["baseURL"], BASE_URL);
    assert!(json["provider"]["tokn-router"]["models"].get("obsolete").is_none());
    assert_eq!(json["provider"]["tokn-router"]["models"]["gpt-5"]["name"], "GPT-5");
  }

  #[test]
  fn stale_generated_legacy_routes_are_removed_after_model_rewrite() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[("gpt-5", "GPT-5")])];
    let rules = [rule("openai", SHARED_PROVIDER_ID, None)];
    let (_, json) = rewrite(
      r#"{
  "model": "openai/gpt-5",
  "provider": {
    "openai": {
      "name": "tokn-router (openai)",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/opencode-openai/v1"
      }
    },
    "anthropic": {"options": {"apiKey": "keep"}}
  }
}"#,
      RouteMode::Route,
      &publications,
      &rules,
    )
    .unwrap();

    assert_eq!(json["model"], "tokn-router/gpt-5");
    assert!(json["provider"].get("openai").is_none());
    assert_eq!(json["provider"]["anthropic"]["options"]["apiKey"], "keep");
    assert!(json["provider"].get(SHARED_PROVIDER_ID).is_some());
  }

  #[test]
  fn rewrites_agent_and_command_models_without_touching_unrelated_model_keys() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let rules = [rule("openai", SHARED_PROVIDER_ID, None)];
    let (_, json) = rewrite(
      r#"{
  "agent": {"build": {"model": "openai/gpt-5"}},
  "command": {"review": {"model": "openai/gpt-5"}},
  "mode": {"legacy": {"model": "openai/gpt-5"}},
  "mcp": {"example": {"environment": {"model": "openai/leave-this-alone"}}},
  "provider": {
    "openai": {
      "name": "tokn-router (openai)",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/opencode-openai/v1"
      }
    }
  }
}"#,
      RouteMode::Route,
      &publications,
      &rules,
    )
    .unwrap();

    assert_eq!(json["agent"]["build"]["model"], "tokn-router/gpt-5");
    assert_eq!(json["command"]["review"]["model"], "tokn-router/gpt-5");
    assert_eq!(json["mode"]["legacy"]["model"], "tokn-router/gpt-5");
    assert_eq!(
      json["mcp"]["example"]["environment"]["model"],
      "openai/leave-this-alone"
    );
    assert!(json["provider"].get("openai").is_none());
  }

  #[test]
  fn switching_to_a_shared_provider_removes_unreferenced_pinned_providers() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let (_, json) = rewrite(
      r#"{
  "provider": {
    "tokn-router-openai": {
      "name": "Tokn Router (OpenAI)",
      "npm": "@ai-sdk/openai-compatible",
      "models": {"gpt-5": {"name": "GPT-5"}},
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/opencode-openai/v1"
      }
    }
  }
}"#,
      RouteMode::Route,
      &publications,
      &[],
    )
    .unwrap();

    assert!(json["provider"].get("tokn-router-openai").is_none());
    assert!(json["provider"].get(SHARED_PROVIDER_ID).is_some());
  }

  #[test]
  fn enabled_provider_policy_follows_agent_owned_and_generated_providers() {
    for transfer_source_auth in [true, false] {
      let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
      let mut route = route(
        "openai",
        "openai",
        "opencode-openai",
        "http://127.0.0.1:4141/opencode-openai/v1",
      );
      route.transfer_source_auth = transfer_source_auth;
      let (_, json) = rewrite_transition_with_routes(
        r#"{
  "enabled_providers": ["openai", "anthropic", "tokn-router-openai"],
  "provider": {
    "tokn-router-openai": {
      "name": "Tokn Router (OpenAI)",
      "npm": "@ai-sdk/openai-compatible",
      "models": {},
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/opencode-openai/v1"
      }
    }
  }
}"#,
        Some(RouteMode::Switch),
        RouteMode::Route,
        &publications,
        &[],
        &[route],
      )
      .unwrap();

      assert_eq!(
        json["enabled_providers"],
        serde_json::json!(["anthropic", SHARED_PROVIDER_ID])
      );
      assert!(json["provider"].get("tokn-router-openai").is_none());
    }
  }

  #[test]
  fn enabled_provider_policy_preserves_main_account_direct_providers() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let mut retained = route("openai", "openai", "", "http://127.0.0.1:4141/opencode/v1");
    retained.transfer_source_auth = false;
    let (_, json) = rewrite_transition_with_routes(
      r#"{"enabled_providers": ["openai"]}"#,
      None,
      RouteMode::Route,
      &publications,
      &[],
      &[retained],
    )
    .unwrap();

    assert_eq!(
      json["enabled_providers"],
      serde_json::json!(["openai", SHARED_PROVIDER_ID])
    );
  }

  #[test]
  fn disabled_provider_policy_rejects_gateway_managed_providers() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let error = rewrite(
      r#"{"disabled_providers": ["tokn-router"]}"#,
      RouteMode::Route,
      &publications,
      &[],
    )
    .unwrap_err();

    assert!(error.to_string().contains("disabled_providers"));
    assert!(error.to_string().contains("tokn-router"));
  }

  #[test]
  fn user_owned_reserved_provider_collision_is_a_hard_error() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let error = rewrite(
      r#"{
  "provider": {
    "tokn-router": {
      "name": "my router",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "apiKey": "user-key",
        "baseURL": "http://127.0.0.1:4141/v1"
      }
    }
  }
}"#,
      RouteMode::Route,
      &publications,
      &[],
    )
    .unwrap_err();

    assert_eq!(
      error.to_string(),
      "OpenCode provider 'tokn-router' already exists and is not managed by the agent link"
    );
  }

  #[test]
  fn reserved_provider_must_be_an_object() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let error = rewrite(
      r#"{"provider": {"tokn-router": false}}"#,
      RouteMode::Route,
      &publications,
      &[],
    )
    .unwrap_err();

    assert_eq!(
      error.to_string(),
      "OpenCode provider 'tokn-router' is not an object and cannot be managed by the agent link"
    );
  }

  #[test]
  fn customized_generated_provider_is_not_mistaken_for_managed_state() {
    let publications = [publication(SHARED_PROVIDER_ID, BASE_URL, &[])];
    let error = rewrite(
      r#"{
  "provider": {
    "tokn-router": {
      "name": "tokn-router",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "apiKey": "tokn-router",
        "baseURL": "http://127.0.0.1:4141/v1",
        "timeout": false
      }
    }
  }
}"#,
      RouteMode::Route,
      &publications,
      &[],
    )
    .unwrap_err();

    assert!(error.to_string().contains("already exists and is not managed"));
  }

  #[test]
  fn accounts_from_auth_json_imports_openai_api_key() {
    let json = serde_json::json!({"openai": {"type": "api", "key": "sk-test"}});
    let accounts = accounts_from_auth_json(
      &json,
      std::path::Path::new("/tmp/opencode-auth.json"),
      "20260604T153012Z",
    );

    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, "opencode-openai");
    assert_eq!(accounts[0].provider, tokn_core::provider::ID_OPENAI);
    assert_eq!(accounts[0].api_key.as_ref().unwrap().expose(), "sk-test");
    assert_eq!(source_provider_id(&accounts[0]), Some("openai"));
  }

  #[test]
  fn accounts_from_auth_json_imports_registry_api_key_providers() {
    let json = serde_json::json!({
      "deepseek": {"type": "api", "key": "sk-deepseek"},
      "zai": {"type": "api", "key": "sk-zai"}
    });
    let accounts = accounts_from_auth_json(
      &json,
      std::path::Path::new("/tmp/opencode-auth.json"),
      "20260604T153012Z",
    );

    assert_eq!(accounts.len(), 2);
    let deepseek = accounts
      .iter()
      .find(|account| account.provider == tokn_core::provider::ID_DEEPSEEK)
      .unwrap();
    assert_eq!(deepseek.id, "opencode-deepseek");
    assert_eq!(deepseek.api_key.as_ref().unwrap().expose(), "sk-deepseek");
    assert_eq!(deepseek.base_url.as_deref(), Some("https://api.deepseek.com"));
    assert_eq!(source_provider_id(deepseek), Some("deepseek"));

    let zai = accounts
      .iter()
      .find(|account| account.provider == tokn_core::provider::ID_ZAI)
      .unwrap();
    assert_eq!(zai.id, "opencode-zai");
    assert_eq!(zai.api_key.as_ref().unwrap().expose(), "sk-zai");
    assert_eq!(zai.base_url.as_deref(), Some("https://api.z.ai/api/paas/v4"));
    assert_eq!(source_provider_id(zai), Some("zai"));
  }

  #[test]
  fn accounts_from_auth_json_imports_oauth_records() {
    let json = serde_json::json!({
      "github-copilot": {"type": "oauth", "access": "at", "refresh": "ghu_rt", "expires": 0},
      "openai": {"type": "oauth", "access": "codex_at", "refresh": "codex_rt", "expires": "1800000000000", "accountId": "acc"}
    });

    let accounts = accounts_from_auth_json(
      &json,
      std::path::Path::new("/tmp/opencode-auth.json"),
      "20260604T153012Z",
    );

    assert_eq!(accounts.len(), 2);
    let copilot = accounts
      .iter()
      .find(|account| account.id == "opencode-github-copilot")
      .unwrap();
    assert_eq!(copilot.provider, tokn_core::provider::ID_GITHUB_COPILOT);
    assert_eq!(copilot.refresh_token.as_ref().unwrap().expose(), "ghu_rt");
    let codex = accounts.iter().find(|account| account.id == "opencode-codex").unwrap();
    assert_eq!(codex.provider, tokn_core::provider::ID_CODEX);
    assert_eq!(codex.access_token_expires_at, Some(1_800_000_000));
    assert_eq!(codex.provider_account_id.as_deref(), Some("acc"));
    assert_eq!(source_provider_id(codex), Some("openai"));
  }

  #[test]
  fn codex_oauth_expiry_roundtrips_between_opencode_milliseconds_and_gateway_seconds() {
    let json = serde_json::json!({
      "openai": {
        "type": "oauth",
        "access": "codex_at",
        "refresh": "codex_rt",
        "expires": 1800000000000_i64
      }
    });
    let account = accounts_from_auth_json(&json, Path::new("/tmp/opencode-auth.json"), "20260604T153012Z")
      .pop()
      .unwrap();

    assert_eq!(account.access_token_expires_at, Some(1_800_000_000));
    assert_eq!(
      opencode_auth_record("openai", &account).unwrap()["expires"],
      1_800_000_000_000_i64
    );
  }

  #[test]
  fn accounts_from_auth_json_ignores_unsupported_and_incomplete_records() {
    let json = serde_json::json!({
      "anthropic": {"type": "api", "key": "unsupported"},
      "google": {"type": "oauth", "access": "at", "refresh": "rt"},
      "openai": {"type": "oauth", "access": "at"},
      "github-copilot": {
        "type": "oauth",
        "access": "github-token",
        "refresh": "github-token",
        "expires": 0,
        "enterpriseUrl": "company.ghe.com"
      }
    });

    assert!(accounts_from_auth_json(
      &json,
      std::path::Path::new("/tmp/opencode-auth.json"),
      "20260604T153012Z",
    )
    .is_empty());
    assert!(account_from_provider_auth(
      tokn_core::provider::ID_GITHUB_COPILOT,
      &serde_json::json!({"type": "api", "key": "not-a-supported-flavor"})
    )
    .is_none());
  }

  #[test]
  fn oauth_import_requires_the_complete_opencode_auth_shape() {
    for auth in [
      serde_json::json!({"type": "oauth", "refresh": "rt", "expires": 1_800_000_000_000_i64}),
      serde_json::json!({"type": "oauth", "refresh": "rt", "access": "at"}),
      serde_json::json!({"type": "oauth", "refresh": "rt", "access": "at", "expires": -1}),
    ] {
      assert!(account_from_provider_auth(tokn_core::provider::ID_OPENAI, &auth).is_none());
    }
  }

  #[test]
  fn adapter_plans_config_patch_and_credential_removal() {
    let dir = tempfile::tempdir().unwrap();
    let adapter = OpencodeAdapter;
    let auth_path = adapter.auth_path(dir.path());
    let config_path = adapter.config_path(dir.path());
    std::fs::create_dir_all(auth_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(
      &auth_path,
      serde_json::json!({
        "openai": {"type": "api", "key": "sk-test"},
        "anthropic": {"type": "api", "key": "keep-me"}
      })
      .to_string(),
    )
    .unwrap();
    std::fs::write(
      &config_path,
      "{\n  // keep me\n  \"agent\": {\"build\": {\"model\": \"openai/gpt-5\"}}\n}\n",
    )
    .unwrap();
    let routes = [route(
      "openai",
      "openai",
      "opencode-openai",
      "http://127.0.0.1:4141/opencode-openai/v1",
    )];
    let publications = [ProviderPublication {
      provider_id: SHARED_PROVIDER_ID.to_string(),
      display_name: "Tokn Router".to_string(),
      base_url: "http://127.0.0.1:4141/opencode/v1".to_string(),
      models: BTreeMap::new(),
    }];
    let rules = [ModelReferenceRule {
      source_provider_id: "openai".to_string(),
      source_model_match: ModelReferenceMatch::Any,
      target_provider_id: SHARED_PROVIDER_ID.to_string(),
      target_model_prefix: None,
      allow_missing_model: true,
    }];
    let projection = AgentConfigProjection {
      target_base_url: "http://127.0.0.1:4141/opencode/v1",
      mode: tokn_config::RouteMode::Route,
      previous_mode: None,
      credential_routes: &routes,
      publications: &publications,
      model_reference_rules: &rules,
    };

    let edits = adapter.rewrite_config(dir.path(), &projection).unwrap();

    assert_eq!(edits.len(), 2);
    let config = edits.iter().find(|edit| edit.path == config_path).unwrap();
    let EditKind::Jsonc(raw) = &config.kind else {
      panic!("expected a JSONC config edit");
    };
    assert!(raw.contains("// keep me"));
    let config_json = crate::jsonc::parse_jsonc(raw, &config_path).unwrap();
    assert_eq!(config_json["agent"]["build"]["model"], "tokn-router/gpt-5");
    assert!(config_json["provider"]["tokn-router"]["models"].get("gpt-5").is_some());
    let auth = edits.iter().find(|edit| edit.path == auth_path).unwrap();
    assert!(!auth.backup);
    assert!(
      matches!(&auth.kind, EditKind::Json(json) if json.get("openai").is_none() && json.get("anthropic").is_some())
    );
  }

  #[test]
  fn retained_gateway_route_does_not_remove_an_untransferred_credential() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    std::fs::write(
      &auth_path,
      serde_json::json!({
        "openai": {"type": "oauth", "access": "missing-refresh-token"}
      })
      .to_string(),
    )
    .unwrap();
    let mut retained = route(
      "openai",
      "openai",
      "opencode-openai",
      "http://127.0.0.1:4141/opencode-openai/v1",
    );
    retained.transfer_source_auth = false;

    assert!(remove_transferred_credentials(&auth_path, &[retained])
      .unwrap()
      .is_none());
    assert!(std::fs::read_to_string(auth_path)
      .unwrap()
      .contains("missing-refresh-token"));
  }

  #[test]
  fn restore_exports_latest_api_and_oauth_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    std::fs::write(&auth_path, r#"{"anthropic":{"type":"api","key":"keep"}}"#).unwrap();
    let mut api = openai_account_from_key("sk-latest");
    api.settings.insert(
      "import".into(),
      toml::Value::Table(toml::toml! { source_provider = "openai" }),
    );
    let mut oauth = oauth_account_from_auth(
      "opencode-github-copilot",
      tokn_core::provider::ID_GITHUB_COPILOT,
      "copilot",
      None,
      None,
      serde_json::json!({"refresh": "rt-latest", "access": "at-latest", "expires": 42})
        .as_object()
        .unwrap(),
      None,
    )
    .unwrap();
    oauth.settings.insert(
      "import".into(),
      toml::Value::Table(toml::toml! { source_provider = "github-copilot" }),
    );

    restore_transferred_credentials(&auth_path, &[api, oauth]).unwrap();

    let restored: Value = serde_json::from_str(&std::fs::read_to_string(auth_path).unwrap()).unwrap();
    assert_eq!(restored["anthropic"]["key"], "keep");
    assert_eq!(restored["openai"]["key"], "sk-latest");
    assert_eq!(restored["github-copilot"]["refresh"], "rt-latest");
    assert_eq!(restored["github-copilot"]["access"], "rt-latest");
    assert_eq!(restored["github-copilot"]["expires"], 0);
  }

  #[test]
  fn restore_preserves_auth_recreated_while_linked() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    std::fs::write(
      &auth_path,
      serde_json::to_vec_pretty(&serde_json::json!({
        "github-copilot": {
          "type": "oauth",
          "refresh": "enterprise-token",
          "access": "enterprise-token",
          "expires": 0,
          "enterpriseUrl": "company.ghe.com"
        }
      }))
      .unwrap(),
    )
    .unwrap();
    let mut account = oauth_account_from_auth(
      "opencode-github-copilot",
      tokn_core::provider::ID_GITHUB_COPILOT,
      "copilot",
      None,
      None,
      serde_json::json!({"refresh": "gateway-token", "access": "gateway-token", "expires": 0})
        .as_object()
        .unwrap(),
      None,
    )
    .unwrap();
    account.settings.insert(
      "import".into(),
      toml::Value::Table(toml::toml! { source_provider = "github-copilot" }),
    );

    restore_transferred_credentials(&auth_path, &[account]).unwrap();

    let restored: Value = serde_json::from_str(&std::fs::read_to_string(auth_path).unwrap()).unwrap();
    assert_eq!(restored["github-copilot"]["refresh"], "enterprise-token");
    assert_eq!(restored["github-copilot"]["enterpriseUrl"], "company.ghe.com");
  }
}

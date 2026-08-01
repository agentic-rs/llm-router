use super::send::filter_accounts;
use super::OutputFormat;
use crate::config::Config;
use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokn_accounts::registry::Registry;
use tokn_auth::AuthStore;
use tokn_core::provider::{match_endpoint_rule, Endpoint, ModelInfo};

#[derive(Args, Debug)]
pub struct ProviderArgs {
  /// Provider id (e.g. `github-copilot`, `openai`, `deepseek`, `zai`).
  pub provider_id: String,

  /// Output format.
  #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
  pub format: OutputFormat,

  /// Also fetch model ids live from the provider's upstream `/models`
  /// endpoint. Requires a configured account for the provider.
  #[arg(long)]
  pub live: bool,
}

pub async fn run(cfg_path: Option<PathBuf>, args: ProviderArgs) -> Result<()> {
  let registry = Registry::builtin();
  let descriptor = registry.resolve(&args.provider_id).ok_or_else(|| {
    let known = registry.ids().join(", ");
    anyhow!("unknown provider '{}'; known: {}", args.provider_id, known)
  })?;

  let static_models = tokn_catalogue::default_models_for(descriptor.id);
  let live_models: Option<Vec<String>> = if args.live {
    Some(fetch_live_models(cfg_path.as_deref(), descriptor.id).await?)
  } else {
    None
  };

  match args.format {
    OutputFormat::Text => print_provider_text(descriptor, &static_models, live_models.as_deref()),
    OutputFormat::Json => print_provider_json(descriptor, &static_models, live_models.as_deref())?,
  }
  Ok(())
}

pub(super) fn endpoints_for_model(
  descriptor: &'static tokn_auth::descriptor::ProviderDescriptor,
  model_id: &str,
) -> Vec<Endpoint> {
  let all: Vec<Endpoint> = descriptor.endpoints.iter().map(|e| e.endpoint).collect();
  let Some(rules) = descriptor.model_endpoint_rules else {
    return all;
  };
  let mut allowed: Vec<Endpoint> = Vec::new();
  let mut matched = false;
  for endpoint in &all {
    if let Some(decision) = match_endpoint_rule(rules, model_id, *endpoint) {
      matched = true;
      if decision {
        allowed.push(*endpoint);
      }
    }
  }
  if matched {
    allowed
  } else {
    all
  }
}

fn print_provider_text(
  descriptor: &'static tokn_auth::descriptor::ProviderDescriptor,
  static_models: &[ModelInfo],
  live_models: Option<&[String]>,
) {
  println!("provider:     {}", descriptor.id);
  println!("display_name: {}", descriptor.display_name);
  println!("base_url:     {}", descriptor.base_url);
  if !descriptor.hosts.is_empty() {
    println!("hosts:        {}", descriptor.hosts.join(", "));
  }

  println!();
  println!("endpoints ({}):", descriptor.endpoints.len());
  for spec in descriptor.endpoints {
    println!("  {} {}  ({})", spec.method, spec.path, spec.endpoint.as_str());
    if !spec.aliases.is_empty() {
      println!("    aliases: {}", spec.aliases.join(", "));
    }
  }

  println!();
  println!("models ({}):", static_models.len());
  for m in static_models {
    let endpoints = endpoints_for_model(descriptor, &m.id);
    let endpoint_names: Vec<&str> = endpoints.iter().map(|e| e.as_str()).collect();
    let suffix = if endpoint_names.is_empty() {
      "(no endpoints)".to_string()
    } else {
      endpoint_names.join(", ")
    };
    if m.name.is_empty() || m.name == m.id {
      println!("  {}", m.id);
    } else {
      println!("  {} - {}", m.id, m.name);
    }
    println!("    endpoints: {suffix}");
  }

  if let Some(live) = live_models {
    println!();
    println!("live models ({}):", live.len());
    let known: HashSet<&str> = static_models.iter().map(|m| m.id.as_str()).collect();
    for id in live {
      let mark = if known.contains(id.as_str()) { " " } else { "*" };
      println!(" {mark} {id}");
    }
    if live.iter().any(|id| !known.contains(id.as_str())) {
      println!("  (* = not in static catalogue)");
    }
  }
}

fn print_provider_json(
  descriptor: &'static tokn_auth::descriptor::ProviderDescriptor,
  static_models: &[ModelInfo],
  live_models: Option<&[String]>,
) -> Result<()> {
  let endpoints: Vec<serde_json::Value> = descriptor
    .endpoints
    .iter()
    .map(|spec| {
      serde_json::json!({
        "endpoint": spec.endpoint.as_str(),
        "method": spec.method,
        "path": spec.path,
        "aliases": spec.aliases,
      })
    })
    .collect();

  let models: Vec<serde_json::Value> = static_models
    .iter()
    .map(|m| {
      let endpoints = endpoints_for_model(descriptor, &m.id);
      let endpoint_names: Vec<&str> = endpoints.iter().map(|e| e.as_str()).collect();
      serde_json::json!({
        "id": m.id,
        "name": m.name,
        "endpoints": endpoint_names,
      })
    })
    .collect();

  let mut out = serde_json::json!({
    "provider": descriptor.id,
    "display_name": descriptor.display_name,
    "base_url": descriptor.base_url,
    "hosts": descriptor.hosts,
    "endpoints": endpoints,
    "models": models,
  });
  if let Some(live) = live_models {
    out
      .as_object_mut()
      .unwrap()
      .insert("live_models".into(), serde_json::json!(live));
  }
  println!("{}", serde_json::to_string_pretty(&out)?);
  Ok(())
}

async fn fetch_live_models(cfg_path: Option<&std::path::Path>, provider_id: &str) -> Result<Vec<String>> {
  let (cfg, _) = Config::load(cfg_path)?;
  let mut accounts = AuthStore::load(None, None)?.accounts;
  filter_accounts(&mut accounts, Some(provider_id), None)?;

  let registry = Registry::builtin();
  let providers = accounts
    .into_iter()
    .filter(|account| account.enabled)
    .map(|account| {
      let account_id = account.id.clone();
      registry
        .build(Arc::new(account))
        .with_context(|| format!("failed to build provider for account `{account_id}`"))
    })
    .collect::<Result<Vec<_>>>()?;
  if providers.is_empty() {
    return Err(anyhow!("no accounts configured. Run `tokn-router account add` first."));
  }
  let http = crate::util::http::build_client(&cfg.proxy)?;

  let mut ids: Vec<String> = Vec::new();
  let mut seen: HashSet<String> = HashSet::new();
  let mut last_err: Option<String> = None;
  for provider in providers {
    if provider.info().id != provider_id {
      continue;
    }
    match provider.list_models(&http).await {
      Ok(value) => extend_model_ids(&value, &mut ids, &mut seen),
      Err(e) => last_err = Some(e.to_string()),
    }
  }

  if ids.is_empty() {
    let msg = last_err.unwrap_or_else(|| format!("no live models returned for provider '{provider_id}'"));
    return Err(anyhow!("live model fetch failed: {msg}"));
  }
  ids.sort();
  Ok(ids)
}

fn extend_model_ids(value: &serde_json::Value, ids: &mut Vec<String>, seen: &mut HashSet<String>) {
  let Some(models) = value.get("data").and_then(serde_json::Value::as_array) else {
    return;
  };
  for model in models {
    let Some(id) = model.get("id").and_then(serde_json::Value::as_str) else {
      continue;
    };
    if seen.insert(id.to_string()) {
      ids.push(id.to_string());
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn extend_model_ids_deduplicates_and_ignores_malformed_entries() {
    let mut ids = vec!["existing".to_string()];
    let mut seen = HashSet::from(["existing".to_string()]);
    let value = json!({
      "data": [
        {"id": "z-model"},
        {"id": "existing"},
        {"object": "model"},
        {"id": 42},
        {"id": "a-model"},
        {"id": "z-model"},
      ]
    });

    extend_model_ids(&value, &mut ids, &mut seen);

    assert_eq!(ids, ["existing", "z-model", "a-model"]);
  }

  #[test]
  fn extend_model_ids_ignores_non_array_data() {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();

    extend_model_ids(&json!({"data": {"id": "ignored"}}), &mut ids, &mut seen);

    assert!(ids.is_empty());
    assert!(seen.is_empty());
  }
}

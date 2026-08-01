use super::send::filter_accounts;
use super::OutputFormat;
use crate::config::Config;
use anyhow::{anyhow, Result};
use clap::Args;
use std::collections::HashSet;
use std::path::PathBuf;
use tokn_core::provider::{match_endpoint_rule, Endpoint, ModelInfo};
use tokn_router::accounts::registry::Registry;

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
  let mut accounts = crate::server_runtime::load_default_accounts()?;
  filter_accounts(&mut accounts, Some(provider_id), None)?;

  let (events, receiver, handlers, archive_runtime) = crate::server_runtime::build_event_bus(&cfg)?;
  let _event_thread = tokn_core::event::spawn_event_loop(receiver, handlers);
  let state = crate::server_runtime::build_state(&cfg, &accounts, events.clone())?;

  let mut ids: Vec<String> = Vec::new();
  let mut seen: HashSet<String> = HashSet::new();
  let mut last_err: Option<String> = None;
  for acct in state.pool.all() {
    if acct.provider.info().id != provider_id {
      continue;
    }
    match acct.provider.list_models(&state.http).await {
      Ok(v) => {
        if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
          for m in arr {
            if let Some(id) = m.get("id").and_then(|x| x.as_str()) {
              if seen.insert(id.to_string()) {
                ids.push(id.to_string());
              }
            }
          }
        }
      }
      Err(e) => last_err = Some(e.to_string()),
    }
  }

  if let Some(rt) = archive_runtime {
    rt.shutdown().await;
  }
  events.shutdown().await;

  if ids.is_empty() {
    let msg = last_err.unwrap_or_else(|| format!("no live models returned for provider '{provider_id}'"));
    return Err(anyhow!("live model fetch failed: {msg}"));
  }
  ids.sort();
  Ok(ids)
}

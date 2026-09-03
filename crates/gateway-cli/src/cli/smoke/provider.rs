use super::OutputFormat;
use anyhow::{anyhow, Result};
use clap::Args;
use std::collections::HashSet;
use std::path::PathBuf;
use tokn_core::provider::{match_endpoint_rule, Endpoint, ModelInfo};
use tokn_policy::{GatewayPlan, ProviderId};
use tokn_router::accounts::registry::Registry;

#[derive(Args, Debug)]
pub struct ProviderArgs {
  /// Configured v2 provider name.
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
  let (compiled, resolved_cfg_path) = super::load_v2_config(cfg_path.as_deref())?;
  let plan = compiled.gateway();
  let registry = Registry::builtin();
  let (provider_id, provider, descriptor) = resolve_provider(plan, &registry, &args.provider_id)?;

  let static_models = tokn_catalogue::default_models_for(descriptor.id);
  let live_models: Option<Vec<String>> = if args.live {
    Some(fetch_live_models(plan, &resolved_cfg_path, provider_id, compiled.service().outbound()).await?)
  } else {
    None
  };

  match args.format {
    OutputFormat::Text => print_provider_text(
      provider_id,
      provider,
      descriptor,
      &static_models,
      live_models.as_deref(),
    ),
    OutputFormat::Json => print_provider_json(
      provider_id,
      provider,
      descriptor,
      &static_models,
      live_models.as_deref(),
    )?,
  }
  Ok(())
}

fn resolve_provider<'a>(
  plan: &'a GatewayPlan,
  registry: &Registry,
  requested: &str,
) -> Result<(
  &'a ProviderId,
  &'a tokn_policy::ProviderPlan,
  &'static tokn_auth::descriptor::ProviderDescriptor,
)> {
  let (provider_id, provider) = plan
    .providers()
    .iter()
    .find(|(provider_id, _)| provider_id.as_str() == requested)
    .ok_or_else(|| {
      let known = plan
        .providers()
        .keys()
        .map(ProviderId::as_str)
        .collect::<Vec<_>>()
        .join(", ");
      anyhow!("unknown configured provider '{requested}'; configured: {known}")
    })?;
  let descriptor = registry
    .resolve_provider_descriptor(provider_id.as_str(), provider.driver().as_str())
    .ok_or_else(|| {
      anyhow!(
        "configured provider '{}' references unknown driver '{}'",
        provider_id,
        provider.driver()
      )
    })?;
  Ok((provider_id, provider, descriptor))
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
  provider_id: &ProviderId,
  provider: &tokn_policy::ProviderPlan,
  descriptor: &'static tokn_auth::descriptor::ProviderDescriptor,
  static_models: &[ModelInfo],
  live_models: Option<&[String]>,
) {
  println!("provider:     {provider_id}");
  println!("driver:       {}", provider.driver());
  println!("display_name: {}", descriptor.display_name);
  println!("base_url:     {}", provider.base_url().unwrap_or(descriptor.base_url));
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
  provider_id: &ProviderId,
  provider: &tokn_policy::ProviderPlan,
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
    "provider": provider_id.as_str(),
    "driver": provider.driver().as_str(),
    "display_name": descriptor.display_name,
    "base_url": provider.base_url().unwrap_or(descriptor.base_url),
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

async fn fetch_live_models(
  plan: &GatewayPlan,
  config_path: &std::path::Path,
  provider_id: &ProviderId,
  outbound: &tokn_config::v2::OutboundPlan,
) -> Result<Vec<String>> {
  let accounts = crate::server_runtime::load_accounts(Some(config_path))?;
  let registry = Registry::builtin();
  let providers = tokn_router::accounts::link::link_provider_graph(plan, &accounts, &registry)?;
  let bindings = providers
    .bindings()
    .filter(|binding| binding.provider_id() == provider_id)
    .collect::<Vec<_>>();
  if bindings.is_empty() {
    anyhow::bail!("configured provider '{provider_id}' has no enabled account");
  }
  let http = tokn_core::util::http::build_client(&outbound.to_http_client_options())?;

  let mut ids: Vec<String> = Vec::new();
  let mut seen: HashSet<String> = HashSet::new();
  let mut last_err: Option<String> = None;
  for binding in bindings {
    match binding.driver().list_models(&http).await {
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

  if ids.is_empty() {
    let msg = last_err.unwrap_or_else(|| format!("no live models returned for provider '{provider_id}'"));
    return Err(anyhow!("live model fetch failed: {msg}"));
  }
  ids.sort();
  Ok(ids)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::Path;

  #[test]
  fn configured_provider_resolves_its_driver_metadata() {
    let plan = tokn_config::v2::parse(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"

[providers.public]
driver = "openai"
base_url = "https://gateway.example/v1"
"#,
      Path::new("provider-smoke.toml"),
    )
    .unwrap();
    let registry = Registry::builtin();

    let (provider_id, provider, descriptor) = resolve_provider(&plan, &registry, "public").unwrap();

    assert_eq!(provider_id.as_str(), "public");
    assert_eq!(provider.driver().as_str(), "openai");
    assert_eq!(descriptor.id, "openai");
    let (provider_id, provider, descriptor) = resolve_provider(&plan, &registry, "openai").unwrap();
    assert_eq!(provider_id.as_str(), "openai");
    assert_eq!(provider.driver().as_str(), "openai");
    assert_eq!(descriptor.id, "openai");

    let (provider_id, provider, descriptor) = resolve_provider(&plan, &registry, "zhipuai").unwrap();
    assert_eq!(provider_id.as_str(), "zhipuai");
    assert_eq!(provider.driver().as_str(), "zai");
    assert_eq!(descriptor.id, "zhipuai");
    assert_eq!(descriptor.base_url, "https://open.bigmodel.cn/api/paas/v4");
  }
}

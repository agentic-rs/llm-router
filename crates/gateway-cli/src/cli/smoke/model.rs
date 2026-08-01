use super::provider::endpoints_for_model;
use super::OutputFormat;
use anyhow::Result;
use clap::Args;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use tokn_accounts::registry::Registry;
use tokn_core::provider::{Capabilities, Cost, Limits, Modalities, ModelInfo};

#[derive(Args, Debug)]
pub struct ModelArgs {
  /// Model id to look up across all registered providers.
  #[arg(required_unless_present = "all", conflicts_with = "all")]
  pub model_id: Option<String>,

  /// Show every model known in the static catalogue.
  #[arg(long)]
  pub all: bool,

  /// Output format.
  #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
  pub format: OutputFormat,
}

struct ProviderMatch {
  id: &'static str,
  display_name: &'static str,
  base_url: &'static str,
  endpoints: Vec<&'static str>,
  model: ModelInfo,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct CommonModelView {
  name: Option<String>,
  endpoints: Vec<&'static str>,
  limit: Option<LimitsView>,
  capabilities: Option<CapabilitiesView>,
  cost: Option<CostView>,
  release_date: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct ProviderOverrideView {
  #[serde(skip_serializing_if = "Option::is_none")]
  name: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  endpoints: Option<Vec<&'static str>>,
  #[serde(skip_serializing_if = "Option::is_none")]
  limit: Option<LimitsView>,
  #[serde(skip_serializing_if = "Option::is_none")]
  capabilities: Option<CapabilitiesView>,
  #[serde(skip_serializing_if = "Option::is_none")]
  cost: Option<CostView>,
  #[serde(skip_serializing_if = "Option::is_none")]
  release_date: Option<String>,
}

#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
struct LimitsView {
  context: u32,
  output: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct CostView {
  input: f64,
  output: f64,
  #[serde(skip_serializing_if = "Option::is_none")]
  cache: Option<CacheCostView>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct CacheCostView {
  read: f64,
  write: f64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct CapabilitiesView {
  temperature: bool,
  reasoning: bool,
  attachment: bool,
  toolcall: bool,
  input: ModalitiesView,
  output: ModalitiesView,
  interleaved: Value,
}

#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
struct ModalitiesView {
  text: bool,
  audio: bool,
  image: bool,
  video: bool,
  pdf: bool,
}

pub async fn run(args: ModelArgs) -> Result<()> {
  let reports = if args.all {
    all_model_ids()
      .into_iter()
      .map(|model_id| model_report(&model_id))
      .collect::<Vec<_>>()
  } else {
    vec![model_report(args.model_id.as_deref().expect("required by clap"))]
  };

  match args.format {
    OutputFormat::Text => print_reports_text(&reports),
    OutputFormat::Json => print_reports_json(&reports, args.all)?,
  }
  Ok(())
}

struct ModelReport {
  model_id: String,
  common: CommonModelView,
  matches: Vec<ProviderMatch>,
}

fn model_report(model_id: &str) -> ModelReport {
  let registry = Registry::builtin();
  let matches = registry
    .iter()
    .filter_map(|descriptor| {
      let model = tokn_catalogue::default_models_for(descriptor.id)
        .into_iter()
        .find(|m| m.id == model_id)?;
      let endpoints = endpoints_for_model(descriptor, &model.id)
        .into_iter()
        .map(|e| e.as_str())
        .collect();
      Some(ProviderMatch {
        id: descriptor.id,
        display_name: descriptor.display_name,
        base_url: descriptor.base_url,
        endpoints,
        model,
      })
    })
    .collect::<Vec<_>>();
  let common = common_view(&matches);
  ModelReport {
    model_id: model_id.to_string(),
    common,
    matches,
  }
}

fn all_model_ids() -> Vec<String> {
  let registry = Registry::builtin();
  let mut ids = BTreeSet::new();
  for descriptor in registry.iter() {
    for model in tokn_catalogue::default_models_for(descriptor.id) {
      ids.insert(model.id);
    }
  }
  ids.into_iter().collect()
}

fn print_reports_text(reports: &[ModelReport]) {
  for (i, report) in reports.iter().enumerate() {
    if i > 0 {
      println!();
    }
    print_report_text(report);
  }
}

fn print_report_text(report: &ModelReport) {
  println!("model: {}", report.model_id);
  print_common_text(&report.common);
  println!();
  println!("providers ({}):", report.matches.len());
  for m in &report.matches {
    println!("  {} - {}", m.id, m.display_name);
    print_override_text(&provider_overrides(&report.common, m));
  }
}

fn print_common_text(common: &CommonModelView) {
  if let Some(name) = &common.name {
    println!("name: {name}");
  }
  if !common.endpoints.is_empty() {
    println!("endpoints: {}", common.endpoints.join(", "));
  }
  if let Some(limit) = &common.limit {
    println!("limit: context={} output={}", limit.context, limit.output);
  }
  if let Some(capabilities) = &common.capabilities {
    println!("capabilities: {}", capabilities_summary(capabilities));
  }
  if let Some(cost) = &common.cost {
    println!("cost: {}", cost_summary(cost));
  }
  if let Some(release_date) = &common.release_date {
    println!("release_date: {release_date}");
  }
}

fn print_override_text(overrides: &ProviderOverrideView) {
  if let Some(name) = &overrides.name {
    println!("    name: {name}");
  }
  if let Some(endpoints) = &overrides.endpoints {
    println!("    endpoints: {}", endpoints.join(", "));
  }
  if let Some(limit) = &overrides.limit {
    println!("    limit: context={} output={}", limit.context, limit.output);
  }
  if let Some(capabilities) = &overrides.capabilities {
    println!("    capabilities: {}", capabilities_summary(capabilities));
  }
  if let Some(cost) = &overrides.cost {
    println!("    cost: {}", cost_summary(cost));
  }
  if let Some(release_date) = &overrides.release_date {
    println!("    release_date: {release_date}");
  }
}

fn print_reports_json(reports: &[ModelReport], all: bool) -> Result<()> {
  if all {
    let models = reports.iter().map(report_json).collect::<Vec<_>>();
    println!(
      "{}",
      serde_json::to_string_pretty(&serde_json::json!({ "models": models }))?
    );
  } else if let Some(report) = reports.first() {
    println!("{}", serde_json::to_string_pretty(&report_json(report))?);
  }
  Ok(())
}

fn report_json(report: &ModelReport) -> Value {
  let providers = report
    .matches
    .iter()
    .map(|m| {
      serde_json::json!({
        "id": m.id,
        "display_name": m.display_name,
        "base_url": m.base_url,
        "overrides": provider_overrides(&report.common, m),
      })
    })
    .collect::<Vec<_>>();
  serde_json::json!({
    "model": report.model_id,
    "common": report.common,
    "providers": providers,
  })
}

fn common_view(matches: &[ProviderMatch]) -> CommonModelView {
  CommonModelView {
    name: most_common(matches.iter().filter_map(|m| non_empty_string(&m.model.name))),
    endpoints: most_common(matches.iter().map(|m| m.endpoints.clone())).unwrap_or_default(),
    limit: largest_limit(matches.iter().map(|m| limits_view(&m.model.limit))),
    capabilities: union_capabilities(matches.iter().map(|m| capabilities_view(&m.model.capabilities))),
    cost: highest_cost(matches.iter().filter_map(|m| m.model.cost.as_ref().map(cost_view))),
    release_date: matches.iter().filter_map(|m| m.model.release_date.clone()).min(),
  }
}

fn provider_overrides(common: &CommonModelView, provider: &ProviderMatch) -> ProviderOverrideView {
  let name = non_empty_string(&provider.model.name).filter(|name| Some(name) != common.name.as_ref());
  let endpoints = (provider.endpoints != common.endpoints).then(|| provider.endpoints.clone());
  let limit = Some(limits_view(&provider.model.limit)).filter(|limit| Some(limit) != common.limit.as_ref());
  let capabilities = Some(capabilities_view(&provider.model.capabilities))
    .filter(|capabilities| Some(capabilities) != common.capabilities.as_ref());
  let cost = provider
    .model
    .cost
    .as_ref()
    .map(cost_view)
    .filter(|cost| Some(cost) != common.cost.as_ref());
  let release_date = provider
    .model
    .release_date
    .clone()
    .filter(|release_date| Some(release_date) != common.release_date.as_ref());
  ProviderOverrideView {
    name,
    endpoints,
    limit,
    capabilities,
    cost,
    release_date,
  }
}

fn non_empty_string(value: &str) -> Option<String> {
  (!value.is_empty()).then(|| value.to_string())
}

fn limits_view(limit: &Limits) -> LimitsView {
  LimitsView {
    context: limit.context,
    output: limit.output,
  }
}

fn cost_view(cost: &Cost) -> CostView {
  CostView {
    input: cost.input,
    output: cost.output,
    cache: cost.cache.as_ref().map(|cache| CacheCostView {
      read: cache.read,
      write: cache.write,
    }),
  }
}

fn capabilities_view(cap: &Capabilities) -> CapabilitiesView {
  CapabilitiesView {
    temperature: cap.temperature,
    reasoning: cap.reasoning,
    attachment: cap.attachment,
    toolcall: cap.toolcall,
    input: modalities_view(&cap.input),
    output: modalities_view(&cap.output),
    interleaved: serde_json::to_value(&cap.interleaved).unwrap_or(Value::Null),
  }
}

fn modalities_view(modalities: &Modalities) -> ModalitiesView {
  ModalitiesView {
    text: modalities.text,
    audio: modalities.audio,
    image: modalities.image,
    video: modalities.video,
    pdf: modalities.pdf,
  }
}

fn largest_limit(values: impl Iterator<Item = LimitsView>) -> Option<LimitsView> {
  let mut iter = values.peekable();
  iter.peek()?;
  Some(iter.fold(LimitsView { context: 0, output: 0 }, |acc, item| LimitsView {
    context: acc.context.max(item.context),
    output: acc.output.max(item.output),
  }))
}

fn highest_cost(values: impl Iterator<Item = CostView>) -> Option<CostView> {
  let mut out: Option<CostView> = None;
  for cost in values {
    out = Some(match out {
      None => cost,
      Some(acc) => CostView {
        input: acc.input.max(cost.input),
        output: acc.output.max(cost.output),
        cache: highest_cache(acc.cache, cost.cache),
      },
    });
  }
  out
}

fn highest_cache(a: Option<CacheCostView>, b: Option<CacheCostView>) -> Option<CacheCostView> {
  match (a, b) {
    (Some(a), Some(b)) => Some(CacheCostView {
      read: a.read.max(b.read),
      write: a.write.max(b.write),
    }),
    (Some(a), None) => Some(a),
    (None, Some(b)) => Some(b),
    (None, None) => None,
  }
}

fn union_capabilities(values: impl Iterator<Item = CapabilitiesView>) -> Option<CapabilitiesView> {
  let values = values.collect::<Vec<_>>();
  let first = values.first()?.clone();
  Some(CapabilitiesView {
    temperature: values.iter().any(|v| v.temperature),
    reasoning: values.iter().any(|v| v.reasoning),
    attachment: values.iter().any(|v| v.attachment),
    toolcall: values.iter().any(|v| v.toolcall),
    input: union_modalities(values.iter().map(|v| v.input)),
    output: union_modalities(values.iter().map(|v| v.output)),
    interleaved: most_common_json(values.into_iter().map(|v| v.interleaved)).unwrap_or(first.interleaved),
  })
}

fn union_modalities(values: impl Iterator<Item = ModalitiesView>) -> ModalitiesView {
  values.fold(
    ModalitiesView {
      text: false,
      audio: false,
      image: false,
      video: false,
      pdf: false,
    },
    |acc, item| ModalitiesView {
      text: acc.text || item.text,
      audio: acc.audio || item.audio,
      image: acc.image || item.image,
      video: acc.video || item.video,
      pdf: acc.pdf || item.pdf,
    },
  )
}

fn most_common<T>(values: impl Iterator<Item = T>) -> Option<T>
where
  T: Clone + Ord,
{
  let mut counts: BTreeMap<T, usize> = BTreeMap::new();
  for value in values {
    *counts.entry(value).or_default() += 1;
  }
  counts
    .into_iter()
    .max_by_key(|(_, count)| *count)
    .map(|(value, _)| value)
}

fn most_common_json(values: impl Iterator<Item = Value>) -> Option<Value> {
  let mut counts: BTreeMap<String, (Value, usize)> = BTreeMap::new();
  for value in values {
    let key = serde_json::to_string(&value).ok()?;
    counts
      .entry(key)
      .and_modify(|(_, count)| *count += 1)
      .or_insert((value, 1));
  }
  counts
    .into_iter()
    .max_by_key(|(_, (_, count))| *count)
    .map(|(_, (value, _))| value)
}

fn capabilities_summary(cap: &CapabilitiesView) -> String {
  let mut parts = Vec::new();
  parts.push(format!("input={}", modalities_summary(&cap.input)));
  parts.push(format!("output={}", modalities_summary(&cap.output)));
  if cap.reasoning {
    parts.push("reasoning".into());
  }
  if cap.toolcall {
    parts.push("toolcall".into());
  }
  if cap.attachment {
    parts.push("attachment".into());
  }
  if cap.temperature {
    parts.push("temperature".into());
  }
  parts.join(", ")
}

fn modalities_summary(modalities: &ModalitiesView) -> String {
  let mut parts = Vec::new();
  if modalities.text {
    parts.push("text");
  }
  if modalities.image {
    parts.push("image");
  }
  if modalities.audio {
    parts.push("audio");
  }
  if modalities.video {
    parts.push("video");
  }
  if modalities.pdf {
    parts.push("pdf");
  }
  if parts.is_empty() {
    "none".into()
  } else {
    parts.join("+")
  }
}

fn cost_summary(cost: &CostView) -> String {
  let mut parts = vec![format!("input={}", cost.input), format!("output={}", cost.output)];
  if let Some(cache) = &cost.cache {
    parts.push(format!("cache_read={}", cache.read));
    parts.push(format!("cache_write={}", cache.write));
  }
  parts.join(" ")
}

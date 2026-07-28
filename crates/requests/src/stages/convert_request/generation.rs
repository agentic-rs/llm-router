//! Provider-aware lowering for typed, provider-neutral generation controls.
//!
//! Controls are applied after endpoint conversion, when both the selected
//! provider and its upstream endpoint are known. Unsupported combinations
//! fail locally instead of being silently dropped or reinterpreted.

use crate::pipeline::error::RequestsError;
use serde_json::{Map, Value};
use tokn_core::generation::{GenerationOptions, ReasoningEffort, ReasoningMode, ReasoningOptions};
use tokn_core::provider::{Endpoint, ID_CODEX, ID_DEEPSEEK, ID_GITHUB_COPILOT, ID_LLAMA_CPP, ID_OPENAI, ZAI_PROVIDERS};

pub(super) fn lower_generation_options(
  body: &mut Value,
  endpoint: Endpoint,
  provider_id: &str,
  model: &str,
  options: &GenerationOptions,
) -> Result<(), RequestsError> {
  if options.is_empty() {
    return Ok(());
  }
  let Some(obj) = body.as_object_mut() else {
    let control = if options.max_output_tokens.is_some() {
      "max_output_tokens"
    } else if options.top_k.is_some() {
      "top_k"
    } else {
      "reasoning"
    };
    return unsupported(
      control,
      provider_id,
      endpoint,
      "typed generation controls require a JSON object request body",
    );
  };

  if let Some(max_output_tokens) = options.max_output_tokens {
    lower_max_output_tokens(obj, endpoint, provider_id, model, max_output_tokens)?;
  }

  if let Some(top_k) = options.top_k {
    lower_top_k(obj, endpoint, provider_id, top_k)?;
  }

  let Some(reasoning) = options.reasoning.as_ref() else {
    return Ok(());
  };
  match endpoint {
    Endpoint::Responses => lower_responses_reasoning(obj, provider_id, reasoning),
    Endpoint::ChatCompletions => lower_chat_reasoning(obj, provider_id, model, reasoning),
    Endpoint::Messages => lower_messages_reasoning(obj, provider_id, model, reasoning),
  }
}

fn lower_max_output_tokens(
  obj: &mut Map<String, Value>,
  endpoint: Endpoint,
  provider_id: &str,
  model: &str,
  max_output_tokens: u64,
) -> Result<(), RequestsError> {
  match endpoint {
    Endpoint::Responses if provider_id == ID_CODEX => unsupported(
      "max_output_tokens",
      provider_id,
      endpoint,
      "the Codex Responses backend removes explicit output-token limits",
    ),
    Endpoint::Responses => {
      obj.remove("max_tokens");
      obj.remove("max_completion_tokens");
      obj.insert("max_output_tokens".into(), Value::from(max_output_tokens));
      Ok(())
    }
    Endpoint::ChatCompletions if uses_max_completion_tokens(provider_id, model) => {
      obj.remove("max_tokens");
      obj.remove("max_output_tokens");
      obj.insert("max_completion_tokens".into(), Value::from(max_output_tokens));
      Ok(())
    }
    Endpoint::ChatCompletions => {
      obj.remove("max_output_tokens");
      obj.remove("max_completion_tokens");
      obj.insert("max_tokens".into(), Value::from(max_output_tokens));
      Ok(())
    }
    Endpoint::Messages => {
      obj.remove("max_output_tokens");
      obj.remove("max_completion_tokens");
      obj.insert("max_tokens".into(), Value::from(max_output_tokens));
      Ok(())
    }
  }
}

fn uses_max_completion_tokens(provider_id: &str, model: &str) -> bool {
  if provider_id == ID_OPENAI {
    return true;
  }
  let model = model.to_ascii_lowercase();
  provider_id == ID_GITHUB_COPILOT
    && ["gpt-5", "o1", "o3", "o4"]
      .iter()
      .any(|prefix| model.starts_with(prefix))
}

pub(super) fn ensure_model_supports_reasoning(
  endpoint: Endpoint,
  provider_id: &str,
  reasoning_supported: Option<bool>,
  options: &GenerationOptions,
) -> Result<(), RequestsError> {
  if options.reasoning.is_some() && reasoning_supported == Some(false) {
    return unsupported(
      "reasoning",
      provider_id,
      endpoint,
      "the selected model is known not to support reasoning",
    );
  }
  Ok(())
}

fn lower_top_k(
  obj: &mut Map<String, Value>,
  endpoint: Endpoint,
  provider_id: &str,
  top_k: u64,
) -> Result<(), RequestsError> {
  if provider_id == ID_LLAMA_CPP && endpoint == Endpoint::ChatCompletions {
    obj.insert("top_k".into(), Value::from(top_k));
    return Ok(());
  }
  unsupported(
    "top_k",
    provider_id,
    endpoint,
    "typed top_k is currently supported only for llama.cpp Chat Completions routes",
  )
}

fn lower_responses_reasoning(
  obj: &mut Map<String, Value>,
  provider_id: &str,
  reasoning: &ReasoningOptions,
) -> Result<(), RequestsError> {
  reject_mode(
    reasoning,
    provider_id,
    Endpoint::Responses,
    &[ReasoningMode::Enabled, ReasoningMode::Adaptive],
    "Responses reasoning is controlled by effort rather than an enabled or adaptive mode",
  )?;
  reject_present(
    reasoning.budget_tokens,
    "reasoning.budget_tokens",
    provider_id,
    Endpoint::Responses,
    "the Responses API does not accept an explicit reasoning token budget",
  )?;

  if reasoning.effort.is_none() && reasoning.summary.is_none() && reasoning.mode.is_none() {
    return Ok(());
  }
  let target = object_field(obj, "reasoning");
  remove_fields(target, &["mode", "budget_tokens"]);
  if let Some(effort) = reasoning.effort.as_ref() {
    target.insert("effort".into(), Value::String(effort.as_str().to_string()));
  }
  if reasoning.mode == Some(ReasoningMode::Disabled) {
    target.insert("effort".into(), Value::String("none".into()));
  }
  if let Some(summary) = reasoning.summary.as_ref() {
    target.insert("summary".into(), Value::String(summary.as_str().to_string()));
  }
  Ok(())
}

fn lower_chat_reasoning(
  obj: &mut Map<String, Value>,
  provider_id: &str,
  model: &str,
  reasoning: &ReasoningOptions,
) -> Result<(), RequestsError> {
  if provider_id == ID_LLAMA_CPP {
    if !reasoning.is_empty() {
      return unsupported(
        "reasoning",
        provider_id,
        Endpoint::ChatCompletions,
        "llama.cpp has no portable reasoning control",
      );
    }
    return Ok(());
  }
  if provider_id == ID_DEEPSEEK {
    return lower_deepseek_reasoning(obj, Endpoint::ChatCompletions, provider_id, reasoning);
  }
  if ZAI_PROVIDERS.contains(&provider_id) {
    return lower_zai_reasoning(obj, provider_id, reasoning);
  }
  if provider_id == ID_GITHUB_COPILOT && model.starts_with("claude-") {
    return lower_claude_reasoning(obj, Endpoint::ChatCompletions, provider_id, model, reasoning);
  }

  reject_mode(
    reasoning,
    provider_id,
    Endpoint::ChatCompletions,
    &[ReasoningMode::Enabled, ReasoningMode::Adaptive],
    "Chat Completions accepts reasoning effort but not an enabled or adaptive mode",
  )?;
  reject_present(
    reasoning.budget_tokens,
    "reasoning.budget_tokens",
    provider_id,
    Endpoint::ChatCompletions,
    "Chat Completions does not accept an explicit reasoning token budget",
  )?;
  reject_present(
    reasoning.summary.as_ref(),
    "reasoning.summary",
    provider_id,
    Endpoint::ChatCompletions,
    "Chat Completions does not support reasoning summaries",
  )?;

  if reasoning.effort.is_some() || reasoning.mode == Some(ReasoningMode::Disabled) {
    obj.remove("reasoning");
    obj.remove("thinking");
  }
  if let Some(effort) = reasoning.effort.as_ref() {
    obj.insert("reasoning_effort".into(), Value::String(effort.as_str().to_string()));
  }
  if reasoning.mode == Some(ReasoningMode::Disabled) {
    obj.insert("reasoning_effort".into(), Value::String("none".into()));
  }
  Ok(())
}

fn lower_deepseek_reasoning(
  obj: &mut Map<String, Value>,
  endpoint: Endpoint,
  provider_id: &str,
  reasoning: &ReasoningOptions,
) -> Result<(), RequestsError> {
  reject_mode(
    reasoning,
    provider_id,
    endpoint,
    &[ReasoningMode::Adaptive],
    "DeepSeek does not support adaptive reasoning",
  )?;
  reject_present(
    reasoning.budget_tokens,
    "reasoning.budget_tokens",
    provider_id,
    endpoint,
    "DeepSeek does not accept an explicit reasoning token budget",
  )?;
  reject_present(
    reasoning.summary.as_ref(),
    "reasoning.summary",
    provider_id,
    endpoint,
    "DeepSeek does not support reasoning summaries",
  )?;
  let thinking_enabled = reasoning.mode != Some(ReasoningMode::Disabled)
    && (reasoning.mode == Some(ReasoningMode::Enabled) || reasoning.effort.is_some());
  if thinking_enabled {
    reject_present(
      obj.get("temperature"),
      "temperature",
      provider_id,
      endpoint,
      "DeepSeek ignores temperature while thinking is enabled",
    )?;
    reject_present(
      obj.get("top_p"),
      "top_p",
      provider_id,
      endpoint,
      "DeepSeek ignores top_p while thinking is enabled",
    )?;
  }
  if let Some(effort) = reasoning.effort.as_ref() {
    if !matches!(effort, ReasoningEffort::High | ReasoningEffort::Max) {
      return unsupported(
        "reasoning.effort",
        provider_id,
        endpoint,
        "DeepSeek accepts only the native high and max effort levels; compatibility aliases are not reinterpreted",
      );
    }
  }

  if reasoning.mode.is_none() && reasoning.effort.is_none() {
    return Ok(());
  }
  obj.remove("reasoning");
  let thinking = object_field(obj, "thinking");
  remove_fields(thinking, &["mode", "budget_tokens", "summary"]);
  if let Some(mode) = reasoning.mode.as_ref() {
    thinking.insert("type".into(), Value::String(reasoning_mode_str(*mode).into()));
  }
  if let Some(effort) = reasoning.effort.as_ref() {
    let effort = effort.as_str().to_string();
    thinking.insert("effort".into(), Value::String(effort.clone()));
    match endpoint {
      Endpoint::ChatCompletions => {
        obj.insert("reasoning_effort".into(), Value::String(effort));
      }
      Endpoint::Messages => {
        object_field(obj, "output_config").insert("effort".into(), Value::String(effort));
      }
      Endpoint::Responses => unreachable!("DeepSeek lowering is only used for Chat and Messages"),
    }
  }
  Ok(())
}

fn lower_zai_reasoning(
  obj: &mut Map<String, Value>,
  provider_id: &str,
  reasoning: &ReasoningOptions,
) -> Result<(), RequestsError> {
  reject_mode(
    reasoning,
    provider_id,
    Endpoint::ChatCompletions,
    &[ReasoningMode::Adaptive],
    "Z.AI does not support adaptive reasoning",
  )?;
  reject_present(
    reasoning.effort.as_ref(),
    "reasoning.effort",
    provider_id,
    Endpoint::ChatCompletions,
    "Z.AI exposes an enabled or disabled thinking mode, not reasoning effort",
  )?;
  reject_present(
    reasoning.budget_tokens,
    "reasoning.budget_tokens",
    provider_id,
    Endpoint::ChatCompletions,
    "Z.AI does not accept an explicit reasoning token budget",
  )?;
  reject_present(
    reasoning.summary.as_ref(),
    "reasoning.summary",
    provider_id,
    Endpoint::ChatCompletions,
    "Z.AI does not support reasoning summaries",
  )?;

  if let Some(mode) = reasoning.mode.as_ref() {
    obj.remove("reasoning");
    let thinking = object_field(obj, "thinking");
    thinking.insert("type".into(), Value::String(reasoning_mode_str(*mode).into()));
    if *mode == ReasoningMode::Enabled {
      thinking.insert("clear_thinking".into(), Value::Bool(false));
    } else {
      thinking.remove("clear_thinking");
    }
  }
  Ok(())
}

fn lower_messages_reasoning(
  obj: &mut Map<String, Value>,
  provider_id: &str,
  model: &str,
  reasoning: &ReasoningOptions,
) -> Result<(), RequestsError> {
  if provider_id == ID_DEEPSEEK {
    return lower_deepseek_reasoning(obj, Endpoint::Messages, provider_id, reasoning);
  }
  lower_claude_reasoning(obj, Endpoint::Messages, provider_id, model, reasoning)
}

fn lower_claude_reasoning(
  obj: &mut Map<String, Value>,
  endpoint: Endpoint,
  provider_id: &str,
  model: &str,
  reasoning: &ReasoningOptions,
) -> Result<(), RequestsError> {
  reject_present(
    reasoning.summary.as_ref(),
    "reasoning.summary",
    provider_id,
    endpoint,
    "Claude-compatible reasoning does not support summaries",
  )?;
  validate_claude_reasoning(obj, endpoint, provider_id, model, reasoning)?;

  if !reasoning.is_empty() {
    obj.remove("reasoning");
  }
  if let Some(thinking) = obj.get_mut("thinking").and_then(Value::as_object_mut) {
    remove_fields(thinking, &["mode", "effort", "summary"]);
    if matches!(
      reasoning.mode.as_ref(),
      Some(ReasoningMode::Adaptive | ReasoningMode::Disabled)
    ) {
      thinking.remove("budget_tokens");
    }
  }

  match reasoning.mode.as_ref() {
    Some(ReasoningMode::Enabled) => {
      let thinking = object_field(obj, "thinking");
      thinking.insert("type".into(), Value::String("enabled".into()));
      if let Some(budget_tokens) = reasoning.budget_tokens {
        thinking.insert("budget_tokens".into(), Value::from(budget_tokens));
      }
    }
    None if reasoning.budget_tokens.is_some() => {
      let thinking = object_field(obj, "thinking");
      thinking.insert("type".into(), Value::String("enabled".into()));
      thinking.insert(
        "budget_tokens".into(),
        Value::from(reasoning.budget_tokens.expect("checked as present")),
      );
    }
    Some(ReasoningMode::Adaptive) => {
      reject_present(
        reasoning.budget_tokens,
        "reasoning.budget_tokens",
        provider_id,
        endpoint,
        "adaptive reasoning does not accept a fixed token budget",
      )?;
      object_field(obj, "thinking").insert("type".into(), Value::String("adaptive".into()));
    }
    Some(ReasoningMode::Disabled) => {
      reject_present(
        reasoning.budget_tokens,
        "reasoning.budget_tokens",
        provider_id,
        endpoint,
        "disabled reasoning cannot have a token budget",
      )?;
      object_field(obj, "thinking").insert("type".into(), Value::String("disabled".into()));
    }
    None => {}
  }

  if let Some(effort) = reasoning.effort.as_ref() {
    object_field(obj, "output_config").insert("effort".into(), Value::String(effort.as_str().to_string()));
  }
  if obj
    .get("thinking")
    .and_then(Value::as_object)
    .is_some_and(Map::is_empty)
  {
    obj.remove("thinking");
  }
  Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaudeThinkingSupport {
  ManualOnly,
  AdaptiveAndManual,
  AdaptiveOnly,
  Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaudeEffortSupport {
  Unsupported,
  LowToHigh,
  ThroughMax,
  ThroughXHigh,
  Unknown,
}

fn validate_claude_reasoning(
  obj: &Map<String, Value>,
  endpoint: Endpoint,
  provider_id: &str,
  model: &str,
  reasoning: &ReasoningOptions,
) -> Result<(), RequestsError> {
  let support = claude_thinking_support(model);
  let manual = reasoning.mode == Some(ReasoningMode::Enabled) || reasoning.budget_tokens.is_some();

  if reasoning.mode == Some(ReasoningMode::Disabled) && claude_rejects_disabled_reasoning(model) {
    return unsupported(
      "reasoning.mode",
      provider_id,
      endpoint,
      "this Claude model has adaptive reasoning enabled by default and does not support disabling it",
    );
  }

  if manual {
    let Some(budget_tokens) = reasoning.budget_tokens else {
      return unsupported(
        "reasoning.budget_tokens",
        provider_id,
        endpoint,
        "manual Claude reasoning requires an explicit token budget",
      );
    };
    if budget_tokens < 1024 {
      return unsupported(
        "reasoning.budget_tokens",
        provider_id,
        endpoint,
        "manual Claude reasoning requires a budget of at least 1024 tokens",
      );
    }
    if support == ClaudeThinkingSupport::AdaptiveOnly {
      return unsupported(
        "reasoning.mode",
        provider_id,
        endpoint,
        "this Claude model supports adaptive reasoning instead of manual token budgets",
      );
    }
    let Some(max_tokens) = obj.get("max_tokens").and_then(Value::as_u64) else {
      return unsupported(
        "max_output_tokens",
        provider_id,
        endpoint,
        "manual Claude reasoning requires an explicit max_tokens limit",
      );
    };
    if budget_tokens >= max_tokens {
      return unsupported(
        "reasoning.budget_tokens",
        provider_id,
        endpoint,
        "manual Claude reasoning requires budget_tokens to be less than max_tokens",
      );
    }
  }

  if reasoning.mode == Some(ReasoningMode::Adaptive) && support == ClaudeThinkingSupport::ManualOnly {
    return unsupported(
      "reasoning.mode",
      provider_id,
      endpoint,
      "this Claude model supports manual reasoning budgets, not adaptive reasoning",
    );
  }
  validate_claude_effort(endpoint, provider_id, model, reasoning.effort.as_ref())?;
  validate_claude_sampling(
    obj,
    endpoint,
    provider_id,
    model,
    manual || reasoning.mode == Some(ReasoningMode::Adaptive),
  )?;
  Ok(())
}

fn claude_thinking_support(model: &str) -> ClaudeThinkingSupport {
  let model = normalize_claude_model(model);
  if model.contains("mythos-preview") || model.contains("-4-6") {
    return ClaudeThinkingSupport::AdaptiveAndManual;
  }
  if model.contains("-4-7")
    || model.contains("-4-8")
    || model.contains("claude-sonnet-5")
    || model.contains("claude-opus-5")
    || model.contains("claude-fable-5")
    || model.contains("claude-mythos-5")
  {
    return ClaudeThinkingSupport::AdaptiveOnly;
  }
  if model.contains("-4-5")
    || model.contains("-4-1")
    || model.contains("-4-0")
    || model.contains("claude-opus-41")
    || model == "claude-sonnet-4"
    || model.starts_with("claude-sonnet-4-20")
    || model.contains("claude-3-7")
  {
    return ClaudeThinkingSupport::ManualOnly;
  }
  ClaudeThinkingSupport::Unknown
}

fn validate_claude_effort(
  endpoint: Endpoint,
  provider_id: &str,
  model: &str,
  effort: Option<&ReasoningEffort>,
) -> Result<(), RequestsError> {
  let Some(effort) = effort else {
    return Ok(());
  };
  let support = claude_effort_support(model);
  let supported = match effort {
    ReasoningEffort::Minimal => false,
    ReasoningEffort::Low | ReasoningEffort::Medium | ReasoningEffort::High => {
      support != ClaudeEffortSupport::Unsupported
    }
    ReasoningEffort::Max => matches!(
      support,
      ClaudeEffortSupport::ThroughMax | ClaudeEffortSupport::ThroughXHigh | ClaudeEffortSupport::Unknown
    ),
    ReasoningEffort::XHigh => matches!(
      support,
      ClaudeEffortSupport::ThroughXHigh | ClaudeEffortSupport::Unknown
    ),
    ReasoningEffort::Custom(_) => true,
  };
  if !supported {
    return unsupported(
      "reasoning.effort",
      provider_id,
      endpoint,
      "the selected Claude model does not support this effort level",
    );
  }
  Ok(())
}

fn claude_effort_support(model: &str) -> ClaudeEffortSupport {
  let model = normalize_claude_model(model);
  if model.contains("claude-opus-4-7")
    || model.contains("claude-opus-4-8")
    || model.contains("claude-fable-5")
    || model.contains("claude-mythos-5")
    || model.contains("claude-opus-5")
    || model.contains("claude-sonnet-5")
  {
    return ClaudeEffortSupport::ThroughXHigh;
  }
  if model.contains("-4-6") || model.contains("mythos-preview") {
    return ClaudeEffortSupport::ThroughMax;
  }
  if model.contains("claude-opus-4-5") {
    return ClaudeEffortSupport::LowToHigh;
  }
  if model.contains("claude-opus-41")
    || model.contains("claude-opus-4-1")
    || model == "claude-sonnet-4"
    || model.starts_with("claude-sonnet-4-20")
    || model.contains("claude-sonnet-4-5")
    || model.contains("claude-haiku-4-5")
    || model.contains("claude-3-7")
  {
    return ClaudeEffortSupport::Unsupported;
  }
  ClaudeEffortSupport::Unknown
}

fn claude_rejects_disabled_reasoning(model: &str) -> bool {
  let model = normalize_claude_model(model);
  model.contains("claude-fable-5") || model.contains("claude-mythos-5") || model.contains("mythos-preview")
}

fn validate_claude_sampling(
  obj: &Map<String, Value>,
  endpoint: Endpoint,
  provider_id: &str,
  model: &str,
  thinking_enabled: bool,
) -> Result<(), RequestsError> {
  if claude_rejects_sampling_controls(model) {
    if obj.get("temperature").is_some_and(|value| value.as_f64() != Some(1.0)) {
      return unsupported(
        "temperature",
        provider_id,
        endpoint,
        "this Claude model rejects non-default sampling controls",
      );
    }
    if obj.contains_key("top_p") {
      return unsupported(
        "top_p",
        provider_id,
        endpoint,
        "this Claude model rejects non-default sampling controls",
      );
    }
    return Ok(());
  }
  if !thinking_enabled {
    return Ok(());
  }
  if obj.get("temperature").is_some_and(|value| value.as_f64() != Some(1.0)) {
    return unsupported(
      "temperature",
      provider_id,
      endpoint,
      "Claude requires temperature to be omitted or set to 1 while thinking is enabled",
    );
  }
  if obj
    .get("top_p")
    .is_some_and(|value| value.as_f64().is_none_or(|top_p| !(0.95..=1.0).contains(&top_p)))
  {
    return unsupported(
      "top_p",
      provider_id,
      endpoint,
      "Claude requires top_p to be between 0.95 and 1 while thinking is enabled",
    );
  }
  Ok(())
}

fn claude_rejects_sampling_controls(model: &str) -> bool {
  let model = normalize_claude_model(model);
  model.contains("claude-fable-5")
    || model.contains("claude-mythos-5")
    || model.contains("mythos-preview")
    || model.contains("claude-opus-4-7")
    || model.contains("claude-opus-4-8")
    || model.contains("claude-opus-5")
    || model.contains("claude-sonnet-5")
}

fn normalize_claude_model(model: &str) -> String {
  model.to_ascii_lowercase().replace(['.', '_'], "-")
}

fn remove_fields(obj: &mut Map<String, Value>, fields: &[&str]) {
  for field in fields {
    obj.remove(*field);
  }
}

fn reasoning_mode_str(mode: ReasoningMode) -> &'static str {
  match mode {
    ReasoningMode::Enabled => "enabled",
    ReasoningMode::Disabled => "disabled",
    ReasoningMode::Adaptive => "adaptive",
  }
}

fn object_field<'a>(obj: &'a mut Map<String, Value>, field: &str) -> &'a mut Map<String, Value> {
  let value = obj
    .entry(field.to_string())
    .or_insert_with(|| Value::Object(Map::new()));
  if !value.is_object() {
    *value = Value::Object(Map::new());
  }
  value.as_object_mut().expect("field was normalized to an object")
}

fn reject_mode(
  reasoning: &ReasoningOptions,
  provider_id: &str,
  endpoint: Endpoint,
  rejected: &[ReasoningMode],
  reason: &'static str,
) -> Result<(), RequestsError> {
  if reasoning.mode.as_ref().is_some_and(|mode| rejected.contains(mode)) {
    return unsupported("reasoning.mode", provider_id, endpoint, reason);
  }
  Ok(())
}

fn reject_present<T>(
  value: Option<T>,
  control: &'static str,
  provider_id: &str,
  endpoint: Endpoint,
  reason: &'static str,
) -> Result<(), RequestsError> {
  if value.is_some() {
    return unsupported(control, provider_id, endpoint, reason);
  }
  Ok(())
}

fn unsupported<T>(
  control: &'static str,
  provider_id: &str,
  endpoint: Endpoint,
  reason: &'static str,
) -> Result<T, RequestsError> {
  Err(RequestsError::UnsupportedGenerationControl {
    control,
    provider_id: provider_id.into(),
    endpoint,
    reason,
  })
}

#[cfg(test)]
mod tests {
  use super::super::default::DefaultConvertRequest;
  use super::*;
  use crate::event::{EventBus, Stage};
  use crate::pipeline::config::RunConfig;
  use crate::pipeline::ctx::PipelineCtx;
  use crate::pipeline::stages::{ConvertRequestStage, Extracted, Resolved, ResolvedRoute};
  use crate::test_support::{mock_handle, mock_handle_with_provider, MockProvider};
  use crate::utils::codec::{decode_body_bytes, encode_body_bytes, ContentEncodingKind};
  use bytes::Bytes;
  use std::sync::Arc;
  use tokn_core::generation::ReasoningSummary;
  use tokn_core::pipeline::InputTransformer;
  use tokn_core::provider::{Endpoint, Result as ProviderResult, ID_OPENAI, ID_ZAI};
  use tokn_headers::HeaderMap;

  fn ctx_at(endpoint: Endpoint) -> PipelineCtx {
    PipelineCtx::new("req-cr", endpoint.into(), Arc::new(EventBus::new(64)))
  }

  fn ctx() -> PipelineCtx {
    ctx_at(Endpoint::ChatCompletions)
  }

  fn ctx_with_config(endpoint: Endpoint, config: RunConfig) -> PipelineCtx {
    PipelineCtx::new_with_config("req-cr", endpoint.into(), Arc::new(EventBus::new(64)), Arc::new(config))
  }

  fn ctx_with_generation_options(endpoint: Endpoint, options: GenerationOptions) -> PipelineCtx {
    ctx_with_config(endpoint, RunConfig::builder().with_generation_options(options).build())
  }

  fn extracted_with(
    body: Value,
    encoding: Option<ContentEncodingKind>,
    wire: Bytes,
    initiator: Option<&str>,
  ) -> Extracted {
    Extracted {
      agent_id: None,
      model: smol_str::SmolStr::new("input-model"),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: initiator.map(smol_str::SmolStr::new),
      header_initiator: None,
      route_mode_hint: None,
      headers: HeaderMap::new(),
      raw_body: wire.clone(),
      decoded_body: Bytes::from(serde_json::to_vec(&body).unwrap()),
      body_json: Arc::new(body),
      content_encoding: encoding,
    }
  }

  fn resolved_with(
    handle: Arc<tokn_accounts::AccountHandle>,
    resolved_endpoint: Endpoint,
    upstream_endpoint: Endpoint,
    upstream_model: &str,
  ) -> Resolved {
    Resolved {
      agent_id: None,
      model: smol_str::SmolStr::new("input-model"),
      upstream_model: smol_str::SmolStr::new(upstream_model),
      route: ResolvedRoute::operation(resolved_endpoint, upstream_endpoint),
      account_id: smol_str::SmolStr::new("acct-1"),
      provider_id: smol_str::SmolStr::from(handle.provider.id()),
      account_handle: handle,
    }
  }

  #[tokio::test]
  async fn passthrough_when_endpoints_match_and_no_transformer() {
    let body = serde_json::json!({"model": "input-model", "messages": [{"role":"user","content":"hi"}]});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body.clone(), None, raw.clone(), None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(*out.upstream_body, body);
    // Body unchanged → original wire bytes reused verbatim.
    assert_eq!(out.upstream_wire_body, raw);
    assert!(out.content_encoding.is_none());
  }

  #[tokio::test]
  async fn rewrites_model_field() {
    let body = serde_json::json!({"model": "input-model", "messages": []});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "upstream-model-7",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.upstream_body["model"], "upstream-model-7");
  }

  #[tokio::test]
  async fn runs_provider_input_transformer() {
    struct Stamp;
    impl InputTransformer for Stamp {
      fn transform_input(&self, _endpoint: Endpoint, mut body: Value) -> ProviderResult<Value> {
        if let Some(obj) = body.as_object_mut() {
          obj.insert("stamped".into(), Value::Bool(true));
        }
        Ok(body)
      }
    }
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let handle = mock_handle_with_provider("acct", MockProvider::new("mock").with_transformer(Stamp));
    let res = resolved_with(
      handle,
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.upstream_body["stamped"], true);
  }

  #[tokio::test]
  async fn cross_endpoint_convert_runs_when_endpoints_differ() {
    // Responses → ChatCompletions. We don't assert on the exact shape
    // (that's `tokn_convert`'s responsibility) — just that the body
    // mutated and was re-serialized into `debug_outbound_body`.
    let body = serde_json::json!({
      "model": "input-model",
      "input": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body.clone(), None, raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::Responses,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest
      .convert_request(&ctx_at(Endpoint::Responses), &ex, &res)
      .await
      .unwrap();
    assert_ne!(
      *out.upstream_body, body,
      "expected cross-endpoint conversion to mutate body"
    );
    // wire body was re-serialized (not the original raw bytes).
    assert_eq!(out.upstream_wire_body, out.debug_outbound_body);
  }

  #[tokio::test]
  async fn openai_responses_lowers_effort_and_summary() {
    let body = serde_json::json!({
      "model": "input-model",
      "input": [{"role": "user", "content": "hi"}],
      "reasoning": {
        "mode": "enabled",
        "effort": "low",
        "budget_tokens": 512,
        "summary": "detailed",
        "provider_extension": true
      }
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_OPENAI),
      Endpoint::Responses,
      Endpoint::Responses,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::Responses,
      GenerationOptions {
        reasoning: Some(ReasoningOptions {
          effort: Some(ReasoningEffort::High),
          summary: Some(ReasoningSummary::Concise),
          ..ReasoningOptions::default()
        }),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert_eq!(out.upstream_body["reasoning"]["effort"], "high");
    assert_eq!(out.upstream_body["reasoning"]["summary"], "concise");
    assert_eq!(out.upstream_body["reasoning"]["provider_extension"], true);
    assert!(out.upstream_body["reasoning"].get("mode").is_none());
    assert!(out.upstream_body["reasoning"].get("budget_tokens").is_none());
  }

  #[tokio::test]
  async fn openai_chat_uses_max_completion_tokens() {
    let body = serde_json::json!({
      "model": "gpt-4o",
      "input": [{"role": "user", "content": "hi"}],
      "max_output_tokens": 512
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_OPENAI),
      Endpoint::Responses,
      Endpoint::ChatCompletions,
      "gpt-4o",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::Responses,
      GenerationOptions {
        max_output_tokens: Some(512),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert_eq!(out.upstream_body["max_completion_tokens"], 512);
    assert!(out.upstream_body.get("max_tokens").is_none());
    assert!(out.upstream_body.get("max_output_tokens").is_none());
  }

  #[tokio::test]
  async fn codex_responses_rejects_explicit_output_token_limit() {
    let body = serde_json::json!({
      "model": "gpt-5-codex",
      "input": [{"role": "user", "content": "hi"}],
      "max_output_tokens": 512
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_CODEX),
      Endpoint::Responses,
      Endpoint::Responses,
      "gpt-5-codex",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::Responses,
      GenerationOptions {
        max_output_tokens: Some(512),
        ..GenerationOptions::default()
      },
    );

    let error = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .unwrap_err();

    assert!(matches!(
      error.inner(),
      RequestsError::UnsupportedGenerationControl {
        control: "max_output_tokens",
        provider_id,
        endpoint: Endpoint::Responses,
        ..
      } if provider_id == ID_CODEX
    ));
  }

  #[tokio::test]
  async fn responses_rejects_explicit_top_k() {
    let body = serde_json::json!({
      "model": "input-model",
      "input": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_OPENAI),
      Endpoint::Responses,
      Endpoint::Responses,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::Responses,
      GenerationOptions {
        top_k: Some(40),
        ..GenerationOptions::default()
      },
    );

    let err = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .unwrap_err();

    assert_eq!(err.stage, Stage::ConvertRequest);
    assert!(!err.recoverable);
    match err.inner() {
      RequestsError::UnsupportedGenerationControl {
        control,
        provider_id,
        endpoint,
        ..
      } => {
        assert_eq!(*control, "top_k");
        assert_eq!(provider_id, ID_OPENAI);
        assert_eq!(*endpoint, Endpoint::Responses);
      }
      other => panic!("expected UnsupportedGenerationControl, got {other:?}"),
    }
  }

  #[tokio::test]
  async fn openai_chat_rejects_explicit_top_k() {
    let body = serde_json::json!({
      "model": "input-model",
      "messages": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_OPENAI),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::ChatCompletions,
      GenerationOptions {
        top_k: Some(40),
        ..GenerationOptions::default()
      },
    );

    let err = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .unwrap_err();

    assert!(matches!(
      err.inner(),
      RequestsError::UnsupportedGenerationControl {
        control: "top_k",
        provider_id,
        endpoint: Endpoint::ChatCompletions,
        ..
      } if provider_id == ID_OPENAI
    ));
  }

  #[tokio::test]
  async fn llama_chat_lowers_top_k_and_overwrites_legacy_value() {
    let body = serde_json::json!({
      "model": "input-model",
      "messages": [{"role": "user", "content": "hi"}],
      "top_k": 7
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_LLAMA_CPP),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::ChatCompletions,
      GenerationOptions {
        top_k: Some(40),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert_eq!(out.upstream_body["top_k"], 40);
  }

  #[tokio::test]
  async fn deepseek_chat_lowers_mode_and_effort_for_provider_transformer() {
    let body = serde_json::json!({
      "model": "input-model",
      "messages": [{"role": "user", "content": "hi"}],
      "reasoning": {"effort": "low"},
      "reasoning_effort": "low"
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_DEEPSEEK),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::ChatCompletions,
      GenerationOptions {
        reasoning: Some(ReasoningOptions {
          mode: Some(ReasoningMode::Enabled),
          effort: Some(ReasoningEffort::High),
          ..ReasoningOptions::default()
        }),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert!(out.upstream_body.get("reasoning").is_none());
    assert_eq!(out.upstream_body["thinking"]["type"], "enabled");
    assert_eq!(out.upstream_body["thinking"]["effort"], "high");
    assert_eq!(out.upstream_body["reasoning_effort"], "high");
  }

  #[test]
  fn deepseek_rejects_compatibility_effort_aliases() {
    for effort in [ReasoningEffort::Low, ReasoningEffort::XHigh] {
      let mut body = serde_json::json!({
        "model": "deepseek-v4-pro",
        "messages": [{"role": "user", "content": "hi"}]
      });
      let options = GenerationOptions::new().with_reasoning(ReasoningOptions::new().with_effort(effort));

      let error = lower_generation_options(
        &mut body,
        Endpoint::ChatCompletions,
        ID_DEEPSEEK,
        "deepseek-v4-pro",
        &options,
      )
      .expect_err("compatibility aliases must not be silently reinterpreted");

      assert!(matches!(
        error,
        RequestsError::UnsupportedGenerationControl {
          control: "reasoning.effort",
          ..
        }
      ));
    }
  }

  #[test]
  fn deepseek_rejects_sampling_controls_that_thinking_would_ignore() {
    let mut body = serde_json::json!({
      "model": "deepseek-v4-pro",
      "messages": [{"role": "user", "content": "hi"}],
      "top_p": 0.9
    });
    let options = GenerationOptions::new().with_reasoning(
      ReasoningOptions::new()
        .with_mode(ReasoningMode::Enabled)
        .with_effort(ReasoningEffort::Max),
    );

    let error = lower_generation_options(
      &mut body,
      Endpoint::ChatCompletions,
      ID_DEEPSEEK,
      "deepseek-v4-pro",
      &options,
    )
    .expect_err("ignored sampling controls must fail locally");

    assert!(matches!(
      error,
      RequestsError::UnsupportedGenerationControl { control: "top_p", .. }
    ));
  }

  #[tokio::test]
  async fn zai_chat_lowers_disabled_mode() {
    let body = serde_json::json!({
      "model": "input-model",
      "messages": [{"role": "user", "content": "hi"}],
      "reasoning": {"mode": "enabled"},
      "thinking": {"type": "enabled", "clear_thinking": false}
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_ZAI),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::ChatCompletions,
      GenerationOptions {
        reasoning: Some(ReasoningOptions {
          mode: Some(ReasoningMode::Disabled),
          ..ReasoningOptions::default()
        }),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert!(out.upstream_body.get("reasoning").is_none());
    assert_eq!(out.upstream_body["thinking"]["type"], "disabled");
    assert!(out.upstream_body["thinking"].get("clear_thinking").is_none());
  }

  #[tokio::test]
  async fn zai_chat_lowers_enabled_mode_with_clear_thinking_disabled() {
    let body = serde_json::json!({
      "model": "input-model",
      "messages": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_ZAI),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::ChatCompletions,
      GenerationOptions {
        reasoning: Some(ReasoningOptions {
          mode: Some(ReasoningMode::Enabled),
          ..ReasoningOptions::default()
        }),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert_eq!(
      out.upstream_body["thinking"],
      serde_json::json!({"type": "enabled", "clear_thinking": false})
    );
  }

  #[tokio::test]
  async fn copilot_messages_lowers_adaptive_mode_and_effort() {
    let body = serde_json::json!({
      "model": "claude-sonnet-4.6",
      "messages": [{"role": "user", "content": "hi"}],
      "max_tokens": 1024,
      "thinking": {"mode": "adaptive", "effort": "low"},
      "output_config": {"effort": "low"}
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_GITHUB_COPILOT),
      Endpoint::Messages,
      Endpoint::Messages,
      "claude-sonnet-4.6",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::Messages,
      GenerationOptions {
        reasoning: Some(ReasoningOptions {
          mode: Some(ReasoningMode::Adaptive),
          effort: Some(ReasoningEffort::Medium),
          ..ReasoningOptions::default()
        }),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert_eq!(out.upstream_body["thinking"], serde_json::json!({"type": "adaptive"}));
    assert_eq!(out.upstream_body["output_config"]["effort"], "medium");
  }

  #[tokio::test]
  async fn copilot_claude_chat_fallback_lowers_manual_budget_and_effort() {
    let body = serde_json::json!({
      "model": "claude-sonnet-4.6",
      "input": [{"role": "user", "content": "hi"}],
      "reasoning": {
        "mode": "enabled",
        "effort": "high",
        "budget_tokens": 2048
      },
      "max_output_tokens": 4096
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_GITHUB_COPILOT),
      Endpoint::Responses,
      Endpoint::ChatCompletions,
      "claude-sonnet-4.6",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::Responses,
      GenerationOptions {
        max_output_tokens: Some(4096),
        reasoning: Some(ReasoningOptions {
          mode: Some(ReasoningMode::Enabled),
          effort: Some(ReasoningEffort::High),
          budget_tokens: Some(2048),
          ..ReasoningOptions::default()
        }),
        ..GenerationOptions::default()
      },
    );

    let out = DefaultConvertRequest.convert_request(&ctx, &ex, &res).await.unwrap();

    assert!(out.upstream_body.get("reasoning").is_none());
    assert_eq!(
      out.upstream_body["thinking"],
      serde_json::json!({"type": "enabled", "budget_tokens": 2048})
    );
    assert_eq!(out.upstream_body["max_tokens"], 4096);
    assert_eq!(out.upstream_body["output_config"]["effort"], "high");
  }

  #[test]
  fn claude_reasoning_rejects_invalid_model_mode_and_budget_combinations() {
    let cases = [
      (
        "enabled without budget",
        "claude-sonnet-4.6",
        ReasoningOptions::new().with_mode(ReasoningMode::Enabled),
        "reasoning.budget_tokens",
      ),
      (
        "budget below minimum",
        "claude-sonnet-4.6",
        ReasoningOptions::new()
          .with_mode(ReasoningMode::Enabled)
          .with_budget_tokens(512),
        "reasoning.budget_tokens",
      ),
      (
        "budget does not leave output room",
        "claude-sonnet-4.6",
        ReasoningOptions::new()
          .with_mode(ReasoningMode::Enabled)
          .with_budget_tokens(2048),
        "reasoning.budget_tokens",
      ),
      (
        "adaptive mode on a manual-only model",
        "claude-sonnet-4.5",
        ReasoningOptions::new().with_mode(ReasoningMode::Adaptive),
        "reasoning.mode",
      ),
      (
        "adaptive mode on Copilot's compact Opus 4.1 id",
        "claude-opus-41",
        ReasoningOptions::new().with_mode(ReasoningMode::Adaptive),
        "reasoning.mode",
      ),
      (
        "adaptive mode on Copilot's Sonnet 4 id",
        "claude-sonnet-4",
        ReasoningOptions::new().with_mode(ReasoningMode::Adaptive),
        "reasoning.mode",
      ),
      (
        "manual mode on an adaptive-only model",
        "claude-opus-4.7",
        ReasoningOptions::new()
          .with_mode(ReasoningMode::Enabled)
          .with_budget_tokens(1024),
        "reasoning.mode",
      ),
      (
        "disabled mode on an always-adaptive model",
        "claude-mythos-preview",
        ReasoningOptions::new().with_mode(ReasoningMode::Disabled),
        "reasoning.mode",
      ),
    ];

    for (name, model, reasoning, expected_control) in cases {
      let mut body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 2048
      });
      let options = GenerationOptions {
        reasoning: Some(reasoning),
        ..GenerationOptions::default()
      };

      let error = lower_generation_options(&mut body, Endpoint::ChatCompletions, ID_GITHUB_COPILOT, model, &options)
        .expect_err(name);

      assert!(
        matches!(
          error,
          RequestsError::UnsupportedGenerationControl { control, .. } if control == expected_control
        ),
        "{name}: {error}"
      );
    }
  }

  #[test]
  fn manual_claude_reasoning_requires_an_explicit_output_limit() {
    let mut body = serde_json::json!({
      "model": "claude-sonnet-4.6",
      "messages": [{"role": "user", "content": "hi"}]
    });
    let options = GenerationOptions::new().with_reasoning(
      ReasoningOptions::new()
        .with_mode(ReasoningMode::Enabled)
        .with_budget_tokens(2048),
    );

    let error = lower_generation_options(
      &mut body,
      Endpoint::ChatCompletions,
      ID_GITHUB_COPILOT,
      "claude-sonnet-4.6",
      &options,
    )
    .expect_err("manual reasoning must have an output limit");

    assert!(matches!(
      error,
      RequestsError::UnsupportedGenerationControl {
        control: "max_output_tokens",
        ..
      }
    ));
  }

  #[test]
  fn claude_reasoning_validates_effort_by_model_generation() {
    let cases = [
      (
        "Sonnet 4.5 has no effort control",
        "claude-sonnet-4.5",
        ReasoningEffort::High,
        true,
      ),
      (
        "Opus 4.5 supports low through high",
        "claude-opus-4.5",
        ReasoningEffort::High,
        false,
      ),
      (
        "Opus 4.5 does not support max",
        "claude-opus-4.5",
        ReasoningEffort::Max,
        true,
      ),
      (
        "Sonnet 4.6 supports max",
        "claude-sonnet-4.6",
        ReasoningEffort::Max,
        false,
      ),
      (
        "Sonnet 4.6 does not support xhigh",
        "claude-sonnet-4.6",
        ReasoningEffort::XHigh,
        true,
      ),
      (
        "Opus 4.7 supports xhigh",
        "claude-opus-4.7",
        ReasoningEffort::XHigh,
        false,
      ),
    ];

    for (name, model, effort, should_reject) in cases {
      let error = validate_claude_effort(Endpoint::Messages, ID_GITHUB_COPILOT, model, Some(&effort)).err();
      assert_eq!(error.is_some(), should_reject, "{name}");
    }
  }

  #[test]
  fn claude_reasoning_validates_sampling_compatibility() {
    let mut old_model_body = serde_json::json!({"temperature": 0.2, "top_p": 0.97});
    let error = validate_claude_sampling(
      old_model_body.as_object().expect("object"),
      Endpoint::Messages,
      ID_GITHUB_COPILOT,
      "claude-sonnet-4.6",
      true,
    )
    .expect_err("non-default temperature is incompatible with thinking");
    assert!(matches!(
      error,
      RequestsError::UnsupportedGenerationControl {
        control: "temperature",
        ..
      }
    ));

    old_model_body["temperature"] = Value::from(1.0);
    validate_claude_sampling(
      old_model_body.as_object().expect("object"),
      Endpoint::Messages,
      ID_GITHUB_COPILOT,
      "claude-sonnet-4.6",
      true,
    )
    .expect("supported manual-thinking sampling values");

    let current_model_body = serde_json::json!({"top_p": 1.0});
    let error = validate_claude_sampling(
      current_model_body.as_object().expect("object"),
      Endpoint::Messages,
      ID_GITHUB_COPILOT,
      "claude-opus-4.7",
      false,
    )
    .expect_err("current Claude models reject explicit non-default sampling");
    assert!(matches!(
      error,
      RequestsError::UnsupportedGenerationControl { control: "top_p", .. }
    ));
  }

  #[test]
  fn known_non_reasoning_models_reject_typed_reasoning() {
    let options = GenerationOptions::new().with_reasoning(ReasoningOptions::new().with_effort(ReasoningEffort::High));

    let error =
      ensure_model_supports_reasoning(Endpoint::Responses, ID_OPENAI, Some(false), &options).expect_err("reject");
    assert!(matches!(
      error,
      RequestsError::UnsupportedGenerationControl {
        control: "reasoning",
        ..
      }
    ));
    ensure_model_supports_reasoning(Endpoint::Responses, ID_OPENAI, Some(true), &options).expect("reasoning model");
    ensure_model_supports_reasoning(Endpoint::Responses, ID_OPENAI, None, &options).expect("unknown future model");
  }

  #[test]
  fn non_object_bodies_reject_explicit_generation_controls() {
    let mut body = serde_json::json!(["not", "an", "object"]);
    let options = GenerationOptions::new().with_max_output_tokens(128);

    let error =
      lower_generation_options(&mut body, Endpoint::Responses, ID_OPENAI, "gpt-5", &options).expect_err("reject");

    assert!(matches!(
      error,
      RequestsError::UnsupportedGenerationControl {
        control: "max_output_tokens",
        ..
      }
    ));
  }

  #[tokio::test]
  async fn invalid_generation_options_in_run_config_fail_before_lowering() {
    let body = serde_json::json!({
      "model": "input-model",
      "messages": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", ID_OPENAI),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    let ctx = ctx_with_generation_options(
      Endpoint::ChatCompletions,
      GenerationOptions {
        max_output_tokens: Some(0),
        ..GenerationOptions::default()
      },
    );

    let error = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .expect_err("invalid generation options");
    assert!(matches!(error.inner(), RequestsError::InvalidGenerationOptions { .. }));
  }

  #[tokio::test]
  async fn raw_request_without_generation_options_keeps_control_fields() {
    let body = serde_json::json!({
      "model": "input-model",
      "messages": [{"role": "user", "content": "hi"}],
      "top_k": 7,
      "reasoning_effort": "custom",
      "thinking": {"type": "provider-specific"}
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body.clone(), None, raw.clone(), None);
    let res = resolved_with(
      mock_handle("acct", ID_OPENAI),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();

    assert_eq!(*out.upstream_body, body);
    assert_eq!(out.upstream_wire_body, raw);
  }

  #[tokio::test]
  async fn gzip_round_trips_when_body_changes() {
    let body = serde_json::json!({"model": "input-model", "messages": []});
    let compressed = encode_body_bytes(
      serde_json::to_vec(&body).unwrap().as_slice(),
      Some(ContentEncodingKind::Gzip),
    )
    .unwrap();
    let ex = extracted_with(body, Some(ContentEncodingKind::Gzip), compressed, None);
    // Different upstream model → body mutates → we must re-compress.
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "upstream-model-2",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.content_encoding, Some(ContentEncodingKind::Gzip));
    let decoded = decode_body_bytes(out.upstream_wire_body.clone(), out.content_encoding).unwrap();
    let v: Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(v["model"], "upstream-model-2");
  }

  #[tokio::test]
  async fn content_encoding_propagates_to_output() {
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, Some(ContentEncodingKind::Zstd), raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.content_encoding, Some(ContentEncodingKind::Zstd));
  }

  #[tokio::test]
  async fn transformer_failure_is_permanent_stage_error() {
    struct Boom;
    impl InputTransformer for Boom {
      fn transform_input(&self, _endpoint: Endpoint, _body: Value) -> ProviderResult<Value> {
        Err(tokn_core::provider::error::Error::Profiles { message: "boom".into() })
      }
    }
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let handle = mock_handle_with_provider("acct", MockProvider::new("mock").with_transformer(Boom));
    let res = resolved_with(
      handle,
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let err = DefaultConvertRequest
      .convert_request(&ctx(), &ex, &res)
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::ConvertRequest);
    assert!(!err.recoverable);
    assert!(err.message().contains("boom"));
  }

  #[tokio::test]
  async fn uses_run_config_upstream_endpoint_override_for_cross_endpoint_conversion() {
    let body = serde_json::json!({
      "model": "input-model",
      "input": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body.clone(), None, raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::Responses,
      Endpoint::Responses,
      "input-model",
    );
    let ctx = ctx_with_config(
      Endpoint::Responses,
      RunConfig::builder()
        .with_str(crate::pipeline::stages::RUN_UPSTREAM_ENDPOINT_KEY, "chat_completions")
        .build(),
    );

    let out = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .expect("convert should use configured upstream endpoint");

    assert_ne!(*out.upstream_body, body);
    assert_eq!(out.upstream_wire_body, out.debug_outbound_body);
  }

  #[tokio::test]
  async fn errors_when_no_resolved_endpoint_is_available() {
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let mut res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    res.route = ResolvedRoute::provider_traffic(tokn_core::provider::ProviderRequestKind::Opaque);
    let ctx = PipelineCtx::new(
      "req-cr-missing",
      tokn_core::request_event::RequestEndpoint::custom("/v1/experimental/agents"),
      Arc::new(EventBus::new(64)),
    );

    let err = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .unwrap_err();

    assert_eq!(err.stage, Stage::ConvertRequest);
    assert!(!err.recoverable);
    match err.inner() {
      RequestsError::MissingResolvedEndpoint { request_endpoint } => {
        assert_eq!(request_endpoint.as_str(), "/v1/experimental/agents");
      }
      other => panic!("expected MissingResolvedEndpoint, got {other:?}"),
    }
  }

  #[test]
  fn extracted_helper_preserves_user_agent_and_none_initiator() {
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());

    assert_eq!(
      extracted_with(body.clone(), None, raw.clone(), None)
        .initiator
        .as_deref(),
      None
    );
    assert_eq!(
      extracted_with(body.clone(), None, raw.clone(), Some("user"))
        .initiator
        .as_deref(),
      Some("user")
    );
    assert_eq!(
      extracted_with(body, None, raw, Some("agent")).initiator.as_deref(),
      Some("agent")
    );
  }
}

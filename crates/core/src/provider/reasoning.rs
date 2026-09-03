use crate::generation::ReasoningEffort;
use serde_json::Value;

/// Read explicit effort support from Copilot, Codex, or Anthropic model records.
/// Missing or unrecognized metadata stays unknown, rather than denying effort.
pub fn upstream_reasoning_efforts(model: &Value) -> Option<Vec<ReasoningEffort>> {
  if let Some(values) = model.pointer("/capabilities/supports/reasoning_effort") {
    return serde_json::from_value(values.clone()).ok();
  }
  if let Some(values) = model
    .get("supported_reasoning_levels")
    .or_else(|| model.pointer("/x_codex/supported_reasoning_levels"))
  {
    return values
      .as_array()?
      .iter()
      .map(|preset| preset.get("effort")?.as_str().map(ReasoningEffort::from))
      .collect();
  }
  let capability = model.pointer("/capabilities/effort")?.as_object()?;
  if capability.get("supported").and_then(Value::as_bool) == Some(false) {
    return Some(Vec::new());
  }
  let mut efforts = Vec::new();
  let mut known = false;
  for (effort, support) in capability {
    if let Some(supported) = support.get("supported").and_then(Value::as_bool) {
      known = true;
      if supported {
        efforts.push(ReasoningEffort::from(effort.as_str()));
      }
    }
  }
  known.then_some(efforts)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::provider::ModelCache;
  use serde_json::json;

  #[test]
  fn upstream_efforts_distinguish_unknown_disabled_and_supported() {
    for model in [
      json!({}),
      json!({"capabilities": null}),
      json!({"capabilities": {"effort": {"supported": true}}}),
    ] {
      assert_eq!(upstream_reasoning_efforts(&model), None);
    }
    assert_eq!(
      upstream_reasoning_efforts(&json!({"capabilities": {"effort": {"supported": false}}})),
      Some(vec![])
    );
    assert_eq!(
      upstream_reasoning_efforts(&json!({"capabilities": {"effort": {
        "supported": true, "high": {"supported": true}, "max": {"supported": false}, "future": {"supported": true}
      }}})),
      Some(vec![ReasoningEffort::from("future"), ReasoningEffort::High])
    );
  }

  #[test]
  fn refreshing_models_replaces_effort_metadata_with_identity() {
    let cache = ModelCache::default();
    cache.set_models(&[json!({"id": "model", "capabilities": {"effort": {"supported": false}}})]);
    assert!(cache.contains("model"));
    assert_eq!(cache.reasoning_efforts("model"), Some(vec![]));
    cache.set_models(&[json!({"id": "model"})]);
    assert_eq!(cache.reasoning_efforts("model"), None);
    cache.set_models(&[json!({"id": "replacement"})]);
    assert!(!cache.contains("model"));
  }

  #[test]
  fn copilot_and_codex_preserve_future_efforts_and_explicit_empty_lists() {
    for model in [
      json!({"capabilities": {"supports": {"reasoning_effort": ["low", "future"]}}}),
      json!({"supported_reasoning_levels": [{"effort": "low"}, {"effort": "future"}]}),
      json!({"x_codex": {"supported_reasoning_levels": [{"effort": "low"}, {"effort": "future"}]}}),
    ] {
      assert_eq!(
        upstream_reasoning_efforts(&model),
        Some(vec![ReasoningEffort::Low, ReasoningEffort::from("future")])
      );
    }
    assert_eq!(
      upstream_reasoning_efforts(&json!({"supported_reasoning_levels": []})),
      Some(vec![])
    );
    assert_eq!(
      upstream_reasoning_efforts(&json!({"supported_reasoning_levels": [{}]})),
      None
    );
    assert_eq!(
      upstream_reasoning_efforts(&json!({"capabilities": {"supports": {"reasoning_effort": true}}})),
      None
    );
  }
}

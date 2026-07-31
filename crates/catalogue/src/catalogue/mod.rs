//! models.dev catalogue.
//!
//! At build time we embed `https://models.dev/api.json`; at runtime we
//! prefer a disk cache produced by the `update` subcommand. See
//! [`loader::global`] for resolution order. See [`mapping::to_model_info`]
//! for the conversion to our internal [`crate::provider::ModelInfo`].

pub mod loader;
pub mod mapping;
pub mod schema;

use tokn_core::provider::ModelInfo;

/// Build our internal model list for a given models.dev provider id.
///
/// Returns an empty Vec when the provider isn't in the catalogue (e.g. the
/// id changed in models.dev or the embedded snapshot is older than the
/// caller). Providers should treat this as best-effort metadata.
pub fn default_models_for(provider_id: &str) -> Vec<ModelInfo> {
  let cat = loader::global();
  let Some(p) = cat.get(provider_id) else {
    return Vec::new();
  };
  p.models.values().map(mapping::to_model_info).collect()
}

/// Look up one model by `(provider_id, model_id)` and convert. None if either
/// key is absent. Useful when a provider's `list_models` upstream is the
/// source of truth for *identity* and we just want to overlay our metadata.
#[allow(dead_code)]
pub fn model_info_for(provider_id: &str, model_id: &str) -> Option<ModelInfo> {
  loader::global()
    .get(provider_id)?
    .models
    .get(model_id)
    .map(mapping::to_model_info)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn copilot_model_count_is_nontrivial() {
    let v = default_models_for("github-copilot");
    assert!(v.len() >= 5, "got only {} copilot models", v.len());
  }

  #[test]
  fn zai_coding_plan_models_present() {
    let v = default_models_for("zai-coding-plan");
    assert!(!v.is_empty(), "zai-coding-plan should expose models");
    assert!(v.iter().any(|m| m.id.starts_with("glm-")));
  }

  #[test]
  fn unknown_provider_yields_empty() {
    assert!(default_models_for("does-not-exist").is_empty());
  }

  #[test]
  fn lookup_specific_model() {
    // Pick a model id that's stable in models.dev: glm-4.5-air on zai.
    let mi = model_info_for("zai", "glm-4.5-air");
    assert!(mi.is_some(), "expected glm-4.5-air on zai");
  }

  #[test]
  fn deepseek_v4_flash_is_catalogued() {
    let mi = model_info_for("deepseek", "deepseek-v4-flash").expect("deepseek-v4-flash should be catalogued");
    assert_eq!(mi.name, "DeepSeek V4 Flash");
    assert!(mi.capabilities.reasoning);
    assert!(mi.capabilities.toolcall);
  }
}

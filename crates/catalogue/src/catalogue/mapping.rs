//! Pure mapping from [models.dev] records to our internal [`ModelInfo`].
//!
//! [models.dev]: https://models.dev
//!
//! models.dev does not encode every nuance our providers care about — most
//! notably `Interleaved::Field { … }` (a wire-side reasoning channel used by
//! GLM and a few others). The mapping here produces a *baseline* `ModelInfo`;
//! providers can post-process it to layer on their quirks.

use tokn_core::provider::{CacheCost, Capabilities, Cost, Interleaved, Limits, Modalities, ModelInfo};

use super::schema;

/// Translate a single models.dev model into our internal [`ModelInfo`].
///
/// Cost values pass through unchanged: both representations are USD per 1M
/// tokens. Modality string arrays (`["text","image","pdf"]`) become a
/// bitfield. `Interleaved` defaults to `Disabled(false)`; providers override
/// per-model.
pub fn to_model_info(m: &schema::Model) -> ModelInfo {
  ModelInfo {
    id: m.id.clone(),
    name: if m.name.is_empty() {
      m.id.clone()
    } else {
      m.name.clone()
    },
    capabilities: Capabilities {
      temperature: m.temperature,
      reasoning: m.reasoning,
      reasoning_efforts: m.reasoning_efforts(),
      attachment: m.attachment,
      toolcall: m.tool_call,
      input: modalities_from(&m.modalities.input),
      output: modalities_from(&m.modalities.output),
      interleaved: Interleaved::Disabled(false),
    },
    cost: m.cost.as_ref().map(to_cost),
    limit: Limits {
      context: m.limit.context,
      output: m.limit.output,
    },
    release_date: m.release_date.clone(),
  }
}

fn to_cost(c: &schema::Cost) -> Cost {
  let cache = match (c.cache_read, c.cache_write) {
    (None, None) => None,
    (read, write) => Some(CacheCost {
      read: read.unwrap_or(0.0),
      write: write.unwrap_or(0.0),
    }),
  };
  Cost {
    input: c.input,
    output: c.output,
    cache,
  }
}

fn modalities_from(list: &[String]) -> Modalities {
  let has = |k: &str| list.iter().any(|s| s.eq_ignore_ascii_case(k));
  Modalities {
    text: has("text"),
    audio: has("audio"),
    image: has("image"),
    video: has("video"),
    pdf: has("pdf"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn fixture() -> schema::Model {
    schema::Model {
      id: "claude-3-sonnet-20240229".into(),
      name: "Claude Sonnet 3".into(),
      attachment: true,
      reasoning: false,
      reasoning_options: None,
      tool_call: true,
      temperature: true,
      modalities: schema::Modalities {
        input: vec!["text".into(), "image".into(), "pdf".into()],
        output: vec!["text".into()],
      },
      cost: Some(schema::Cost {
        input: 3.0,
        output: 15.0,
        cache_read: Some(0.3),
        cache_write: Some(0.3),
      }),
      limit: schema::Limits {
        context: 200_000,
        output: 4_096,
      },
      release_date: Some("2024-03-04".into()),
    }
  }

  #[test]
  fn maps_basic_fields() {
    let mi = to_model_info(&fixture());
    assert_eq!(mi.id, "claude-3-sonnet-20240229");
    assert_eq!(mi.name, "Claude Sonnet 3");
    assert_eq!(mi.limit.context, 200_000);
    assert_eq!(mi.limit.output, 4_096);
    assert_eq!(mi.release_date.as_deref(), Some("2024-03-04"));
  }

  #[test]
  fn maps_capabilities() {
    let mi = to_model_info(&fixture());
    assert!(mi.capabilities.attachment);
    assert!(mi.capabilities.toolcall);
    assert!(mi.capabilities.temperature);
    assert!(!mi.capabilities.reasoning);
    assert!(mi.capabilities.input.text);
    assert!(mi.capabilities.input.image);
    assert!(mi.capabilities.input.pdf);
    assert!(!mi.capabilities.input.audio);
    assert!(!mi.capabilities.input.video);
    assert!(matches!(mi.capabilities.interleaved, Interleaved::Disabled(false)));
  }

  #[test]
  fn maps_effort_metadata_without_conflating_unknown_and_unsupported() {
    for (options, expected) in [
      (serde_json::Value::Null, serde_json::Value::Null),
      (serde_json::json!([]), serde_json::json!([])),
      (
        serde_json::json!([{"type": "toggle"}, {"type": "budget_tokens", "min": 1024}]),
        serde_json::json!([]),
      ),
      (serde_json::json!([{"type": "future_control"}]), serde_json::Value::Null),
      (
        serde_json::json!([{"type": "effort", "values": ["low", "high", "future"]}]),
        serde_json::json!(["low", "high", "future"]),
      ),
    ] {
      let model: schema::Model = serde_json::from_value(serde_json::json!({
        "id": "model", "reasoning": true, "reasoning_options": options
      }))
      .unwrap();
      assert_eq!(
        serde_json::to_value(to_model_info(&model).capabilities).unwrap()["reasoning_efforts"],
        expected
      );
    }
    let model: schema::Model = serde_json::from_value(serde_json::json!({"id": "old-snapshot"})).unwrap();
    assert!(model.reasoning_efforts().is_none());
  }

  #[test]
  fn maps_cost_with_cache() {
    let mi = to_model_info(&fixture());
    let c = mi.cost.as_ref().unwrap();
    assert_eq!(c.input, 3.0);
    assert_eq!(c.output, 15.0);
    let cache = c.cache.as_ref().unwrap();
    assert_eq!(cache.read, 0.3);
    assert_eq!(cache.write, 0.3);
  }

  #[test]
  fn missing_cost_yields_none() {
    let mut m = fixture();
    m.cost = None;
    let mi = to_model_info(&m);
    assert!(mi.cost.is_none());
  }

  #[test]
  fn empty_name_falls_back_to_id() {
    let mut m = fixture();
    m.name.clear();
    let mi = to_model_info(&m);
    assert_eq!(mi.name, m.id);
  }
}

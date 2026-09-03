//! Strict serde schema mirroring [models.dev]'s public `api.json`.
//!
//! [models.dev]: https://models.dev/api.json
//!
//! The file is a flat object keyed by provider id. Every provider has a
//! `models` map keyed by model id.
//!
//! We intentionally only deserialize fields we actually consume — the upstream
//! schema occasionally widens (e.g. `experimental` is sometimes a `bool` and
//! sometimes a richer object), so a narrow schema is also more robust.
//! `#[serde(deny_unknown_fields)]` is *not* used: unknown fields are tolerated.

use serde::Deserialize;
use std::collections::BTreeMap;
use tokn_core::generation::ReasoningEffort;

/// Top-level: provider id → provider record.
pub type Catalogue = BTreeMap<String, Provider>;

#[derive(Debug, Clone, Deserialize)]
pub struct Provider {
  #[allow(dead_code)]
  pub id: String,
  #[allow(dead_code)]
  pub name: String,
  #[serde(default)]
  pub models: BTreeMap<String, Model>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Model {
  pub id: String,
  #[serde(default)]
  pub name: String,
  #[serde(default)]
  pub attachment: bool,
  #[serde(default)]
  pub reasoning: bool,
  #[serde(default)]
  pub reasoning_options: Option<Vec<ReasoningOption>>,
  #[serde(default)]
  pub tool_call: bool,
  #[serde(default)]
  pub temperature: bool,
  #[serde(default)]
  pub modalities: Modalities,
  #[serde(default)]
  pub cost: Option<Cost>,
  #[serde(default)]
  pub limit: Limits,
  #[serde(default)]
  pub release_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReasoningOption {
  Effort {
    values: Vec<ReasoningEffort>,
  },
  Toggle,
  BudgetTokens,
  #[serde(other)]
  Unknown,
}

impl Model {
  pub fn reasoning_efforts(&self) -> Option<Vec<ReasoningEffort>> {
    let options = self.reasoning_options.as_ref()?;
    let mut efforts = Vec::new();
    for option in options {
      match option {
        ReasoningOption::Effort { values } => {
          for value in values {
            if !efforts.contains(value) {
              efforts.push(value.clone());
            }
          }
        }
        ReasoningOption::Unknown => return None,
        ReasoningOption::Toggle | ReasoningOption::BudgetTokens => {}
      }
    }
    Some(efforts)
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Modalities {
  #[serde(default)]
  pub input: Vec<String>,
  #[serde(default)]
  pub output: Vec<String>,
}

/// USD per **1M** tokens.
#[derive(Debug, Clone, Deserialize)]
pub struct Cost {
  #[serde(default)]
  pub input: f64,
  #[serde(default)]
  pub output: f64,
  #[serde(default)]
  pub cache_read: Option<f64>,
  #[serde(default)]
  pub cache_write: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Limits {
  #[serde(default)]
  pub context: u32,
  #[serde(default)]
  pub output: u32,
}

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Provider-neutral generation controls carried alongside an SDK request.
///
/// These values describe caller intent. The request pipeline lowers them to
/// the selected provider and endpoint only after routing has completed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationOptions {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub max_output_tokens: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub top_k: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub reasoning: Option<ReasoningOptions>,
}

impl GenerationOptions {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn with_top_k(mut self, top_k: u64) -> Self {
    self.top_k = Some(top_k);
    self
  }

  pub fn with_max_output_tokens(mut self, max_output_tokens: u64) -> Self {
    self.max_output_tokens = Some(max_output_tokens);
    self
  }

  pub fn with_reasoning(mut self, reasoning: ReasoningOptions) -> Self {
    self.reasoning = Some(reasoning);
    self
  }

  pub fn is_empty(&self) -> bool {
    self.max_output_tokens.is_none() && self.top_k.is_none() && self.reasoning.is_none()
  }

  pub fn validate(&self) -> Result<(), GenerationOptionsError> {
    if self.max_output_tokens == Some(0) {
      return Err(GenerationOptionsError::InvalidMaxOutputTokens);
    }
    if let Some(reasoning) = &self.reasoning {
      reasoning.validate()?;
    }
    Ok(())
  }
}

/// Provider-neutral reasoning intent.
///
/// No field implies universal provider support. Unsupported combinations are
/// rejected after routing, when the concrete provider and model are known.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasoningOptions {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mode: Option<ReasoningMode>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub effort: Option<ReasoningEffort>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub budget_tokens: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub summary: Option<ReasoningSummary>,
}

impl ReasoningOptions {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn with_mode(mut self, mode: ReasoningMode) -> Self {
    self.mode = Some(mode);
    self
  }

  pub fn with_effort(mut self, effort: impl Into<ReasoningEffort>) -> Self {
    self.effort = Some(effort.into());
    self
  }

  pub fn with_budget_tokens(mut self, budget_tokens: u64) -> Self {
    self.budget_tokens = Some(budget_tokens);
    self
  }

  pub fn with_summary(mut self, summary: impl Into<ReasoningSummary>) -> Self {
    self.summary = Some(summary.into());
    self
  }

  pub fn is_empty(&self) -> bool {
    self.mode.is_none() && self.effort.is_none() && self.budget_tokens.is_none() && self.summary.is_none()
  }

  pub fn validate(&self) -> Result<(), GenerationOptionsError> {
    if self.is_empty() {
      return Err(GenerationOptionsError::EmptyReasoningOptions);
    }
    if self.budget_tokens == Some(0) {
      return Err(GenerationOptionsError::InvalidReasoningBudget);
    }
    if matches!(self.mode, Some(ReasoningMode::Disabled))
      && (self.effort.is_some() || self.budget_tokens.is_some() || self.summary.is_some())
    {
      return Err(GenerationOptionsError::DisabledReasoningControls);
    }
    if matches!(self.mode, Some(ReasoningMode::Adaptive)) && self.budget_tokens.is_some() {
      return Err(GenerationOptionsError::AdaptiveReasoningBudget);
    }
    if matches!(&self.effort, Some(ReasoningEffort::Custom(value)) if value.trim().is_empty()) {
      return Err(GenerationOptionsError::BlankReasoningEffort);
    }
    if matches!(&self.summary, Some(ReasoningSummary::Custom(value)) if value.trim().is_empty()) {
      return Err(GenerationOptionsError::BlankReasoningSummary);
    }
    Ok(())
  }
}

/// Whether and how a provider should enable reasoning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningMode {
  Enabled,
  Disabled,
  Adaptive,
}

/// Qualitative reasoning effort.
///
/// Providers expose different vocabularies. Known cross-provider values have
/// dedicated variants while [`Custom`](Self::Custom) preserves newer or
/// provider-specific values without changing the serialized shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReasoningEffort {
  Minimal,
  Low,
  Medium,
  High,
  XHigh,
  Max,
  Custom(String),
}

impl ReasoningEffort {
  pub fn as_str(&self) -> &str {
    match self {
      Self::Minimal => "minimal",
      Self::Low => "low",
      Self::Medium => "medium",
      Self::High => "high",
      Self::XHigh => "xhigh",
      Self::Max => "max",
      Self::Custom(value) => value,
    }
  }
}

impl From<&str> for ReasoningEffort {
  fn from(value: &str) -> Self {
    match value {
      "minimal" => Self::Minimal,
      "low" => Self::Low,
      "medium" => Self::Medium,
      "high" => Self::High,
      "xhigh" => Self::XHigh,
      "max" => Self::Max,
      custom => Self::Custom(custom.to_string()),
    }
  }
}

impl From<String> for ReasoningEffort {
  fn from(value: String) -> Self {
    match value.as_str() {
      "minimal" => Self::Minimal,
      "low" => Self::Low,
      "medium" => Self::Medium,
      "high" => Self::High,
      "xhigh" => Self::XHigh,
      "max" => Self::Max,
      _ => Self::Custom(value),
    }
  }
}

impl Serialize for ReasoningEffort {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

impl<'de> Deserialize<'de> for ReasoningEffort {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    String::deserialize(deserializer).map(Self::from)
  }
}

/// Requested reasoning-summary style.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReasoningSummary {
  Auto,
  Concise,
  Detailed,
  Custom(String),
}

impl ReasoningSummary {
  pub fn as_str(&self) -> &str {
    match self {
      Self::Auto => "auto",
      Self::Concise => "concise",
      Self::Detailed => "detailed",
      Self::Custom(value) => value,
    }
  }
}

impl From<&str> for ReasoningSummary {
  fn from(value: &str) -> Self {
    match value {
      "auto" => Self::Auto,
      "concise" => Self::Concise,
      "detailed" => Self::Detailed,
      custom => Self::Custom(custom.to_string()),
    }
  }
}

impl From<String> for ReasoningSummary {
  fn from(value: String) -> Self {
    match value.as_str() {
      "auto" => Self::Auto,
      "concise" => Self::Concise,
      "detailed" => Self::Detailed,
      _ => Self::Custom(value),
    }
  }
}

impl Serialize for ReasoningSummary {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

impl<'de> Deserialize<'de> for ReasoningSummary {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    String::deserialize(deserializer).map(Self::from)
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenerationOptionsError {
  InvalidMaxOutputTokens,
  EmptyReasoningOptions,
  InvalidReasoningBudget,
  DisabledReasoningControls,
  AdaptiveReasoningBudget,
  BlankReasoningEffort,
  BlankReasoningSummary,
}

impl fmt::Display for GenerationOptionsError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let message = match self {
      Self::InvalidMaxOutputTokens => "max_output_tokens must be greater than zero",
      Self::EmptyReasoningOptions => "reasoning options cannot be empty",
      Self::InvalidReasoningBudget => "reasoning budget_tokens must be greater than zero",
      Self::DisabledReasoningControls => "disabled reasoning cannot also specify effort, budget_tokens, or summary",
      Self::AdaptiveReasoningBudget => "adaptive reasoning cannot specify budget_tokens",
      Self::BlankReasoningEffort => "custom reasoning effort cannot be empty",
      Self::BlankReasoningSummary => "custom reasoning summary cannot be empty",
    };
    formatter.write_str(message)
  }
}

impl std::error::Error for GenerationOptionsError {}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn generation_options_round_trip_with_string_enums() {
    let options = GenerationOptions::new()
      .with_max_output_tokens(8192)
      .with_top_k(40)
      .with_reasoning(
        ReasoningOptions::new()
          .with_mode(ReasoningMode::Enabled)
          .with_effort(ReasoningEffort::XHigh)
          .with_budget_tokens(4096)
          .with_summary(ReasoningSummary::Auto),
      );

    let value = serde_json::to_value(&options).expect("serialize generation options");
    assert_eq!(
      value,
      json!({
        "max_output_tokens": 8192,
        "top_k": 40,
        "reasoning": {
          "mode": "enabled",
          "effort": "xhigh",
          "budget_tokens": 4096,
          "summary": "auto"
        }
      })
    );
    assert_eq!(
      serde_json::from_value::<GenerationOptions>(value).expect("deserialize generation options"),
      options
    );
  }

  #[test]
  fn custom_values_serialize_as_plain_strings() {
    let reasoning = ReasoningOptions::new()
      .with_effort("provider_effort")
      .with_summary("provider_summary");

    assert_eq!(
      serde_json::to_value(reasoning).expect("serialize custom reasoning controls"),
      json!({"effort": "provider_effort", "summary": "provider_summary"})
    );
  }

  #[test]
  fn reasoning_validation_rejects_contradictory_or_empty_controls() {
    assert_eq!(
      ReasoningOptions::new().validate(),
      Err(GenerationOptionsError::EmptyReasoningOptions)
    );
    assert_eq!(
      ReasoningOptions::new()
        .with_mode(ReasoningMode::Disabled)
        .with_effort(ReasoningEffort::High)
        .validate(),
      Err(GenerationOptionsError::DisabledReasoningControls)
    );
    assert_eq!(
      ReasoningOptions::new()
        .with_mode(ReasoningMode::Adaptive)
        .with_budget_tokens(1024)
        .validate(),
      Err(GenerationOptionsError::AdaptiveReasoningBudget)
    );
    assert_eq!(
      ReasoningOptions::new().with_budget_tokens(0).validate(),
      Err(GenerationOptionsError::InvalidReasoningBudget)
    );
  }

  #[test]
  fn generation_validation_allows_zero_top_k_and_rejects_blank_custom_values() {
    assert_eq!(GenerationOptions::new().with_top_k(0).validate(), Ok(()));
    assert_eq!(
      ReasoningOptions::new().with_effort(" ").validate(),
      Err(GenerationOptionsError::BlankReasoningEffort)
    );
    assert_eq!(
      ReasoningOptions::new().with_summary("").validate(),
      Err(GenerationOptionsError::BlankReasoningSummary)
    );
  }
}

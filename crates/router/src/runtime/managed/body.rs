//! Transport-independent managed request-body semantics.
//!
//! HTTP ingress is responsible for bounded content decoding and JSON parsing.
//! This module validates the resulting JSON value so listener-backed and
//! embedded managed execution share one authoritative model invariant.

use serde_json::Value;
use smol_str::SmolStr;
use snafu::Snafu;

/// An owned managed request body with its validated inbound model.
#[derive(Clone, Debug)]
pub struct ManagedRequestBody {
  value: Value,
  requested_model: SmolStr,
}

impl ManagedRequestBody {
  pub fn value(&self) -> &Value {
    &self.value
  }

  pub fn requested_model(&self) -> &str {
    self.requested_model.as_str()
  }

  pub fn into_parts(self) -> (Value, SmolStr) {
    (self.value, self.requested_model)
  }
}

impl TryFrom<Value> for ManagedRequestBody {
  type Error = ManagedRequestBodyError;

  fn try_from(value: Value) -> Result<Self, Self::Error> {
    let object = value.as_object().ok_or(ManagedRequestBodyError::ObjectRequired)?;
    let model = object
      .get("model")
      .and_then(Value::as_str)
      .ok_or(ManagedRequestBodyError::ModelStringRequired)?;
    let trimmed_model = model.trim();
    if trimmed_model.is_empty() {
      return Err(ManagedRequestBodyError::ModelEmpty);
    }
    if trimmed_model != model {
      return Err(ManagedRequestBodyError::ModelSurroundingWhitespace);
    }

    Ok(Self {
      requested_model: SmolStr::new(model),
      value,
    })
  }
}

/// Invalid transport-independent semantics in a managed request body.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagedRequestBodyError {
  #[snafu(display("managed request body must be a JSON object"))]
  ObjectRequired,

  #[snafu(display("managed request body field 'model' must be a string"))]
  ModelStringRequired,

  #[snafu(display("managed request body field 'model' must not be empty"))]
  ModelEmpty,

  #[snafu(display("managed request body field 'model' must not have surrounding whitespace"))]
  ModelSurroundingWhitespace,
}

pub type ManagedRequestBodyResult<T> = std::result::Result<T, ManagedRequestBodyError>;

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn preserves_valid_body_and_requested_model() {
    let value = json!({"model": "inbound-model", "input": "hello"});
    let body = ManagedRequestBody::try_from(value.clone()).unwrap();

    assert_eq!(body.value(), &value);
    assert_eq!(body.requested_model(), "inbound-model");
    let (actual_value, requested_model) = body.into_parts();
    assert_eq!(actual_value, value);
    assert_eq!(requested_model, "inbound-model");
  }

  #[test]
  fn rejects_invalid_object_and_model_shapes() {
    type ErrorPredicate = fn(&ManagedRequestBodyError) -> bool;

    let cases: Vec<(Value, ErrorPredicate)> = vec![
      (json!([]), |error| {
        matches!(error, ManagedRequestBodyError::ObjectRequired)
      }),
      (json!({}), |error| {
        matches!(error, ManagedRequestBodyError::ModelStringRequired)
      }),
      (json!({"model": null}), |error| {
        matches!(error, ManagedRequestBodyError::ModelStringRequired)
      }),
      (json!({"model": 42}), |error| {
        matches!(error, ManagedRequestBodyError::ModelStringRequired)
      }),
      (json!({"model": ""}), |error| {
        matches!(error, ManagedRequestBodyError::ModelEmpty)
      }),
      (json!({"model": "   "}), |error| {
        matches!(error, ManagedRequestBodyError::ModelEmpty)
      }),
      (json!({"model": " model"}), |error| {
        matches!(error, ManagedRequestBodyError::ModelSurroundingWhitespace)
      }),
      (json!({"model": "model "}), |error| {
        matches!(error, ManagedRequestBodyError::ModelSurroundingWhitespace)
      }),
    ];

    for (value, expected) in cases {
      let error = ManagedRequestBody::try_from(value.clone()).unwrap_err();
      assert!(expected(&error), "unexpected error for {value}: {error}");
    }
  }
}

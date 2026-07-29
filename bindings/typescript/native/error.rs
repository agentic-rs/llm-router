use napi::{Error as NapiError, Status};
use serde::Serialize;
use std::error::Error as StdError;
use tokn_sdk::Error as SdkError;

const ERROR_PREFIX: &str = "TOKN_ERROR:";

pub(crate) const CANCELLED: &str = "cancelled";
pub(crate) const CLIENT_CLOSED: &str = "client_closed";
pub(crate) const INTERNAL_ERROR: &str = "internal_error";
pub(crate) const REQUEST_ERROR: &str = "request_error";
pub(crate) const SERIALIZATION_ERROR: &str = "serialization_error";
pub(crate) const STREAM_ERROR: &str = "stream_error";

#[derive(Serialize)]
struct ErrorPayload {
  code: &'static str,
  message: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  status: Option<u16>,
  #[serde(skip_serializing_if = "Option::is_none")]
  body: Option<String>,
}

pub(crate) fn native_error(code: &'static str, message: impl Into<String>) -> NapiError {
  structured_error(code, message.into(), None, None)
}

pub(crate) fn api_status_error(message: String, status: u16, body: String) -> NapiError {
  structured_error("api_status_error", message, Some(status), Some(body))
}

pub(crate) fn sdk_error(error: SdkError) -> NapiError {
  let message = error_chain(&error);
  match error {
    SdkError::LoadConfig { .. } | SdkError::BuildEngine { .. } | SdkError::UnknownProfile { .. } => {
      native_error("configuration_error", message)
    }
    SdkError::LoadCredentials { .. } => native_error("authentication_error", message),
    SdkError::InvalidGenerateRequest { .. }
    | SdkError::BuildGenerateRequest { .. }
    | SdkError::Pipeline { .. }
    | SdkError::UnexpectedStream
    | SdkError::UnexpectedBuffered => native_error(REQUEST_ERROR, message),
    SdkError::GenerateResponseStatus { status, body } => api_status_error(message, status, body),
    SdkError::GenerateStream { .. } | SdkError::DeserializeStreamEvent { .. } => native_error(STREAM_ERROR, message),
    SdkError::SerializeRequest { .. } | SdkError::DeserializeResponse { .. } => {
      native_error(SERIALIZATION_ERROR, message)
    }
  }
}

pub(crate) fn error_chain(error: &dyn StdError) -> String {
  let mut message = error.to_string();
  let mut source = error.source();
  while let Some(error) = source {
    message.push_str(": ");
    message.push_str(&error.to_string());
    source = error.source();
  }
  message
}

fn structured_error(code: &'static str, message: String, status: Option<u16>, body: Option<String>) -> NapiError {
  let payload = ErrorPayload {
    code,
    message,
    status,
    body,
  };
  let encoded = serde_json::to_string(&payload).unwrap_or_else(|error| {
    format!(
      r#"{{"code":"internal_error","message":"failed to serialize native error: {}"}}"#,
      escape_json_string(&error.to_string())
    )
  });
  NapiError::new(Status::GenericFailure, format!("{ERROR_PREFIX}{encoded}"))
}

fn escape_json_string(value: &str) -> String {
  value
    .chars()
    .flat_map(|character| match character {
      '"' => "\\\"".chars().collect::<Vec<_>>(),
      '\\' => "\\\\".chars().collect(),
      '\n' => "\\n".chars().collect(),
      '\r' => "\\r".chars().collect(),
      '\t' => "\\t".chars().collect(),
      character if character.is_control() => '\u{fffd}'.to_string().chars().collect(),
      character => vec![character],
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn structured_errors_have_a_machine_readable_prefix() {
    let error = native_error(REQUEST_ERROR, "bad request");
    assert!(error.reason.starts_with(ERROR_PREFIX));
    let payload: serde_json::Value = serde_json::from_str(&error.reason[ERROR_PREFIX.len()..]).expect("valid JSON");
    assert_eq!(payload["code"], REQUEST_ERROR);
    assert_eq!(payload["message"], "bad request");
  }
}

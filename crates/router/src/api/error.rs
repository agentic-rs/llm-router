//! HTTP error responses.
//!
//! All errors a handler returns funnel through [`Error`] and serialise to the
//! OpenAI-shape envelope `{ error: { message, type, code, request_id? } }`.
//! Variants carry the precise upstream status when one is known so retries and
//! per-status billing logic in clients keep working.
//!
//! `request_id` in the body envelope is intentionally always `null`: the
//! authoritative request id is the `x-request-id` response header set by
//! the router's response propagation middleware. The body field exists for
//! convenience only — populating it would require routing the id through
//! every handler. Clients should prefer the header.
//!
//! `From<anyhow::Error>` is deliberately NOT implemented: every callsite that
//! produces an error must classify it as one of the variants below, so we
//! never accidentally surface internal source-chains (which may include
//! credentials interpolated into upstream-error bodies) to clients.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde_json::json;
use snafu::Snafu;

/// Backwards-compat alias so handler signatures `Result<_, ApiError>` keep
/// compiling while the rest of the codebase migrates.
pub type ApiError = Error;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
  /// No valid client API key was supplied. Maps to 401.
  #[snafu(display("{message}"))]
  Unauthorized { message: String },

  /// The authenticated API key cannot use the resolved provider. Maps to 403.
  #[snafu(display("{message}"))]
  Forbidden { message: String },

  /// Request was malformed (JSON missing required fields, etc.). Maps to 400.
  #[snafu(display("{message}"))]
  BadRequest { message: String },

  /// The requested API path or generation endpoint is not exposed. Maps to 404.
  #[snafu(display("{message}"))]
  NotFound { message: String },

  /// Request body exceeded the listener's configured maximum. Maps to 413.
  #[snafu(display("{message}"))]
  PayloadTooLarge { message: String },

  /// Request body used an unsupported transport/content encoding. Maps to 415.
  #[snafu(display("{message}"))]
  UnsupportedMediaType { message: String },

  /// Upstream returned a non-2xx the dispatcher chose to surface verbatim.
  /// `body` is the upstream-supplied error message; `status` is its HTTP
  /// status. Maps to whatever `status` is so clients can branch on it.
  #[snafu(display("upstream returned {status}: {body}"))]
  Upstream { status: StatusCode, body: String },

  /// No configured account advertises support for the requested
  /// `(model, endpoint)`. Not retryable. Maps to 501.
  #[snafu(display("no configured account supports endpoint '{endpoint}' for model '{model}'"))]
  NotImplemented { endpoint: String, model: String },

  /// A supplied `x-session-id` was known but its in-memory binding expired.
  /// Maps to 410 so clients replay with a fresh session id.
  #[snafu(display("session expired"))]
  SessionExpired { session_id: String },

  /// Transport failure, body-read failure, or "all attempts failed" summary
  /// from the dispatcher. Maps to 502.
  #[snafu(display("{message}"))]
  BadGateway { message: String },

  /// Catch-all for unexpected internal failures. Maps to 500.
  /// Avoid in handler code — prefer a more specific variant.
  #[snafu(display("internal error: {message}"))]
  Internal { message: String },
}

impl Error {
  pub fn unauthorized(msg: impl Into<String>) -> Self {
    Error::Unauthorized { message: msg.into() }
  }
  pub fn forbidden(msg: impl Into<String>) -> Self {
    Error::Forbidden { message: msg.into() }
  }
  pub fn not_found(msg: impl Into<String>) -> Self {
    Error::NotFound { message: msg.into() }
  }
  pub fn upstream(status: StatusCode, body: impl Into<String>) -> Self {
    Error::Upstream {
      status,
      body: body.into(),
    }
  }
  #[allow(dead_code)]
  pub fn internal(msg: impl Into<String>) -> Self {
    Error::Internal { message: msg.into() }
  }
  #[allow(dead_code)]
  pub fn bad_request(msg: impl Into<String>) -> Self {
    Error::BadRequest { message: msg.into() }
  }
  pub fn payload_too_large(msg: impl Into<String>) -> Self {
    Error::PayloadTooLarge { message: msg.into() }
  }
  pub fn bad_gateway(msg: impl Into<String>) -> Self {
    Error::BadGateway { message: msg.into() }
  }
  pub fn unsupported_media_type(msg: impl Into<String>) -> Self {
    Error::UnsupportedMediaType { message: msg.into() }
  }
  pub fn not_implemented(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
    Error::NotImplemented {
      endpoint: endpoint.into(),
      model: model.into(),
    }
  }
  pub fn session_expired(session_id: impl Into<String>) -> Self {
    Error::SessionExpired {
      session_id: session_id.into(),
    }
  }

  pub(crate) fn body_bytes(&self) -> Bytes {
    Bytes::from(
      serde_json::to_vec(&json!({
          "error": {
              "message": self.message(),
              "type": self.kind(),
              "code": self.status().as_u16(),
              // Body field reserved for compatibility; the authoritative
              // request id is in the `x-request-id` response header.
              "request_id": serde_json::Value::Null,
          }
      }))
      .unwrap_or_default(),
    )
  }

  pub(crate) fn status(&self) -> StatusCode {
    match self {
      Error::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
      Error::Forbidden { .. } => StatusCode::FORBIDDEN,
      Error::BadRequest { .. } => StatusCode::BAD_REQUEST,
      Error::NotFound { .. } => StatusCode::NOT_FOUND,
      Error::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
      Error::UnsupportedMediaType { .. } => StatusCode::UNSUPPORTED_MEDIA_TYPE,
      Error::Upstream { status, .. } => *status,
      Error::NotImplemented { .. } => StatusCode::NOT_IMPLEMENTED,
      Error::SessionExpired { .. } => StatusCode::GONE,
      Error::BadGateway { .. } => StatusCode::BAD_GATEWAY,
      Error::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }

  fn kind(&self) -> &'static str {
    match self {
      Error::Unauthorized { .. } => "authentication_error",
      Error::Forbidden { .. } => "permission_error",
      Error::BadRequest { .. } => "bad_request",
      Error::NotFound { .. } => "not_found",
      Error::PayloadTooLarge { .. } => "payload_too_large",
      Error::UnsupportedMediaType { .. } => "unsupported_media_type",
      Error::Upstream { .. } => "upstream_error",
      Error::NotImplemented { .. } => "not_implemented_error",
      Error::SessionExpired { .. } => "session_expired",
      Error::BadGateway { .. } => "bad_gateway",
      Error::Internal { .. } => "internal_error",
    }
  }

  fn message(&self) -> String {
    match self {
      Error::Unauthorized { message } | Error::Forbidden { message } => message.clone(),
      Error::BadRequest { message } => message.clone(),
      Error::NotFound { message } => message.clone(),
      Error::PayloadTooLarge { message } => message.clone(),
      Error::UnsupportedMediaType { message } => message.clone(),
      Error::Upstream { status, body } => {
        if body.trim().is_empty() {
          fallback_upstream_message(*status)
        } else {
          body.clone()
        }
      }
      Error::NotImplemented { endpoint, model } => {
        format!("no configured account supports endpoint '{endpoint}' for model '{model}'")
      }
      Error::SessionExpired { .. } => "session expired".into(),
      Error::BadGateway { message } => message.clone(),
      Error::Internal { message } => message.clone(),
    }
  }
}

impl IntoResponse for Error {
  fn into_response(self) -> Response {
    let status = self.status();
    let body = Json(
      serde_json::from_slice::<serde_json::Value>(&self.body_bytes()).unwrap_or_else(|_| {
        json!({
          "error": {
            "message": "internal error",
            "type": "internal_error",
            "code": status.as_u16(),
            "request_id": serde_json::Value::Null,
          }
        })
      }),
    );
    (status, body).into_response()
  }
}

pub(crate) fn fallback_upstream_message(status: StatusCode) -> String {
  format!("upstream returned {} with an empty response body", status.as_u16())
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::response::IntoResponse;

  #[test]
  fn status_mapping() {
    assert_eq!(Error::unauthorized("x").status(), StatusCode::UNAUTHORIZED);
    assert_eq!(Error::forbidden("x").status(), StatusCode::FORBIDDEN);
    assert_eq!(Error::bad_request("x").status(), StatusCode::BAD_REQUEST);
    assert_eq!(Error::payload_too_large("x").status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
      Error::unsupported_media_type("x").status(),
      StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
      Error::upstream(StatusCode::TOO_MANY_REQUESTS, "x").status(),
      StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(Error::not_implemented("e", "m").status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(Error::session_expired("s").status(), StatusCode::GONE);
    assert_eq!(Error::bad_gateway("x").status(), StatusCode::BAD_GATEWAY);
    assert_eq!(Error::internal("x").status(), StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[test]
  fn kind_names_are_stable() {
    assert_eq!(Error::unauthorized("x").kind(), "authentication_error");
    assert_eq!(Error::forbidden("x").kind(), "permission_error");
    assert_eq!(Error::bad_request("x").kind(), "bad_request");
    assert_eq!(Error::payload_too_large("x").kind(), "payload_too_large");
    assert_eq!(Error::unsupported_media_type("x").kind(), "unsupported_media_type");
    assert_eq!(Error::upstream(StatusCode::BAD_GATEWAY, "x").kind(), "upstream_error");
    assert_eq!(Error::not_implemented("e", "m").kind(), "not_implemented_error");
    assert_eq!(Error::session_expired("s").kind(), "session_expired");
    assert_eq!(Error::bad_gateway("x").kind(), "bad_gateway");
    assert_eq!(Error::internal("x").kind(), "internal_error");
  }

  #[tokio::test]
  async fn blank_upstream_body_gets_fallback_message() {
    let resp = Error::upstream(StatusCode::NOT_IMPLEMENTED, "").into_response();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], 501);
    assert_eq!(json["error"]["type"], "upstream_error");
    assert_eq!(
      json["error"]["message"],
      serde_json::Value::String("upstream returned 501 with an empty response body".into())
    );
  }
}

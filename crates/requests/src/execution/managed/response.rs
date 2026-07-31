//! Client-facing response contracts for one managed attempt.
//!
//! Settlement belongs to the caller and happens from the final upstream head
//! before this adapter is invoked. Body read, JSON conversion, SSE
//! accumulation, and live SSE translation therefore cannot revise account
//! health after downstream polling begins.

use bytes::Bytes;
use futures_util::stream::BoxStream;
use http::{HeaderMap, StatusCode};
use snafu::Snafu;
use tokn_convert::error::ConvertError;
use tokn_core::provider::Endpoint;

/// Client-facing body after managed response adaptation.
pub enum ManagedClientBody {
  Buffered(Bytes),
  Stream(BoxStream<'static, std::io::Result<Bytes>>),
}

impl std::fmt::Debug for ManagedClientBody {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Buffered(body) => formatter
        .debug_tuple("Buffered")
        .field(&format_args!("{} bytes", body.len()))
        .finish(),
      Self::Stream(_) => formatter.debug_tuple("Stream").field(&"<live SSE>").finish(),
    }
  }
}

/// Adapted managed response ready for the HTTP serving layer.
#[derive(Debug)]
pub struct ManagedClientResponse {
  status: StatusCode,
  headers: HeaderMap,
  body: ManagedClientBody,
}

impl ManagedClientResponse {
  pub fn status(&self) -> StatusCode {
    self.status
  }

  pub fn headers(&self) -> &HeaderMap {
    &self.headers
  }

  pub fn body(&self) -> &ManagedClientBody {
    &self.body
  }

  pub fn into_parts(self) -> (StatusCode, HeaderMap, ManagedClientBody) {
    (self.status, self.headers, self.body)
  }
}

/// Failure while adapting a response body after its head was received.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagedResponseError {
  #[snafu(display("could not read managed upstream response with status {status}: {source}"))]
  ResponseRead { status: StatusCode, source: reqwest::Error },

  #[snafu(display("managed upstream response with status {status} is not valid JSON: {source}"))]
  ResponseJson {
    status: StatusCode,
    source: serde_json::Error,
  },

  #[snafu(display("could not convert managed response from {from} to {to} with status {status}: {source}"))]
  ResponseConversion {
    status: StatusCode,
    from: Endpoint,
    to: Endpoint,
    source: ConvertError,
  },

  #[snafu(display("could not serialize managed response with status {status}: {source}"))]
  ResponseSerialization {
    status: StatusCode,
    source: serde_json::Error,
  },

  #[snafu(display("could not accumulate managed SSE response with status {status}: {source}"))]
  SseAccumulation { status: StatusCode, source: ConvertError },

  #[snafu(display(
    "managed upstream returned a successful non-SSE response for a streaming {upstream_operation} request{}",
    content_type
      .as_deref()
      .map(|value| format!(" (content-type: {value})"))
      .unwrap_or_default()
  ))]
  StreamingProtocolMismatch {
    upstream_operation: Endpoint,
    content_type: Option<String>,
  },
}

/// Stateless managed response adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct ManagedResponseAdapter;

impl ManagedResponseAdapter {
  pub fn new() -> Self {
    Self
  }
}

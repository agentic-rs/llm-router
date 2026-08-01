//! Client-facing response contracts for one managed attempt.
//!
//! Settlement belongs to the caller and happens from the final upstream head
//! before this adapter is invoked. Body read, JSON conversion, SSE
//! accumulation, and live SSE translation therefore cannot revise account
//! health after downstream polling begins.

use super::ManagedHttpResponse;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, StatusCode};
use serde_json::Value;
use snafu::Snafu;
use tokn_convert::error::ConvertError;
use tokn_convert::ir::IrResponse;
use tokn_convert::sse::{EndpointTranslator, SsePipeline};
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

  /// Replace the client-facing body while preserving the adapted response
  /// status and headers.
  pub fn map_body(self, map: impl FnOnce(ManagedClientBody) -> ManagedClientBody) -> Self {
    Self {
      status: self.status,
      headers: self.headers,
      body: map(self.body),
    }
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

  /// Adapt a received final response after the caller has settled the exact
  /// account selection from its status. Actual response content type is
  /// authoritative; the transformed upstream stream flag is used only when
  /// the upstream omitted `Content-Type`.
  pub async fn adapt(&self, upstream: ManagedHttpResponse) -> Result<ManagedClientResponse, ManagedResponseError> {
    let (response, metadata) = upstream.into_parts();
    let status = response.status();
    let mut headers = response.headers().clone();

    if !status.is_success() {
      let body = read_body(response, status).await?;
      return Ok(ManagedClientResponse {
        status,
        headers,
        body: ManagedClientBody::Buffered(body),
      });
    }

    let response_kind = ResponseKind::from_headers(&headers, metadata.upstream_stream());
    match (metadata.requested_stream(), response_kind) {
      (false, ResponseKind::Json) => {
        let body = read_body(response, status).await?;
        let body = convert_buffered_json(
          status,
          body,
          metadata.upstream_operation(),
          metadata.requested_operation(),
        )?;
        if metadata.upstream_operation() != metadata.requested_operation() {
          set_buffered_json_headers(&mut headers);
        }
        Ok(ManagedClientResponse {
          status,
          headers,
          body: ManagedClientBody::Buffered(body),
        })
      }
      (false, ResponseKind::Sse) => {
        let response = tokn_convert::sse::accumulate(metadata.upstream_operation(), response)
          .await
          .map_err(|source| ManagedResponseError::SseAccumulation { status, source })?;
        let body = render_accumulated(
          status,
          response,
          metadata.upstream_operation(),
          metadata.requested_operation(),
        )?;
        set_buffered_json_headers(&mut headers);
        Ok(ManagedClientResponse {
          status,
          headers,
          body: ManagedClientBody::Buffered(body),
        })
      }
      (true, ResponseKind::Sse) => {
        let mut pipeline = SsePipeline::from_response(response);
        if metadata.upstream_operation() != metadata.requested_operation() {
          pipeline = pipeline.with_transformer(EndpointTranslator::new(
            metadata.upstream_operation(),
            metadata.requested_operation(),
          ));
        }
        set_stream_headers(&mut headers);
        Ok(ManagedClientResponse {
          status,
          headers,
          body: ManagedClientBody::Stream(pipeline.run()),
        })
      }
      (true, ResponseKind::Json) => Err(ManagedResponseError::StreamingProtocolMismatch {
        upstream_operation: metadata.upstream_operation(),
        content_type: content_type(&headers),
      }),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseKind {
  Json,
  Sse,
}

impl ResponseKind {
  fn from_headers(headers: &HeaderMap, upstream_stream: bool) -> Self {
    match content_type(headers) {
      Some(value) if media_type(&value).eq_ignore_ascii_case("text/event-stream") => Self::Sse,
      Some(_) => Self::Json,
      None if upstream_stream => Self::Sse,
      None => Self::Json,
    }
  }
}

async fn read_body(response: reqwest::Response, status: StatusCode) -> Result<Bytes, ManagedResponseError> {
  response
    .bytes()
    .await
    .map_err(|source| ManagedResponseError::ResponseRead { status, source })
}

fn convert_buffered_json(
  status: StatusCode,
  body: Bytes,
  upstream_operation: Endpoint,
  requested_operation: Endpoint,
) -> Result<Bytes, ManagedResponseError> {
  if body.is_empty() {
    return Ok(body);
  }
  let value: Value =
    serde_json::from_slice(&body).map_err(|source| ManagedResponseError::ResponseJson { status, source })?;
  if upstream_operation == requested_operation {
    return Ok(body);
  }
  let converted =
    tokn_convert::convert_response(upstream_operation, requested_operation, &value).map_err(|source| {
      ManagedResponseError::ResponseConversion {
        status,
        from: upstream_operation,
        to: requested_operation,
        source,
      }
    })?;
  serialize_response(status, &converted)
}

fn render_accumulated(
  status: StatusCode,
  response: IrResponse,
  upstream_operation: Endpoint,
  requested_operation: Endpoint,
) -> Result<Bytes, ManagedResponseError> {
  let converted = match requested_operation {
    Endpoint::ChatCompletions => tokn_convert::value::chat::response_to_value(&response),
    Endpoint::Responses => tokn_convert::value::responses::response_to_value(&response),
    Endpoint::Messages => tokn_convert::value::messages::response_to_value(&response),
  }
  .map_err(|source| ManagedResponseError::ResponseConversion {
    status,
    from: upstream_operation,
    to: requested_operation,
    source,
  })?;
  serialize_response(status, &converted)
}

fn serialize_response(status: StatusCode, value: &Value) -> Result<Bytes, ManagedResponseError> {
  serde_json::to_vec(value)
    .map(Bytes::from)
    .map_err(|source| ManagedResponseError::ResponseSerialization { status, source })
}

fn set_buffered_json_headers(headers: &mut HeaderMap) {
  headers.remove(CONTENT_LENGTH);
  headers.remove(CONTENT_ENCODING);
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
}

fn set_stream_headers(headers: &mut HeaderMap) {
  headers.remove(CONTENT_LENGTH);
  headers.remove(CONTENT_ENCODING);
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
}

fn content_type(headers: &HeaderMap) -> Option<String> {
  headers
    .get(CONTENT_TYPE)
    .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn media_type(content_type: &str) -> &str {
  content_type.split(';').next().unwrap_or_default().trim()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::execution::ManagedResponseMetadata;
  use futures_util::{stream, StreamExt};

  fn upstream(
    status: StatusCode,
    content_type: Option<&'static str>,
    body: &'static str,
    metadata: ManagedResponseMetadata,
  ) -> ManagedHttpResponse {
    let mut response = http::Response::builder().status(status);
    if let Some(content_type) = content_type {
      response = response.header(CONTENT_TYPE, content_type);
    }
    response = response.header(CONTENT_LENGTH, body.len());
    ManagedHttpResponse {
      response: reqwest::Response::from(response.body(body).unwrap()),
      metadata,
    }
  }

  fn metadata(
    requested_operation: Endpoint,
    upstream_operation: Endpoint,
    requested_stream: bool,
    upstream_stream: bool,
  ) -> ManagedResponseMetadata {
    ManagedResponseMetadata::new(
      requested_operation,
      upstream_operation,
      requested_stream,
      upstream_stream,
    )
  }

  fn buffered(response: ManagedClientResponse) -> (StatusCode, HeaderMap, Bytes) {
    let (status, headers, body) = response.into_parts();
    let ManagedClientBody::Buffered(body) = body else {
      panic!("expected buffered body")
    };
    (status, headers, body)
  }

  #[tokio::test]
  async fn non_success_response_is_buffered_without_conversion() {
    let body = r#"{"error":{"message":"slow down"}}"#;
    let response = upstream(
      StatusCode::TOO_MANY_REQUESTS,
      Some("application/json"),
      body,
      metadata(Endpoint::Responses, Endpoint::ChatCompletions, true, true),
    );

    let (status, headers, actual) = buffered(ManagedResponseAdapter::new().adapt(response).await.unwrap());

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(actual.as_ref(), body.as_bytes());
    assert_eq!(headers[CONTENT_TYPE], "application/json");
    assert_eq!(headers[CONTENT_LENGTH], body.len().to_string());
  }

  #[tokio::test]
  async fn same_operation_json_preserves_exact_response_bytes() {
    let body = "{ \"id\" : \"chat-1\", \"choices\" : [] }";
    let response = upstream(
      StatusCode::OK,
      Some("application/json; charset=utf-8"),
      body,
      metadata(Endpoint::ChatCompletions, Endpoint::ChatCompletions, false, false),
    );

    let (_, headers, actual) = buffered(ManagedResponseAdapter::new().adapt(response).await.unwrap());

    assert_eq!(actual.as_ref(), body.as_bytes());
    assert_eq!(headers[CONTENT_LENGTH], body.len().to_string());
    assert_eq!(headers[CONTENT_TYPE], "application/json; charset=utf-8");
  }

  #[tokio::test]
  async fn cross_operation_json_is_converted_and_reframed() {
    let body = r#"{
      "id":"chatcmpl-1",
      "object":"chat.completion",
      "model":"upstream-model",
      "choices":[{
        "index":0,
        "message":{"role":"assistant","content":"hello"},
        "finish_reason":"stop"
      }]
    }"#;
    let response = upstream(
      StatusCode::OK,
      Some("application/json"),
      body,
      metadata(Endpoint::Responses, Endpoint::ChatCompletions, false, false),
    );

    let (_, headers, actual) = buffered(ManagedResponseAdapter::new().adapt(response).await.unwrap());
    let actual: Value = serde_json::from_slice(&actual).unwrap();

    assert_eq!(actual["object"], "response");
    assert_eq!(actual["output_text"], "hello");
    assert!(!headers.contains_key(CONTENT_LENGTH));
    assert_eq!(headers[CONTENT_TYPE], "application/json");
  }

  #[tokio::test]
  async fn buffered_client_accumulates_actual_sse_even_when_it_did_not_request_streaming() {
    let body = concat!(
      "data: {\"id\":\"chatcmpl-1\",\"model\":\"upstream-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
      "data: {\"id\":\"chatcmpl-1\",\"model\":\"upstream-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
      "data: [DONE]\n\n"
    );
    let response = upstream(
      StatusCode::OK,
      Some("Text/Event-Stream; charset=utf-8"),
      body,
      metadata(Endpoint::Responses, Endpoint::ChatCompletions, false, true),
    );

    let (_, headers, actual) = buffered(ManagedResponseAdapter::new().adapt(response).await.unwrap());
    let actual: Value = serde_json::from_slice(&actual).unwrap();

    assert_eq!(actual["object"], "response");
    assert_eq!(actual["output_text"], "hello");
    assert!(!headers.contains_key(CONTENT_LENGTH));
    assert_eq!(headers[CONTENT_TYPE], "application/json");
  }

  #[tokio::test]
  async fn explicit_json_is_a_protocol_error_for_a_streaming_client() {
    let response = upstream(
      StatusCode::OK,
      Some("application/json"),
      r#"{"id":"response-1"}"#,
      metadata(Endpoint::Responses, Endpoint::Responses, true, true),
    );

    let error = ManagedResponseAdapter::new().adapt(response).await.err().unwrap();

    assert!(matches!(
      error,
      ManagedResponseError::StreamingProtocolMismatch {
        upstream_operation: Endpoint::Responses,
        ..
      }
    ));
  }

  #[tokio::test]
  async fn translated_stream_delivers_before_upstream_eof() {
    let first_event = Bytes::from_static(
      b"data: {\"id\":\"chatcmpl-live\",\"model\":\"upstream-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
    );
    let source =
      stream::iter([Ok::<_, std::io::Error>(first_event)]).chain(stream::pending::<std::io::Result<Bytes>>());
    let response = http::Response::builder()
      .status(StatusCode::OK)
      .header(CONTENT_TYPE, "text/event-stream")
      .body(reqwest::Body::wrap_stream(source))
      .unwrap();
    let upstream = ManagedHttpResponse {
      response: reqwest::Response::from(response),
      metadata: metadata(Endpoint::Responses, Endpoint::ChatCompletions, true, true),
    };

    let adapted = ManagedResponseAdapter::new().adapt(upstream).await.unwrap();
    let (_, headers, body) = adapted.into_parts();
    let ManagedClientBody::Stream(mut body) = body else {
      panic!("expected live stream")
    };
    let first = tokio::time::timeout(std::time::Duration::from_millis(250), body.next())
      .await
      .expect("adapter waited for upstream EOF")
      .expect("stream ended before its first translated event")
      .unwrap();

    assert!(String::from_utf8_lossy(&first).contains("response.created"));
    assert_eq!(headers[CONTENT_TYPE], "text/event-stream");
    assert!(!headers.contains_key(CONTENT_LENGTH));
  }
}

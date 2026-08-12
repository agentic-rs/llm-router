//! Adapter from the low-level native HTTP service response to axum.
//!
//! Compatibility pipeline responses retain their body classification in an
//! HTTP extension. Router-owned JSON and SSE endpoints rebuild the same safe
//! downstream headers as before, avoiding stale upstream content encodings.
//! Arbitrary low-level responses preserve their native headers unchanged.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Response};
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use tokn_requests::PipelineResponseKind;

pub(crate) fn converted_to_axum(response: tokn_service::Response) -> Response<Body> {
  let (mut parts, body) = response.into_parts();
  match parts.extensions.get::<PipelineResponseKind>().copied() {
    Some(PipelineResponseKind::Buffered) => parts.headers = buffered_headers(),
    Some(PipelineResponseKind::Opaque) => {}
    Some(PipelineResponseKind::Stream) => parts.headers = sse_headers(),
    None => {}
  }
  let body = Body::from_stream(
    body
      .into_data_stream()
      .map_err(|error| std::io::Error::other(error.to_string())),
  );
  Response::from_parts(parts, body)
}

fn buffered_headers() -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
  headers
}

fn sse_headers() -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
  headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
  headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
  headers
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn opaque_buffered_responses_preserve_upstream_headers() {
    let mut response = http::Response::builder()
      .status(201)
      .header(header::CONTENT_TYPE, "application/octet-stream")
      .header("x-upstream", "preserved")
      .body(tokn_service::body::full("opaque"))
      .unwrap();
    response.extensions_mut().insert(PipelineResponseKind::Opaque);

    let response = converted_to_axum(response);

    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(response.headers()["x-upstream"], "preserved");
    assert_eq!(
      axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
      "opaque"
    );
  }
}

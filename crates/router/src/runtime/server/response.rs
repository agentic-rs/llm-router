//! Downstream HTTP response materialization for the v2 serving path.
//!
//! Managed responses have already completed any required protocol conversion.
//! Opaque responses retain reqwest's live body. Both paths preserve native
//! status and header types, remove connection-local metadata, and return an
//! axum body without buffering it in the router.

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::header::{HeaderName, CONNECTION};
use http::{HeaderMap, StatusCode};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use snafu::Snafu;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokn_requests::execution::{ManagedClientBody, ManagedClientResponse};

const HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
  "connection",
  "http2-settings",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

pub type ResponseBridgeResult<T> = std::result::Result<T, ResponseBridgeError>;

/// A response head that cannot be represented by a regular axum response.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ResponseBridgeError {
  #[snafu(display(
    "cannot forward 101 Switching Protocols as a regular HTTP response; dispatch upgrades through a tunnel"
  ))]
  SwitchingProtocols,
}

/// Materialize one adapted managed response for axum.
///
/// Account selection must already be settled from the upstream response head
/// before this function is called. Streaming bodies remain lazy.
pub fn managed_response_to_axum(response: ManagedClientResponse) -> ResponseBridgeResult<Response> {
  let (status, mut headers, body) = response.into_parts();
  ensure_regular_response(status)?;
  sanitize_response_headers(&mut headers);
  let body = match body {
    ManagedClientBody::Buffered(body) => Body::from(body),
    ManagedClientBody::Stream(body) => Body::from_stream(body),
  };
  Ok(response_from_parts(status, headers, body))
}

/// Materialize one unadapted, content-coding-preserving opaque upstream
/// response for axum.
///
/// Converting through `http::Response<reqwest::Body>` moves the native header
/// map and live body instead of rebuilding headers or adapting the body into a
/// data-only stream. This preserves duplicate and non-UTF-8 header values,
/// response-body errors, size hints, and trailer frames. Trailer fields pass
/// through the same connection-local sanitizer as the response head.
pub fn opaque_response_to_axum(response: reqwest::Response) -> ResponseBridgeResult<Response> {
  let response: http::Response<reqwest::Body> = response.into();
  let (mut parts, body) = response.into_parts();
  ensure_regular_response(parts.status)?;
  sanitize_response_headers(&mut parts.headers);
  let body = Body::new(SanitizedResponseBody::new(body));
  Ok(response_from_parts(parts.status, parts.headers, body))
}

fn ensure_regular_response(status: StatusCode) -> ResponseBridgeResult<()> {
  if status == StatusCode::SWITCHING_PROTOCOLS {
    return Err(ResponseBridgeError::SwitchingProtocols);
  }
  Ok(())
}

fn response_from_parts(status: StatusCode, headers: HeaderMap, body: Body) -> Response {
  let mut response = Response::new(body);
  *response.status_mut() = status;
  *response.headers_mut() = headers;
  response
}

/// Preserve body frames while removing connection-local trailer fields.
struct SanitizedResponseBody<B> {
  inner: B,
}

impl<B> SanitizedResponseBody<B> {
  fn new(inner: B) -> Self {
    Self { inner }
  }
}

impl<B> HttpBody for SanitizedResponseBody<B>
where
  B: HttpBody<Data = Bytes> + Unpin,
{
  type Data = Bytes;
  type Error = B::Error;

  fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
    let this = self.get_mut();
    match Pin::new(&mut this.inner).poll_frame(context) {
      Poll::Ready(Some(Ok(mut frame))) => {
        if let Some(trailers) = frame.trailers_mut() {
          sanitize_response_headers(trailers);
        }
        Poll::Ready(Some(Ok(frame)))
      }
      other => other,
    }
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

/// Remove metadata that applies only to the upstream connection.
///
/// Every field nominated by every `Connection` value is removed in addition
/// to the standard and widely deployed connection-local fields. Parsing uses
/// raw bytes so an unrelated non-UTF-8 response header never becomes lossy.
fn sanitize_response_headers(headers: &mut HeaderMap) {
  let mut nominated = Vec::new();
  for value in headers.get_all(CONNECTION) {
    for token in value.as_bytes().split(|byte| *byte == b',') {
      let token = trim_optional_whitespace(token);
      if let Ok(name) = HeaderName::from_bytes(token) {
        nominated.push(name);
      }
    }
  }

  for name in nominated {
    headers.remove(name);
  }
  for name in HOP_BY_HOP_RESPONSE_HEADERS {
    headers.remove(*name);
  }
}

fn trim_optional_whitespace(value: &[u8]) -> &[u8] {
  let start = value
    .iter()
    .position(|byte| !matches!(*byte, b' ' | b'\t'))
    .unwrap_or(value.len());
  let end = value
    .iter()
    .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
    .map_or(start, |position| position + 1);
  &value[start..end]
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::to_bytes;
  use bytes::BytesMut;
  use futures_util::{StreamExt, TryStreamExt};
  use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, SET_COOKIE};
  use std::convert::Infallible;
  use std::future::poll_fn;
  use std::time::Duration;

  #[tokio::test]
  async fn opaque_response_preserves_end_to_end_head_and_duplicate_headers() {
    let mut upstream = http::Response::new("payload");
    *upstream.status_mut() = StatusCode::IM_A_TEAPOT;
    let headers = upstream.headers_mut();
    headers.append(SET_COOKIE, "first=1".parse().unwrap());
    headers.append(SET_COOKIE, "second=2".parse().unwrap());
    headers.append(CONNECTION, "keep-alive, X-First-Hop".parse().unwrap());
    headers.append(CONNECTION, "X-Second-Hop".parse().unwrap());
    headers.insert("x-first-hop", "remove-first".parse().unwrap());
    headers.insert("x-second-hop", "remove-second".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("proxy-authenticate", "Basic realm=upstream".parse().unwrap());
    headers.insert(CONTENT_LENGTH, "7".parse().unwrap());
    headers.insert(CONTENT_ENCODING, "identity".parse().unwrap());

    let downstream = opaque_response_to_axum(reqwest::Response::from(upstream)).unwrap();

    assert_eq!(downstream.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(
      downstream
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>(),
      ["first=1", "second=2"]
    );
    assert!(!downstream.headers().contains_key(CONNECTION));
    assert!(!downstream.headers().contains_key("x-first-hop"));
    assert!(!downstream.headers().contains_key("x-second-hop"));
    assert!(!downstream.headers().contains_key("keep-alive"));
    assert!(!downstream.headers().contains_key("proxy-authenticate"));
    assert_eq!(downstream.headers()[CONTENT_LENGTH], "7");
    assert_eq!(downstream.headers()[CONTENT_ENCODING], "identity");
    assert_eq!(to_bytes(downstream.into_body(), usize::MAX).await.unwrap(), "payload");
  }

  #[test]
  fn switching_protocols_requires_tunnel_handling() {
    let upstream = http::Response::builder()
      .status(StatusCode::SWITCHING_PROTOCOLS)
      .body("")
      .unwrap();

    let error = opaque_response_to_axum(reqwest::Response::from(upstream)).unwrap_err();

    assert!(matches!(error, ResponseBridgeError::SwitchingProtocols));
  }

  #[tokio::test]
  async fn opaque_response_body_stays_live() {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<std::io::Result<Bytes>>();
    sender.send(Ok(Bytes::from_static(b"first"))).unwrap();
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
      receiver.recv().await.map(|item| (item, receiver))
    });
    let upstream = http::Response::new(reqwest::Body::wrap_stream(stream));
    let upstream = reqwest::Response::from(upstream);

    let downstream = opaque_response_to_axum(upstream).unwrap();
    let mut body = downstream.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_secs(1), body.next())
      .await
      .expect("first downstream chunk timed out")
      .expect("body ended before the first chunk")
      .expect("first downstream chunk failed");
    assert_eq!(first, Bytes::from_static(b"first"));

    sender.send(Ok(Bytes::from_static(b"second"))).unwrap();
    drop(sender);
    let remaining = body
      .try_fold(BytesMut::new(), |mut output, chunk| async move {
        output.extend_from_slice(&chunk);
        Ok(output)
      })
      .await
      .unwrap()
      .freeze();
    assert_eq!(remaining, Bytes::from_static(b"second"));
  }

  #[tokio::test]
  async fn opaque_response_sanitizes_trailer_fields_without_dropping_them() {
    let mut trailers = HeaderMap::new();
    trailers.append(SET_COOKIE, "first=1".parse().unwrap());
    trailers.append(SET_COOKIE, "second=2".parse().unwrap());
    trailers.insert(CONNECTION, "X-Trailer-Hop".parse().unwrap());
    trailers.insert("x-trailer-hop", "remove-me".parse().unwrap());
    trailers.insert("x-end-to-end", "keep-me".parse().unwrap());
    let mut body = SanitizedResponseBody::new(OneFrameBody(Some(Frame::trailers(trailers))));

    let frame = poll_fn(|context| Pin::new(&mut body).poll_frame(context))
      .await
      .expect("body ended before trailers")
      .unwrap();
    let trailers = frame.into_trailers().expect("expected trailer frame");

    assert!(!trailers.contains_key(CONNECTION));
    assert!(!trailers.contains_key("x-trailer-hop"));
    assert_eq!(trailers["x-end-to-end"], "keep-me");
    assert_eq!(
      trailers
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>(),
      ["first=1", "second=2"]
    );
  }

  struct OneFrameBody(Option<Frame<Bytes>>);

  impl HttpBody for OneFrameBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
      mut self: Pin<&mut Self>,
      _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
      Poll::Ready(self.0.take().map(Ok))
    }
  }
}

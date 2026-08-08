//! Streaming HTTP body helpers for the low-level service contract.

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body::Frame;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use std::convert::Infallible;
use std::error::Error as StdError;

/// Type-erased byte body used by low-level requests and responses.
///
/// The body can be buffered or streaming. It is intentionally not tied to
/// reqwest, axum, config, routing, or a provider implementation.
pub type Body = UnsyncBoxBody<Bytes, BodyError>;

/// Concrete error carried by streaming HTTP bodies.
#[derive(Debug)]
pub struct BodyError {
  source: crate::BoxError,
}

impl BodyError {
  /// Erase a concrete body-stream failure.
  pub fn new(source: impl StdError + Send + Sync + 'static) -> Self {
    Self {
      source: Box::new(source),
    }
  }

  /// Recover the type-erased source.
  pub fn into_source(self) -> crate::BoxError {
    self.source
  }
}

impl std::fmt::Display for BodyError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.source.fmt(formatter)
  }
}

impl StdError for BodyError {
  fn source(&self) -> Option<&(dyn StdError + 'static)> {
    Some(self.source.as_ref())
  }
}

/// Construct an empty body.
pub fn empty() -> Body {
  Empty::<Bytes>::new().map_err(infallible).boxed_unsync()
}

/// Construct a body containing one buffered byte chunk.
pub fn full(bytes: impl Into<Bytes>) -> Body {
  Full::new(bytes.into()).map_err(infallible).boxed_unsync()
}

/// Construct a body from a fallible byte stream.
pub fn stream<S, E>(stream: S) -> Body
where
  S: Stream<Item = Result<Bytes, E>> + Send + 'static,
  E: StdError + Send + Sync + 'static,
{
  let frames = stream.map(|item| item.map(Frame::data).map_err(BodyError::new));
  StreamBody::new(frames).boxed_unsync()
}

fn infallible(error: Infallible) -> BodyError {
  match error {}
}

#[cfg(test)]
mod tests {
  use super::*;
  use futures_util::stream;

  #[tokio::test]
  async fn streaming_body_preserves_chunk_boundaries() {
    let body = stream(stream::iter([
      Ok::<_, std::io::Error>(Bytes::from_static(b"first")),
      Ok(Bytes::from_static(b"second")),
    ]));
    let frames = body.collect().await.unwrap().to_bytes();

    assert_eq!(frames, Bytes::from_static(b"firstsecond"));
  }
}

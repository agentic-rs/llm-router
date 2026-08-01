use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::TryStreamExt;
use serde::de::DeserializeOwned;
use tokn_headers::HeaderMap;
use tokn_requests::execution::{ManagedClientBody, ManagedClientResponse};

use crate::{Error, Result};

pub type ByteStream = BoxStream<'static, std::io::Result<Bytes>>;

pub struct RawResponse {
  pub status: u16,
  pub headers: HeaderMap,
  pub body: ResponseBody,
}

pub enum ResponseBody {
  Buffered(Bytes),
  Stream(ByteStream),
}

impl std::fmt::Debug for RawResponse {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("RawResponse")
      .field("status", &self.status)
      .field("headers", &self.headers)
      .field("body", &self.body)
      .finish()
  }
}

impl std::fmt::Debug for ResponseBody {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Buffered(bytes) => formatter
        .debug_tuple("Buffered")
        .field(&format_args!("{} bytes", bytes.len()))
        .finish(),
      Self::Stream(_) => formatter.debug_tuple("Stream").field(&"<byte stream>").finish(),
    }
  }
}

impl From<ManagedClientResponse> for RawResponse {
  fn from(response: ManagedClientResponse) -> Self {
    let (status, headers, body) = response.into_parts();
    let body = match body {
      ManagedClientBody::Buffered(body) => ResponseBody::Buffered(body),
      ManagedClientBody::Stream(body) => ResponseBody::Stream(body),
    };
    Self {
      status: status.as_u16(),
      headers: HeaderMap::from(&headers),
      body,
    }
  }
}

impl RawResponse {
  pub fn into_buffered(self) -> Result<BufferedResponse<Bytes>> {
    match self.body {
      ResponseBody::Buffered(data) => Ok(BufferedResponse {
        status: self.status,
        headers: self.headers,
        data,
      }),
      ResponseBody::Stream(_) => Err(Error::UnexpectedStream),
    }
  }

  pub fn into_stream(self) -> Result<StreamResponse> {
    match self.body {
      ResponseBody::Buffered(_) => Err(Error::UnexpectedBuffered),
      ResponseBody::Stream(stream) => Ok(StreamResponse {
        status: self.status,
        headers: self.headers,
        stream,
      }),
    }
  }

  pub fn into_json<T: DeserializeOwned>(self) -> Result<BufferedResponse<T>> {
    let buffered = self.into_buffered()?;
    let data = serde_json::from_slice(&buffered.data).map_err(|source| Error::DeserializeResponse { source })?;
    Ok(BufferedResponse {
      status: buffered.status,
      headers: buffered.headers,
      data,
    })
  }
}

#[derive(Debug)]
pub struct BufferedResponse<T> {
  pub status: u16,
  pub headers: HeaderMap,
  pub data: T,
}

pub struct StreamResponse {
  pub status: u16,
  pub headers: HeaderMap,
  stream: ByteStream,
}

impl std::fmt::Debug for StreamResponse {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("StreamResponse")
      .field("status", &self.status)
      .field("headers", &self.headers)
      .field("stream", &"<byte stream>")
      .finish()
  }
}

impl StreamResponse {
  pub fn into_stream(self) -> ByteStream {
    self.stream
  }

  pub async fn bytes(self) -> std::io::Result<Bytes> {
    self
      .stream
      .try_fold(bytes::BytesMut::new(), |mut output, chunk| async move {
        output.extend_from_slice(&chunk);
        Ok(output)
      })
      .await
      .map(|output| output.freeze())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use futures_util::stream;
  use serde::Deserialize;

  fn raw_buffered(body: &'static [u8]) -> RawResponse {
    RawResponse {
      status: 201,
      headers: HeaderMap::new(),
      body: ResponseBody::Buffered(Bytes::from_static(body)),
    }
  }

  fn raw_stream(chunks: Vec<std::io::Result<Bytes>>) -> RawResponse {
    RawResponse {
      status: 202,
      headers: HeaderMap::new(),
      body: ResponseBody::Stream(Box::pin(stream::iter(chunks))),
    }
  }

  #[derive(Debug, Deserialize, PartialEq)]
  struct Payload {
    answer: u8,
  }

  #[test]
  fn buffered_response_supports_bytes_json_and_debug_output() {
    let raw = raw_buffered(br#"{"answer":42}"#);
    assert!(format!("{raw:?}").contains("Buffered(13 bytes)"));

    let response = raw.into_json::<Payload>().expect("deserialize buffered response");
    assert_eq!(response.status, 201);
    assert_eq!(response.data, Payload { answer: 42 });
    assert!(format!("{response:?}").contains("answer: 42"));
  }

  #[test]
  fn response_body_kind_mismatches_are_reported() {
    let buffered_error = raw_buffered(b"{}")
      .into_stream()
      .expect_err("buffered body is not a stream");
    assert!(matches!(buffered_error, Error::UnexpectedBuffered));

    let stream_error = raw_stream(Vec::new())
      .into_buffered()
      .expect_err("stream body is not buffered");
    assert!(matches!(stream_error, Error::UnexpectedStream));
  }

  #[test]
  fn malformed_json_is_reported() {
    let error = raw_buffered(b"{")
      .into_json::<Payload>()
      .expect_err("malformed response JSON should fail");
    assert!(matches!(error, Error::DeserializeResponse { .. }));
  }

  #[tokio::test]
  async fn stream_response_collects_chunks_and_propagates_errors() {
    let response = raw_stream(vec![
      Ok(Bytes::from_static(b"hello ")),
      Ok(Bytes::from_static(b"world")),
    ])
    .into_stream()
    .expect("stream response");
    assert!(format!("{response:?}").contains("<byte stream>"));
    assert_eq!(
      response.bytes().await.expect("collect stream"),
      Bytes::from_static(b"hello world")
    );

    let response = raw_stream(vec![Err(std::io::Error::other("stream failed"))])
      .into_stream()
      .expect("stream response");
    let error = response.bytes().await.expect_err("stream error should propagate");
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
  }
}

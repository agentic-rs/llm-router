use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::TryStreamExt;
use serde::de::DeserializeOwned;
use tokn_headers::HeaderMap;
use tokn_requests::pipeline::stages::{ConvertedBody, ConvertedResponse};

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

impl From<ConvertedResponse> for RawResponse {
  fn from(response: ConvertedResponse) -> Self {
    let body = match response.body {
      ConvertedBody::Buffered { body_bytes, .. } => ResponseBody::Buffered(body_bytes),
      ConvertedBody::Stream { body } => ResponseBody::Stream(body),
    };
    Self {
      status: response.status,
      headers: response.headers,
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

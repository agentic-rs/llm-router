use super::error::ApiError;
use axum::http::header::CONTENT_ENCODING;
use axum::http::HeaderMap;
use bytes::Bytes;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentEncodingKind {
  Gzip,
  Zstd,
}

impl ContentEncodingKind {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      ContentEncodingKind::Gzip => "gzip",
      ContentEncodingKind::Zstd => "zstd",
    }
  }
}

#[derive(Clone, Debug)]
pub(crate) struct DecodedJsonRequest {
  pub raw_body: Bytes,
  /// Post-decompression bytes of the request body. Same as `raw_body` when no
  /// content-encoding was applied, otherwise the inflated payload.
  pub decoded_body: Bytes,
  pub value: Value,
}

pub(crate) fn decode_json_request(headers: &HeaderMap, raw_body: Bytes) -> Result<DecodedJsonRequest, ApiError> {
  let encoding = request_content_encoding(headers)?;
  let decoded = decode_body_bytes(raw_body.clone(), encoding)?;
  let value: Value =
    serde_json::from_slice(&decoded).map_err(|e| ApiError::bad_request(format!("invalid JSON request body: {e}")))?;
  Ok(DecodedJsonRequest {
    raw_body,
    decoded_body: decoded,
    value,
  })
}

pub(crate) fn encode_body_bytes(body: &[u8], encoding: Option<ContentEncodingKind>) -> Result<Bytes, String> {
  match encoding {
    None => Ok(Bytes::copy_from_slice(body)),
    Some(ContentEncodingKind::Gzip) => {
      let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
      encoder
        .write_all(body)
        .map_err(|e| format!("gzip encode failed: {e}"))?;
      encoder
        .finish()
        .map(Bytes::from)
        .map_err(|e| format!("gzip encode failed: {e}"))
    }
    Some(ContentEncodingKind::Zstd) => zstd::stream::encode_all(body, 0)
      .map(Bytes::from)
      .map_err(|e| format!("zstd encode failed: {e}")),
  }
}

pub(crate) fn request_content_encoding(headers: &HeaderMap) -> Result<Option<ContentEncodingKind>, ApiError> {
  let Some(value) = headers.get(CONTENT_ENCODING) else {
    return Ok(None);
  };
  let value = value
    .to_str()
    .map_err(|_| ApiError::unsupported_media_type("unsupported content-encoding header"))?;
  let mut encodings = value
    .split(',')
    .map(str::trim)
    .filter(|part| !part.is_empty() && !part.eq_ignore_ascii_case("identity"));
  let first = match encodings.next() {
    Some(first) => first,
    None => return Ok(None),
  };
  if encodings.next().is_some() {
    return Err(ApiError::unsupported_media_type(
      "multiple content-encodings are not supported",
    ));
  }
  match first.to_ascii_lowercase().as_str() {
    "gzip" => Ok(Some(ContentEncodingKind::Gzip)),
    "zstd" => Ok(Some(ContentEncodingKind::Zstd)),
    other => Err(ApiError::unsupported_media_type(format!(
      "unsupported content-encoding '{other}'"
    ))),
  }
}

pub(crate) fn decode_body_bytes(body: Bytes, encoding: Option<ContentEncodingKind>) -> Result<Bytes, ApiError> {
  match encoding {
    None => Ok(body),
    Some(ContentEncodingKind::Gzip) => {
      let mut decoder = GzDecoder::new(body.as_ref());
      let mut out = Vec::new();
      decoder
        .read_to_end(&mut out)
        .map_err(|e| ApiError::bad_request(format!("gzip decode failed: {e}")))?;
      Ok(Bytes::from(out))
    }
    Some(ContentEncodingKind::Zstd) => zstd::stream::decode_all(body.as_ref())
      .map(Bytes::from)
      .map_err(|e| ApiError::bad_request(format!("zstd decode failed: {e}"))),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::response::IntoResponse;
  use http::HeaderValue;

  #[test]
  fn gzip_round_trip() {
    let body = br#"{"model":"gpt-5","input":"hi"}"#;
    let encoded = encode_body_bytes(body, Some(ContentEncodingKind::Gzip)).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    let decoded = decode_json_request(&headers, encoded).unwrap();
    assert_eq!(decoded.value["model"], "gpt-5");
  }

  #[test]
  fn zstd_round_trip() {
    let body = br#"{"model":"gpt-5","input":"hi"}"#;
    let encoded = encode_body_bytes(body, Some(ContentEncodingKind::Zstd)).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
    let decoded = decode_json_request(&headers, encoded).unwrap();
    assert_eq!(decoded.value["model"], "gpt-5");
  }

  #[test]
  fn rejects_unsupported_content_encoding() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
    let err = decode_json_request(&headers, Bytes::from_static(br#"{}"#)).unwrap_err();
    assert_eq!(
      err.into_response().status(),
      axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
  }
}

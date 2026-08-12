use super::error::ApiError;
use axum::http::header::CONTENT_ENCODING;
use axum::http::HeaderMap;
use bytes::Bytes;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;
use std::io::{Read, Write};

const MIN_ZSTD_WINDOW_LOG: u32 = 23;
const MAX_ZSTD_WINDOW_LOG: u32 = 27;

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
  decode_json_request_with_limit(headers, raw_body, usize::MAX)
}

pub(crate) fn decode_json_request_with_limit(
  headers: &HeaderMap,
  raw_body: Bytes,
  max_decoded_bytes: usize,
) -> Result<DecodedJsonRequest, ApiError> {
  let encoding = request_content_encoding(headers)?;
  let decoded = decode_body_bytes_with_limit(raw_body.clone(), encoding, max_decoded_bytes)?;
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

pub(crate) fn decode_body_bytes_with_limit(
  body: Bytes,
  encoding: Option<ContentEncodingKind>,
  max_decoded_bytes: usize,
) -> Result<Bytes, ApiError> {
  match encoding {
    None => ensure_decoded_limit(body, max_decoded_bytes),
    Some(ContentEncodingKind::Gzip) => {
      let mut decoder = GzDecoder::new(body.as_ref());
      let mut out = Vec::new();
      read_to_limit(&mut decoder, &mut out, max_decoded_bytes, "gzip")?;
      Ok(Bytes::from(out))
    }
    Some(ContentEncodingKind::Zstd) => {
      let mut decoder = zstd::stream::read::Decoder::new(body.as_ref())
        .map_err(|e| ApiError::bad_request(format!("zstd decode failed: {e}")))?;
      decoder
        .window_log_max(zstd_window_log(max_decoded_bytes))
        .map_err(|e| ApiError::bad_request(format!("zstd decode failed: {e}")))?;
      let mut out = Vec::new();
      read_to_limit(&mut decoder, &mut out, max_decoded_bytes, "zstd")?;
      Ok(Bytes::from(out))
    }
  }
}

fn ensure_decoded_limit(body: Bytes, max_decoded_bytes: usize) -> Result<Bytes, ApiError> {
  if body.len() > max_decoded_bytes {
    return Err(decoded_body_too_large(max_decoded_bytes));
  }
  Ok(body)
}

fn read_to_limit(
  reader: &mut impl Read,
  output: &mut Vec<u8>,
  max_decoded_bytes: usize,
  encoding: &str,
) -> Result<(), ApiError> {
  let read_limit = u64::try_from(max_decoded_bytes).unwrap_or(u64::MAX).saturating_add(1);
  reader
    .take(read_limit)
    .read_to_end(output)
    .map_err(|e| ApiError::bad_request(format!("{encoding} decode failed: {e}")))?;
  if output.len() > max_decoded_bytes {
    return Err(decoded_body_too_large(max_decoded_bytes));
  }
  Ok(())
}

fn decoded_body_too_large(max_decoded_bytes: usize) -> ApiError {
  ApiError::payload_too_large(format!(
    "decoded request body exceeds the configured {max_decoded_bytes} byte limit"
  ))
}

fn zstd_window_log(max_decoded_bytes: usize) -> u32 {
  let minimum_window = 1usize << MIN_ZSTD_WINDOW_LOG;
  let ceiling_log = usize::BITS - max_decoded_bytes.max(minimum_window).saturating_sub(1).leading_zeros();
  ceiling_log.clamp(MIN_ZSTD_WINDOW_LOG, MAX_ZSTD_WINDOW_LOG)
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

  #[test]
  fn decoded_limit_applies_after_decompression() {
    let body = br#"{"model":"gpt-5","input":"compressible compressible"}"#;
    let encoded = encode_body_bytes(body, Some(ContentEncodingKind::Gzip)).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

    let error = decode_json_request_with_limit(&headers, encoded, body.len() - 1).unwrap_err();
    assert_eq!(
      error.into_response().status(),
      axum::http::StatusCode::PAYLOAD_TOO_LARGE
    );
  }

  #[test]
  fn decoded_limit_applies_to_zstd() {
    let body = br#"{"model":"gpt-5","input":"compressible compressible"}"#;
    let encoded = encode_body_bytes(body, Some(ContentEncodingKind::Zstd)).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("zstd"));

    let error = decode_json_request_with_limit(&headers, encoded, body.len() - 1).unwrap_err();
    assert_eq!(
      error.into_response().status(),
      axum::http::StatusCode::PAYLOAD_TOO_LARGE
    );
  }
}

use crate::api::first_header;
use crate::provider::Endpoint;
use axum::http::HeaderMap;
use tokn_headers::inbound::REQUEST_ID_HEADERS;

#[derive(Clone, Debug)]
pub(crate) struct HeaderExtract {
  pub request_id: String,
}

pub(crate) fn request_header_extract(headers: &HeaderMap) -> HeaderExtract {
  let request_id = first_header(headers, REQUEST_ID_HEADERS)
    .map(str::to_string)
    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
  HeaderExtract { request_id }
}

pub(crate) trait RequestParser: Send + Sync {
  fn endpoint(&self) -> Endpoint;
}

pub(crate) struct ChatParser;
pub(crate) struct ResponsesParser;
pub(crate) struct MessagesParser;

impl RequestParser for ChatParser {
  fn endpoint(&self) -> Endpoint {
    Endpoint::ChatCompletions
  }
}

impl RequestParser for ResponsesParser {
  fn endpoint(&self) -> Endpoint {
    Endpoint::Responses
  }
}

impl RequestParser for MessagesParser {
  fn endpoint(&self) -> Endpoint {
    Endpoint::Messages
  }
}

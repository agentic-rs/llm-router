use axum::extract::Request as AxumRequest;
use axum::middleware::Next;
use axum::response::Response as AxumResponse;
use http::{HeaderMap, HeaderValue, Request, Response};
use tower_http::request_id::{MakeRequestId, RequestId};

pub const REQUEST_ID_HEADER: &str = "x-request-id";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MakeRouterRequestId;

impl MakeRequestId for MakeRouterRequestId {
  fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
    Some(RequestId::new(new_request_id_header()))
  }
}

pub(crate) fn new_request_id() -> String {
  format!("req-{}", uuid::Uuid::new_v4())
}

pub(crate) fn ensure_request_id(headers: &mut HeaderMap) -> HeaderValue {
  if let Some(request_id) = headers.get(REQUEST_ID_HEADER) {
    return request_id.clone();
  }

  let request_id = new_request_id_header();
  headers.insert(REQUEST_ID_HEADER, request_id.clone());
  request_id
}

pub(crate) async fn propagate_request_id(request: AxumRequest, next: Next) -> AxumResponse {
  let request_id = request.headers().get(REQUEST_ID_HEADER).cloned();
  let mut response = next.run(request).await;
  if let Some(request_id) = request_id {
    set_response_request_id(&mut response, request_id);
  }
  response
}

pub(crate) fn set_response_request_id<B>(response: &mut Response<B>, request_id: HeaderValue) {
  response.headers_mut().insert(REQUEST_ID_HEADER, request_id);
}

fn new_request_id_header() -> HeaderValue {
  HeaderValue::from_str(&new_request_id()).expect("router-generated request ids are valid HTTP header values")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn generated_request_id_is_prefixed_uuid() {
    let request_id = new_request_id();
    let uuid = request_id.strip_prefix("req-").expect("missing req- prefix");
    assert_eq!(uuid::Uuid::parse_str(uuid).unwrap().get_version_num(), 4);
  }

  #[test]
  fn ensure_request_id_preserves_client_value() {
    let mut headers = HeaderMap::new();
    headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("client-request"));

    assert_eq!(ensure_request_id(&mut headers), "client-request");
    assert_eq!(headers[REQUEST_ID_HEADER], "client-request");
  }
}

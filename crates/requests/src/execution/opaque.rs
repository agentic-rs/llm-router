//! Policy-free one-attempt transport for relay and transparent HTTP routes.
//!
//! The dispatcher has already selected the exact destination and, for relay
//! traffic, the exact account binding. This module only prepares that target
//! and sends one request. It does not resolve, retry, settle selection state,
//! inspect response bodies, or reinterpret received HTTP statuses.

use super::{
  sanitize_forward_headers, ExecutionTarget, HttpAttemptHead, RelayExecutionTarget, TransparentExecutionTarget,
};
use bytes::Bytes;
use snafu::Snafu;
use tokn_accounts::link::SelectionOutcome;
use tokn_core::provider::Error as ProviderError;
use tokn_core::upstream_url::InvalidRequestUrl;
use tokn_headers::inbound::build_template_vars;
use tokn_headers::registry::build_wire_identity_headers;
use tokn_headers::HeaderMap;

/// An exact route-family target accepted by the opaque executor.
#[derive(Clone, Copy, Debug)]
pub enum OpaqueHttpTarget<'a> {
  Relay(RelayExecutionTarget<'a>),
  Transparent(TransparentExecutionTarget<'a>),
}

impl<'a> OpaqueHttpTarget<'a> {
  /// Narrow a generic execution target without allowing managed traffic to
  /// enter the opaque transport path.
  pub fn from_execution(target: ExecutionTarget<'a>) -> Option<Self> {
    match target {
      ExecutionTarget::Managed(_) => None,
      ExecutionTarget::Relay(target) => Some(Self::Relay(target)),
      ExecutionTarget::Transparent(target) => Some(Self::Transparent(target)),
    }
  }
}

/// Borrowed wire input for exactly one opaque upstream attempt.
///
/// `body` distinguishes an absent body from a present zero-length body. The
/// transport borrows all input and returns an owned, still-live response.
#[derive(Clone, Copy, Debug)]
pub struct OpaqueHttpAttempt<'a> {
  head: HttpAttemptHead<'a>,
  target: OpaqueHttpTarget<'a>,
  headers: &'a HeaderMap,
  body: Option<&'a Bytes>,
}

impl<'a> OpaqueHttpAttempt<'a> {
  pub fn new(
    head: HttpAttemptHead<'a>,
    target: OpaqueHttpTarget<'a>,
    headers: &'a HeaderMap,
    body: Option<&'a Bytes>,
  ) -> Self {
    Self {
      head,
      target,
      headers,
      body,
    }
  }

  pub fn relay(
    head: HttpAttemptHead<'a>,
    target: RelayExecutionTarget<'a>,
    headers: &'a HeaderMap,
    body: Option<&'a Bytes>,
  ) -> Self {
    Self::new(head, OpaqueHttpTarget::Relay(target), headers, body)
  }

  pub fn transparent(
    head: HttpAttemptHead<'a>,
    target: TransparentExecutionTarget<'a>,
    headers: &'a HeaderMap,
    body: Option<&'a Bytes>,
  ) -> Self {
    Self::new(head, OpaqueHttpTarget::Transparent(target), headers, body)
  }

  pub fn head(&self) -> HttpAttemptHead<'a> {
    self.head
  }

  pub fn target(&self) -> OpaqueHttpTarget<'a> {
    self.target
  }

  pub fn headers(&self) -> &'a HeaderMap {
    self.headers
  }

  pub fn body(&self) -> Option<&'a Bytes> {
    self.body
  }
}

/// A failure before a final upstream response head was received.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum OpaqueAttemptError {
  #[snafu(display("invalid opaque upstream request URL: {source}"))]
  InvalidRequestUrl { source: InvalidRequestUrl },

  #[snafu(display("provider '{provider}' could not authorize opaque relay request: {source}"))]
  Authorization { provider: String, source: ProviderError },

  #[snafu(display("opaque upstream request failed: {source}"))]
  Transport { source: ProviderError },
}

impl OpaqueAttemptError {
  /// Pool outcome appropriate when this attempt owned an account selection.
  ///
  /// An invalid local URL is not evidence that the binding is unhealthy.
  /// Authorization and transport failures happen after selecting a binding
  /// but before receiving a response head, so a later attempt should prefer
  /// another eligible binding.
  pub fn selection_outcome(&self) -> SelectionOutcome {
    match self {
      Self::InvalidRequestUrl { .. } => SelectionOutcome::Unchanged,
      Self::Authorization { .. } | Self::Transport { .. } => SelectionOutcome::Unavailable,
    }
  }
}

/// HTTP clients with intentionally separate control- and data-plane
/// behavior for opaque execution.
///
/// Provider authorization may perform token exchange and therefore uses the
/// normal client. The final relay/transparent request uses a client configured
/// not to follow redirects or decode response bodies. Callers must construct
/// `transport_http` with [`tokn_core::util::http::build_opaque_client`].
#[derive(Clone, Debug)]
pub struct OpaqueHttpExecutor {
  authorization_http: reqwest::Client,
  transport_http: reqwest::Client,
}

impl OpaqueHttpExecutor {
  pub fn new(authorization_http: reqwest::Client, transport_http: reqwest::Client) -> Self {
    Self {
      authorization_http,
      transport_http,
    }
  }

  pub fn authorization_http(&self) -> &reqwest::Client {
    &self.authorization_http
  }

  pub fn transport_http(&self) -> &reqwest::Client {
    &self.transport_http
  }

  /// Send one relay or transparent request and return the untouched live
  /// response after its final head arrives.
  ///
  /// Any received HTTP status is `Ok`, including authentication errors,
  /// throttling, redirects, and server errors. The caller classifies that
  /// head, settles any selected account, and chooses how to forward the body.
  pub async fn execute(&self, attempt: OpaqueHttpAttempt<'_>) -> Result<reqwest::Response, OpaqueAttemptError> {
    let head = attempt.head();
    let target = attempt.target();
    let url = match target {
      OpaqueHttpTarget::Relay(target) => target.request_url(head),
      OpaqueHttpTarget::Transparent(target) => target.request_url(head),
    }
    .map_err(|source| OpaqueAttemptError::InvalidRequestUrl { source })?;

    let headers = match target {
      OpaqueHttpTarget::Relay(target) => {
        prepare_relay_headers(&self.authorization_http, target, attempt.headers()).await?
      }
      OpaqueHttpTarget::Transparent(_) => sanitize_forward_headers(attempt.headers()),
    };

    tokn_core::util::http::send(
      &self.transport_http,
      head.method().clone(),
      url.as_str(),
      headers,
      attempt.body().cloned(),
      None,
      "opaque upstream request",
    )
    .await
    .map_err(|source| OpaqueAttemptError::Transport { source })
  }
}

async fn prepare_relay_headers(
  client: &reqwest::Client,
  target: RelayExecutionTarget<'_>,
  inbound: &HeaderMap,
) -> Result<HeaderMap, OpaqueAttemptError> {
  let binding = target.target().binding();
  let provider = binding.provider();
  let provider_id = provider.info().id.as_str();
  let mut outbound = sanitize_forward_headers(inbound);

  if let Some(identity) = target.wire_identity() {
    let vars = build_template_vars(inbound);
    let identity_headers = build_wire_identity_headers(provider_id, identity.as_str(), &vars, inbound);
    outbound.merge_replacing(identity_headers);
    // Persona schemas may model captured Host, Content-Length, Connection,
    // and other transport metadata. They remain useful for construction but
    // must not cross a newly established outbound connection.
    outbound = sanitize_forward_headers(&outbound);
  }

  provider
    .authorize_request(client, &mut outbound, target.request_kind())
    .await
    .map_err(|source| OpaqueAttemptError::Authorization {
      provider: provider_id.to_string(),
      source,
    })?;
  Ok(outbound)
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::{uri::PathAndQuery, Method, StatusCode};
  use std::time::Duration;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokn_core::upstream_url::{CanonicalHttpOrigin, CleartextHttpPolicy};
  use tokn_core::util::http::{build_client, build_opaque_client, HttpClientOptions};
  use tokn_headers::{HeaderName, HeaderValue};

  #[test]
  fn local_url_failures_do_not_penalize_a_selection() {
    let error = OpaqueAttemptError::InvalidRequestUrl {
      source: InvalidRequestUrl::ChangedPath {
        expected: "/expected".into(),
        found: "/found".into(),
      },
    };
    assert_eq!(error.selection_outcome(), SelectionOutcome::Unchanged);
  }

  #[tokio::test]
  async fn transparent_attempt_preserves_the_opaque_exchange() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received = tokio::spawn(async move {
      let (mut socket, _) = listener.accept().await.unwrap();
      let request = read_request(&mut socket).await;
      socket
        .write_all(
          b"HTTP/1.1 418 I'm a teapot\r\nSet-Cookie: first=1\r\nSet-Cookie: second=2\r\nContent-Encoding: gzip\r\nContent-Length: 17\r\nConnection: close\r\n\r\nnot-really-a-gzip",
        )
        .await
        .unwrap();
      request
    });

    let destination =
      CanonicalHttpOrigin::parse(&format!("http://{address}"), CleartextHttpPolicy::LoopbackOnly).unwrap();
    let method = Method::PATCH;
    let path = PathAndQuery::from_static("/v1/raw%2Fitem?x=1%202&x=two");
    let body = Bytes::from_static(b"opaque\0body");
    let headers = headers(&[
      ("Host", "attacker.invalid"),
      ("Content-Length", "999"),
      ("Connection", "keep-alive, X-Connection-Only"),
      ("X-Connection-Only", "remove-me"),
      ("Authorization", "Bearer client-token"),
      ("Cookie", "session=client"),
      ("X-End-To-End", "first"),
      ("X-End-To-End", "second"),
    ]);
    let target = TransparentExecutionTarget::new(&destination);
    let attempt = OpaqueHttpAttempt::transparent(HttpAttemptHead::new(&method, &path), target, &headers, Some(&body));
    let options = HttpClientOptions::default();
    let executor = OpaqueHttpExecutor::new(build_client(&options).unwrap(), build_opaque_client(&options).unwrap());

    let response = executor.execute(attempt).await.unwrap();

    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(
      response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>(),
      ["first=1", "second=2"]
    );
    assert_eq!(response.headers()["content-encoding"], "gzip");
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"not-really-a-gzip");

    let request = received.await.unwrap();
    let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
    assert!(request_text.starts_with("patch /v1/raw%2fitem?x=1%202&x=two http/1.1\r\n"));
    assert!(request_text.contains(&format!("host: {address}\r\n")));
    assert!(request_text.contains("content-length: 11\r\n"));
    assert!(request_text.contains("authorization: bearer client-token\r\n"));
    assert!(request_text.contains("cookie: session=client\r\n"));
    assert_eq!(request_text.matches("x-end-to-end:").count(), 2);
    assert!(!request_text.contains("x-connection-only"));
    assert!(!request_text.contains("connection: keep-alive"));
    assert!(request.ends_with(b"opaque\0body"));
  }

  fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
      headers.append(HeaderName::new(*name), HeaderValue::from_string((*value).to_string()));
    }
    headers
  }

  async fn read_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
      let read = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer))
        .await
        .expect("request read timed out")
        .unwrap();
      assert!(read > 0, "client closed before sending the complete request");
      request.extend_from_slice(&buffer[..read]);

      let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        continue;
      };
      let head_end = head_end + 4;
      let head = String::from_utf8_lossy(&request[..head_end]);
      let body_len = head
        .lines()
        .find_map(|line| {
          let (name, value) = line.split_once(':')?;
          name
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
      if request.len() >= head_end + body_len {
        return request;
      }
    }
  }
}

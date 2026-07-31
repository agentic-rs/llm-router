//! Borrowed post-dispatch inputs for one v2 HTTP execution attempt.
//!
//! Dispatch and account selection retain ownership of the linked runtime
//! graph. These types borrow those exact decisions so execution cannot drift
//! by reconstructing provider, account, upstream, or destination identity.

mod opaque;

pub use opaque::{OpaqueAttemptError, OpaqueHttpAttempt, OpaqueHttpExecutor, OpaqueHttpTarget};

use http::{uri::PathAndQuery, Method, StatusCode};
use std::collections::BTreeSet;
use tokn_accounts::link::{RelayDestination, SelectedManagedTarget, SelectedRelayTarget, SelectionOutcome};
use tokn_core::provider::{Endpoint, ProviderRequestKind};
use tokn_core::upstream_url::{CanonicalHttpOrigin, InvalidRequestUrl};
use tokn_core::AgentId;
use tokn_headers::HeaderMap;

const FORWARD_STRIPPED_HEADERS: &[&str] = &[
  "connection",
  "content-length",
  "host",
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

/// Copy end-to-end inbound headers for a new outbound HTTP connection.
///
/// The returned map preserves order, original casing, duplicate values, and
/// credentials. Relay authorization may replace credentials afterward;
/// transparent forwarding leaves them untouched. Transport-derived fields,
/// router controls, and every extension named by `Connection` are removed.
pub fn sanitize_forward_headers(inbound: &HeaderMap) -> HeaderMap {
  let mut stripped = FORWARD_STRIPPED_HEADERS
    .iter()
    .map(|name| (*name).to_string())
    .collect::<BTreeSet<_>>();
  for value in inbound.get_all("connection") {
    stripped.extend(
      value
        .as_str()
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase),
    );
  }

  let mut outbound = HeaderMap::with_capacity(inbound.len());
  for (name, value) in inbound {
    let lower = name.as_str();
    if stripped.contains(lower) || is_router_owned_header(lower) {
      continue;
    }
    outbound.append(name.clone(), value.clone());
  }
  outbound
}

fn is_router_owned_header(name: &str) -> bool {
  name.starts_with("x-tokn-router-") || matches!(name, "x-route-mode" | "x-behave-as")
}

/// Classify a received final response head for account-pool settlement.
///
/// This is deliberately independent from whether the response is forwarded
/// as an HTTP success or error. Ordinary client errors still prove that the
/// selected binding reached a responsive upstream. Statuses associated with
/// credentials, throttling, timeout, early-data rejection, or server failure
/// make another binding preferable for a later attempt.
pub fn classify_selection_outcome(status: StatusCode) -> SelectionOutcome {
  match status.as_u16() {
    401 => SelectionOutcome::Unauthorized,
    403 | 408 | 425 | 429 | 500..=599 => SelectionOutcome::Unavailable,
    200..=499 => SelectionOutcome::Healthy,
    _ => SelectionOutcome::Unchanged,
  }
}

/// Exact request-line fields retained for one outbound attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpAttemptHead<'a> {
  method: &'a Method,
  path_and_query: &'a PathAndQuery,
}

impl<'a> HttpAttemptHead<'a> {
  pub fn new(method: &'a Method, path_and_query: &'a PathAndQuery) -> Self {
    Self { method, path_and_query }
  }

  pub fn method(&self) -> &'a Method {
    self.method
  }

  pub fn path_and_query(&self) -> &'a PathAndQuery {
    self.path_and_query
  }
}

/// Route-family-specific target for one execution attempt.
#[derive(Clone, Copy, Debug)]
pub enum ExecutionTarget<'a> {
  Managed(ManagedExecutionTarget<'a>),
  Relay(RelayExecutionTarget<'a>),
  Transparent(TransparentExecutionTarget<'a>),
}

impl<'a> ExecutionTarget<'a> {
  pub fn managed(
    requested_model: &'a str,
    requested_operation: Endpoint,
    target: &'a SelectedManagedTarget,
    wire_identity: Option<&'a AgentId>,
  ) -> Self {
    Self::Managed(ManagedExecutionTarget::new(
      requested_model,
      requested_operation,
      target,
      wire_identity,
    ))
  }

  pub fn relay(
    request_kind: ProviderRequestKind,
    target: &'a SelectedRelayTarget,
    wire_identity: Option<&'a AgentId>,
  ) -> Self {
    Self::Relay(RelayExecutionTarget::new(request_kind, target, wire_identity))
  }

  pub fn transparent(destination: &'a CanonicalHttpOrigin) -> Self {
    Self::Transparent(TransparentExecutionTarget::new(destination))
  }

  pub fn as_managed(&self) -> Option<&ManagedExecutionTarget<'a>> {
    match self {
      Self::Managed(target) => Some(target),
      Self::Relay(_) | Self::Transparent(_) => None,
    }
  }

  pub fn as_relay(&self) -> Option<&RelayExecutionTarget<'a>> {
    match self {
      Self::Relay(target) => Some(target),
      Self::Managed(_) | Self::Transparent(_) => None,
    }
  }

  pub fn as_transparent(&self) -> Option<&TransparentExecutionTarget<'a>> {
    match self {
      Self::Transparent(target) => Some(target),
      Self::Managed(_) | Self::Relay(_) => None,
    }
  }
}

/// Managed execution keeps the inbound request semantics beside the exact
/// account-selected outbound target.
#[derive(Clone, Copy, Debug)]
pub struct ManagedExecutionTarget<'a> {
  requested_model: &'a str,
  requested_operation: Endpoint,
  target: &'a SelectedManagedTarget,
  wire_identity: Option<&'a AgentId>,
}

impl<'a> ManagedExecutionTarget<'a> {
  pub fn new(
    requested_model: &'a str,
    requested_operation: Endpoint,
    target: &'a SelectedManagedTarget,
    wire_identity: Option<&'a AgentId>,
  ) -> Self {
    Self {
      requested_model,
      requested_operation,
      target,
      wire_identity,
    }
  }

  pub fn requested_model(&self) -> &'a str {
    self.requested_model
  }

  pub fn requested_operation(&self) -> Endpoint {
    self.requested_operation
  }

  pub fn target(&self) -> &'a SelectedManagedTarget {
    self.target
  }

  pub fn wire_identity(&self) -> Option<&'a AgentId> {
    self.wire_identity
  }
}

/// Opaque relay execution with the request classification used for
/// provider-owned credential replacement.
#[derive(Clone, Copy, Debug)]
pub struct RelayExecutionTarget<'a> {
  request_kind: ProviderRequestKind,
  target: &'a SelectedRelayTarget,
  wire_identity: Option<&'a AgentId>,
}

impl<'a> RelayExecutionTarget<'a> {
  pub fn new(
    request_kind: ProviderRequestKind,
    target: &'a SelectedRelayTarget,
    wire_identity: Option<&'a AgentId>,
  ) -> Self {
    Self {
      request_kind,
      target,
      wire_identity,
    }
  }

  pub fn request_kind(&self) -> ProviderRequestKind {
    self.request_kind
  }

  pub fn target(&self) -> &'a SelectedRelayTarget {
    self.target
  }

  pub fn wire_identity(&self) -> Option<&'a AgentId> {
    self.wire_identity
  }

  /// Compose the exact opaque request URL without interpreting the inbound
  /// target as a relative URL. Fixed relays append it beneath the configured
  /// upstream prefix; origin relays preserve the admitted ingress origin.
  pub fn request_url(&self, head: HttpAttemptHead<'_>) -> Result<reqwest::Url, InvalidRequestUrl> {
    match self.target.destination() {
      RelayDestination::Configured(target) => target.base_url().relay_url(head.path_and_query()),
      RelayDestination::Original(origin) => origin.request_url(head.path_and_query()),
    }
  }
}

/// Account-less execution at the exact admitted inbound origin.
#[derive(Clone, Copy, Debug)]
pub struct TransparentExecutionTarget<'a> {
  destination: &'a CanonicalHttpOrigin,
}

impl<'a> TransparentExecutionTarget<'a> {
  pub fn new(destination: &'a CanonicalHttpOrigin) -> Self {
    Self { destination }
  }

  pub fn destination(&self) -> &'a CanonicalHttpOrigin {
    self.destination
  }

  /// Compose the exact opaque request URL at the admitted ingress origin.
  pub fn request_url(&self, head: HttpAttemptHead<'_>) -> Result<reqwest::Url, InvalidRequestUrl> {
    self.destination.request_url(head.path_and_query())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::upstream_url::CleartextHttpPolicy;
  use tokn_headers::{HeaderName, HeaderValue};

  fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
      headers.append(HeaderName::new(*name), HeaderValue::from_string((*value).to_string()));
    }
    headers
  }

  #[test]
  fn forward_sanitizer_removes_connection_and_router_metadata() {
    let inbound = headers(&[
      ("Host", "client.example"),
      ("Content-Length", "999"),
      ("Connection", "keep-alive, X-Connection-Only"),
      ("X-Connection-Only", "secret"),
      ("Keep-Alive", "timeout=5"),
      ("Proxy-Authorization", "Basic gateway-secret"),
      ("Transfer-Encoding", "chunked"),
      ("X-Tokn-Router-Local-Addr", "127.0.0.1:8080"),
      ("X-Route-Mode", "relay"),
      ("X-Behave-As", "codex"),
      ("Authorization", "Bearer upstream-secret"),
      ("Cookie", "session=upstream"),
      ("X-End-To-End", "first"),
      ("X-End-To-End", "second"),
    ]);

    let outbound = sanitize_forward_headers(&inbound);

    for removed in [
      "host",
      "content-length",
      "connection",
      "x-connection-only",
      "keep-alive",
      "proxy-authorization",
      "transfer-encoding",
      "x-tokn-router-local-addr",
      "x-route-mode",
      "x-behave-as",
    ] {
      assert!(!outbound.contains_key(removed), "header {removed}");
    }
    assert_eq!(
      outbound.get("authorization").map(|value| value.as_str()),
      Some("Bearer upstream-secret")
    );
    assert_eq!(
      outbound.get("cookie").map(|value| value.as_str()),
      Some("session=upstream")
    );
    assert_eq!(
      outbound
        .get_all("x-end-to-end")
        .map(|value| value.as_str())
        .collect::<Vec<_>>(),
      ["first", "second"]
    );
  }

  #[test]
  fn attempt_head_borrows_the_exact_request_line() {
    let method = Method::PATCH;
    let path_and_query = PathAndQuery::from_static("/v1/models%2Factive?limit=2");
    let head = HttpAttemptHead::new(&method, &path_and_query);

    assert!(std::ptr::eq(head.method(), &method));
    assert!(std::ptr::eq(head.path_and_query(), &path_and_query));
  }

  #[test]
  fn managed_and_relay_contracts_retain_borrowed_lifetimes() {
    fn check<'a>(
      requested_model: &'a str,
      managed_target: &'a SelectedManagedTarget,
      relay_target: &'a SelectedRelayTarget,
      wire_identity: Option<&'a AgentId>,
    ) {
      let managed = ExecutionTarget::managed(
        requested_model,
        Endpoint::ChatCompletions,
        managed_target,
        wire_identity,
      );
      let managed = managed.as_managed().unwrap();
      let _: &'a str = managed.requested_model();
      let _: &'a SelectedManagedTarget = managed.target();
      let _: Option<&'a AgentId> = managed.wire_identity();

      let relay = ExecutionTarget::relay(ProviderRequestKind::Opaque, relay_target, wire_identity);
      let relay = relay.as_relay().unwrap();
      let _: &'a SelectedRelayTarget = relay.target();
      let _: Option<&'a AgentId> = relay.wire_identity();
    }

    let _: for<'a> fn(&'a str, &'a SelectedManagedTarget, &'a SelectedRelayTarget, Option<&'a AgentId>) = check;
  }

  #[test]
  fn transparent_target_borrows_the_exact_destination() {
    let destination =
      CanonicalHttpOrigin::parse("https://[2001:db8::1]:8443", CleartextHttpPolicy::LoopbackOnly).unwrap();
    let execution = ExecutionTarget::transparent(&destination);
    let transparent = execution.as_transparent().unwrap();

    assert!(std::ptr::eq(transparent.destination(), &destination));
    assert!(execution.as_managed().is_none());
    assert!(execution.as_relay().is_none());
  }

  #[test]
  fn response_status_classification_is_independent_from_http_success() {
    for status in [200, 299, 300, 400, 404, 422, 499] {
      assert_eq!(
        classify_selection_outcome(StatusCode::from_u16(status).unwrap()),
        SelectionOutcome::Healthy,
        "status {status}"
      );
    }

    assert_eq!(
      classify_selection_outcome(StatusCode::UNAUTHORIZED),
      SelectionOutcome::Unauthorized
    );
    for status in [403, 408, 425, 429, 500, 503, 599] {
      assert_eq!(
        classify_selection_outcome(StatusCode::from_u16(status).unwrap()),
        SelectionOutcome::Unavailable,
        "status {status}"
      );
    }
    for status in [199, 600] {
      assert_eq!(
        classify_selection_outcome(StatusCode::from_u16(status).unwrap()),
        SelectionOutcome::Unchanged,
        "status {status}"
      );
    }
  }
}

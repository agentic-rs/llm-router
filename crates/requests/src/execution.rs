//! Borrowed post-dispatch inputs for one v2 HTTP execution attempt.
//!
//! Dispatch and account selection retain ownership of the linked runtime
//! graph. These types borrow those exact decisions so execution cannot drift
//! by reconstructing provider, account, upstream, or destination identity.

use http::{uri::PathAndQuery, Method};
use tokn_accounts::link::{SelectedManagedTarget, SelectedRelayTarget};
use tokn_core::provider::{Endpoint, ProviderRequestKind};
use tokn_core::upstream_url::CanonicalHttpOrigin;
use tokn_core::AgentId;

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
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::upstream_url::CleartextHttpPolicy;

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
}

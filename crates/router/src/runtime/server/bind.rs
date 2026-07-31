//! Atomic listener binding over one exact linked runtime generation.

use super::super::{
  LinkedGatewayRuntime, LinkedListener, LinkedListenerKind, MaterializedClientAuth, MaterializedListener,
  MaterializedListenerKind, MaterializedListeners,
};
use snafu::Snafu;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokn_policy::{ClientAuthPlan, ListenerId, ListenerKind};

/// Request-serving state shared by every connection entering one listener.
///
/// Retaining the complete gateway generation keeps provider, pool, route, and
/// profile state alive alongside the exact listener node that was
/// materialized from it.
#[derive(Debug)]
pub struct ListenerServerState {
  gateway: Arc<LinkedGatewayRuntime>,
  resource: MaterializedListener,
}

impl ListenerServerState {
  pub fn gateway(&self) -> &Arc<LinkedGatewayRuntime> {
    &self.gateway
  }

  pub fn resource(&self) -> &MaterializedListener {
    &self.resource
  }

  pub fn listener(&self) -> &Arc<LinkedListener> {
    self.resource.listener()
  }
}

/// Every configured listener socket, acquired before any accept loop starts.
#[derive(Debug)]
pub struct BoundGatewayListeners {
  listeners: BTreeMap<ListenerId, BoundListener>,
}

impl BoundGatewayListeners {
  pub fn listener(&self, listener_id: &ListenerId) -> Option<&BoundListener> {
    self.listeners.get(listener_id)
  }

  pub fn listeners(&self) -> impl ExactSizeIterator<Item = (&ListenerId, &BoundListener)> {
    self.listeners.iter()
  }

  /// Consume all sockets in deterministic listener-id order.
  pub fn into_listeners(self) -> impl ExactSizeIterator<Item = (ListenerId, BoundListener)> {
    self.listeners.into_iter()
  }

  pub fn len(&self) -> usize {
    self.listeners.len()
  }

  pub fn is_empty(&self) -> bool {
    self.listeners.is_empty()
  }
}

/// One bound socket and the immutable state later accept loops will share.
#[derive(Debug)]
pub struct BoundListener {
  socket: TcpListener,
  state: Arc<ListenerServerState>,
}

impl BoundListener {
  pub fn state(&self) -> &Arc<ListenerServerState> {
    &self.state
  }

  pub fn local_addr(&self) -> io::Result<SocketAddr> {
    self.socket.local_addr()
  }

  /// Transfer the socket and shared state into a family-specific accept loop.
  pub fn into_parts(self) -> (TcpListener, Arc<ListenerServerState>) {
    (self.socket, self.state)
  }
}

/// Validate and bind one complete listener generation without accepting.
///
/// All graph/resource validation precedes socket I/O. Sockets are then bound
/// sequentially in listener-id order. If a later bind fails, the partially
/// built map is dropped with this function frame, releasing every earlier
/// socket before the error is returned.
pub async fn bind_gateway_listeners(
  gateway: Arc<LinkedGatewayRuntime>,
  resources: MaterializedListeners,
) -> ListenerBindResult<BoundGatewayListeners> {
  validate_listener_set(&gateway, &resources)?;

  let mut states = BTreeMap::new();
  for (listener_id, resource) in resources.into_listeners() {
    validate_listener_resource(&gateway, &listener_id, &resource)?;
    states.insert(
      listener_id,
      Arc::new(ListenerServerState {
        gateway: gateway.clone(),
        resource,
      }),
    );
  }

  let mut listeners = BTreeMap::new();
  for (listener_id, state) in states {
    let address = state.listener().bind();
    let kind = state.listener().kind();
    let socket = TcpListener::bind(address)
      .await
      .map_err(|source| ListenerBindError::Bind {
        listener: listener_id.clone(),
        kind,
        address,
        source,
      })?;
    listeners.insert(listener_id, BoundListener { socket, state });
  }

  Ok(BoundGatewayListeners { listeners })
}

fn validate_listener_set(gateway: &LinkedGatewayRuntime, resources: &MaterializedListeners) -> ListenerBindResult<()> {
  let linked_ids = gateway
    .listeners()
    .listeners()
    .map(|(listener_id, _)| listener_id.clone())
    .collect::<BTreeSet<_>>();
  let resource_ids = resources
    .listeners()
    .map(|(listener_id, _)| listener_id.clone())
    .collect::<BTreeSet<_>>();

  if linked_ids.len() == resource_ids.len() && linked_ids == resource_ids {
    return Ok(());
  }

  let missing = linked_ids.difference(&resource_ids).cloned().collect::<Box<[_]>>();
  let unexpected = resource_ids.difference(&linked_ids).cloned().collect::<Box<[_]>>();
  Err(ListenerBindError::ListenerSetMismatch {
    linked_count: linked_ids.len(),
    resource_count: resource_ids.len(),
    missing,
    unexpected,
  })
}

fn validate_listener_resource(
  gateway: &LinkedGatewayRuntime,
  listener_id: &ListenerId,
  resource: &MaterializedListener,
) -> ListenerBindResult<()> {
  let linked = gateway
    .listeners()
    .listener(listener_id)
    .expect("the listener id set was validated before resource identity");
  if !Arc::ptr_eq(linked, resource.listener()) {
    return Err(ListenerBindError::ListenerIdentityMismatch {
      listener: listener_id.clone(),
    });
  }

  let materialized_auth = match resource.client_auth() {
    MaterializedClientAuth::None => ClientAuthPlan::None,
    MaterializedClientAuth::LocalKeys(_) => ClientAuthPlan::LocalKeys,
  };
  if linked.client_auth() != materialized_auth {
    return Err(ListenerBindError::ClientAuthMismatch {
      listener: listener_id.clone(),
      linked: linked.client_auth(),
      materialized: materialized_auth,
    });
  }

  match (linked.linked_kind(), resource.kind()) {
    (LinkedListenerKind::LlmApi, MaterializedListenerKind::LlmApi) => Ok(()),
    (LinkedListenerKind::ForwardProxy(policy), MaterializedListenerKind::ForwardProxy { ca }) => {
      match (policy.requires_interception(), ca.is_some()) {
        (true, false) => Err(ListenerBindError::MissingProxyCa {
          listener: listener_id.clone(),
        }),
        (false, true) => Err(ListenerBindError::UnexpectedProxyCa {
          listener: listener_id.clone(),
        }),
        _ => Ok(()),
      }
    }
    (linked_kind, materialized_kind) => Err(ListenerBindError::ListenerKindMismatch {
      listener: listener_id.clone(),
      linked: listener_kind(linked_kind),
      materialized: materialized_listener_kind(materialized_kind),
    }),
  }
}

fn listener_kind(kind: &LinkedListenerKind) -> ListenerKind {
  match kind {
    LinkedListenerKind::LlmApi => ListenerKind::LlmApi,
    LinkedListenerKind::ForwardProxy(_) => ListenerKind::ForwardProxy,
  }
}

fn materialized_listener_kind(kind: &MaterializedListenerKind) -> ListenerKind {
  match kind {
    MaterializedListenerKind::LlmApi => ListenerKind::LlmApi,
    MaterializedListenerKind::ForwardProxy { .. } => ListenerKind::ForwardProxy,
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ListenerBindError {
  #[snafu(display(
    "linked listener/resource sets differ (linked: {linked_count}, resources: {resource_count}, missing: {missing:?}, unexpected: {unexpected:?})"
  ))]
  ListenerSetMismatch {
    linked_count: usize,
    resource_count: usize,
    missing: Box<[ListenerId]>,
    unexpected: Box<[ListenerId]>,
  },

  #[snafu(display("listener '{listener}' was materialized from a different linked runtime generation"))]
  ListenerIdentityMismatch { listener: ListenerId },

  #[snafu(display("listener '{listener}' resource kind {materialized:?} does not match linked kind {linked:?}"))]
  ListenerKindMismatch {
    listener: ListenerId,
    linked: ListenerKind,
    materialized: ListenerKind,
  },

  #[snafu(display(
    "listener '{listener}' resource client auth {materialized:?} does not match linked client auth {linked:?}"
  ))]
  ClientAuthMismatch {
    listener: ListenerId,
    linked: ClientAuthPlan,
    materialized: ClientAuthPlan,
  },

  #[snafu(display("intercepting forward proxy listener '{listener}' has no materialized CA"))]
  MissingProxyCa { listener: ListenerId },

  #[snafu(display("non-intercepting forward proxy listener '{listener}' unexpectedly carries a materialized CA"))]
  UnexpectedProxyCa { listener: ListenerId },

  #[snafu(display("failed to bind {kind:?} listener '{listener}' at '{address}': {source}"))]
  Bind {
    listener: ListenerId,
    kind: ListenerKind,
    address: SocketAddr,
    source: io::Error,
  },
}

pub type ListenerBindResult<T> = std::result::Result<T, ListenerBindError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{link_gateway_runtime, materialize_listeners, RuntimeNameRegistry};
  use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
  use tokn_accounts::registry::Registry;
  use tokn_policy::{
    ConnectAction, ForwardProxyListenerPlan, GatewayPlan, HttpAction, ListenerPlan, LlmApiListenerPlan,
  };

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn reserve_addresses(count: usize) -> (Vec<SocketAddr>, Vec<StdTcpListener>) {
    let reservations = (0..count)
      .map(|_| StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
      .collect::<Vec<_>>();
    let addresses = reservations
      .iter()
      .map(|listener| listener.local_addr().unwrap())
      .collect();
    (addresses, reservations)
  }

  fn llm_listener(address: SocketAddr) -> ListenerPlan {
    ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      address,
      ClientAuthPlan::None,
      Box::default(),
      HttpAction::Reject,
    ))
  }

  fn proxy_listener(address: SocketAddr, connect: ConnectAction) -> ListenerPlan {
    ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      address,
      ClientAuthPlan::None,
      Box::default(),
      HttpAction::Reject,
      Box::default(),
      connect,
      None,
    ))
  }

  fn runtime(listeners: impl IntoIterator<Item = (&'static str, ListenerPlan)>) -> Arc<LinkedGatewayRuntime> {
    let plan = GatewayPlan::new(
      listeners
        .into_iter()
        .map(|(id, listener)| (listener_id(id), listener))
        .collect(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    Arc::new(link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap())
  }

  #[tokio::test]
  async fn bound_state_retains_the_exact_runtime_generation() {
    let (addresses, reservations) = reserve_addresses(1);
    let gateway = runtime([("api", llm_listener(addresses[0]))]);
    let linked_listener = gateway.listeners().listener(&listener_id("api")).unwrap().clone();
    let resources = materialize_listeners(gateway.listeners(), None).unwrap();
    let weak_gateway = Arc::downgrade(&gateway);
    drop(reservations);

    let bound = bind_gateway_listeners(gateway.clone(), resources).await.unwrap();
    let state = bound.listener(&listener_id("api")).unwrap().state();
    assert!(Arc::ptr_eq(state.gateway(), &gateway));
    assert!(Arc::ptr_eq(state.listener(), &linked_listener));
    assert_eq!(
      bound.listener(&listener_id("api")).unwrap().local_addr().unwrap(),
      addresses[0]
    );

    drop(gateway);
    assert!(weak_gateway.upgrade().is_some());
    drop(bound);
    assert!(weak_gateway.upgrade().is_none());
  }

  #[tokio::test]
  async fn listener_set_mismatch_is_rejected_before_binding() {
    let (addresses, reservations) = reserve_addresses(1);
    let gateway = runtime([("expected", llm_listener(addresses[0]))]);
    let other = runtime([("unexpected", llm_listener(addresses[0]))]);
    let resources = materialize_listeners(other.listeners(), None).unwrap();

    let error = bind_gateway_listeners(gateway, resources).await.unwrap_err();
    assert!(matches!(error, ListenerBindError::ListenerSetMismatch { .. }));
    assert_eq!(reservations[0].local_addr().unwrap(), addresses[0]);
  }

  #[tokio::test]
  async fn listener_identity_mismatch_is_rejected_before_binding() {
    let (addresses, reservations) = reserve_addresses(1);
    let gateway = runtime([("api", llm_listener(addresses[0]))]);
    let other = runtime([("api", llm_listener(addresses[0]))]);
    let resources = materialize_listeners(other.listeners(), None).unwrap();

    let error = bind_gateway_listeners(gateway, resources).await.unwrap_err();
    assert!(matches!(error, ListenerBindError::ListenerIdentityMismatch { .. }));
    assert_eq!(reservations[0].local_addr().unwrap(), addresses[0]);
  }

  #[tokio::test]
  async fn later_bind_failure_releases_every_earlier_socket() {
    let (addresses, mut reservations) = reserve_addresses(2);
    let first_address = addresses[0];
    let second_address = addresses[1];
    let second_reservation = reservations.pop().unwrap();
    drop(reservations);
    let gateway = runtime([
      ("a-first", llm_listener(first_address)),
      ("b-second", llm_listener(second_address)),
    ]);
    let resources = materialize_listeners(gateway.listeners(), None).unwrap();

    let error = bind_gateway_listeners(gateway, resources).await.unwrap_err();
    assert!(matches!(
      error,
      ListenerBindError::Bind {
        ref listener,
        address,
        ..
      } if listener == &listener_id("b-second") && address == second_address
    ));
    let rebound = StdTcpListener::bind(first_address).expect("the earlier socket must be released on rollback");
    assert_eq!(rebound.local_addr().unwrap(), first_address);
    drop(second_reservation);
  }

  #[tokio::test]
  async fn tunnel_and_reject_proxies_bind_without_ca_material() {
    let (addresses, reservations) = reserve_addresses(2);
    let gateway = runtime([
      ("reject", proxy_listener(addresses[0], ConnectAction::Reject)),
      ("tunnel", proxy_listener(addresses[1], ConnectAction::Tunnel)),
    ]);
    let resources = materialize_listeners(gateway.listeners(), None).unwrap();
    assert!(resources
      .listeners()
      .all(|(_, resource)| resource.kind().proxy_ca().is_none()));
    drop(reservations);

    let bound = bind_gateway_listeners(gateway, resources).await.unwrap();
    assert_eq!(bound.len(), 2);
    assert!(bound
      .listeners()
      .all(|(_, listener)| listener.state().resource().kind().proxy_ca().is_none()));
  }

  #[tokio::test]
  async fn empty_listener_set_is_valid_for_binding() {
    let gateway = runtime([]);
    let resources = materialize_listeners(gateway.listeners(), None).unwrap();

    let bound = bind_gateway_listeners(gateway, resources).await.unwrap();
    assert!(bound.is_empty());
    assert_eq!(bound.into_listeners().len(), 0);
  }
}

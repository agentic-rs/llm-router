//! Socket startup for a fully linked and materialized gateway.
//!
//! Binding is a separate phase from serving so startup can acquire every
//! configured socket before any listener begins accepting connections.

mod bind;

pub use bind::{
  bind_gateway_listeners, BoundGatewayListeners, BoundListener, ListenerBindError, ListenerBindResult,
  ListenerServerState,
};

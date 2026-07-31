//! Socket startup for a fully linked and materialized gateway.
//!
//! Binding is a separate phase from serving so startup can acquire every
//! configured socket before any listener begins accepting connections.

mod auth;
mod bind;
mod response;

pub use auth::{authenticate_forward_proxy_client, authenticate_llm_api_client, ClientAuthError};
pub use bind::{
  bind_gateway_listeners, BoundGatewayListeners, BoundListener, ListenerBindError, ListenerBindResult,
  ListenerServerState,
};
pub use response::{managed_response_to_axum, opaque_response_to_axum, ResponseBridgeError, ResponseBridgeResult};

//! Socket startup for a fully linked and materialized gateway.
//!
//! Binding is a separate phase from serving so startup can acquire every
//! configured socket before any listener begins accepting connections.

mod adapter;
mod admission;
mod auth;
mod bind;
mod body;
mod connect;
mod error;
mod http;
mod intercept;
mod response;
mod serve;
mod state;
mod tunnel;

pub use admission::{
  admit_forward_proxy_request, admit_intercepted_https_request, admit_llm_api_request, classify_request_kind,
  AdmissionError, AdmittedHttpRequest, AuthorityLocation, ExpectedRequestTarget, ForwardProxyAdmission,
  RequestTargetForm,
};
pub use auth::{authenticate_forward_proxy_client, authenticate_llm_api_client, ClientAuthError};
pub use bind::{bind_gateway_listeners, BoundGatewayListeners, BoundListener, ListenerBindError, ListenerBindResult};
pub use body::{
  buffer_matched_body, BufferedRequestBody, ManagedRequestBody, RequestBodyError, RequestBodyLimits, RequestBodyResult,
};
pub use error::{AuthBoundary, ConnectUpgradeUnavailableReason, ServerError};
pub use http::{handle_admitted_http, request_body_present};
pub use response::{managed_response_to_axum, opaque_response_to_axum, ResponseBridgeError, ResponseBridgeResult};
pub use serve::{serve_gateway_listeners, GatewayServeError, GatewayServeResult};
pub use state::{
  GatewayServerState, GatewayServerStateError, GatewayServerStateResult, GatewayServingDefaults, ListenerServerState,
};
pub use tunnel::{
  BoxTunnelIo, TunnelConnectError, TunnelConnectResult, TunnelConnector, TunnelConnectorBuildError,
  TunnelConnectorBuildResult, TunnelIo,
};

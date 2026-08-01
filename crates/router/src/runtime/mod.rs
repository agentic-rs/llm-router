mod connect;
mod dispatch;
mod execution;
mod gateway;
mod intercept_ca;
mod listeners;
mod matchers;
mod names;
mod profiles;
mod resources;
mod server;

pub use connect::{
  dispatch_connect, ConnectDispatch, ConnectDispatchError, ConnectDispatchResult, ConnectDispatchSite,
};
pub use dispatch::{
  match_http, HttpDispatchError, HttpDispatchResult, HttpDispatchSite, HttpRequestHead, HttpRequestSemantics,
  HttpRouteMatch, MatchedHttpRoute, RoutedHttpDispatch,
};
pub use execution::{
  HttpExecutionCoordinator, HttpExecutionError, HttpExecutionOutcome, HttpExecutionRequest, HttpExecutionResult,
};
pub use gateway::{
  link_builtin_gateway_runtime, link_gateway_runtime, GatewayLinkError, GatewayLinkResult, LinkedGatewayRuntime,
};
pub use intercept_ca::{load_or_generate_ca, ProxyCa};
pub use listeners::{
  link_listeners, BindingKind, ConnectActionSite, HttpActionSite, LinkedConnectDecision, LinkedConnectPolicy,
  LinkedConnectRule, LinkedForwardProxyPolicy, LinkedHttpAction, LinkedHttpBinding, LinkedHttpDecision,
  LinkedHttpPolicy, LinkedListener, LinkedListenerKind, LinkedListeners, ListenerLinkError, ListenerLinkResult,
};
pub use matchers::{
  link_connect_matcher, link_http_matcher, ConnectFactsError, ConnectFactsResult, ConnectRequestFacts,
  HttpRequestFacts, LinkedConnectMatcher, LinkedHttpMatcher, MatcherLinkError, MatcherLinkResult,
};
pub use names::{RuntimeNameError, RuntimeNameRegistry, RuntimeNameResult};
pub use profiles::{
  link_profiles, scan_profile_reachability, LinkedProfile, LinkedProfiles, LinkedWireIdentity, ProfileLinkError,
  ProfileLinkResult, ProfileReachability, ProfileReferenceSite,
};
pub use resources::{
  materialize_listeners, ListenerResourceError, ListenerResourceResult, MaterializedClientAuth, MaterializedListener,
  MaterializedListenerKind, MaterializedListeners,
};
pub use server::{
  admit_forward_proxy_request, admit_intercepted_https_request, admit_llm_api_request,
  authenticate_forward_proxy_client, authenticate_llm_api_client, bind_gateway_listeners, buffer_matched_body,
  classify_request_kind, handle_admitted_http, managed_response_to_axum, opaque_response_to_axum, request_body_present,
  serve_gateway_listeners, AdmissionError, AdmittedHttpRequest, AuthBoundary, AuthorityLocation, BoundGatewayListeners,
  BoundListener, BoxTunnelIo, BufferedRequestBody, ClientAuthError, ConnectUpgradeUnavailableReason,
  ExpectedRequestTarget, ForwardProxyAdmission, GatewayServeError, GatewayServeResult, GatewayServerState,
  GatewayServerStateError, GatewayServerStateResult, GatewayServingDefaults, ListenerBindError, ListenerBindResult,
  ListenerServerState, ManagedRequestBody, RequestBodyError, RequestBodyLimits, RequestBodyResult, RequestTargetForm,
  ResponseBridgeError, ResponseBridgeResult, ServerError, TunnelConnectError, TunnelConnectResult, TunnelConnector,
  TunnelConnectorBuildError, TunnelConnectorBuildResult, TunnelIo,
};

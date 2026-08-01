mod attempts;
mod connect;
mod dispatch;
mod downstream;
mod execution;
mod gateway;
mod intercept_ca;
mod listeners;
mod managed;
mod matchers;
mod names;
mod observation;
mod profiles;
mod resources;
mod routes;
mod server;

pub use connect::{
  dispatch_connect, ConnectDispatch, ConnectDispatchError, ConnectDispatchResult, ConnectDispatchSite,
};
pub use dispatch::{
  match_http, HttpDispatchError, HttpDispatchResult, HttpDispatchSite, HttpRequestHead, HttpRequestSemantics,
  HttpRouteMatch, MatchedHttpRoute, RoutedHttpDispatch,
};
pub(crate) use execution::ObservedHttpExecutionOutcome;
pub use execution::{
  HttpExecutionCoordinator, HttpExecutionError, HttpExecutionOutcome, HttpExecutionRequest, HttpExecutionResult,
};
pub use gateway::{
  link_builtin_gateway_runtime, link_builtin_gateway_runtime_with_profile_roots, link_gateway_runtime,
  link_gateway_runtime_with_profile_roots, GatewayLinkError, GatewayLinkResult, LinkedGatewayRuntime,
};
pub use intercept_ca::{load_or_generate_ca, ProxyCa};
pub use listeners::{
  link_listeners, BindingKind, ConnectActionSite, HttpActionSite, LinkedConnectDecision, LinkedConnectPolicy,
  LinkedConnectRule, LinkedForwardProxyPolicy, LinkedHttpAction, LinkedHttpBinding, LinkedHttpDecision,
  LinkedHttpPolicy, LinkedListener, LinkedListenerKind, LinkedListeners, ListenerLinkError, ListenerLinkResult,
};
pub use managed::{
  ManagedGatewayBuildError, ManagedGatewayBuildResult, ManagedGatewayError, ManagedGatewayExecutor,
  ManagedGatewayOutcome, ManagedGatewayRequest, ManagedGatewayResult, ManagedProfileResolveError,
  ManagedProfileResolveResult, ManagedProfileSite, ManagedRequestBody, ManagedRequestBodyError,
  ManagedRequestBodyResult, ManagedSelectionSummary,
};
pub use matchers::{
  link_connect_matcher, link_http_matcher, ConnectFactsError, ConnectFactsResult, ConnectRequestFacts,
  HttpRequestFacts, LinkedConnectMatcher, LinkedHttpMatcher, MatcherLinkError, MatcherLinkResult,
};
pub use names::{RuntimeNameError, RuntimeNameRegistry, RuntimeNameResult};
pub use profiles::{
  include_embedded_profile_roots, link_profiles, scan_profile_reachability, EmbeddedProfileRoots, LinkedProfile,
  LinkedProfiles, LinkedWireIdentity, ProfileLinkError, ProfileLinkResult, ProfileReachability, ProfileReferenceSite,
};
pub use resources::{
  materialize_listeners, ListenerResourceError, ListenerResourceResult, MaterializedClientAuth, MaterializedListener,
  MaterializedListenerKind, MaterializedListeners,
};
pub use routes::{
  link_routes, LinkedManagedRoute, LinkedRelayRoute, LinkedRoute, LinkedRouteKind, LinkedRoutes,
  LinkedTransparentRoute, RouteLinkError, RouteLinkResult,
};
pub use server::{
  admit_forward_proxy_request, admit_intercepted_https_request, admit_llm_api_request,
  authenticate_forward_proxy_client, authenticate_llm_api_client, bind_gateway_listeners, buffer_matched_body,
  classify_request_kind, handle_admitted_http, managed_response_to_axum, opaque_response_to_axum, request_body_present,
  serve_gateway_listeners, AdmissionError, AdmittedHttpRequest, AuthBoundary, AuthorityLocation, BoundGatewayListeners,
  BoundListener, BoxTunnelIo, BufferedRequestBody, ClientAuthError, ConnectUpgradeUnavailableReason,
  ExpectedRequestTarget, ForwardProxyAdmission, GatewayServeError, GatewayServeResult, GatewayServerState,
  GatewayServerStateError, GatewayServerStateResult, GatewayServingDefaults, ListenerBindError, ListenerBindResult,
  ListenerServerState, RequestBodyAdmission, RequestBodyError, RequestBodyLimits, RequestBodyResult, RequestTargetForm,
  ResponseBridgeError, ResponseBridgeResult, ServerError, TunnelConnectError, TunnelConnectResult, TunnelConnector,
  TunnelConnectorBuildError, TunnelConnectorBuildResult, TunnelIo,
};

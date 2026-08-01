//! Safe client-facing errors for the v2 HTTP serving boundary.
//!
//! Runtime errors retain rich context for diagnostics, but that context may
//! include configured provider names, upstream locations, or transport error
//! text. This module deliberately classifies those errors into a small,
//! stable response contract instead of forwarding their `Display` output.

use super::{AdmissionError, ClientAuthError, RequestBodyError, ResponseBridgeError, TunnelConnectError};
use crate::runtime::{
  ConnectDispatchError, ConnectDispatchSite, HttpDispatchError, HttpDispatchSite, HttpExecutionError,
  ManagedProfileResolveError, ManagedRequestBodyError,
};
use axum::response::{IntoResponse, Response};
use axum::Json;
use http::header::{ALLOW, PROXY_AUTHENTICATE, RETRY_AFTER, WWW_AUTHENTICATE};
use http::{HeaderName, HeaderValue, StatusCode};
use serde::Serialize;
use std::fmt;
use std::time::{Duration, Instant};
use tokn_access::AuthenticationError;
use tokn_accounts::link::{NoEligibleReason, TargetResolveError};
use tokn_events::RequestPhase;
use tokn_policy::ListenerId;
use tokn_requests::execution::{ManagedAttemptError, ManagedResponseError, OpaqueAttemptError};

const BEARER_CHALLENGE: HeaderValue = HeaderValue::from_static("Bearer");

/// Authentication protocol at the listener that rejected a credential.
///
/// HTTP origin authentication and forward-proxy authentication use different
/// statuses and challenge headers. Keeping this fact explicit prevents a
/// context-free `ClientAuthError` conversion from returning the wrong wire
/// protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthBoundary {
  LlmApi,
  ForwardProxy,
}

/// Internal reason a prepared CONNECT upgrade could not be handed off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectUpgradeUnavailableReason {
  MissingToken,
  QueueFull,
  OwnerClosed,
}

impl fmt::Display for ConnectUpgradeUnavailableReason {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::MissingToken => "the HTTP connection supplied no upgrade token",
      Self::QueueFull => "the connection upgrade queue was already full",
      Self::OwnerClosed => "the connection upgrade owner was already closed",
    })
  }
}

/// An error ready to cross the v2 HTTP serving boundary.
#[derive(Debug)]
pub enum ServerError {
  EventPublication {
    phase: RequestPhase,
    source: anyhow::Error,
  },
  Admission(AdmissionError),
  ClientAuth {
    boundary: AuthBoundary,
    source: ClientAuthError,
  },
  ConnectDispatch(ConnectDispatchError),
  ConnectBodyUnsupported {
    listener: ListenerId,
  },
  ConnectRejected {
    site: ConnectDispatchSite,
  },
  ConnectInterceptionSetup {
    site: ConnectDispatchSite,
    source: anyhow::Error,
  },
  TunnelConnect {
    site: ConnectDispatchSite,
    source: TunnelConnectError,
  },
  ConnectUpgradeUnavailable {
    site: ConnectDispatchSite,
    reason: ConnectUpgradeUnavailableReason,
  },
  RequestBody(RequestBodyError),
  RouteRejected {
    site: HttpDispatchSite,
  },
  Dispatch(HttpDispatchError),
  NoEligible {
    site: HttpDispatchSite,
    reason: NoEligibleReason,
  },
  CoolingDown {
    site: HttpDispatchSite,
    retry_at: Instant,
  },
  Execution(HttpExecutionError),
  ResponseBridge(ResponseBridgeError),
}

impl ServerError {
  /// Fail a request when its reliable public lifecycle cannot be published.
  ///
  /// An enabled event hub is part of the serving generation's durability
  /// contract. Continuing without it would make persistence and library
  /// consumers observe a different request history from the wire.
  pub fn event_publication(phase: RequestPhase, source: impl Into<anyhow::Error>) -> Self {
    Self::EventPublication {
      phase,
      source: source.into(),
    }
  }

  /// Classify authentication failure at a direct LLM API listener.
  pub fn llm_auth(source: ClientAuthError) -> Self {
    Self::ClientAuth {
      boundary: AuthBoundary::LlmApi,
      source,
    }
  }

  /// Classify authentication failure at a forward-proxy listener.
  pub fn proxy_auth(source: ClientAuthError) -> Self {
    Self::ClientAuth {
      boundary: AuthBoundary::ForwardProxy,
      source,
    }
  }

  /// Reject CONNECT framing before authentication, policy, or transport I/O.
  pub fn connect_body_unsupported(listener: ListenerId) -> Self {
    Self::ConnectBodyUnsupported { listener }
  }

  /// Preserve the policy location that explicitly rejected CONNECT.
  pub fn connect_rejected(site: ConnectDispatchSite) -> Self {
    Self::ConnectRejected { site }
  }

  /// Preserve a pre-response TLS identity/configuration failure for logs.
  pub fn connect_interception_setup(site: ConnectDispatchSite, source: anyhow::Error) -> Self {
    Self::ConnectInterceptionSetup { site, source }
  }

  /// Preserve the policy location and rich outbound tunnel failure for logs.
  pub fn tunnel_connect(site: ConnectDispatchSite, source: TunnelConnectError) -> Self {
    Self::TunnelConnect { site, source }
  }

  /// Report failure to transfer a prepared upgrade to its connection owner.
  pub fn connect_upgrade_unavailable(site: ConnectDispatchSite, reason: ConnectUpgradeUnavailableReason) -> Self {
    Self::ConnectUpgradeUnavailable { site, reason }
  }

  /// Preserve the policy location that explicitly rejected a matched route.
  pub fn route_rejected(site: HttpDispatchSite) -> Self {
    Self::RouteRejected { site }
  }

  /// Report that one routed decision had no eligible request-time target.
  pub fn no_eligible(site: HttpDispatchSite, reason: NoEligibleReason) -> Self {
    Self::NoEligible { site, reason }
  }

  /// Report that all otherwise eligible bindings are temporarily cooling.
  pub fn cooling_down(site: HttpDispatchSite, retry_at: Instant) -> Self {
    Self::CoolingDown { site, retry_at }
  }

  pub fn status(&self) -> StatusCode {
    self.descriptor().status
  }

  /// Stable lifecycle location at which this request stopped.
  pub fn phase(&self) -> RequestPhase {
    match self {
      Self::EventPublication { phase, .. } => *phase,
      Self::Admission(_) => RequestPhase::Admission,
      Self::ClientAuth { .. } => RequestPhase::Authentication,
      Self::ConnectDispatch(_)
      | Self::ConnectBodyUnsupported { .. }
      | Self::ConnectRejected { .. }
      | Self::ConnectInterceptionSetup { .. }
      | Self::TunnelConnect { .. }
      | Self::ConnectUpgradeUnavailable { .. } => RequestPhase::Connect,
      Self::RequestBody(_) => RequestPhase::RequestBody,
      Self::RouteRejected { .. } => RequestPhase::Policy,
      Self::Dispatch(_) | Self::NoEligible { .. } | Self::CoolingDown { .. } => RequestPhase::TargetSelection,
      Self::Execution(HttpExecutionError::ManagedResponse { .. }) => RequestPhase::UpstreamResponse,
      Self::Execution(_) => RequestPhase::UpstreamRequest,
      Self::ResponseBridge(_) => RequestPhase::DownstreamResponse,
    }
  }

  /// Stable, snake-case machine-readable error code.
  pub fn code(&self) -> &'static str {
    self.descriptor().code
  }

  /// Safe client-facing message that omits runtime source details.
  pub fn message(&self) -> &'static str {
    self.descriptor().message
  }

  pub fn auth_boundary(&self) -> Option<AuthBoundary> {
    match self {
      Self::ClientAuth { boundary, .. } => Some(*boundary),
      _ => None,
    }
  }

  /// Whole-second delay sent in `Retry-After`, rounded upward.
  pub fn retry_after_seconds(&self) -> Option<u64> {
    let Self::CoolingDown { retry_at, .. } = self else {
      return None;
    };
    Some(ceil_seconds(retry_at.saturating_duration_since(Instant::now())))
  }

  fn descriptor(&self) -> ErrorDescriptor {
    match self {
      Self::EventPublication { .. } => ErrorDescriptor::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "event_publication_failed",
        "the request lifecycle could not be recorded",
      ),
      Self::Admission(source) => admission_descriptor(source),
      Self::ClientAuth { boundary, source } => auth_descriptor(*boundary, *source),
      Self::ConnectDispatch(_) | Self::ConnectInterceptionSetup { .. } | Self::ConnectUpgradeUnavailable { .. } => {
        ErrorDescriptor::new(
          StatusCode::INTERNAL_SERVER_ERROR,
          "internal_error",
          "the CONNECT request could not be processed",
        )
      }
      Self::ConnectBodyUnsupported { .. } => ErrorDescriptor::new(
        StatusCode::BAD_REQUEST,
        "invalid_connect_body",
        "CONNECT requests must not contain a body representation",
      ),
      Self::ConnectRejected { .. } => ErrorDescriptor::new(
        StatusCode::FORBIDDEN,
        "connect_rejected",
        "listener policy rejected this CONNECT request",
      ),
      Self::TunnelConnect {
        source: TunnelConnectError::Timeout { .. },
        ..
      } => ErrorDescriptor::new(
        StatusCode::GATEWAY_TIMEOUT,
        "tunnel_timeout",
        "the tunnel could not be established before its deadline",
      ),
      Self::TunnelConnect { .. } => ErrorDescriptor::new(
        StatusCode::BAD_GATEWAY,
        "tunnel_unavailable",
        "the tunnel could not be established",
      ),
      Self::RequestBody(source) => request_body_descriptor(source),
      Self::RouteRejected { .. } => ErrorDescriptor::new(
        StatusCode::FORBIDDEN,
        "route_rejected",
        "listener policy rejected this request",
      ),
      Self::Dispatch(source) => dispatch_descriptor(source),
      Self::NoEligible { reason, .. } => no_eligible_descriptor(reason),
      Self::CoolingDown { .. } => ErrorDescriptor::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "no upstream target is currently available",
      ),
      Self::Execution(source) => execution_descriptor(source),
      Self::ResponseBridge(source) => response_bridge_descriptor(source),
    }
  }

  fn response_header(&self) -> Option<(HeaderName, HeaderValue)> {
    match self {
      Self::Admission(AdmissionError::ConnectMethodRequired { .. }) => {
        Some((ALLOW, HeaderValue::from_static("CONNECT")))
      }
      Self::ClientAuth {
        boundary: AuthBoundary::LlmApi,
        source: ClientAuthError::Rejected(_),
      } => Some((WWW_AUTHENTICATE, BEARER_CHALLENGE)),
      Self::ClientAuth {
        boundary: AuthBoundary::ForwardProxy,
        source: ClientAuthError::Rejected(_),
      } => Some((PROXY_AUTHENTICATE, BEARER_CHALLENGE)),
      Self::CoolingDown { .. } => {
        let value = HeaderValue::from_str(&self.retry_after_seconds().unwrap_or_default().to_string())
          .expect("a decimal u64 is always a valid header value");
        Some((RETRY_AFTER, value))
      }
      _ => None,
    }
  }
}

impl fmt::Display for ServerError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::EventPublication { phase, source } => {
        write!(
          formatter,
          "request lifecycle publication failed during {phase:?}: {source}"
        )
      }
      Self::Admission(source) => write!(formatter, "HTTP request admission failed: {source}"),
      Self::ClientAuth { boundary, source } => {
        write!(formatter, "{boundary:?} client authentication failed: {source}")
      }
      Self::ConnectDispatch(source) => write!(formatter, "CONNECT dispatch failed: {source}"),
      Self::ConnectBodyUnsupported { listener } => {
        write!(formatter, "listener '{listener}' rejected CONNECT request body framing")
      }
      Self::ConnectRejected { site } => write!(formatter, "{site} explicitly rejected CONNECT"),
      Self::ConnectInterceptionSetup { site, source } => {
        write!(formatter, "failed to prepare intercepted TLS for {site}: {source}")
      }
      Self::TunnelConnect { site, source } => write!(formatter, "failed to establish tunnel for {site}: {source}"),
      Self::ConnectUpgradeUnavailable { site, reason } => {
        write!(
          formatter,
          "prepared CONNECT upgrade for {site} was unavailable: {reason}"
        )
      }
      Self::RequestBody(source) => write!(formatter, "HTTP request body admission failed: {source}"),
      Self::RouteRejected { site } => write!(formatter, "{site} explicitly rejected the HTTP request"),
      Self::Dispatch(source) => write!(formatter, "HTTP dispatch failed: {source}"),
      Self::NoEligible { site, reason } => write!(formatter, "{site} found no eligible target: {reason}"),
      Self::CoolingDown { site, retry_at } => {
        write!(
          formatter,
          "all eligible HTTP targets for {site} are cooling until {retry_at:?}"
        )
      }
      Self::Execution(source) => write!(formatter, "HTTP execution failed: {source}"),
      Self::ResponseBridge(source) => write!(formatter, "HTTP response bridging failed: {source}"),
    }
  }
}

impl std::error::Error for ServerError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::EventPublication { source, .. } => Some(source.as_ref()),
      Self::Admission(source) => Some(source),
      Self::ClientAuth { source, .. } => Some(source),
      Self::ConnectDispatch(source) => Some(source),
      Self::ConnectInterceptionSetup { source, .. } => Some(source.as_ref()),
      Self::TunnelConnect { source, .. } => Some(source),
      Self::RequestBody(source) => Some(source),
      Self::Dispatch(source) => Some(source),
      Self::Execution(source) => Some(source),
      Self::ResponseBridge(source) => Some(source),
      Self::ConnectBodyUnsupported { .. }
      | Self::ConnectRejected { .. }
      | Self::ConnectUpgradeUnavailable { .. }
      | Self::RouteRejected { .. }
      | Self::NoEligible { .. }
      | Self::CoolingDown { .. } => None,
    }
  }
}

impl IntoResponse for ServerError {
  fn into_response(self) -> Response {
    let descriptor = self.descriptor();
    let mut response = (
      descriptor.status,
      Json(ErrorEnvelope {
        error: ErrorBody {
          code: descriptor.code,
          message: descriptor.message,
        },
      }),
    )
      .into_response();
    if let Some((name, value)) = self.response_header() {
      response.headers_mut().insert(name, value);
    }
    response
  }
}

impl From<AdmissionError> for ServerError {
  fn from(source: AdmissionError) -> Self {
    Self::Admission(source)
  }
}

impl From<RequestBodyError> for ServerError {
  fn from(source: RequestBodyError) -> Self {
    Self::RequestBody(source)
  }
}

impl From<ConnectDispatchError> for ServerError {
  fn from(source: ConnectDispatchError) -> Self {
    Self::ConnectDispatch(source)
  }
}

impl From<HttpDispatchError> for ServerError {
  fn from(source: HttpDispatchError) -> Self {
    Self::Dispatch(source)
  }
}

impl From<HttpExecutionError> for ServerError {
  fn from(source: HttpExecutionError) -> Self {
    Self::Execution(source)
  }
}

impl From<ResponseBridgeError> for ServerError {
  fn from(source: ResponseBridgeError) -> Self {
    Self::ResponseBridge(source)
  }
}

#[derive(Clone, Copy)]
struct ErrorDescriptor {
  status: StatusCode,
  code: &'static str,
  message: &'static str,
}

impl ErrorDescriptor {
  const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
    Self { status, code, message }
  }
}

fn ceil_seconds(duration: Duration) -> u64 {
  duration
    .as_secs()
    .saturating_add(u64::from(duration.subsec_nanos() != 0))
}

fn admission_descriptor(source: &AdmissionError) -> ErrorDescriptor {
  match source {
    AdmissionError::ConnectMethodRequired { .. } => ErrorDescriptor::new(
      StatusCode::METHOD_NOT_ALLOWED,
      "method_not_allowed",
      "CONNECT is required for an authority-form request target",
    ),
    AdmissionError::NestedConnectUnsupported => ErrorDescriptor::new(
      StatusCode::NOT_IMPLEMENTED,
      "nested_connect_unsupported",
      "CONNECT is not supported inside an intercepted HTTPS connection",
    ),
    AdmissionError::WrongTargetForm { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_request_target",
      "the request target form is not accepted by this listener",
    ),
    AdmissionError::UnsupportedScheme { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_request_target",
      "the request URI scheme is not accepted by this listener",
    ),
    AdmissionError::MissingHost | AdmissionError::MultipleHostValues { .. } | AdmissionError::HostNotUtf8 => {
      ErrorDescriptor::new(
        StatusCode::BAD_REQUEST,
        "invalid_host",
        "the request must contain exactly one valid Host header",
      )
    }
    AdmissionError::InvalidAuthority { .. }
    | AdmissionError::AuthorityMismatch { .. }
    | AdmissionError::InvalidInterceptedIngress { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_authority",
      "the request contains an invalid or conflicting authority",
    ),
    AdmissionError::InvalidPath { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_request_target",
      "the request path is invalid",
    ),
  }
}

fn auth_descriptor(boundary: AuthBoundary, source: ClientAuthError) -> ErrorDescriptor {
  match source {
    ClientAuthError::Unavailable => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "client authentication is unavailable",
    ),
    ClientAuthError::Rejected(AuthenticationError::Missing) => match boundary {
      AuthBoundary::LlmApi => ErrorDescriptor::new(
        StatusCode::UNAUTHORIZED,
        "authentication_required",
        "an API authentication credential is required",
      ),
      AuthBoundary::ForwardProxy => ErrorDescriptor::new(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy_authentication_required",
        "a proxy authentication credential is required",
      ),
    },
    ClientAuthError::Rejected(AuthenticationError::Invalid | AuthenticationError::Revoked) => match boundary {
      AuthBoundary::LlmApi => ErrorDescriptor::new(
        StatusCode::UNAUTHORIZED,
        "authentication_failed",
        "the API authentication credential is invalid",
      ),
      AuthBoundary::ForwardProxy => ErrorDescriptor::new(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy_authentication_failed",
        "the proxy authentication credential is invalid",
      ),
    },
  }
}

fn request_body_descriptor(source: &RequestBodyError) -> ErrorDescriptor {
  match source {
    RequestBodyError::ManagedOperationRequired { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "unsupported_operation",
      "the selected managed route does not support this request operation",
    ),
    RequestBodyError::ManagedBodyRequired => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_request_body",
      "a managed request body is required",
    ),
    RequestBodyError::WireBodyTooLarge { .. } | RequestBodyError::DecodedBodyTooLarge { .. } => ErrorDescriptor::new(
      StatusCode::PAYLOAD_TOO_LARGE,
      "request_body_too_large",
      "the request body exceeds the configured limit",
    ),
    RequestBodyError::UnsupportedContentEncoding { .. } | RequestBodyError::TooManyContentEncodings { .. } => {
      ErrorDescriptor::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_content_encoding",
        "the request content encoding is not supported",
      )
    }
    RequestBodyError::InvalidContentEncodingHeader { .. }
    | RequestBodyError::EmptyContentEncodingMember { .. }
    | RequestBodyError::GzipDecode { .. }
    | RequestBodyError::ZstdDecode { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_content_encoding",
      "the encoded request body is invalid",
    ),
    RequestBodyError::BodyRead { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_request_body",
      "the request body could not be read",
    ),
    RequestBodyError::ManagedProcessingUnavailable { .. } => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "managed request processing is unavailable",
    ),
    RequestBodyError::InvalidManagedJson { .. } => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_request_body",
      "the managed request body must be a valid JSON object",
    ),
    RequestBodyError::InvalidManagedBody { source } => managed_request_body_descriptor(source),
  }
}

fn managed_request_body_descriptor(source: &ManagedRequestBodyError) -> ErrorDescriptor {
  match source {
    ManagedRequestBodyError::ObjectRequired => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_request_body",
      "the managed request body must be a valid JSON object",
    ),
    ManagedRequestBodyError::ModelStringRequired
    | ManagedRequestBodyError::ModelEmpty
    | ManagedRequestBodyError::ModelSurroundingWhitespace => ErrorDescriptor::new(
      StatusCode::BAD_REQUEST,
      "invalid_model",
      "the managed request field 'model' must be a non-empty canonical string",
    ),
  }
}

fn target_resolution_descriptor(_source: &TargetResolveError) -> ErrorDescriptor {
  ErrorDescriptor::new(
    StatusCode::BAD_REQUEST,
    "invalid_model",
    "the qualified model name is invalid",
  )
}

fn managed_profile_resolution_descriptor(source: &ManagedProfileResolveError) -> ErrorDescriptor {
  match source {
    ManagedProfileResolveError::MalformedQualification { source, .. } => target_resolution_descriptor(source),
    ManagedProfileResolveError::NonManagedRoute { .. }
    | ManagedProfileResolveError::MissingProviderWireIdentity { .. } => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "the selected route could not be dispatched",
    ),
  }
}

fn dispatch_descriptor(source: &HttpDispatchError) -> ErrorDescriptor {
  match source {
    HttpDispatchError::ManagedTarget { source, .. } => managed_profile_resolution_descriptor(source),
    HttpDispatchError::ManagedSemanticsRequired { .. }
    | HttpDispatchError::ManagedOperationRequestKindRequired { .. }
    | HttpDispatchError::MissingProviderWireIdentity { .. } => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "the selected route could not be dispatched",
    ),
  }
}

fn no_eligible_descriptor(reason: &NoEligibleReason) -> ErrorDescriptor {
  match reason {
    NoEligibleReason::ProviderAccessDenied => ErrorDescriptor::new(
      StatusCode::FORBIDDEN,
      "provider_access_denied",
      "the authenticated client cannot use the requested provider",
    ),
    NoEligibleReason::ModelSelectorNoMatch { .. }
    | NoEligibleReason::QualifiedTargetUnavailable { .. }
    | NoEligibleReason::CapabilityUnavailable { .. } => ErrorDescriptor::new(
      StatusCode::NOT_FOUND,
      "target_unavailable",
      "no configured target supports the requested model and operation",
    ),
    NoEligibleReason::OriginNotConfigured { .. } => ErrorDescriptor::new(
      StatusCode::NOT_FOUND,
      "target_unavailable",
      "the requested destination is not configured for this route",
    ),
    NoEligibleReason::NoPoolBinding { .. } => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "the selected route could not resolve an upstream target",
    ),
  }
}

fn execution_descriptor(source: &HttpExecutionError) -> ErrorDescriptor {
  match source {
    HttpExecutionError::RequestFamilyMismatch { .. } => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "the selected route could not be executed",
    ),
    HttpExecutionError::ManagedAttempt { source, .. } => managed_attempt_descriptor(source),
    HttpExecutionError::OpaqueAttempt { source, .. } => opaque_attempt_descriptor(source),
    HttpExecutionError::ManagedResponse { source, .. } => managed_response_descriptor(source),
  }
}

fn managed_attempt_descriptor(source: &ManagedAttemptError) -> ErrorDescriptor {
  match source {
    ManagedAttemptError::RequestConversion { .. } | ManagedAttemptError::GenerationControl { .. } => {
      ErrorDescriptor::new(
        StatusCode::BAD_REQUEST,
        "invalid_managed_request",
        "the managed request is not valid for the selected operation",
      )
    }
    ManagedAttemptError::ProviderRequest { .. } => ErrorDescriptor::new(
      StatusCode::BAD_GATEWAY,
      "upstream_unavailable",
      "the upstream request could not be completed",
    ),
    ManagedAttemptError::BodyObjectRequired
    | ManagedAttemptError::DispatchBodyMismatch { .. }
    | ManagedAttemptError::InputTransform { .. }
    | ManagedAttemptError::RequestSerialization { .. } => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "the managed request could not be prepared",
    ),
  }
}

fn opaque_attempt_descriptor(source: &OpaqueAttemptError) -> ErrorDescriptor {
  match source {
    OpaqueAttemptError::Authorization { .. } | OpaqueAttemptError::Transport { .. } => ErrorDescriptor::new(
      StatusCode::BAD_GATEWAY,
      "upstream_unavailable",
      "the upstream request could not be completed",
    ),
    OpaqueAttemptError::InvalidRequestUrl { .. }
    | OpaqueAttemptError::InvalidHeaderName { .. }
    | OpaqueAttemptError::InvalidHeaderValue { .. } => ErrorDescriptor::new(
      StatusCode::INTERNAL_SERVER_ERROR,
      "internal_error",
      "the opaque request could not be prepared",
    ),
  }
}

fn managed_response_descriptor(_source: &ManagedResponseError) -> ErrorDescriptor {
  ErrorDescriptor::new(
    StatusCode::BAD_GATEWAY,
    "invalid_upstream_response",
    "the upstream response could not be processed",
  )
}

fn response_bridge_descriptor(_source: &ResponseBridgeError) -> ErrorDescriptor {
  ErrorDescriptor::new(
    StatusCode::BAD_GATEWAY,
    "invalid_upstream_response",
    "the upstream response cannot be forwarded over this connection",
  )
}

#[derive(Serialize)]
struct ErrorEnvelope {
  error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
  code: &'static str,
  message: &'static str,
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::{to_bytes, Body};
  use http::header::CONTENT_TYPE;
  use http::Method;
  use serde_json::Value;
  use std::io;
  use std::num::NonZeroU16;
  use tokn_core::provider::Error as ProviderError;
  use tokn_policy::{CanonicalHost, ListenerId, ResolvedAuthority};

  fn dispatch_site() -> HttpDispatchSite {
    HttpDispatchSite::new(ListenerId::new("listener").unwrap(), None)
  }

  fn connect_site() -> ConnectDispatchSite {
    ConnectDispatchSite::new(ListenerId::new("proxy").unwrap(), None)
  }

  fn tunnel_target() -> ResolvedAuthority {
    ResolvedAuthority::new(
      CanonicalHost::parse("private.example").unwrap(),
      NonZeroU16::new(8443).unwrap(),
    )
  }

  #[test]
  fn admission_distinguishes_method_errors_and_malformed_targets() {
    let method = ServerError::from(AdmissionError::ConnectMethodRequired { method: Method::GET });
    assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(method.code(), "method_not_allowed");

    let nested = ServerError::from(AdmissionError::NestedConnectUnsupported);
    assert_eq!(nested.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(nested.code(), "nested_connect_unsupported");

    let malformed = ServerError::from(AdmissionError::MissingHost);
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(malformed.code(), "invalid_host");
  }

  #[tokio::test]
  async fn method_error_sets_allow_and_uses_the_minimal_envelope() {
    let response = ServerError::from(AdmissionError::ConnectMethodRequired { method: Method::GET }).into_response();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers().get(ALLOW).unwrap(), "CONNECT");
    assert_eq!(response.headers().get(CONTENT_TYPE).unwrap(), "application/json");
    let body = json_body(response.into_body()).await;
    assert_eq!(body["error"]["code"], "method_not_allowed");
    assert_eq!(
      body["error"]["message"],
      "CONNECT is required for an authority-form request target"
    );
    assert_eq!(body["error"].as_object().unwrap().len(), 2);
  }

  #[test]
  fn authentication_boundary_selects_the_protocol_status() {
    let llm = ServerError::llm_auth(ClientAuthError::Rejected(AuthenticationError::Missing));
    assert_eq!(llm.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(llm.code(), "authentication_required");
    assert_eq!(llm.auth_boundary(), Some(AuthBoundary::LlmApi));

    let proxy = ServerError::proxy_auth(ClientAuthError::Rejected(AuthenticationError::Invalid));
    assert_eq!(proxy.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert_eq!(proxy.code(), "proxy_authentication_failed");
    assert_eq!(proxy.auth_boundary(), Some(AuthBoundary::ForwardProxy));

    let unavailable = ServerError::proxy_auth(ClientAuthError::Unavailable);
    assert_eq!(unavailable.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(unavailable.code(), "internal_error");
  }

  #[test]
  fn authentication_response_uses_the_matching_challenge_header() {
    let llm = ServerError::llm_auth(ClientAuthError::Rejected(AuthenticationError::Missing)).into_response();
    assert_eq!(llm.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
    assert!(!llm.headers().contains_key(PROXY_AUTHENTICATE));

    let proxy = ServerError::proxy_auth(ClientAuthError::Rejected(AuthenticationError::Missing)).into_response();
    assert_eq!(proxy.headers().get(PROXY_AUTHENTICATE).unwrap(), "Bearer");
    assert!(!proxy.headers().contains_key(WWW_AUTHENTICATE));

    let unavailable = ServerError::proxy_auth(ClientAuthError::Unavailable).into_response();
    assert!(!unavailable.headers().contains_key(PROXY_AUTHENTICATE));
  }

  #[test]
  fn connect_errors_preserve_distinct_wire_classifications() {
    let body = ServerError::connect_body_unsupported(ListenerId::new("proxy").unwrap());
    assert_eq!(body.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body.code(), "invalid_connect_body");

    let rejected = ServerError::connect_rejected(connect_site());
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert_eq!(rejected.code(), "connect_rejected");

    let setup = ServerError::connect_interception_setup(connect_site(), anyhow::anyhow!("sensitive TLS setup detail"));
    assert_eq!(setup.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(setup.code(), "internal_error");
    assert!(setup.to_string().contains("sensitive TLS setup detail"));
    assert_eq!(
      std::error::Error::source(&setup).unwrap().to_string(),
      "sensitive TLS setup detail"
    );

    let scheduling =
      ServerError::connect_upgrade_unavailable(connect_site(), ConnectUpgradeUnavailableReason::OwnerClosed);
    assert_eq!(scheduling.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(scheduling.code(), "internal_error");
    assert!(scheduling.to_string().contains("owner was already closed"));

    let full = ServerError::connect_upgrade_unavailable(connect_site(), ConnectUpgradeUnavailableReason::QueueFull);
    assert_eq!(full.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(full.to_string().contains("queue was already full"));

    let dispatch = ServerError::from(ConnectDispatchError::UnsupportedListener {
      listener: ListenerId::new("direct").unwrap(),
    });
    assert_eq!(dispatch.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(dispatch.code(), "internal_error");
  }

  #[test]
  fn tunnel_timeout_and_other_setup_failures_are_distinct() {
    let timeout = ServerError::tunnel_connect(
      connect_site(),
      TunnelConnectError::Timeout {
        target: tunnel_target(),
      },
    );
    assert_eq!(timeout.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(timeout.code(), "tunnel_timeout");

    let rejected = ServerError::tunnel_connect(
      connect_site(),
      TunnelConnectError::ProxyRejected {
        target: tunnel_target(),
        status: 407,
      },
    );
    assert_eq!(rejected.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(rejected.code(), "tunnel_unavailable");
    assert!(rejected.to_string().contains("private.example:8443"));
    assert!(rejected.to_string().contains("407"));
  }

  #[tokio::test]
  async fn tunnel_setup_response_hides_target_and_proxy_details() {
    let response = ServerError::tunnel_connect(
      connect_site(),
      TunnelConnectError::ProxyRejected {
        target: tunnel_target(),
        status: 407,
      },
    )
    .into_response();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();

    assert!(!text.contains("private.example"));
    assert!(!text.contains("8443"));
    assert!(!text.contains("407"));
  }

  #[tokio::test]
  async fn interception_setup_response_hides_source_details() {
    let response =
      ServerError::connect_interception_setup(connect_site(), anyhow::anyhow!("sensitive TLS setup detail"))
        .into_response();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();

    assert!(!text.contains("sensitive TLS setup detail"));
    assert!(!text.contains("TLS"));
  }

  #[test]
  fn body_errors_separate_size_encoding_client_and_internal_failures() {
    let too_large = ServerError::from(RequestBodyError::DecodedBodyTooLarge { limit: 1024 });
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(too_large.code(), "request_body_too_large");

    let unsupported = ServerError::from(RequestBodyError::UnsupportedContentEncoding {
      encoding: "br".to_string(),
    });
    assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(unsupported.code(), "unsupported_content_encoding");

    let malformed = ServerError::from(RequestBodyError::GzipDecode {
      source: io::Error::new(io::ErrorKind::InvalidData, "sensitive decoder detail"),
    });
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(malformed.code(), "invalid_content_encoding");

    let invalid_object = ServerError::from(RequestBodyError::InvalidManagedBody {
      source: ManagedRequestBodyError::ObjectRequired,
    });
    assert_eq!(invalid_object.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid_object.code(), "invalid_request_body");

    let invalid_model = ServerError::from(RequestBodyError::InvalidManagedBody {
      source: ManagedRequestBodyError::ModelEmpty,
    });
    assert_eq!(invalid_model.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid_model.code(), "invalid_model");
  }

  #[tokio::test]
  async fn response_does_not_expose_source_details() {
    let response = ServerError::from(RequestBodyError::GzipDecode {
      source: io::Error::new(io::ErrorKind::InvalidData, "sensitive decoder detail"),
    })
    .into_response();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();

    assert!(!text.contains("sensitive decoder detail"));
    assert!(!text.contains("gzip"));
  }

  #[test]
  fn target_availability_and_access_denial_are_distinct() {
    let unavailable = ServerError::no_eligible(
      dispatch_site(),
      NoEligibleReason::ModelSelectorNoMatch {
        requested_model: "unknown".into(),
      },
    );
    assert_eq!(unavailable.status(), StatusCode::NOT_FOUND);
    assert_eq!(unavailable.code(), "target_unavailable");
    assert!(unavailable.to_string().contains("listener 'listener'"));

    let denied = ServerError::no_eligible(dispatch_site(), NoEligibleReason::ProviderAccessDenied);
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(denied.code(), "provider_access_denied");
  }

  #[test]
  fn attempt_classification_hides_provider_failures() {
    let invariant = managed_attempt_descriptor(&ManagedAttemptError::BodyObjectRequired);
    assert_eq!(invariant.status, StatusCode::INTERNAL_SERVER_ERROR);

    let provider = managed_attempt_descriptor(&ManagedAttemptError::ProviderRequest {
      provider: "private-provider".to_string(),
      source: ProviderError::MissingCredential {
        account: "private-account".to_string(),
        what: "token",
      },
    });
    assert_eq!(provider.status, StatusCode::BAD_GATEWAY);
    assert_eq!(provider.code, "upstream_unavailable");

    let response = managed_response_descriptor(&ManagedResponseError::StreamingProtocolMismatch {
      upstream_operation: tokn_core::provider::Endpoint::Responses,
      content_type: Some("private/type".to_string()),
    });
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    assert_eq!(response.message, "the upstream response could not be processed");
  }

  #[test]
  fn response_bridge_failure_is_a_safe_bad_gateway() {
    let error = ServerError::from(ResponseBridgeError::SwitchingProtocols);

    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(error.code(), "invalid_upstream_response");
    assert_eq!(
      error.message(),
      "the upstream response cannot be forwarded over this connection"
    );
  }

  #[test]
  fn cooling_down_rounds_retry_after_up() {
    assert_eq!(ceil_seconds(Duration::from_millis(1001)), 2);

    let error = ServerError::cooling_down(dispatch_site(), Instant::now() + Duration::from_secs(10));
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.code(), "temporarily_unavailable");
    assert_eq!(error.retry_after_seconds(), Some(10));

    let response = error.into_response();
    assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "10");
  }

  async fn json_body(body: Body) -> Value {
    let bytes = to_bytes(body, usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
  }
}

//! Disclosure-safe projections from server-native request facts into the
//! public gateway event contract.
//!
//! This module owns conversion only. Request lifecycle ownership remains with
//! the listener adapters and response-body boundaries that observe when each
//! fact actually occurs.

use super::{AdmittedHttpRequest, ServerError};
use crate::runtime::observation::{capture_headers, native_correlation};
use crate::runtime::{ConnectDispatch, HttpRouteMatch, LinkedRouteKind};
use axum::response::Response;
use http::Request;
use smol_str::SmolStr;
use tokn_access::AccessContext;
use tokn_core::provider::ProviderRequestKind;
use tokn_events::{
  CapturedUri, ClientIdentity, ConnectAction as EventConnectAction, EventFailure, HttpFamily, HttpResponseHead,
  PolicySelection, RequestAdmitted, RequestOutcome, RequestPhase, RequestSource, RequestStarted, SelectedAction,
};
use tokn_policy::IngressAuthority;
use tokn_requests::{RequestCompletion, RequestTermination};

/// Capture the immutable request facts that exist before admission or
/// authentication mutates the inbound request.
pub(super) fn request_started<B>(source: RequestSource, request: &Request<B>, body_present: bool) -> RequestStarted {
  RequestStarted {
    source,
    http_version: Some(SmolStr::new(format!("{:?}", request.version()))),
    method: SmolStr::new(request.method().as_str()),
    target: CapturedUri::exact(request.uri().to_string()),
    headers: capture_headers(request.headers()),
    body_present,
    correlation: native_correlation(request.headers()),
  }
}

/// Project an admitted HTTP target after the request-target trust boundary has
/// canonicalized its scheme and authority.
pub(super) fn request_admitted_http(admitted: &AdmittedHttpRequest) -> RequestAdmitted {
  let head = admitted.head();
  let operation = match admitted.request_kind() {
    ProviderRequestKind::Operation(endpoint) => Some(SmolStr::new_static(endpoint.as_str())),
    ProviderRequestKind::Models => Some(SmolStr::new_static("models")),
    ProviderRequestKind::Opaque => None,
  };

  RequestAdmitted::Http {
    scheme: SmolStr::new_static(head.ingress().scheme().as_str()),
    authority: SmolStr::new(head.ingress().authority().to_string()),
    path_and_query: CapturedUri::exact(head.path_and_query().as_str()),
    operation,
  }
}

/// Project the canonical destination of an admitted CONNECT request.
pub(super) fn request_admitted_connect(authority: &IngressAuthority) -> RequestAdmitted {
  RequestAdmitted::Connect {
    authority: SmolStr::new(authority.to_string()),
  }
}

/// Project the exact listener decision before body admission can inspect any
/// payload semantics.
pub(super) fn policy_selection(route_match: &HttpRouteMatch) -> PolicySelection {
  let binding_id = route_match
    .site()
    .binding_id()
    .map(|binding| SmolStr::new(binding.as_str()));
  let action = match route_match {
    HttpRouteMatch::Reject(_) => SelectedAction::Reject,
    HttpRouteMatch::Route(matched) => SelectedAction::Http {
      profile_id: SmolStr::new(matched.profile().id().as_str()),
      route_id: SmolStr::new(matched.route().id().as_str()),
      family: match matched.route().kind() {
        LinkedRouteKind::Managed(_) => HttpFamily::Managed,
        LinkedRouteKind::Relay(_) => HttpFamily::Relay,
        LinkedRouteKind::Transparent(_) => HttpFamily::Transparent,
      },
    },
  };
  PolicySelection { binding_id, action }
}

/// Project the exact CONNECT rule/default action selected before any tunnel
/// setup I/O begins.
pub(super) fn connect_policy_selection(dispatch: &ConnectDispatch) -> PolicySelection {
  let binding_id = dispatch.site().rule_id().map(|binding| SmolStr::new(binding.as_str()));
  let action = connect_action(dispatch.action());
  PolicySelection {
    binding_id,
    action: SelectedAction::Connect { action },
  }
}

pub(super) const fn connect_action(action: tokn_policy::ConnectAction) -> EventConnectAction {
  match action {
    tokn_policy::ConnectAction::Intercept => EventConnectAction::Intercept,
    tokn_policy::ConnectAction::Tunnel => EventConnectAction::Tunnel,
    tokn_policy::ConnectAction::Reject => EventConnectAction::Reject,
  }
}

/// Capture the downstream wire head before its body is handed to hyper.
pub(super) fn downstream_response_head(response: &Response) -> HttpResponseHead {
  HttpResponseHead {
    status: response.status().as_u16(),
    headers: capture_headers(response.headers()),
  }
}

/// Expose only the stable, non-secret identity established by listener
/// authentication.
pub(super) fn client_identity(access: &AccessContext) -> ClientIdentity {
  match &access.key_id {
    Some(key_id) => ClientIdentity::LocalKey {
      key_id: SmolStr::new(key_id),
      key_name: access.key_name.as_deref().map(SmolStr::new),
    },
    None => ClientIdentity::Anonymous,
  }
}

/// Convert a server failure without exposing its `Display` chain or source.
pub(super) fn event_failure(error: &ServerError) -> EventFailure {
  EventFailure {
    code: SmolStr::new_static(error.code()),
    message: SmolStr::new_static(error.message()),
  }
}

/// Build the terminal plan for a local error materialized by the server.
///
/// The caller supplies the lifecycle phase because that information belongs
/// to the boundary that caught the error, not to the error's wire descriptor.
pub(super) fn error_termination(error: &ServerError, phase: RequestPhase) -> RequestTermination {
  let status = error.status();
  let outcome = if status.is_client_error() {
    RequestOutcome::Rejected
  } else {
    RequestOutcome::Failed
  };
  RequestTermination::new(RequestCompletion::new(
    outcome,
    phase,
    Some(status.as_u16()),
    Some(event_failure(error)),
  ))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::server::{admit_forward_proxy_request, admit_llm_api_request, AdmissionError, ClientAuthError};
  use http::header::{AUTHORIZATION, COOKIE, HOST};
  use http::{HeaderValue, Method, Version};
  use tokn_access::{AuthenticationError, ProviderAccess};
  use tokn_events::{CapturedHeaderValue, IngressKind};

  fn source() -> RequestSource {
    RequestSource::Listener {
      listener_id: SmolStr::new_static("listener"),
      ingress: IngressKind::LlmApi,
      local_addr: None,
      peer_addr: None,
    }
  }

  #[test]
  fn started_preserves_request_line_and_http_version() {
    let request = Request::builder()
      .method(Method::PATCH)
      .uri("https://api.example/v1/responses?stream=true")
      .version(Version::HTTP_2)
      .body(())
      .unwrap();

    let started = request_started(source(), &request, true);

    assert_eq!(started.method, "PATCH");
    assert_eq!(started.target.as_str(), "https://api.example/v1/responses?stream=true");
    assert!(!started.target.is_redacted());
    assert_eq!(started.http_version.as_deref(), Some("HTTP/2.0"));
    assert!(started.body_present);
    assert_eq!(started.source, source());
  }

  #[test]
  fn headers_preserve_duplicates_and_non_utf8_while_redacting_secrets() {
    let mut request = Request::builder().uri("/").body(()).unwrap();
    request
      .headers_mut()
      .append(AUTHORIZATION, HeaderValue::from_static("Bearer private"));
    request
      .headers_mut()
      .append(COOKIE, HeaderValue::from_static("session=private"));
    request
      .headers_mut()
      .append("x-duplicate", HeaderValue::from_static("first"));
    request
      .headers_mut()
      .append("x-duplicate", HeaderValue::from_bytes(b"\xffsecond").unwrap());

    let started = request_started(source(), &request, false);
    let authorization = started
      .headers
      .iter()
      .find(|header| header.name() == "authorization")
      .unwrap();
    let cookie = started.headers.iter().find(|header| header.name() == "cookie").unwrap();
    let duplicates = started
      .headers
      .iter()
      .filter(|header| header.name() == "x-duplicate")
      .map(|header| header.captured_value())
      .collect::<Vec<_>>();

    assert!(authorization.captured_value().is_redacted());
    assert!(cookie.captured_value().is_redacted());
    assert_eq!(duplicates.len(), 2);
    assert_eq!(duplicates[0].as_bytes(), Some(b"first".as_slice()));
    assert_eq!(duplicates[1].as_bytes(), Some(b"\xffsecond".as_slice()));
    assert!(matches!(authorization.captured_value(), CapturedHeaderValue::Redacted));
  }

  #[test]
  fn correlation_uses_direct_and_consistent_structured_inputs() {
    let mut request = Request::builder().uri("/").body(()).unwrap();
    let headers = request.headers_mut();
    headers.insert("x-client-request-id", HeaderValue::from_static("client-primary"));
    headers.insert("x-request-id", HeaderValue::from_static("client-fallback"));
    headers.insert("session-id", HeaderValue::from_static("session-1"));
    headers.insert("thread-id", HeaderValue::from_static("thread-1"));
    headers.insert("parent-thread-id", HeaderValue::from_static("thread-parent"));
    headers.insert("x-parent-session-id", HeaderValue::from_static("session-parent"));
    headers.insert("x-opencode-project", HeaderValue::from_static("project-1"));
    headers.insert(
      "x-codex-turn-metadata",
      HeaderValue::from_static(
        r#"{"session_id":"session-1","thread_id":"thread-1","parent_thread_id":"metadata-parent","turn_id":"turn-1"}"#,
      ),
    );

    let correlation = request_started(source(), &request, false).correlation;

    assert_eq!(correlation.client_request_id.as_deref(), Some("client-primary"));
    assert_eq!(correlation.session_id.as_deref(), Some("session-1"));
    assert_eq!(correlation.thread_id.as_deref(), Some("thread-1"));
    assert_eq!(correlation.parent_thread_id.as_deref(), Some("thread-parent"));
    assert_eq!(correlation.parent_session_id.as_deref(), Some("session-parent"));
    assert_eq!(correlation.project_id.as_deref(), Some("project-1"));
    assert_eq!(correlation.turn_id.as_deref(), Some("turn-1"));
  }

  #[test]
  fn admitted_http_and_connect_use_canonical_native_facts() {
    let request = Request::builder()
      .method(Method::POST)
      .uri("/v1/responses?stream=true")
      .header(HOST, "api.example")
      .body(())
      .unwrap();
    let admitted = admit_llm_api_request(&request).unwrap();
    assert_eq!(
      request_admitted_http(&admitted),
      RequestAdmitted::Http {
        scheme: SmolStr::new_static("http"),
        authority: SmolStr::new_static("api.example:80"),
        path_and_query: CapturedUri::exact("/v1/responses?stream=true"),
        operation: Some(SmolStr::new_static("responses")),
      }
    );

    let connect = Request::builder()
      .method(Method::CONNECT)
      .uri("api.example:443")
      .body(())
      .unwrap();
    let admitted = admit_forward_proxy_request(&connect).unwrap();
    let super::super::ForwardProxyAdmission::Connect(authority) = admitted else {
      panic!("expected CONNECT admission")
    };
    assert_eq!(
      request_admitted_connect(&authority),
      RequestAdmitted::Connect {
        authority: SmolStr::new_static("api.example:443"),
      }
    );
  }

  #[test]
  fn access_context_projects_only_non_secret_identity() {
    assert_eq!(
      client_identity(&AccessContext::unrestricted()),
      ClientIdentity::Anonymous
    );

    let access = AccessContext {
      key_id: Some("key-1".to_string()),
      key_name: Some("automation".to_string()),
      providers: ProviderAccess::All,
    };
    assert_eq!(
      client_identity(&access),
      ClientIdentity::LocalKey {
        key_id: SmolStr::new_static("key-1"),
        key_name: Some(SmolStr::new_static("automation")),
      }
    );
  }

  #[test]
  fn local_error_termination_uses_only_safe_wire_descriptors() {
    let cases = [
      (
        ServerError::Admission(AdmissionError::MissingHost),
        RequestPhase::Admission,
        400,
        "invalid_host",
        "the request must contain exactly one valid Host header",
        RequestOutcome::Rejected,
      ),
      (
        ServerError::llm_auth(ClientAuthError::Rejected(AuthenticationError::Missing)),
        RequestPhase::Authentication,
        401,
        "authentication_required",
        "an API authentication credential is required",
        RequestOutcome::Rejected,
      ),
      (
        ServerError::ResponseBridge(super::super::ResponseBridgeError::SwitchingProtocols),
        RequestPhase::DownstreamResponse,
        502,
        "invalid_upstream_response",
        "the upstream response cannot be forwarded over this connection",
        RequestOutcome::Failed,
      ),
    ];

    for (error, phase, status, code, message, outcome) in cases {
      let termination = error_termination(&error, phase);
      let completion = termination.completion();
      assert_eq!(completion.outcome, outcome);
      assert_eq!(completion.phase, phase);
      assert_eq!(completion.downstream_status, Some(status));
      assert_eq!(completion.failure.as_ref().unwrap().code, code);
      assert_eq!(completion.failure.as_ref().unwrap().message, message);
      assert!(termination.events().is_empty());
    }
  }
}

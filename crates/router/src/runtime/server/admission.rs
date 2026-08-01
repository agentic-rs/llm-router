//! Strict HTTP request admission for v2 listeners.
//!
//! This module is the request-target trust boundary. It turns the potentially
//! ambiguous URI and `Host` header carried by an HTTP request into one typed,
//! immutable ingress authority before listener matching or request-body
//! processing begins.

use super::super::HttpRequestHead;
use http::header::HOST;
use http::uri::PathAndQuery;
use http::{HeaderMap, Method, Request, Uri};
use std::fmt;
use tokn_core::provider::{Endpoint, ProviderRequestKind};
use tokn_policy::{
  AuthorityMismatch, CanonicalAuthority, HttpIngress, HttpIngressError, HttpScheme, IngressAuthority, InvalidAuthority,
  InvalidHttpPath,
};

/// An admitted non-CONNECT HTTP request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedHttpRequest {
  head: HttpRequestHead,
  request_kind: ProviderRequestKind,
}

impl AdmittedHttpRequest {
  pub fn head(&self) -> &HttpRequestHead {
    &self.head
  }

  pub fn request_kind(&self) -> ProviderRequestKind {
    self.request_kind
  }

  pub fn into_parts(self) -> (HttpRequestHead, ProviderRequestKind) {
    (self.head, self.request_kind)
  }
}

/// A request admitted at a forward-proxy listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardProxyAdmission {
  /// An absolute-form cleartext HTTP request.
  Http(AdmittedHttpRequest),
  /// A CONNECT request with an explicit, nonzero destination port.
  Connect(IngressAuthority),
}

/// The syntactic request-target form observed at the listener boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestTargetForm {
  Origin,
  Absolute,
  Authority,
  Asterisk,
  Relative,
}

impl fmt::Display for RequestTargetForm {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::Origin => "origin-form",
      Self::Absolute => "absolute-form",
      Self::Authority => "authority-form",
      Self::Asterisk => "asterisk-form",
      Self::Relative => "relative-form",
    })
  }
}

/// The request-target form required by a particular listener boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedRequestTarget {
  Origin,
  AbsoluteHttp,
  Authority,
  OriginOrAbsoluteHttps,
}

impl fmt::Display for ExpectedRequestTarget {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::Origin => "origin-form",
      Self::AbsoluteHttp => "absolute-form with an HTTP URI",
      Self::Authority => "authority-form",
      Self::OriginOrAbsoluteHttps => "origin-form or absolute-form with an HTTPS URI",
    })
  }
}

/// Identifies which untrusted authority failed admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityLocation {
  RequestTarget,
  HostHeader,
}

impl fmt::Display for AuthorityLocation {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::RequestTarget => "request-target authority",
      Self::HostHeader => "Host header authority",
    })
  }
}

/// A request that could not cross the HTTP listener trust boundary.
///
/// `ConnectMethodRequired` is the only method-specific failure and can be
/// mapped to 405. The remaining variants describe malformed or conflicting
/// request metadata and can be mapped to 400 without string inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
  WrongTargetForm {
    expected: ExpectedRequestTarget,
    found: RequestTargetForm,
  },
  ConnectMethodRequired {
    method: Method,
  },
  NestedConnectUnsupported,
  UnsupportedScheme {
    expected: HttpScheme,
    found: String,
  },
  MissingHost,
  MultipleHostValues {
    count: usize,
  },
  HostNotUtf8,
  InvalidAuthority {
    location: AuthorityLocation,
    source: InvalidAuthority,
  },
  AuthorityMismatch {
    location: AuthorityLocation,
    source: AuthorityMismatch,
  },
  InvalidInterceptedIngress {
    source: HttpIngressError,
  },
  InvalidPath {
    source: InvalidHttpPath,
  },
}

impl fmt::Display for AdmissionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::WrongTargetForm { expected, found } => {
        write!(formatter, "expected {expected} request target, found {found}")
      }
      Self::ConnectMethodRequired { method } => {
        write!(
          formatter,
          "authority-form request target requires CONNECT, found {method}"
        )
      }
      Self::NestedConnectUnsupported => {
        formatter.write_str("CONNECT is not supported inside an intercepted HTTPS connection")
      }
      Self::UnsupportedScheme { expected, found } => {
        write!(formatter, "expected {expected} URI scheme, found `{found}`")
      }
      Self::MissingHost => formatter.write_str("origin-form request requires exactly one Host header"),
      Self::MultipleHostValues { count } => {
        write!(
          formatter,
          "request contains {count} Host header values; exactly one is allowed"
        )
      }
      Self::HostNotUtf8 => formatter.write_str("Host header is not valid UTF-8"),
      Self::InvalidAuthority { location, source } => write!(formatter, "invalid {location}: {source}"),
      Self::AuthorityMismatch { location, source } => write!(formatter, "conflicting {location}: {source}"),
      Self::InvalidInterceptedIngress { source } => write!(formatter, "invalid intercepted HTTPS ingress: {source}"),
      Self::InvalidPath { source } => write!(formatter, "invalid HTTP request path: {source}"),
    }
  }
}

impl std::error::Error for AdmissionError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::InvalidAuthority { source, .. } => Some(source),
      Self::AuthorityMismatch { source, .. } => Some(source),
      Self::InvalidInterceptedIngress { source } => Some(source),
      Self::InvalidPath { source } => Some(source),
      Self::WrongTargetForm { .. }
      | Self::ConnectMethodRequired { .. }
      | Self::NestedConnectUnsupported
      | Self::UnsupportedScheme { .. }
      | Self::MissingHost
      | Self::MultipleHostValues { .. }
      | Self::HostNotUtf8 => None,
    }
  }
}

/// Admit one direct LLM API request.
///
/// Direct API listeners accept origin-form only. Their single `Host` header
/// becomes the immutable HTTP ingress authority, with an omitted port resolved
/// to 80.
pub fn admit_llm_api_request<B>(request: &Request<B>) -> Result<AdmittedHttpRequest, AdmissionError> {
  require_target_form(request.uri(), ExpectedRequestTarget::Origin, RequestTargetForm::Origin)?;
  let authority = required_host(request.headers())?;
  admitted_http_request(request, HttpIngress::direct(HttpScheme::Http, authority))
}

/// Admit one request received by a cleartext forward-proxy listener.
///
/// Non-CONNECT requests must use an absolute `http` URI. CONNECT requests must
/// use authority-form and name an explicit, nonzero port.
pub fn admit_forward_proxy_request<B>(request: &Request<B>) -> Result<ForwardProxyAdmission, AdmissionError> {
  let form = request_target_form(request.uri());
  if request.method() == Method::CONNECT {
    require_target_form(
      request.uri(),
      ExpectedRequestTarget::Authority,
      RequestTargetForm::Authority,
    )?;
    let target = parse_uri_authority(request.uri())?;
    let ingress =
      IngressAuthority::from_connect_authority(target).map_err(|source| AdmissionError::InvalidAuthority {
        location: AuthorityLocation::RequestTarget,
        source,
      })?;
    if let Some(host) = optional_host(request.headers())? {
      require_explicit_port(host.clone(), AuthorityLocation::HostHeader)?;
      ingress
        .validate_inner(host, HttpScheme::Https.default_port())
        .map_err(|source| AdmissionError::AuthorityMismatch {
          location: AuthorityLocation::HostHeader,
          source,
        })?;
    }
    return Ok(ForwardProxyAdmission::Connect(ingress));
  }

  if form == RequestTargetForm::Authority {
    return Err(AdmissionError::ConnectMethodRequired {
      method: request.method().clone(),
    });
  }
  require_target_form(
    request.uri(),
    ExpectedRequestTarget::AbsoluteHttp,
    RequestTargetForm::Absolute,
  )?;
  require_scheme(request.uri(), HttpScheme::Http)?;
  let target = parse_uri_authority(request.uri())?;
  let ingress = HttpIngress::direct(HttpScheme::Http, target);
  if let Some(host) = optional_host(request.headers())? {
    ingress
      .authority()
      .validate_inner(host, HttpScheme::Http.default_port())
      .map_err(|source| AdmissionError::AuthorityMismatch {
        location: AuthorityLocation::HostHeader,
        source,
      })?;
  }
  admitted_http_request(request, ingress).map(ForwardProxyAdmission::Http)
}

/// Admit one HTTPS request decoded inside an intercepted CONNECT tunnel.
///
/// The returned ingress always retains `connect` as its immutable destination.
/// Inner origin-form and absolute-form authorities are validation evidence
/// only; they can never replace the CONNECT target.
pub fn admit_intercepted_https_request<B>(
  request: &Request<B>,
  connect: &IngressAuthority,
) -> Result<AdmittedHttpRequest, AdmissionError> {
  if request.method() == Method::CONNECT {
    return Err(AdmissionError::NestedConnectUnsupported);
  }
  let ingress = match request_target_form(request.uri()) {
    RequestTargetForm::Origin => {
      let host = required_host(request.headers())?;
      intercepted_ingress(connect, host, AuthorityLocation::HostHeader)?
    }
    RequestTargetForm::Absolute => {
      require_scheme(request.uri(), HttpScheme::Https)?;
      let target = parse_uri_authority(request.uri())?;
      let ingress = intercepted_ingress(connect, target, AuthorityLocation::RequestTarget)?;
      if let Some(host) = optional_host(request.headers())? {
        connect
          .validate_inner(host, HttpScheme::Https.default_port())
          .map_err(|source| AdmissionError::AuthorityMismatch {
            location: AuthorityLocation::HostHeader,
            source,
          })?;
      }
      ingress
    }
    found => {
      return Err(AdmissionError::WrongTargetForm {
        expected: ExpectedRequestTarget::OriginOrAbsoluteHttps,
        found,
      });
    }
  };
  admitted_http_request(request, ingress)
}

/// Classify the operation implied by an admitted request method and path.
///
/// Query parameters are ignored. Paths are not normalized: in particular, a
/// trailing slash prevents an operation or models match.
pub fn classify_request_kind(method: &Method, path_and_query: &PathAndQuery) -> ProviderRequestKind {
  let path = path_and_query.path();
  if method == Method::POST {
    if path.ends_with("/chat/completions") {
      ProviderRequestKind::Operation(Endpoint::ChatCompletions)
    } else if path.ends_with("/responses") {
      ProviderRequestKind::Operation(Endpoint::Responses)
    } else if path.ends_with("/messages") {
      ProviderRequestKind::Operation(Endpoint::Messages)
    } else {
      ProviderRequestKind::Opaque
    }
  } else if method == Method::GET && path.ends_with("/models") {
    ProviderRequestKind::Models
  } else {
    ProviderRequestKind::Opaque
  }
}

fn admitted_http_request<B>(request: &Request<B>, ingress: HttpIngress) -> Result<AdmittedHttpRequest, AdmissionError> {
  let path_and_query = request
    .uri()
    .path_and_query()
    .cloned()
    .unwrap_or_else(|| PathAndQuery::from_static("/"));
  let request_kind = classify_request_kind(request.method(), &path_and_query);
  let head = HttpRequestHead::new(ingress, request.method().clone(), path_and_query)
    .map_err(|source| AdmissionError::InvalidPath { source })?;
  Ok(AdmittedHttpRequest { head, request_kind })
}

fn request_target_form(uri: &Uri) -> RequestTargetForm {
  match (uri.scheme().is_some(), uri.authority().is_some()) {
    (true, true) => RequestTargetForm::Absolute,
    (false, true) if uri.path_and_query().is_none() => RequestTargetForm::Authority,
    (false, false) if uri.path() == "*" => RequestTargetForm::Asterisk,
    (false, false) if uri.path().starts_with('/') => RequestTargetForm::Origin,
    _ => RequestTargetForm::Relative,
  }
}

fn require_target_form(
  uri: &Uri,
  expected: ExpectedRequestTarget,
  required: RequestTargetForm,
) -> Result<(), AdmissionError> {
  let found = request_target_form(uri);
  if found == required {
    Ok(())
  } else {
    Err(AdmissionError::WrongTargetForm { expected, found })
  }
}

fn require_scheme(uri: &Uri, expected: HttpScheme) -> Result<(), AdmissionError> {
  let found = uri.scheme_str().unwrap_or_default();
  if found.eq_ignore_ascii_case(expected.as_str()) {
    Ok(())
  } else {
    Err(AdmissionError::UnsupportedScheme {
      expected,
      found: found.to_owned(),
    })
  }
}

fn parse_uri_authority(uri: &Uri) -> Result<CanonicalAuthority, AdmissionError> {
  let raw = uri
    .authority()
    .expect("request-target form validation guarantees an authority")
    .as_str();
  parse_authority(raw, AuthorityLocation::RequestTarget)
}

fn required_host(headers: &HeaderMap) -> Result<CanonicalAuthority, AdmissionError> {
  optional_host(headers)?.ok_or(AdmissionError::MissingHost)
}

fn optional_host(headers: &HeaderMap) -> Result<Option<CanonicalAuthority>, AdmissionError> {
  let mut values = headers.get_all(HOST).iter();
  let Some(value) = values.next() else {
    return Ok(None);
  };
  if values.next().is_some() {
    return Err(AdmissionError::MultipleHostValues {
      count: 2 + values.count(),
    });
  }
  let raw = value.to_str().map_err(|_| AdmissionError::HostNotUtf8)?;
  parse_authority(raw, AuthorityLocation::HostHeader).map(Some)
}

fn parse_authority(raw: &str, location: AuthorityLocation) -> Result<CanonicalAuthority, AdmissionError> {
  CanonicalAuthority::parse(raw).map_err(|source| AdmissionError::InvalidAuthority { location, source })
}

fn require_explicit_port(authority: CanonicalAuthority, location: AuthorityLocation) -> Result<(), AdmissionError> {
  IngressAuthority::from_connect_authority(authority)
    .map(|_| ())
    .map_err(|source| AdmissionError::InvalidAuthority { location, source })
}

fn intercepted_ingress(
  connect: &IngressAuthority,
  inner: CanonicalAuthority,
  location: AuthorityLocation,
) -> Result<HttpIngress, AdmissionError> {
  HttpIngress::intercepted_https(connect, inner).map_err(|error| match error {
    HttpIngressError::AuthorityMismatch(source) => AdmissionError::AuthorityMismatch { location, source },
    source @ HttpIngressError::ConnectIngressRequired { .. } => AdmissionError::InvalidInterceptedIngress { source },
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::header::HeaderValue;

  fn make_request(method: Method, target: &str, hosts: &[HeaderValue]) -> Request<()> {
    let mut request = Request::builder().method(method).uri(target).body(()).unwrap();
    for host in hosts {
      request.headers_mut().append(HOST, host.clone());
    }
    request
  }

  fn host(value: &'static str) -> HeaderValue {
    HeaderValue::from_static(value)
  }

  fn connect_authority(value: &str) -> IngressAuthority {
    IngressAuthority::from_connect(value).unwrap()
  }

  #[test]
  fn llm_api_admits_only_origin_form_with_one_host() {
    let request = make_request(
      Method::POST,
      "/prefix/responses?stream=true",
      &[host("API.Example.test")],
    );
    let admitted = admit_llm_api_request(&request).unwrap();

    assert_eq!(admitted.head().ingress().scheme(), HttpScheme::Http);
    assert_eq!(admitted.head().ingress().host().as_str(), "api.example.test");
    assert_eq!(admitted.head().ingress().port(), 80);
    assert_eq!(
      admitted.head().path_and_query().as_str(),
      "/prefix/responses?stream=true"
    );
    assert_eq!(
      admitted.request_kind(),
      ProviderRequestKind::Operation(Endpoint::Responses)
    );

    for target in ["http://api.example.test/responses", "*", "relative"] {
      let request = make_request(Method::POST, target, &[host("api.example.test")]);
      assert!(matches!(
        admit_llm_api_request(&request),
        Err(AdmissionError::WrongTargetForm { .. })
      ));
    }
    assert_eq!(
      admit_llm_api_request(&make_request(Method::GET, "/models", &[])),
      Err(AdmissionError::MissingHost)
    );
  }

  #[test]
  fn host_must_be_single_utf8_and_strictly_canonicalizable() {
    let duplicate = make_request(
      Method::GET,
      "/models",
      &[host("api.example.test"), host("api.example.test")],
    );
    assert_eq!(
      admit_llm_api_request(&duplicate),
      Err(AdmissionError::MultipleHostValues { count: 2 })
    );

    let non_utf8 = make_request(Method::GET, "/models", &[HeaderValue::from_bytes(&[0xff]).unwrap()]);
    assert_eq!(admit_llm_api_request(&non_utf8), Err(AdmissionError::HostNotUtf8));

    for invalid in ["api.example.test.", "127.1", "0x7f000001", "user@api.example.test"] {
      let request = make_request(Method::GET, "/models", &[host(invalid)]);
      assert!(matches!(
        admit_llm_api_request(&request),
        Err(AdmissionError::InvalidAuthority {
          location: AuthorityLocation::HostHeader,
          ..
        })
      ));
    }
  }

  #[test]
  fn forward_http_uses_absolute_authority_and_resolves_default_ports() {
    for host_header in [None, Some("api.example.test"), Some("api.example.test:80")] {
      let hosts = host_header.map_or_else(Vec::new, |value| vec![host(value)]);
      let request = make_request(Method::GET, "http://API.Example.test/v1/models?available=true", &hosts);
      let ForwardProxyAdmission::Http(admitted) = admit_forward_proxy_request(&request).unwrap() else {
        panic!("expected HTTP admission");
      };
      assert_eq!(admitted.head().ingress().host().as_str(), "api.example.test");
      assert_eq!(admitted.head().ingress().port(), 80);
      assert_eq!(admitted.request_kind(), ProviderRequestKind::Models);
      assert_eq!(admitted.head().path_and_query().as_str(), "/v1/models?available=true");
    }
  }

  #[test]
  fn forward_http_rejects_non_http_forms_and_conflicting_hosts() {
    let https = make_request(Method::GET, "https://api.example.test/models", &[]);
    assert!(matches!(
      admit_forward_proxy_request(&https),
      Err(AdmissionError::UnsupportedScheme {
        expected: HttpScheme::Http,
        ..
      })
    ));

    for target in ["/models", "*"] {
      let request = make_request(Method::GET, target, &[host("api.example.test")]);
      assert!(matches!(
        admit_forward_proxy_request(&request),
        Err(AdmissionError::WrongTargetForm {
          expected: ExpectedRequestTarget::AbsoluteHttp,
          ..
        })
      ));
    }

    let mismatch = make_request(
      Method::GET,
      "http://api.example.test:8080/models",
      &[host("api.example.test")],
    );
    assert!(matches!(
      admit_forward_proxy_request(&mismatch),
      Err(AdmissionError::AuthorityMismatch {
        location: AuthorityLocation::HostHeader,
        ..
      })
    ));
  }

  #[test]
  fn connect_requires_authority_form_and_explicit_matching_ports() {
    let request = make_request(
      Method::CONNECT,
      "API.Example.test:0443",
      &[host("api.example.test:443")],
    );
    let ForwardProxyAdmission::Connect(admitted) = admit_forward_proxy_request(&request).unwrap() else {
      panic!("expected CONNECT admission");
    };
    assert_eq!(admitted.host().as_str(), "api.example.test");
    assert_eq!(admitted.port(), 443);

    for target in ["api.example.test", "api.example.test:0"] {
      let request = make_request(Method::CONNECT, target, &[]);
      assert!(matches!(
        admit_forward_proxy_request(&request),
        Err(AdmissionError::InvalidAuthority {
          location: AuthorityLocation::RequestTarget,
          ..
        })
      ));
    }

    for invalid_host in ["api.example.test", "api.example.test:8443"] {
      let request = make_request(Method::CONNECT, "api.example.test:443", &[host(invalid_host)]);
      assert!(admit_forward_proxy_request(&request).is_err());
    }

    let wrong_form = make_request(Method::CONNECT, "/tunnel", &[host("api.example.test:443")]);
    assert!(matches!(
      admit_forward_proxy_request(&wrong_form),
      Err(AdmissionError::WrongTargetForm {
        expected: ExpectedRequestTarget::Authority,
        ..
      })
    ));

    let wrong_method = make_request(Method::GET, "api.example.test:443", &[]);
    assert_eq!(
      admit_forward_proxy_request(&wrong_method),
      Err(AdmissionError::ConnectMethodRequired { method: Method::GET })
    );
  }

  #[test]
  fn intercepted_origin_form_is_pinned_to_connect_authority() {
    let connect = connect_authority("api.example.test:443");
    let request = make_request(Method::POST, "/v1/messages", &[host("API.Example.test")]);
    let admitted = admit_intercepted_https_request(&request, &connect).unwrap();

    assert_eq!(admitted.head().ingress().authority(), &connect);
    assert_eq!(admitted.head().ingress().scheme(), HttpScheme::Https);
    assert_eq!(
      admitted.request_kind(),
      ProviderRequestKind::Operation(Endpoint::Messages)
    );

    let nondefault = connect_authority("api.example.test:8443");
    assert!(matches!(
      admit_intercepted_https_request(&request, &nondefault),
      Err(AdmissionError::AuthorityMismatch {
        location: AuthorityLocation::HostHeader,
        ..
      })
    ));
  }

  #[test]
  fn intercepted_https_rejects_nested_connect_independent_of_target_form() {
    let connect = connect_authority("api.example.test:443");

    for target in ["nested.example.test:443", "/tunnel", "https://api.example.test/tunnel"] {
      let request = make_request(Method::CONNECT, target, &[]);
      assert_eq!(
        admit_intercepted_https_request(&request, &connect),
        Err(AdmissionError::NestedConnectUnsupported)
      );
    }
  }

  #[test]
  fn intercepted_absolute_form_validates_target_and_optional_host() {
    let connect = connect_authority("api.example.test:443");
    for hosts in [Vec::new(), vec![host("api.example.test:443")]] {
      let request = make_request(
        Method::POST,
        "https://api.example.test/v1/chat/completions?stream=1",
        &hosts,
      );
      let admitted = admit_intercepted_https_request(&request, &connect).unwrap();
      assert_eq!(admitted.head().ingress().authority(), &connect);
      assert_eq!(
        admitted.request_kind(),
        ProviderRequestKind::Operation(Endpoint::ChatCompletions)
      );
    }

    let wrong_scheme = make_request(Method::GET, "http://api.example.test/models", &[]);
    assert!(matches!(
      admit_intercepted_https_request(&wrong_scheme, &connect),
      Err(AdmissionError::UnsupportedScheme {
        expected: HttpScheme::Https,
        ..
      })
    ));

    let wrong_target = make_request(Method::GET, "https://other.example.test/models", &[]);
    assert!(matches!(
      admit_intercepted_https_request(&wrong_target, &connect),
      Err(AdmissionError::AuthorityMismatch {
        location: AuthorityLocation::RequestTarget,
        ..
      })
    ));

    let wrong_host = make_request(
      Method::GET,
      "https://api.example.test/models",
      &[host("other.example.test")],
    );
    assert!(matches!(
      admit_intercepted_https_request(&wrong_host, &connect),
      Err(AdmissionError::AuthorityMismatch {
        location: AuthorityLocation::HostHeader,
        ..
      })
    ));
  }

  #[test]
  fn intercepted_requests_require_connect_sourced_ingress() {
    let direct = HttpIngress::direct(
      HttpScheme::Https,
      CanonicalAuthority::parse("api.example.test").unwrap(),
    );
    let request = make_request(Method::GET, "/models", &[host("api.example.test")]);
    assert!(matches!(
      admit_intercepted_https_request(&request, direct.authority()),
      Err(AdmissionError::InvalidInterceptedIngress { .. })
    ));
  }

  #[test]
  fn classifier_is_method_aware_and_does_not_normalize_paths() {
    for (method, target, expected) in [
      (
        Method::POST,
        "/v1/chat/completions?stream=true",
        ProviderRequestKind::Operation(Endpoint::ChatCompletions),
      ),
      (
        Method::POST,
        "/responses?stream=true",
        ProviderRequestKind::Operation(Endpoint::Responses),
      ),
      (
        Method::POST,
        "/vendor/messages",
        ProviderRequestKind::Operation(Endpoint::Messages),
      ),
      (Method::GET, "/v1/models?fresh=true", ProviderRequestKind::Models),
      (Method::GET, "/responses", ProviderRequestKind::Opaque),
      (Method::POST, "/models", ProviderRequestKind::Opaque),
      (Method::POST, "/responses/", ProviderRequestKind::Opaque),
      (Method::GET, "/models/", ProviderRequestKind::Opaque),
    ] {
      let uri: Uri = target.parse().unwrap();
      assert_eq!(
        classify_request_kind(&method, uri.path_and_query().unwrap()),
        expected,
        "classified {method} {target} incorrectly"
      );
    }
  }

  #[test]
  fn admitted_path_retains_query_but_rejects_dot_segments() {
    let request = make_request(Method::GET, "/safe/%7evalue?q=%2f", &[host("api.example.test")]);
    let admitted = admit_llm_api_request(&request).unwrap();
    assert_eq!(admitted.head().path_and_query().as_str(), "/safe/%7evalue?q=%2f");

    for target in ["/v1/../secret", "/v1/.%2e/secret"] {
      let request = make_request(Method::GET, target, &[host("api.example.test")]);
      assert!(matches!(
        admit_llm_api_request(&request),
        Err(AdmissionError::InvalidPath {
          source: InvalidHttpPath::DotSegment
        })
      ));
    }
  }

  #[test]
  fn absolute_target_authority_uses_strict_security_parser() {
    for target in [
      "http://api.example.test./models",
      "http://127.1/models",
      "http://0x7f000001/models",
      "http://user@api.example.test/models",
    ] {
      let request = make_request(Method::GET, target, &[]);
      assert!(matches!(
        admit_forward_proxy_request(&request),
        Err(AdmissionError::InvalidAuthority {
          location: AuthorityLocation::RequestTarget,
          ..
        })
      ));
    }
  }
}

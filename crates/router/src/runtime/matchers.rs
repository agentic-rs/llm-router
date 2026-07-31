//! Linked request matchers for compiled listener policy.
//!
//! Configuration compilation validates file input, but policy values have
//! public constructors. Linking repeats the runtime-critical validation and
//! resolves symbolic operation names before a listener can bind.

use super::RuntimeNameRegistry;
use smol_str::SmolStr;
use snafu::Snafu;
use tokn_core::provider::Endpoint;
use tokn_policy::{
  BindingId, CanonicalHttpPath, ConnectMatch, HostPattern, HttpIngress, HttpMatch, HttpPathPrefix, IngressAuthority,
  IngressAuthoritySource, ListenerId, OperationId,
};

/// Immutable facts used to evaluate one linked HTTP matcher.
///
/// `ingress` has crossed the typed HTTP checkpoint. For intercepted traffic
/// it retains the validated CONNECT authority, rather than an inner request's
/// Host header.
#[derive(Clone, Copy, Debug)]
pub struct HttpRequestFacts<'a> {
  pub ingress: &'a HttpIngress,
  pub path: &'a CanonicalHttpPath,
  pub method: &'a str,
  pub operation: Option<Endpoint>,
}

/// A fully resolved HTTP match expression ready for request evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedHttpMatcher {
  hosts: Box<[HostPattern]>,
  path_prefixes: Box<[HttpPathPrefix]>,
  methods: Box<[SmolStr]>,
  operations: Box<[Endpoint]>,
}

impl LinkedHttpMatcher {
  pub fn hosts(&self) -> &[HostPattern] {
    &self.hosts
  }

  pub fn path_prefixes(&self) -> &[HttpPathPrefix] {
    &self.path_prefixes
  }

  /// Canonical method alternatives in policy order.
  pub fn methods(&self) -> &[SmolStr] {
    &self.methods
  }

  /// Resolved operation alternatives in policy order.
  pub fn operations(&self) -> &[Endpoint] {
    &self.operations
  }

  /// Evaluate dimensions with AND and alternatives within each dimension
  /// with OR. An empty dimension remains unconstrained.
  pub fn matches(&self, facts: &HttpRequestFacts<'_>) -> bool {
    matches_dimension(&self.hosts, |pattern| pattern.matches(facts.ingress.host()))
      && matches_dimension(&self.path_prefixes, |prefix| prefix.matches(facts.path))
      && matches_dimension(&self.methods, |method| method.as_str() == facts.method)
      && matches_dimension(&self.operations, |operation| Some(*operation) == facts.operation)
  }
}

/// Resolve and validate one compiled HTTP matcher.
///
/// Listener and binding ids are carried into every failure so a startup error
/// identifies the exact policy owner. Alternatives are copied without sorting
/// or deduplication, preserving the compiler's policy order.
pub fn link_http_matcher(
  listener: &ListenerId,
  binding: &BindingId,
  matcher: &HttpMatch,
  names: &RuntimeNameRegistry,
) -> MatcherLinkResult<LinkedHttpMatcher> {
  let mut methods = Vec::with_capacity(matcher.methods().len());
  for method in matcher.methods() {
    if !is_canonical_http_method(method.as_str()) {
      return Err(MatcherLinkError::InvalidMethod {
        listener: listener.clone(),
        binding: binding.clone(),
        method: method.clone(),
      });
    }
    methods.push(method.clone());
  }

  let mut operations = Vec::with_capacity(matcher.operations().len());
  for operation in matcher.operations() {
    let endpoint = names
      .resolve_operation(operation)
      .ok_or_else(|| MatcherLinkError::UnknownOperation {
        listener: listener.clone(),
        binding: binding.clone(),
        operation: operation.clone(),
      })?;
    operations.push(endpoint);
  }

  Ok(LinkedHttpMatcher {
    hosts: matcher.hosts().into(),
    path_prefixes: matcher.path_prefixes().into(),
    methods: methods.into_boxed_slice(),
    operations: operations.into_boxed_slice(),
  })
}

#[derive(Clone, Debug, Eq, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum MatcherLinkError {
  #[snafu(display(
    "listener '{listener}' binding '{binding}' has invalid HTTP method selector '{method}'; expected a non-empty uppercase HTTP token without '*'"
  ))]
  InvalidMethod {
    listener: ListenerId,
    binding: BindingId,
    method: SmolStr,
  },

  #[snafu(display("listener '{listener}' binding '{binding}' references unknown operation '{operation}'"))]
  UnknownOperation {
    listener: ListenerId,
    binding: BindingId,
    operation: OperationId,
  },

  #[snafu(display(
    "listener '{listener}' CONNECT rule '{binding}' has invalid port {port}; port zero is not allowed"
  ))]
  InvalidConnectPort {
    listener: ListenerId,
    binding: BindingId,
    port: u16,
  },
}

pub type MatcherLinkResult<T> = std::result::Result<T, MatcherLinkError>;

/// A CONNECT-sourced authority suitable for CONNECT policy evaluation.
///
/// The field is private so callers cannot bypass source validation and supply
/// a direct request authority or an intercepted request's inner Host header.
#[derive(Clone, Copy, Debug)]
pub struct ConnectRequestFacts<'a> {
  ingress: &'a IngressAuthority,
}

impl<'a> ConnectRequestFacts<'a> {
  pub fn new(ingress: &'a IngressAuthority) -> ConnectFactsResult<Self> {
    if ingress.source() != IngressAuthoritySource::Connect {
      return Err(ConnectFactsError::ConnectIngressRequired {
        found: ingress.source(),
      });
    }
    Ok(Self { ingress })
  }

  pub fn ingress(&self) -> &'a IngressAuthority {
    self.ingress
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum ConnectFactsError {
  #[snafu(display("CONNECT matching requires a CONNECT-sourced ingress authority, found {found:?}"))]
  ConnectIngressRequired { found: IngressAuthoritySource },
}

pub type ConnectFactsResult<T> = std::result::Result<T, ConnectFactsError>;

/// A linked CONNECT match expression ready for authority evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedConnectMatcher {
  hosts: Box<[HostPattern]>,
  ports: Box<[u16]>,
}

impl LinkedConnectMatcher {
  pub fn hosts(&self) -> &[HostPattern] {
    &self.hosts
  }

  pub fn ports(&self) -> &[u16] {
    &self.ports
  }

  pub fn matches(&self, facts: &ConnectRequestFacts<'_>) -> bool {
    matches_dimension(&self.hosts, |pattern| pattern.matches(facts.ingress.host()))
      && matches_dimension(&self.ports, |port| *port == facts.ingress.port())
  }
}

/// Validate and link one CONNECT matcher while preserving alternative order.
pub fn link_connect_matcher(
  listener: &ListenerId,
  binding: &BindingId,
  matcher: &ConnectMatch,
) -> MatcherLinkResult<LinkedConnectMatcher> {
  for port in matcher.ports() {
    if *port == 0 {
      return Err(MatcherLinkError::InvalidConnectPort {
        listener: listener.clone(),
        binding: binding.clone(),
        port: *port,
      });
    }
  }

  Ok(LinkedConnectMatcher {
    hosts: matcher.hosts().into(),
    ports: matcher.ports().into(),
  })
}

fn matches_dimension<T>(alternatives: &[T], mut predicate: impl FnMut(&T) -> bool) -> bool {
  alternatives.is_empty() || alternatives.iter().any(&mut predicate)
}

fn is_canonical_http_method(method: &str) -> bool {
  !method.is_empty()
    && !method.contains('*')
    && method.bytes().all(is_http_token_byte)
    && !method.bytes().any(|byte| byte.is_ascii_lowercase())
}

fn is_http_token_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_policy::{CanonicalAuthority, CanonicalHost, HttpScheme};

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn binding_id(value: &str) -> BindingId {
    BindingId::new(value).unwrap()
  }

  fn operation_id(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
  }

  fn host(value: &str) -> CanonicalHost {
    CanonicalHost::parse(value).unwrap()
  }

  fn exact_host(value: &str) -> HostPattern {
    HostPattern::exact(host(value))
  }

  fn subdomains_of(value: &str) -> HostPattern {
    HostPattern::subdomains_of(host(value)).unwrap()
  }

  fn direct_ingress(value: &str) -> HttpIngress {
    HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse(value).unwrap())
  }

  fn link(matcher: &HttpMatch) -> MatcherLinkResult<LinkedHttpMatcher> {
    link_http_matcher(
      &listener_id("public"),
      &binding_id("api"),
      matcher,
      &RuntimeNameRegistry::builtin(),
    )
  }

  #[test]
  fn http_dimensions_are_anded_and_alternatives_are_ored() {
    let matcher = HttpMatch::new(
      vec![exact_host("other.example.com"), subdomains_of("example.test")].into_boxed_slice(),
      vec![
        HttpPathPrefix::parse("/v1/chat").unwrap(),
        HttpPathPrefix::parse("/v2/chat").unwrap(),
      ]
      .into_boxed_slice(),
      vec![SmolStr::new("POST"), SmolStr::new("PUT")].into_boxed_slice(),
      vec![operation_id("responses"), operation_id("messages")].into_boxed_slice(),
    )
    .unwrap();
    let linked = link(&matcher).unwrap();
    let ingress = direct_ingress("api.example.test");
    let path = CanonicalHttpPath::parse("/v2/chat/completions").unwrap();
    let facts = HttpRequestFacts {
      ingress: &ingress,
      path: &path,
      method: "PUT",
      operation: Some(Endpoint::Messages),
    };

    assert!(linked.matches(&facts));

    let wrong_host = direct_ingress("example.test");
    assert!(!linked.matches(&HttpRequestFacts {
      ingress: &wrong_host,
      ..facts
    }));
    let wrong_path = CanonicalHttpPath::parse("/v3/chat").unwrap();
    assert!(!linked.matches(&HttpRequestFacts {
      path: &wrong_path,
      ..facts
    }));
    assert!(!linked.matches(&HttpRequestFacts { method: "GET", ..facts }));
    assert!(!linked.matches(&HttpRequestFacts {
      operation: Some(Endpoint::ChatCompletions),
      ..facts
    }));
  }

  #[test]
  fn operation_dimension_requires_a_resolved_operation_when_constrained() {
    let constrained = HttpMatch::new(
      Box::default(),
      Box::default(),
      Box::default(),
      vec![operation_id("responses")].into_boxed_slice(),
    )
    .unwrap();
    let unconstrained = HttpMatch::new(
      vec![exact_host("api.example.com")].into_boxed_slice(),
      Box::default(),
      Box::default(),
      Box::default(),
    )
    .unwrap();
    let constrained = link(&constrained).unwrap();
    let unconstrained = link(&unconstrained).unwrap();
    let ingress = direct_ingress("api.example.com");
    let path = CanonicalHttpPath::parse("/unknown").unwrap();
    let facts = HttpRequestFacts {
      ingress: &ingress,
      path: &path,
      method: "GET",
      operation: None,
    };

    assert!(!constrained.matches(&facts));
    assert!(unconstrained.matches(&facts));
  }

  #[test]
  fn operation_linking_is_strict_and_contextual() {
    let matcher = HttpMatch::new(
      Box::default(),
      Box::default(),
      Box::default(),
      vec![operation_id("not_registered")].into_boxed_slice(),
    )
    .unwrap();

    let error = link(&matcher).unwrap_err();
    assert!(matches!(
      error,
      MatcherLinkError::UnknownOperation {
        listener,
        binding,
        operation,
      } if listener.as_str() == "public" && binding.as_str() == "api" && operation.as_str() == "not_registered"
    ));
  }

  #[test]
  fn canonical_paths_do_not_decode_encoded_slashes() {
    let matcher = HttpMatch::new(
      Box::default(),
      vec![HttpPathPrefix::parse("/v1%2fchat").unwrap()].into_boxed_slice(),
      Box::default(),
      Box::default(),
    )
    .unwrap();
    let linked = link(&matcher).unwrap();
    let ingress = direct_ingress("api.example.com");
    let encoded = CanonicalHttpPath::parse("/v1%2Fchat/completions").unwrap();
    let segmented = CanonicalHttpPath::parse("/v1/chat/completions").unwrap();

    assert!(linked.matches(&HttpRequestFacts {
      ingress: &ingress,
      path: &encoded,
      method: "POST",
      operation: None,
    }));
    assert!(!linked.matches(&HttpRequestFacts {
      ingress: &ingress,
      path: &segmented,
      method: "POST",
      operation: None,
    }));
  }

  #[test]
  fn exact_and_subdomain_hosts_keep_distinct_semantics() {
    let exact = link(
      &HttpMatch::new(
        vec![exact_host("example.com")].into_boxed_slice(),
        Box::default(),
        Box::default(),
        Box::default(),
      )
      .unwrap(),
    )
    .unwrap();
    let subdomain = link(
      &HttpMatch::new(
        vec![subdomains_of("example.com")].into_boxed_slice(),
        Box::default(),
        Box::default(),
        Box::default(),
      )
      .unwrap(),
    )
    .unwrap();
    let path = CanonicalHttpPath::parse("/v1").unwrap();
    let apex = direct_ingress("example.com");
    let child = direct_ingress("api.example.com");

    assert!(exact.matches(&HttpRequestFacts {
      ingress: &apex,
      path: &path,
      method: "GET",
      operation: None,
    }));
    assert!(!exact.matches(&HttpRequestFacts {
      ingress: &child,
      path: &path,
      method: "GET",
      operation: None,
    }));
    assert!(!subdomain.matches(&HttpRequestFacts {
      ingress: &apex,
      path: &path,
      method: "GET",
      operation: None,
    }));
    assert!(subdomain.matches(&HttpRequestFacts {
      ingress: &child,
      path: &path,
      method: "GET",
      operation: None,
    }));
  }

  #[test]
  fn connect_matches_host_and_port_from_connect_ingress() {
    let matcher = link_connect_matcher(
      &listener_id("proxy"),
      &binding_id("tls"),
      &ConnectMatch::new(
        vec![exact_host("other.example.com"), subdomains_of("example.test")].into_boxed_slice(),
        vec![443, 8443].into_boxed_slice(),
      )
      .unwrap(),
    )
    .unwrap();
    let matching = IngressAuthority::from_connect("api.example.test:8443").unwrap();
    let wrong_host = IngressAuthority::from_connect("example.test:8443").unwrap();
    let wrong_port = IngressAuthority::from_connect("api.example.test:9443").unwrap();

    assert!(matcher.matches(&ConnectRequestFacts::new(&matching).unwrap()));
    assert!(!matcher.matches(&ConnectRequestFacts::new(&wrong_host).unwrap()));
    assert!(!matcher.matches(&ConnectRequestFacts::new(&wrong_port).unwrap()));
  }

  #[test]
  fn connect_facts_reject_a_direct_http_authority() {
    let direct = direct_ingress("api.example.com");

    assert_eq!(
      ConnectRequestFacts::new(direct.authority()).unwrap_err(),
      ConnectFactsError::ConnectIngressRequired {
        found: IngressAuthoritySource::DirectHttp,
      }
    );
  }

  #[test]
  fn zero_connect_port_from_public_constructor_fails_contextual_linking() {
    let matcher = ConnectMatch::new(Box::default(), vec![443, 0, 8443].into_boxed_slice()).unwrap();

    let error = link_connect_matcher(&listener_id("proxy"), &binding_id("tls"), &matcher).unwrap_err();
    assert!(matches!(
      error,
      MatcherLinkError::InvalidConnectPort {
        listener,
        binding,
        port: 0,
      } if listener.as_str() == "proxy" && binding.as_str() == "tls"
    ));
  }

  #[test]
  fn malformed_or_noncanonical_public_methods_fail_linking_without_normalization() {
    for method in ["", "GET POST", "*", "F*O", "get"] {
      let matcher = HttpMatch::new(
        Box::default(),
        Box::default(),
        vec![SmolStr::new(method)].into_boxed_slice(),
        Box::default(),
      )
      .unwrap();
      let error = link(&matcher).unwrap_err();
      assert!(matches!(
        error,
        MatcherLinkError::InvalidMethod {
          listener,
          binding,
          method: found,
        } if listener.as_str() == "public" && binding.as_str() == "api" && found == method
      ));
    }
  }

  #[test]
  fn linking_preserves_method_and_resolved_operation_order() {
    let matcher = HttpMatch::new(
      Box::default(),
      Box::default(),
      vec![SmolStr::new("PUT"), SmolStr::new("GET")].into_boxed_slice(),
      vec![operation_id("messages"), operation_id("responses")].into_boxed_slice(),
    )
    .unwrap();

    let linked = link(&matcher).unwrap();
    assert_eq!(linked.methods(), ["PUT", "GET"]);
    assert_eq!(linked.operations(), [Endpoint::Messages, Endpoint::Responses]);

    let connect = link_connect_matcher(
      &listener_id("proxy"),
      &binding_id("tls"),
      &ConnectMatch::new(Box::default(), vec![8443, 443].into_boxed_slice()).unwrap(),
    )
    .unwrap();
    assert_eq!(connect.ports(), [8443, 443]);
  }
}

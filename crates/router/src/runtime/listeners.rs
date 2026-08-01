//! Runtime-linked listener policy.
//!
//! Listener linking resolves profile actions and request matchers into an
//! immutable graph before any socket binds. It deliberately leaves I/O-owned
//! resources, such as proxy CA material, to a later startup phase.

use super::{
  link_connect_matcher, link_http_matcher, ConnectRequestFacts, HttpRequestFacts, LinkedConnectMatcher,
  LinkedHttpMatcher, LinkedProfile, LinkedProfiles, MatcherLinkError, RuntimeNameRegistry,
};
use snafu::Snafu;
use std::collections::{btree_map::Entry, BTreeMap};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokn_policy::{
  BindingId, ClientAuthPlan, ConnectAction, DestinationPolicy, GatewayPlan, HttpAction, ListenerId, ListenerKind,
  ListenerPlan, ProfileId, RouteId, TlsPlan,
};

/// Runtime-linked listeners keyed by their stable policy ids.
#[derive(Clone, Debug)]
pub struct LinkedListeners {
  listeners: BTreeMap<ListenerId, Arc<LinkedListener>>,
}

impl LinkedListeners {
  pub fn listener(&self, listener_id: &ListenerId) -> Option<&Arc<LinkedListener>> {
    self.listeners.get(listener_id)
  }

  pub fn listeners(&self) -> impl ExactSizeIterator<Item = (&ListenerId, &Arc<LinkedListener>)> {
    self.listeners.iter()
  }

  pub fn len(&self) -> usize {
    self.listeners.len()
  }

  pub fn is_empty(&self) -> bool {
    self.listeners.is_empty()
  }
}

/// One listener with its common transport and HTTP policy.
#[derive(Clone, Debug)]
pub struct LinkedListener {
  id: ListenerId,
  bind: SocketAddr,
  client_auth: ClientAuthPlan,
  http: LinkedHttpPolicy,
  linked_kind: LinkedListenerKind,
}

impl LinkedListener {
  pub fn id(&self) -> &ListenerId {
    &self.id
  }

  pub fn bind(&self) -> SocketAddr {
    self.bind
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    self.client_auth
  }

  pub fn http(&self) -> &LinkedHttpPolicy {
    &self.http
  }

  pub fn kind(&self) -> ListenerKind {
    match &self.linked_kind {
      LinkedListenerKind::LlmApi => ListenerKind::LlmApi,
      LinkedListenerKind::ForwardProxy(_) => ListenerKind::ForwardProxy,
    }
  }

  pub fn linked_kind(&self) -> &LinkedListenerKind {
    &self.linked_kind
  }

  pub fn forward_proxy(&self) -> Option<&LinkedForwardProxyPolicy> {
    match &self.linked_kind {
      LinkedListenerKind::LlmApi => None,
      LinkedListenerKind::ForwardProxy(policy) => Some(policy),
    }
  }
}

/// Listener-family-specific linked state.
#[derive(Clone, Debug)]
pub enum LinkedListenerKind {
  LlmApi,
  ForwardProxy(LinkedForwardProxyPolicy),
}

/// Ordered HTTP bindings and their catch-all action.
#[derive(Clone, Debug)]
pub struct LinkedHttpPolicy {
  bindings: Box<[LinkedHttpBinding]>,
  default_action: LinkedHttpAction,
}

impl LinkedHttpPolicy {
  pub fn bindings(&self) -> &[LinkedHttpBinding] {
    &self.bindings
  }

  pub fn default_action(&self) -> &LinkedHttpAction {
    &self.default_action
  }

  /// Apply first-match semantics and retain the selected binding id for
  /// observability. `None` identifies the listener default action.
  pub fn decide<'a>(&'a self, facts: &HttpRequestFacts<'_>) -> LinkedHttpDecision<'a> {
    if let Some(binding) = self.bindings.iter().find(|binding| binding.matcher.matches(facts)) {
      LinkedHttpDecision {
        binding_id: Some(&binding.id),
        action: &binding.action,
      }
    } else {
      LinkedHttpDecision {
        binding_id: None,
        action: &self.default_action,
      }
    }
  }
}

/// One linked HTTP binding in evaluation order.
#[derive(Clone, Debug)]
pub struct LinkedHttpBinding {
  id: BindingId,
  matcher: LinkedHttpMatcher,
  action: LinkedHttpAction,
}

impl LinkedHttpBinding {
  pub fn id(&self) -> &BindingId {
    &self.id
  }

  pub fn matcher(&self) -> &LinkedHttpMatcher {
    &self.matcher
  }

  pub fn action(&self) -> &LinkedHttpAction {
    &self.action
  }
}

/// An HTTP action with its profile reference materialized.
#[derive(Clone, Debug)]
pub enum LinkedHttpAction {
  Route(Arc<LinkedProfile>),
  Reject,
}

impl LinkedHttpAction {
  pub fn profile(&self) -> Option<&Arc<LinkedProfile>> {
    match self {
      Self::Route(profile) => Some(profile),
      Self::Reject => None,
    }
  }
}

/// Result of one HTTP policy decision.
#[derive(Clone, Copy, Debug)]
pub struct LinkedHttpDecision<'a> {
  binding_id: Option<&'a BindingId>,
  action: &'a LinkedHttpAction,
}

impl<'a> LinkedHttpDecision<'a> {
  pub fn binding_id(&self) -> Option<&'a BindingId> {
    self.binding_id
  }

  pub fn action(&self) -> &'a LinkedHttpAction {
    self.action
  }
}

/// Forward-proxy-only policy and the still-unmaterialized TLS plan.
#[derive(Clone, Debug)]
pub struct LinkedForwardProxyPolicy {
  connect: LinkedConnectPolicy,
  tls_plan: Option<TlsPlan>,
}

impl LinkedForwardProxyPolicy {
  pub fn connect(&self) -> &LinkedConnectPolicy {
    &self.connect
  }

  pub fn tls_plan(&self) -> Option<&TlsPlan> {
    self.tls_plan.as_ref()
  }

  pub fn requires_interception(&self) -> bool {
    self.connect.requires_interception()
  }
}

/// Ordered CONNECT rules and their catch-all action.
#[derive(Clone, Debug)]
pub struct LinkedConnectPolicy {
  rules: Box<[LinkedConnectRule]>,
  default_action: ConnectAction,
}

impl LinkedConnectPolicy {
  pub fn rules(&self) -> &[LinkedConnectRule] {
    &self.rules
  }

  pub fn default_action(&self) -> ConnectAction {
    self.default_action
  }

  pub fn requires_interception(&self) -> bool {
    self.default_action == ConnectAction::Intercept
      || self.rules.iter().any(|rule| rule.action == ConnectAction::Intercept)
  }

  /// Apply first-match semantics and retain the selected rule id for
  /// observability. `None` identifies the listener default action.
  pub fn decide<'a>(&'a self, facts: &ConnectRequestFacts<'_>) -> LinkedConnectDecision<'a> {
    if let Some(rule) = self.rules.iter().find(|rule| rule.matcher.matches(facts)) {
      LinkedConnectDecision {
        binding_id: Some(&rule.id),
        action: rule.action,
      }
    } else {
      LinkedConnectDecision {
        binding_id: None,
        action: self.default_action,
      }
    }
  }
}

/// One linked CONNECT rule in evaluation order.
#[derive(Clone, Debug)]
pub struct LinkedConnectRule {
  id: BindingId,
  matcher: LinkedConnectMatcher,
  action: ConnectAction,
}

impl LinkedConnectRule {
  pub fn id(&self) -> &BindingId {
    &self.id
  }

  pub fn matcher(&self) -> &LinkedConnectMatcher {
    &self.matcher
  }

  pub fn action(&self) -> ConnectAction {
    self.action
  }
}

/// Result of one CONNECT policy decision.
#[derive(Clone, Copy, Debug)]
pub struct LinkedConnectDecision<'a> {
  binding_id: Option<&'a BindingId>,
  action: ConnectAction,
}

impl<'a> LinkedConnectDecision<'a> {
  pub fn binding_id(&self) -> Option<&'a BindingId> {
    self.binding_id
  }

  pub fn action(&self) -> ConnectAction {
    self.action
  }
}

/// Location of an HTTP action within a listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpActionSite {
  Binding(BindingId),
  Default,
}

impl fmt::Display for HttpActionSite {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Binding(binding) => write!(formatter, "binding '{binding}'"),
      Self::Default => formatter.write_str("default HTTP action"),
    }
  }
}

/// Location of a CONNECT action within a listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectActionSite {
  Rule(BindingId),
  Default,
}

impl fmt::Display for ConnectActionSite {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Rule(binding) => write!(formatter, "CONNECT rule '{binding}'"),
      Self::Default => formatter.write_str("default CONNECT action"),
    }
  }
}

/// Kind of rule that claimed a globally unique binding id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingKind {
  Http,
  Connect,
}

impl fmt::Display for BindingKind {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Http => formatter.write_str("HTTP binding"),
      Self::Connect => formatter.write_str("CONNECT rule"),
    }
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ListenerLinkError {
  #[snafu(display("listener '{listener}' has invalid bind address '{bind}': port zero is not allowed"))]
  InvalidBindPort { listener: ListenerId, bind: SocketAddr },

  #[snafu(display(
    "listener '{listener}' cannot bind without client authentication on non-loopback address '{bind}'"
  ))]
  UnauthenticatedNonLoopback { listener: ListenerId, bind: SocketAddr },

  #[snafu(display(
    "listener '{second_listener}' bind '{second_bind}' overlaps listener '{first_listener}' bind '{first_bind}'"
  ))]
  OverlappingBind {
    first_listener: ListenerId,
    first_bind: SocketAddr,
    second_listener: ListenerId,
    second_bind: SocketAddr,
  },

  #[snafu(display(
    "binding id '{binding}' is used by {first_kind} on listener '{first_listener}' and {second_kind} on listener '{second_listener}'"
  ))]
  DuplicateBindingId {
    binding: BindingId,
    first_listener: ListenerId,
    first_kind: BindingKind,
    second_listener: ListenerId,
    second_kind: BindingKind,
  },

  #[snafu(display("failed to link a listener matcher: {source}"))]
  Matcher { source: MatcherLinkError },

  #[snafu(display("listener '{listener}' {site} references profile '{profile}' without a linked runtime"))]
  MissingProfile {
    listener: ListenerId,
    site: HttpActionSite,
    profile: ProfileId,
  },

  #[snafu(display(
    "LLM API listener '{listener}' {site} cannot use profile '{profile}' because route '{route}' requires the original destination"
  ))]
  OriginalDestinationOnLlm {
    listener: ListenerId,
    site: HttpActionSite,
    profile: ProfileId,
    route: RouteId,
  },

  #[snafu(display("forward proxy listener '{listener}' {site} intercepts CONNECT requests but has no TLS plan"))]
  InterceptWithoutTls {
    listener: ListenerId,
    site: ConnectActionSite,
  },
}

pub type ListenerLinkResult<T> = std::result::Result<T, ListenerLinkError>;

/// Link and validate every listener without binding sockets or loading CA
/// material.
pub fn link_listeners(
  plan: &GatewayPlan,
  profiles: &LinkedProfiles,
  names: &RuntimeNameRegistry,
) -> ListenerLinkResult<LinkedListeners> {
  validate_listener_structure(plan)?;

  let listeners = plan
    .listeners()
    .iter()
    .map(|(listener_id, listener)| {
      link_listener(listener_id, listener, profiles, names).map(|listener| (listener_id.clone(), Arc::new(listener)))
    })
    .collect::<ListenerLinkResult<_>>()?;
  Ok(LinkedListeners { listeners })
}

fn validate_listener_structure(plan: &GatewayPlan) -> ListenerLinkResult<()> {
  let mut binds = Vec::<(ListenerId, SocketAddr)>::new();
  let mut binding_owners = BTreeMap::<BindingId, (ListenerId, BindingKind)>::new();

  for (listener_id, listener) in plan.listeners() {
    let bind = listener.bind();
    if bind.port() == 0 {
      return Err(ListenerLinkError::InvalidBindPort {
        listener: listener_id.clone(),
        bind,
      });
    }
    if listener.client_auth() == ClientAuthPlan::None && !bind.ip().is_loopback() {
      return Err(ListenerLinkError::UnauthenticatedNonLoopback {
        listener: listener_id.clone(),
        bind,
      });
    }
    if let Some((first_listener, first_bind)) = binds
      .iter()
      .find(|(_, first_bind)| bind_addresses_overlap(*first_bind, bind))
    {
      return Err(ListenerLinkError::OverlappingBind {
        first_listener: first_listener.clone(),
        first_bind: *first_bind,
        second_listener: listener_id.clone(),
        second_bind: bind,
      });
    }
    binds.push((listener_id.clone(), bind));

    for binding in listener.http_bindings() {
      claim_binding_id(&mut binding_owners, binding.id(), listener_id, BindingKind::Http)?;
    }
    if let ListenerPlan::ForwardProxy(proxy) = listener {
      for rule in proxy.connect_rules() {
        claim_binding_id(&mut binding_owners, rule.id(), listener_id, BindingKind::Connect)?;
      }
    }
  }
  Ok(())
}

fn claim_binding_id(
  owners: &mut BTreeMap<BindingId, (ListenerId, BindingKind)>,
  binding: &BindingId,
  listener: &ListenerId,
  kind: BindingKind,
) -> ListenerLinkResult<()> {
  match owners.entry(binding.clone()) {
    Entry::Vacant(entry) => {
      entry.insert((listener.clone(), kind));
      Ok(())
    }
    Entry::Occupied(entry) => {
      let (first_listener, first_kind) = entry.get();
      Err(ListenerLinkError::DuplicateBindingId {
        binding: binding.clone(),
        first_listener: first_listener.clone(),
        first_kind: *first_kind,
        second_listener: listener.clone(),
        second_kind: kind,
      })
    }
  }
}

fn bind_addresses_overlap(first: SocketAddr, second: SocketAddr) -> bool {
  first.port() == second.port()
    && (first.ip() == second.ip() || first.ip().is_unspecified() || second.ip().is_unspecified())
}

fn link_listener(
  listener_id: &ListenerId,
  listener: &ListenerPlan,
  profiles: &LinkedProfiles,
  names: &RuntimeNameRegistry,
) -> ListenerLinkResult<LinkedListener> {
  let http = link_http_policy(listener_id, listener, profiles, names)?;
  let linked_kind = match listener {
    ListenerPlan::LlmApi(_) => LinkedListenerKind::LlmApi,
    ListenerPlan::ForwardProxy(proxy) => {
      let connect = link_connect_policy(listener_id, proxy)?;
      let intercept_site = proxy
        .connect_rules()
        .iter()
        .find(|rule| rule.action() == ConnectAction::Intercept)
        .map(|rule| ConnectActionSite::Rule(rule.id().clone()))
        .or_else(|| (proxy.default_connect_action() == ConnectAction::Intercept).then_some(ConnectActionSite::Default));
      if let Some(site) = intercept_site.filter(|_| proxy.tls().is_none()) {
        return Err(ListenerLinkError::InterceptWithoutTls {
          listener: listener_id.clone(),
          site,
        });
      }
      LinkedListenerKind::ForwardProxy(LinkedForwardProxyPolicy {
        connect,
        tls_plan: proxy.tls().cloned(),
      })
    }
  };

  Ok(LinkedListener {
    id: listener_id.clone(),
    bind: listener.bind(),
    client_auth: listener.client_auth(),
    http,
    linked_kind,
  })
}

fn link_http_policy(
  listener_id: &ListenerId,
  listener: &ListenerPlan,
  profiles: &LinkedProfiles,
  names: &RuntimeNameRegistry,
) -> ListenerLinkResult<LinkedHttpPolicy> {
  let mut bindings = Vec::with_capacity(listener.http_bindings().len());
  for binding in listener.http_bindings() {
    let matcher = link_http_matcher(listener_id, binding.id(), binding.matcher(), names)
      .map_err(|source| ListenerLinkError::Matcher { source })?;
    let action = link_http_action(
      listener_id,
      listener.kind(),
      HttpActionSite::Binding(binding.id().clone()),
      binding.action(),
      profiles,
    )?;
    bindings.push(LinkedHttpBinding {
      id: binding.id().clone(),
      matcher,
      action,
    });
  }

  let default_action = link_http_action(
    listener_id,
    listener.kind(),
    HttpActionSite::Default,
    listener.default_http_action(),
    profiles,
  )?;
  Ok(LinkedHttpPolicy {
    bindings: bindings.into_boxed_slice(),
    default_action,
  })
}

fn link_http_action(
  listener_id: &ListenerId,
  listener_kind: ListenerKind,
  site: HttpActionSite,
  action: &HttpAction,
  profiles: &LinkedProfiles,
) -> ListenerLinkResult<LinkedHttpAction> {
  let HttpAction::Route(profile_id) = action else {
    return Ok(LinkedHttpAction::Reject);
  };
  let profile = profiles
    .profile(profile_id)
    .cloned()
    .ok_or_else(|| ListenerLinkError::MissingProfile {
      listener: listener_id.clone(),
      site: site.clone(),
      profile: profile_id.clone(),
    })?;

  if listener_kind == ListenerKind::LlmApi && profile.route().destination_policy() == DestinationPolicy::Original {
    return Err(ListenerLinkError::OriginalDestinationOnLlm {
      listener: listener_id.clone(),
      site,
      profile: profile_id.clone(),
      route: profile.route().id().clone(),
    });
  }
  Ok(LinkedHttpAction::Route(profile))
}

fn link_connect_policy(
  listener_id: &ListenerId,
  proxy: &tokn_policy::ForwardProxyListenerPlan,
) -> ListenerLinkResult<LinkedConnectPolicy> {
  let mut rules = Vec::with_capacity(proxy.connect_rules().len());
  for rule in proxy.connect_rules() {
    let matcher = link_connect_matcher(listener_id, rule.id(), rule.matcher())
      .map_err(|source| ListenerLinkError::Matcher { source })?;
    rules.push(LinkedConnectRule {
      id: rule.id().clone(),
      matcher,
      action: rule.action(),
    });
  }
  Ok(LinkedConnectPolicy {
    rules: rules.into_boxed_slice(),
    default_action: proxy.default_connect_action(),
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{link_profiles, scan_profile_reachability};
  use std::collections::BTreeMap;
  use std::net::{IpAddr, Ipv4Addr};
  use std::path::Path;
  use tokn_accounts::link::{build_account_pool_runtimes, link_account_pools, link_provider_graph, link_routes};
  use tokn_accounts::registry::Registry;
  use tokn_core::provider::Endpoint;
  use tokn_policy::{
    CanonicalAuthority, CanonicalHost, CanonicalHttpPath, ConnectMatch, ConnectRulePlan, ForwardProxyListenerPlan,
    HostPattern, HttpBindingPlan, HttpIngress, HttpMatch, HttpPathPattern, HttpPathPrefix, HttpScheme,
    IngressAuthority, LlmApiListenerPlan, OperationId, ProfilePlan, RoutePlan, WireIdentity,
  };

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn binding_id(value: &str) -> BindingId {
    BindingId::new(value).unwrap()
  }

  fn profile_id(value: &str) -> ProfileId {
    ProfileId::new(value).unwrap()
  }

  fn route_id(value: &str) -> RouteId {
    RouteId::new(value).unwrap()
  }

  fn operation_id(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
  }

  fn bind(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
  }

  fn path_binding(id: &str, prefix: &str, action: HttpAction) -> HttpBindingPlan {
    HttpBindingPlan::new(
      binding_id(id),
      HttpMatch::new(
        Box::default(),
        vec![HttpPathPattern::Prefix(HttpPathPrefix::parse(prefix).unwrap())].into_boxed_slice(),
        Box::default(),
        Box::default(),
      )
      .unwrap(),
      action,
    )
  }

  fn operation_binding(id: &str, operation: &str, action: HttpAction) -> HttpBindingPlan {
    HttpBindingPlan::new(
      binding_id(id),
      HttpMatch::new(
        Box::default(),
        Box::default(),
        Box::default(),
        vec![operation_id(operation)].into_boxed_slice(),
      )
      .unwrap(),
      action,
    )
  }

  fn connect_rule(id: &str, ports: &[u16], action: ConnectAction) -> ConnectRulePlan {
    ConnectRulePlan::new(
      binding_id(id),
      ConnectMatch::new(Box::default(), ports.to_vec().into_boxed_slice()).unwrap(),
      action,
    )
  }

  fn host_connect_rule(id: &str, host: &str, action: ConnectAction) -> ConnectRulePlan {
    ConnectRulePlan::new(
      binding_id(id),
      ConnectMatch::new(
        vec![HostPattern::exact(CanonicalHost::parse(host).unwrap())].into_boxed_slice(),
        Box::default(),
      )
      .unwrap(),
      action,
    )
  }

  fn llm_listener(
    bind: SocketAddr,
    client_auth: ClientAuthPlan,
    bindings: Vec<HttpBindingPlan>,
    default_action: HttpAction,
  ) -> ListenerPlan {
    ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      bind,
      client_auth,
      bindings.into_boxed_slice(),
      default_action,
    ))
  }

  fn proxy_listener(
    bind: SocketAddr,
    client_auth: ClientAuthPlan,
    bindings: Vec<HttpBindingPlan>,
    default_http_action: HttpAction,
    connect_rules: Vec<ConnectRulePlan>,
    default_connect_action: ConnectAction,
    tls: Option<TlsPlan>,
  ) -> ListenerPlan {
    ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      bind,
      client_auth,
      bindings.into_boxed_slice(),
      default_http_action,
      connect_rules.into_boxed_slice(),
      default_connect_action,
      tls,
    ))
  }

  fn gateway(
    listeners: impl IntoIterator<Item = (&'static str, ListenerPlan)>,
    with_transparent_profile: bool,
  ) -> GatewayPlan {
    let listeners = listeners
      .into_iter()
      .map(|(id, listener)| (listener_id(id), listener))
      .collect();
    let (profiles, routes) = if with_transparent_profile {
      (
        BTreeMap::from([(
          profile_id("transparent"),
          ProfilePlan::new(route_id("transparent"), WireIdentity::None),
        )]),
        BTreeMap::from([(route_id("transparent"), RoutePlan::Transparent(Default::default()))]),
      )
    } else {
      (BTreeMap::new(), BTreeMap::new())
    };

    GatewayPlan::new(
      listeners,
      profiles,
      routes,
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    )
  }

  fn linked_profiles(plan: &GatewayPlan, names: &RuntimeNameRegistry) -> LinkedProfiles {
    let registry = Registry::builtin();
    let providers = link_provider_graph(plan, &[], &registry).unwrap();
    let pools = link_account_pools(plan, &providers, &registry).unwrap();
    let pool_runtimes = build_account_pool_runtimes(&pools);
    let reachable = scan_profile_reachability(plan).unwrap();
    let routes = link_routes(plan, reachable.route_ids(), &providers, &pool_runtimes).unwrap();
    link_profiles(plan, &reachable, &routes, names).unwrap()
  }

  fn direct_ingress(authority: &str) -> HttpIngress {
    HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse(authority).unwrap())
  }

  #[test]
  fn http_policy_preserves_order_uses_first_match_and_reuses_profile_arcs() {
    let profile = profile_id("transparent");
    let plan = gateway(
      [(
        "proxy",
        proxy_listener(
          bind([127, 0, 0, 1], 4100),
          ClientAuthPlan::None,
          vec![
            path_binding("first", "/v1", HttpAction::Route(profile.clone())),
            path_binding("second", "/v1/chat", HttpAction::Route(profile.clone())),
          ],
          HttpAction::Route(profile.clone()),
          Vec::new(),
          ConnectAction::Tunnel,
          None,
        ),
      )],
      true,
    );
    let names = RuntimeNameRegistry::builtin();
    let profiles = linked_profiles(&plan, &names);
    let linked = link_listeners(&plan, &profiles, &names).unwrap();
    let listener = linked.listener(&listener_id("proxy")).unwrap();
    let expected = profiles.profile(&profile).unwrap();

    assert_eq!(listener.kind(), ListenerKind::ForwardProxy);
    assert_eq!(
      listener
        .http()
        .bindings()
        .iter()
        .map(|binding| binding.id().as_str())
        .collect::<Vec<_>>(),
      ["first", "second"]
    );
    for action in listener
      .http()
      .bindings()
      .iter()
      .map(LinkedHttpBinding::action)
      .chain(std::iter::once(listener.http().default_action()))
    {
      assert!(Arc::ptr_eq(action.profile().unwrap(), expected));
    }

    let ingress = direct_ingress("api.example.com");
    let first_path = CanonicalHttpPath::parse("/v1/chat/completions").unwrap();
    let first = listener.http().decide(&HttpRequestFacts {
      ingress: &ingress,
      path: &first_path,
      method: "POST",
      operation: Some(Endpoint::ChatCompletions),
    });
    assert_eq!(first.binding_id().map(BindingId::as_str), Some("first"));
    assert!(matches!(first.action(), LinkedHttpAction::Route(_)));

    let default_path = CanonicalHttpPath::parse("/other").unwrap();
    let default = listener.http().decide(&HttpRequestFacts {
      ingress: &ingress,
      path: &default_path,
      method: "GET",
      operation: None,
    });
    assert!(default.binding_id().is_none());
    assert!(matches!(default.action(), LinkedHttpAction::Route(_)));
  }

  #[test]
  fn reject_binding_still_resolves_operation_names() {
    let plan = gateway(
      [(
        "api",
        llm_listener(
          bind([127, 0, 0, 1], 4101),
          ClientAuthPlan::None,
          vec![operation_binding(
            "reject-unknown",
            "not_registered",
            HttpAction::Reject,
          )],
          HttpAction::Reject,
        ),
      )],
      false,
    );
    let names = RuntimeNameRegistry::builtin();
    let profiles = linked_profiles(&plan, &names);

    assert!(matches!(
      link_listeners(&plan, &profiles, &names),
      Err(ListenerLinkError::Matcher {
        source: MatcherLinkError::UnknownOperation {
          listener,
          binding,
          operation,
        },
      }) if listener.as_str() == "api"
        && binding.as_str() == "reject-unknown"
        && operation.as_str() == "not_registered"
    ));
  }

  #[test]
  fn llm_listener_rejects_original_destination_at_binding_and_default() {
    let profile = profile_id("transparent");
    let binding_plan = gateway(
      [(
        "api",
        llm_listener(
          bind([127, 0, 0, 1], 4102),
          ClientAuthPlan::None,
          vec![path_binding("transparent", "/v1", HttpAction::Route(profile.clone()))],
          HttpAction::Reject,
        ),
      )],
      true,
    );
    let names = RuntimeNameRegistry::builtin();
    let profiles = linked_profiles(&binding_plan, &names);
    assert!(matches!(
      link_listeners(&binding_plan, &profiles, &names),
      Err(ListenerLinkError::OriginalDestinationOnLlm {
        listener,
        site: HttpActionSite::Binding(binding),
        profile: found_profile,
        route,
      }) if listener.as_str() == "api"
        && binding.as_str() == "transparent"
        && found_profile == profile
        && route.as_str() == "transparent"
    ));

    let default_plan = gateway(
      [(
        "api",
        llm_listener(
          bind([127, 0, 0, 1], 4103),
          ClientAuthPlan::None,
          Vec::new(),
          HttpAction::Route(profile.clone()),
        ),
      )],
      true,
    );
    let profiles = linked_profiles(&default_plan, &names);
    assert!(matches!(
      link_listeners(&default_plan, &profiles, &names),
      Err(ListenerLinkError::OriginalDestinationOnLlm {
        site: HttpActionSite::Default,
        profile: found_profile,
        ..
      }) if found_profile == profile
    ));
  }

  #[test]
  fn forward_proxy_routes_original_destinations_and_connect_policy_uses_first_match() {
    let profile = profile_id("transparent");
    let plan = gateway(
      [(
        "proxy",
        proxy_listener(
          bind([127, 0, 0, 1], 4104),
          ClientAuthPlan::None,
          Vec::new(),
          HttpAction::Route(profile),
          vec![
            connect_rule("port", &[443], ConnectAction::Tunnel),
            host_connect_rule("host", "api.example.com", ConnectAction::Reject),
          ],
          ConnectAction::Tunnel,
          None,
        ),
      )],
      true,
    );
    let names = RuntimeNameRegistry::builtin();
    let profiles = linked_profiles(&plan, &names);
    let linked = link_listeners(&plan, &profiles, &names).unwrap();
    let proxy = linked.listener(&listener_id("proxy")).unwrap().forward_proxy().unwrap();
    assert!(!proxy.requires_interception());
    assert!(proxy.tls_plan().is_none());
    assert_eq!(
      proxy
        .connect()
        .rules()
        .iter()
        .map(|rule| rule.id().as_str())
        .collect::<Vec<_>>(),
      ["port", "host"]
    );

    let both = IngressAuthority::from_connect("api.example.com:443").unwrap();
    let decision = proxy.connect().decide(&ConnectRequestFacts::new(&both).unwrap());
    assert_eq!(decision.binding_id().map(BindingId::as_str), Some("port"));
    assert_eq!(decision.action(), ConnectAction::Tunnel);

    let host_only = IngressAuthority::from_connect("api.example.com:8443").unwrap();
    let decision = proxy.connect().decide(&ConnectRequestFacts::new(&host_only).unwrap());
    assert_eq!(decision.binding_id().map(BindingId::as_str), Some("host"));
    assert_eq!(decision.action(), ConnectAction::Reject);

    let default = IngressAuthority::from_connect("other.example.com:8443").unwrap();
    let decision = proxy.connect().decide(&ConnectRequestFacts::new(&default).unwrap());
    assert!(decision.binding_id().is_none());
    assert_eq!(decision.action(), ConnectAction::Tunnel);
  }

  #[test]
  fn intercept_requires_tls_for_rule_and_default_and_preserves_the_plan() {
    let rule_plan = gateway(
      [(
        "proxy",
        proxy_listener(
          bind([127, 0, 0, 1], 4105),
          ClientAuthPlan::None,
          Vec::new(),
          HttpAction::Reject,
          vec![connect_rule("intercept", &[443], ConnectAction::Intercept)],
          ConnectAction::Tunnel,
          None,
        ),
      )],
      false,
    );
    let names = RuntimeNameRegistry::builtin();
    let profiles = linked_profiles(&rule_plan, &names);
    assert!(matches!(
      link_listeners(&rule_plan, &profiles, &names),
      Err(ListenerLinkError::InterceptWithoutTls {
        listener,
        site: ConnectActionSite::Rule(binding),
      }) if listener.as_str() == "proxy" && binding.as_str() == "intercept"
    ));

    let default_plan = gateway(
      [(
        "proxy",
        proxy_listener(
          bind([127, 0, 0, 1], 4106),
          ClientAuthPlan::None,
          Vec::new(),
          HttpAction::Reject,
          Vec::new(),
          ConnectAction::Intercept,
          None,
        ),
      )],
      false,
    );
    let profiles = linked_profiles(&default_plan, &names);
    assert!(matches!(
      link_listeners(&default_plan, &profiles, &names),
      Err(ListenerLinkError::InterceptWithoutTls {
        site: ConnectActionSite::Default,
        ..
      })
    ));

    let tls_plan = gateway(
      [(
        "proxy",
        proxy_listener(
          bind([127, 0, 0, 1], 4107),
          ClientAuthPlan::None,
          Vec::new(),
          HttpAction::Reject,
          Vec::new(),
          ConnectAction::Intercept,
          Some(TlsPlan::new("certificates".into())),
        ),
      )],
      false,
    );
    let profiles = linked_profiles(&tls_plan, &names);
    let linked = link_listeners(&tls_plan, &profiles, &names).unwrap();
    let proxy = linked.listener(&listener_id("proxy")).unwrap().forward_proxy().unwrap();
    assert!(proxy.requires_interception());
    assert_eq!(proxy.tls_plan().unwrap().ca_dir(), Path::new("certificates"));
  }

  #[test]
  fn structural_validation_rejects_bad_bind_exposure_and_overlap() {
    let zero_port = gateway(
      [(
        "api",
        llm_listener(
          bind([127, 0, 0, 1], 0),
          ClientAuthPlan::None,
          Vec::new(),
          HttpAction::Reject,
        ),
      )],
      false,
    );
    let names = RuntimeNameRegistry::builtin();
    let profiles = linked_profiles(&zero_port, &names);
    assert!(matches!(
      link_listeners(&zero_port, &profiles, &names),
      Err(ListenerLinkError::InvalidBindPort { listener, .. }) if listener.as_str() == "api"
    ));

    let exposed = gateway(
      [(
        "api",
        llm_listener(
          bind([0, 0, 0, 0], 4110),
          ClientAuthPlan::None,
          Vec::new(),
          HttpAction::Reject,
        ),
      )],
      false,
    );
    let profiles = linked_profiles(&exposed, &names);
    assert!(matches!(
      link_listeners(&exposed, &profiles, &names),
      Err(ListenerLinkError::UnauthenticatedNonLoopback { listener, .. }) if listener.as_str() == "api"
    ));

    let overlap = gateway(
      [
        (
          "any",
          llm_listener(
            bind([0, 0, 0, 0], 4111),
            ClientAuthPlan::LocalKeys,
            Vec::new(),
            HttpAction::Reject,
          ),
        ),
        (
          "loopback",
          llm_listener(
            bind([127, 0, 0, 1], 4111),
            ClientAuthPlan::None,
            Vec::new(),
            HttpAction::Reject,
          ),
        ),
      ],
      false,
    );
    let profiles = linked_profiles(&overlap, &names);
    assert!(matches!(
      link_listeners(&overlap, &profiles, &names),
      Err(ListenerLinkError::OverlappingBind {
        first_listener,
        second_listener,
        ..
      }) if first_listener.as_str() == "any" && second_listener.as_str() == "loopback"
    ));
  }

  #[test]
  fn binding_ids_are_global_across_http_and_connect_rules() {
    let duplicate = binding_id("shared");
    let plan = gateway(
      [(
        "proxy",
        proxy_listener(
          bind([127, 0, 0, 1], 4112),
          ClientAuthPlan::None,
          vec![path_binding("shared", "/v1", HttpAction::Reject)],
          HttpAction::Reject,
          vec![ConnectRulePlan::new(
            duplicate,
            ConnectMatch::new(Box::default(), vec![443].into_boxed_slice()).unwrap(),
            ConnectAction::Tunnel,
          )],
          ConnectAction::Reject,
          None,
        ),
      )],
      false,
    );
    let names = RuntimeNameRegistry::builtin();
    let profiles = linked_profiles(&plan, &names);

    assert!(matches!(
      link_listeners(&plan, &profiles, &names),
      Err(ListenerLinkError::DuplicateBindingId {
        binding,
        first_kind: BindingKind::Http,
        second_kind: BindingKind::Connect,
        ..
      }) if binding.as_str() == "shared"
    ));
  }
}

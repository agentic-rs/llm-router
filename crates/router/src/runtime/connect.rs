//! Typed CONNECT dispatch over one linked forward-proxy listener.
//!
//! Admission first creates a strict CONNECT-sourced authority. Dispatch then
//! consumes that authority and pins it beside the exact rule/default action
//! selected from one immutable listener generation.

use super::{ConnectFactsError, ConnectRequestFacts, LinkedListener};
use snafu::Snafu;
use std::fmt;
use tokn_policy::{BindingId, ConnectAction, IngressAuthority, ListenerId};

/// Stable listener location that selected a CONNECT action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectDispatchSite {
  listener_id: ListenerId,
  rule_id: Option<BindingId>,
}

impl ConnectDispatchSite {
  pub(crate) fn new(listener_id: ListenerId, rule_id: Option<BindingId>) -> Self {
    Self { listener_id, rule_id }
  }

  pub fn listener_id(&self) -> &ListenerId {
    &self.listener_id
  }

  /// `None` identifies the listener's default CONNECT action.
  pub fn rule_id(&self) -> Option<&BindingId> {
    self.rule_id.as_ref()
  }
}

impl fmt::Display for ConnectDispatchSite {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self.rule_id {
      Some(rule) => write!(formatter, "listener '{}' CONNECT rule '{}'", self.listener_id, rule),
      None => write!(formatter, "listener '{}' default CONNECT action", self.listener_id),
    }
  }
}

/// One immutable CONNECT target and the exact transport action selected for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectDispatch {
  site: ConnectDispatchSite,
  authority: IngressAuthority,
  action: ConnectAction,
}

impl ConnectDispatch {
  pub fn site(&self) -> &ConnectDispatchSite {
    &self.site
  }

  pub fn authority(&self) -> &IngressAuthority {
    &self.authority
  }

  pub fn action(&self) -> ConnectAction {
    self.action
  }

  pub fn into_parts(self) -> (ConnectDispatchSite, IngressAuthority, ConnectAction) {
    (self.site, self.authority, self.action)
  }
}

/// Select one CONNECT action without performing I/O or opening an upstream.
pub fn dispatch_connect(
  listener: &LinkedListener,
  authority: IngressAuthority,
) -> ConnectDispatchResult<ConnectDispatch> {
  let policy = listener
    .forward_proxy()
    .ok_or_else(|| ConnectDispatchError::UnsupportedListener {
      listener: listener.id().clone(),
    })?;
  let facts = ConnectRequestFacts::new(&authority).map_err(|source| ConnectDispatchError::InvalidAuthoritySource {
    listener: listener.id().clone(),
    source,
  })?;
  let decision = policy.connect().decide(&facts);

  Ok(ConnectDispatch {
    site: ConnectDispatchSite::new(listener.id().clone(), decision.binding_id().cloned()),
    authority,
    action: decision.action(),
  })
}

#[derive(Clone, Debug, Eq, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum ConnectDispatchError {
  #[snafu(display("listener '{listener}' does not accept CONNECT requests"))]
  UnsupportedListener { listener: ListenerId },

  #[snafu(display("listener '{listener}' received an invalid CONNECT authority source: {source}"))]
  InvalidAuthoritySource {
    listener: ListenerId,
    source: ConnectFactsError,
  },
}

pub type ConnectDispatchResult<T> = std::result::Result<T, ConnectDispatchError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{link_gateway_runtime, RuntimeNameRegistry};
  use std::collections::BTreeMap;
  use std::net::{Ipv4Addr, SocketAddr};
  use tokn_accounts::registry::Registry;
  use tokn_policy::{
    CanonicalAuthority, CanonicalHost, ClientAuthPlan, ConnectMatch, ConnectRulePlan, ForwardProxyListenerPlan,
    GatewayPlan, HostPattern, HttpAction, HttpIngress, HttpScheme, ListenerPlan, LlmApiListenerPlan, TlsPlan,
  };

  fn listener_id(value: &str) -> ListenerId {
    ListenerId::new(value).unwrap()
  }

  fn binding_id(value: &str) -> BindingId {
    BindingId::new(value).unwrap()
  }

  fn linked(listener: ListenerPlan) -> std::sync::Arc<LinkedListener> {
    let id = listener_id("listener");
    let plan = GatewayPlan::new(
      BTreeMap::from([(id.clone(), listener)]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let runtime = link_gateway_runtime(&plan, &[], &Registry::builtin(), &RuntimeNameRegistry::new()).unwrap();
    runtime.listeners().listener(&id).unwrap().clone()
  }

  fn proxy() -> ListenerPlan {
    let rule = ConnectRulePlan::new(
      binding_id("secure"),
      ConnectMatch::new(
        vec![HostPattern::exact(CanonicalHost::parse("api.example").unwrap())].into_boxed_slice(),
        vec![443].into_boxed_slice(),
      )
      .unwrap(),
      ConnectAction::Intercept,
    );
    ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 41_101)),
      ClientAuthPlan::None,
      Box::default(),
      HttpAction::Reject,
      vec![rule].into_boxed_slice(),
      ConnectAction::Tunnel,
      Some(TlsPlan::new("unused-test-ca".into())),
    ))
  }

  #[test]
  fn pins_the_matching_rule_and_connect_authority() {
    let listener = linked(proxy());
    let authority = IngressAuthority::from_connect("API.Example:443").unwrap();

    let dispatch = dispatch_connect(&listener, authority.clone()).unwrap();

    assert_eq!(dispatch.site().listener_id().as_str(), "listener");
    assert_eq!(dispatch.site().rule_id().unwrap().as_str(), "secure");
    assert_eq!(dispatch.authority(), &authority);
    assert_eq!(dispatch.action(), ConnectAction::Intercept);
  }

  #[test]
  fn retains_the_default_action_site() {
    let listener = linked(proxy());
    let authority = IngressAuthority::from_connect("other.example:8443").unwrap();

    let dispatch = dispatch_connect(&listener, authority).unwrap();

    assert!(dispatch.site().rule_id().is_none());
    assert_eq!(dispatch.action(), ConnectAction::Tunnel);
  }

  #[test]
  fn rejects_non_connect_ingress_and_non_proxy_listeners() {
    let proxy = linked(proxy());
    let direct = HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse("api.example").unwrap());
    let error = dispatch_connect(&proxy, direct.authority().clone()).unwrap_err();
    assert!(matches!(error, ConnectDispatchError::InvalidAuthoritySource { .. }));

    let api = linked(ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 41_102)),
      ClientAuthPlan::None,
      Box::default(),
      HttpAction::Reject,
    )));
    let authority = IngressAuthority::from_connect("api.example:443").unwrap();
    let error = dispatch_connect(&api, authority).unwrap_err();
    assert!(matches!(error, ConnectDispatchError::UnsupportedListener { .. }));
  }
}

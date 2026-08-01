use crate::{
  AccountPoolId, BindingId, CanonicalHost, HttpPathPrefix, ListenerId, ModelGroupId, OperationId, ProfileId,
  ProfilePlan, ProviderId, RouteId, RoutePlan, UpstreamId,
};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A configuration-compiled gateway plan.
///
/// References within the configuration and all raw syntax are validated
/// before this value is constructed. A runtime linker must still resolve
/// provider catalogue defaults and runtime-owned names (such as operations
/// and wire identities), then reject an unusable plan before listeners bind.
/// Runtime crates consume this graph without knowing how it was represented
/// on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPlan {
  listeners: BTreeMap<ListenerId, ListenerPlan>,
  profiles: BTreeMap<ProfileId, ProfilePlan>,
  routes: BTreeMap<RouteId, RoutePlan>,
  account_pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
  upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
  model_groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
}

impl GatewayPlan {
  pub fn new(
    listeners: BTreeMap<ListenerId, ListenerPlan>,
    profiles: BTreeMap<ProfileId, ProfilePlan>,
    routes: BTreeMap<RouteId, RoutePlan>,
    account_pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
    model_groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
  ) -> Self {
    Self {
      listeners,
      profiles,
      routes,
      account_pools,
      upstreams,
      model_groups,
    }
  }

  pub fn listeners(&self) -> &BTreeMap<ListenerId, ListenerPlan> {
    &self.listeners
  }

  pub fn listener(&self, id: &ListenerId) -> Option<&ListenerPlan> {
    self.listeners.get(id)
  }

  pub fn profiles(&self) -> &BTreeMap<ProfileId, ProfilePlan> {
    &self.profiles
  }

  pub fn profile(&self, id: &ProfileId) -> Option<&ProfilePlan> {
    self.profiles.get(id)
  }

  pub fn routes(&self) -> &BTreeMap<RouteId, RoutePlan> {
    &self.routes
  }

  pub fn route(&self, id: &RouteId) -> Option<&RoutePlan> {
    self.routes.get(id)
  }

  pub fn account_pools(&self) -> &BTreeMap<AccountPoolId, AccountPoolPlan> {
    &self.account_pools
  }

  pub fn account_pool(&self, id: &AccountPoolId) -> Option<&AccountPoolPlan> {
    self.account_pools.get(id)
  }

  pub fn upstreams(&self) -> &BTreeMap<UpstreamId, UpstreamPlan> {
    &self.upstreams
  }

  pub fn upstream(&self, id: &UpstreamId) -> Option<&UpstreamPlan> {
    self.upstreams.get(id)
  }

  pub fn model_groups(&self) -> &BTreeMap<ModelGroupId, ModelGroupPlan> {
    &self.model_groups
  }

  pub fn model_group(&self, id: &ModelGroupId) -> Option<&ModelGroupPlan> {
    self.model_groups.get(id)
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerKind {
  LlmApi,
  ForwardProxy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListenerPlan {
  LlmApi(LlmApiListenerPlan),
  ForwardProxy(ForwardProxyListenerPlan),
}

impl ListenerPlan {
  pub fn kind(&self) -> ListenerKind {
    match self {
      Self::LlmApi(_) => ListenerKind::LlmApi,
      Self::ForwardProxy(_) => ListenerKind::ForwardProxy,
    }
  }

  pub fn bind(&self) -> SocketAddr {
    match self {
      Self::LlmApi(listener) => listener.bind(),
      Self::ForwardProxy(listener) => listener.bind(),
    }
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    match self {
      Self::LlmApi(listener) => listener.client_auth(),
      Self::ForwardProxy(listener) => listener.client_auth(),
    }
  }

  /// HTTP match rules in evaluation order. The first matching rule wins.
  pub fn http_bindings(&self) -> &[HttpBindingPlan] {
    match self {
      Self::LlmApi(listener) => listener.http_bindings(),
      Self::ForwardProxy(listener) => listener.http_bindings(),
    }
  }

  pub fn default_http_action(&self) -> &HttpAction {
    match self {
      Self::LlmApi(listener) => listener.default_http_action(),
      Self::ForwardProxy(listener) => listener.default_http_action(),
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LlmApiListenerPlan {
  bind: SocketAddr,
  client_auth: ClientAuthPlan,
  http_bindings: Box<[HttpBindingPlan]>,
  default_http_action: HttpAction,
}

impl LlmApiListenerPlan {
  pub fn new(
    bind: SocketAddr,
    client_auth: ClientAuthPlan,
    http_bindings: Box<[HttpBindingPlan]>,
    default_http_action: HttpAction,
  ) -> Self {
    Self {
      bind,
      client_auth,
      http_bindings,
      default_http_action,
    }
  }

  pub fn bind(&self) -> SocketAddr {
    self.bind
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    self.client_auth
  }

  pub fn http_bindings(&self) -> &[HttpBindingPlan] {
    &self.http_bindings
  }

  pub fn default_http_action(&self) -> &HttpAction {
    &self.default_http_action
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardProxyListenerPlan {
  bind: SocketAddr,
  client_auth: ClientAuthPlan,
  http_bindings: Box<[HttpBindingPlan]>,
  default_http_action: HttpAction,
  connect_rules: Box<[ConnectRulePlan]>,
  default_connect_action: ConnectAction,
  tls: Option<TlsPlan>,
}

impl ForwardProxyListenerPlan {
  pub fn new(
    bind: SocketAddr,
    client_auth: ClientAuthPlan,
    http_bindings: Box<[HttpBindingPlan]>,
    default_http_action: HttpAction,
    connect_rules: Box<[ConnectRulePlan]>,
    default_connect_action: ConnectAction,
    tls: Option<TlsPlan>,
  ) -> Self {
    Self {
      bind,
      client_auth,
      http_bindings,
      default_http_action,
      connect_rules,
      default_connect_action,
      tls,
    }
  }

  pub fn bind(&self) -> SocketAddr {
    self.bind
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    self.client_auth
  }

  pub fn http_bindings(&self) -> &[HttpBindingPlan] {
    &self.http_bindings
  }

  pub fn default_http_action(&self) -> &HttpAction {
    &self.default_http_action
  }

  /// CONNECT match rules in evaluation order. The first matching rule wins.
  pub fn connect_rules(&self) -> &[ConnectRulePlan] {
    &self.connect_rules
  }

  pub fn default_connect_action(&self) -> ConnectAction {
    self.default_connect_action
  }

  pub fn tls(&self) -> Option<&TlsPlan> {
    self.tls.as_ref()
  }
}

/// Client authentication performed before binding selection.
///
/// Credential storage is deliberately outside the policy graph. `LocalKeys`
/// means the runtime must authenticate against its configured client-key
/// store; it does not embed secret material in the plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthPlan {
  None,
  LocalKeys,
}

/// Material needed to terminate forward-proxy TLS connections selected for
/// [`ConnectAction::Intercept`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPlan {
  ca_dir: PathBuf,
}

impl TlsPlan {
  pub fn new(ca_dir: PathBuf) -> Self {
    Self { ca_dir }
  }

  pub fn ca_dir(&self) -> &Path {
    &self.ca_dir
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpBindingPlan {
  id: BindingId,
  matcher: HttpMatch,
  action: HttpAction,
}

impl HttpBindingPlan {
  pub fn new(id: BindingId, matcher: HttpMatch, action: HttpAction) -> Self {
    Self { id, matcher, action }
  }

  pub fn id(&self) -> &BindingId {
    &self.id
  }

  pub fn matcher(&self) -> &HttpMatch {
    &self.matcher
  }

  pub fn action(&self) -> &HttpAction {
    &self.action
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpAction {
  Route(ProfileId),
  Reject,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum HostPatternKind {
  Exact(CanonicalHost),
  SubdomainsOf(CanonicalHost),
}

/// A host selector in a binding rule.
///
/// Runtime matching uses a canonical, immutable ingress authority. For an
/// intercepted request this is the original CONNECT authority, never an
/// untrusted inner Host header. A conflicting inner authority must be rejected
/// before binding or credential selection.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostPattern {
  kind: HostPatternKind,
}

impl HostPattern {
  pub fn exact(host: CanonicalHost) -> Self {
    Self {
      kind: HostPatternKind::Exact(host),
    }
  }

  pub fn subdomains_of(suffix: CanonicalHost) -> Result<Self, InvalidSubdomainSuffix> {
    if !suffix.is_dns() {
      return Err(InvalidSubdomainSuffix);
    }
    Ok(Self {
      kind: HostPatternKind::SubdomainsOf(suffix),
    })
  }

  pub fn host(&self) -> &CanonicalHost {
    match &self.kind {
      HostPatternKind::Exact(host) | HostPatternKind::SubdomainsOf(host) => host,
    }
  }

  pub fn matches(&self, host: &CanonicalHost) -> bool {
    match &self.kind {
      HostPatternKind::Exact(expected) => host == expected,
      HostPatternKind::SubdomainsOf(suffix) => host.is_strict_subdomain_of(suffix),
    }
  }

  /// Whether every host selected by `other` is also selected by this pattern.
  pub fn subsumes(&self, other: &Self) -> bool {
    match (&self.kind, &other.kind) {
      (HostPatternKind::Exact(left), HostPatternKind::Exact(right)) => left == right,
      (HostPatternKind::SubdomainsOf(suffix), HostPatternKind::Exact(host)) => host.is_strict_subdomain_of(suffix),
      (HostPatternKind::SubdomainsOf(left), HostPatternKind::SubdomainsOf(right)) => {
        left == right || right.is_strict_subdomain_of(left)
      }
      (HostPatternKind::Exact(_), HostPatternKind::SubdomainsOf(_)) => false,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSubdomainSuffix;

impl fmt::Display for InvalidSubdomainSuffix {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("subdomain patterns require a DNS suffix, not an IP address")
  }
}

impl std::error::Error for InvalidSubdomainSuffix {}

/// Error returned when a binding tries to act as an implicit catch-all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyHttpMatch;

impl fmt::Display for EmptyHttpMatch {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(
      "an HTTP binding must constrain at least one match dimension; use the listener default HTTP action for catch-all behavior",
    )
  }
}

impl std::error::Error for EmptyHttpMatch {}

/// Match dimensions are combined with AND. Values within one dimension are
/// combined with OR. An empty dimension is unconstrained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpMatch {
  hosts: Box<[HostPattern]>,
  path_prefixes: Box<[HttpPathPrefix]>,
  methods: Box<[SmolStr]>,
  operations: Box<[OperationId]>,
}

impl HttpMatch {
  pub fn new(
    hosts: Box<[HostPattern]>,
    path_prefixes: Box<[HttpPathPrefix]>,
    methods: Box<[SmolStr]>,
    operations: Box<[OperationId]>,
  ) -> Result<Self, EmptyHttpMatch> {
    if hosts.is_empty() && path_prefixes.is_empty() && methods.is_empty() && operations.is_empty() {
      return Err(EmptyHttpMatch);
    }

    Ok(Self {
      hosts,
      path_prefixes,
      methods,
      operations,
    })
  }

  pub fn hosts(&self) -> &[HostPattern] {
    &self.hosts
  }

  pub fn path_prefixes(&self) -> &[HttpPathPrefix] {
    &self.path_prefixes
  }

  pub fn methods(&self) -> &[SmolStr] {
    &self.methods
  }

  pub fn operations(&self) -> &[OperationId] {
    &self.operations
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRulePlan {
  id: BindingId,
  matcher: ConnectMatch,
  action: ConnectAction,
}

impl ConnectRulePlan {
  pub fn new(id: BindingId, matcher: ConnectMatch, action: ConnectAction) -> Self {
    Self { id, matcher, action }
  }

  pub fn id(&self) -> &BindingId {
    &self.id
  }

  pub fn matcher(&self) -> &ConnectMatch {
    &self.matcher
  }

  pub fn action(&self) -> ConnectAction {
    self.action
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectAction {
  /// Terminate TLS, then evaluate the decoded request against the listener's
  /// HTTP bindings. Those bindings may select any route family, including a
  /// transparent route. The immutable CONNECT authority remains the request's
  /// original destination; an inner authority mismatch is rejected.
  Intercept,
  /// Preserve the connection as an opaque byte stream.
  Tunnel,
  Reject,
}

/// Error returned when a CONNECT rule tries to act as an implicit catch-all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyConnectMatch;

impl fmt::Display for EmptyConnectMatch {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(
      "a CONNECT rule must constrain hosts or ports; use the listener default CONNECT action for catch-all behavior",
    )
  }
}

impl std::error::Error for EmptyConnectMatch {}

/// CONNECT match dimensions are combined with AND. Values within one
/// dimension are combined with OR. An empty dimension is unconstrained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectMatch {
  hosts: Box<[HostPattern]>,
  ports: Box<[u16]>,
}

impl ConnectMatch {
  pub fn new(hosts: Box<[HostPattern]>, ports: Box<[u16]>) -> Result<Self, EmptyConnectMatch> {
    if hosts.is_empty() && ports.is_empty() {
      return Err(EmptyConnectMatch);
    }

    Ok(Self { hosts, ports })
  }

  pub fn hosts(&self) -> &[HostPattern] {
    &self.hosts
  }

  pub fn ports(&self) -> &[u16] {
    &self.ports
  }
}

/// Typed constraints used to materialize one pool-local view of the account
/// inventory. Provider selection applies to both tiers. `None` active accounts
/// means every matching account is active unless it is explicitly assigned to
/// the fallback tier; an empty active set selects no active accounts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountSelector {
  providers: Option<BTreeSet<ProviderId>>,
  active_accounts: Option<BTreeSet<SmolStr>>,
  fallback_accounts: BTreeSet<SmolStr>,
}

impl AccountSelector {
  pub fn new(
    providers: Option<BTreeSet<ProviderId>>,
    active_accounts: Option<BTreeSet<SmolStr>>,
    fallback_accounts: BTreeSet<SmolStr>,
  ) -> Self {
    Self {
      providers,
      active_accounts,
      fallback_accounts,
    }
  }

  pub fn all() -> Self {
    Self::default()
  }

  pub fn providers(&self) -> Option<&BTreeSet<ProviderId>> {
    self.providers.as_ref()
  }

  pub fn active_accounts(&self) -> Option<&BTreeSet<SmolStr>> {
    self.active_accounts.as_ref()
  }

  pub fn fallback_accounts(&self) -> &BTreeSet<SmolStr> {
    &self.fallback_accounts
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountSelectionStrategy {
  RoundRobin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionAffinityPlan {
  ttl: Duration,
  expired_retention: Duration,
}

impl SessionAffinityPlan {
  pub fn new(ttl: Duration, expired_retention: Duration) -> Self {
    Self { ttl, expired_retention }
  }

  pub fn ttl(&self) -> Duration {
    self.ttl
  }

  /// Additional time to retain an expired affinity entry for observability.
  pub fn expired_retention(&self) -> Duration {
    self.expired_retention
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountPoolPlan {
  selector: AccountSelector,
  strategy: AccountSelectionStrategy,
  failure_cooldown: Duration,
  session_affinity: Option<SessionAffinityPlan>,
}

impl AccountPoolPlan {
  pub fn new(
    selector: AccountSelector,
    strategy: AccountSelectionStrategy,
    failure_cooldown: Duration,
    session_affinity: Option<SessionAffinityPlan>,
  ) -> Self {
    Self {
      selector,
      strategy,
      failure_cooldown,
      session_affinity,
    }
  }

  pub fn selector(&self) -> &AccountSelector {
    &self.selector
  }

  pub fn strategy(&self) -> AccountSelectionStrategy {
    self.strategy
  }

  pub fn failure_cooldown(&self) -> Duration {
    self.failure_cooldown
  }

  pub fn session_affinity(&self) -> Option<SessionAffinityPlan> {
    self.session_affinity
  }
}

/// Canonical origin claimed by an upstream for origin-based relay selection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UpstreamOrigin(SmolStr);

impl UpstreamOrigin {
  pub fn new(origin: impl AsRef<str>) -> Self {
    Self(SmolStr::new(origin.as_ref()))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

impl AsRef<str> for UpstreamOrigin {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl fmt::Display for UpstreamOrigin {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamPlan {
  provider: ProviderId,
  base_url: Option<SmolStr>,
  origins: Box<[UpstreamOrigin]>,
  allow_insecure_http: bool,
  eligible_accounts: Option<BTreeSet<SmolStr>>,
}

impl UpstreamPlan {
  pub fn new(
    provider: ProviderId,
    base_url: Option<SmolStr>,
    origins: Box<[UpstreamOrigin]>,
    allow_insecure_http: bool,
  ) -> Self {
    Self {
      provider,
      base_url,
      origins,
      allow_insecure_http,
      eligible_accounts: None,
    }
  }

  /// Restrict this endpoint to named accounts. `None` permits every account
  /// whose provider matches. Runtime linking intersects this constraint with
  /// the selected account pool before constructing any credential-bearing
  /// provider binding.
  pub fn with_eligible_accounts(mut self, eligible_accounts: Option<BTreeSet<SmolStr>>) -> Self {
    self.eligible_accounts = eligible_accounts;
    self
  }

  pub fn provider(&self) -> &ProviderId {
    &self.provider
  }

  /// Canonical trailing-slash URL prefix. Runtime linking fills catalogue
  /// defaults; request execution appends a relative operation or relay path.
  pub fn base_url(&self) -> Option<&str> {
    self.base_url.as_deref()
  }

  pub fn origins(&self) -> &[UpstreamOrigin] {
    &self.origins
  }

  /// Whether runtime linking may accept a non-loopback `http://` catalogue
  /// default for this upstream. Explicit URLs are checked by the config
  /// compiler; defaults must receive the same check after resolution.
  pub fn allow_insecure_http(&self) -> bool {
    self.allow_insecure_http
  }

  pub fn eligible_accounts(&self) -> Option<&BTreeSet<SmolStr>> {
    self.eligible_accounts.as_ref()
  }

  pub fn permits_account(&self, account_id: &str) -> bool {
    self
      .eligible_accounts
      .as_ref()
      .is_none_or(|accounts| accounts.contains(account_id))
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCandidate {
  upstream: Option<UpstreamId>,
  model: SmolStr,
}

impl ModelCandidate {
  pub fn new(upstream: Option<UpstreamId>, model: impl AsRef<str>) -> Self {
    Self {
      upstream,
      model: SmolStr::new(model.as_ref()),
    }
  }

  pub fn upstream(&self) -> Option<&UpstreamId> {
    self.upstream.as_ref()
  }

  pub fn model(&self) -> &str {
    self.model.as_str()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelGroupPlan {
  candidates: Box<[ModelCandidate]>,
}

impl ModelGroupPlan {
  pub fn new(candidates: Box<[ModelCandidate]>) -> Self {
    Self { candidates }
  }

  /// Candidates in fallback order.
  pub fn candidates(&self) -> &[ModelCandidate] {
    &self.candidates
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    ManagedRetry, ManagedRoute, ManagedTarget, ModelSelector, OperationPolicy, UpstreamSelector, WireIdentity,
  };

  fn id<T>(value: &str) -> T
  where
    T: TryFrom<String>,
    T::Error: fmt::Debug,
  {
    T::try_from(value.to_string()).unwrap()
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

  fn http_matcher(host: &str) -> HttpMatch {
    HttpMatch::new(
      vec![exact_host(host)].into_boxed_slice(),
      Box::default(),
      Box::default(),
      Box::default(),
    )
    .unwrap()
  }

  #[test]
  fn forward_proxy_keeps_connect_and_http_decisions_separate() {
    let first_http = HttpBindingPlan::new(
      id("specific"),
      http_matcher("api.example.com"),
      HttpAction::Route(id("transparent")),
    );
    let second_http = HttpBindingPlan::new(
      id("wildcard"),
      HttpMatch::new(
        vec![subdomains_of("example.com")].into_boxed_slice(),
        Box::default(),
        Box::default(),
        Box::default(),
      )
      .unwrap(),
      HttpAction::Reject,
    );
    let first_connect = ConnectRulePlan::new(
      id("tunnel-internal"),
      ConnectMatch::new(
        vec![subdomains_of("internal.example")].into_boxed_slice(),
        vec![443].into_boxed_slice(),
      )
      .unwrap(),
      ConnectAction::Tunnel,
    );
    let second_connect = ConnectRulePlan::new(
      id("intercept-public"),
      ConnectMatch::new(
        vec![subdomains_of("example.com")].into_boxed_slice(),
        vec![443, 8443].into_boxed_slice(),
      )
      .unwrap(),
      ConnectAction::Intercept,
    );
    let listener = ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      "127.0.0.1:8080".parse().unwrap(),
      ClientAuthPlan::LocalKeys,
      vec![first_http, second_http].into_boxed_slice(),
      HttpAction::Reject,
      vec![first_connect, second_connect].into_boxed_slice(),
      ConnectAction::Reject,
      Some(TlsPlan::new(PathBuf::from("/tmp/tokn-ca"))),
    ));

    assert_eq!(listener.kind(), ListenerKind::ForwardProxy);
    assert_eq!(listener.http_bindings()[0].id().as_str(), "specific");
    assert_eq!(listener.http_bindings()[1].id().as_str(), "wildcard");
    assert_eq!(listener.default_http_action(), &HttpAction::Reject);

    let ListenerPlan::ForwardProxy(proxy) = listener else {
      panic!("expected forward-proxy listener");
    };
    assert_eq!(proxy.connect_rules()[0].id().as_str(), "tunnel-internal");
    assert_eq!(proxy.connect_rules()[0].action(), ConnectAction::Tunnel);
    assert_eq!(proxy.connect_rules()[1].id().as_str(), "intercept-public");
    assert_eq!(proxy.connect_rules()[1].action(), ConnectAction::Intercept);
    assert_eq!(proxy.default_connect_action(), ConnectAction::Reject);
    assert_eq!(proxy.tls().unwrap().ca_dir(), Path::new("/tmp/tokn-ca"));
  }

  #[test]
  fn http_match_requires_a_dimension_and_exposes_and_or_groups() {
    assert_eq!(
      HttpMatch::new(Box::default(), Box::default(), Box::default(), Box::default()),
      Err(EmptyHttpMatch)
    );

    let rule = HttpMatch::new(
      vec![exact_host("api.example.com")].into_boxed_slice(),
      vec![
        HttpPathPrefix::parse("/v1").unwrap(),
        HttpPathPrefix::parse("/compatible").unwrap(),
      ]
      .into_boxed_slice(),
      vec![SmolStr::new("POST")].into_boxed_slice(),
      vec![id("responses"), id("chat-completions")].into_boxed_slice(),
    )
    .unwrap();

    assert_eq!(rule.hosts().len(), 1);
    assert_eq!(rule.path_prefixes().len(), 2);
    assert_eq!(rule.methods(), &[SmolStr::new("POST")]);
    assert_eq!(rule.operations().len(), 2);
  }

  #[test]
  fn connect_match_requires_a_dimension_and_exposes_host_and_port_groups() {
    assert_eq!(
      ConnectMatch::new(Box::default(), Box::default()),
      Err(EmptyConnectMatch)
    );

    let rule = ConnectMatch::new(
      vec![exact_host("api.example.com")].into_boxed_slice(),
      vec![443, 8443].into_boxed_slice(),
    )
    .unwrap();

    assert_eq!(rule.hosts(), &[exact_host("api.example.com")]);
    assert_eq!(rule.ports(), &[443, 8443]);
  }

  #[test]
  fn subdomain_pattern_excludes_apex_and_label_lookalikes() {
    let pattern = subdomains_of("example.com");

    assert!(pattern.matches(&host("api.example.com")));
    assert!(pattern.matches(&host("API.EXAMPLE.COM")));
    assert!(!pattern.matches(&host("example.com")));
    assert!(!pattern.matches(&host("notexample.com")));
    assert_eq!(
      HostPattern::subdomains_of(host("127.0.0.1")),
      Err(InvalidSubdomainSuffix)
    );
  }

  #[test]
  fn pool_keeps_typed_selectors_and_runtime_timing() {
    let selector = AccountSelector::new(
      Some(BTreeSet::from([id("openai")])),
      Some(BTreeSet::from([SmolStr::new("personal")])),
      BTreeSet::from([SmolStr::new("backup")]),
    );
    let pool = AccountPoolPlan::new(
      selector,
      AccountSelectionStrategy::RoundRobin,
      Duration::from_secs(60),
      Some(SessionAffinityPlan::new(
        Duration::from_secs(300),
        Duration::from_secs(900),
      )),
    );

    assert!(pool
      .selector()
      .providers()
      .unwrap()
      .contains(&id::<ProviderId>("openai")));
    assert!(pool.selector().active_accounts().unwrap().contains("personal"));
    assert!(pool.selector().fallback_accounts().contains("backup"));
    assert_eq!(pool.failure_cooldown(), Duration::from_secs(60));
    assert_eq!(
      pool.session_affinity().unwrap().expired_retention(),
      Duration::from_secs(900)
    );
  }

  #[test]
  fn upstream_and_model_group_keep_distinct_ordered_facts() {
    let upstream = UpstreamPlan::new(
      id("openai"),
      Some(SmolStr::new("https://gateway.example/v1")),
      vec![
        UpstreamOrigin::new("https://api.openai.com"),
        UpstreamOrigin::new("https://chatgpt.com"),
      ]
      .into_boxed_slice(),
      false,
    )
    .with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("work")])));
    let group = ModelGroupPlan::new(
      vec![
        ModelCandidate::new(Some(id("openai-public")), "gpt-5"),
        ModelCandidate::new(None, "claude-sonnet"),
      ]
      .into_boxed_slice(),
    );

    assert_eq!(upstream.provider().as_str(), "openai");
    assert_eq!(upstream.origins()[1].as_str(), "https://chatgpt.com");
    assert!(upstream.permits_account("work"));
    assert!(!upstream.permits_account("personal"));
    assert_eq!(group.candidates()[0].model(), "gpt-5");
    assert_eq!(group.candidates()[1].upstream(), None);
  }

  #[test]
  fn gateway_plan_owns_the_compiled_graph() {
    let listener_id: ListenerId = id("api");
    let profile_id: ProfileId = id("default");
    let route_id: RouteId = id("managed");
    let pool_id: AccountPoolId = id("default");
    let upstream_id: UpstreamId = id("openai-public");
    let group_id: ModelGroupId = id("flagship");

    let listener = ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      "127.0.0.1:3000".parse().unwrap(),
      ClientAuthPlan::None,
      Vec::new().into_boxed_slice(),
      HttpAction::Route(profile_id.clone()),
    ));
    let profile = ProfilePlan::new(route_id.clone(), WireIdentity::ProviderDefault);
    let route = RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(pool_id.clone(), UpstreamSelector::Any, ModelSelector::Capability),
      OperationPolicy::TranslateCompatible,
      None,
      ManagedRetry::Never,
    ));

    let gateway = GatewayPlan::new(
      BTreeMap::from([(listener_id.clone(), listener)]),
      BTreeMap::from([(profile_id.clone(), profile)]),
      BTreeMap::from([(route_id.clone(), route)]),
      BTreeMap::from([(
        pool_id.clone(),
        AccountPoolPlan::new(
          AccountSelector::all(),
          AccountSelectionStrategy::RoundRobin,
          Duration::ZERO,
          None,
        ),
      )]),
      BTreeMap::from([(
        upstream_id.clone(),
        UpstreamPlan::new(id("openai"), None, Box::default(), false),
      )]),
      BTreeMap::from([(
        group_id.clone(),
        ModelGroupPlan::new(vec![ModelCandidate::new(None, "gpt-5")].into_boxed_slice()),
      )]),
    );

    assert_eq!(gateway.listener(&listener_id).unwrap().kind(), ListenerKind::LlmApi);
    assert_eq!(gateway.profile(&profile_id).unwrap().route(), &route_id);
    assert!(gateway.route(&route_id).is_some());
    assert!(gateway.account_pool(&pool_id).is_some());
    assert!(gateway.upstream(&upstream_id).is_some());
    assert!(gateway.model_group(&group_id).is_some());
  }
}

use crate::{
  AccountPoolId, BindingId, CanonicalHost, DriverId, ListenerId, OperationId, ProfileId, ProfilePlan, ProviderId,
  RetryPolicyId, RetryPolicyPlan, RouteId, RoutePlan,
};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES: usize = 10 * 1024 * 1024;

/// A configuration-compiled gateway plan.
///
/// References within the configuration and all raw syntax are validated
/// before this value is constructed. A runtime linker must still resolve
/// driver catalogue defaults and runtime-owned names (such as operations
/// and wire identities), then reject an unusable plan before listeners bind.
/// Runtime crates consume this graph without knowing how it was represented
/// on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPlan {
  listeners: BTreeMap<ListenerId, ListenerPlan>,
  profiles: BTreeMap<ProfileId, ProfilePlan>,
  routes: BTreeMap<RouteId, RoutePlan>,
  retry_policies: BTreeMap<RetryPolicyId, RetryPolicyPlan>,
  account_pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
  providers: BTreeMap<ProviderId, ProviderPlan>,
}

impl GatewayPlan {
  pub fn new(
    listeners: BTreeMap<ListenerId, ListenerPlan>,
    profiles: BTreeMap<ProfileId, ProfilePlan>,
    routes: BTreeMap<RouteId, RoutePlan>,
    retry_policies: BTreeMap<RetryPolicyId, RetryPolicyPlan>,
    account_pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    providers: BTreeMap<ProviderId, ProviderPlan>,
  ) -> Self {
    Self {
      listeners,
      profiles,
      routes,
      retry_policies,
      account_pools,
      providers,
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

  pub fn retry_policies(&self) -> &BTreeMap<RetryPolicyId, RetryPolicyPlan> {
    &self.retry_policies
  }

  pub fn retry_policy(&self, id: &RetryPolicyId) -> Option<&RetryPolicyPlan> {
    self.retry_policies.get(id)
  }

  pub fn account_pools(&self) -> &BTreeMap<AccountPoolId, AccountPoolPlan> {
    &self.account_pools
  }

  pub fn account_pool(&self, id: &AccountPoolId) -> Option<&AccountPoolPlan> {
    self.account_pools.get(id)
  }

  pub fn providers(&self) -> &BTreeMap<ProviderId, ProviderPlan> {
    &self.providers
  }

  pub fn provider(&self, id: &ProviderId) -> Option<&ProviderPlan> {
    self.providers.get(id)
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
  request_body_max_bytes: NonZeroUsize,
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
      request_body_max_bytes: NonZeroUsize::new(DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES)
        .expect("the default forward-proxy body limit is nonzero"),
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

  pub fn request_body_max_bytes(&self) -> usize {
    self.request_body_max_bytes.get()
  }

  pub fn with_request_body_max_bytes(mut self, request_body_max_bytes: NonZeroUsize) -> Self {
    self.request_body_max_bytes = request_body_max_bytes;
    self
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
  path_prefixes: Box<[SmolStr]>,
  methods: Box<[SmolStr]>,
  operations: Box<[OperationId]>,
}

impl HttpMatch {
  pub fn new(
    hosts: Box<[HostPattern]>,
    path_prefixes: Box<[SmolStr]>,
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

  pub fn path_prefixes(&self) -> &[SmolStr] {
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
  /// HTTP bindings. Those bindings may select an original-destination relay
  /// that preserves client credentials. The immutable CONNECT authority
  /// remains the request's original destination; an inner authority mismatch
  /// is rejected.
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

/// Typed constraints used to materialize an account pool from the account
/// inventory. `None` leaves that dimension unconstrained.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountSelector {
  providers: Option<BTreeSet<ProviderId>>,
  accounts: Option<BTreeSet<SmolStr>>,
}

impl AccountSelector {
  pub fn new(providers: Option<BTreeSet<ProviderId>>, accounts: Option<BTreeSet<SmolStr>>) -> Self {
    Self { providers, accounts }
  }

  pub fn all() -> Self {
    Self::default()
  }

  pub fn providers(&self) -> Option<&BTreeSet<ProviderId>> {
    self.providers.as_ref()
  }

  pub fn accounts(&self) -> Option<&BTreeSet<SmolStr>> {
    self.accounts.as_ref()
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

/// Canonical origin claimed by a provider for origin-based relay selection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderOrigin(SmolStr);

impl ProviderOrigin {
  pub fn new(origin: impl AsRef<str>) -> Self {
    Self(SmolStr::new(origin.as_ref()))
  }

  pub fn as_str(&self) -> &str {
    self.0.as_str()
  }
}

impl AsRef<str> for ProviderOrigin {
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl fmt::Display for ProviderOrigin {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.as_str())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPlan {
  driver: DriverId,
  base_url: Option<SmolStr>,
  origins: Box<[ProviderOrigin]>,
  allow_insecure_http: bool,
}

impl ProviderPlan {
  pub fn new(
    driver: DriverId,
    base_url: Option<SmolStr>,
    origins: Box<[ProviderOrigin]>,
    allow_insecure_http: bool,
  ) -> Self {
    Self {
      driver,
      base_url,
      origins,
      allow_insecure_http,
    }
  }

  pub fn driver(&self) -> &DriverId {
    &self.driver
  }

  /// Canonical trailing-slash URL prefix. Runtime linking fills catalogue
  /// defaults; request execution appends a relative operation or relay path.
  pub fn base_url(&self) -> Option<&str> {
    self.base_url.as_deref()
  }

  pub fn origins(&self) -> &[ProviderOrigin] {
    &self.origins
  }

  /// Whether runtime linking may accept a non-loopback `http://` driver
  /// default for this provider. Explicit URLs are checked by the config
  /// compiler; defaults must receive the same check after resolution.
  pub fn allow_insecure_http(&self) -> bool {
    self.allow_insecure_http
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    ManagedRetry, ManagedRoute, ManagedTarget, ModelSelector, OperationPolicy, ProviderSelector, WireIdentity,
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
    assert_eq!(proxy.request_body_max_bytes(), 10 * 1024 * 1024);
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
      vec![SmolStr::new("/v1"), SmolStr::new("/compatible")].into_boxed_slice(),
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
    assert!(pool.selector().accounts().unwrap().contains("personal"));
    assert_eq!(pool.failure_cooldown(), Duration::from_secs(60));
    assert_eq!(
      pool.session_affinity().unwrap().expired_retention(),
      Duration::from_secs(900)
    );
  }

  #[test]
  fn provider_keeps_driver_and_origin_facts() {
    let provider = ProviderPlan::new(
      id("openai-driver"),
      Some(SmolStr::new("https://gateway.example/v1")),
      vec![
        ProviderOrigin::new("https://api.openai.com"),
        ProviderOrigin::new("https://chatgpt.com"),
      ]
      .into_boxed_slice(),
      false,
    );

    assert_eq!(provider.driver().as_str(), "openai-driver");
    assert_eq!(provider.origins()[1].as_str(), "https://chatgpt.com");
  }

  #[test]
  fn gateway_plan_owns_the_compiled_graph() {
    let listener_id: ListenerId = id("api");
    let profile_id: ProfileId = id("default");
    let route_id: RouteId = id("managed");
    let pool_id: AccountPoolId = id("default");
    let provider_id: ProviderId = id("openai-public");

    let listener = ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      "127.0.0.1:3000".parse().unwrap(),
      ClientAuthPlan::None,
      Vec::new().into_boxed_slice(),
      HttpAction::Route(profile_id.clone()),
    ));
    let profile = ProfilePlan::new(route_id.clone(), WireIdentity::ProviderDefault);
    let route = RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(pool_id.clone(), ProviderSelector::Any, ModelSelector::Capability),
      OperationPolicy::TranslateCompatible,
      None,
      ManagedRetry::Never,
    ));

    let gateway = GatewayPlan::new(
      BTreeMap::from([(listener_id.clone(), listener)]),
      BTreeMap::from([(profile_id.clone(), profile)]),
      BTreeMap::from([(route_id.clone(), route)]),
      BTreeMap::new(),
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
        provider_id.clone(),
        ProviderPlan::new(id("openai"), None, Box::default(), false),
      )]),
    );

    assert_eq!(gateway.listener(&listener_id).unwrap().kind(), ListenerKind::LlmApi);
    assert_eq!(gateway.profile(&profile_id).unwrap().route(), &route_id);
    assert!(gateway.route(&route_id).is_some());
    assert!(gateway.retry_policies().is_empty());
    assert!(gateway.account_pool(&pool_id).is_some());
    assert!(gateway.provider(&provider_id).is_some());
  }
}

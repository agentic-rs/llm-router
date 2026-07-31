use crate::{
  AccountPoolId, BindingId, ListenerId, ModelGroupId, OperationId, ProfileId, ProfilePlan, ProviderId, RouteId,
  RoutePlan, UpstreamId,
};
use smol_str::SmolStr;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A fully compiled gateway configuration.
///
/// All cross-references and raw configuration values are expected to be
/// validated before this value is constructed. Runtime crates consume this
/// graph without knowing how it was represented on disk.
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

  /// Match rules in evaluation order. The first matching rule wins.
  pub fn bindings(&self) -> &[BindingPlan] {
    match self {
      Self::LlmApi(listener) => listener.bindings(),
      Self::ForwardProxy(listener) => listener.bindings(),
    }
  }

  pub fn default_action(&self) -> &BindingAction {
    match self {
      Self::LlmApi(listener) => listener.default_action(),
      Self::ForwardProxy(listener) => listener.default_action(),
    }
  }

  pub fn tls(&self) -> Option<&TlsPlan> {
    match self {
      Self::LlmApi(_) => None,
      Self::ForwardProxy(listener) => listener.tls(),
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LlmApiListenerPlan {
  bind: SocketAddr,
  client_auth: ClientAuthPlan,
  bindings: Box<[BindingPlan]>,
  default_action: BindingAction,
}

impl LlmApiListenerPlan {
  pub fn new(
    bind: SocketAddr,
    client_auth: ClientAuthPlan,
    bindings: Box<[BindingPlan]>,
    default_action: BindingAction,
  ) -> Self {
    Self {
      bind,
      client_auth,
      bindings,
      default_action,
    }
  }

  pub fn bind(&self) -> SocketAddr {
    self.bind
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    self.client_auth
  }

  pub fn bindings(&self) -> &[BindingPlan] {
    &self.bindings
  }

  pub fn default_action(&self) -> &BindingAction {
    &self.default_action
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardProxyListenerPlan {
  bind: SocketAddr,
  client_auth: ClientAuthPlan,
  bindings: Box<[BindingPlan]>,
  default_action: BindingAction,
  tls: Option<TlsPlan>,
}

impl ForwardProxyListenerPlan {
  pub fn new(
    bind: SocketAddr,
    client_auth: ClientAuthPlan,
    bindings: Box<[BindingPlan]>,
    default_action: BindingAction,
    tls: Option<TlsPlan>,
  ) -> Self {
    Self {
      bind,
      client_auth,
      bindings,
      default_action,
      tls,
    }
  }

  pub fn bind(&self) -> SocketAddr {
    self.bind
  }

  pub fn client_auth(&self) -> ClientAuthPlan {
    self.client_auth
  }

  pub fn bindings(&self) -> &[BindingPlan] {
    &self.bindings
  }

  pub fn default_action(&self) -> &BindingAction {
    &self.default_action
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

/// Material needed to terminate intercepted forward-proxy TLS connections.
/// Host selection is expressed once through [`BindingAction`], not duplicated
/// in a second TLS-specific rule list.
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
pub struct BindingPlan {
  id: BindingId,
  matcher: BindingMatch,
  action: BindingAction,
}

impl BindingPlan {
  pub fn new(id: BindingId, matcher: BindingMatch, action: BindingAction) -> Self {
    Self { id, matcher, action }
  }

  pub fn id(&self) -> &BindingId {
    &self.id
  }

  pub fn matcher(&self) -> &BindingMatch {
    &self.matcher
  }

  pub fn action(&self) -> &BindingAction {
    &self.action
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingAction {
  /// Select a profile. On a forward-proxy CONNECT request, this also means
  /// intercepting TLS before routing the decoded HTTP request.
  Route(ProfileId),
  /// Preserve the connection as an opaque byte stream.
  Tunnel,
  Reject,
}

/// A host selector in a binding rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostPattern {
  Exact(SmolStr),
  /// Match subdomains of the named suffix, but not the suffix itself.
  SubdomainsOf(SmolStr),
}

impl HostPattern {
  pub fn exact(host: impl AsRef<str>) -> Self {
    Self::Exact(SmolStr::new(host.as_ref().to_ascii_lowercase()))
  }

  pub fn subdomains_of(suffix: impl AsRef<str>) -> Self {
    Self::SubdomainsOf(SmolStr::new(suffix.as_ref().to_ascii_lowercase()))
  }

  pub fn matches(&self, host: &str) -> bool {
    match self {
      Self::Exact(expected) => host.eq_ignore_ascii_case(expected),
      Self::SubdomainsOf(suffix) => {
        host.len() > suffix.len()
          && host
            .get(..host.len() - suffix.len())
            .is_some_and(|prefix| prefix.ends_with('.'))
          && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
      }
    }
  }
}

/// Error returned when a binding tries to act as an implicit catch-all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyBindingMatch;

impl fmt::Display for EmptyBindingMatch {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(
      "a binding must constrain at least one match dimension; use the listener default action for catch-all behavior",
    )
  }
}

impl std::error::Error for EmptyBindingMatch {}

/// Match dimensions are combined with AND. Values within one dimension are
/// combined with OR. An empty dimension is unconstrained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingMatch {
  hosts: Box<[HostPattern]>,
  path_prefixes: Box<[SmolStr]>,
  methods: Box<[SmolStr]>,
  operations: Box<[OperationId]>,
}

impl BindingMatch {
  pub fn new(
    hosts: Box<[HostPattern]>,
    path_prefixes: Box<[SmolStr]>,
    methods: Box<[SmolStr]>,
    operations: Box<[OperationId]>,
  ) -> Result<Self, EmptyBindingMatch> {
    if hosts.is_empty() && path_prefixes.is_empty() && methods.is_empty() && operations.is_empty() {
      return Err(EmptyBindingMatch);
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
}

impl UpstreamPlan {
  pub fn new(provider: ProviderId, base_url: Option<SmolStr>, origins: Box<[UpstreamOrigin]>) -> Self {
    Self {
      provider,
      base_url,
      origins,
    }
  }

  pub fn provider(&self) -> &ProviderId {
    &self.provider
  }

  pub fn base_url(&self) -> Option<&str> {
    self.base_url.as_deref()
  }

  pub fn origins(&self) -> &[UpstreamOrigin] {
    &self.origins
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

  fn matcher(host: &str) -> BindingMatch {
    BindingMatch::new(
      vec![HostPattern::exact(host)].into_boxed_slice(),
      Box::default(),
      Box::default(),
      Box::default(),
    )
    .unwrap()
  }

  #[test]
  fn listener_preserves_binding_order_and_separate_default() {
    let first = BindingPlan::new(
      id("specific"),
      matcher("api.example.com"),
      BindingAction::Route(id("managed")),
    );
    let second = BindingPlan::new(
      id("wildcard"),
      BindingMatch::new(
        vec![HostPattern::subdomains_of("example.com")].into_boxed_slice(),
        Box::default(),
        Box::default(),
        Box::default(),
      )
      .unwrap(),
      BindingAction::Tunnel,
    );
    let listener = ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      "127.0.0.1:8080".parse().unwrap(),
      ClientAuthPlan::LocalKeys,
      vec![first, second].into_boxed_slice(),
      BindingAction::Reject,
      Some(TlsPlan::new(PathBuf::from("/tmp/tokn-ca"))),
    ));

    assert_eq!(listener.kind(), ListenerKind::ForwardProxy);
    assert_eq!(listener.bindings()[0].id().as_str(), "specific");
    assert_eq!(listener.bindings()[1].id().as_str(), "wildcard");
    assert_eq!(listener.default_action(), &BindingAction::Reject);
    assert_eq!(listener.tls().unwrap().ca_dir(), Path::new("/tmp/tokn-ca"));
  }

  #[test]
  fn match_requires_a_dimension_and_exposes_and_or_groups() {
    assert_eq!(
      BindingMatch::new(Box::default(), Box::default(), Box::default(), Box::default()),
      Err(EmptyBindingMatch)
    );

    let rule = BindingMatch::new(
      vec![HostPattern::exact("api.example.com")].into_boxed_slice(),
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
  fn subdomain_pattern_excludes_apex_and_label_lookalikes() {
    let pattern = HostPattern::subdomains_of("example.com");

    assert!(pattern.matches("api.example.com"));
    assert!(pattern.matches("API.EXAMPLE.COM"));
    assert!(!pattern.matches("example.com"));
    assert!(!pattern.matches("notexample.com"));
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
  fn upstream_and_model_group_keep_distinct_ordered_facts() {
    let upstream = UpstreamPlan::new(
      id("openai"),
      Some(SmolStr::new("https://gateway.example/v1")),
      vec![
        UpstreamOrigin::new("https://api.openai.com"),
        UpstreamOrigin::new("https://chatgpt.com"),
      ]
      .into_boxed_slice(),
    );
    let group = ModelGroupPlan::new(
      vec![
        ModelCandidate::new(Some(id("openai-public")), "gpt-5"),
        ModelCandidate::new(None, "claude-sonnet"),
      ]
      .into_boxed_slice(),
    );

    assert_eq!(upstream.provider().as_str(), "openai");
    assert_eq!(upstream.origins()[1].as_str(), "https://chatgpt.com");
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
      BindingAction::Route(profile_id.clone()),
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
        UpstreamPlan::new(id("openai"), None, Box::default()),
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

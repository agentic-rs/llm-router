//! Synchronous HTTP dispatch over the fully linked runtime graph.
//!
//! Listener matching is deliberately separate from route resolution. The
//! first stage needs only admitted request-line facts and pins the exact
//! profile generation. The second stage may then use parsed managed semantics
//! to select an account target without allowing payload facts to change which
//! listener action matched.

use super::{HttpRequestFacts, LinkedHttpAction, LinkedListener, LinkedProfile, LinkedWireIdentity};
use http::{uri::PathAndQuery, Method};
use smol_str::SmolStr;
use snafu::Snafu;
use std::fmt;
use std::sync::Arc;
use tokn_access::ProviderAccess;
use tokn_accounts::link::{
  resolve_managed_target, resolve_relay_target, LinkedRoute, LinkedRouteKind, PoolRuntimeResult, SelectedManagedTarget,
  SelectedRelayTarget, SelectionOutcome, SelectionSettlement, TargetResolution, TargetResolveError,
};
use tokn_core::provider::{Endpoint, ProviderRequestKind};
use tokn_core::upstream_url::CanonicalHttpOrigin;
use tokn_core::AgentId;
use tokn_policy::{
  BindingId, CanonicalHttpPath, HttpIngress, InvalidHttpPath, ListenerId, ProfileId, ProviderId, RouteId,
};
use tokn_requests::execution::{ExecutionTarget, HttpAttemptHead};

/// Immutable, typed request-line and ingress facts admitted at the HTTP trust
/// boundary.
///
/// The canonical path is derived once from the exact path-and-query retained
/// for execution. This prevents listener matching and upstream forwarding from
/// observing request targets that disagree through decoding or normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequestHead {
  ingress: HttpIngress,
  method: Method,
  path_and_query: PathAndQuery,
  canonical_path: CanonicalHttpPath,
}

impl HttpRequestHead {
  pub fn new(ingress: HttpIngress, method: Method, path_and_query: PathAndQuery) -> Result<Self, InvalidHttpPath> {
    let canonical_path = CanonicalHttpPath::parse(path_and_query.path())?;
    Ok(Self {
      ingress,
      method,
      path_and_query,
      canonical_path,
    })
  }

  pub fn ingress(&self) -> &HttpIngress {
    &self.ingress
  }

  pub fn method(&self) -> &Method {
    &self.method
  }

  pub fn path_and_query(&self) -> &PathAndQuery {
    &self.path_and_query
  }

  pub fn canonical_path(&self) -> &CanonicalHttpPath {
    &self.canonical_path
  }
}

/// Payload-independent semantics available before a route is selected.
///
/// Opaque traffic may still carry an inferred operation for listener
/// matching. It deliberately cannot provide a model to managed routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRequestSemantics<'a> {
  Opaque {
    operation: Option<Endpoint>,
  },
  Structured {
    requested_model: &'a str,
    requested_operation: Endpoint,
  },
}

impl HttpRequestSemantics<'_> {
  pub fn operation(self) -> Option<Endpoint> {
    match self {
      Self::Opaque { operation } => operation,
      Self::Structured {
        requested_operation, ..
      } => Some(requested_operation),
    }
  }

  fn provider_request_kind(self, path_and_query: &PathAndQuery) -> ProviderRequestKind {
    self
      .operation()
      .map(ProviderRequestKind::Operation)
      .unwrap_or_else(|| ProviderRequestKind::from_provider_path(path_and_query.as_str()))
  }
}

/// Typed facts required to dispatch one HTTP request.
#[derive(Clone, Copy, Debug)]
pub struct HttpDispatchRequest<'a> {
  pub head: &'a HttpRequestHead,
  pub semantics: HttpRequestSemantics<'a>,
  pub session_id: Option<&'a str>,
}

/// Stable listener location that made the dispatch decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpDispatchSite {
  listener_id: ListenerId,
  binding_id: Option<BindingId>,
}

impl HttpDispatchSite {
  pub fn listener_id(&self) -> &ListenerId {
    &self.listener_id
  }

  /// `None` identifies the listener's default HTTP action.
  pub fn binding_id(&self) -> Option<&BindingId> {
    self.binding_id.as_ref()
  }
}

impl fmt::Display for HttpDispatchSite {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self.binding_id {
      Some(binding) => write!(formatter, "listener '{}' HTTP binding '{}'", self.listener_id, binding),
      None => write!(formatter, "listener '{}' default HTTP action", self.listener_id),
    }
  }
}

/// Payload-independent listener decision for one admitted HTTP request.
#[derive(Debug)]
pub enum HttpRouteMatch {
  Reject(HttpDispatchSite),
  Route(MatchedHttpRoute),
}

impl HttpRouteMatch {
  pub fn site(&self) -> &HttpDispatchSite {
    match self {
      Self::Reject(site) => site,
      Self::Route(route) => route.site(),
    }
  }
}

/// An HTTP route pinned to the exact listener action and linked profile that
/// matched before any managed request body is inspected.
#[derive(Debug)]
pub struct MatchedHttpRoute {
  site: HttpDispatchSite,
  head: HttpRequestHead,
  profile: Arc<LinkedProfile>,
  request_kind: ProviderRequestKind,
}

impl MatchedHttpRoute {
  pub fn site(&self) -> &HttpDispatchSite {
    &self.site
  }

  pub fn head(&self) -> &HttpRequestHead {
    &self.head
  }

  pub fn profile(&self) -> &Arc<LinkedProfile> {
    &self.profile
  }

  pub fn route(&self) -> &Arc<LinkedRoute> {
    self.profile.route()
  }

  pub fn request_kind(&self) -> ProviderRequestKind {
    self.request_kind
  }

  /// Resolve the matched profile into one request-time target decision.
  ///
  /// Managed semantics are intentionally required here, after the listener
  /// action is fixed. Relay authorization remains pinned to the request kind
  /// retained by the matching stage and cannot be changed by later payload
  /// inspection.
  pub fn resolve(
    self,
    semantics: HttpRequestSemantics<'_>,
    session_id: Option<&str>,
    provider_access: &ProviderAccess,
  ) -> HttpDispatchResult<RoutedHttpDispatch> {
    let resolution = resolve_profile(
      &self.site,
      &self.head,
      &self.profile,
      self.request_kind,
      semantics,
      session_id,
      provider_access,
    )?;
    Ok(RoutedHttpDispatch {
      site: self.site,
      head: self.head,
      profile: self.profile,
      resolution: Box::new(resolution),
    })
  }
}

/// Complete dispatch decision for one request.
#[derive(Debug)]
pub enum HttpDispatch {
  Reject(HttpDispatchSite),
  Routed(RoutedHttpDispatch),
}

impl HttpDispatch {
  pub fn site(&self) -> &HttpDispatchSite {
    match self {
      Self::Reject(site) => site,
      Self::Routed(routed) => routed.site(),
    }
  }
}

/// A routed request pinned to the exact linked profile and route generation
/// selected by the listener action.
#[derive(Debug)]
pub struct RoutedHttpDispatch {
  site: HttpDispatchSite,
  head: HttpRequestHead,
  profile: Arc<LinkedProfile>,
  resolution: Box<TargetResolution<SelectedHttpTarget>>,
}

impl RoutedHttpDispatch {
  pub fn site(&self) -> &HttpDispatchSite {
    &self.site
  }

  pub fn head(&self) -> &HttpRequestHead {
    &self.head
  }

  pub fn profile(&self) -> &Arc<LinkedProfile> {
    &self.profile
  }

  pub fn route(&self) -> &Arc<LinkedRoute> {
    self.profile.route()
  }

  pub fn resolution(&self) -> &TargetResolution<SelectedHttpTarget> {
    self.resolution.as_ref()
  }

  /// Borrow the exact admitted request head and selected target for one
  /// execution attempt. Cooling and ineligible resolutions have no execution
  /// view because no account/upstream target was selected.
  pub fn execution_view(&self) -> Option<HttpExecutionView<'_>> {
    let TargetResolution::Selected(target) = self.resolution() else {
      return None;
    };
    Some(HttpExecutionView {
      head: HttpAttemptHead::new(self.head.method(), self.head.path_and_query()),
      target: target.execution_target(),
    })
  }

  pub fn into_parts(
    self,
  ) -> (
    HttpDispatchSite,
    HttpRequestHead,
    Arc<LinkedProfile>,
    TargetResolution<SelectedHttpTarget>,
  ) {
    (self.site, self.head, self.profile, *self.resolution)
  }
}

/// Borrowed input to one post-dispatch HTTP execution attempt.
#[derive(Clone, Copy, Debug)]
pub struct HttpExecutionView<'a> {
  head: HttpAttemptHead<'a>,
  target: ExecutionTarget<'a>,
}

impl<'a> HttpExecutionView<'a> {
  pub fn head(&self) -> HttpAttemptHead<'a> {
    self.head
  }

  pub fn target(&self) -> ExecutionTarget<'a> {
    self.target
  }
}

/// Route-family-specific selected HTTP execution target.
#[derive(Debug)]
pub enum SelectedHttpTarget {
  Managed(SelectedManagedHttpTarget),
  Relay(SelectedRelayHttpTarget),
  Transparent(SelectedTransparentHttpTarget),
}

impl SelectedHttpTarget {
  pub fn execution_target(&self) -> ExecutionTarget<'_> {
    match self {
      Self::Managed(selected) => ExecutionTarget::managed(
        selected.requested_model(),
        selected.requested_operation(),
        selected.target(),
        selected.wire_identity(),
      ),
      Self::Relay(selected) => {
        ExecutionTarget::relay(selected.request_kind(), selected.target(), selected.wire_identity())
      }
      Self::Transparent(selected) => ExecutionTarget::transparent(selected.destination()),
    }
  }

  /// Consume the exact selected target and apply one pool-local outcome.
  /// Transparent traffic has no account selection and therefore settles as
  /// unchanged without touching pool state.
  pub fn settle(self, outcome: SelectionOutcome) -> PoolRuntimeResult<SelectionSettlement> {
    match self {
      Self::Managed(selected) => selected.into_target().into_selection_token().settle(outcome),
      Self::Relay(selected) => selected.into_target().into_selection_token().settle(outcome),
      Self::Transparent(_) => Ok(SelectionSettlement::Unchanged),
    }
  }
}

/// Managed selection keeps inbound request semantics alongside the outbound
/// model and operation selected by the accounts resolver.
#[derive(Debug)]
pub struct SelectedManagedHttpTarget {
  requested_model: SmolStr,
  requested_operation: Endpoint,
  target: SelectedManagedTarget,
  wire_identity: Option<AgentId>,
}

impl SelectedManagedHttpTarget {
  pub fn requested_model(&self) -> &str {
    self.requested_model.as_str()
  }

  pub fn requested_operation(&self) -> Endpoint {
    self.requested_operation
  }

  pub fn target(&self) -> &SelectedManagedTarget {
    &self.target
  }

  pub fn wire_identity(&self) -> Option<&AgentId> {
    self.wire_identity.as_ref()
  }

  pub fn into_target(self) -> SelectedManagedTarget {
    self.target
  }
}

/// Opaque relay selection with its post-selection wire identity.
#[derive(Debug)]
pub struct SelectedRelayHttpTarget {
  target: SelectedRelayTarget,
  request_kind: ProviderRequestKind,
  wire_identity: Option<AgentId>,
}

impl SelectedRelayHttpTarget {
  pub fn target(&self) -> &SelectedRelayTarget {
    &self.target
  }

  pub fn request_kind(&self) -> ProviderRequestKind {
    self.request_kind
  }

  pub fn wire_identity(&self) -> Option<&AgentId> {
    self.wire_identity.as_ref()
  }

  pub fn into_target(self) -> SelectedRelayTarget {
    self.target
  }
}

/// Account-less transparent destination derived from typed HTTP ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedTransparentHttpTarget {
  destination: CanonicalHttpOrigin,
}

impl SelectedTransparentHttpTarget {
  pub fn destination(&self) -> &CanonicalHttpOrigin {
    &self.destination
  }
}

/// Match one admitted request against a linked listener without consulting
/// managed payload semantics or selecting an account target.
pub fn match_http(
  listener: &LinkedListener,
  head: HttpRequestHead,
  request_kind: ProviderRequestKind,
) -> HttpRouteMatch {
  let facts = HttpRequestFacts {
    ingress: head.ingress(),
    path: head.canonical_path(),
    method: head.method().as_str(),
    operation: request_kind.endpoint(),
  };
  let decision = listener.http().decide(&facts);
  let site = HttpDispatchSite {
    listener_id: listener.id().clone(),
    binding_id: decision.binding_id().cloned(),
  };

  let LinkedHttpAction::Route(profile) = decision.action() else {
    return HttpRouteMatch::Reject(site);
  };
  HttpRouteMatch::Route(MatchedHttpRoute {
    site,
    head,
    profile: profile.clone(),
    request_kind,
  })
}

/// Dispatch one request through both matching and target-resolution stages.
pub fn dispatch_http(
  listener: &LinkedListener,
  request: HttpDispatchRequest<'_>,
  provider_access: &ProviderAccess,
) -> HttpDispatchResult<HttpDispatch> {
  let request_kind = request.semantics.provider_request_kind(request.head.path_and_query());
  match match_http(listener, request.head.clone(), request_kind) {
    HttpRouteMatch::Reject(site) => Ok(HttpDispatch::Reject(site)),
    HttpRouteMatch::Route(route) => route
      .resolve(request.semantics, request.session_id, provider_access)
      .map(HttpDispatch::Routed),
  }
}

fn resolve_profile(
  site: &HttpDispatchSite,
  head: &HttpRequestHead,
  profile: &LinkedProfile,
  request_kind: ProviderRequestKind,
  semantics: HttpRequestSemantics<'_>,
  session_id: Option<&str>,
  provider_access: &ProviderAccess,
) -> HttpDispatchResult<TargetResolution<SelectedHttpTarget>> {
  match profile.route().kind() {
    LinkedRouteKind::Managed(route) => {
      let HttpRequestSemantics::Structured {
        requested_model,
        requested_operation,
      } = semantics
      else {
        return Err(HttpDispatchError::ManagedStructuredSemanticsRequired {
          site: site.clone(),
          profile: profile.id().clone(),
          route: profile.route().id().clone(),
        });
      };
      match request_kind {
        ProviderRequestKind::Operation(matched_operation) if matched_operation == requested_operation => {}
        ProviderRequestKind::Operation(matched_operation) => {
          return Err(HttpDispatchError::ManagedOperationChangedAfterMatch {
            site: site.clone(),
            profile: profile.id().clone(),
            route: profile.route().id().clone(),
            matched_operation,
            requested_operation,
          });
        }
        request_kind @ (ProviderRequestKind::Models | ProviderRequestKind::Opaque) => {
          return Err(HttpDispatchError::ManagedOperationRequestKindRequired {
            site: site.clone(),
            profile: profile.id().clone(),
            route: profile.route().id().clone(),
            request_kind,
          });
        }
      }
      let resolution = resolve_managed_target(route, requested_model, requested_operation, session_id, |provider| {
        provider_access.allows(provider.as_str())
      })
      .map_err(|source| HttpDispatchError::ManagedTarget {
        site: site.clone(),
        profile: profile.id().clone(),
        route: profile.route().id().clone(),
        source: Box::new(source),
      })?;
      map_managed_resolution(site, profile, requested_model, requested_operation, resolution)
    }
    LinkedRouteKind::Relay(route) => {
      let resolution = resolve_relay_target(route, head.ingress(), session_id, |provider| {
        provider_access.allows(provider.as_str())
      });
      map_relay_resolution(site, profile, request_kind, resolution)
    }
    LinkedRouteKind::Transparent(_) => Ok(TargetResolution::Selected(SelectedHttpTarget::Transparent(
      SelectedTransparentHttpTarget {
        destination: CanonicalHttpOrigin::from_ingress(head.ingress()),
      },
    ))),
  }
}

fn map_managed_resolution(
  site: &HttpDispatchSite,
  profile: &LinkedProfile,
  requested_model: &str,
  requested_operation: Endpoint,
  resolution: TargetResolution<SelectedManagedTarget>,
) -> HttpDispatchResult<TargetResolution<SelectedHttpTarget>> {
  match resolution {
    TargetResolution::Selected(target) => {
      let wire_identity = resolve_wire_identity(
        site,
        profile.id(),
        profile.route().id(),
        profile.wire_identity(),
        target.upstream().provider_id(),
      )?;
      Ok(TargetResolution::Selected(SelectedHttpTarget::Managed(
        SelectedManagedHttpTarget {
          requested_model: SmolStr::new(requested_model),
          requested_operation,
          target,
          wire_identity,
        },
      )))
    }
    TargetResolution::CoolingDown { retry_at } => Ok(TargetResolution::CoolingDown { retry_at }),
    TargetResolution::NoEligible { reason } => Ok(TargetResolution::NoEligible { reason }),
  }
}

fn map_relay_resolution(
  site: &HttpDispatchSite,
  profile: &LinkedProfile,
  request_kind: ProviderRequestKind,
  resolution: TargetResolution<SelectedRelayTarget>,
) -> HttpDispatchResult<TargetResolution<SelectedHttpTarget>> {
  match resolution {
    TargetResolution::Selected(target) => {
      let wire_identity = resolve_wire_identity(
        site,
        profile.id(),
        profile.route().id(),
        profile.wire_identity(),
        target.upstream().provider_id(),
      )?;
      Ok(TargetResolution::Selected(SelectedHttpTarget::Relay(
        SelectedRelayHttpTarget {
          target,
          request_kind,
          wire_identity,
        },
      )))
    }
    TargetResolution::CoolingDown { retry_at } => Ok(TargetResolution::CoolingDown { retry_at }),
    TargetResolution::NoEligible { reason } => Ok(TargetResolution::NoEligible { reason }),
  }
}

fn resolve_wire_identity(
  site: &HttpDispatchSite,
  profile: &ProfileId,
  route: &RouteId,
  identity: &LinkedWireIdentity,
  provider: &ProviderId,
) -> HttpDispatchResult<Option<AgentId>> {
  match identity {
    LinkedWireIdentity::None => Ok(None),
    LinkedWireIdentity::Fixed(identity) => Ok(Some(identity.clone())),
    LinkedWireIdentity::ProviderDefaults(defaults) => {
      defaults
        .get(provider)
        .cloned()
        .map(Some)
        .ok_or_else(|| HttpDispatchError::MissingProviderWireIdentity {
          site: site.clone(),
          profile: profile.clone(),
          route: route.clone(),
          provider: provider.clone(),
        })
    }
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum HttpDispatchError {
  #[snafu(display(
    "{site} selected managed profile '{profile}' route '{route}', but the request has opaque semantics"
  ))]
  ManagedStructuredSemanticsRequired {
    site: HttpDispatchSite,
    profile: ProfileId,
    route: RouteId,
  },

  #[snafu(display(
    "{site} selected managed profile '{profile}' route '{route}', but matched request kind {request_kind:?} is not an LLM operation"
  ))]
  ManagedOperationRequestKindRequired {
    site: HttpDispatchSite,
    profile: ProfileId,
    route: RouteId,
    request_kind: ProviderRequestKind,
  },

  #[snafu(display(
    "{site} selected managed profile '{profile}' route '{route}' for operation {matched_operation}, but resolution supplied operation {requested_operation}"
  ))]
  ManagedOperationChangedAfterMatch {
    site: HttpDispatchSite,
    profile: ProfileId,
    route: RouteId,
    matched_operation: Endpoint,
    requested_operation: Endpoint,
  },

  #[snafu(display("{site} failed to resolve managed profile '{profile}' route '{route}': {source}"))]
  ManagedTarget {
    site: HttpDispatchSite,
    profile: ProfileId,
    route: RouteId,
    source: Box<TargetResolveError>,
  },

  #[snafu(display(
    "{site} profile '{profile}' route '{route}' has no linked default wire identity for selected provider '{provider}'"
  ))]
  MissingProviderWireIdentity {
    site: HttpDispatchSite,
    profile: ProfileId,
    route: RouteId,
    provider: ProviderId,
  },
}

pub type HttpDispatchResult<T> = std::result::Result<T, HttpDispatchError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{link_gateway_runtime, LinkedGatewayRuntime, RuntimeNameRegistry};
  use smol_str::SmolStr;
  use std::collections::{BTreeMap, BTreeSet};
  use std::net::{Ipv4Addr, SocketAddr};
  use std::path::PathBuf;
  use std::time::Duration;
  use tokn_accounts::link::{NoEligibleReason, QualificationSyntaxError, RelayDestination};
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, CanonicalAuthority, ClientAuthPlan,
    ConnectAction, FallbackSelector, ForwardProxyListenerPlan, GatewayPlan, HttpAction, HttpBindingPlan, HttpMatch,
    HttpScheme, IngressAuthority, ListenerPlan, LlmApiListenerPlan, ManagedRetry, ManagedRoute, ManagedTarget,
    ModelCandidate, ModelGroupId, ModelGroupPlan, ModelSelector, OperationId, OperationPolicy, ProfilePlan,
    QualificationNamespace, RelayRetry, RelayRoute, RelayTarget, RoutePlan, SessionAffinityPlan, TlsPlan, UpstreamId,
    UpstreamOrigin, UpstreamPlan, UpstreamSelector, WireIdentity,
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

  fn pool_id(value: &str) -> AccountPoolId {
    AccountPoolId::new(value).unwrap()
  }

  fn upstream_id(value: &str) -> UpstreamId {
    UpstreamId::new(value).unwrap()
  }

  fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
  }

  fn group_id(value: &str) -> ModelGroupId {
    ModelGroupId::new(value).unwrap()
  }

  fn operation_id(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
  }

  fn account(id: &str) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.id = id.to_string();
    account.tier = AccountTier::Active;
    account
  }

  fn pool() -> AccountPoolPlan {
    AccountPoolPlan::new(
      AccountSelector::all(),
      AccountSelectionStrategy::RoundRobin,
      Duration::from_secs(60),
      Some(SessionAffinityPlan::new(
        Duration::from_secs(300),
        Duration::from_secs(60),
      )),
    )
  }

  fn upstream(base_url: &str, origins: &[&str]) -> UpstreamPlan {
    UpstreamPlan::new(
      provider_id(ID_LLAMA_CPP),
      Some(base_url.into()),
      origins
        .iter()
        .map(|origin| UpstreamOrigin::new(*origin))
        .collect::<Vec<_>>()
        .into_boxed_slice(),
      false,
    )
    .with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("account")])))
  }

  fn operation_binding(id: &str, operation: &str, profile: &str) -> HttpBindingPlan {
    HttpBindingPlan::new(
      binding_id(id),
      HttpMatch::new(
        Box::default(),
        Box::default(),
        Box::default(),
        vec![operation_id(operation)].into_boxed_slice(),
      )
      .unwrap(),
      HttpAction::Route(profile_id(profile)),
    )
  }

  fn llm_listener(bindings: Vec<HttpBindingPlan>, default: HttpAction) -> ListenerPlan {
    ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 42_101)),
      ClientAuthPlan::None,
      bindings.into_boxed_slice(),
      default,
    ))
  }

  fn proxy_listener(
    bindings: Vec<HttpBindingPlan>,
    default: HttpAction,
    connect: ConnectAction,
    tls: Option<TlsPlan>,
  ) -> ListenerPlan {
    ListenerPlan::ForwardProxy(ForwardProxyListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 42_102)),
      ClientAuthPlan::None,
      bindings.into_boxed_slice(),
      default,
      Box::default(),
      connect,
      tls,
    ))
  }

  fn gateway(
    listener: ListenerPlan,
    profiles: BTreeMap<ProfileId, ProfilePlan>,
    routes: BTreeMap<RouteId, RoutePlan>,
    pools: BTreeMap<AccountPoolId, AccountPoolPlan>,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
    groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::from([(listener_id("listener"), listener)]),
      profiles,
      routes,
      pools,
      upstreams,
      groups,
    )
  }

  fn link(plan: &GatewayPlan, accounts: &[AccountConfig]) -> LinkedGatewayRuntime {
    link_gateway_runtime(plan, accounts, &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap()
  }

  fn direct_ingress(authority: &str) -> HttpIngress {
    HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse(authority).unwrap())
  }

  fn request_head(ingress: HttpIngress, path_and_query: &str) -> HttpRequestHead {
    HttpRequestHead::new(ingress, Method::POST, path_and_query.parse().unwrap()).unwrap()
  }

  fn request<'a>(head: &'a HttpRequestHead, semantics: HttpRequestSemantics<'a>) -> HttpDispatchRequest<'a> {
    HttpDispatchRequest {
      head,
      semantics,
      session_id: Some("session"),
    }
  }

  fn routed(dispatch: HttpDispatch) -> RoutedHttpDispatch {
    let HttpDispatch::Routed(routed) = dispatch else {
      panic!("expected routed dispatch, got {dispatch:?}");
    };
    routed
  }

  fn matched(result: HttpRouteMatch) -> MatchedHttpRoute {
    let HttpRouteMatch::Route(route) = result else {
      panic!("expected matched route, got {result:?}");
    };
    route
  }

  #[test]
  fn request_head_keeps_the_exact_target_but_canonicalizes_the_match_path() {
    let head = request_head(
      direct_ingress("client.example"),
      "/v1%2fchat/completions?redirect=https%3A%2F%2Fother.example",
    );

    assert_eq!(head.method(), Method::POST);
    assert_eq!(head.canonical_path().as_str(), "/v1%2Fchat/completions");
    assert_eq!(
      head.path_and_query().as_str(),
      "/v1%2fchat/completions?redirect=https%3A%2F%2Fother.example"
    );

    let invalid = HttpRequestHead::new(
      direct_ingress("client.example"),
      Method::GET,
      "/safe/%2e%2e/private".parse().unwrap(),
    )
    .unwrap_err();
    assert_eq!(invalid, InvalidHttpPath::DotSegment);
  }

  #[test]
  fn managed_preserves_exact_arcs_and_inbound_and_outbound_semantics() {
    let group = group_id("fallback");
    let plan = gateway(
      llm_listener(
        vec![operation_binding("managed-binding", "responses", "managed-profile")],
        HttpAction::Reject,
      ),
      BTreeMap::from([(
        profile_id("managed-profile"),
        ProfilePlan::new(route_id("managed-route"), WireIdentity::ProviderDefault),
      )]),
      BTreeMap::from([(
        route_id("managed-route"),
        RoutePlan::Managed(ManagedRoute::new(
          ManagedTarget::new(
            pool_id("default"),
            UpstreamSelector::Fixed(upstream_id("upstream")),
            ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
          ),
          OperationPolicy::TranslateCompatible,
          None,
          ManagedRetry::Never,
        )),
      )]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(upstream_id("upstream"), upstream("https://upstream.example/v1/", &[]))]),
      BTreeMap::from([(
        group,
        ModelGroupPlan::new(
          vec![ModelCandidate::new(Some(upstream_id("upstream")), "outbound-model")].into_boxed_slice(),
        ),
      )]),
    );
    let runtime = link(&plan, &[account("account")]);
    let listener_key = listener_id("listener");
    let profile_key = profile_id("managed-profile");
    let route_key = route_id("managed-route");
    let listener = runtime.listeners().listener(&listener_key).unwrap();
    let action_profile = listener.http().bindings()[0].action().profile().unwrap();
    let head = request_head(direct_ingress("client.example"), "/v1/responses?trace=one%2Ftwo");

    let dispatch = dispatch_http(
      listener,
      request(
        &head,
        HttpRequestSemantics::Structured {
          requested_model: "inbound-model",
          requested_operation: Endpoint::Responses,
        },
      ),
      &ProviderAccess::All,
    )
    .unwrap();
    let routed = routed(dispatch);

    assert_eq!(routed.site().listener_id(), &listener_key);
    assert_eq!(routed.site().binding_id().unwrap().as_str(), "managed-binding");
    assert_eq!(routed.head(), &head);
    assert_eq!(routed.head().path_and_query().as_str(), "/v1/responses?trace=one%2Ftwo");
    assert!(Arc::ptr_eq(routed.profile(), action_profile));
    assert!(Arc::ptr_eq(
      routed.profile(),
      runtime.profiles().profile(&profile_key).unwrap()
    ));
    assert!(Arc::ptr_eq(routed.route(), runtime.routes().route(&route_key).unwrap()));

    let TargetResolution::Selected(SelectedHttpTarget::Managed(selected)) = routed.resolution() else {
      panic!("expected selected managed target, got {:?}", routed.resolution());
    };
    let execution = routed.execution_view().unwrap();
    assert!(std::ptr::eq(execution.head().method(), routed.head().method()));
    assert!(std::ptr::eq(
      execution.head().path_and_query(),
      routed.head().path_and_query()
    ));
    let ExecutionTarget::Managed(execution_target) = execution.target() else {
      panic!("expected managed execution target");
    };
    assert!(std::ptr::eq(execution_target.target(), selected.target()));
    assert_eq!(execution_target.wire_identity(), selected.wire_identity());
    assert_eq!(selected.requested_model(), "inbound-model");
    assert_eq!(selected.requested_operation(), Endpoint::Responses);
    assert_eq!(selected.target().model(), "outbound-model");
    assert_eq!(selected.target().operation(), Endpoint::ChatCompletions);
    assert_eq!(selected.wire_identity(), Some(&AgentId::Opencode));
    assert_eq!(
      selected.target().selection_token().key().upstream_id(),
      &upstream_id("upstream")
    );
    assert_eq!(selected.target().selection_token().key().account_id(), "account");

    let (_, _, _, resolution) = routed.into_parts();
    let TargetResolution::Selected(target) = resolution else {
      panic!("expected selected managed target");
    };
    assert_eq!(
      target.settle(SelectionOutcome::Healthy).unwrap(),
      SelectionSettlement::Healthy
    );
  }

  #[test]
  fn default_reject_needs_no_structured_semantics() {
    let plan = gateway(
      llm_listener(Vec::new(), HttpAction::Reject),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let runtime = link(&plan, &[]);
    let listener = runtime.listeners().listener(&listener_id("listener")).unwrap();
    let head = request_head(direct_ingress("reject.example"), "/opaque");
    let denied = ProviderAccess::from_provider_ids(vec!["nothing".into()]).unwrap();

    let matched = match_http(listener, head.clone(), ProviderRequestKind::Opaque);
    let HttpRouteMatch::Reject(site) = matched else {
      panic!("expected matching stage to reject");
    };
    assert_eq!(site.listener_id().as_str(), "listener");
    assert!(site.binding_id().is_none());

    let dispatch = dispatch_http(
      listener,
      request(&head, HttpRequestSemantics::Opaque { operation: None }),
      &denied,
    )
    .unwrap();

    let HttpDispatch::Reject(site) = dispatch else {
      panic!("expected reject");
    };
    assert_eq!(site.listener_id().as_str(), "listener");
    assert!(site.binding_id().is_none());
  }

  #[test]
  fn opaque_inferred_operations_match_relay_and_transparent_bindings() {
    let plan = gateway(
      proxy_listener(
        vec![
          operation_binding("relay-binding", "responses", "relay-profile"),
          operation_binding("transparent-binding", "messages", "transparent-profile"),
        ],
        HttpAction::Reject,
        ConnectAction::Tunnel,
        None,
      ),
      BTreeMap::from([
        (
          profile_id("relay-profile"),
          ProfilePlan::new(route_id("relay-route"), WireIdentity::ProviderDefault),
        ),
        (
          profile_id("transparent-profile"),
          ProfilePlan::new(route_id("transparent-route"), WireIdentity::None),
        ),
      ]),
      BTreeMap::from([
        (
          route_id("relay-route"),
          RoutePlan::Relay(RelayRoute::new(
            RelayTarget::FixedUpstream {
              upstream: upstream_id("upstream"),
              account_pool: pool_id("default"),
            },
            None,
            RelayRetry::Never,
          )),
        ),
        (
          route_id("transparent-route"),
          RoutePlan::Transparent(Default::default()),
        ),
      ]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(upstream_id("upstream"), upstream("https://upstream.example/v1/", &[]))]),
      BTreeMap::new(),
    );
    let runtime = link(&plan, &[account("account")]);
    let listener = runtime.listeners().listener(&listener_id("listener")).unwrap();
    let head = request_head(direct_ingress("original.example"), "/opaque");

    let relay = matched(match_http(
      listener,
      head.clone(),
      ProviderRequestKind::Operation(Endpoint::Responses),
    ))
    .resolve(
      HttpRequestSemantics::Opaque {
        operation: Some(Endpoint::Messages),
      },
      Some("session"),
      &ProviderAccess::All,
    )
    .unwrap();
    assert_eq!(relay.site().binding_id().unwrap().as_str(), "relay-binding");
    assert!(matches!(
      relay.resolution(),
      TargetResolution::Selected(SelectedHttpTarget::Relay(selected))
        if selected.request_kind() == ProviderRequestKind::Operation(Endpoint::Responses)
    ));
    let execution = relay.execution_view().unwrap();
    let ExecutionTarget::Relay(execution_target) = execution.target() else {
      panic!("expected relay execution target");
    };
    assert_eq!(
      execution_target.request_kind(),
      ProviderRequestKind::Operation(Endpoint::Responses)
    );
    assert_eq!(
      execution_target.request_url(execution.head()).unwrap().as_str(),
      "https://upstream.example/v1/opaque"
    );

    let transparent = routed(
      dispatch_http(
        listener,
        request(
          &head,
          HttpRequestSemantics::Opaque {
            operation: Some(Endpoint::Messages),
          },
        ),
        &ProviderAccess::All,
      )
      .unwrap(),
    );
    assert_eq!(transparent.site().binding_id().unwrap().as_str(), "transparent-binding");
    assert!(matches!(
      transparent.resolution(),
      TargetResolution::Selected(SelectedHttpTarget::Transparent(_))
    ));
  }

  #[test]
  fn managed_route_rejects_opaque_semantics_with_full_context() {
    let plan = gateway(
      llm_listener(Vec::new(), HttpAction::Route(profile_id("managed-profile"))),
      BTreeMap::from([(
        profile_id("managed-profile"),
        ProfilePlan::new(route_id("managed-route"), WireIdentity::None),
      )]),
      BTreeMap::from([(
        route_id("managed-route"),
        RoutePlan::Managed(ManagedRoute::new(
          ManagedTarget::new(
            pool_id("default"),
            UpstreamSelector::Fixed(upstream_id("upstream")),
            ModelSelector::Capability,
          ),
          OperationPolicy::Preserve,
          None,
          ManagedRetry::Never,
        )),
      )]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(upstream_id("upstream"), upstream("https://upstream.example/v1/", &[]))]),
      BTreeMap::new(),
    );
    let runtime = link(&plan, &[account("account")]);
    let listener = runtime.listeners().listener(&listener_id("listener")).unwrap();
    let head = request_head(direct_ingress("managed.example"), "/opaque");

    let route = matched(match_http(
      listener,
      head.clone(),
      ProviderRequestKind::Operation(Endpoint::ChatCompletions),
    ));
    assert_eq!(route.head(), &head);
    assert!(Arc::ptr_eq(
      route.profile(),
      runtime.profiles().profile(&profile_id("managed-profile")).unwrap()
    ));

    let error = route
      .resolve(
        HttpRequestSemantics::Opaque {
          operation: Some(Endpoint::ChatCompletions),
        },
        Some("session"),
        &ProviderAccess::All,
      )
      .unwrap_err();

    assert!(matches!(
      error,
      HttpDispatchError::ManagedStructuredSemanticsRequired {
        site,
        profile,
        route,
      } if site.listener_id().as_str() == "listener"
        && site.binding_id().is_none()
        && profile.as_str() == "managed-profile"
        && route.as_str() == "managed-route"
    ));
  }

  #[test]
  fn managed_resolution_cannot_change_or_invent_the_matched_operation() {
    let plan = gateway(
      llm_listener(Vec::new(), HttpAction::Route(profile_id("managed-profile"))),
      BTreeMap::from([(
        profile_id("managed-profile"),
        ProfilePlan::new(route_id("managed-route"), WireIdentity::None),
      )]),
      BTreeMap::from([(
        route_id("managed-route"),
        RoutePlan::Managed(ManagedRoute::new(
          ManagedTarget::new(
            pool_id("default"),
            UpstreamSelector::Fixed(upstream_id("upstream")),
            ModelSelector::Capability,
          ),
          OperationPolicy::TranslateCompatible,
          None,
          ManagedRetry::Never,
        )),
      )]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(upstream_id("upstream"), upstream("https://upstream.example/v1/", &[]))]),
      BTreeMap::new(),
    );
    let runtime = link(&plan, &[account("account")]);
    let listener = runtime.listeners().listener(&listener_id("listener")).unwrap();
    let head = request_head(direct_ingress("managed.example"), "/v1/responses");

    let changed = matched(match_http(
      listener,
      head.clone(),
      ProviderRequestKind::Operation(Endpoint::Responses),
    ))
    .resolve(
      HttpRequestSemantics::Structured {
        requested_model: "model",
        requested_operation: Endpoint::ChatCompletions,
      },
      None,
      &ProviderAccess::All,
    )
    .unwrap_err();
    assert!(matches!(
      changed,
      HttpDispatchError::ManagedOperationChangedAfterMatch {
        matched_operation: Endpoint::Responses,
        requested_operation: Endpoint::ChatCompletions,
        ..
      }
    ));

    let non_operation = matched(match_http(listener, head, ProviderRequestKind::Models))
      .resolve(
        HttpRequestSemantics::Structured {
          requested_model: "model",
          requested_operation: Endpoint::Responses,
        },
        None,
        &ProviderAccess::All,
      )
      .unwrap_err();
    assert!(matches!(
      non_operation,
      HttpDispatchError::ManagedOperationRequestKindRequired {
        request_kind: ProviderRequestKind::Models,
        ..
      }
    ));
  }

  #[test]
  fn malformed_qualification_is_error_while_access_denial_is_routed_outcome() {
    let plan = gateway(
      llm_listener(Vec::new(), HttpAction::Route(profile_id("managed-profile"))),
      BTreeMap::from([(
        profile_id("managed-profile"),
        ProfilePlan::new(route_id("managed-route"), WireIdentity::None),
      )]),
      BTreeMap::from([(
        route_id("managed-route"),
        RoutePlan::Managed(ManagedRoute::new(
          ManagedTarget::new(
            pool_id("default"),
            UpstreamSelector::Fixed(upstream_id("upstream")),
            ModelSelector::Qualified {
              namespace: QualificationNamespace::Provider,
            },
          ),
          OperationPolicy::Preserve,
          None,
          ManagedRetry::Never,
        )),
      )]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(upstream_id("upstream"), upstream("https://upstream.example/v1/", &[]))]),
      BTreeMap::new(),
    );
    let runtime = link(&plan, &[account("account")]);
    let listener = runtime.listeners().listener(&listener_id("listener")).unwrap();
    let head = request_head(direct_ingress("managed.example"), "/v1/chat/completions");

    let malformed = dispatch_http(
      listener,
      request(
        &head,
        HttpRequestSemantics::Structured {
          requested_model: ID_LLAMA_CPP,
          requested_operation: Endpoint::ChatCompletions,
        },
      ),
      &ProviderAccess::All,
    )
    .unwrap_err();
    let HttpDispatchError::ManagedTarget { source, .. } = malformed else {
      panic!("expected contextual managed target error");
    };
    assert!(matches!(
      source.as_ref(),
      TargetResolveError::MalformedQualification {
        reason: QualificationSyntaxError::MissingSeparator,
        ..
      }
    ));

    let denied_access = ProviderAccess::from_provider_ids(vec!["openai".into()]).unwrap();
    let denied = routed(
      dispatch_http(
        listener,
        request(
          &head,
          HttpRequestSemantics::Structured {
            requested_model: "llama-cpp/model",
            requested_operation: Endpoint::ChatCompletions,
          },
        ),
        &denied_access,
      )
      .unwrap(),
    );
    assert!(matches!(
      denied.resolution(),
      TargetResolution::NoEligible {
        reason: NoEligibleReason::ProviderAccessDenied
      }
    ));
    assert!(denied.execution_view().is_none());
  }

  #[test]
  fn intercepted_origin_relay_uses_validated_connect_ingress() {
    let plan = gateway(
      proxy_listener(
        Vec::new(),
        HttpAction::Route(profile_id("relay-profile")),
        ConnectAction::Intercept,
        Some(TlsPlan::new(PathBuf::from("/unused/test-ca"))),
      ),
      BTreeMap::from([(
        profile_id("relay-profile"),
        ProfilePlan::new(route_id("relay-route"), WireIdentity::ProviderDefault),
      )]),
      BTreeMap::from([(
        route_id("relay-route"),
        RoutePlan::Relay(RelayRoute::new(
          RelayTarget::UpstreamFromOrigin {
            account_pool: pool_id("default"),
          },
          None,
          RelayRetry::Never,
        )),
      )]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream("https://base.example/v1/", &["https://origin.example"]),
      )]),
      BTreeMap::new(),
    );
    let runtime = link(&plan, &[account("account")]);
    let listener = runtime.listeners().listener(&listener_id("listener")).unwrap();
    let connect = IngressAuthority::from_connect("origin.example:443").unwrap();
    let ingress =
      HttpIngress::intercepted_https(&connect, CanonicalAuthority::parse("origin.example").unwrap()).unwrap();
    let head = request_head(ingress, "/v1/models?client_version=test");

    let routed = routed(
      dispatch_http(
        listener,
        request(&head, HttpRequestSemantics::Opaque { operation: None }),
        &ProviderAccess::All,
      )
      .unwrap(),
    );
    let TargetResolution::Selected(SelectedHttpTarget::Relay(selected)) = routed.resolution() else {
      panic!("expected relay selection, got {:?}", routed.resolution());
    };
    let RelayDestination::Original(origin) = selected.target().destination() else {
      panic!("expected original relay destination");
    };
    assert_eq!(origin.as_str(), "https://origin.example");
    assert_eq!(selected.request_kind(), ProviderRequestKind::Models);
    assert_eq!(selected.wire_identity(), Some(&AgentId::Opencode));
    assert_eq!(
      routed.head().path_and_query().as_str(),
      "/v1/models?client_version=test"
    );
    let execution = routed.execution_view().unwrap();
    let ExecutionTarget::Relay(execution_target) = execution.target() else {
      panic!("expected relay execution target");
    };
    assert_eq!(
      execution_target.request_url(execution.head()).unwrap().as_str(),
      "https://origin.example/v1/models?client_version=test"
    );
  }

  #[test]
  fn transparent_target_uses_typed_origin_without_access_or_identity() {
    let plan = gateway(
      proxy_listener(
        Vec::new(),
        HttpAction::Route(profile_id("transparent-profile")),
        ConnectAction::Tunnel,
        None,
      ),
      BTreeMap::from([(
        profile_id("transparent-profile"),
        ProfilePlan::new(route_id("transparent-route"), WireIdentity::None),
      )]),
      BTreeMap::from([(
        route_id("transparent-route"),
        RoutePlan::Transparent(Default::default()),
      )]),
      BTreeMap::new(),
      BTreeMap::new(),
      BTreeMap::new(),
    );
    let runtime = link(&plan, &[]);
    let listener = runtime.listeners().listener(&listener_id("listener")).unwrap();
    let head = request_head(
      HttpIngress::direct(
        HttpScheme::Http,
        CanonicalAuthority::parse("[2001:db8::1]:8080").unwrap(),
      ),
      "/opaque",
    );
    let denied = ProviderAccess::from_provider_ids(vec!["nothing".into()]).unwrap();

    let routed = routed(
      dispatch_http(
        listener,
        request(&head, HttpRequestSemantics::Opaque { operation: None }),
        &denied,
      )
      .unwrap(),
    );
    let TargetResolution::Selected(SelectedHttpTarget::Transparent(selected)) = routed.resolution() else {
      panic!("expected transparent selection, got {:?}", routed.resolution());
    };
    assert_eq!(selected.destination().as_str(), "http://[2001:db8::1]:8080");
    let execution = routed.execution_view().unwrap();
    let ExecutionTarget::Transparent(execution_target) = execution.target() else {
      panic!("expected transparent execution target");
    };
    assert!(std::ptr::eq(execution_target.destination(), selected.destination()));
    assert_eq!(
      execution_target.request_url(execution.head()).unwrap().as_str(),
      "http://[2001:db8::1]:8080/opaque"
    );

    let (_, _, _, resolution) = routed.into_parts();
    let TargetResolution::Selected(target) = resolution else {
      panic!("expected selected transparent target");
    };
    assert_eq!(
      target.settle(SelectionOutcome::Unavailable).unwrap(),
      SelectionSettlement::Unchanged
    );
  }

  #[test]
  fn missing_provider_default_identity_is_contextual_invariant_error() {
    let site = HttpDispatchSite {
      listener_id: listener_id("listener"),
      binding_id: Some(binding_id("binding")),
    };
    let provider = provider_id(ID_LLAMA_CPP);
    let error = resolve_wire_identity(
      &site,
      &profile_id("profile"),
      &route_id("route"),
      &LinkedWireIdentity::ProviderDefaults(BTreeMap::new()),
      &provider,
    )
    .unwrap_err();

    assert!(matches!(
      error,
      HttpDispatchError::MissingProviderWireIdentity {
        site: error_site,
        profile,
        route,
        provider: error_provider,
      } if error_site == site
        && profile.as_str() == "profile"
        && route.as_str() == "route"
        && error_provider == provider
    ));
  }
}

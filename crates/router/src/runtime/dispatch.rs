//! Synchronous HTTP dispatch over the fully linked runtime graph.
//!
//! Listener matching is deliberately separate from route resolution. The
//! first stage needs only admitted request-line facts and pins the exact
//! profile generation. The second stage may then use parsed managed semantics
//! to select an account target without allowing payload facts to change which
//! listener action matched.

use super::managed::{resolve_managed_profile, RoutedManagedTarget};
use super::{
  HttpRequestFacts, LinkedHttpAction, LinkedListener, LinkedProfile, LinkedRoute, LinkedRouteKind, LinkedWireIdentity,
  ManagedProfileResolveError,
};
use http::{uri::PathAndQuery, Method};
use smol_str::SmolStr;
use snafu::Snafu;
use std::fmt;
use std::sync::Arc;
use tokn_access::ProviderAccess;
use tokn_accounts::link::{
  resolve_relay_target, PoolRuntimeResult, SelectedRelayTarget, SelectionOutcome, SelectionSettlement, TargetResolution,
};
use tokn_core::provider::ProviderRequestKind;
use tokn_core::upstream_url::CanonicalHttpOrigin;
use tokn_core::AgentId;
use tokn_events::{HttpFamily, TargetSelection};
use tokn_policy::{
  BindingId, CanonicalHttpPath, HttpIngress, InvalidHttpPath, ListenerId, ProfileId, ProviderId, RouteId,
};
use tokn_requests::execution::ExecutionTarget;

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

/// Route-family-specific facts obtained after listener matching.
///
/// The operation is deliberately absent: [`MatchedHttpRoute`] already pins
/// the authoritative method/path classification before the body is read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpRequestSemantics {
  Opaque,
  Managed { requested_model: SmolStr },
}

/// Stable listener location that made the dispatch decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpDispatchSite {
  listener_id: ListenerId,
  binding_id: Option<BindingId>,
}

impl HttpDispatchSite {
  pub(crate) fn new(listener_id: ListenerId, binding_id: Option<BindingId>) -> Self {
    Self {
      listener_id,
      binding_id,
    }
  }

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
    semantics: HttpRequestSemantics,
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

  #[cfg(test)]
  pub(super) fn resolution(&self) -> &TargetResolution<SelectedHttpTarget> {
    self.resolution.as_ref()
  }

  pub(super) fn into_parts(
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

/// Route-family-specific selected HTTP execution target.
#[derive(Debug)]
pub(super) enum SelectedHttpTarget {
  Managed(RoutedManagedTarget),
  Relay(SelectedRelayHttpTarget),
  Transparent(SelectedTransparentHttpTarget),
}

impl SelectedHttpTarget {
  pub(super) fn event_selection(&self) -> TargetSelection {
    match self {
      Self::Managed(selected) => {
        let target = selected.target();
        TargetSelection {
          family: HttpFamily::Managed,
          account_id: Some(target.binding().account_id().into()),
          provider_id: Some(target.upstream().provider_id().as_str().into()),
          upstream_id: Some(target.upstream().id().as_str().into()),
          requested_model: Some(selected.requested_model().into()),
          upstream_model: Some(target.model().into()),
          requested_operation: Some(selected.requested_operation().as_str().into()),
          upstream_operation: Some(target.operation().as_str().into()),
        }
      }
      Self::Relay(selected) => TargetSelection {
        family: HttpFamily::Relay,
        account_id: Some(selected.target().binding().account_id().into()),
        provider_id: Some(selected.target().upstream().provider_id().as_str().into()),
        upstream_id: Some(selected.target().upstream().id().as_str().into()),
        requested_model: None,
        upstream_model: None,
        requested_operation: None,
        upstream_operation: None,
      },
      Self::Transparent(_) => TargetSelection {
        family: HttpFamily::Transparent,
        account_id: None,
        provider_id: None,
        upstream_id: None,
        requested_model: None,
        upstream_model: None,
        requested_operation: None,
        upstream_operation: None,
      },
    }
  }

  pub(super) fn execution_target(&self) -> ExecutionTarget<'_> {
    match self {
      Self::Managed(selected) => ExecutionTarget::Managed(selected.execution_target()),
      Self::Relay(selected) => {
        ExecutionTarget::relay(selected.request_kind(), selected.target(), selected.wire_identity())
      }
      Self::Transparent(selected) => ExecutionTarget::transparent(selected.destination()),
    }
  }

  /// Consume the exact selected target and apply one pool-local outcome.
  /// Transparent traffic has no account selection and therefore settles as
  /// unchanged without touching pool state.
  pub(super) fn settle(self, outcome: SelectionOutcome) -> PoolRuntimeResult<SelectionSettlement> {
    match self {
      Self::Managed(selected) => selected.settle(outcome),
      Self::Relay(selected) => selected.into_target().into_selection_token().settle(outcome),
      Self::Transparent(_) => Ok(SelectionSettlement::Unchanged),
    }
  }
}

/// Opaque relay selection with its post-selection wire identity.
#[derive(Debug)]
pub(super) struct SelectedRelayHttpTarget {
  target: SelectedRelayTarget,
  request_kind: ProviderRequestKind,
  wire_identity: Option<AgentId>,
}

impl SelectedRelayHttpTarget {
  pub(super) fn target(&self) -> &SelectedRelayTarget {
    &self.target
  }

  pub(super) fn request_kind(&self) -> ProviderRequestKind {
    self.request_kind
  }

  pub(super) fn wire_identity(&self) -> Option<&AgentId> {
    self.wire_identity.as_ref()
  }

  fn into_target(self) -> SelectedRelayTarget {
    self.target
  }
}

/// Account-less transparent destination derived from typed HTTP ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SelectedTransparentHttpTarget {
  destination: CanonicalHttpOrigin,
}

impl SelectedTransparentHttpTarget {
  pub(super) fn destination(&self) -> &CanonicalHttpOrigin {
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
  let site = HttpDispatchSite::new(listener.id().clone(), decision.binding_id().cloned());

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

fn resolve_profile(
  site: &HttpDispatchSite,
  head: &HttpRequestHead,
  profile: &LinkedProfile,
  request_kind: ProviderRequestKind,
  semantics: HttpRequestSemantics,
  session_id: Option<&str>,
  provider_access: &ProviderAccess,
) -> HttpDispatchResult<TargetResolution<SelectedHttpTarget>> {
  match profile.route().kind() {
    LinkedRouteKind::Managed(_) => {
      let HttpRequestSemantics::Managed { requested_model } = semantics else {
        return Err(HttpDispatchError::ManagedSemanticsRequired {
          site: site.clone(),
          profile: profile.id().clone(),
          route: profile.route().id().clone(),
        });
      };
      let requested_operation = match request_kind {
        ProviderRequestKind::Operation(operation) => operation,
        request_kind @ (ProviderRequestKind::Models | ProviderRequestKind::Opaque) => {
          return Err(HttpDispatchError::ManagedOperationRequestKindRequired {
            site: site.clone(),
            profile: profile.id().clone(),
            route: profile.route().id().clone(),
            request_kind,
          });
        }
      };
      let resolution = resolve_managed_profile(
        profile,
        requested_model,
        requested_operation,
        session_id,
        provider_access,
      )
      .map_err(|source| HttpDispatchError::ManagedTarget {
        site: site.clone(),
        source: Box::new(source),
      })?;
      Ok(map_managed_resolution(profile, resolution))
    }
    LinkedRouteKind::Relay(route) => {
      let resolution = resolve_relay_target(route.target(), head.ingress(), session_id, |provider| {
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
  profile: &LinkedProfile,
  resolution: TargetResolution<RoutedManagedTarget>,
) -> TargetResolution<SelectedHttpTarget> {
  match resolution {
    TargetResolution::Selected(target) => {
      debug_assert_eq!(target.site().profile_id(), profile.id());
      debug_assert_eq!(target.site().route_id(), profile.route().id());
      TargetResolution::Selected(SelectedHttpTarget::Managed(target))
    }
    TargetResolution::CoolingDown { retry_at } => TargetResolution::CoolingDown { retry_at },
    TargetResolution::NoEligible { reason } => TargetResolution::NoEligible { reason },
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
      let wire_identity = resolve_relay_wire_identity(
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

fn resolve_relay_wire_identity(
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
  ManagedSemanticsRequired {
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

  #[snafu(display("{site} failed to resolve {source}"))]
  ManagedTarget {
    site: HttpDispatchSite,
    source: Box<ManagedProfileResolveError>,
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
  use tokn_accounts::link::{NoEligibleReason, QualificationSyntaxError, RelayDestination, TargetResolveError};
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::{Endpoint, ID_LLAMA_CPP};
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, CanonicalAuthority, ClientAuthPlan,
    ConnectAction, FallbackSelector, ForwardProxyListenerPlan, GatewayPlan, HttpAction, HttpBindingPlan, HttpMatch,
    HttpScheme, IngressAuthority, ListenerPlan, LlmApiListenerPlan, ManagedRetry, ManagedRoute, ManagedTarget,
    ModelCandidate, ModelGroupId, ModelGroupPlan, ModelSelector, OperationId, OperationPolicy, ProfilePlan,
    QualificationNamespace, RelayRetry, RelayRoute, RelayTarget, RoutePlan, SessionAffinityPlan, TlsPlan, UpstreamId,
    UpstreamOrigin, UpstreamPlan, UpstreamSelector, WireIdentity,
  };
  use tokn_requests::execution::HttpAttemptHead;

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

  fn resolve_http(
    listener: &LinkedListener,
    head: &HttpRequestHead,
    request_kind: ProviderRequestKind,
    semantics: HttpRequestSemantics,
    provider_access: &ProviderAccess,
  ) -> HttpDispatchResult<RoutedHttpDispatch> {
    matched(match_http(listener, head.clone(), request_kind)).resolve(semantics, Some("session"), provider_access)
  }

  fn routed(result: HttpDispatchResult<RoutedHttpDispatch>) -> RoutedHttpDispatch {
    result.unwrap()
  }

  fn matched(result: HttpRouteMatch) -> MatchedHttpRoute {
    let HttpRouteMatch::Route(route) = result else {
      panic!("expected matched route, got {result:?}");
    };
    route
  }

  fn execution_head(dispatch: &RoutedHttpDispatch) -> HttpAttemptHead<'_> {
    HttpAttemptHead::new(dispatch.head().method(), dispatch.head().path_and_query())
  }

  fn execution_target(dispatch: &RoutedHttpDispatch) -> ExecutionTarget<'_> {
    let TargetResolution::Selected(target) = dispatch.resolution() else {
      panic!("expected selected target, got {:?}", dispatch.resolution());
    };
    target.execution_target()
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

    let routed = routed(resolve_http(
      listener,
      &head,
      ProviderRequestKind::Operation(Endpoint::Responses),
      HttpRequestSemantics::Managed {
        requested_model: SmolStr::new("inbound-model"),
      },
      &ProviderAccess::All,
    ));

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
    let execution_head = execution_head(&routed);
    assert!(std::ptr::eq(execution_head.method(), routed.head().method()));
    assert!(std::ptr::eq(
      execution_head.path_and_query(),
      routed.head().path_and_query()
    ));
    let ExecutionTarget::Managed(execution_target) = execution_target(&routed) else {
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
    let matched = match_http(listener, head.clone(), ProviderRequestKind::Opaque);
    let HttpRouteMatch::Reject(site) = matched else {
      panic!("expected matching stage to reject");
    };
    assert_eq!(site.listener_id().as_str(), "listener");
    assert!(site.binding_id().is_none());
  }

  #[test]
  fn admitted_operations_match_relay_and_transparent_bindings() {
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
    .resolve(HttpRequestSemantics::Opaque, Some("session"), &ProviderAccess::All)
    .unwrap();
    assert_eq!(relay.site().binding_id().unwrap().as_str(), "relay-binding");
    assert!(matches!(
      relay.resolution(),
      TargetResolution::Selected(SelectedHttpTarget::Relay(selected))
        if selected.request_kind() == ProviderRequestKind::Operation(Endpoint::Responses)
    ));
    let ExecutionTarget::Relay(execution_target) = execution_target(&relay) else {
      panic!("expected relay execution target");
    };
    assert_eq!(
      execution_target.request_kind(),
      ProviderRequestKind::Operation(Endpoint::Responses)
    );
    assert_eq!(
      execution_target.request_url(execution_head(&relay)).unwrap().as_str(),
      "https://upstream.example/v1/opaque"
    );

    let transparent = routed(resolve_http(
      listener,
      &head,
      ProviderRequestKind::Operation(Endpoint::Messages),
      HttpRequestSemantics::Opaque,
      &ProviderAccess::All,
    ));
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
      .resolve(HttpRequestSemantics::Opaque, Some("session"), &ProviderAccess::All)
      .unwrap_err();

    assert!(matches!(
      error,
      HttpDispatchError::ManagedSemanticsRequired {
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
  fn managed_resolution_uses_only_the_matched_operation() {
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

    let routed = matched(match_http(
      listener,
      head.clone(),
      ProviderRequestKind::Operation(Endpoint::Responses),
    ))
    .resolve(
      HttpRequestSemantics::Managed {
        requested_model: SmolStr::new("model"),
      },
      None,
      &ProviderAccess::All,
    )
    .unwrap();
    assert!(matches!(
      routed.resolution(),
      TargetResolution::Selected(SelectedHttpTarget::Managed(selected))
        if selected.requested_operation() == Endpoint::Responses
    ));

    let non_operation = matched(match_http(listener, head, ProviderRequestKind::Models))
      .resolve(
        HttpRequestSemantics::Managed {
          requested_model: SmolStr::new("model"),
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

    let malformed = resolve_http(
      listener,
      &head,
      ProviderRequestKind::Operation(Endpoint::ChatCompletions),
      HttpRequestSemantics::Managed {
        requested_model: SmolStr::new(ID_LLAMA_CPP),
      },
      &ProviderAccess::All,
    )
    .unwrap_err();
    let HttpDispatchError::ManagedTarget { source, .. } = malformed else {
      panic!("expected contextual managed target error");
    };
    assert!(matches!(
      source.as_ref(),
      ManagedProfileResolveError::MalformedQualification {
        source: TargetResolveError::MalformedQualification {
          reason: QualificationSyntaxError::MissingSeparator,
          ..
        },
        ..
      }
    ));

    let denied_access = ProviderAccess::from_provider_ids(vec!["openai".into()]).unwrap();
    let denied = routed(resolve_http(
      listener,
      &head,
      ProviderRequestKind::Operation(Endpoint::ChatCompletions),
      HttpRequestSemantics::Managed {
        requested_model: SmolStr::new("llama-cpp/model"),
      },
      &denied_access,
    ));
    assert!(matches!(
      denied.resolution(),
      TargetResolution::NoEligible {
        reason: NoEligibleReason::ProviderAccessDenied
      }
    ));
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

    let routed = routed(resolve_http(
      listener,
      &head,
      ProviderRequestKind::Models,
      HttpRequestSemantics::Opaque,
      &ProviderAccess::All,
    ));
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
    let ExecutionTarget::Relay(execution_target) = execution_target(&routed) else {
      panic!("expected relay execution target");
    };
    assert_eq!(
      execution_target.request_url(execution_head(&routed)).unwrap().as_str(),
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

    let routed = routed(resolve_http(
      listener,
      &head,
      ProviderRequestKind::Opaque,
      HttpRequestSemantics::Opaque,
      &denied,
    ));
    let TargetResolution::Selected(SelectedHttpTarget::Transparent(selected)) = routed.resolution() else {
      panic!("expected transparent selection, got {:?}", routed.resolution());
    };
    assert_eq!(selected.destination().as_str(), "http://[2001:db8::1]:8080");
    let ExecutionTarget::Transparent(execution_target) = execution_target(&routed) else {
      panic!("expected transparent execution target");
    };
    assert!(std::ptr::eq(execution_target.destination(), selected.destination()));
    assert_eq!(
      execution_target.request_url(execution_head(&routed)).unwrap().as_str(),
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
    let error = resolve_relay_wire_identity(
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

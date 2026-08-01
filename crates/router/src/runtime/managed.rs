//! Site-free managed request semantics, target resolution, and execution.
//!
//! This layer validates structured request bodies and resolves an already
//! linked profile without depending on an HTTP listener or request admission
//! site. It owns the selected account token and post-selection wire identity
//! so every caller observes the same managed routing invariants.

mod body;
mod gateway;

pub use body::{ManagedRequestBody, ManagedRequestBodyError, ManagedRequestBodyResult};
pub use gateway::{
  ManagedGatewayBuildError, ManagedGatewayBuildResult, ManagedGatewayError, ManagedGatewayExecutor,
  ManagedGatewayOutcome, ManagedGatewayRequest, ManagedGatewayResult,
};

use super::{LinkedManagedRoute, LinkedProfile, LinkedRouteKind, LinkedWireIdentity};
use crate::runtime::attempts::{
  close_pre_head_failure, endpoint_usage_kind, observe_upstream_response, publish_attempt_started,
  publish_response_head, AttemptBodyPlan, AttemptRequestObserver,
};
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderMap;
use serde_json::Value;
use smol_str::SmolStr;
use snafu::Snafu;
use std::fmt;
use std::future::Future;
use tokn_access::ProviderAccess;
use tokn_accounts::link::{
  resolve_managed_target, PoolRuntimeResult, SelectedManagedTarget, SelectionOutcome, SelectionSettlement,
  TargetResolution, TargetResolveError,
};
use tokn_core::generation::GenerationOptions;
use tokn_core::provider::Endpoint;
use tokn_core::provider::OutboundRequestObserver;
use tokn_core::AgentId;
use tokn_events::{AttemptNo, HttpFamily, RequestPhase, TargetSelection};
use tokn_headers::HeaderMap as SemanticHeaderMap;
use tokn_policy::{ProfileId, ProviderId, RouteId, RouteKind, UpstreamId};
use tokn_requests::execution::{
  ManagedAttemptError, ManagedClientResponse, ManagedExecutionTarget, ManagedHttpAttempt, ManagedHttpExecutor,
  ManagedHttpResponse, ManagedResponseAdapter, ManagedResponseError,
};
use tokn_requests::{BoundaryPublishError, RequestLifecycle};

/// Stable, non-secret location of a managed profile in the linked runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedProfileSite {
  profile_id: ProfileId,
  route_id: RouteId,
}

impl ManagedProfileSite {
  fn from_profile(profile: &LinkedProfile) -> Self {
    Self {
      profile_id: profile.id().clone(),
      route_id: profile.route().id().clone(),
    }
  }

  pub fn profile_id(&self) -> &ProfileId {
    &self.profile_id
  }

  pub fn route_id(&self) -> &RouteId {
    &self.route_id
  }
}

impl fmt::Display for ManagedProfileSite {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "profile '{}' route '{}'", self.profile_id, self.route_id)
  }
}

/// Detached, non-secret identity and model facts for one selected managed
/// attempt. The profile and route location remains separate in
/// [`ManagedProfileSite`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSelectionSummary {
  facts: Box<ManagedSelectionFacts>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedSelectionFacts {
  account_id: SmolStr,
  provider_id: ProviderId,
  upstream_id: UpstreamId,
  requested_model: SmolStr,
  upstream_model: SmolStr,
  requested_operation: Endpoint,
  upstream_operation: Endpoint,
  wire_identity: Option<AgentId>,
}

impl ManagedSelectionSummary {
  fn from_target(target: &RoutedManagedTarget) -> Self {
    let selected = target.target();
    Self {
      facts: Box::new(ManagedSelectionFacts {
        account_id: SmolStr::new(selected.binding().account_id()),
        provider_id: selected.upstream().provider_id().clone(),
        upstream_id: selected.upstream().id().clone(),
        requested_model: SmolStr::new(target.requested_model()),
        upstream_model: SmolStr::new(selected.model()),
        requested_operation: target.requested_operation(),
        upstream_operation: selected.operation(),
        wire_identity: target.wire_identity().cloned(),
      }),
    }
  }

  pub fn account_id(&self) -> &str {
    self.facts.account_id.as_str()
  }

  pub fn provider_id(&self) -> &ProviderId {
    &self.facts.provider_id
  }

  pub fn upstream_id(&self) -> &UpstreamId {
    &self.facts.upstream_id
  }

  pub fn requested_model(&self) -> &str {
    self.facts.requested_model.as_str()
  }

  pub fn upstream_model(&self) -> &str {
    self.facts.upstream_model.as_str()
  }

  pub fn requested_operation(&self) -> Endpoint {
    self.facts.requested_operation
  }

  pub fn upstream_operation(&self) -> Endpoint {
    self.facts.upstream_operation
  }

  pub fn wire_identity(&self) -> Option<&AgentId> {
    self.facts.wire_identity.as_ref()
  }
}

/// Remove stale transport metadata before semantic managed execution.
///
/// The caller already owns decoded JSON, so a managed request is serialized
/// as identity bytes and its outbound transport derives fresh framing.
pub(crate) fn strip_managed_wire_metadata(headers: &mut HeaderMap) {
  headers.remove(CONTENT_ENCODING);
  headers.remove(CONTENT_LENGTH);
  headers.remove(TRANSFER_ENCODING);
}

/// A managed target carrying both inbound semantics and the selected outbound
/// account state.
#[derive(Debug)]
pub(crate) struct RoutedManagedTarget {
  site: ManagedProfileSite,
  requested_model: SmolStr,
  requested_operation: Endpoint,
  target: SelectedManagedTarget,
  wire_identity: Option<AgentId>,
}

impl RoutedManagedTarget {
  pub(crate) fn site(&self) -> &ManagedProfileSite {
    &self.site
  }

  pub(crate) fn requested_model(&self) -> &str {
    self.requested_model.as_str()
  }

  pub(crate) fn requested_operation(&self) -> Endpoint {
    self.requested_operation
  }

  pub(crate) fn target(&self) -> &SelectedManagedTarget {
    &self.target
  }

  pub(crate) fn wire_identity(&self) -> Option<&AgentId> {
    self.wire_identity.as_ref()
  }

  pub(crate) fn execution_target(&self) -> ManagedExecutionTarget<'_> {
    ManagedExecutionTarget::new(
      self.requested_model(),
      self.requested_operation(),
      self.target(),
      self.wire_identity(),
    )
  }

  pub(crate) fn event_selection(&self) -> TargetSelection {
    TargetSelection {
      family: HttpFamily::Managed,
      account_id: Some(self.target.binding().account_id().into()),
      provider_id: Some(self.target.upstream().provider_id().as_str().into()),
      upstream_id: Some(self.target.upstream().id().as_str().into()),
      requested_model: Some(self.requested_model().into()),
      upstream_model: Some(self.target.model().into()),
      requested_operation: Some(self.requested_operation().as_str().into()),
      upstream_operation: Some(self.target.operation().as_str().into()),
    }
  }

  pub(crate) fn settle(self, outcome: SelectionOutcome) -> PoolRuntimeResult<SelectionSettlement> {
    self.target.into_selection_token().settle(outcome)
  }
}

/// One-attempt managed execution independent of listener admission policy.
#[derive(Clone, Debug)]
pub(crate) struct ManagedAttemptCoordinator {
  executor: ManagedHttpExecutor,
  adapter: ManagedResponseAdapter,
}

impl ManagedAttemptCoordinator {
  pub(crate) fn new(executor: ManagedHttpExecutor) -> Self {
    Self {
      executor,
      adapter: ManagedResponseAdapter::new(),
    }
  }

  /// Execute exactly one selected managed target, settle its owned selection
  /// immediately after the final response head or pre-head error, and only
  /// then adapt the response body.
  pub(crate) async fn execute(
    &self,
    target: RoutedManagedTarget,
    headers: &SemanticHeaderMap,
    body: &Value,
    generation_options: Option<&GenerationOptions>,
  ) -> Result<ManagedAttemptSuccess, ManagedAttemptCoordinatorError> {
    let received = self
      .receive_observed(target, headers, body, generation_options, None)
      .await?;
    self.adapt(received).await
  }

  /// Execute one managed attempt with the same stable event boundaries for
  /// listener-backed and embedded callers.
  pub(crate) async fn execute_observed(
    &self,
    target: RoutedManagedTarget,
    headers: &SemanticHeaderMap,
    body: &Value,
    generation_options: Option<&GenerationOptions>,
    lifecycle: &mut RequestLifecycle,
    capture_limit: usize,
  ) -> Result<ManagedObservedAttemptSuccess, ManagedAttemptCoordinatorError> {
    if let Err(source) = publish_attempt_started(lifecycle, target.event_selection()).await {
      let site = target.site().clone();
      let summary = ManagedSelectionSummary::from_target(&target);
      settle_managed_selection(&site, &summary, target, SelectionOutcome::Unchanged);
      return Err(ManagedAttemptCoordinatorError::Lifecycle {
        phase: RequestPhase::TargetSelection,
        source: Box::new(source),
      });
    }

    let (received, request_publication_error) = {
      let mut observer = AttemptRequestObserver::new(lifecycle, AttemptNo::FIRST, capture_limit);
      let received = self
        .receive_observed(target, headers, body, generation_options, Some(&mut observer))
        .await;
      let publication_error = observer.take_publication_error();
      (received, publication_error)
    };
    if let Some(source) = request_publication_error {
      let _ = close_pre_head_failure(lifecycle, RequestPhase::UpstreamRequest).await;
      return Err(ManagedAttemptCoordinatorError::Lifecycle {
        phase: RequestPhase::UpstreamRequest,
        source: Box::new(source),
      });
    }
    let received = match received {
      Ok(received) => received,
      Err(error @ ManagedAttemptCoordinatorError::Attempt { .. }) => {
        close_pre_head_failure(lifecycle, RequestPhase::UpstreamRequest)
          .await
          .map_err(|source| ManagedAttemptCoordinatorError::Lifecycle {
            phase: RequestPhase::UpstreamRequest,
            source: Box::new(source),
          })?;
        return Err(error);
      }
      Err(ManagedAttemptCoordinatorError::Response { .. } | ManagedAttemptCoordinatorError::Lifecycle { .. }) => {
        unreachable!("receiving a managed response cannot adapt its body or publish another lifecycle")
      }
    };

    publish_response_head(lifecycle, received.response().response())
      .await
      .map_err(|source| ManagedAttemptCoordinatorError::Lifecycle {
        phase: RequestPhase::UpstreamResponse,
        source: Box::new(source),
      })?;
    let usage_kind = Some(endpoint_usage_kind(received.response().metadata().upstream_operation()));
    let mut plan = None;
    let received = received.map_response(|response| {
      let (response, metadata) = response.into_parts();
      let (response, body_plan) = observe_upstream_response(response, capture_limit, usage_kind);
      plan = Some(body_plan);
      ManagedHttpResponse::new(response, metadata)
    });
    let body_plan = plan.expect("managed response observation plan is installed before adaptation");
    body_plan.arm(lifecycle);

    let mut adaptation = Box::pin(self.adapt(received));
    let mut progress_available = true;
    let adapted = std::future::poll_fn(|context| {
      let result = adaptation.as_mut().poll(context);
      if progress_available {
        if let Some(progress) = body_plan.take_progress() {
          if let Err(error) = lifecycle.try_publish_progress(progress) {
            progress_available = false;
            tracing::warn!(error = %error, "upstream body progress publication failed during managed adaptation");
          }
        }
      }
      result
    })
    .await;

    match adapted {
      Ok(success) => {
        let (site, summary, response) = success.into_parts();
        let attempt = if body_plan.is_finished() {
          body_plan
            .publish_terminal(lifecycle)
            .await
            .map_err(|source| ManagedAttemptCoordinatorError::Lifecycle {
              phase: RequestPhase::UpstreamResponse,
              source: Box::new(source),
            })?;
          None
        } else {
          Some(body_plan)
        };
        Ok(ManagedObservedAttemptSuccess {
          site,
          summary,
          response,
          attempt,
        })
      }
      Err(error @ ManagedAttemptCoordinatorError::Response { .. }) => {
        body_plan
          .publish_terminal(lifecycle)
          .await
          .map_err(|source| ManagedAttemptCoordinatorError::Lifecycle {
            phase: RequestPhase::UpstreamResponse,
            source: Box::new(source),
          })?;
        Err(error)
      }
      Err(ManagedAttemptCoordinatorError::Attempt { .. } | ManagedAttemptCoordinatorError::Lifecycle { .. }) => {
        unreachable!("adapting a received managed response cannot send another attempt or publish a boundary")
      }
    }
  }

  /// Send and settle one managed attempt without polling its response body.
  pub(crate) async fn receive_observed(
    &self,
    target: RoutedManagedTarget,
    headers: &SemanticHeaderMap,
    body: &Value,
    generation_options: Option<&GenerationOptions>,
    request_observer: Option<&mut dyn OutboundRequestObserver>,
  ) -> Result<ManagedAttemptReceived, ManagedAttemptCoordinatorError> {
    let site = target.site().clone();
    let summary = ManagedSelectionSummary::from_target(&target);
    let received = {
      let mut attempt = ManagedHttpAttempt::new(target.execution_target(), headers, body);
      if let Some(generation_options) = generation_options {
        attempt = attempt.with_generation_options(generation_options);
      }
      self.executor.execute_observed(attempt, request_observer).await
    };
    let outcome = match &received {
      Ok(response) => response.selection_outcome(),
      Err(source) => source.selection_outcome(),
    };
    settle_managed_selection(&site, &summary, target, outcome);

    let response = match received {
      Ok(response) => response,
      Err(source) => {
        return Err(ManagedAttemptCoordinatorError::Attempt { site, summary, source });
      }
    };
    Ok(ManagedAttemptReceived {
      site,
      summary,
      response,
    })
  }

  /// Adapt a previously settled response, polling it only after callers have
  /// observed its final upstream head.
  pub(crate) async fn adapt(
    &self,
    received: ManagedAttemptReceived,
  ) -> Result<ManagedAttemptSuccess, ManagedAttemptCoordinatorError> {
    let ManagedAttemptReceived {
      site,
      summary,
      response,
    } = received;
    match self.adapter.adapt(response).await {
      Ok(response) => Ok(ManagedAttemptSuccess {
        site,
        summary,
        response,
      }),
      Err(source) => Err(ManagedAttemptCoordinatorError::Response { site, summary, source }),
    }
  }
}

#[derive(Debug)]
pub(crate) struct ManagedAttemptReceived {
  site: ManagedProfileSite,
  summary: ManagedSelectionSummary,
  response: ManagedHttpResponse,
}

impl ManagedAttemptReceived {
  pub(crate) fn response(&self) -> &ManagedHttpResponse {
    &self.response
  }

  pub(crate) fn map_response(self, map: impl FnOnce(ManagedHttpResponse) -> ManagedHttpResponse) -> Self {
    Self {
      site: self.site,
      summary: self.summary,
      response: map(self.response),
    }
  }
}

#[derive(Debug)]
pub(crate) struct ManagedAttemptSuccess {
  site: ManagedProfileSite,
  summary: ManagedSelectionSummary,
  response: ManagedClientResponse,
}

pub(crate) struct ManagedObservedAttemptSuccess {
  site: ManagedProfileSite,
  summary: ManagedSelectionSummary,
  response: ManagedClientResponse,
  attempt: Option<AttemptBodyPlan>,
}

impl ManagedObservedAttemptSuccess {
  pub(crate) fn into_parts(
    self,
  ) -> (
    ManagedProfileSite,
    ManagedSelectionSummary,
    ManagedClientResponse,
    Option<AttemptBodyPlan>,
  ) {
    (self.site, self.summary, self.response, self.attempt)
  }
}

impl ManagedAttemptSuccess {
  pub(crate) fn into_parts(self) -> (ManagedProfileSite, ManagedSelectionSummary, ManagedClientResponse) {
    (self.site, self.summary, self.response)
  }
}

#[derive(Debug)]
pub(crate) enum ManagedAttemptCoordinatorError {
  Attempt {
    site: ManagedProfileSite,
    summary: ManagedSelectionSummary,
    source: ManagedAttemptError,
  },
  Response {
    site: ManagedProfileSite,
    summary: ManagedSelectionSummary,
    source: ManagedResponseError,
  },
  Lifecycle {
    phase: RequestPhase,
    source: Box<BoundaryPublishError>,
  },
}

fn settle_managed_selection(
  site: &ManagedProfileSite,
  summary: &ManagedSelectionSummary,
  target: RoutedManagedTarget,
  outcome: SelectionOutcome,
) {
  match target.settle(outcome) {
    Ok(settlement) => tracing::trace!(
      %site,
      account = summary.account_id(),
      provider = %summary.provider_id(),
      upstream = %summary.upstream_id(),
      ?outcome,
      ?settlement,
      "settled selected managed target after final attempt head"
    ),
    Err(error) => tracing::error!(
      %site,
      account = summary.account_id(),
      provider = %summary.provider_id(),
      upstream = %summary.upstream_id(),
      ?outcome,
      error = %error,
      "could not record selected managed target settlement"
    ),
  }
}

/// Resolve one linked managed profile independently of any listener site.
pub(crate) fn resolve_managed_profile(
  profile: &LinkedProfile,
  requested_model: SmolStr,
  requested_operation: Endpoint,
  session_id: Option<&str>,
  provider_access: &ProviderAccess,
) -> ManagedProfileResolveResult<TargetResolution<RoutedManagedTarget>> {
  let (site, route) = managed_profile_route(profile)?;
  let resolution = resolve_managed_target(
    route.target(),
    route.operation(),
    requested_model.as_str(),
    requested_operation,
    session_id,
    |provider| provider_access.allows(provider.as_str()),
  )
  .map_err(|source| ManagedProfileResolveError::MalformedQualification {
    site: site.clone(),
    source,
  })?;

  match resolution {
    TargetResolution::Selected(target) => {
      let wire_identity = resolve_wire_identity(&site, profile.wire_identity(), target.upstream().provider_id())?;
      Ok(TargetResolution::Selected(RoutedManagedTarget {
        site,
        requested_model,
        requested_operation,
        target,
        wire_identity,
      }))
    }
    TargetResolution::CoolingDown { retry_at } => Ok(TargetResolution::CoolingDown { retry_at }),
    TargetResolution::NoEligible { reason } => Ok(TargetResolution::NoEligible { reason }),
  }
}

fn managed_profile_route(
  profile: &LinkedProfile,
) -> ManagedProfileResolveResult<(ManagedProfileSite, &LinkedManagedRoute)> {
  let site = ManagedProfileSite::from_profile(profile);
  let LinkedRouteKind::Managed(route) = profile.route().kind() else {
    return Err(ManagedProfileResolveError::NonManagedRoute {
      site,
      route_kind: profile.route().route_kind(),
    });
  };
  Ok((site, route))
}

fn resolve_wire_identity(
  site: &ManagedProfileSite,
  identity: &LinkedWireIdentity,
  provider: &ProviderId,
) -> ManagedProfileResolveResult<Option<AgentId>> {
  match identity {
    LinkedWireIdentity::None => Ok(None),
    LinkedWireIdentity::Fixed(identity) => Ok(Some(identity.clone())),
    LinkedWireIdentity::ProviderDefaults(defaults) => {
      defaults
        .get(provider)
        .cloned()
        .map(Some)
        .ok_or_else(|| ManagedProfileResolveError::MissingProviderWireIdentity {
          site: site.clone(),
          provider: provider.clone(),
        })
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagedProfileResolveError {
  #[snafu(display("{site} has route kind {route_kind:?}, not managed"))]
  NonManagedRoute {
    site: ManagedProfileSite,
    route_kind: RouteKind,
  },

  #[snafu(display("{site} has a malformed qualified model request: {source}"))]
  MalformedQualification {
    site: ManagedProfileSite,
    source: TargetResolveError,
  },

  #[snafu(display("{site} has no linked default wire identity for selected provider '{provider}'"))]
  MissingProviderWireIdentity {
    site: ManagedProfileSite,
    provider: ProviderId,
  },
}

impl ManagedProfileResolveError {
  pub fn site(&self) -> &ManagedProfileSite {
    match self {
      Self::NonManagedRoute { site, .. }
      | Self::MalformedQualification { site, .. }
      | Self::MissingProviderWireIdentity { site, .. } => site,
    }
  }
}

pub type ManagedProfileResolveResult<T> = std::result::Result<T, ManagedProfileResolveError>;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{
    link_gateway_runtime_with_profile_roots, EmbeddedProfileRoots, LinkedGatewayRuntime, RuntimeNameRegistry,
  };
  use std::collections::{BTreeMap, BTreeSet};
  use std::time::Duration;
  use tokn_accounts::link::{NoEligibleReason, QualificationSyntaxError};
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::ID_LLAMA_CPP;
  use tokn_core::util::http::{build_managed_client, HttpClientOptions};
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, GatewayPlan, ManagedRetry, ManagedRoute,
    ManagedTarget, ModelSelector, OperationPolicy, ProfilePlan, QualificationNamespace, RelayRetry, RelayRoute,
    RelayTarget, RoutePlan, SessionAffinityPlan, UpstreamId, UpstreamOrigin, UpstreamPlan, UpstreamSelector,
    WireIdentity,
  };

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

  fn account() -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.id = "account".to_owned();
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

  fn upstream() -> UpstreamPlan {
    UpstreamPlan::new(
      provider_id(ID_LLAMA_CPP),
      Some("https://upstream.example/v1/".into()),
      Vec::<UpstreamOrigin>::new().into_boxed_slice(),
      false,
    )
    .with_eligible_accounts(Some(BTreeSet::from([SmolStr::new("account")])))
  }

  fn managed_runtime(model: ModelSelector, wire_identity: WireIdentity) -> LinkedGatewayRuntime {
    let profile = profile_id("managed-profile");
    let route = route_id("managed-route");
    let plan = GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::from([(profile.clone(), ProfilePlan::new(route.clone(), wire_identity))]),
      BTreeMap::from([(
        route,
        RoutePlan::Managed(ManagedRoute::new(
          ManagedTarget::new(
            pool_id("default"),
            UpstreamSelector::Fixed(upstream_id("upstream")),
            model,
          ),
          OperationPolicy::Preserve,
          None,
          ManagedRetry::Never,
        )),
      )]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(upstream_id("upstream"), upstream())]),
      BTreeMap::new(),
    );
    link_gateway_runtime_with_profile_roots(
      &plan,
      &[account()],
      &Registry::builtin(),
      &RuntimeNameRegistry::builtin(),
      &EmbeddedProfileRoots::one(profile),
    )
    .unwrap()
  }

  fn relay_runtime() -> LinkedGatewayRuntime {
    let profile = profile_id("relay-profile");
    let route = route_id("relay-route");
    let plan = GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::from([(profile.clone(), ProfilePlan::new(route.clone(), WireIdentity::None))]),
      BTreeMap::from([(
        route,
        RoutePlan::Relay(RelayRoute::new(
          RelayTarget::FixedUpstream {
            upstream: upstream_id("upstream"),
            account_pool: pool_id("default"),
          },
          None,
          RelayRetry::Never,
        )),
      )]),
      BTreeMap::from([(pool_id("default"), pool())]),
      BTreeMap::from([(upstream_id("upstream"), upstream())]),
      BTreeMap::new(),
    );
    link_gateway_runtime_with_profile_roots(
      &plan,
      &[account()],
      &Registry::builtin(),
      &RuntimeNameRegistry::builtin(),
      &EmbeddedProfileRoots::one(profile),
    )
    .unwrap()
  }

  fn managed_profile(runtime: &LinkedGatewayRuntime) -> &LinkedProfile {
    runtime.profiles().profile(&profile_id("managed-profile")).unwrap()
  }

  fn selected_target(
    runtime: &LinkedGatewayRuntime,
    requested_model: &str,
    requested_operation: Endpoint,
  ) -> RoutedManagedTarget {
    let resolution = resolve_managed_profile(
      managed_profile(runtime),
      SmolStr::new(requested_model),
      requested_operation,
      Some("session"),
      &ProviderAccess::All,
    )
    .unwrap();
    let TargetResolution::Selected(target) = resolution else {
      panic!("expected selected managed target, got {resolution:?}");
    };
    target
  }

  #[test]
  fn selects_managed_target_with_exact_site_semantics_and_identity() {
    let runtime = managed_runtime(ModelSelector::Capability, WireIdentity::ProviderDefault);
    let target = selected_target(&runtime, "requested-model", Endpoint::ChatCompletions);
    let summary = ManagedSelectionSummary::from_target(&target);

    assert_eq!(target.site().profile_id().as_str(), "managed-profile");
    assert_eq!(target.site().route_id().as_str(), "managed-route");
    assert_eq!(
      target.site().to_string(),
      "profile 'managed-profile' route 'managed-route'"
    );
    assert_eq!(target.requested_model(), "requested-model");
    assert_eq!(target.requested_operation(), Endpoint::ChatCompletions);
    assert_eq!(target.target().model(), "requested-model");
    assert_eq!(target.target().operation(), Endpoint::ChatCompletions);
    assert_eq!(target.wire_identity(), Some(&AgentId::Opencode));
    assert_eq!(summary.account_id(), "account");
    assert_eq!(summary.provider_id(), &provider_id(ID_LLAMA_CPP));
    assert_eq!(summary.upstream_id(), &upstream_id("upstream"));
    assert_eq!(summary.requested_model(), "requested-model");
    assert_eq!(summary.upstream_model(), "requested-model");
    assert_eq!(summary.requested_operation(), Endpoint::ChatCompletions);
    assert_eq!(summary.upstream_operation(), Endpoint::ChatCompletions);
    assert_eq!(summary.wire_identity(), Some(&AgentId::Opencode));
  }

  #[tokio::test]
  async fn local_generation_control_error_settles_unchanged_without_exposing_token() {
    let runtime = managed_runtime(ModelSelector::Capability, WireIdentity::ProviderDefault);
    let target = selected_target(&runtime, "requested-model", Endpoint::ChatCompletions);
    let coordinator = ManagedAttemptCoordinator::new(ManagedHttpExecutor::new(
      build_managed_client(&HttpClientOptions::default()).unwrap(),
    ));
    let headers = SemanticHeaderMap::new();
    let body = serde_json::json!({"model": "requested-model", "messages": []});
    let options = GenerationOptions::new().with_max_output_tokens(0);

    let error = coordinator
      .execute(target, &headers, &body, Some(&options))
      .await
      .unwrap_err();
    let ManagedAttemptCoordinatorError::Attempt { site, summary, source } = error else {
      panic!("expected a pre-head managed attempt error");
    };
    assert!(matches!(&source, ManagedAttemptError::GenerationControl { .. }));
    assert_eq!(source.selection_outcome(), SelectionOutcome::Unchanged);
    assert_eq!(site.profile_id().as_str(), "managed-profile");
    assert_eq!(site.route_id().as_str(), "managed-route");
    assert_eq!(summary.account_id(), "account");
    assert_eq!(summary.provider_id(), &provider_id(ID_LLAMA_CPP));
    assert_eq!(summary.upstream_id(), &upstream_id("upstream"));
    assert_eq!(summary.requested_model(), "requested-model");
    assert_eq!(summary.upstream_model(), "requested-model");
    assert_eq!(summary.wire_identity(), Some(&AgentId::Opencode));

    assert!(matches!(
      resolve_managed_profile(
        managed_profile(&runtime),
        SmolStr::new("requested-model"),
        Endpoint::ChatCompletions,
        Some("session"),
        &ProviderAccess::All,
      )
      .unwrap(),
      TargetResolution::Selected(_)
    ));
  }

  #[test]
  fn rejects_non_managed_profile_with_route_kind_and_site() {
    let runtime = relay_runtime();
    let profile = runtime.profiles().profile(&profile_id("relay-profile")).unwrap();
    let error = resolve_managed_profile(
      profile,
      SmolStr::new("model"),
      Endpoint::Responses,
      None,
      &ProviderAccess::All,
    )
    .unwrap_err();

    assert!(matches!(
      error,
      ManagedProfileResolveError::NonManagedRoute {
        site,
        route_kind: RouteKind::Relay,
      } if site.profile_id().as_str() == "relay-profile"
        && site.route_id().as_str() == "relay-route"
    ));
  }

  #[test]
  fn reports_malformed_qualification_with_profile_site() {
    let runtime = managed_runtime(
      ModelSelector::Qualified {
        namespace: QualificationNamespace::Provider,
      },
      WireIdentity::None,
    );
    let error = resolve_managed_profile(
      managed_profile(&runtime),
      SmolStr::new(ID_LLAMA_CPP),
      Endpoint::ChatCompletions,
      None,
      &ProviderAccess::All,
    )
    .unwrap_err();

    assert!(matches!(
      error,
      ManagedProfileResolveError::MalformedQualification {
        site,
        source: TargetResolveError::MalformedQualification {
          reason: QualificationSyntaxError::MissingSeparator,
          ..
        },
      } if site.profile_id().as_str() == "managed-profile"
        && site.route_id().as_str() == "managed-route"
    ));
  }

  #[test]
  fn reports_missing_provider_wire_identity_with_profile_site() {
    let site = ManagedProfileSite {
      profile_id: profile_id("managed-profile"),
      route_id: route_id("managed-route"),
    };
    let provider = provider_id(ID_LLAMA_CPP);
    let error =
      resolve_wire_identity(&site, &LinkedWireIdentity::ProviderDefaults(BTreeMap::new()), &provider).unwrap_err();

    assert!(matches!(
      error,
      ManagedProfileResolveError::MissingProviderWireIdentity {
        site: error_site,
        provider: error_provider,
      } if error_site == site && error_provider == provider
    ));
  }

  #[test]
  fn preserves_no_eligible_and_cooling_outcomes() {
    let runtime = managed_runtime(ModelSelector::Capability, WireIdentity::None);
    let denied_access = ProviderAccess::from_provider_ids(vec!["openai".to_owned()]).unwrap();
    let denied = resolve_managed_profile(
      managed_profile(&runtime),
      SmolStr::new("model"),
      Endpoint::ChatCompletions,
      None,
      &denied_access,
    )
    .unwrap();
    assert!(matches!(
      denied,
      TargetResolution::NoEligible {
        reason: NoEligibleReason::ProviderAccessDenied,
      }
    ));

    let selected = resolve_managed_profile(
      managed_profile(&runtime),
      SmolStr::new("model"),
      Endpoint::ChatCompletions,
      None,
      &ProviderAccess::All,
    )
    .unwrap();
    let TargetResolution::Selected(target) = selected else {
      panic!("expected selected target before cooldown, got {selected:?}");
    };
    let SelectionSettlement::CoolingDown { retry_at } = target.settle(SelectionOutcome::Unavailable).unwrap() else {
      panic!("expected unavailable settlement to start cooldown");
    };

    let cooling = resolve_managed_profile(
      managed_profile(&runtime),
      SmolStr::new("model"),
      Endpoint::ChatCompletions,
      None,
      &ProviderAccess::All,
    )
    .unwrap();
    assert!(matches!(
      cooling,
      TargetResolution::CoolingDown { retry_at: actual } if actual == retry_at
    ));
  }
}

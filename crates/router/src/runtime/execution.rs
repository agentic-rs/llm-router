//! Policy-free execution of one fully routed v2 HTTP request.
//!
//! Dispatch has already fixed the listener action, profile generation, and
//! exact request-time target. This coordinator makes at most one upstream
//! attempt. It settles the selected account as soon as that attempt yields a
//! final response head (or a pre-head error), before managed adaptation can
//! poll the response body. It does not retry or map outcomes into downstream
//! HTTP policy.

use super::attempts::{
  close_pre_head_failure, endpoint_usage_kind, observe_upstream_response, publish_attempt_started,
  publish_response_head, AttemptBodyPlan, AttemptRequestObserver,
};
use super::dispatch::SelectedHttpTarget;
use super::managed::{
  strip_managed_wire_metadata, ManagedAttemptCoordinator, ManagedAttemptCoordinatorError, RoutedManagedTarget,
};
use super::{HttpDispatchSite, RoutedHttpDispatch};
use bytes::Bytes;
use http::HeaderMap;
use serde_json::Value;
use snafu::Snafu;
use std::future::Future;
use std::time::Instant;
use tokn_accounts::link::{NoEligibleReason, SelectionOutcome, TargetResolution};
use tokn_events::{AttemptNo, RequestPhase};
use tokn_requests::execution::{
  classify_selection_outcome, ExecutionTarget, HttpAttemptHead, ManagedAttemptError, ManagedClientResponse,
  ManagedHttpExecutor, ManagedResponseError, OpaqueAttemptError, OpaqueHttpAttempt, OpaqueHttpExecutor,
  OpaqueHttpTarget,
};
use tokn_requests::{BoundaryPublishError, RequestLifecycle};

/// Shared one-attempt transports for routed v2 HTTP requests.
///
/// The three underlying HTTP clients should be constructed once for the
/// serving generation and shared through this cloneable coordinator.
#[derive(Clone, Debug)]
pub struct HttpExecutionCoordinator {
  managed: ManagedAttemptCoordinator,
  opaque: OpaqueHttpExecutor,
}

impl HttpExecutionCoordinator {
  pub fn new(managed: ManagedHttpExecutor, opaque: OpaqueHttpExecutor) -> Self {
    Self {
      managed: ManagedAttemptCoordinator::new(managed),
      opaque,
    }
  }

  /// Execute one routed decision without retrying or choosing another target.
  ///
  /// Native headers remain byte-preserving for relay and transparent traffic.
  /// Only the managed arm creates the string-backed semantic projection used
  /// by provider request construction.
  pub async fn execute(
    &self,
    dispatch: RoutedHttpDispatch,
    request: HttpExecutionRequest,
  ) -> HttpExecutionResult<HttpExecutionOutcome> {
    let (site, head, _profile, resolution) = dispatch.into_parts();
    let target = match resolution {
      TargetResolution::Selected(target) => target,
      TargetResolution::CoolingDown { retry_at } => {
        return Ok(HttpExecutionOutcome::CoolingDown { site, retry_at });
      }
      TargetResolution::NoEligible { reason } => {
        return Ok(HttpExecutionOutcome::NoEligible { site, reason });
      }
    };

    match target {
      SelectedHttpTarget::Managed(target) => self.execute_managed(site, target, request).await,
      target @ (SelectedHttpTarget::Relay(_) | SelectedHttpTarget::Transparent(_)) => {
        self.execute_opaque(site, head, target, request).await
      }
    }
  }

  /// Execute one routed request while publishing the complete one-attempt
  /// lifecycle. Live raw response-body ownership is returned to the server
  /// adapter without buffering.
  pub(crate) async fn execute_observed(
    &self,
    dispatch: RoutedHttpDispatch,
    request: HttpExecutionRequest,
    lifecycle: &mut RequestLifecycle,
    capture_limit: usize,
  ) -> HttpExecutionResult<ObservedHttpExecutionOutcome> {
    let (site, head, _profile, resolution) = dispatch.into_parts();
    let target = match resolution {
      TargetResolution::Selected(target) => target,
      TargetResolution::CoolingDown { retry_at } => {
        return Ok(ObservedHttpExecutionOutcome::CoolingDown { site, retry_at });
      }
      TargetResolution::NoEligible { reason } => {
        return Ok(ObservedHttpExecutionOutcome::NoEligible { site, reason });
      }
    };

    publish_attempt_started(lifecycle, target.event_selection())
      .await
      .map_err(|source| lifecycle_error(site.clone(), RequestPhase::TargetSelection, source))?;
    match target {
      SelectedHttpTarget::Managed(target) => {
        self
          .execute_managed_observed(site, target, request, lifecycle, capture_limit)
          .await
      }
      target @ (SelectedHttpTarget::Relay(_) | SelectedHttpTarget::Transparent(_)) => {
        self
          .execute_opaque_observed(site, head, target, request, lifecycle, capture_limit)
          .await
      }
    }
  }

  async fn execute_managed_observed(
    &self,
    dispatch_site: HttpDispatchSite,
    target: RoutedManagedTarget,
    request: HttpExecutionRequest,
    lifecycle: &mut RequestLifecycle,
    capture_limit: usize,
  ) -> HttpExecutionResult<ObservedHttpExecutionOutcome> {
    let HttpExecutionBody::Managed(body) = &request.body else {
      settle_managed_mismatch(&dispatch_site, target);
      close_pre_head_failure(lifecycle, RequestPhase::TargetSelection)
        .await
        .map_err(|source| lifecycle_error(dispatch_site.clone(), RequestPhase::TargetSelection, source))?;
      return Err(HttpExecutionError::RequestFamilyMismatch { site: dispatch_site });
    };
    let semantic_headers = tokn_headers::HeaderMap::from(&request.headers);
    let received = {
      let mut observer = AttemptRequestObserver::new(lifecycle, AttemptNo::FIRST, capture_limit);
      self
        .managed
        .receive_observed(target, &semantic_headers, body, None, Some(&mut observer))
        .await
    };
    let received = match received {
      Ok(received) => received,
      Err(ManagedAttemptCoordinatorError::Attempt {
        site: _profile_site,
        summary: _summary,
        source,
      }) => {
        close_pre_head_failure(lifecycle, RequestPhase::UpstreamRequest)
          .await
          .map_err(|event_source| {
            lifecycle_error(dispatch_site.clone(), RequestPhase::UpstreamRequest, event_source)
          })?;
        return Err(HttpExecutionError::ManagedAttempt {
          site: dispatch_site,
          source,
        });
      }
      Err(ManagedAttemptCoordinatorError::Response { .. }) => {
        unreachable!("receiving a managed response cannot adapt its body")
      }
    };
    publish_response_head(lifecycle, received.response().response())
      .await
      .map_err(|source| lifecycle_error(dispatch_site.clone(), RequestPhase::UpstreamResponse, source))?;
    let usage_kind = Some(endpoint_usage_kind(received.response().metadata().upstream_operation()));
    let mut plan = None;
    let received = received.map_response(|response| {
      let (response, metadata) = response.into_parts();
      let (response, body_plan) = observe_upstream_response(response, capture_limit, usage_kind);
      plan = Some(body_plan);
      tokn_requests::execution::ManagedHttpResponse::new(response, metadata)
    });
    let body_plan = plan.expect("managed response observation plan is installed before adaptation");
    body_plan.arm(lifecycle);
    let mut adaptation = Box::pin(self.managed.adapt(received));
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
        let (_profile_site, _summary, response) = success.into_parts();
        let attempt = if body_plan.is_finished() {
          body_plan
            .publish_terminal(lifecycle)
            .await
            .map_err(|source| lifecycle_error(dispatch_site.clone(), RequestPhase::UpstreamResponse, source))?;
          None
        } else {
          Some(body_plan)
        };
        Ok(ObservedHttpExecutionOutcome::Managed { response, attempt })
      }
      Err(ManagedAttemptCoordinatorError::Response {
        site: _profile_site,
        summary: _summary,
        source,
      }) => {
        body_plan.publish_terminal(lifecycle).await.map_err(|event_source| {
          lifecycle_error(dispatch_site.clone(), RequestPhase::UpstreamResponse, event_source)
        })?;
        Err(HttpExecutionError::ManagedResponse {
          site: dispatch_site,
          source,
        })
      }
      Err(ManagedAttemptCoordinatorError::Attempt { .. }) => {
        unreachable!("adapting a received managed response cannot send another attempt")
      }
    }
  }

  async fn execute_opaque_observed(
    &self,
    site: HttpDispatchSite,
    head: super::HttpRequestHead,
    target: SelectedHttpTarget,
    request: HttpExecutionRequest,
    lifecycle: &mut RequestLifecycle,
    capture_limit: usize,
  ) -> HttpExecutionResult<ObservedHttpExecutionOutcome> {
    let received = match (target.execution_target(), &request.body) {
      (ExecutionTarget::Relay(target), HttpExecutionBody::Opaque(body)) => {
        let attempt = OpaqueHttpAttempt::new(
          HttpAttemptHead::new(head.method(), head.path_and_query()),
          OpaqueHttpTarget::Relay(target),
          &request.headers,
          body.as_ref(),
        );
        let mut observer = AttemptRequestObserver::new(lifecycle, AttemptNo::FIRST, capture_limit);
        self
          .opaque
          .execute_observed(attempt, Some(&mut observer))
          .await
          .map_err(AttemptFailure::Opaque)
      }
      (ExecutionTarget::Transparent(target), HttpExecutionBody::Opaque(body)) => {
        let attempt = OpaqueHttpAttempt::new(
          HttpAttemptHead::new(head.method(), head.path_and_query()),
          OpaqueHttpTarget::Transparent(target),
          &request.headers,
          body.as_ref(),
        );
        let mut observer = AttemptRequestObserver::new(lifecycle, AttemptNo::FIRST, capture_limit);
        self
          .opaque
          .execute_observed(attempt, Some(&mut observer))
          .await
          .map_err(AttemptFailure::Opaque)
      }
      (ExecutionTarget::Managed(_), _)
      | (ExecutionTarget::Relay(_) | ExecutionTarget::Transparent(_), HttpExecutionBody::Managed(_)) => {
        Err(AttemptFailure::RequestFamilyMismatch)
      }
    };
    let outcome = match &received {
      Ok(response) => classify_selection_outcome(response.status()),
      Err(error) => error.selection_outcome(),
    };
    settle_selection(&site, target, outcome);

    let response = match received {
      Ok(response) => response,
      Err(AttemptFailure::Opaque(source)) => {
        close_pre_head_failure(lifecycle, RequestPhase::UpstreamRequest)
          .await
          .map_err(|event_source| lifecycle_error(site.clone(), RequestPhase::UpstreamRequest, event_source))?;
        return Err(HttpExecutionError::OpaqueAttempt { site, source });
      }
      Err(AttemptFailure::RequestFamilyMismatch) => {
        close_pre_head_failure(lifecycle, RequestPhase::TargetSelection)
          .await
          .map_err(|event_source| lifecycle_error(site.clone(), RequestPhase::TargetSelection, event_source))?;
        return Err(HttpExecutionError::RequestFamilyMismatch { site });
      }
    };
    publish_response_head(lifecycle, &response)
      .await
      .map_err(|source| lifecycle_error(site.clone(), RequestPhase::UpstreamResponse, source))?;
    let (response, attempt) = observe_upstream_response(response, capture_limit, None);
    attempt.arm(lifecycle);
    Ok(ObservedHttpExecutionOutcome::Opaque {
      response,
      attempt: Some(attempt),
    })
  }

  async fn execute_managed(
    &self,
    dispatch_site: HttpDispatchSite,
    target: RoutedManagedTarget,
    request: HttpExecutionRequest,
  ) -> HttpExecutionResult<HttpExecutionOutcome> {
    let HttpExecutionBody::Managed(body) = &request.body else {
      settle_managed_mismatch(&dispatch_site, target);
      return Err(HttpExecutionError::RequestFamilyMismatch { site: dispatch_site });
    };
    let semantic_headers = tokn_headers::HeaderMap::from(&request.headers);
    match self.managed.execute(target, &semantic_headers, body, None).await {
      Ok(success) => {
        let (_profile_site, _summary, response) = success.into_parts();
        Ok(HttpExecutionOutcome::Managed {
          site: dispatch_site,
          response,
        })
      }
      Err(ManagedAttemptCoordinatorError::Attempt {
        site: _profile_site,
        summary: _summary,
        source,
      }) => Err(HttpExecutionError::ManagedAttempt {
        site: dispatch_site,
        source,
      }),
      Err(ManagedAttemptCoordinatorError::Response {
        site: _profile_site,
        summary: _summary,
        source,
      }) => Err(HttpExecutionError::ManagedResponse {
        site: dispatch_site,
        source,
      }),
    }
  }

  async fn execute_opaque(
    &self,
    site: HttpDispatchSite,
    head: super::HttpRequestHead,
    target: SelectedHttpTarget,
    request: HttpExecutionRequest,
  ) -> HttpExecutionResult<HttpExecutionOutcome> {
    let received = self.receive_opaque_head(&head, &target, &request).await;
    let outcome = match &received {
      Ok(response) => classify_selection_outcome(response.status()),
      Err(error) => error.selection_outcome(),
    };
    settle_selection(&site, target, outcome);

    match received {
      Ok(response) => Ok(HttpExecutionOutcome::Opaque { site, response }),
      Err(AttemptFailure::Opaque(source)) => Err(HttpExecutionError::OpaqueAttempt { site, source }),
      Err(AttemptFailure::RequestFamilyMismatch) => Err(HttpExecutionError::RequestFamilyMismatch { site }),
    }
  }

  async fn receive_opaque_head(
    &self,
    head: &super::HttpRequestHead,
    target: &SelectedHttpTarget,
    request: &HttpExecutionRequest,
  ) -> Result<reqwest::Response, AttemptFailure> {
    match (target.execution_target(), &request.body) {
      (ExecutionTarget::Relay(target), HttpExecutionBody::Opaque(body)) => {
        let attempt = OpaqueHttpAttempt::new(
          HttpAttemptHead::new(head.method(), head.path_and_query()),
          OpaqueHttpTarget::Relay(target),
          &request.headers,
          body.as_ref(),
        );
        self.opaque.execute(attempt).await.map_err(AttemptFailure::Opaque)
      }
      (ExecutionTarget::Transparent(target), HttpExecutionBody::Opaque(body)) => {
        let attempt = OpaqueHttpAttempt::new(
          HttpAttemptHead::new(head.method(), head.path_and_query()),
          OpaqueHttpTarget::Transparent(target),
          &request.headers,
          body.as_ref(),
        );
        self.opaque.execute(attempt).await.map_err(AttemptFailure::Opaque)
      }
      (ExecutionTarget::Managed(_), _)
      | (ExecutionTarget::Relay(_) | ExecutionTarget::Transparent(_), HttpExecutionBody::Managed(_)) => {
        Err(AttemptFailure::RequestFamilyMismatch)
      }
    }
  }
}

/// Route-family-specific request input for one already-routed attempt.
#[derive(Debug)]
pub struct HttpExecutionRequest {
  headers: HeaderMap,
  body: HttpExecutionBody,
}

#[derive(Debug)]
enum HttpExecutionBody {
  Managed(Value),
  Opaque(Option<Bytes>),
}

impl HttpExecutionRequest {
  /// Build managed input after content decoding and JSON validation.
  ///
  /// Managed execution always serializes identity JSON. Remove stale wire
  /// encoding and framing fields before constructing its semantic header
  /// projection; the outbound transport derives its own content length.
  pub fn managed(mut headers: HeaderMap, body: Value) -> Self {
    strip_managed_wire_metadata(&mut headers);
    Self {
      headers,
      body: HttpExecutionBody::Managed(body),
    }
  }

  pub fn opaque(headers: HeaderMap, body: Option<Bytes>) -> Self {
    Self {
      headers,
      body: HttpExecutionBody::Opaque(body),
    }
  }
}

/// Result of one policy-free routed execution decision.
#[derive(Debug)]
pub enum HttpExecutionOutcome {
  /// Adapted managed response. Buffered conversion has completed; SSE bodies
  /// remain live and lazy.
  Managed {
    site: HttpDispatchSite,
    response: ManagedClientResponse,
  },
  /// Untouched relay or transparent response with its live native body.
  Opaque {
    site: HttpDispatchSite,
    response: reqwest::Response,
  },
  /// Every otherwise eligible selected binding is temporarily cooling.
  CoolingDown { site: HttpDispatchSite, retry_at: Instant },
  /// The routed request had no eligible request-time target.
  NoEligible {
    site: HttpDispatchSite,
    reason: NoEligibleReason,
  },
}

/// Server-only execution result retaining ownership of a live attempt body.
pub(crate) enum ObservedHttpExecutionOutcome {
  Managed {
    response: ManagedClientResponse,
    attempt: Option<AttemptBodyPlan>,
  },
  Opaque {
    response: reqwest::Response,
    attempt: Option<AttemptBodyPlan>,
  },
  CoolingDown {
    site: HttpDispatchSite,
    retry_at: Instant,
  },
  NoEligible {
    site: HttpDispatchSite,
    reason: NoEligibleReason,
  },
}

impl HttpExecutionOutcome {
  pub fn site(&self) -> &HttpDispatchSite {
    match self {
      Self::Managed { site, .. }
      | Self::Opaque { site, .. }
      | Self::CoolingDown { site, .. }
      | Self::NoEligible { site, .. } => site,
    }
  }
}

/// Failure from the one selected attempt or from post-settlement managed
/// response adaptation.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum HttpExecutionError {
  #[snafu(display("{site} routed target and prepared request families do not match"))]
  RequestFamilyMismatch { site: HttpDispatchSite },

  #[snafu(display("{site} managed attempt failed before a final response head: {source}"))]
  ManagedAttempt {
    site: HttpDispatchSite,
    source: ManagedAttemptError,
  },

  #[snafu(display("{site} opaque attempt failed before a final response head: {source}"))]
  OpaqueAttempt {
    site: HttpDispatchSite,
    source: OpaqueAttemptError,
  },

  #[snafu(display("{site} managed response failed after its final head was settled: {source}"))]
  ManagedResponse {
    site: HttpDispatchSite,
    source: ManagedResponseError,
  },

  #[snafu(display("{site} request lifecycle publication failed during {phase:?}: {source}"))]
  Lifecycle {
    site: HttpDispatchSite,
    phase: RequestPhase,
    source: Box<BoundaryPublishError>,
  },
}

impl HttpExecutionError {
  pub fn site(&self) -> &HttpDispatchSite {
    match self {
      Self::RequestFamilyMismatch { site }
      | Self::ManagedAttempt { site, .. }
      | Self::OpaqueAttempt { site, .. }
      | Self::ManagedResponse { site, .. }
      | Self::Lifecycle { site, .. } => site,
    }
  }
}

fn lifecycle_error(site: HttpDispatchSite, phase: RequestPhase, source: BoundaryPublishError) -> HttpExecutionError {
  HttpExecutionError::Lifecycle {
    site,
    phase,
    source: Box::new(source),
  }
}

pub type HttpExecutionResult<T> = std::result::Result<T, HttpExecutionError>;

/// A failure before any final upstream response head was received.
enum AttemptFailure {
  RequestFamilyMismatch,
  Opaque(OpaqueAttemptError),
}

impl AttemptFailure {
  fn selection_outcome(&self) -> SelectionOutcome {
    match self {
      Self::RequestFamilyMismatch => SelectionOutcome::Unchanged,
      Self::Opaque(error) => error.selection_outcome(),
    }
  }
}

fn settle_managed_mismatch(site: &HttpDispatchSite, target: RoutedManagedTarget) {
  match target.settle(SelectionOutcome::Unchanged) {
    Ok(settlement) => tracing::trace!(
      %site,
      ?settlement,
      "settled mismatched managed request without an upstream attempt"
    ),
    Err(error) => tracing::error!(
      %site,
      error = %error,
      "could not record mismatched managed request settlement"
    ),
  }
}

fn settle_selection(site: &HttpDispatchSite, target: SelectedHttpTarget, outcome: SelectionOutcome) {
  match target.settle(outcome) {
    Ok(settlement) => tracing::trace!(
      %site,
      ?outcome,
      ?settlement,
      "settled selected HTTP target after final attempt head"
    ),
    Err(error) => tracing::error!(
      %site,
      ?outcome,
      error = %error,
      "could not record selected HTTP target settlement"
    ),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::{
    link_gateway_runtime, match_http, HttpRequestHead, HttpRequestSemantics, HttpRouteMatch, LinkedGatewayRuntime,
    RuntimeNameRegistry,
  };
  use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING};
  use http::{Method, StatusCode};
  use smol_str::SmolStr;
  use std::collections::BTreeMap;
  use std::net::{Ipv4Addr, SocketAddr};
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::Arc;
  use std::time::Duration;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::{TcpListener, TcpStream};
  use tokio::sync::oneshot;
  use tokn_access::ProviderAccess;
  use tokn_accounts::link::SelectionSettlement;
  use tokn_accounts::registry::Registry;
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::{Endpoint, ProviderRequestKind, ID_LLAMA_CPP};
  use tokn_core::util::http::{build_client, build_managed_client, build_opaque_client, HttpClientOptions};
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, CanonicalAuthority, ClientAuthPlan,
    FallbackSelector, GatewayPlan, HttpAction, HttpIngress, HttpScheme, ListenerId, ListenerPlan, LlmApiListenerPlan,
    ManagedRetry, ManagedRoute, ManagedTarget, ModelCandidate, ModelGroupId, ModelGroupPlan, ModelSelector,
    OperationPolicy, ProfileId, ProfilePlan, ProviderId, RelayRetry, RelayRoute, RelayTarget, RouteId, RoutePlan,
    SessionAffinityPlan, UpstreamId, UpstreamPlan, UpstreamSelector, WireIdentity,
  };

  const SESSION: &str = "stable-session";

  fn listener_id() -> ListenerId {
    ListenerId::new("listener").unwrap()
  }

  fn profile_id() -> ProfileId {
    ProfileId::new("profile").unwrap()
  }

  fn route_id() -> RouteId {
    RouteId::new("route").unwrap()
  }

  fn pool_id() -> AccountPoolId {
    AccountPoolId::new("pool").unwrap()
  }

  fn upstream_id() -> UpstreamId {
    UpstreamId::new("upstream").unwrap()
  }

  fn group_id() -> ModelGroupId {
    ModelGroupId::new("models").unwrap()
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

  fn account_pool() -> AccountPoolPlan {
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

  fn upstream(base_url: &str) -> UpstreamPlan {
    UpstreamPlan::new(
      ProviderId::new(ID_LLAMA_CPP).unwrap(),
      Some(SmolStr::new(base_url)),
      Box::default(),
      true,
    )
  }

  fn listener() -> ListenerPlan {
    ListenerPlan::LlmApi(LlmApiListenerPlan::new(
      SocketAddr::from((Ipv4Addr::LOCALHOST, 42_101)),
      ClientAuthPlan::None,
      Box::default(),
      HttpAction::Route(profile_id()),
    ))
  }

  fn plan(base_url: &str, route: RoutePlan, groups: BTreeMap<ModelGroupId, ModelGroupPlan>) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::from([(listener_id(), listener())]),
      BTreeMap::from([(profile_id(), ProfilePlan::new(route_id(), WireIdentity::None))]),
      BTreeMap::from([(route_id(), route)]),
      BTreeMap::from([(pool_id(), account_pool())]),
      BTreeMap::from([(upstream_id(), upstream(base_url))]),
      groups,
    )
  }

  fn relay_plan(base_url: &str) -> GatewayPlan {
    plan(
      base_url,
      RoutePlan::Relay(RelayRoute::new(
        RelayTarget::FixedUpstream {
          upstream: upstream_id(),
          account_pool: pool_id(),
        },
        None,
        RelayRetry::Never,
      )),
      BTreeMap::new(),
    )
  }

  fn managed_plan(base_url: &str) -> GatewayPlan {
    let group = group_id();
    plan(
      base_url,
      RoutePlan::Managed(ManagedRoute::new(
        ManagedTarget::new(
          pool_id(),
          UpstreamSelector::Fixed(upstream_id()),
          ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
        ),
        OperationPolicy::Preserve,
        None,
        ManagedRetry::Never,
      )),
      BTreeMap::from([(
        group,
        ModelGroupPlan::new(vec![ModelCandidate::new(Some(upstream_id()), "upstream-model")].into_boxed_slice()),
      )]),
    )
  }

  fn link(plan: &GatewayPlan, accounts: &[AccountConfig]) -> LinkedGatewayRuntime {
    link_gateway_runtime(plan, accounts, &Registry::builtin(), &RuntimeNameRegistry::builtin()).unwrap()
  }

  fn request_head(path: &str) -> HttpRequestHead {
    HttpRequestHead::new(
      HttpIngress::direct(HttpScheme::Http, CanonicalAuthority::parse("client.example").unwrap()),
      Method::POST,
      path.parse().unwrap(),
    )
    .unwrap()
  }

  fn relay_dispatch(
    runtime: &LinkedGatewayRuntime,
    session_id: Option<&str>,
    access: &ProviderAccess,
  ) -> RoutedHttpDispatch {
    let listener = runtime.listeners().listener(&listener_id()).unwrap();
    let matched = match_http(listener, request_head("/opaque?exact=yes"), ProviderRequestKind::Opaque);
    let HttpRouteMatch::Route(matched) = matched else {
      panic!("relay fixture unexpectedly rejected");
    };
    matched
      .resolve(HttpRequestSemantics::Opaque, session_id, access)
      .unwrap()
  }

  fn managed_dispatch(runtime: &LinkedGatewayRuntime, session_id: Option<&str>) -> RoutedHttpDispatch {
    let listener = runtime.listeners().listener(&listener_id()).unwrap();
    let matched = match_http(
      listener,
      request_head("/v1/chat/completions"),
      ProviderRequestKind::Operation(Endpoint::ChatCompletions),
    );
    let HttpRouteMatch::Route(matched) = matched else {
      panic!("managed fixture unexpectedly rejected");
    };
    matched
      .resolve(
        HttpRequestSemantics::Managed {
          requested_model: SmolStr::new("client-model"),
        },
        session_id,
        &ProviderAccess::All,
      )
      .unwrap()
  }

  fn selected_account(dispatch: &RoutedHttpDispatch) -> &str {
    let TargetResolution::Selected(target) = dispatch.resolution() else {
      panic!("expected selected target, got {:?}", dispatch.resolution());
    };
    match target {
      SelectedHttpTarget::Managed(target) => target.target().selection_token().key().account_id(),
      SelectedHttpTarget::Relay(target) => target.target().selection_token().key().account_id(),
      SelectedHttpTarget::Transparent(_) => panic!("transparent target has no account"),
    }
  }

  fn settle(dispatch: RoutedHttpDispatch, outcome: SelectionOutcome) -> SelectionSettlement {
    let (_, _, _, resolution) = dispatch.into_parts();
    let TargetResolution::Selected(target) = resolution else {
      panic!("expected selected target");
    };
    target.settle(outcome).unwrap()
  }

  fn coordinator() -> HttpExecutionCoordinator {
    let options = HttpClientOptions::default();
    HttpExecutionCoordinator::new(
      ManagedHttpExecutor::new(build_managed_client(&options).unwrap()),
      OpaqueHttpExecutor::new(build_client(&options).unwrap(), build_opaque_client(&options).unwrap()),
    )
  }

  fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
    headers
  }

  async fn read_request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let (head_end, content_length) = loop {
      let read = stream.read(&mut buffer).await.unwrap();
      assert!(read > 0, "client closed before sending the request head");
      request.extend_from_slice(&buffer[..read]);
      if let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
        let head_end = head_end + 4;
        let head = std::str::from_utf8(&request[..head_end]).unwrap();
        let content_length = head
          .lines()
          .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name
              .eq_ignore_ascii_case("content-length")
              .then(|| value.trim().parse::<usize>().unwrap())
          })
          .unwrap_or(0);
        break (head_end, content_length);
      }
    };
    while request.len() < head_end + content_length {
      let read = stream.read(&mut buffer).await.unwrap();
      assert!(read > 0, "client closed before sending the request body");
      request.extend_from_slice(&buffer[..read]);
    }
  }

  async fn spawn_closing_server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let task = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      observed.fetch_add(1, Ordering::SeqCst);
      read_request(&mut stream).await;
      // Drop the stream without a response head.
    });
    (format!("http://{address}/"), requests, task)
  }

  async fn spawn_held_response_server(
    status: StatusCode,
    body: &'static [u8],
  ) -> (
    String,
    Arc<AtomicUsize>,
    oneshot::Receiver<()>,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
  ) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let (head_sent, head_received) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.unwrap();
      observed.fetch_add(1, Ordering::SeqCst);
      read_request(&mut stream).await;
      let reason = status.canonical_reason().unwrap_or("Test");
      let head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        body.len()
      );
      stream.write_all(head.as_bytes()).await.unwrap();
      stream.flush().await.unwrap();
      let _ = head_sent.send(());
      let _ = released.await;
      stream.write_all(body).await.unwrap();
      stream.shutdown().await.unwrap();
    });
    (format!("http://{address}/"), requests, head_received, release, task)
  }

  #[test]
  fn managed_input_removes_consumed_wire_metadata() {
    let mut headers = json_headers();
    headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
    headers.insert(CONTENT_LENGTH, "123".parse().unwrap());
    headers.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());

    let request = HttpExecutionRequest::managed(headers, serde_json::json!({"model": "test"}));

    assert!(!request.headers.contains_key(CONTENT_ENCODING));
    assert!(!request.headers.contains_key(CONTENT_LENGTH));
    assert!(!request.headers.contains_key(TRANSFER_ENCODING));
    assert_eq!(request.headers[http::header::CONTENT_TYPE], "application/json");
  }

  #[tokio::test]
  async fn request_family_mismatch_settles_without_an_upstream_attempt() {
    let runtime = link(&relay_plan("https://unreachable.invalid/"), &[account("account")]);
    let executor = coordinator();
    let error = tokio::time::timeout(
      Duration::from_secs(1),
      executor.execute(
        relay_dispatch(&runtime, Some(SESSION), &ProviderAccess::All),
        HttpExecutionRequest::managed(json_headers(), serde_json::json!({"model": "test"})),
      ),
    )
    .await
    .expect("a family mismatch must fail before network I/O")
    .unwrap_err();

    assert!(matches!(error, HttpExecutionError::RequestFamilyMismatch { .. }));
    assert!(matches!(
      relay_dispatch(&runtime, Some(SESSION), &ProviderAccess::All).resolution(),
      TargetResolution::Selected(_)
    ));
  }

  #[tokio::test]
  async fn pre_head_error_settles_once_and_no_target_outcomes_do_not_execute() {
    let (base_url, requests, server) = spawn_closing_server().await;
    let runtime = link(&relay_plan(&base_url), &[account("account")]);
    let executor = coordinator();

    let denied = ProviderAccess::from_provider_ids(vec!["openai".into()]).unwrap();
    let outcome = executor
      .execute(
        relay_dispatch(&runtime, Some(SESSION), &denied),
        HttpExecutionRequest::opaque(HeaderMap::new(), None),
      )
      .await
      .unwrap();
    assert!(matches!(
      outcome,
      HttpExecutionOutcome::NoEligible {
        reason: NoEligibleReason::ProviderAccessDenied,
        ..
      }
    ));
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    let error = executor
      .execute(
        relay_dispatch(&runtime, Some(SESSION), &ProviderAccess::All),
        HttpExecutionRequest::opaque(HeaderMap::new(), None),
      )
      .await
      .unwrap_err();
    assert!(matches!(error, HttpExecutionError::OpaqueAttempt { .. }));
    server.await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 1, "the coordinator must not retry");

    let outcome = executor
      .execute(
        relay_dispatch(&runtime, Some(SESSION), &ProviderAccess::All),
        HttpExecutionRequest::opaque(HeaderMap::new(), None),
      )
      .await
      .unwrap();
    assert!(matches!(outcome, HttpExecutionOutcome::CoolingDown { .. }));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
  }

  #[tokio::test]
  async fn opaque_response_is_live_and_settled_before_body_polling() {
    let (base_url, requests, _head, release, server) = spawn_held_response_server(StatusCode::OK, b"payload").await;
    let runtime = link(&relay_plan(&base_url), &[account("account-a"), account("account-b")]);
    let executor = coordinator();
    let first = relay_dispatch(&runtime, Some(SESSION), &ProviderAccess::All);
    let first_account = selected_account(&first).to_string();

    let outcome = tokio::time::timeout(
      Duration::from_secs(2),
      executor.execute(
        first,
        HttpExecutionRequest::opaque(HeaderMap::new(), Some(Bytes::from_static(b"request"))),
      ),
    )
    .await
    .expect("opaque execution should return after the response head")
    .unwrap();
    let HttpExecutionOutcome::Opaque { site, response } = outcome else {
      panic!("expected live opaque response");
    };
    assert_eq!(site.listener_id(), &listener_id());
    assert_eq!(response.status(), StatusCode::OK);

    let next = relay_dispatch(&runtime, Some(SESSION), &ProviderAccess::All);
    assert_eq!(
      selected_account(&next),
      first_account,
      "healthy affinity must be committed before the live body is polled"
    );
    drop(next);

    release.send(()).unwrap();
    assert_eq!(response.bytes().await.unwrap(), Bytes::from_static(b"payload"));
    server.await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 1);
  }

  #[tokio::test]
  async fn managed_status_settles_before_buffered_response_adaptation() {
    let (base_url, requests, head_received, release, server) =
      spawn_held_response_server(StatusCode::TOO_MANY_REQUESTS, b"limited").await;
    let runtime = Arc::new(link(
      &managed_plan(&base_url),
      &[account("account-a"), account("account-b")],
    ));

    let priming = managed_dispatch(&runtime, Some(SESSION));
    let affinity_account = selected_account(&priming).to_string();
    assert_eq!(settle(priming, SelectionOutcome::Healthy), SelectionSettlement::Healthy);

    let selected = managed_dispatch(&runtime, Some(SESSION));
    assert_eq!(selected_account(&selected), affinity_account);
    let executor = coordinator();
    let task = tokio::spawn(async move {
      executor
        .execute(
          selected,
          HttpExecutionRequest::managed(
            json_headers(),
            serde_json::json!({"model": "client-model", "messages": []}),
          ),
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), head_received)
      .await
      .expect("managed upstream should return its head")
      .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let replacement_account = loop {
      let candidate = managed_dispatch(&runtime, Some(SESSION));
      let account = selected_account(&candidate).to_string();
      drop(candidate);
      if account != affinity_account {
        break account;
      }
      assert!(
        tokio::time::Instant::now() < deadline,
        "429 selection was not settled before response adaptation polled the held body"
      );
      tokio::task::yield_now().await;
    };
    assert_ne!(replacement_account, affinity_account);
    assert!(
      !task.is_finished(),
      "managed adaptation should still be waiting for the body"
    );

    release.send(()).unwrap();
    let outcome = task.await.unwrap().unwrap();
    let HttpExecutionOutcome::Managed { site, response } = outcome else {
      panic!("received HTTP status must remain a managed response outcome");
    };
    assert_eq!(site.listener_id(), &listener_id());
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let tokn_requests::execution::ManagedClientBody::Buffered(body) = response.body() else {
      panic!("non-success managed response should be buffered");
    };
    assert_eq!(body, &Bytes::from_static(b"limited"));
    server.await.unwrap();
    assert_eq!(
      requests.load(Ordering::SeqCst),
      1,
      "the coordinator must not retry a 429"
    );
  }
}

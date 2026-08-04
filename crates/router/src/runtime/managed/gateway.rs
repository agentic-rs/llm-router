//! Listener-free execution for embedded managed profile consumers.
//!
//! SDK and CLI callers provide an explicit linked profile for every request.
//! This facade applies the same body, correlation, target-selection,
//! settlement, and response-adaptation semantics as listener-backed serving
//! without constructing a synthetic listener or opaque transport client.

use super::{
  managed_profile_route, resolve_managed_profile, strip_managed_wire_metadata, ManagedAttemptCoordinator,
  ManagedAttemptCoordinatorError, ManagedProfileResolveError, ManagedProfileSite, ManagedRequestBody,
  ManagedRequestBodyError, ManagedSelectionSummary,
};
use crate::runtime::attempts::{capture_bytes, AttemptBodyPlan};
use crate::runtime::downstream::{downstream_body_failure, DownstreamLifecycle};
use crate::runtime::observation::{body_json_facts, capture_headers, correlation};
use crate::runtime::LinkedGatewayRuntime;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::Stream;
use http::HeaderMap;
use serde_json::Value;
use smol_str::SmolStr;
use snafu::Snafu;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Instant;
use tokn_access::ProviderAccess;
use tokn_accounts::link::{NoEligibleReason, TargetResolution};
use tokn_core::generation::GenerationOptions;
use tokn_core::provider::Endpoint;
use tokn_core::util::http::{build_managed_client, HttpClientOptions};
use tokn_events::{
  BodyCapture, BodyOutcome, ClientIdentity, EventFailure, HttpFamily, HttpResponseHead, PolicySelection,
  RequestBodyObservation, RequestOutcome, RequestPhase, RequestSource, RequestStarted, SelectedAction,
  TrafficEventKind,
};
use tokn_policy::ProfileId;
use tokn_requests::execution::{
  ManagedAttemptError, ManagedClientBody, ManagedClientResponse, ManagedHttpExecutor, ManagedResponseError,
};
use tokn_requests::{RequestCompletion, RequestLifecycle, RequestLifecycleEmitter, RequestTermination};

/// One listener-free managed request against an explicit linked profile.
#[derive(Clone)]
pub struct ManagedGatewayRequest {
  endpoint: Endpoint,
  body: Value,
  headers: HeaderMap,
  session_id: Option<SmolStr>,
  provider_access: ProviderAccess,
  generation_options: Option<GenerationOptions>,
}

impl fmt::Debug for ManagedGatewayRequest {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ManagedGatewayRequest")
      .field("endpoint", &self.endpoint)
      .field("body_kind", &json_kind(&self.body))
      .field("header_count", &self.headers.len())
      .field("has_session_id", &self.session_id.is_some())
      .field("provider_access", &self.provider_access)
      .field("has_generation_options", &self.generation_options.is_some())
      .finish()
  }
}

impl ManagedGatewayRequest {
  pub fn new(endpoint: Endpoint, body: Value) -> Self {
    Self {
      endpoint,
      body,
      headers: HeaderMap::new(),
      session_id: None,
      provider_access: ProviderAccess::All,
      generation_options: None,
    }
  }

  pub fn with_headers(mut self, headers: HeaderMap) -> Self {
    self.headers = headers;
    self
  }

  /// Set authoritative session affinity for both selection and provider
  /// persona rendering. This replaces any semantic `x-session-id` value.
  pub fn with_session_id(mut self, session_id: impl Into<SmolStr>) -> Self {
    self.session_id = Some(session_id.into());
    self
  }

  pub fn with_provider_access(mut self, provider_access: ProviderAccess) -> Self {
    self.provider_access = provider_access;
    self
  }

  pub fn with_generation_options(mut self, generation_options: GenerationOptions) -> Self {
    self.generation_options = Some(generation_options);
    self
  }

  pub fn endpoint(&self) -> Endpoint {
    self.endpoint
  }

  pub fn body(&self) -> &Value {
    &self.body
  }

  pub fn headers(&self) -> &HeaderMap {
    &self.headers
  }

  pub fn session_id(&self) -> Option<&str> {
    self.session_id.as_deref()
  }

  pub fn provider_access(&self) -> &ProviderAccess {
    &self.provider_access
  }

  pub fn generation_options(&self) -> Option<&GenerationOptions> {
    self.generation_options.as_ref()
  }
}

/// Listener-free managed execution over one immutable linked runtime.
#[derive(Clone)]
pub struct ManagedGatewayExecutor {
  runtime: Arc<LinkedGatewayRuntime>,
  attempts: ManagedAttemptCoordinator,
  events: RequestLifecycleEmitter,
  body_capture_limit: usize,
}

impl fmt::Debug for ManagedGatewayExecutor {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ManagedGatewayExecutor")
      .field("linked_profiles", &self.runtime.profiles().len())
      .field("events_enabled", &self.events.is_enabled())
      .field("body_capture_limit", &self.body_capture_limit)
      .finish_non_exhaustive()
  }
}

impl ManagedGatewayExecutor {
  /// Build only the managed data-plane transport needed by embedded callers.
  pub fn build(
    runtime: Arc<LinkedGatewayRuntime>,
    http_options: &HttpClientOptions,
  ) -> ManagedGatewayBuildResult<Self> {
    let http =
      build_managed_client(http_options).map_err(|source| ManagedGatewayBuildError::ManagedHttpClient { source })?;
    Ok(Self::new(runtime, ManagedHttpExecutor::new(http)))
  }

  /// Build an embedded managed executor that publishes request lifecycles.
  ///
  /// `events` connects this executor to a caller-owned event hub. The caller
  /// retains the hub, chooses its consumers and ingress capacity, observes
  /// consumer/backpressure failures, and shuts it down after all executors and
  /// response streams have been dropped.
  ///
  /// `body_capture_limit` bounds only the request, upstream-response, and
  /// downstream-response byte prefixes retained in lifecycle events. It never
  /// rejects a body or truncates bytes delivered to an upstream or caller.
  pub fn build_with_events(
    runtime: Arc<LinkedGatewayRuntime>,
    http_options: &HttpClientOptions,
    events: RequestLifecycleEmitter,
    body_capture_limit: usize,
  ) -> ManagedGatewayBuildResult<Self> {
    let http =
      build_managed_client(http_options).map_err(|source| ManagedGatewayBuildError::ManagedHttpClient { source })?;
    Ok(Self::new_with_events(
      runtime,
      ManagedHttpExecutor::new(http),
      events,
      body_capture_limit,
    ))
  }

  pub(crate) fn new(runtime: Arc<LinkedGatewayRuntime>, executor: ManagedHttpExecutor) -> Self {
    Self::new_with_events(runtime, executor, RequestLifecycleEmitter::disabled(), 0)
  }

  pub(crate) fn new_with_events(
    runtime: Arc<LinkedGatewayRuntime>,
    executor: ManagedHttpExecutor,
    events: RequestLifecycleEmitter,
    body_capture_limit: usize,
  ) -> Self {
    Self {
      runtime,
      attempts: ManagedAttemptCoordinator::new(executor),
      events,
      body_capture_limit,
    }
  }

  pub fn runtime(&self) -> &Arc<LinkedGatewayRuntime> {
    &self.runtime
  }

  /// Resolve and execute exactly one attempt for `profile_id`.
  pub async fn execute(
    &self,
    profile_id: &ProfileId,
    request: ManagedGatewayRequest,
  ) -> ManagedGatewayResult<ManagedGatewayOutcome> {
    self
      .execute_controlled(profile_id, request)
      .await
      .map(ManagedGatewayExecution::into_outcome)
  }

  /// Execute one request while retaining an optional semantic-stream terminal.
  ///
  /// Protocol-aware library adapters may consume the returned linear handle
  /// when they recognize a complete terminal message. Raw body consumers
  /// should use [`Self::execute`], whose EOF and early-drop behavior is
  /// unchanged.
  pub async fn execute_controlled(
    &self,
    profile_id: &ProfileId,
    request: ManagedGatewayRequest,
  ) -> ManagedGatewayResult<ManagedGatewayExecution> {
    if self.events.is_enabled() {
      self.execute_with_events(profile_id, request).await
    } else {
      self
        .execute_unobserved(profile_id, request)
        .await
        .map(ManagedGatewayExecution::without_semantic_completion)
    }
  }

  async fn execute_unobserved(
    &self,
    profile_id: &ProfileId,
    request: ManagedGatewayRequest,
  ) -> ManagedGatewayResult<ManagedGatewayOutcome> {
    let profile = self
      .runtime
      .profiles()
      .profile(profile_id)
      .ok_or_else(|| ManagedGatewayError::ProfileNotLinked {
        profile: profile_id.clone(),
      })?;

    // Route-family admission precedes payload semantics for the same reason it
    // does in listener-backed serving: request data cannot change the selected
    // profile or hide a configuration-family error.
    let (site, _) = managed_profile_route(profile).map_err(|source| ManagedGatewayError::Resolve { source })?;
    let ManagedGatewayRequest {
      endpoint,
      body,
      headers,
      session_id,
      provider_access,
      generation_options,
    } = request;
    let body = ManagedRequestBody::try_from(body).map_err(|source| ManagedGatewayError::InvalidBody {
      site: site.clone(),
      source,
    })?;
    let (headers, session_id) = prepare_semantic_headers(headers, session_id);
    let resolution = resolve_managed_profile(
      profile,
      SmolStr::new(body.requested_model()),
      endpoint,
      session_id.as_deref(),
      &provider_access,
    )
    .map_err(|source| ManagedGatewayError::Resolve { source })?;

    let target = match resolution {
      TargetResolution::Selected(target) => target,
      TargetResolution::CoolingDown { retry_at } => {
        return Ok(ManagedGatewayOutcome::CoolingDown { site, retry_at });
      }
      TargetResolution::NoEligible { reason } => {
        return Ok(ManagedGatewayOutcome::NoEligible { site, reason });
      }
    };

    match self
      .attempts
      .execute(target, &headers, body.value(), generation_options.as_ref())
      .await
    {
      Ok(success) => {
        let (site, selection, response) = success.into_parts();
        Ok(ManagedGatewayOutcome::Response {
          site,
          selection,
          response,
        })
      }
      Err(ManagedAttemptCoordinatorError::Attempt { site, summary, source }) => Err(ManagedGatewayError::Attempt {
        site,
        selection: summary,
        source,
      }),
      Err(ManagedAttemptCoordinatorError::Response { site, summary, source }) => Err(ManagedGatewayError::Response {
        site,
        selection: summary,
        source,
      }),
      Err(ManagedAttemptCoordinatorError::Lifecycle { .. }) => {
        unreachable!("disabled embedded execution cannot publish a lifecycle")
      }
    }
  }

  async fn execute_with_events(
    &self,
    profile_id: &ProfileId,
    request: ManagedGatewayRequest,
  ) -> ManagedGatewayResult<ManagedGatewayExecution> {
    let ManagedGatewayRequest {
      endpoint,
      body,
      headers,
      session_id,
      provider_access,
      generation_options,
    } = request;
    let event_headers = headers.clone();
    let (headers, session_id) = prepare_semantic_headers(headers, session_id);
    let started = RequestStarted {
      source: RequestSource::Embedded {
        profile_id: profile_id.as_str().into(),
      },
      http_version: None,
      method: "POST".into(),
      target: tokn_events::CapturedUri::exact(endpoint_target(endpoint)),
      headers: capture_headers(&event_headers),
      body_present: true,
      correlation: correlation(&headers),
    };
    let mut lifecycle = self
      .events
      .begin(started)
      .await
      .map_err(|source| lifecycle_error(RequestPhase::Admission, source))?;
    publish_embedded_boundary(
      &mut lifecycle,
      TrafficEventKind::Authenticated(ClientIdentity::Embedded),
      RequestPhase::Authentication,
    )
    .await?;

    let profile = match self.runtime.profiles().profile(profile_id) {
      Some(profile) => profile,
      None => {
        let error = ManagedGatewayError::ProfileNotLinked {
          profile: profile_id.clone(),
        };
        return Err(finish_embedded_error(lifecycle, error));
      }
    };
    let (site, _) = match managed_profile_route(profile) {
      Ok(route) => route,
      Err(source) => {
        return Err(finish_embedded_error(
          lifecycle,
          ManagedGatewayError::Resolve { source },
        ));
      }
    };
    publish_embedded_boundary(
      &mut lifecycle,
      TrafficEventKind::PolicySelected(PolicySelection {
        binding_id: None,
        action: SelectedAction::Http {
          profile_id: site.profile_id().as_str().into(),
          route_id: site.route_id().as_str().into(),
          family: HttpFamily::Managed,
        },
      }),
      RequestPhase::Policy,
    )
    .await?;

    let (requested_model, stream, initiator) = body_json_facts(&event_headers, &body);
    let decoded = match serde_json::to_vec(&body) {
      Ok(decoded) => decoded,
      Err(source) => {
        let failure = EventFailure {
          code: "internal_error".into(),
          message: "the embedded request body could not be recorded".into(),
        };
        publish_embedded_boundary(
          &mut lifecycle,
          TrafficEventKind::RequestBody(RequestBodyObservation {
            wire: BodyCapture::Absent,
            decoded: None,
            requested_model,
            stream,
            initiator,
            outcome: BodyOutcome::Rejected(failure),
          }),
          RequestPhase::RequestBody,
        )
        .await?;
        return Err(finish_embedded_error(
          lifecycle,
          ManagedGatewayError::BodySerialization { site, source },
        ));
      }
    };
    let body_result = ManagedRequestBody::try_from(body);
    let body_failure = body_result.as_ref().err().map(managed_body_failure);
    publish_embedded_boundary(
      &mut lifecycle,
      TrafficEventKind::RequestBody(RequestBodyObservation {
        wire: BodyCapture::Absent,
        decoded: Some(capture_bytes(&decoded, self.body_capture_limit)),
        requested_model,
        stream,
        initiator,
        outcome: match body_failure {
          Some(failure) => BodyOutcome::Rejected(failure),
          None => BodyOutcome::Accepted,
        },
      }),
      RequestPhase::RequestBody,
    )
    .await?;
    let body = match body_result {
      Ok(body) => body,
      Err(source) => {
        return Err(finish_embedded_error(
          lifecycle,
          ManagedGatewayError::InvalidBody {
            site: site.clone(),
            source,
          },
        ));
      }
    };

    let resolution = match resolve_managed_profile(
      profile,
      SmolStr::new(body.requested_model()),
      endpoint,
      session_id.as_deref(),
      &provider_access,
    ) {
      Ok(resolution) => resolution,
      Err(source) => {
        return Err(finish_embedded_error(
          lifecycle,
          ManagedGatewayError::Resolve { source },
        ));
      }
    };
    let target = match resolution {
      TargetResolution::Selected(target) => target,
      TargetResolution::CoolingDown { retry_at } => {
        if let Some(error) = finish_embedded_outcome(
          lifecycle,
          selection_completion(
            RequestOutcome::Failed,
            "temporarily_unavailable",
            "no upstream target is currently available",
          ),
        ) {
          return Err(error);
        }
        return Ok(ManagedGatewayExecution::without_semantic_completion(
          ManagedGatewayOutcome::CoolingDown { site, retry_at },
        ));
      }
      TargetResolution::NoEligible { reason } => {
        let completion = no_eligible_completion(&reason);
        if let Some(error) = finish_embedded_outcome(lifecycle, completion) {
          return Err(error);
        }
        return Ok(ManagedGatewayExecution::without_semantic_completion(
          ManagedGatewayOutcome::NoEligible { site, reason },
        ));
      }
    };

    let success = match self
      .attempts
      .execute_observed(
        target,
        &headers,
        body.value(),
        generation_options.as_ref(),
        &mut lifecycle,
        self.body_capture_limit,
      )
      .await
    {
      Ok(success) => success,
      Err(ManagedAttemptCoordinatorError::Attempt { site, summary, source }) => {
        return Err(finish_embedded_error(
          lifecycle,
          ManagedGatewayError::Attempt {
            site,
            selection: summary,
            source,
          },
        ));
      }
      Err(ManagedAttemptCoordinatorError::Response { site, summary, source }) => {
        return Err(finish_embedded_error(
          lifecycle,
          ManagedGatewayError::Response {
            site,
            selection: summary,
            source,
          },
        ));
      }
      Err(ManagedAttemptCoordinatorError::Lifecycle { phase, source }) => {
        return Err(lifecycle_error(phase, source));
      }
    };
    let (site, selection, response, attempt) = success.into_parts();
    publish_embedded_boundary(
      &mut lifecycle,
      TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: response.status().as_u16(),
        headers: capture_headers(response.headers()),
      }),
      RequestPhase::DownstreamResponse,
    )
    .await?;

    let status = response.status().as_u16();
    let termination = RequestTermination::new(RequestCompletion::new(
      RequestOutcome::Delivered,
      RequestPhase::Complete,
      Some(status),
      None,
    ));
    match response.body() {
      ManagedClientBody::Buffered(body) => {
        let body = body.clone();
        let mut downstream = DownstreamLifecycle::new(lifecycle, termination, self.body_capture_limit, attempt);
        downstream
          .publish_attempt_progress()
          .map_err(|source| lifecycle_error(RequestPhase::UpstreamResponse, source))?;
        if !body.is_empty() {
          downstream
            .observe_data(&body)
            .map_err(|source| lifecycle_error(RequestPhase::DownstreamResponse, source))?;
        }
        downstream
          .finish_complete()
          .map_err(|source| lifecycle_error(RequestPhase::DownstreamResponse, source))?;
        Ok(ManagedGatewayExecution::without_semantic_completion(
          ManagedGatewayOutcome::Response {
            site,
            selection,
            response,
          },
        ))
      }
      ManagedClientBody::Stream(_) => {
        let mut semantic_completion = None;
        let response = response.map_body(|body| {
          let ManagedClientBody::Stream(stream) = body else {
            unreachable!("managed response body variant changed while installing lifecycle ownership")
          };
          let (stream, completion) =
            EmbeddedLifecycleStream::new(stream, lifecycle, termination, self.body_capture_limit, attempt);
          semantic_completion = Some(completion);
          ManagedClientBody::Stream(Box::pin(stream))
        });
        Ok(ManagedGatewayExecution {
          outcome: ManagedGatewayOutcome::Response {
            site,
            selection,
            response,
          },
          semantic_completion,
        })
      }
    }
  }
}

struct EmbeddedLifecycleStream {
  inner: BoxStream<'static, std::io::Result<Bytes>>,
  state: SharedDownstreamLifecycle,
}

type SharedDownstreamLifecycle = Arc<Mutex<DownstreamLifecycle>>;

/// Linear authority to finish one embedded semantic stream at its application
/// protocol boundary without waiting for HTTP response-body EOF.
#[must_use = "dropping the handle preserves raw EOF/drop lifecycle semantics"]
pub struct ManagedSemanticCompletion {
  state: SharedDownstreamLifecycle,
}

impl fmt::Debug for ManagedSemanticCompletion {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ManagedSemanticCompletion")
      .finish_non_exhaustive()
  }
}

impl ManagedSemanticCompletion {
  /// Atomically close the upstream attempt, downstream body, and request as a
  /// successful semantic delivery. Terminal publication failure is returned
  /// to the protocol adapter and must be surfaced instead of semantic success.
  pub fn complete(self) -> Result<(), tokn_events::TerminalSubmitError> {
    let mut state = lock_downstream(&self.state);
    if !state.is_active() {
      return Ok(());
    }
    if let Err(error) = state.publish_attempt_progress() {
      tracing::warn!(error = %error, "embedded upstream body progress publication failed at semantic completion");
    }
    state.finish_semantically_complete()
  }
}

fn lock_downstream(state: &SharedDownstreamLifecycle) -> MutexGuard<'_, DownstreamLifecycle> {
  state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl EmbeddedLifecycleStream {
  fn new(
    inner: BoxStream<'static, std::io::Result<Bytes>>,
    lifecycle: RequestLifecycle,
    termination: RequestTermination,
    capture_limit: usize,
    attempt: Option<AttemptBodyPlan>,
  ) -> (Self, ManagedSemanticCompletion) {
    let state = Arc::new(Mutex::new(DownstreamLifecycle::new(
      lifecycle,
      termination,
      capture_limit,
      attempt,
    )));
    (
      Self {
        inner,
        state: Arc::clone(&state),
      },
      ManagedSemanticCompletion { state },
    )
  }

  fn is_active(&self) -> bool {
    lock_downstream(&self.state).is_active()
  }

  fn publish_attempt_progress(&self) {
    if let Err(error) = lock_downstream(&self.state).publish_attempt_progress() {
      tracing::warn!(error = %error, "embedded upstream body progress publication failed");
    }
  }

  fn observe_data(&self, data: &Bytes) {
    if let Err(error) = lock_downstream(&self.state).observe_data(data) {
      tracing::warn!(error = %error, "embedded downstream body progress publication failed");
    }
  }

  fn finish_failed(&self) {
    if let Err(error) = lock_downstream(&self.state).finish_failed(downstream_body_failure()) {
      tracing::warn!(error = %error, "embedded downstream body terminal publication failed");
    }
  }

  fn finish_complete(&self) {
    if let Err(error) = lock_downstream(&self.state).finish_complete() {
      tracing::warn!(error = %error, "embedded downstream body terminal publication failed");
    }
  }

  fn finish_cancelled(&self) {
    let mut state = lock_downstream(&self.state);
    if state.is_active() {
      if let Err(error) = state.finish_cancelled() {
        tracing::warn!(error = %error, "embedded downstream body cancellation publication failed");
      }
    }
  }
}

impl Stream for EmbeddedLifecycleStream {
  type Item = std::io::Result<Bytes>;

  fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    if !self.is_active() {
      return Poll::Ready(None);
    }
    match self.inner.as_mut().poll_next(context) {
      Poll::Ready(Some(Ok(data))) => {
        self.publish_attempt_progress();
        self.observe_data(&data);
        Poll::Ready(Some(Ok(data)))
      }
      Poll::Ready(Some(Err(error))) => {
        self.publish_attempt_progress();
        self.finish_failed();
        Poll::Ready(Some(Err(error)))
      }
      Poll::Ready(None) => {
        self.publish_attempt_progress();
        self.finish_complete();
        Poll::Ready(None)
      }
      Poll::Pending => {
        self.publish_attempt_progress();
        Poll::Pending
      }
    }
  }
}

impl Drop for EmbeddedLifecycleStream {
  fn drop(&mut self) {
    self.finish_cancelled();
  }
}

async fn publish_embedded_boundary(
  lifecycle: &mut RequestLifecycle,
  kind: TrafficEventKind,
  phase: RequestPhase,
) -> ManagedGatewayResult<()> {
  lifecycle
    .publish_boundary(kind)
    .await
    .map(|_| ())
    .map_err(|source| lifecycle_error(phase, source))
}

fn finish_embedded_error(lifecycle: RequestLifecycle, error: ManagedGatewayError) -> ManagedGatewayError {
  let completion = error.completion();
  let phase = completion.phase;
  match lifecycle.finish(RequestTermination::new(completion)) {
    Ok(_) => error,
    Err(source) => lifecycle_error(phase, source),
  }
}

fn finish_embedded_outcome(lifecycle: RequestLifecycle, completion: RequestCompletion) -> Option<ManagedGatewayError> {
  let phase = completion.phase;
  lifecycle
    .finish(RequestTermination::new(completion))
    .err()
    .map(|source| lifecycle_error(phase, source))
}

fn lifecycle_error(phase: RequestPhase, source: impl Into<anyhow::Error>) -> ManagedGatewayError {
  ManagedGatewayError::Lifecycle {
    phase,
    source: source.into(),
  }
}

fn endpoint_target(endpoint: Endpoint) -> &'static str {
  match endpoint {
    Endpoint::ChatCompletions => "/v1/chat/completions",
    Endpoint::Responses => "/v1/responses",
    Endpoint::Messages => "/v1/messages",
  }
}

fn managed_body_failure(_source: &ManagedRequestBodyError) -> EventFailure {
  EventFailure {
    code: "invalid_managed_body".into(),
    message: "the managed request body is invalid".into(),
  }
}

fn selection_completion(outcome: RequestOutcome, code: &'static str, message: &'static str) -> RequestCompletion {
  RequestCompletion::new(
    outcome,
    RequestPhase::TargetSelection,
    None,
    Some(EventFailure {
      code: code.into(),
      message: message.into(),
    }),
  )
}

fn no_eligible_completion(reason: &NoEligibleReason) -> RequestCompletion {
  match reason {
    NoEligibleReason::ProviderAccessDenied => selection_completion(
      RequestOutcome::Rejected,
      "provider_access_denied",
      "the embedded caller cannot use the requested provider",
    ),
    NoEligibleReason::ModelSelectorNoMatch { .. }
    | NoEligibleReason::QualifiedTargetUnavailable { .. }
    | NoEligibleReason::CapabilityUnavailable { .. }
    | NoEligibleReason::OriginNotConfigured { .. } => selection_completion(
      RequestOutcome::Rejected,
      "target_unavailable",
      "no configured target supports the requested model and operation",
    ),
    NoEligibleReason::NoPoolBinding { .. } => selection_completion(
      RequestOutcome::Failed,
      "internal_error",
      "the selected route could not resolve an upstream target",
    ),
  }
}

fn prepare_semantic_headers(
  mut headers: HeaderMap,
  explicit_session_id: Option<SmolStr>,
) -> (tokn_headers::HeaderMap, Option<SmolStr>) {
  strip_managed_wire_metadata(&mut headers);

  // Managed headers are string semantics. Native values that cannot be
  // represented as strings are intentionally ignored by this projection.
  let mut headers = tokn_headers::HeaderMap::from(&headers);
  let explicit_session_id = explicit_session_id.and_then(|session_id| {
    let session_id = session_id.trim();
    (!session_id.is_empty()).then(|| SmolStr::new(session_id))
  });
  let session_id = match explicit_session_id {
    Some(session_id) => {
      headers.insert(&tokn_headers::keys::X_SESSION_ID, session_id.clone());
      Some(session_id)
    }
    None => tokn_headers::inbound::inbound_correlation(&headers).session_id,
  };
  (headers, session_id)
}

fn json_kind(value: &Value) -> &'static str {
  match value {
    Value::Null => "null",
    Value::Bool(_) => "boolean",
    Value::Number(_) => "number",
    Value::String(_) => "string",
    Value::Array(_) => "array",
    Value::Object(_) => "object",
  }
}

/// Policy-free result of one embedded managed request.
#[derive(Debug)]
pub enum ManagedGatewayOutcome {
  Response {
    site: ManagedProfileSite,
    selection: ManagedSelectionSummary,
    response: ManagedClientResponse,
  },
  CoolingDown {
    site: ManagedProfileSite,
    retry_at: Instant,
  },
  NoEligible {
    site: ManagedProfileSite,
    reason: NoEligibleReason,
  },
}

/// One embedded result plus optional linear semantic-stream completion.
#[derive(Debug)]
pub struct ManagedGatewayExecution {
  outcome: ManagedGatewayOutcome,
  semantic_completion: Option<ManagedSemanticCompletion>,
}

impl ManagedGatewayExecution {
  fn without_semantic_completion(outcome: ManagedGatewayOutcome) -> Self {
    Self {
      outcome,
      semantic_completion: None,
    }
  }

  pub fn outcome(&self) -> &ManagedGatewayOutcome {
    &self.outcome
  }

  pub fn into_outcome(self) -> ManagedGatewayOutcome {
    self.outcome
  }

  pub fn into_parts(self) -> (ManagedGatewayOutcome, Option<ManagedSemanticCompletion>) {
    (self.outcome, self.semantic_completion)
  }
}

impl ManagedGatewayOutcome {
  pub fn site(&self) -> &ManagedProfileSite {
    match self {
      Self::Response { site, .. } | Self::CoolingDown { site, .. } | Self::NoEligible { site, .. } => site,
    }
  }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ManagedGatewayBuildError {
  #[snafu(display("could not build the managed HTTP client: {source}"))]
  ManagedHttpClient { source: anyhow::Error },
}

pub type ManagedGatewayBuildResult<T> = std::result::Result<T, ManagedGatewayBuildError>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum ManagedGatewayError {
  #[snafu(display("embedded request lifecycle publication failed during {phase:?}: {source}"))]
  Lifecycle { phase: RequestPhase, source: anyhow::Error },

  #[snafu(display("profile '{profile}' is not linked into this gateway runtime"))]
  ProfileNotLinked { profile: ProfileId },

  #[snafu(display("{site} has an invalid request body: {source}"))]
  InvalidBody {
    site: ManagedProfileSite,
    source: ManagedRequestBodyError,
  },

  #[snafu(display("{site} request body could not be serialized for lifecycle capture: {source}"))]
  BodySerialization {
    site: ManagedProfileSite,
    source: serde_json::Error,
  },

  #[snafu(display("could not resolve embedded managed request: {source}"))]
  Resolve { source: ManagedProfileResolveError },

  #[snafu(display("{site} selected managed attempt failed before a final response head: {source}"))]
  Attempt {
    site: ManagedProfileSite,
    selection: ManagedSelectionSummary,
    source: ManagedAttemptError,
  },

  #[snafu(display("{site} selected managed response failed after its final head was settled: {source}"))]
  Response {
    site: ManagedProfileSite,
    selection: ManagedSelectionSummary,
    source: ManagedResponseError,
  },
}

pub type ManagedGatewayResult<T> = std::result::Result<T, ManagedGatewayError>;

impl ManagedGatewayError {
  pub fn site(&self) -> Option<&ManagedProfileSite> {
    match self {
      Self::Lifecycle { .. } | Self::ProfileNotLinked { .. } => None,
      Self::InvalidBody { site, .. }
      | Self::BodySerialization { site, .. }
      | Self::Attempt { site, .. }
      | Self::Response { site, .. } => Some(site),
      Self::Resolve { source } => Some(source.site()),
    }
  }

  pub fn selection(&self) -> Option<&ManagedSelectionSummary> {
    match self {
      Self::Attempt { selection, .. } | Self::Response { selection, .. } => Some(selection),
      Self::Lifecycle { .. }
      | Self::ProfileNotLinked { .. }
      | Self::InvalidBody { .. }
      | Self::BodySerialization { .. }
      | Self::Resolve { .. } => None,
    }
  }

  pub fn phase(&self) -> RequestPhase {
    match self {
      Self::Lifecycle { phase, .. } => *phase,
      Self::ProfileNotLinked { .. } => RequestPhase::Policy,
      Self::InvalidBody { .. } | Self::BodySerialization { .. } => RequestPhase::RequestBody,
      Self::Resolve {
        source: ManagedProfileResolveError::NonManagedRoute { .. },
      } => RequestPhase::Policy,
      Self::Resolve { .. } => RequestPhase::TargetSelection,
      Self::Attempt { .. } => RequestPhase::UpstreamRequest,
      Self::Response { .. } => RequestPhase::UpstreamResponse,
    }
  }

  fn completion(&self) -> RequestCompletion {
    let phase = self.phase();
    let (outcome, code, message) = match self {
      Self::Lifecycle { .. } => (
        RequestOutcome::Failed,
        "event_publication_failed",
        "the request lifecycle could not be recorded",
      ),
      Self::ProfileNotLinked { .. } => (
        RequestOutcome::Failed,
        "profile_not_linked",
        "the embedded profile is not linked into this gateway runtime",
      ),
      Self::InvalidBody { .. } => (
        RequestOutcome::Rejected,
        "invalid_managed_body",
        "the managed request body is invalid",
      ),
      Self::BodySerialization { .. } => (
        RequestOutcome::Failed,
        "internal_error",
        "the embedded request body could not be recorded",
      ),
      Self::Resolve {
        source: ManagedProfileResolveError::MalformedQualification { .. },
      } => (
        RequestOutcome::Rejected,
        "invalid_managed_request",
        "the requested model qualification is invalid",
      ),
      Self::Resolve { .. } => (
        RequestOutcome::Failed,
        "internal_error",
        "the embedded managed profile could not resolve a target",
      ),
      Self::Attempt { source, .. } => managed_attempt_completion(source),
      Self::Response { .. } => (
        RequestOutcome::Failed,
        "invalid_upstream_response",
        "the upstream response could not be processed",
      ),
    };
    RequestCompletion::new(
      outcome,
      phase,
      None,
      Some(EventFailure {
        code: code.into(),
        message: message.into(),
      }),
    )
  }
}

fn managed_attempt_completion(source: &ManagedAttemptError) -> (RequestOutcome, &'static str, &'static str) {
  match source {
    ManagedAttemptError::RequestConversion { .. } | ManagedAttemptError::GenerationControl { .. } => (
      RequestOutcome::Rejected,
      "invalid_managed_request",
      "the managed request is not valid for the selected operation",
    ),
    ManagedAttemptError::ProviderRequest { .. } => (
      RequestOutcome::Failed,
      "upstream_unavailable",
      "the upstream request could not be completed",
    ),
    ManagedAttemptError::BodyObjectRequired
    | ManagedAttemptError::DispatchBodyMismatch { .. }
    | ManagedAttemptError::InputTransform { .. }
    | ManagedAttemptError::RequestSerialization { .. } => (
      RequestOutcome::Failed,
      "internal_error",
      "the managed request could not be prepared",
    ),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::attempts::{ObservedUpstreamBody, UpstreamBodyObservation};
  use futures_util::{stream, StreamExt};
  use http::header::{HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING};
  use hyper::body::{Body as HttpBody, Frame};
  use std::io;
  use std::sync::{Arc, Mutex};
  use tokn_events::{
    AttemptHttpRequest, AttemptHttpResponseHead, AttemptNo, AttemptOutcome, AttemptStarted, BodyFinished, BodyLeg,
    BodyResult, CapturedHeaders, CapturedUri, ConsumerResult, Correlation, EventConsumer, EventSeq, GatewayEvent,
    HttpRequestSnapshot, HubBuilder, RequestOutcome, RequestSource, RequestStarted, TargetSelection, TrafficEvent,
  };

  struct CaptureConsumer {
    events: Arc<Mutex<Vec<GatewayEvent>>>,
  }

  struct ErrorBody(Option<io::Error>);

  impl HttpBody for ErrorBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
      mut self: Pin<&mut Self>,
      _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
      Poll::Ready(self.0.take().map(Err))
    }
  }

  impl EventConsumer<GatewayEvent> for CaptureConsumer {
    fn name(&self) -> &str {
      "embedded-stream-test"
    }

    fn handle(&mut self, _sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
      self.events.lock().unwrap().push(event.clone());
      Ok(())
    }
  }

  fn embedded_started() -> RequestStarted {
    RequestStarted {
      source: RequestSource::Embedded {
        profile_id: "test".into(),
      },
      http_version: None,
      method: "POST".into(),
      target: CapturedUri::exact("/v1/responses"),
      headers: CapturedHeaders::default(),
      body_present: true,
      correlation: Correlation::default(),
    }
  }

  fn captured_traffic(events: &Arc<Mutex<Vec<GatewayEvent>>>) -> Vec<TrafficEvent> {
    events
      .lock()
      .unwrap()
      .iter()
      .filter_map(|event| match event {
        GatewayEvent::Traffic(event) => Some(event.clone()),
        _ => None,
      })
      .collect()
  }

  #[test]
  fn explicit_session_replaces_header_correlation_and_strips_wire_metadata() {
    let mut headers = HeaderMap::new();
    headers.insert("x-session-id", HeaderValue::from_static("header-session"));
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("120"));
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

    let (headers, session_id) = prepare_semantic_headers(headers, Some(SmolStr::new(" explicit-session ")));

    assert_eq!(session_id.as_deref(), Some("explicit-session"));
    assert_eq!(
      headers
        .get(&tokn_headers::keys::X_SESSION_ID)
        .map(|value| value.as_str()),
      Some("explicit-session")
    );
    assert!(!headers.contains_key(&tokn_headers::keys::CONTENT_ENCODING));
    assert!(!headers.contains_key(&tokn_headers::keys::CONTENT_LENGTH));
    assert!(!headers.contains_key("transfer-encoding"));
  }

  #[test]
  fn header_correlation_is_used_when_session_is_not_explicit() {
    let mut headers = HeaderMap::new();
    headers.insert("x-client-session-id", HeaderValue::from_static("header-session"));

    let (headers, session_id) = prepare_semantic_headers(headers, None);

    assert_eq!(session_id.as_deref(), Some("header-session"));
    assert_eq!(
      headers.get("x-client-session-id").map(|value| value.as_str()),
      Some("header-session")
    );
    assert!(!headers.contains_key(&tokn_headers::keys::X_SESSION_ID));
  }

  #[tokio::test]
  async fn embedded_stream_error_is_preserved_and_closes_both_body_legs_and_attempt() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (publisher, hub) = HubBuilder::new()
      .consumer(CaptureConsumer {
        events: Arc::clone(&events),
      })
      .start()
      .unwrap();
    let emitter = RequestLifecycleEmitter::new(publisher);
    let mut lifecycle = emitter.begin(embedded_started()).await.unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::AttemptStarted(AttemptStarted {
        attempt: AttemptNo::FIRST,
        target: TargetSelection {
          family: HttpFamily::Managed,
          account_id: None,
          provider_id: None,
          upstream_id: None,
          requested_model: None,
          upstream_model: None,
          requested_operation: None,
          upstream_operation: None,
        },
      }))
      .await
      .unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::AttemptRequest(AttemptHttpRequest {
        attempt: AttemptNo::FIRST,
        request: HttpRequestSnapshot {
          method: "POST".into(),
          uri: CapturedUri::exact("http://upstream.test/v1/chat/completions"),
          headers: CapturedHeaders::default(),
          body: BodyCapture::Absent,
        },
      }))
      .await
      .unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::AttemptResponseHead(AttemptHttpResponseHead {
        attempt: AttemptNo::FIRST,
        response: HttpResponseHead {
          status: 502,
          headers: CapturedHeaders::default(),
        },
      }))
      .await
      .unwrap();
    lifecycle
      .publish_boundary(TrafficEventKind::DownstreamResponseHead(HttpResponseHead {
        status: 200,
        headers: CapturedHeaders::default(),
      }))
      .await
      .unwrap();

    let upstream = UpstreamBodyObservation::new(AttemptNo::FIRST, 2, None, false);
    let raw_error = io::Error::new(io::ErrorKind::ConnectionReset, "raw upstream reset");
    let mut raw = ObservedUpstreamBody::new(ErrorBody(Some(raw_error)), upstream.clone());
    let observed_error = std::future::poll_fn(|context| Pin::new(&mut raw).poll_frame(context))
      .await
      .expect("the raw body yields an error")
      .expect_err("the raw body error is preserved");
    assert_eq!(observed_error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(observed_error.to_string(), "raw upstream reset");
    let attempt = AttemptBodyPlan::new(upstream, 502);

    let downstream_error = io::Error::new(io::ErrorKind::BrokenPipe, "embedded output failed");
    let inner = stream::iter([Err(downstream_error)]).boxed();
    let termination = RequestTermination::new(RequestCompletion::new(
      RequestOutcome::Delivered,
      RequestPhase::Complete,
      Some(200),
      None,
    ));
    let (mut stream, semantic_completion) =
      EmbeddedLifecycleStream::new(inner, lifecycle, termination, 2, Some(attempt));
    drop(semantic_completion);
    let propagated = stream
      .next()
      .await
      .expect("the embedded stream yields its error")
      .expect_err("the embedded stream error is preserved");
    assert_eq!(propagated.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(propagated.to_string(), "embedded output failed");
    assert!(stream.next().await.is_none());
    drop(stream);
    hub.shutdown().await.unwrap();

    let traffic = captured_traffic(&events);
    let upstream_finished = traffic
      .iter()
      .position(|event| {
        matches!(
          &event.kind,
          TrafficEventKind::BodyFinished(BodyFinished {
            leg: BodyLeg::Upstream { .. },
            result: BodyResult::Failed(_),
            ..
          })
        )
      })
      .expect("upstream body failure");
    let attempt_finished = traffic
      .iter()
      .position(|event| {
        matches!(
          &event.kind,
          TrafficEventKind::AttemptFinished(event) if event.outcome == AttemptOutcome::Failed
        )
      })
      .expect("attempt failure");
    let downstream_finished = traffic
      .iter()
      .position(|event| {
        matches!(
          &event.kind,
          TrafficEventKind::BodyFinished(BodyFinished {
            leg: BodyLeg::Downstream,
            capture: BodyCapture::Truncated { prefix, bytes_seen: 0 },
            result: BodyResult::Failed(_),
          }) if prefix.is_empty()
        )
      })
      .expect("downstream body failure");
    let request_finished = traffic
      .iter()
      .position(|event| {
        matches!(
          &event.kind,
          TrafficEventKind::Finished(event) if event.outcome == RequestOutcome::Failed
        )
      })
      .expect("request failure");
    assert!(upstream_finished < attempt_finished);
    assert!(attempt_finished < downstream_finished);
    assert!(downstream_finished < request_finished);
  }
}

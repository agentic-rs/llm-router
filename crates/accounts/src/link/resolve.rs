//! Request-time target resolution over runtime-linked routes.
//!
//! Static linking has already removed invalid route, pool, upstream, and
//! model-group references. This module applies the remaining request facts in
//! a deliberate order: model candidate, operation candidate, then pool-local
//! account/upstream selection. Selection never sleeps and does not commit
//! session affinity until a [`SelectionToken`] is settled as healthy.

use super::{
  AccountPoolRuntime, LinkedManagedRoute, LinkedModelCandidate, LinkedModelSelector, LinkedRelayRoute,
  LinkedRelayTarget, LinkedUpstream, PoolAcquire, PoolRuntimeResult, ProviderBinding, ProviderBindingKey,
};
use smol_str::SmolStr;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;
use tokn_core::provider::{Endpoint, ProviderTarget};
use tokn_core::upstream_url::CanonicalHttpOrigin;
use tokn_policy::{HttpIngress, InvalidIdentifier, OperationPolicy, ProviderId, QualificationNamespace, UpstreamId};

const BUILTIN_OPERATION_ORDER: [Endpoint; 3] = [Endpoint::ChatCompletions, Endpoint::Responses, Endpoint::Messages];

/// Request-time target resolution. A cooling result is advisory; callers
/// decide whether and when a later request should retry.
#[derive(Debug)]
pub enum TargetResolution<T> {
  Selected(T),
  CoolingDown { retry_at: Instant },
  NoEligible { reason: NoEligibleReason },
}

/// Why a linked route could not select a request-time target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoEligibleReason {
  /// A by-requested fallback selector had no exact group/member match.
  ModelSelectorNoMatch { requested_model: SmolStr },
  /// A valid qualifier did not name a provider/upstream in the route domain.
  QualifiedTargetUnavailable {
    namespace: QualificationNamespace,
    qualifier: SmolStr,
  },
  /// No route candidate serves the exact model and requested/compatible
  /// operation combination.
  CapabilityUnavailable {
    requested_model: SmolStr,
    requested_operation: Endpoint,
  },
  /// A target would otherwise be eligible but is outside the caller's
  /// provider allowlist.
  ProviderAccessDenied,
  /// An original-destination relay does not claim the inbound HTTP origin.
  OriginNotConfigured { origin: CanonicalHttpOrigin },
  /// Static linking promised this upstream had a pool binding, but none was
  /// available at request time.
  NoPoolBinding { upstream: UpstreamId },
}

impl fmt::Display for NoEligibleReason {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ModelSelectorNoMatch { requested_model } => {
        write!(
          formatter,
          "no fallback group exactly matches requested model '{requested_model}'"
        )
      }
      Self::QualifiedTargetUnavailable { namespace, qualifier } => write!(
        formatter,
        "qualified model target {} '{qualifier}' is unavailable in this route",
        qualification_name(*namespace),
      ),
      Self::CapabilityUnavailable {
        requested_model,
        requested_operation,
      } => write!(
        formatter,
        "no linked target serves exact model '{requested_model}' for requested operation '{requested_operation}'"
      ),
      Self::ProviderAccessDenied => {
        formatter.write_str("provider access policy denies every otherwise eligible target")
      }
      Self::OriginNotConfigured { origin } => {
        write!(formatter, "no linked relay upstream claims original origin '{origin}'")
      }
      Self::NoPoolBinding { upstream } => {
        write!(
          formatter,
          "no account-pool binding is available for upstream '{upstream}'"
        )
      }
    }
  }
}

/// The outcome of one attempt made with a selected binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionOutcome {
  Healthy,
  Unauthorized,
  Unavailable,
  Unchanged,
}

/// The pool-local state transition applied while settling a selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionSettlement {
  Healthy,
  CoolingDown { retry_at: Instant },
  Unchanged,
}

/// The exact pool-local selection state to update after an upstream attempt.
///
/// Constructed only for a selected binding, this keeps the session id and
/// complete `(upstream, account)` key together so callers cannot accidentally
/// record an outcome against a different pool tuple.
pub struct SelectionToken {
  pool: Arc<AccountPoolRuntime>,
  binding: Arc<ProviderBinding>,
  session_id: Option<SmolStr>,
}

impl SelectionToken {
  pub fn key(&self) -> &ProviderBindingKey {
    self.binding.key()
  }

  pub fn session_id(&self) -> Option<&str> {
    self.session_id.as_deref()
  }

  /// Consume this token and apply exactly one pool-local attempt outcome.
  pub fn settle(self, outcome: SelectionOutcome) -> PoolRuntimeResult<SelectionSettlement> {
    match outcome {
      SelectionOutcome::Healthy => self.record_success().map(|()| SelectionSettlement::Healthy),
      SelectionOutcome::Unauthorized => self
        .record_unauthorized()
        .map(|retry_at| SelectionSettlement::CoolingDown { retry_at }),
      SelectionOutcome::Unavailable => self
        .record_failure()
        .map(|retry_at| SelectionSettlement::CoolingDown { retry_at }),
      SelectionOutcome::Unchanged => Ok(SelectionSettlement::Unchanged),
    }
  }

  /// Commit successful use, clearing the exact cooldown and recording
  /// affinity only now that the upstream response succeeded.
  pub fn record_success(self) -> PoolRuntimeResult<()> {
    self.pool.record_success(self.session_id.as_deref(), self.binding.key())
  }

  /// Cool the exact selected binding after an upstream failure.
  pub fn record_failure(self) -> PoolRuntimeResult<Instant> {
    self.pool.record_failure(self.binding.key())
  }

  /// Invalidate credentials and cool the exact selected binding after an
  /// unauthorized upstream response.
  ///
  /// Like [`Self::record_failure`], this deliberately does not commit session
  /// affinity. A later retry may therefore select another eligible binding.
  pub fn record_unauthorized(self) -> PoolRuntimeResult<Instant> {
    self.binding.invalidate_credentials();
    self.pool.record_failure(self.binding.key())
  }

  fn new(pool: Arc<AccountPoolRuntime>, binding: Arc<ProviderBinding>, session_id: Option<&str>) -> Self {
    Self {
      pool,
      binding,
      session_id: session_id.map(SmolStr::new),
    }
  }
}

impl fmt::Debug for SelectionToken {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("SelectionToken")
      .field("pool", self.pool.pool().id())
      .field("key", self.binding.key())
      .field("has_session", &self.session_id.is_some())
      .finish()
  }
}

/// A selected managed request target.
#[derive(Debug)]
pub struct SelectedManagedTarget {
  binding: Arc<ProviderBinding>,
  upstream: LinkedUpstream,
  model: SmolStr,
  operation: Endpoint,
  token: SelectionToken,
}

impl SelectedManagedTarget {
  pub fn binding(&self) -> &Arc<ProviderBinding> {
    &self.binding
  }

  pub fn upstream(&self) -> &LinkedUpstream {
    &self.upstream
  }

  pub fn model(&self) -> &str {
    self.model.as_str()
  }

  pub fn operation(&self) -> Endpoint {
    self.operation
  }

  pub fn selection_token(&self) -> &SelectionToken {
    &self.token
  }

  pub fn into_selection_token(self) -> SelectionToken {
    self.token
  }
}

/// Destination used by an opaque relay after account selection.
#[derive(Clone, Debug)]
pub enum RelayDestination {
  Configured(ProviderTarget),
  Original(CanonicalHttpOrigin),
}

/// A selected opaque relay target. Relay selection deliberately carries no
/// model or endpoint because neither participates in eligibility.
#[derive(Debug)]
pub struct SelectedRelayTarget {
  binding: Arc<ProviderBinding>,
  upstream: LinkedUpstream,
  destination: RelayDestination,
  token: SelectionToken,
}

impl SelectedRelayTarget {
  pub fn binding(&self) -> &Arc<ProviderBinding> {
    &self.binding
  }

  pub fn upstream(&self) -> &LinkedUpstream {
    &self.upstream
  }

  pub fn destination(&self) -> &RelayDestination {
    &self.destination
  }

  pub fn selection_token(&self) -> &SelectionToken {
    &self.token
  }

  pub fn into_selection_token(self) -> SelectionToken {
    self.token
  }
}

/// A malformed qualified-model request. Valid but unavailable qualifiers are
/// represented as [`NoEligibleReason::QualifiedTargetUnavailable`] instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetResolveError {
  MalformedQualification {
    namespace: QualificationNamespace,
    requested_model: SmolStr,
    reason: QualificationSyntaxError,
  },
}

impl fmt::Display for TargetResolveError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::MalformedQualification {
        namespace,
        requested_model,
        reason,
      } => write!(
        formatter,
        "invalid {}-qualified model '{requested_model}': {reason}",
        qualification_name(*namespace)
      ),
    }
  }
}

impl std::error::Error for TargetResolveError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::MalformedQualification {
        reason: QualificationSyntaxError::InvalidIdentifier(source),
        ..
      } => Some(source),
      _ => None,
    }
  }
}

/// Exact syntax failure within a qualified model request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationSyntaxError {
  MissingSeparator,
  EmptyModel,
  NonCanonicalModel,
  InvalidIdentifier(InvalidIdentifier),
}

impl fmt::Display for QualificationSyntaxError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::MissingSeparator => formatter.write_str("expected '<qualifier>/<model>'"),
      Self::EmptyModel => formatter.write_str("model after the qualifier must not be empty"),
      Self::NonCanonicalModel => formatter.write_str("model after the qualifier must not have surrounding whitespace"),
      Self::InvalidIdentifier(source) => source.fmt(formatter),
    }
  }
}

impl std::error::Error for QualificationSyntaxError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::InvalidIdentifier(source) => Some(source),
      _ => None,
    }
  }
}

/// Resolve one structured managed request.
///
/// `provider_allowed` may be evaluated more than once and must be pure.
pub fn resolve_managed_target<F>(
  route: &LinkedManagedRoute,
  requested_model: &str,
  requested_operation: Endpoint,
  session_id: Option<&str>,
  provider_allowed: F,
) -> Result<TargetResolution<SelectedManagedTarget>, TargetResolveError>
where
  F: Fn(&ProviderId) -> bool,
{
  match route.model() {
    LinkedModelSelector::Capability => Ok(resolve_managed_candidates(
      route,
      requested_model,
      requested_operation,
      session_id,
      &provider_allowed,
      std::iter::once(ManagedCandidate {
        model: requested_model,
        constraint: UpstreamConstraint::Any,
      }),
    )),
    LinkedModelSelector::Qualified { namespace } => {
      let (qualification, model) = parse_qualification(*namespace, requested_model)?;
      if !route
        .upstreams()
        .upstreams()
        .iter()
        .any(|upstream| qualification.matches(upstream))
      {
        return Ok(TargetResolution::NoEligible {
          reason: NoEligibleReason::QualifiedTargetUnavailable {
            namespace: *namespace,
            qualifier: SmolStr::new(qualification.as_str()),
          },
        });
      }
      Ok(resolve_managed_candidates(
        route,
        requested_model,
        requested_operation,
        session_id,
        &provider_allowed,
        std::iter::once(ManagedCandidate {
          model,
          constraint: qualification.into_constraint(),
        }),
      ))
    }
    LinkedModelSelector::Fallback(fallback) => {
      let Some(group) = fallback.group_for_requested(requested_model) else {
        return Ok(TargetResolution::NoEligible {
          reason: NoEligibleReason::ModelSelectorNoMatch {
            requested_model: SmolStr::new(requested_model),
          },
        });
      };
      Ok(resolve_managed_candidates(
        route,
        requested_model,
        requested_operation,
        session_id,
        &provider_allowed,
        group.candidates().iter().map(|candidate| ManagedCandidate {
          model: candidate.model(),
          constraint: UpstreamConstraint::Fallback(candidate),
        }),
      ))
    }
  }
}

/// Resolve one opaque relay request without consulting model or operation
/// capabilities.
///
/// `provider_allowed` may be evaluated more than once and must be pure.
pub fn resolve_relay_target<F>(
  route: &LinkedRelayRoute,
  ingress: &HttpIngress,
  session_id: Option<&str>,
  provider_allowed: F,
) -> TargetResolution<SelectedRelayTarget>
where
  F: Fn(&ProviderId) -> bool,
{
  match route.target() {
    LinkedRelayTarget::Fixed { pool, upstream } => resolve_relay_upstream(
      pool,
      upstream,
      RelayDestination::Configured(upstream.target().clone()),
      session_id,
      &provider_allowed,
    ),
    target @ LinkedRelayTarget::FromOrigin { pool, .. } => {
      let origin = CanonicalHttpOrigin::from_ingress(ingress);
      let Some(upstream) = target.upstream_for_origin(&origin) else {
        return TargetResolution::NoEligible {
          reason: NoEligibleReason::OriginNotConfigured { origin },
        };
      };
      resolve_relay_upstream(
        pool,
        upstream,
        RelayDestination::Original(origin),
        session_id,
        &provider_allowed,
      )
    }
  }
}

#[derive(Clone, Debug)]
enum Qualification {
  Provider(ProviderId),
  Upstream(UpstreamId),
}

impl Qualification {
  fn as_str(&self) -> &str {
    match self {
      Self::Provider(provider) => provider.as_str(),
      Self::Upstream(upstream) => upstream.as_str(),
    }
  }

  fn matches(&self, upstream: &LinkedUpstream) -> bool {
    match self {
      Self::Provider(provider) => upstream.provider_id() == provider,
      Self::Upstream(expected) => upstream.id() == expected,
    }
  }

  fn into_constraint(self) -> UpstreamConstraint<'static> {
    match self {
      Self::Provider(provider) => UpstreamConstraint::Provider(provider),
      Self::Upstream(upstream) => UpstreamConstraint::Upstream(upstream),
    }
  }
}

#[derive(Clone, Debug)]
enum UpstreamConstraint<'a> {
  Any,
  Provider(ProviderId),
  Upstream(UpstreamId),
  Fallback(&'a LinkedModelCandidate),
}

impl UpstreamConstraint<'_> {
  fn matches(&self, upstream: &LinkedUpstream) -> bool {
    match self {
      Self::Any => true,
      Self::Provider(provider) => upstream.provider_id() == provider,
      Self::Upstream(expected) => upstream.id() == expected,
      Self::Fallback(candidate) => candidate.permits_upstream(upstream.id()),
    }
  }
}

#[derive(Clone, Debug)]
struct ManagedCandidate<'a> {
  model: &'a str,
  constraint: UpstreamConstraint<'a>,
}

fn resolve_managed_candidates<'a, F>(
  route: &LinkedManagedRoute,
  requested_model: &str,
  requested_operation: Endpoint,
  session_id: Option<&str>,
  provider_allowed: &F,
  candidates: impl IntoIterator<Item = ManagedCandidate<'a>>,
) -> TargetResolution<SelectedManagedTarget>
where
  F: Fn(&ProviderId) -> bool,
{
  let mut denied_by_access = false;
  let mut earliest_retry = None;

  for candidate in candidates {
    for operation in operation_candidates(route.operation(), requested_operation) {
      denied_by_access |= route
        .pool()
        .pool()
        .active()
        .iter()
        .chain(route.pool().pool().fallback())
        .flat_map(|account| account.bindings().values())
        .any(|binding| {
          managed_binding_matches(route, &candidate, operation, binding)
            && !provider_allowed(
              route
                .upstreams()
                .upstream(binding.upstream_id())
                .expect("matching binding must belong to the linked managed route")
                .provider_id(),
            )
        });

      let acquired = route.pool().acquire(session_id, |binding| {
        if !managed_binding_matches(route, &candidate, operation, binding) {
          return false;
        }
        provider_allowed(
          route
            .upstreams()
            .upstream(binding.upstream_id())
            .expect("matching binding must belong to the linked managed route")
            .provider_id(),
        )
      });

      match acquired {
        PoolAcquire::Selected(binding) => {
          let upstream = route
            .upstreams()
            .upstream(binding.upstream_id())
            .expect("selected binding must belong to the linked managed route")
            .clone();
          let token = SelectionToken::new(route.pool().clone(), binding.clone(), session_id);
          return TargetResolution::Selected(SelectedManagedTarget {
            binding,
            upstream,
            model: SmolStr::new(candidate.model),
            operation,
            token,
          });
        }
        PoolAcquire::CoolingDown { retry_at } => retain_earliest(&mut earliest_retry, retry_at),
        PoolAcquire::NoEligible => {}
      }
    }
  }

  if let Some(retry_at) = earliest_retry {
    TargetResolution::CoolingDown { retry_at }
  } else if denied_by_access {
    TargetResolution::NoEligible {
      reason: NoEligibleReason::ProviderAccessDenied,
    }
  } else {
    TargetResolution::NoEligible {
      reason: NoEligibleReason::CapabilityUnavailable {
        requested_model: SmolStr::new(requested_model),
        requested_operation,
      },
    }
  }
}

fn resolve_relay_upstream<F>(
  pool: &Arc<AccountPoolRuntime>,
  upstream: &LinkedUpstream,
  destination: RelayDestination,
  session_id: Option<&str>,
  provider_allowed: &F,
) -> TargetResolution<SelectedRelayTarget>
where
  F: Fn(&ProviderId) -> bool,
{
  if !provider_allowed(upstream.provider_id()) {
    return TargetResolution::NoEligible {
      reason: NoEligibleReason::ProviderAccessDenied,
    };
  }

  match pool.acquire(session_id, |binding| binding.upstream_id() == upstream.id()) {
    PoolAcquire::Selected(binding) => {
      let token = SelectionToken::new(pool.clone(), binding.clone(), session_id);
      TargetResolution::Selected(SelectedRelayTarget {
        binding,
        upstream: upstream.clone(),
        destination,
        token,
      })
    }
    PoolAcquire::CoolingDown { retry_at } => TargetResolution::CoolingDown { retry_at },
    PoolAcquire::NoEligible => TargetResolution::NoEligible {
      reason: NoEligibleReason::NoPoolBinding {
        upstream: upstream.id().clone(),
      },
    },
  }
}

fn parse_qualification(
  namespace: QualificationNamespace,
  requested_model: &str,
) -> Result<(Qualification, &str), TargetResolveError> {
  let (qualifier, model) = requested_model
    .split_once('/')
    .ok_or_else(|| malformed_qualification(namespace, requested_model, QualificationSyntaxError::MissingSeparator))?;
  if model.is_empty() {
    return Err(malformed_qualification(
      namespace,
      requested_model,
      QualificationSyntaxError::EmptyModel,
    ));
  }
  if model.trim() != model {
    return Err(malformed_qualification(
      namespace,
      requested_model,
      QualificationSyntaxError::NonCanonicalModel,
    ));
  }
  let qualification = match namespace {
    QualificationNamespace::Provider => ProviderId::new(qualifier)
      .map(Qualification::Provider)
      .map_err(|source| {
        malformed_qualification(
          namespace,
          requested_model,
          QualificationSyntaxError::InvalidIdentifier(source),
        )
      })?,
    QualificationNamespace::Upstream => UpstreamId::new(qualifier)
      .map(Qualification::Upstream)
      .map_err(|source| {
        malformed_qualification(
          namespace,
          requested_model,
          QualificationSyntaxError::InvalidIdentifier(source),
        )
      })?,
  };
  Ok((qualification, model))
}

fn malformed_qualification(
  namespace: QualificationNamespace,
  requested_model: &str,
  reason: QualificationSyntaxError,
) -> TargetResolveError {
  TargetResolveError::MalformedQualification {
    namespace,
    requested_model: SmolStr::new(requested_model),
    reason,
  }
}

fn qualification_name(namespace: QualificationNamespace) -> &'static str {
  match namespace {
    QualificationNamespace::Provider => "provider",
    QualificationNamespace::Upstream => "upstream",
  }
}

fn managed_binding_matches(
  route: &LinkedManagedRoute,
  candidate: &ManagedCandidate<'_>,
  operation: Endpoint,
  binding: &ProviderBinding,
) -> bool {
  route
    .upstreams()
    .upstream(binding.upstream_id())
    .is_some_and(|upstream| {
      candidate.constraint.matches(upstream) && binding.provider().supports(candidate.model, operation)
    })
}

fn operation_candidates(policy: OperationPolicy, requested: Endpoint) -> impl Iterator<Item = Endpoint> {
  let mut operations = [requested; BUILTIN_OPERATION_ORDER.len()];
  let mut len = 1;
  if policy == OperationPolicy::TranslateCompatible {
    for operation in BUILTIN_OPERATION_ORDER {
      if operation != requested {
        operations[len] = operation;
        len += 1;
      }
    }
  }
  operations.into_iter().take(len)
}

fn retain_earliest(earliest: &mut Option<Instant>, candidate: Instant) {
  if earliest.is_none_or(|current| candidate < current) {
    *earliest = Some(candidate);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::link::{
    build_account_pool_runtimes, link_account_pools, link_provider_graph, link_routes, LinkedRouteKind, LinkedRoutes,
  };
  use crate::registry::Registry;
  use async_trait::async_trait;
  use serde_json::Value;
  use smol_str::SmolStr;
  use std::collections::{BTreeMap, BTreeSet, HashSet};
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::time::Duration;
  use tokn_auth::descriptor::{EndpointSpec, ProviderDescriptor};
  use tokn_core::account::{AccountConfig, AccountTier};
  use tokn_core::provider::{AuthKind, Provider, ProviderInfo, RequestCtx, ID_LLAMA_CPP, ID_OPENAI};
  use tokn_policy::{
    AccountPoolId, AccountPoolPlan, AccountSelectionStrategy, AccountSelector, CanonicalAuthority, FallbackSelector,
    GatewayPlan, HttpScheme, ManagedRetry, ManagedRoute, ManagedTarget, ModelCandidate, ModelGroupId, ModelGroupPlan,
    ModelSelector, RelayRetry, RelayRoute, RelayTarget, RouteId, RoutePlan, SessionAffinityPlan, UpstreamOrigin,
    UpstreamPlan, UpstreamSelector,
  };

  const INVALIDATING_PROVIDER_ID: &str = "invalidating-test";
  static FIRST_INVALIDATIONS: AtomicUsize = AtomicUsize::new(0);
  static SECOND_INVALIDATIONS: AtomicUsize = AtomicUsize::new(0);
  static INVALIDATING_ENDPOINTS: &[Endpoint] = &[Endpoint::ChatCompletions];
  static INVALIDATING_ENDPOINT_SPECS: &[EndpointSpec] = &[EndpointSpec {
    endpoint: Endpoint::ChatCompletions,
    method: "POST",
    path: "/v1/chat/completions",
    aliases: &[],
  }];

  struct InvalidatingProvider {
    info: ProviderInfo,
    invalidations: &'static AtomicUsize,
  }

  #[async_trait]
  impl Provider for InvalidatingProvider {
    fn id(&self) -> &str {
      &self.info.id
    }

    fn info(&self) -> &ProviderInfo {
      &self.info
    }

    async fn list_models(&self, _http: &reqwest::Client) -> tokn_core::provider::Result<Value> {
      Ok(Value::Null)
    }

    async fn chat(&self, _ctx: RequestCtx<'_>) -> tokn_core::provider::Result<reqwest::Response> {
      unreachable!("selection test does not send upstream requests")
    }

    fn on_unauthorized(&self) {
      self.invalidations.fetch_add(1, Ordering::Relaxed);
    }
  }

  fn validate_invalidating_account(_account: &AccountConfig) -> tokn_core::provider::Result<()> {
    Ok(())
  }

  fn build_invalidating_provider(
    account: Arc<AccountConfig>,
    target: ProviderTarget,
  ) -> tokn_core::provider::Result<Arc<dyn Provider>> {
    let invalidations = match account.id.as_str() {
      "first" => &FIRST_INVALIDATIONS,
      "second" => &SECOND_INVALIDATIONS,
      account_id => panic!("unexpected invalidating test account '{account_id}'"),
    };
    Ok(Arc::new(InvalidatingProvider {
      info: ProviderInfo {
        id: INVALIDATING_PROVIDER_ID.into(),
        aliases: &[],
        display_name: "Invalidating test provider",
        upstream_url: target.base_url().to_string(),
        auth_kind: AuthKind::None,
        default_models: Vec::new(),
        default_endpoints: INVALIDATING_ENDPOINTS,
        model_cache: target.model_cache().clone(),
      },
      invalidations,
    }))
  }

  fn never_matches(_host: &str, _path: &str, _id: &'static str) -> bool {
    false
  }

  static INVALIDATING_DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
    id: INVALIDATING_PROVIDER_ID,
    display_name: "Invalidating test provider",
    hosts: &[],
    base_url: "https://invalidating.example/v1",
    credentials: &[],
    endpoints: INVALIDATING_ENDPOINT_SPECS,
    model_endpoint_rules: Some(&[]),
    rewrites: &[],
    auth_urls: &[],
    matches_url: never_matches,
    validate: validate_invalidating_account,
    build: build_invalidating_provider,
    build_auth: None,
  };

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

  fn account(id: &str, provider: &str, tier: AccountTier) -> AccountConfig {
    let mut account: AccountConfig = toml::from_str(
      r#"
        id = "fixture"
        provider = "llama-cpp"
      "#,
    )
    .unwrap();
    account.id = id.to_string();
    account.provider = provider.to_string();
    account.tier = tier;
    if provider != ID_LLAMA_CPP {
      account.api_key = Some("test-key".to_string().into());
    }
    account
  }

  fn account_pool(affinity: Option<SessionAffinityPlan>) -> AccountPoolPlan {
    AccountPoolPlan::new(
      AccountSelector::all(),
      AccountSelectionStrategy::RoundRobin,
      Duration::from_secs(60),
      affinity,
    )
  }

  fn upstream(provider: &str, base_url: &str, eligible_accounts: &[&str], origins: &[&str]) -> UpstreamPlan {
    UpstreamPlan::new(
      provider_id(provider),
      Some(base_url.into()),
      origins
        .iter()
        .map(|origin| UpstreamOrigin::new(*origin))
        .collect::<Vec<_>>()
        .into_boxed_slice(),
      false,
    )
    .with_eligible_accounts(Some(eligible_accounts.iter().map(SmolStr::new).collect()))
  }

  fn managed_route(model: ModelSelector, operation: OperationPolicy) -> RoutePlan {
    RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(pool_id("default"), UpstreamSelector::Any, model),
      operation,
      None,
      ManagedRetry::Never,
    ))
  }

  fn fixed_relay(upstream: &str) -> RoutePlan {
    RoutePlan::Relay(RelayRoute::new(
      RelayTarget::FixedUpstream {
        upstream: upstream_id(upstream),
        account_pool: pool_id("default"),
      },
      None,
      RelayRetry::Never,
    ))
  }

  fn origin_relay() -> RoutePlan {
    RoutePlan::Relay(RelayRoute::new(
      RelayTarget::UpstreamFromOrigin {
        account_pool: pool_id("default"),
      },
      None,
      RelayRetry::Never,
    ))
  }

  fn gateway(
    routes: BTreeMap<RouteId, RoutePlan>,
    pool: AccountPoolPlan,
    upstreams: BTreeMap<UpstreamId, UpstreamPlan>,
    groups: BTreeMap<ModelGroupId, ModelGroupPlan>,
  ) -> GatewayPlan {
    GatewayPlan::new(
      BTreeMap::new(),
      BTreeMap::new(),
      routes,
      BTreeMap::from([(pool_id("default"), pool)]),
      upstreams,
      groups,
    )
  }

  fn link_with_registry(gateway: &GatewayPlan, accounts: &[AccountConfig], registry: &Registry) -> LinkedRoutes {
    let providers = link_provider_graph(gateway, accounts, registry).unwrap();
    let pools = link_account_pools(gateway, &providers, registry).unwrap();
    let runtimes = build_account_pool_runtimes(&pools);
    let reachable = gateway.routes().keys().cloned().collect::<BTreeSet<_>>();
    link_routes(gateway, &reachable, &providers, &runtimes).unwrap()
  }

  fn link(gateway: &GatewayPlan, accounts: &[AccountConfig]) -> LinkedRoutes {
    link_with_registry(gateway, accounts, &Registry::builtin())
  }

  fn managed<'a>(routes: &'a LinkedRoutes, id: &str) -> &'a LinkedManagedRoute {
    match routes.route(&route_id(id)).unwrap().kind() {
      LinkedRouteKind::Managed(route) => route,
      other => panic!("expected managed route, got {other:?}"),
    }
  }

  fn relay<'a>(routes: &'a LinkedRoutes, id: &str) -> &'a LinkedRelayRoute {
    match routes.route(&route_id(id)).unwrap().kind() {
      LinkedRouteKind::Relay(route) => route,
      other => panic!("expected relay route, got {other:?}"),
    }
  }

  fn warm(route: &LinkedManagedRoute, upstream: &str, models: &[&str]) {
    route
      .upstreams()
      .upstream(&upstream_id(upstream))
      .unwrap()
      .target()
      .model_cache()
      .set(models.iter().map(|model| (*model).to_string()).collect::<HashSet<_>>());
  }

  fn selected_managed(result: TargetResolution<SelectedManagedTarget>) -> SelectedManagedTarget {
    let TargetResolution::Selected(selected) = result else {
      panic!("expected selected managed target, got {result:?}");
    };
    selected
  }

  fn selected_relay(result: TargetResolution<SelectedRelayTarget>) -> SelectedRelayTarget {
    let TargetResolution::Selected(selected) = result else {
      panic!("expected selected relay target, got {result:?}");
    };
    selected
  }

  fn fallback_group(candidates: &[(&str, &str)]) -> ModelGroupPlan {
    ModelGroupPlan::new(
      candidates
        .iter()
        .map(|(upstream, model)| ModelCandidate::new(Some(upstream_id(upstream)), *model))
        .collect::<Vec<_>>()
        .into_boxed_slice(),
    )
  }

  fn affinity_managed_routes(provider: &str, registry: &Registry) -> LinkedRoutes {
    let affinity = SessionAffinityPlan::new(Duration::from_secs(300), Duration::from_secs(60));
    let gateway = gateway(
      BTreeMap::from([(
        route_id("managed"),
        managed_route(ModelSelector::Capability, OperationPolicy::Preserve),
      )]),
      account_pool(Some(affinity)),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream(provider, "https://upstream.example/v1/", &["first", "second"], &[]),
      )]),
      BTreeMap::new(),
    );
    let routes = link_with_registry(
      &gateway,
      &[
        account("first", provider, AccountTier::Active),
        account("second", provider, AccountTier::Active),
      ],
      registry,
    );
    warm(managed(&routes, "managed"), "upstream", &["model"]);
    routes
  }

  #[test]
  fn managed_orders_model_then_requested_and_stable_compatible_operations() {
    let group = group_id("ordered");
    let gateway = gateway(
      BTreeMap::from([(
        route_id("managed"),
        managed_route(
          ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
          OperationPolicy::TranslateCompatible,
        ),
      )]),
      account_pool(None),
      BTreeMap::from([
        (
          upstream_id("a-llama"),
          upstream(ID_LLAMA_CPP, "https://llama.example/v1/", &["llama"], &[]),
        ),
        (
          upstream_id("z-openai"),
          upstream(ID_OPENAI, "https://openai.example/v1/", &["openai"], &[]),
        ),
      ]),
      BTreeMap::from([(
        group.clone(),
        fallback_group(&[("a-llama", "first-model"), ("z-openai", "second-model")]),
      )]),
    );
    let routes = link(
      &gateway,
      &[
        account("llama", ID_LLAMA_CPP, AccountTier::Active),
        account("openai", ID_OPENAI, AccountTier::Active),
      ],
    );
    let route = managed(&routes, "managed");
    warm(route, "a-llama", &["first-model"]);
    warm(route, "z-openai", &["second-model"]);

    let selected =
      selected_managed(resolve_managed_target(route, "request-name", Endpoint::Responses, None, |_| true).unwrap());

    // The first model's compatible Chat Completions operation wins before
    // the second model's requested Responses operation is considered.
    assert_eq!(selected.model(), "first-model");
    assert_eq!(selected.operation(), Endpoint::ChatCompletions);
    assert_eq!(selected.upstream().id().as_str(), "a-llama");

    let requested_first = selected_managed(
      resolve_managed_target(route, "request-name", Endpoint::ChatCompletions, None, |_| true).unwrap(),
    );
    assert_eq!(requested_first.operation(), Endpoint::ChatCompletions);
  }

  #[test]
  fn access_filters_without_perturbing_capability_reasons() {
    let gateway = gateway(
      BTreeMap::from([(
        route_id("managed"),
        managed_route(ModelSelector::Capability, OperationPolicy::Preserve),
      )]),
      account_pool(None),
      BTreeMap::from([
        (
          upstream_id("a-llama"),
          upstream(ID_LLAMA_CPP, "https://llama.example/v1/", &["llama"], &[]),
        ),
        (
          upstream_id("z-openai"),
          upstream(ID_OPENAI, "https://openai.example/v1/", &["openai"], &[]),
        ),
      ]),
      BTreeMap::new(),
    );
    let routes = link(
      &gateway,
      &[
        account("llama", ID_LLAMA_CPP, AccountTier::Active),
        account("openai", ID_OPENAI, AccountTier::Active),
      ],
    );
    let route = managed(&routes, "managed");
    warm(route, "a-llama", &["shared-model"]);
    warm(route, "z-openai", &["shared-model"]);

    let selected = selected_managed(
      resolve_managed_target(route, "shared-model", Endpoint::ChatCompletions, None, |provider| {
        provider.as_str() == ID_OPENAI
      })
      .unwrap(),
    );
    assert_eq!(selected.upstream().provider_id().as_str(), ID_OPENAI);

    assert!(matches!(
      resolve_managed_target(route, "shared-model", Endpoint::ChatCompletions, None, |_| false).unwrap(),
      TargetResolution::NoEligible {
        reason: NoEligibleReason::ProviderAccessDenied
      }
    ));
    assert!(matches!(
      resolve_managed_target(route, "not-advertised", Endpoint::ChatCompletions, None, |_| false).unwrap(),
      TargetResolution::NoEligible {
        reason: NoEligibleReason::CapabilityUnavailable { .. }
      }
    ));
  }

  #[test]
  fn cooldown_falls_through_candidates_and_reports_global_earliest_retry() {
    let group = group_id("fallback");
    let gateway = gateway(
      BTreeMap::from([(
        route_id("managed"),
        managed_route(
          ModelSelector::Fallback(FallbackSelector::Fixed(group.clone())),
          OperationPolicy::Preserve,
        ),
      )]),
      account_pool(None),
      BTreeMap::from([
        (
          upstream_id("first"),
          upstream(ID_LLAMA_CPP, "https://first.example/v1/", &["account"], &[]),
        ),
        (
          upstream_id("second"),
          upstream(ID_LLAMA_CPP, "https://second.example/v1/", &["account"], &[]),
        ),
      ]),
      BTreeMap::from([(
        group,
        fallback_group(&[("first", "first-model"), ("second", "second-model")]),
      )]),
    );
    let routes = link(&gateway, &[account("account", ID_LLAMA_CPP, AccountTier::Active)]);
    let route = managed(&routes, "managed");
    warm(route, "first", &["first-model"]);
    warm(route, "second", &["second-model"]);

    let first =
      selected_managed(resolve_managed_target(route, "request", Endpoint::ChatCompletions, None, |_| true).unwrap());
    assert_eq!(first.upstream().id().as_str(), "first");
    let first_retry = first.into_selection_token().record_failure().unwrap();

    let second =
      selected_managed(resolve_managed_target(route, "request", Endpoint::ChatCompletions, None, |_| true).unwrap());
    assert_eq!(second.upstream().id().as_str(), "second");
    let second_retry = second.into_selection_token().record_failure().unwrap();
    assert!(first_retry <= second_retry);

    assert!(matches!(
      resolve_managed_target(route, "request", Endpoint::ChatCompletions, None, |_| true).unwrap(),
      TargetResolution::CoolingDown { retry_at } if retry_at == first_retry
    ));
  }

  #[test]
  fn selection_token_records_affinity_only_on_success_and_failure_on_exact_key() {
    let affinity = SessionAffinityPlan::new(Duration::from_secs(300), Duration::from_secs(60));
    let gateway = gateway(
      BTreeMap::from([(
        route_id("managed"),
        managed_route(ModelSelector::Capability, OperationPolicy::Preserve),
      )]),
      account_pool(Some(affinity)),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream(ID_LLAMA_CPP, "https://upstream.example/v1/", &["first", "second"], &[]),
      )]),
      BTreeMap::new(),
    );
    let routes = link(
      &gateway,
      &[
        account("first", ID_LLAMA_CPP, AccountTier::Active),
        account("second", ID_LLAMA_CPP, AccountTier::Active),
      ],
    );
    let route = managed(&routes, "managed");
    warm(route, "upstream", &["model"]);

    let uncommitted = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(uncommitted.binding().account_id(), "first");
    drop(uncommitted);

    let committed = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(committed.binding().account_id(), "second");
    committed.into_selection_token().record_success().unwrap();

    let affinity_hit = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(affinity_hit.binding().account_id(), "second");
    affinity_hit.into_selection_token().record_failure().unwrap();

    let exact_fallthrough = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(exact_fallthrough.binding().account_id(), "first");
  }

  #[test]
  fn selection_token_settle_healthy_clears_cooldown_and_commits_affinity() {
    let routes = affinity_managed_routes(ID_LLAMA_CPP, &Registry::builtin());
    let route = managed(&routes, "managed");
    let selected = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(selected.binding().account_id(), "first");
    let token = selected.into_selection_token();
    let pool = token.pool.clone();
    let selected_key = token.key().clone();

    pool.record_failure(&selected_key).unwrap();
    assert_eq!(
      token.settle(SelectionOutcome::Healthy).unwrap(),
      SelectionSettlement::Healthy
    );

    assert!(matches!(
      pool.acquire(None, |binding| binding.key() == &selected_key),
      PoolAcquire::Selected(binding) if binding.key() == &selected_key
    ));
    let affinity_hit = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(affinity_hit.binding().account_id(), "first");
  }

  #[test]
  fn selection_token_settle_unavailable_cools_without_committing_affinity() {
    let routes = affinity_managed_routes(ID_LLAMA_CPP, &Registry::builtin());
    let route = managed(&routes, "managed");
    let selected = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(selected.binding().account_id(), "first");
    let token = selected.into_selection_token();
    let pool = token.pool.clone();
    let selected_key = token.key().clone();

    let SelectionSettlement::CoolingDown { retry_at } = token.settle(SelectionOutcome::Unavailable).unwrap() else {
      panic!("unavailable selection did not enter cooldown");
    };
    assert!(matches!(
      pool.acquire(Some("session"), |binding| binding.key() == &selected_key),
      PoolAcquire::CoolingDown { retry_at: actual } if actual == retry_at
    ));

    pool.record_success(None, &selected_key).unwrap();
    let retry = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(retry.binding().account_id(), "second");
  }

  #[test]
  fn selection_token_settle_unchanged_does_not_mutate_pool_state() {
    let routes = affinity_managed_routes(ID_LLAMA_CPP, &Registry::builtin());
    let route = managed(&routes, "managed");
    let selected = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(selected.binding().account_id(), "first");
    let token = selected.into_selection_token();
    let pool = token.pool.clone();
    let selected_key = token.key().clone();

    assert_eq!(
      token.settle(SelectionOutcome::Unchanged).unwrap(),
      SelectionSettlement::Unchanged
    );

    let retry = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(retry.binding().account_id(), "second");
    assert!(matches!(
      pool.acquire(None, |binding| binding.key() == &selected_key),
      PoolAcquire::Selected(binding) if binding.key() == &selected_key
    ));
  }

  #[test]
  fn selection_token_settle_unauthorized_invalidates_and_cools_only_the_selected_binding() {
    FIRST_INVALIDATIONS.store(0, Ordering::Relaxed);
    SECOND_INVALIDATIONS.store(0, Ordering::Relaxed);

    let mut registry = Registry::builtin();
    registry.register(&INVALIDATING_DESCRIPTOR);
    let routes = affinity_managed_routes(INVALIDATING_PROVIDER_ID, &registry);
    let route = managed(&routes, "managed");

    let selected = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(selected.binding().account_id(), "first");
    let token = selected.into_selection_token();
    let pool = token.pool.clone();
    let selected_key = token.key().clone();

    let SelectionSettlement::CoolingDown { retry_at } = token.settle(SelectionOutcome::Unauthorized).unwrap() else {
      panic!("unauthorized selection did not enter cooldown");
    };

    assert_eq!(FIRST_INVALIDATIONS.load(Ordering::Relaxed), 1);
    assert_eq!(SECOND_INVALIDATIONS.load(Ordering::Relaxed), 0);
    assert!(matches!(
      pool.acquire(Some("session"), |binding| binding.key() == &selected_key),
      PoolAcquire::CoolingDown { retry_at: actual } if actual == retry_at
    ));

    // Clear only the test cooldown without writing affinity. If the
    // unauthorized outcome had committed affinity, the same session would
    // select `first` again instead of advancing round-robin to `second`.
    pool.record_success(None, &selected_key).unwrap();
    let retry = selected_managed(
      resolve_managed_target(route, "model", Endpoint::ChatCompletions, Some("session"), |_| true).unwrap(),
    );
    assert_eq!(retry.binding().account_id(), "second");
    assert_eq!(FIRST_INVALIDATIONS.load(Ordering::Relaxed), 1);
    assert_eq!(SECOND_INVALIDATIONS.load(Ordering::Relaxed), 0);
  }

  #[test]
  fn qualified_selectors_are_exact_strip_prefixes_and_type_syntax_errors() {
    let gateway = gateway(
      BTreeMap::from([
        (
          route_id("provider"),
          managed_route(
            ModelSelector::Qualified {
              namespace: QualificationNamespace::Provider,
            },
            OperationPolicy::Preserve,
          ),
        ),
        (
          route_id("upstream"),
          managed_route(
            ModelSelector::Qualified {
              namespace: QualificationNamespace::Upstream,
            },
            OperationPolicy::Preserve,
          ),
        ),
      ]),
      account_pool(None),
      BTreeMap::from([(
        upstream_id("local"),
        upstream(ID_LLAMA_CPP, "https://local.example/v1/", &["account"], &[]),
      )]),
      BTreeMap::new(),
    );
    let routes = link(&gateway, &[account("account", ID_LLAMA_CPP, AccountTier::Active)]);
    for route in [managed(&routes, "provider"), managed(&routes, "upstream")] {
      warm(route, "local", &["exact/model"]);
    }

    let provider = selected_managed(
      resolve_managed_target(
        managed(&routes, "provider"),
        "llama-cpp/exact/model",
        Endpoint::ChatCompletions,
        None,
        |_| true,
      )
      .unwrap(),
    );
    assert_eq!(provider.model(), "exact/model");

    let upstream = selected_managed(
      resolve_managed_target(
        managed(&routes, "upstream"),
        "local/exact/model",
        Endpoint::ChatCompletions,
        None,
        |_| true,
      )
      .unwrap(),
    );
    assert_eq!(upstream.upstream().id().as_str(), "local");

    assert!(matches!(
      resolve_managed_target(
        managed(&routes, "provider"),
        "other/exact/model",
        Endpoint::ChatCompletions,
        None,
        |_| true,
      )
      .unwrap(),
      TargetResolution::NoEligible {
        reason: NoEligibleReason::QualifiedTargetUnavailable { .. }
      }
    ));
    assert!(matches!(
      resolve_managed_target(
        managed(&routes, "provider"),
        "llama-cpp",
        Endpoint::ChatCompletions,
        None,
        |_| true,
      ),
      Err(TargetResolveError::MalformedQualification {
        reason: QualificationSyntaxError::MissingSeparator,
        ..
      })
    ));
    assert!(matches!(
      resolve_managed_target(
        managed(&routes, "provider"),
        "Bad/exact",
        Endpoint::ChatCompletions,
        None,
        |_| true,
      ),
      Err(TargetResolveError::MalformedQualification {
        reason: QualificationSyntaxError::InvalidIdentifier(_),
        ..
      })
    ));
  }

  #[test]
  fn by_requested_fallback_has_no_fuzzy_matching() {
    let group = group_id("gpt-family");
    let gateway = gateway(
      BTreeMap::from([(
        route_id("managed"),
        managed_route(
          ModelSelector::Fallback(FallbackSelector::ByRequested(vec![group.clone()].into_boxed_slice())),
          OperationPolicy::Preserve,
        ),
      )]),
      account_pool(None),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream(ID_LLAMA_CPP, "https://upstream.example/v1/", &["account"], &[]),
      )]),
      BTreeMap::from([(group, fallback_group(&[("upstream", "gpt-4o")]))]),
    );
    let routes = link(&gateway, &[account("account", ID_LLAMA_CPP, AccountTier::Active)]);
    let route = managed(&routes, "managed");
    warm(route, "upstream", &["gpt-4o"]);

    assert!(matches!(
      resolve_managed_target(route, "gpt-4", Endpoint::ChatCompletions, None, |_| true).unwrap(),
      TargetResolution::NoEligible {
        reason: NoEligibleReason::ModelSelectorNoMatch { .. }
      }
    ));
    let exact =
      selected_managed(resolve_managed_target(route, "gpt-4o", Endpoint::ChatCompletions, None, |_| true).unwrap());
    assert_eq!(exact.model(), "gpt-4o");
  }

  #[test]
  fn relay_uses_configured_target_or_origin_derived_only_from_typed_ingress() {
    let gateway = gateway(
      BTreeMap::from([
        (route_id("fixed"), fixed_relay("upstream")),
        (route_id("origin"), origin_relay()),
      ]),
      account_pool(None),
      BTreeMap::from([(
        upstream_id("upstream"),
        upstream(
          ID_LLAMA_CPP,
          "https://base.example/v1/",
          &["account"],
          &["https://origin.example"],
        ),
      )]),
      BTreeMap::new(),
    );
    let routes = link(&gateway, &[account("account", ID_LLAMA_CPP, AccountTier::Active)]);
    let ingress = HttpIngress::direct(HttpScheme::Https, CanonicalAuthority::parse("origin.example").unwrap());

    let fixed = selected_relay(resolve_relay_target(relay(&routes, "fixed"), &ingress, None, |_| true));
    let RelayDestination::Configured(target) = fixed.destination() else {
      panic!("expected configured relay destination");
    };
    assert_eq!(target.base_url().as_str(), "https://base.example/v1/");

    let original = selected_relay(resolve_relay_target(relay(&routes, "origin"), &ingress, None, |_| true));
    let RelayDestination::Original(origin) = original.destination() else {
      panic!("expected original relay destination");
    };
    assert_eq!(origin.as_str(), "https://origin.example");

    let unmapped = HttpIngress::direct(
      HttpScheme::Https,
      CanonicalAuthority::parse("unmapped.example").unwrap(),
    );
    assert!(matches!(
      resolve_relay_target(relay(&routes, "origin"), &unmapped, None, |_| true),
      TargetResolution::NoEligible {
        reason: NoEligibleReason::OriginNotConfigured { .. }
      }
    ));
  }
}

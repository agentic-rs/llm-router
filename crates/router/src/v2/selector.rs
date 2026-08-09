use async_trait::async_trait;
use smol_str::SmolStr;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokn_accounts::link::{AccountPoolRuntime, AccountPoolRuntimes, PoolAcquire, ProviderBinding};
use tokn_accounts::AccountHandle;
use tokn_core::provider::Endpoint;
use tokn_policy::{
  AccountPoolId, FallbackSelector, GatewayPlan, ManagedRoute, ModelSelector, OperationPolicy, ProviderId,
  QualificationNamespace, RelayRoute, RelayTarget, RouteId, RoutePlan, UpstreamId, UpstreamSelector,
};
use tokn_requests::event::Stage;
use tokn_requests::pipeline::ctx::PipelineCtx;
use tokn_requests::pipeline::error::{PipelineError, RequestsError};
use tokn_requests::pipeline::stages::{BuiltHeaders, ConvertedRequest, Extracted, Resolved, SendStage, SentResponse};
use tokn_requests::stages::{AccountSelector, DefaultSend, SelectorOutcome, ACCESS_ALLOWED_PROVIDERS_KEY};

const BUILTIN_OPERATION_ORDER: [Endpoint; 3] = [Endpoint::ChatCompletions, Endpoint::Responses, Endpoint::Messages];

pub(super) struct SelectionState {
  pool: Arc<AccountPoolRuntime>,
  bindings: Box<[Arc<ProviderBinding>]>,
}

impl SelectionState {
  fn new(pool: Arc<AccountPoolRuntime>) -> Self {
    let bindings = pool
      .pool()
      .active()
      .iter()
      .chain(pool.pool().fallback())
      .flat_map(|account| account.bindings().values().cloned())
      .collect::<Vec<_>>()
      .into_boxed_slice();
    Self { pool, bindings }
  }

  fn binding_for_handle(&self, handle: &Arc<AccountHandle>) -> Option<&Arc<ProviderBinding>> {
    self
      .bindings
      .iter()
      .find(|binding| Arc::ptr_eq(binding.handle(), handle))
  }
}

pub(super) struct V2AccountSelector {
  plan: Arc<GatewayPlan>,
  route_id: RouteId,
  state: Arc<SelectionState>,
}

impl V2AccountSelector {
  pub(super) fn new(
    plan: Arc<GatewayPlan>,
    route_id: RouteId,
    pools: &AccountPoolRuntimes,
  ) -> anyhow::Result<(Self, Arc<SelectionState>)> {
    let route = plan
      .route(&route_id)
      .ok_or_else(|| anyhow::anyhow!("profile references missing route '{route_id}'"))?;
    let pool_id = route_pool(route).ok_or_else(|| {
      anyhow::anyhow!("route '{route_id}' requires an original destination and cannot run on an LLM API listener")
    })?;
    let pool = pools
      .runtime(pool_id)
      .cloned()
      .ok_or_else(|| anyhow::anyhow!("route '{route_id}' references missing account pool '{pool_id}'"))?;
    let state = Arc::new(SelectionState::new(pool));
    Ok((
      Self {
        plan,
        route_id,
        state: state.clone(),
      },
      state,
    ))
  }

  fn route(&self) -> &RoutePlan {
    self
      .plan
      .route(&self.route_id)
      .expect("v2 selector route was validated during construction")
  }

  fn select_managed(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    route: &ManagedRoute,
  ) -> Result<SelectorOutcome, PipelineError> {
    let endpoint = resolved_endpoint(ctx)?;
    let allowed = allowed_provider_ids(ctx)?;
    let candidates = model_candidates(&self.plan, route, extracted.model.as_str())?;
    let operations = operation_candidates(route.operation(), endpoint);
    let mut denied = false;

    for candidate in candidates {
      for operation in operations.iter().copied() {
        denied |= self.state.bindings.iter().any(|binding| {
          managed_binding_matches(&self.plan, route, &candidate, operation, binding)
            && !provider_allowed(binding.provider().info().id.as_str(), allowed.as_ref())
        });
        match self.state.pool.acquire(extracted.session_id.as_deref(), |binding| {
          managed_binding_matches(&self.plan, route, &candidate, operation, binding)
            && provider_allowed(binding.provider().info().id.as_str(), allowed.as_ref())
        }) {
          PoolAcquire::Selected(binding) => {
            return Ok(selected(binding, operation, candidate.model.clone()));
          }
          PoolAcquire::CoolingDown { .. } | PoolAcquire::NoEligible => {}
        }
      }
    }

    if denied {
      Ok(SelectorOutcome::ProviderAccessDenied)
    } else {
      Ok(SelectorOutcome::NoAccount)
    }
  }

  fn select_relay(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    route: &RelayRoute,
  ) -> Result<SelectorOutcome, PipelineError> {
    let endpoint = resolved_endpoint(ctx)?;
    let RelayTarget::FixedUpstream { upstream, .. } = route.target() else {
      return Err(invalid_route_request(
        "origin-based relay cannot run on an LLM API listener",
      ));
    };
    let allowed = allowed_provider_ids(ctx)?;
    let provider_id = self
      .plan
      .upstream(upstream)
      .expect("compiled route upstream must exist")
      .provider();
    if !provider_allowed(provider_id.as_str(), allowed.as_ref()) {
      return Ok(SelectorOutcome::ProviderAccessDenied);
    }
    Ok(
      match self.state.pool.acquire(extracted.session_id.as_deref(), |binding| {
        binding.upstream_id() == upstream
      }) {
        PoolAcquire::Selected(binding) => selected(binding, endpoint, extracted.model.clone()),
        PoolAcquire::CoolingDown { .. } | PoolAcquire::NoEligible => SelectorOutcome::NoAccount,
      },
    )
  }
}

#[async_trait]
impl AccountSelector for V2AccountSelector {
  async fn select(&self, ctx: &PipelineCtx, extracted: &Extracted) -> Result<SelectorOutcome, PipelineError> {
    match self.route() {
      RoutePlan::Managed(route) => self.select_managed(ctx, extracted, route),
      RoutePlan::Relay(route) => self.select_relay(ctx, extracted, route),
      RoutePlan::Transparent(_) => Err(invalid_route_request(
        "transparent routes cannot run on an LLM API listener",
      )),
    }
  }
}

pub(super) struct PoolAwareSend {
  inner: DefaultSend,
  state: Arc<SelectionState>,
}

impl PoolAwareSend {
  pub(super) fn new(http: reqwest::Client, state: Arc<SelectionState>) -> Self {
    Self {
      inner: DefaultSend::new(http),
      state,
    }
  }
}

#[async_trait]
impl SendStage for PoolAwareSend {
  async fn send(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
    headers: &BuiltHeaders,
    body: &ConvertedRequest,
  ) -> Result<SentResponse, PipelineError> {
    let binding = self
      .state
      .binding_for_handle(&resolved.account_handle)
      .ok_or_else(|| invalid_route_request("selected account is not a member of the route's v2 account pool"))?;
    let result = self.inner.send(ctx, extracted, resolved, headers, body).await;
    match &result {
      Ok(_) => {
        self
          .state
          .pool
          .record_success(extracted.session_id.as_deref(), binding.key())
          .map_err(|error| invalid_route_request(error.to_string()))?;
      }
      Err(error) if error.recoverable => {
        self
          .state
          .pool
          .record_failure(binding.key())
          .map_err(|error| invalid_route_request(error.to_string()))?;
      }
      Err(_) => {}
    }
    result
  }
}

fn route_pool(route: &RoutePlan) -> Option<&AccountPoolId> {
  match route {
    RoutePlan::Managed(route) => Some(route.target().account_pool()),
    RoutePlan::Relay(route) => match route.target() {
      RelayTarget::FixedUpstream { account_pool, .. } => Some(account_pool),
      RelayTarget::UpstreamFromOrigin { .. } => None,
    },
    RoutePlan::Transparent(_) => None,
  }
}

fn selected(binding: Arc<ProviderBinding>, operation: Endpoint, model: SmolStr) -> SelectorOutcome {
  SelectorOutcome::Selected {
    account_id: SmolStr::new(binding.account_id()),
    provider_id: SmolStr::new(binding.provider().info().id.as_str()),
    upstream_endpoint: Some(operation),
    upstream_model: model,
    account_handle: binding.handle().clone(),
  }
}

#[derive(Clone)]
struct ModelCandidate {
  model: SmolStr,
  constraint: UpstreamConstraint,
}

#[derive(Clone)]
enum UpstreamConstraint {
  Any,
  Provider(ProviderId),
  Upstream(UpstreamId),
  OneOf(Box<[UpstreamId]>),
}

impl UpstreamConstraint {
  fn matches(&self, plan: &GatewayPlan, upstream_id: &UpstreamId) -> bool {
    match self {
      Self::Any => true,
      Self::Provider(provider) => plan
        .upstream(upstream_id)
        .is_some_and(|upstream| upstream.provider() == provider),
      Self::Upstream(expected) => upstream_id == expected,
      Self::OneOf(upstreams) => upstreams.binary_search(upstream_id).is_ok(),
    }
  }
}

fn model_candidates(
  plan: &GatewayPlan,
  route: &ManagedRoute,
  requested_model: &str,
) -> Result<Vec<ModelCandidate>, PipelineError> {
  match route.target().model() {
    ModelSelector::Capability => Ok(vec![ModelCandidate {
      model: SmolStr::new(requested_model),
      constraint: UpstreamConstraint::Any,
    }]),
    ModelSelector::Qualified { namespace } => {
      let (qualifier, model) = requested_model.split_once('/').ok_or_else(|| {
        invalid_route_request(format!(
          "{}-qualified model must use '<qualifier>/<model>'",
          qualification_name(*namespace)
        ))
      })?;
      if model.is_empty() || model.trim() != model {
        return Err(invalid_route_request("qualified model name is empty or non-canonical"));
      }
      let constraint = match namespace {
        QualificationNamespace::Provider => UpstreamConstraint::Provider(
          ProviderId::new(qualifier).map_err(|error| invalid_route_request(error.to_string()))?,
        ),
        QualificationNamespace::Upstream => UpstreamConstraint::Upstream(
          UpstreamId::new(qualifier).map_err(|error| invalid_route_request(error.to_string()))?,
        ),
      };
      Ok(vec![ModelCandidate {
        model: SmolStr::new(model),
        constraint,
      }])
    }
    ModelSelector::Fallback(selector) => {
      let group_ids: Vec<_> = match selector {
        FallbackSelector::Fixed(group) => vec![group],
        FallbackSelector::ByRequested(groups) => groups
          .iter()
          .find(|group_id| {
            group_id.as_str() == requested_model
              || plan.model_group(group_id).is_some_and(|group| {
                group
                  .candidates()
                  .iter()
                  .any(|candidate| candidate.model() == requested_model)
              })
          })
          .into_iter()
          .collect(),
      };
      let mut candidates = Vec::new();
      for group_id in group_ids {
        let group = plan.model_group(group_id).expect("compiled fallback group must exist");
        for candidate in group.candidates() {
          let upstreams = match candidate.upstream() {
            Some(upstream) => vec![upstream.clone()],
            None => route_upstream_ids(plan, route.target().upstream()),
          };
          candidates.push(ModelCandidate {
            model: SmolStr::new(candidate.model()),
            constraint: UpstreamConstraint::OneOf(upstreams.into_boxed_slice()),
          });
        }
      }
      Ok(candidates)
    }
  }
}

fn route_upstream_ids(plan: &GatewayPlan, selector: &UpstreamSelector) -> Vec<UpstreamId> {
  match selector {
    UpstreamSelector::Any => plan.upstreams().keys().cloned().collect(),
    UpstreamSelector::Fixed(upstream) => vec![upstream.clone()],
  }
}

fn managed_binding_matches(
  plan: &GatewayPlan,
  route: &ManagedRoute,
  candidate: &ModelCandidate,
  operation: Endpoint,
  binding: &ProviderBinding,
) -> bool {
  let route_upstream_matches = match route.target().upstream() {
    UpstreamSelector::Any => true,
    UpstreamSelector::Fixed(upstream) => binding.upstream_id() == upstream,
  };
  route_upstream_matches
    && candidate.constraint.matches(plan, binding.upstream_id())
    && binding.provider().supports(candidate.model.as_str(), operation)
}

fn operation_candidates(policy: OperationPolicy, requested: Endpoint) -> Vec<Endpoint> {
  if policy == OperationPolicy::Preserve {
    return vec![requested];
  }
  std::iter::once(requested)
    .chain(
      BUILTIN_OPERATION_ORDER
        .into_iter()
        .filter(|operation| *operation != requested),
    )
    .collect()
}

fn provider_allowed(provider_id: &str, allowed: Option<&BTreeSet<String>>) -> bool {
  allowed.is_none_or(|providers| providers.contains(provider_id))
}

fn allowed_provider_ids(ctx: &PipelineCtx) -> Result<Option<BTreeSet<String>>, PipelineError> {
  let Some(value) = ctx.config.get(ACCESS_ALLOWED_PROVIDERS_KEY) else {
    return Ok(None);
  };
  let Some(values) = value.as_array() else {
    return Err(PipelineError::permanent(
      Stage::Resolve,
      RequestsError::InvalidAccessPolicy,
    ));
  };
  values
    .iter()
    .map(|value| value.as_str().map(str::to_string))
    .collect::<Option<BTreeSet<_>>>()
    .map(Some)
    .ok_or_else(|| PipelineError::permanent(Stage::Resolve, RequestsError::InvalidAccessPolicy))
}

fn resolved_endpoint(ctx: &PipelineCtx) -> Result<Endpoint, PipelineError> {
  ctx.request_endpoint.resolved().ok_or_else(|| {
    PipelineError::permanent(
      Stage::Resolve,
      RequestsError::MissingResolvedEndpoint {
        request_endpoint: SmolStr::new(ctx.request_endpoint.as_str()),
      },
    )
  })
}

fn qualification_name(namespace: QualificationNamespace) -> &'static str {
  match namespace {
    QualificationNamespace::Provider => "provider",
    QualificationNamespace::Upstream => "upstream",
  }
}

fn invalid_route_request(message: impl Into<String>) -> PipelineError {
  PipelineError::permanent(
    Stage::Resolve,
    RequestsError::InvalidRouteRequest {
      message: SmolStr::new(message.into()),
    },
  )
}

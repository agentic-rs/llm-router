//! Site-free managed-profile target resolution.
//!
//! This layer resolves an already linked profile without depending on an HTTP
//! listener or request admission site. It owns the selected account token and
//! the post-selection wire identity so every caller observes the same managed
//! routing invariants.

use super::{LinkedProfile, LinkedWireIdentity};
use smol_str::SmolStr;
use snafu::Snafu;
use std::fmt;
use tokn_access::ProviderAccess;
use tokn_accounts::link::{
  resolve_managed_target, LinkedRouteKind, PoolRuntimeResult, SelectedManagedTarget, SelectionOutcome,
  SelectionSettlement, TargetResolution, TargetResolveError,
};
use tokn_core::provider::Endpoint;
use tokn_core::AgentId;
use tokn_policy::{ProfileId, ProviderId, RouteId, RouteKind};

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
    write!(
      formatter,
      "managed profile '{}' route '{}'",
      self.profile_id, self.route_id
    )
  }
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

  pub(crate) fn settle(self, outcome: SelectionOutcome) -> PoolRuntimeResult<SelectionSettlement> {
    self.target.into_selection_token().settle(outcome)
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
  let site = ManagedProfileSite::from_profile(profile);
  let LinkedRouteKind::Managed(route) = profile.route().kind() else {
    return Err(ManagedProfileResolveError::NonManagedRoute {
      site,
      route_kind: profile.route().route_kind(),
    });
  };
  let resolution = resolve_managed_target(
    route,
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

  #[test]
  fn selects_managed_target_with_exact_site_semantics_and_identity() {
    let runtime = managed_runtime(ModelSelector::Capability, WireIdentity::ProviderDefault);
    let resolution = resolve_managed_profile(
      managed_profile(&runtime),
      SmolStr::new("requested-model"),
      Endpoint::ChatCompletions,
      Some("session"),
      &ProviderAccess::All,
    )
    .unwrap();
    let TargetResolution::Selected(target) = resolution else {
      panic!("expected selected managed target, got {resolution:?}");
    };

    assert_eq!(target.site().profile_id().as_str(), "managed-profile");
    assert_eq!(target.site().route_id().as_str(), "managed-route");
    assert_eq!(
      target.site().to_string(),
      "managed profile 'managed-profile' route 'managed-route'"
    );
    assert_eq!(target.requested_model(), "requested-model");
    assert_eq!(target.requested_operation(), Endpoint::ChatCompletions);
    assert_eq!(target.target().model(), "requested-model");
    assert_eq!(target.target().operation(), Endpoint::ChatCompletions);
    assert_eq!(target.wire_identity(), Some(&AgentId::Opencode));
    assert_eq!(target.target().selection_token().key().account_id(), "account");
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

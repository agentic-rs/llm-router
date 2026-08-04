use crate::{AccountPoolId, HeaderPatchSetId, ModelGroupId, RetryPolicyId, RouteId, UpstreamId, WireIdentityId};

/// The three coherent request-handling families supported by the gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteKind {
  /// Decode a supported LLM request, select a managed account, and allow
  /// request/response translation.
  Managed,
  /// Preserve payload bytes while selecting a managed account and replacing
  /// client credentials.
  Relay,
  /// Preserve the original destination, payload, headers, and credentials.
  Transparent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadTransform {
  Structured,
  Opaque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPolicy {
  Account,
  Client,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationPolicy {
  SelectedUpstream,
  Original,
}

/// Whether a managed route preserves the inbound operation or may translate
/// between compatible API operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPolicy {
  Preserve,
  TranslateCompatible,
}

/// Base header behavior derived from the route family and destination.
/// Optional patch sets may add safe, non-structural changes after this step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderStrategy {
  ProviderOwned,
  CrossOriginSanitize,
  SameOriginReplaceCredentials,
  SameOriginForward,
}

/// Namespace accepted before the slash in a qualified model name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationNamespace {
  /// Match a provider implementation, which may have multiple configured
  /// upstream instances.
  Provider,
  /// Match one configured upstream instance exactly.
  Upstream,
}

/// How an ordered model fallback group is chosen for a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FallbackSelector {
  /// Use one group for every request handled by the route.
  Fixed(ModelGroupId),
  /// Find the first listed group whose name or members contain the requested
  /// model. This is the explicit replacement for legacy fuzzy routing.
  ByRequested(Box<[ModelGroupId]>),
}

/// How a managed route interprets the requested model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelSelector {
  /// Select an account whose upstream advertises the requested model.
  Capability,
  /// Parse a qualified model and constrain selection to its namespace.
  Qualified { namespace: QualificationNamespace },
  /// Resolve to an ordered candidate list and use the actual chosen candidate
  /// as the outbound model.
  Fallback(FallbackSelector),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpstreamSelector {
  /// Select from explicitly configured upstreams compatible with the route's
  /// account pool. Provider catalogue defaults are resolved for those
  /// upstreams during runtime linking; they do not create implicit entries.
  ///
  /// The account-pool strategy chooses an account first. Compatible upstreams
  /// for that account are then considered in typed upstream-id order as
  /// deterministic failover, not as an implicit load-balancing policy.
  Any,
  Fixed(UpstreamId),
}

/// Managed selection keeps its three inputs together so a fixed upstream does
/// not accidentally discard model-selection behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedTarget {
  account_pool: AccountPoolId,
  upstream: UpstreamSelector,
  model: ModelSelector,
}

impl ManagedTarget {
  pub fn new(account_pool: AccountPoolId, upstream: UpstreamSelector, model: ModelSelector) -> Self {
    Self {
      account_pool,
      upstream,
      model,
    }
  }

  pub fn account_pool(&self) -> &AccountPoolId {
    &self.account_pool
  }

  pub fn upstream(&self) -> &UpstreamSelector {
    &self.upstream
  }

  pub fn model(&self) -> &ModelSelector {
    &self.model
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayTarget {
  /// Match the original request authority to an upstream for account
  /// selection while preserving the original destination.
  UpstreamFromOrigin { account_pool: AccountPoolId },
  /// Send to a configured upstream instead of the inbound destination.
  FixedUpstream {
    upstream: UpstreamId,
    account_pool: AccountPoolId,
  },
}

impl RelayTarget {
  pub fn account_pool(&self) -> &AccountPoolId {
    match self {
      Self::UpstreamFromOrigin { account_pool } | Self::FixedUpstream { account_pool, .. } => account_pool,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedRetry {
  Never,
  Recoverable(RetryPolicyId),
}

/// Retrying an opaque request requires an explicit replay-safety choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayRetry {
  Never,
  SafeMethods(RetryPolicyId),
  Buffered(RetryPolicyId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireIdentity {
  None,
  ProviderDefault,
  Named(WireIdentityId),
}

/// A managed route always uses structured request handling and account-owned
/// credentials. The target makes its account pool explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRoute {
  target: ManagedTarget,
  operation: OperationPolicy,
  header_patches: Option<HeaderPatchSetId>,
  retry: ManagedRetry,
}

impl ManagedRoute {
  pub fn new(
    target: ManagedTarget,
    operation: OperationPolicy,
    header_patches: Option<HeaderPatchSetId>,
    retry: ManagedRetry,
  ) -> Self {
    Self {
      target,
      operation,
      header_patches,
      retry,
    }
  }

  pub fn target(&self) -> &ManagedTarget {
    &self.target
  }

  pub fn operation(&self) -> OperationPolicy {
    self.operation
  }

  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    self.header_patches.as_ref()
  }

  pub fn retry(&self) -> &ManagedRetry {
    &self.retry
  }
}

/// A relay route keeps the payload opaque while selecting managed account
/// credentials for either a fixed upstream or one detected from the origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRoute {
  target: RelayTarget,
  header_patches: Option<HeaderPatchSetId>,
  retry: RelayRetry,
}

impl RelayRoute {
  pub fn new(target: RelayTarget, header_patches: Option<HeaderPatchSetId>, retry: RelayRetry) -> Self {
    Self {
      target,
      header_patches,
      retry,
    }
  }

  pub fn target(&self) -> &RelayTarget {
    &self.target
  }

  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    self.header_patches.as_ref()
  }

  pub fn retry(&self) -> &RelayRetry {
    &self.retry
  }
}

/// Transparent routes cannot name an account pool, retry policy, or alternate
/// destination. Those omissions are intentional security invariants.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransparentRoute {
  header_patches: Option<HeaderPatchSetId>,
}

impl TransparentRoute {
  pub fn new(header_patches: Option<HeaderPatchSetId>) -> Self {
    Self { header_patches }
  }

  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    self.header_patches.as_ref()
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutePlan {
  Managed(ManagedRoute),
  Relay(RelayRoute),
  Transparent(TransparentRoute),
}

impl RoutePlan {
  pub fn kind(&self) -> RouteKind {
    match self {
      Self::Managed(_) => RouteKind::Managed,
      Self::Relay(_) => RouteKind::Relay,
      Self::Transparent(_) => RouteKind::Transparent,
    }
  }

  pub fn request_transform(&self) -> PayloadTransform {
    match self {
      Self::Managed(_) => PayloadTransform::Structured,
      Self::Relay(_) | Self::Transparent(_) => PayloadTransform::Opaque,
    }
  }

  pub fn response_transform(&self) -> PayloadTransform {
    self.request_transform()
  }

  pub fn credential_policy(&self) -> CredentialPolicy {
    match self {
      Self::Managed(_) | Self::Relay(_) => CredentialPolicy::Account,
      Self::Transparent(_) => CredentialPolicy::Client,
    }
  }

  pub fn destination_policy(&self) -> DestinationPolicy {
    match self {
      Self::Managed(_)
      | Self::Relay(RelayRoute {
        target: RelayTarget::FixedUpstream { .. },
        ..
      }) => DestinationPolicy::SelectedUpstream,
      Self::Relay(RelayRoute {
        target: RelayTarget::UpstreamFromOrigin { .. },
        ..
      })
      | Self::Transparent(_) => DestinationPolicy::Original,
    }
  }

  pub fn operation_policy(&self) -> OperationPolicy {
    match self {
      Self::Managed(route) => route.operation(),
      Self::Relay(_) | Self::Transparent(_) => OperationPolicy::Preserve,
    }
  }

  pub fn header_strategy(&self) -> HeaderStrategy {
    match self {
      Self::Managed(_) => HeaderStrategy::ProviderOwned,
      Self::Relay(RelayRoute {
        target: RelayTarget::FixedUpstream { .. },
        ..
      }) => HeaderStrategy::CrossOriginSanitize,
      Self::Relay(RelayRoute {
        target: RelayTarget::UpstreamFromOrigin { .. },
        ..
      }) => HeaderStrategy::SameOriginReplaceCredentials,
      Self::Transparent(_) => HeaderStrategy::SameOriginForward,
    }
  }

  pub fn header_patches(&self) -> Option<&HeaderPatchSetId> {
    match self {
      Self::Managed(route) => route.header_patches(),
      Self::Relay(route) => route.header_patches(),
      Self::Transparent(route) => route.header_patches(),
    }
  }
}

/// A client-facing profile is intentionally limited to a route reference and
/// wire identity. Routing filters and account selection belong to the route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePlan {
  route: RouteId,
  wire_identity: WireIdentity,
}

impl ProfilePlan {
  pub fn new(route: RouteId, wire_identity: WireIdentity) -> Self {
    Self { route, wire_identity }
  }

  pub fn route(&self) -> &RouteId {
    &self.route
  }

  pub fn wire_identity(&self) -> &WireIdentity {
    &self.wire_identity
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn id<T>(value: &str) -> T
  where
    T: TryFrom<String>,
    T::Error: std::fmt::Debug,
  {
    T::try_from(value.to_string()).unwrap()
  }

  #[test]
  fn managed_route_exposes_structured_account_owned_axes() {
    let route = RoutePlan::Managed(ManagedRoute::new(
      ManagedTarget::new(id("default"), UpstreamSelector::Any, ModelSelector::Capability),
      OperationPolicy::TranslateCompatible,
      None,
      ManagedRetry::Recoverable(id("standard")),
    ));

    assert_eq!(route.kind(), RouteKind::Managed);
    assert_eq!(route.request_transform(), PayloadTransform::Structured);
    assert_eq!(route.response_transform(), PayloadTransform::Structured);
    assert_eq!(route.credential_policy(), CredentialPolicy::Account);
    assert_eq!(route.destination_policy(), DestinationPolicy::SelectedUpstream);
    assert_eq!(route.operation_policy(), OperationPolicy::TranslateCompatible);
    assert_eq!(route.header_strategy(), HeaderStrategy::ProviderOwned);
  }

  #[test]
  fn fixed_relay_exposes_cross_origin_account_owned_axes() {
    let route = RoutePlan::Relay(RelayRoute::new(
      RelayTarget::FixedUpstream {
        upstream: id("openai-public"),
        account_pool: id("default"),
      },
      None,
      RelayRetry::Never,
    ));

    assert_eq!(route.kind(), RouteKind::Relay);
    assert_eq!(route.request_transform(), PayloadTransform::Opaque);
    assert_eq!(route.credential_policy(), CredentialPolicy::Account);
    assert_eq!(route.destination_policy(), DestinationPolicy::SelectedUpstream);
    assert_eq!(route.operation_policy(), OperationPolicy::Preserve);
    assert_eq!(route.header_strategy(), HeaderStrategy::CrossOriginSanitize);
  }

  #[test]
  fn origin_relay_preserves_destination_and_replaces_credentials() {
    let route = RoutePlan::Relay(RelayRoute::new(
      RelayTarget::UpstreamFromOrigin {
        account_pool: id("default"),
      },
      None,
      RelayRetry::SafeMethods(id("conservative")),
    ));

    assert_eq!(route.destination_policy(), DestinationPolicy::Original);
    assert_eq!(route.header_strategy(), HeaderStrategy::SameOriginReplaceCredentials);
  }

  #[test]
  fn transparent_route_exposes_only_original_client_axes() {
    let route = RoutePlan::Transparent(TransparentRoute::default());

    assert_eq!(route.kind(), RouteKind::Transparent);
    assert_eq!(route.request_transform(), PayloadTransform::Opaque);
    assert_eq!(route.credential_policy(), CredentialPolicy::Client);
    assert_eq!(route.destination_policy(), DestinationPolicy::Original);
    assert_eq!(route.operation_policy(), OperationPolicy::Preserve);
    assert_eq!(route.header_strategy(), HeaderStrategy::SameOriginForward);
  }

  #[test]
  fn fallback_by_requested_is_explicit() {
    let selector = ModelSelector::Fallback(FallbackSelector::ByRequested(
      vec![id("claude"), id("gpt")].into_boxed_slice(),
    ));

    assert_eq!(
      selector,
      ModelSelector::Fallback(FallbackSelector::ByRequested(
        vec![id("claude"), id("gpt")].into_boxed_slice()
      ))
    );
  }

  #[test]
  fn profile_contains_only_route_and_wire_identity() {
    let profile = ProfilePlan::new(id("coding"), WireIdentity::Named(id("codex-cli")));
    assert_eq!(profile.route().as_str(), "coding");
    assert_eq!(profile.wire_identity(), &WireIdentity::Named(id("codex-cli")));
  }
}

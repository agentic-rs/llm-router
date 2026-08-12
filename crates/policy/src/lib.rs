//! Dependency-light request policy types shared by configuration and runtime crates.
//!
//! This crate deliberately contains no configuration-file representation and no
//! request execution code. Configuration compilers produce these values, while
//! runtime crates consume them without depending on TOML shape or compatibility
//! aliases.

mod authority;
mod id;
mod route;
mod topology;

pub use authority::{
  AuthorityMismatch, CanonicalAuthority, CanonicalHost, IngressAuthority, IngressAuthoritySource, InvalidAuthority,
  InvalidHost, ResolvedAuthority,
};
pub use id::{
  AccountPoolId, BindingId, DriverId, HeaderPatchSetId, InvalidIdentifier, ListenerId, ModelGroupId, OperationId,
  ProfileId, ProviderId, RetryPolicyId, RouteId, WireIdentityId,
};
pub use route::{
  CredentialPolicy, DestinationPolicy, FallbackSelector, HeaderStrategy, ManagedRetry, ManagedRoute, ManagedTarget,
  ModelSelector, OperationPolicy, PayloadTransform, ProfilePlan, ProviderSelector, QualificationNamespace, RelayRetry,
  RelayRoute, RelayTarget, RouteKind, RoutePlan, WireIdentity,
};
pub use topology::{
  AccountPoolPlan, AccountSelectionStrategy, AccountSelector, ClientAuthPlan, ConnectAction, ConnectMatch,
  ConnectRulePlan, EmptyConnectMatch, EmptyHttpMatch, ForwardProxyListenerPlan, GatewayPlan, HostPattern, HttpAction,
  HttpBindingPlan, HttpMatch, InvalidSubdomainSuffix, ListenerKind, ListenerPlan, LlmApiListenerPlan, ModelCandidate,
  ModelGroupPlan, ProviderOrigin, ProviderPlan, SessionAffinityPlan, TlsPlan,
  DEFAULT_FORWARD_PROXY_REQUEST_BODY_MAX_BYTES,
};

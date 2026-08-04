//! `tokn-auth` — provider-agnostic account auth orchestration.
//!
//! This crate owns:
//! * The [`ProviderAuth`] trait and its companion lifecycle types
//!   ([`DeviceFlowOutcome`], [`RefreshOutcome`], [`QuotaSnapshot`],
//!   [`AuthError`]). Provider crates implement this trait; everything
//!   above the provider layer programs against it.
//! * The [`AuthStore`] backing `auth.yaml` — the latest home for account
//!   records. Legacy schema conversion from `config.toml` lives in
//!   `tokn-router-legacy-config`.
//!
//! Note: the provider-id → [`ProviderAuth`] *registry* deliberately does
//! **not** live here. `tokn-auth` is the bottom of the auth stack and must
//! not depend on any provider crate (cycle-free). The dispatch table
//! lives in the consumer that already pulls in every provider — currently
//! `gateway-cli::auth_registry`.

pub mod descriptor;
pub mod provider;
pub mod store;

pub use descriptor::{EndpointSpec, PathRewrite, ProviderDescriptor};
pub use provider::{
  default_import_from, AuthError, CredentialFlavor, CredentialResult, CredentialSource, CredentialSourceKind,
  DeviceCodeHandle, DeviceFlowOutcome, MeteredBucket, ProviderAuth, QuotaSnapshot, RefreshOutcome, Result, UsageBucket,
  VerifyOutcome,
};
pub use store::{default_auth_path, AuthSource, AuthStore, AuthStoreLock};
pub use tokn_core::account::{AccountConfig, AccountState, AccountTier};

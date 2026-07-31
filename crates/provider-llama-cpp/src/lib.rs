pub mod auth;
pub mod llama_cpp;

pub use tokn_catalogue as catalogue;
pub use tokn_core::provider::{
  error, AuthKind, Endpoint, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx, Result,
  TemplateVars, ID_LLAMA_CPP,
};
pub use tokn_core::{account as config, provider, util};

pub use llama_cpp::*;

use std::sync::Arc;
use tokn_auth::descriptor::{EndpointSpec, ProviderDescriptor};
use tokn_auth::provider::CredentialFlavor;
use tokn_core::provider::ProviderTarget;

pub static DEFAULT_ENDPOINTS: &[Endpoint] = &[Endpoint::ChatCompletions];

pub static DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
  id: ID_LLAMA_CPP,
  display_name: "llama.cpp",
  hosts: &["localhost", "127.0.0.1", "::1"],
  base_url: llama_cpp::DEFAULT_BASE_URL,
  credentials: &[CredentialFlavor::ApiKey],
  endpoints: &[EndpointSpec {
    endpoint: Endpoint::ChatCompletions,
    method: "POST",
    path: "/v1/chat/completions",
    aliases: &["/chat/completions"],
  }],
  model_endpoint_rules: Some(&[]),
  rewrites: &[],
  auth_urls: &[],
  matches_url,
  validate,
  build,
  build_auth: Some(crate::auth::provider_auth),
};

pub fn matches_url(host: &str, path: &str, _id: &'static str) -> bool {
  DESCRIPTOR.hosts.contains(&host) && (path.is_empty() || path == "/" || path.starts_with("/v1/"))
}

pub fn validate(account: &tokn_core::account::AccountConfig) -> tokn_core::provider::Result<()> {
  llama_cpp::LlamaCppProvider::validate_account(account)
}

pub fn build(
  account: Arc<tokn_core::account::AccountConfig>,
  target: ProviderTarget,
) -> tokn_core::provider::Result<Arc<dyn tokn_core::provider::Provider>> {
  Ok(Arc::new(llama_cpp::LlamaCppProvider::from_account_at(account, target)?))
}

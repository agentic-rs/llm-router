pub mod auth;
pub mod deepseek;

pub use tokn_catalogue as catalogue;
pub use tokn_core::provider::{
  error, AuthKind, Endpoint, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx, Result,
  TemplateVars, ID_DEEPSEEK,
};
pub use tokn_core::{account as config, provider, util};

pub use deepseek::*;

use std::sync::Arc;
use tokn_auth::descriptor::{EndpointSpec, ProviderDescriptor};
use tokn_auth::provider::CredentialFlavor;
use tokn_core::provider::ProviderTarget;

pub static DEFAULT_ENDPOINTS: &[Endpoint] = &[Endpoint::ChatCompletions, Endpoint::Messages];

pub(crate) fn operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  let segments = match endpoint {
    Endpoint::ChatCompletions => &["chat", "completions"][..],
    Endpoint::Messages if target.base_url().as_str().trim_end_matches('/').ends_with("/anthropic") => {
      &["v1", "messages"][..]
    }
    Endpoint::Messages => &["anthropic", "v1", "messages"][..],
    Endpoint::Responses => {
      return Err(error::Error::UnsupportedEndpoint {
        provider: ID_DEEPSEEK.to_string(),
        endpoint: endpoint.as_str(),
      });
    }
  };
  Ok(target.base_url().operation_url(segments.iter().copied())?)
}

pub static DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
  id: ID_DEEPSEEK,
  display_name: "DeepSeek",
  hosts: &["api.deepseek.com"],
  base_url: deepseek::DEFAULT_BASE_URL,
  credentials: &[CredentialFlavor::ApiKey],
  endpoints: &[
    EndpointSpec {
      endpoint: Endpoint::ChatCompletions,
      method: "POST",
      path: "/v1/chat/completions",
      aliases: &["/chat/completions"],
    },
    EndpointSpec {
      endpoint: Endpoint::Messages,
      method: "POST",
      path: "/v1/messages",
      aliases: &["/anthropic/v1/messages"],
    },
  ],
  model_endpoint_rules: Some(&[]),
  operation_url,
  rewrites: &[],
  auth_urls: &[],
  matches_url,
  validate,
  build,
  build_auth: Some(crate::auth::provider_auth),
};

pub fn matches_url(host: &str, _path: &str, _id: &'static str) -> bool {
  DESCRIPTOR.hosts.contains(&host)
}

pub fn validate(account: &tokn_core::account::AccountConfig) -> tokn_core::provider::Result<()> {
  deepseek::DeepSeekProvider::validate_account(account)
}

pub fn build(
  account: Arc<tokn_core::account::AccountConfig>,
  target: ProviderTarget,
) -> tokn_core::provider::Result<Arc<dyn tokn_core::provider::Provider>> {
  Ok(Arc::new(deepseek::DeepSeekProvider::from_account_at(account, target)?))
}

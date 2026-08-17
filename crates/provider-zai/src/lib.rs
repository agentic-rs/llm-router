pub mod auth;
pub mod models;
pub mod quota;
pub mod transform;
pub mod zai;

pub use tokn_catalogue as catalogue;
pub use tokn_core::provider::{
  error, AuthKind, Endpoint, HeaderPatchCtx, ModelInfo, Provider, ProviderInfo, ProviderRequestKind, RequestCtx,
  Result, TemplateVars, ID_ZAI, ID_ZAI_CODING_PLAN, ID_ZHIPUAI, ID_ZHIPUAI_CODING_PLAN, ZAI_PROVIDERS,
};
pub use tokn_core::{account as config, provider, util};

pub use zai::*;

use std::sync::Arc;
use tokn_auth::descriptor::{EndpointSpec, ProviderDescriptor};
use tokn_auth::provider::CredentialFlavor;
use tokn_core::provider::ProviderTarget;

const ZAI_HOSTS: &[&str] = &["api.z.ai"];
const ZHIPU_HOSTS: &[&str] = &["open.bigmodel.cn"];
const CHAT_COMPLETIONS_PATH_PAAS: &str = "/api/paas/v4/chat/completions";
const CHAT_COMPLETIONS_PATH_CODING: &str = "/api/coding/paas/v4/chat/completions";

pub static DEFAULT_ENDPOINTS: &[Endpoint] = &[Endpoint::ChatCompletions];

fn operation_url_for(provider: &str, target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  match endpoint {
    Endpoint::ChatCompletions => Ok(target.base_url().operation_url(["chat", "completions"])?),
    Endpoint::Responses | Endpoint::Messages => Err(error::Error::UnsupportedEndpoint {
      provider: provider.to_string(),
      endpoint: endpoint.as_str(),
    }),
  }
}

pub(crate) fn zai_operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  operation_url_for(ID_ZAI, target, endpoint)
}

fn zai_coding_plan_operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  operation_url_for(ID_ZAI_CODING_PLAN, target, endpoint)
}

fn zhipuai_operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  operation_url_for(ID_ZHIPUAI, target, endpoint)
}

fn zhipuai_coding_plan_operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  operation_url_for(ID_ZHIPUAI_CODING_PLAN, target, endpoint)
}

pub static DESCRIPTOR_ZAI: ProviderDescriptor = ProviderDescriptor {
  id: ID_ZAI,
  display_name: "Z.ai",
  hosts: ZAI_HOSTS,
  base_url: zai::ZAI_BASE_URL,
  credentials: &[CredentialFlavor::ApiKey],
  endpoints: &[EndpointSpec {
    endpoint: Endpoint::ChatCompletions,
    method: "POST",
    path: "/v1/chat/completions",
    aliases: &[CHAT_COMPLETIONS_PATH_PAAS],
  }],
  model_endpoint_rules: Some(&[]),
  operation_url: zai_operation_url,
  rewrites: &[],
  auth_urls: &[],
  matches_url,
  validate,
  build,
  build_auth: Some(crate::auth::zai_auth),
};

pub static DESCRIPTOR_ZAI_CODING_PLAN: ProviderDescriptor = ProviderDescriptor {
  id: ID_ZAI_CODING_PLAN,
  display_name: "Z.ai Coding Plan",
  hosts: ZAI_HOSTS,
  base_url: zai::ZAI_CODING_PLAN_BASE_URL,
  credentials: &[CredentialFlavor::ApiKey],
  endpoints: &[EndpointSpec {
    endpoint: Endpoint::ChatCompletions,
    method: "POST",
    path: "/v1/chat/completions",
    aliases: &[CHAT_COMPLETIONS_PATH_CODING],
  }],
  model_endpoint_rules: Some(&[]),
  operation_url: zai_coding_plan_operation_url,
  rewrites: &[],
  auth_urls: &[],
  matches_url,
  validate,
  build,
  build_auth: Some(crate::auth::zai_coding_plan_auth),
};

pub static DESCRIPTOR_ZHIPUAI: ProviderDescriptor = ProviderDescriptor {
  id: ID_ZHIPUAI,
  display_name: "Zhipu BigModel",
  hosts: ZHIPU_HOSTS,
  base_url: zai::ZHIPUAI_BASE_URL,
  credentials: &[CredentialFlavor::ApiKey],
  endpoints: &[EndpointSpec {
    endpoint: Endpoint::ChatCompletions,
    method: "POST",
    path: "/v1/chat/completions",
    aliases: &[CHAT_COMPLETIONS_PATH_PAAS],
  }],
  model_endpoint_rules: Some(&[]),
  operation_url: zhipuai_operation_url,
  rewrites: &[],
  auth_urls: &[],
  matches_url,
  validate,
  build,
  build_auth: Some(crate::auth::zhipuai_auth),
};

pub static DESCRIPTOR_ZHIPUAI_CODING_PLAN: ProviderDescriptor = ProviderDescriptor {
  id: ID_ZHIPUAI_CODING_PLAN,
  display_name: "Zhipu BigModel Coding Plan",
  hosts: ZHIPU_HOSTS,
  base_url: zai::ZHIPUAI_CODING_PLAN_BASE_URL,
  credentials: &[CredentialFlavor::ApiKey],
  endpoints: &[EndpointSpec {
    endpoint: Endpoint::ChatCompletions,
    method: "POST",
    path: "/v1/chat/completions",
    aliases: &[CHAT_COMPLETIONS_PATH_CODING],
  }],
  model_endpoint_rules: Some(&[]),
  operation_url: zhipuai_coding_plan_operation_url,
  rewrites: &[],
  auth_urls: &[],
  matches_url,
  validate,
  build,
  build_auth: Some(crate::auth::zhipuai_coding_plan_auth),
};

pub fn matches_url(host: &str, path: &str, id: &'static str) -> bool {
  match (host, id) {
    ("api.z.ai", ID_ZAI_CODING_PLAN) => path.starts_with("/api/coding/paas/v4"),
    ("api.z.ai", ID_ZAI) => path.is_empty() || path.starts_with("/api/paas/v4"),
    ("open.bigmodel.cn", ID_ZHIPUAI_CODING_PLAN) => path.starts_with("/api/coding/paas/v4"),
    ("open.bigmodel.cn", ID_ZHIPUAI) => path.is_empty() || path.starts_with("/api/paas/v4"),
    _ => false,
  }
}

pub fn validate(account: &tokn_core::account::AccountConfig) -> tokn_core::provider::Result<()> {
  zai::ZaiProvider::validate_account(account)
}

pub fn build(
  account: Arc<tokn_core::account::AccountConfig>,
  target: ProviderTarget,
) -> tokn_core::provider::Result<Arc<dyn tokn_core::provider::Provider>> {
  Ok(Arc::new(zai::ZaiProvider::from_account_at(account, target)?))
}

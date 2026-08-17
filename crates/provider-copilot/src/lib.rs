pub mod auth;
pub mod github_copilot;
pub mod headers;
pub mod import;
pub mod models;
pub mod oauth;
pub mod token;
pub mod user;

pub mod config;

pub use tokn_catalogue as catalogue;
pub use tokn_core::provider::{
  error, AuthKind, Endpoint, EndpointRule, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx,
  Result, TemplateVars, ID_GITHUB_COPILOT,
};
pub use tokn_core::{provider, util};

pub use github_copilot::*;

use std::sync::Arc;
use tokn_auth::descriptor::{EndpointSpec, ProviderDescriptor};
use tokn_auth::provider::CredentialFlavor;
use tokn_core::provider::ProviderTarget;

pub const COPILOT_BASE_URL: &str = "https://api.githubcopilot.com";
pub const COPILOT_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
pub const COPILOT_ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
pub const COPILOT_TOKEN_EXCHANGE_URL: &str = "https://api.github.com/copilot_internal/v2/token";
pub const COPILOT_USER_INFO_URL: &str = "https://api.github.com/copilot_internal/user";

/// Endpoints Copilot serves; mirrored on `DESCRIPTOR.endpoints` and used
/// to populate `ProviderInfo::default_endpoints`.
pub static DEFAULT_ENDPOINTS: &[Endpoint] = &[Endpoint::ChatCompletions, Endpoint::Responses, Endpoint::Messages];

pub(crate) fn operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  let segments = match endpoint {
    Endpoint::ChatCompletions => &["chat", "completions"][..],
    Endpoint::Responses => &["responses"][..],
    Endpoint::Messages => &["v1", "messages"][..],
  };
  Ok(target.base_url().operation_url(segments.iter().copied())?)
}

/// Per-model endpoint rules. Mirrors what the official Copilot CLI / VSCode
/// plugin route — Copilot ships new ids continuously and `/models` does
/// not annotate per-endpoint support, so we pattern-match the id.
///
/// First match wins: an unmatched model falls back to
/// `DEFAULT_ENDPOINTS` (every endpoint allowed) — optimistic by design.
pub static MODEL_ENDPOINT_RULES: &[EndpointRule] = &[
  EndpointRule {
    pattern: "claude-*",
    endpoints: &[Endpoint::Messages, Endpoint::ChatCompletions],
  },
  EndpointRule {
    pattern: "gpt-5-mini",
    endpoints: &[Endpoint::ChatCompletions, Endpoint::Responses],
  },
  EndpointRule {
    pattern: "gpt-5*",
    endpoints: &[Endpoint::Responses],
  },
  EndpointRule {
    pattern: "o1*",
    endpoints: &[Endpoint::Responses, Endpoint::ChatCompletions],
  },
  EndpointRule {
    pattern: "o3*",
    endpoints: &[Endpoint::Responses, Endpoint::ChatCompletions],
  },
  EndpointRule {
    pattern: "o4*",
    endpoints: &[Endpoint::Responses, Endpoint::ChatCompletions],
  },
];

pub static DESCRIPTOR: ProviderDescriptor = ProviderDescriptor {
  id: ID_GITHUB_COPILOT,
  display_name: "GitHub Copilot",
  hosts: &["api.github.com", "api.githubcopilot.com"],
  base_url: COPILOT_BASE_URL,
  credentials: &[CredentialFlavor::RefreshToken],
  endpoints: &[
    EndpointSpec {
      endpoint: Endpoint::ChatCompletions,
      method: "POST",
      path: "/v1/chat/completions",
      aliases: &[],
    },
    EndpointSpec {
      endpoint: Endpoint::Messages,
      method: "POST",
      path: "/v1/messages",
      aliases: &[],
    },
    EndpointSpec {
      endpoint: Endpoint::Responses,
      method: "POST",
      path: "/v1/responses",
      aliases: &[],
    },
  ],
  model_endpoint_rules: Some(MODEL_ENDPOINT_RULES),
  operation_url,
  rewrites: &[],
  auth_urls: &[
    ("device_authorize", COPILOT_DEVICE_CODE_URL),
    ("device_token", COPILOT_ACCESS_TOKEN_URL),
    ("token_exchange", COPILOT_TOKEN_EXCHANGE_URL),
    ("user_info", COPILOT_USER_INFO_URL),
  ],
  matches_url,
  validate,
  build,
  build_auth: Some(crate::auth::provider_auth),
};

pub fn matches_url(host: &str, _path: &str, _id: &'static str) -> bool {
  DESCRIPTOR.hosts.contains(&host)
}

pub fn validate(account: &tokn_core::account::AccountConfig) -> tokn_core::provider::Result<()> {
  github_copilot::CopilotProvider::validate_account(account)
}

pub fn build(
  account: Arc<tokn_core::account::AccountConfig>,
  target: ProviderTarget,
) -> tokn_core::provider::Result<Arc<dyn tokn_core::provider::Provider>> {
  Ok(Arc::new(github_copilot::CopilotProvider::from_account_at(
    account, target,
  )?))
}

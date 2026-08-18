pub mod auth;
pub mod auth_codex;
pub mod auth_openai;
pub mod codex;
mod common;
pub mod jwt;
pub mod openai;

pub use tokn_catalogue as catalogue;
pub use tokn_core::provider::{
  error, AuthKind, Endpoint, EndpointRule, HeaderPatchCtx, Provider, ProviderInfo, ProviderRequestKind, RequestCtx,
  Result, TemplateVars, ID_CODEX, ID_OPENAI,
};
pub use tokn_core::{account as config, provider, util};

pub use codex::CodexProvider;
pub use openai::OpenAiProvider;

use tokn_auth::descriptor::{EndpointSpec, ProviderDescriptor};
use tokn_auth::provider::CredentialFlavor;
use tokn_core::provider::ProviderTarget;

pub const CODEX_DEVICE_USERCODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
pub const CODEX_DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
pub const CODEX_OAUTH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const CODEX_DEVICE_VERIFY_URL: &str = "https://auth.openai.com/codex/device";
pub const CODEX_DEVICE_REDIRECT_URL: &str = "https://auth.openai.com/deviceauth/callback";

pub static DEFAULT_ENDPOINTS_OPENAI: &[Endpoint] = &[Endpoint::ChatCompletions, Endpoint::Responses];
pub static DEFAULT_ENDPOINTS_CODEX: &[Endpoint] = &[Endpoint::Responses];

pub(crate) fn openai_operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  let segments = match endpoint {
    Endpoint::ChatCompletions => &["chat", "completions"][..],
    Endpoint::Responses => &["responses"][..],
    Endpoint::Messages => return unsupported_operation(ID_OPENAI, endpoint),
  };
  Ok(target.base_url().operation_url(segments.iter().copied())?)
}

pub(crate) fn codex_operation_url(target: &ProviderTarget, endpoint: Endpoint) -> Result<reqwest::Url> {
  match endpoint {
    Endpoint::Responses => Ok(target.base_url().operation_url(["responses"])?),
    Endpoint::ChatCompletions | Endpoint::Messages => unsupported_operation(ID_CODEX, endpoint),
  }
}

fn unsupported_operation(provider: &str, endpoint: Endpoint) -> Result<reqwest::Url> {
  Err(error::Error::UnsupportedEndpoint {
    provider: provider.to_string(),
    endpoint: endpoint.as_str(),
  })
}

pub static DESCRIPTOR_OPENAI: ProviderDescriptor = ProviderDescriptor {
  id: ID_OPENAI,
  display_name: "OpenAI",
  hosts: &["api.openai.com"],
  base_url: openai::OPENAI_BASE_URL,
  credentials: &[CredentialFlavor::ApiKey],
  endpoints: &[
    EndpointSpec {
      endpoint: Endpoint::ChatCompletions,
      method: "POST",
      path: "/v1/chat/completions",
      aliases: &[],
    },
    EndpointSpec {
      endpoint: Endpoint::Responses,
      method: "POST",
      path: "/v1/responses",
      aliases: &[],
    },
  ],
  model_endpoint_rules: Some(&[]),
  operation_url: openai_operation_url,
  rewrites: &[],
  auth_urls: &[],
  matches_url,
  validate: openai::validate,
  build: openai::build,
  build_auth: Some(crate::auth::openai_auth),
};

pub static DESCRIPTOR_CODEX: ProviderDescriptor = ProviderDescriptor {
  id: ID_CODEX,
  display_name: "ChatGPT (Codex)",
  hosts: &["chatgpt.com"],
  base_url: codex::CODEX_BASE_URL,
  credentials: &[CredentialFlavor::RefreshToken, CredentialFlavor::ApiKey],
  endpoints: &[EndpointSpec {
    endpoint: Endpoint::Responses,
    method: "POST",
    path: "/v1/responses",
    aliases: &["/backend-api/codex/responses"],
  }],
  model_endpoint_rules: Some(&[]),
  operation_url: codex_operation_url,
  rewrites: &[],
  auth_urls: &[
    ("device_usercode", CODEX_DEVICE_USERCODE_URL),
    ("device_token", CODEX_DEVICE_TOKEN_URL),
    ("oauth_token", CODEX_OAUTH_TOKEN_URL),
    ("device_verify", CODEX_DEVICE_VERIFY_URL),
    ("device_redirect", CODEX_DEVICE_REDIRECT_URL),
  ],
  matches_url,
  validate: codex::validate,
  build: codex::build,
  build_auth: Some(crate::auth::codex_auth),
};

pub fn matches_url(host: &str, path: &str, id: &'static str) -> bool {
  match (host, id) {
    ("api.openai.com", ID_OPENAI) => true,
    ("chatgpt.com", ID_CODEX) => path.starts_with("/backend-api/codex"),
    _ => false,
  }
}

use crate::util::secret::Secret;
use crate::HeaderPatchCtx;
use tokn_headers::keys::{
  ACCEPT, AUTHORIZATION, CHATGPT_ACCOUNT_ID, CONTENT_ENCODING, CONTENT_TYPE, OPENAI_BETA, ORIGINATOR, SESSION_ID_LOWER,
  USER_AGENT, VERSION, X_CODEX_TURN_METADATA, X_SESSION_AFFINITY,
};
use tokn_headers::{AgentId, HeaderMap, HeaderName, HeaderNormalizeCtx, HeaderNormalizer, HeaderValue};

pub const CODEX_CLI_USER_AGENT: &str = "codex_cli_rs/0.125.0";
pub const CODEX_CLI_VERSION: &str = "0.125.0";
pub const CODEX_RESPONSES_BETA: &str = "responses=experimental";
pub const OPENCODE_USER_AGENT: &str = "opencode/1.14.28 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13";

#[derive(Debug, Clone, Copy, Default)]
pub struct CodexCliNormalizer;

#[derive(Debug, Clone, Copy, Default)]
pub struct CodexOpencodeNormalizer;

pub enum Credential {
  ApiKey(Secret<String>),
  AccessToken(Secret<String>),
}

impl Credential {
  pub fn expose(&self) -> &str {
    match self {
      Credential::ApiKey(secret) | Credential::AccessToken(secret) => secret.expose(),
    }
  }
}

pub fn inject_openai_credentials(headers: &mut HeaderMap, token: &str) {
  headers.insert(&AUTHORIZATION, HeaderValue::from_string(format!("Bearer {token}")));
}

pub fn inject_codex_credentials(headers: &mut HeaderMap, token: &str, provider_account_id: Option<&str>) {
  inject_openai_credentials(headers, token);
  if let Some(account_id) = provider_account_id.filter(|s| !s.trim().is_empty()) {
    headers.insert(&CHATGPT_ACCOUNT_ID, HeaderValue::from_string(account_id.to_string()));
  }
}

pub fn normalize_openai_platform_headers(headers: &HeaderMap, ctx: &HeaderPatchCtx<'_>) -> HeaderMap {
  let authorization = headers.get(&AUTHORIZATION).map(|value| value.as_str().to_string());
  let mut out = HeaderMap::new();
  if let Some(authorization) = authorization {
    out.insert(&AUTHORIZATION, HeaderValue::from_string(authorization));
  }
  out.insert(&ACCEPT, HeaderValue::from_static(accept_value(ctx.stream)));
  out.insert(&CONTENT_TYPE, HeaderValue::from_static("application/json"));
  if let Some(encoding) = ctx.content_encoding {
    out.insert(&CONTENT_ENCODING, HeaderValue::from_string(encoding.to_string()));
  }
  preserve_allowed(headers, &mut out, &[&USER_AGENT]);
  out
}

pub fn normalize_codex_headers(headers: &HeaderMap, ctx: &HeaderPatchCtx<'_>) -> HeaderMap {
  codex_normalizer_for(ctx.agent_id, headers).normalize(
    headers,
    &HeaderNormalizeCtx {
      agent_id: ctx.agent_id,
      stream: ctx.stream,
      content_encoding: ctx.content_encoding,
      vars: ctx.vars,
    },
  )
}

impl HeaderNormalizer for CodexCliNormalizer {
  fn normalize(&self, headers: &HeaderMap, ctx: &HeaderNormalizeCtx<'_>) -> HeaderMap {
    let authorization = first_non_empty(headers, &[AUTHORIZATION.as_str()]).map(str::to_string);
    let chatgpt_account_id = first_non_empty(headers, &[CHATGPT_ACCOUNT_ID.as_str()]).map(str::to_string);
    let originator = first_non_empty(headers, &[ORIGINATOR.as_str()])
      .unwrap_or("codex_cli_rs")
      .to_string();
    let user_agent = first_non_empty(headers, &[USER_AGENT.as_str()])
      .filter(|value| is_codex_user_agent(value))
      .unwrap_or(CODEX_CLI_USER_AGENT)
      .to_string();
    let session_id = session_id(headers, ctx);
    let turn_metadata = first_non_empty(headers, &[X_CODEX_TURN_METADATA.as_str()]).map(str::to_string);

    let mut out = HeaderMap::new();
    if let Some(authorization) = authorization {
      out.insert(&AUTHORIZATION, HeaderValue::from_string(authorization));
    }
    out.insert(&ACCEPT, HeaderValue::from_static(accept_value(ctx.stream)));
    out.insert(&CONTENT_TYPE, HeaderValue::from_static("application/json"));
    out.insert(&OPENAI_BETA, HeaderValue::from_static(CODEX_RESPONSES_BETA));
    out.insert(&ORIGINATOR, HeaderValue::from_string(originator));
    out.insert(&VERSION, HeaderValue::from_static(CODEX_CLI_VERSION));
    out.insert(&USER_AGENT, HeaderValue::from_string(user_agent));
    if let Some(chatgpt_account_id) = chatgpt_account_id {
      out.insert(&CHATGPT_ACCOUNT_ID, HeaderValue::from_string(chatgpt_account_id));
    }
    if let Some(session_id) = session_id {
      out.insert(&SESSION_ID_LOWER, HeaderValue::from_string(session_id));
    }
    if let Some(turn_metadata) = turn_metadata {
      out.insert(&X_CODEX_TURN_METADATA, HeaderValue::from_string(turn_metadata));
    }
    if let Some(encoding) = ctx.content_encoding {
      out.insert(&CONTENT_ENCODING, HeaderValue::from_string(encoding.to_string()));
    }
    out
  }
}

impl HeaderNormalizer for CodexOpencodeNormalizer {
  fn normalize(&self, headers: &HeaderMap, ctx: &HeaderNormalizeCtx<'_>) -> HeaderMap {
    let authorization = first_non_empty(headers, &[AUTHORIZATION.as_str()]).map(str::to_string);
    let chatgpt_account_id = first_non_empty(headers, &[CHATGPT_ACCOUNT_ID.as_str()]).map(str::to_string);
    let session_id = session_id(headers, ctx);
    let session_affinity = session_affinity(headers, ctx, session_id.as_deref());

    let mut out = HeaderMap::new();
    if let Some(authorization) = authorization {
      out.insert(&AUTHORIZATION, HeaderValue::from_string(authorization));
    }
    out.insert(&ACCEPT, HeaderValue::from_static(accept_value(ctx.stream)));
    out.insert(&CONTENT_TYPE, HeaderValue::from_static("application/json"));
    out.insert(&OPENAI_BETA, HeaderValue::from_static(CODEX_RESPONSES_BETA));
    out.insert(&ORIGINATOR, HeaderValue::from_static("opencode"));
    out.insert(&USER_AGENT, HeaderValue::from_static(OPENCODE_USER_AGENT));
    if let Some(chatgpt_account_id) = chatgpt_account_id {
      out.insert(&CHATGPT_ACCOUNT_ID, HeaderValue::from_string(chatgpt_account_id));
    }
    if let Some(session_id) = session_id {
      out.insert(&SESSION_ID_LOWER, HeaderValue::from_string(session_id));
    }
    if let Some(session_affinity) = session_affinity {
      out.insert(&X_SESSION_AFFINITY, HeaderValue::from_string(session_affinity));
    }
    if let Some(encoding) = ctx.content_encoding {
      out.insert(&CONTENT_ENCODING, HeaderValue::from_string(encoding.to_string()));
    }
    out
  }
}

pub fn codex_normalizer_for(agent_id: &AgentId, headers: &HeaderMap) -> &'static dyn HeaderNormalizer {
  match agent_id {
    AgentId::CodexCli => &CodexCliNormalizer,
    AgentId::Opencode => &CodexOpencodeNormalizer,
    _ if first_non_empty(headers, &[X_CODEX_TURN_METADATA.as_str()]).is_some() => &CodexCliNormalizer,
    _ => &CodexOpencodeNormalizer,
  }
}

fn first_non_empty<'a>(headers: &'a HeaderMap, keys: &[&str]) -> Option<&'a str> {
  keys
    .iter()
    .filter_map(|key| headers.get(*key).map(|value| value.as_str().trim()))
    .find(|value| !value.is_empty())
}

fn accept_value(stream: bool) -> &'static str {
  if stream {
    "text/event-stream"
  } else {
    "application/json"
  }
}

fn preserve_allowed(src: &HeaderMap, dst: &mut HeaderMap, allowed: &[&HeaderName]) {
  for key in allowed {
    if let Some(value) = src.get(*key) {
      dst.insert(*key, HeaderValue::from_string(value.as_str().to_string()));
    }
  }
}

fn session_id(headers: &HeaderMap, ctx: &HeaderNormalizeCtx<'_>) -> Option<String> {
  first_non_empty(headers, &[SESSION_ID_LOWER.as_str()])
    .map(str::to_string)
    .or_else(|| ctx.vars.session_id.as_ref().map(ToString::to_string))
}

fn session_affinity(headers: &HeaderMap, ctx: &HeaderNormalizeCtx<'_>, fallback: Option<&str>) -> Option<String> {
  first_non_empty(headers, &[X_SESSION_AFFINITY.as_str()])
    .map(str::to_string)
    .or_else(|| ctx.vars.session_id.as_ref().map(ToString::to_string))
    .or_else(|| fallback.map(str::to_string))
}

fn is_codex_user_agent(value: &str) -> bool {
  value.contains("codex_cli_rs") || value.contains("codex_exec") || value.contains("codex-tui")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::ProviderRequestKind;
  use tokn_headers::TemplateVars;

  #[test]
  fn codex_opencode_shape_uses_opencode_identity_and_sanitizes_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(&AUTHORIZATION, "Bearer atk-test");
    headers.insert(&CHATGPT_ACCOUNT_ID, "acc-1");
    headers.insert(&ORIGINATOR, "Codex Desktop");
    headers.insert("x-api-key", "wrong");
    let vars = TemplateVars {
      session_id: Some("sess-vars".into()),
      ..Default::default()
    };
    let ctx = HeaderNormalizeCtx {
      agent_id: &AgentId::Opencode,
      stream: false,
      content_encoding: Some("gzip"),
      vars: &vars,
    };

    let out = CodexOpencodeNormalizer.normalize(&headers, &ctx);

    assert_eq!(out.get(&AUTHORIZATION).unwrap().as_str(), "Bearer atk-test");
    assert_eq!(out.get(&ACCEPT).unwrap().as_str(), "application/json");
    assert_eq!(out.get(&OPENAI_BETA).unwrap().as_str(), CODEX_RESPONSES_BETA);
    assert_eq!(out.get(&ORIGINATOR).unwrap().as_str(), "opencode");
    assert!(out.get(&VERSION).is_none());
    assert_eq!(out.get(&USER_AGENT).unwrap().as_str(), OPENCODE_USER_AGENT);
    assert_eq!(out.get(&SESSION_ID_LOWER).unwrap().as_str(), "sess-vars");
    assert_eq!(out.get(&X_SESSION_AFFINITY).unwrap().as_str(), "sess-vars");
    assert_eq!(out.get(&CONTENT_ENCODING).unwrap().as_str(), "gzip");
    assert!(out.get("x-api-key").is_none());
  }

  #[test]
  fn codex_cli_shape_preserves_turn_metadata_and_codex_identity() {
    let mut headers = HeaderMap::new();
    headers.insert(&AUTHORIZATION, "Bearer atk-test");
    headers.insert(&USER_AGENT, "codex_exec/0.130.0");
    headers.insert(&ORIGINATOR, "codex_exec");
    headers.insert(&SESSION_ID_LOWER, "sess-inbound");
    headers.insert(&X_CODEX_TURN_METADATA, r#"{"cwd":"/work"}"#);
    let ctx = HeaderNormalizeCtx {
      agent_id: &AgentId::CodexCli,
      stream: true,
      content_encoding: None,
      vars: &TemplateVars::default(),
    };

    let out = CodexCliNormalizer.normalize(&headers, &ctx);

    assert_eq!(out.get(&ACCEPT).unwrap().as_str(), "text/event-stream");
    assert_eq!(out.get(&ORIGINATOR).unwrap().as_str(), "codex_exec");
    assert_eq!(out.get(&USER_AGENT).unwrap().as_str(), "codex_exec/0.130.0");
    assert_eq!(out.get(&SESSION_ID_LOWER).unwrap().as_str(), "sess-inbound");
    assert_eq!(out.get(&X_CODEX_TURN_METADATA).unwrap().as_str(), r#"{"cwd":"/work"}"#);
  }

  #[test]
  fn codex_cli_shape_rejects_non_codex_user_agent() {
    let mut headers = HeaderMap::new();
    headers.insert(&USER_AGENT, "curl/8");
    headers.insert(&X_CODEX_TURN_METADATA, "{}");
    let ctx = HeaderNormalizeCtx {
      agent_id: &AgentId::CodexCli,
      stream: false,
      content_encoding: None,
      vars: &TemplateVars::default(),
    };

    let out = CodexCliNormalizer.normalize(&headers, &ctx);

    assert_eq!(out.get(&USER_AGENT).unwrap().as_str(), CODEX_CLI_USER_AGENT);
  }

  #[test]
  fn codex_normalizer_selects_shape_from_turn_metadata() {
    let ctx = HeaderPatchCtx {
      request_kind: ProviderRequestKind::Operation(crate::Endpoint::Responses),
      body: &serde_json::Value::Null,
      bearer_token: None,
      content_encoding: None,
      stream: false,
      initiator: "user",
      inbound_headers: &HeaderMap::new(),
      vars: &TemplateVars::default(),
      agent_id: &AgentId::Opencode,
    };
    let opencode = HeaderMap::new();
    let out = normalize_codex_headers(&opencode, &ctx);
    assert_eq!(out.get(&ORIGINATOR).unwrap().as_str(), "opencode");

    let mut codex_cli = HeaderMap::new();
    codex_cli.insert(&X_CODEX_TURN_METADATA, "{}");
    let ctx = HeaderPatchCtx {
      agent_id: &AgentId::CodexCli,
      ..ctx
    };
    let out = normalize_codex_headers(&codex_cli, &ctx);
    assert_eq!(out.get(&ORIGINATOR).unwrap().as_str(), "codex_cli_rs");
    assert_eq!(out.get(&X_CODEX_TURN_METADATA).unwrap().as_str(), "{}");
  }
}

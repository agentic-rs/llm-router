use crate::api::error::ApiError;
use crate::api::AppState;
use crate::pipeline::parse::RequestParser;
use crate::provider::Endpoint;
use bytes::Bytes;
use serde_json::Value;
use std::sync::Arc;
use tokn_accounts::{AccountHandle, EndpointAcquire};
use tokn_config::RouteMode;
use tokn_core::pipeline::{ParsedRequest, RequestMeta};
use tokn_core::provider::{ProviderRequestKind, TemplateVars};
use tokn_core::AgentId;
use tokn_headers::agent::build_agent_headers;
use tokn_headers::inbound::build_template_vars;
use tokn_headers::registry::{lookup, OverlayKind, ResolvedSchema};
use tokn_headers::schemas::{CodexOverlay, CopilotOverlay};
use tracing::warn;

pub struct DryRunOutput {
  pub account_id: String,
  pub provider_id: String,
  pub model: String,
  pub endpoint: Endpoint,
  pub headers: reqwest::header::HeaderMap,
  pub body: Bytes,
}

#[derive(Clone, Copy)]
pub enum DryRunEndpoint {
  ChatCompletions,
  Responses,
  Messages,
}

impl From<DryRunEndpoint> for Endpoint {
  fn from(value: DryRunEndpoint) -> Self {
    match value {
      DryRunEndpoint::ChatCompletions => Endpoint::ChatCompletions,
      DryRunEndpoint::Responses => Endpoint::Responses,
      DryRunEndpoint::Messages => Endpoint::Messages,
    }
  }
}

struct PreparedDryRun {
  meta: RequestMeta,
  upstream_body: Value,
  debug_outbound_body: Bytes,
  content_encoding: Option<crate::api::codec::ContentEncodingKind>,
  provider_headers: reqwest::header::HeaderMap,
  client_headers: Option<reqwest::header::HeaderMap>,
  vars: TemplateVars,
  account: Arc<AccountHandle>,
}

fn resolve_request(
  state: &AppState,
  parsed: ParsedRequest,
  attempt: usize,
) -> Result<(RequestMeta, Value, Arc<AccountHandle>, String), ApiError> {
  let route = state
    .route
    .resolve(
      &parsed.meta.model,
      parsed
        .meta
        .inbound_headers
        .get(tokn_accounts::routing::RouteResolver::mode_header())
        .map(|v| v.as_str()),
    )
    .map_err(|e| ApiError::bad_request(e.to_string()))?;
  if route.mode.is_verbatim() {
    return Err(ApiError::bad_request(format!(
      "{} mode only applies in proxy mode",
      match route.mode {
        RouteMode::Passthrough => "passthrough",
        RouteMode::Switch => "switch",
        _ => unreachable!(),
      }
    )));
  }
  let (account, upstream_endpoint) =
    match state
      .pool
      .acquire_for_route(parsed.meta.session_id.as_deref(), &route, parsed.meta.endpoint)
    {
      EndpointAcquire::Account { acct, endpoint } => (acct, endpoint),
      EndpointAcquire::SessionExpired => {
        let id = parsed.meta.session_id.clone().unwrap_or_default();
        warn!(%parsed.meta.endpoint, model = %parsed.meta.model, session_id = %id, attempt, "session expired");
        return Err(ApiError::session_expired(id));
      }
      EndpointAcquire::None => {
        warn!(%parsed.meta.endpoint, model = %parsed.meta.model, attempt, "no account supports endpoint/model");
        return Err(ApiError::not_implemented(
          parsed.meta.endpoint.to_string(),
          parsed.meta.model.clone(),
        ));
      }
    };

  let mut meta = parsed.meta;
  meta.upstream_endpoint = upstream_endpoint;
  meta.upstream_model = route.upstream_model.clone();
  Ok((meta, parsed.body, account, route.upstream_model))
}

fn prepare_dry_run(
  meta: RequestMeta,
  body: Value,
  account: Arc<AccountHandle>,
  raw_body: Bytes,
  content_encoding: Option<crate::api::codec::ContentEncodingKind>,
) -> crate::provider::Result<PreparedDryRun> {
  let mut upstream_body = rewrite_model(&body, &meta.upstream_model);
  if meta.upstream_endpoint != meta.endpoint {
    upstream_body =
      crate::convert::convert_request(meta.endpoint, meta.upstream_endpoint, &upstream_body).map_err(|source| {
        crate::provider::error::Error::Profiles {
          message: format!("request conversion failed: {source}"),
        }
      })?;
  }
  if let Some(transformer) = account.provider.input_transformer() {
    upstream_body = transformer.transform_input(meta.upstream_endpoint, upstream_body)?;
  }
  let debug_outbound_body = Bytes::from(serde_json::to_vec(&upstream_body).unwrap_or_default());
  let _upstream_wire_body = if upstream_body == body {
    raw_body
  } else {
    crate::api::codec::encode_body_bytes(debug_outbound_body.as_ref(), content_encoding)
      .map_err(|message| crate::provider::error::Error::Profiles { message })?
  };
  let inbound_compat: reqwest::header::HeaderMap = meta.inbound_headers.clone().into();
  let provider_headers = provider_headers(&inbound_compat);
  let vars = parse_inbound_vars(&inbound_compat);
  let client_headers = build_client_headers(&account, &inbound_compat, &vars);
  Ok(PreparedDryRun {
    meta,
    upstream_body,
    debug_outbound_body,
    content_encoding,
    provider_headers,
    client_headers,
    vars,
    account,
  })
}

fn build_client_headers(
  account: &Arc<AccountHandle>,
  inbound: &reqwest::header::HeaderMap,
  vars: &TemplateVars,
) -> Option<reqwest::header::HeaderMap> {
  let agent_id = selected_agent_id(account)?;
  let provider_id = account.provider.info().id.as_str();
  let inbound_headers: tokn_headers::HeaderMap = inbound.into();
  let mut headers = match lookup(provider_id, agent_id.as_str()) {
    Some(schema) => compose_with_schema(&schema, vars, &inbound_headers),
    None => build_agent_headers(agent_id.as_str(), vars, &inbound_headers),
  };
  let patch: tokn_headers::HeaderMap = (&account_extra_headers(&account.config.load().headers)).into();
  headers.merge_replacing(patch);
  Some(headers.into())
}

fn selected_agent_id(account: &Arc<AccountHandle>) -> Option<AgentId> {
  AgentId::provider_default(account.provider.info().id.as_str())
}

fn account_extra_headers(headers: &std::collections::BTreeMap<String, String>) -> reqwest::header::HeaderMap {
  let mut out = reqwest::header::HeaderMap::new();
  for (name, value) in headers {
    if is_router_controlled(name) {
      continue;
    }
    let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) else {
      continue;
    };
    let Ok(value) = reqwest::header::HeaderValue::from_str(value) else {
      continue;
    };
    out.insert(name, value);
  }
  out
}

fn rewrite_model(body: &Value, model: &str) -> Value {
  let mut body = body.clone();
  if let Some(obj) = body.as_object_mut() {
    obj.insert("model".into(), Value::String(model.to_string()));
  }
  body
}

pub fn dry_run_request(
  state: &AppState,
  endpoint: DryRunEndpoint,
  headers: reqwest::header::HeaderMap,
  body: Value,
  raw_body: Bytes,
  content_encoding: Option<crate::api::codec::ContentEncodingKind>,
) -> Result<DryRunOutput, ApiError> {
  let parsed = match endpoint {
    DryRunEndpoint::ChatCompletions => crate::pipeline::ChatParser.parse(headers, body),
    DryRunEndpoint::Responses => crate::pipeline::ResponsesParser.parse(headers, body),
    DryRunEndpoint::Messages => crate::pipeline::MessagesParser.parse(headers, body),
  };
  let (meta, body, account, _) = resolve_request(state, parsed, 0)?;
  let prepared = prepare_dry_run(meta, body, account, raw_body, content_encoding)
    .map_err(|e| ApiError::bad_gateway(e.to_string()))?;
  let mut headers: tokn_headers::HeaderMap = prepared.client_headers.as_ref().map(|h| h.into()).unwrap_or_default();
  let inbound_lh: tokn_headers::HeaderMap = (&prepared.provider_headers).into();
  prepared
    .account
    .provider
    .patch_headers(
      &mut headers,
      &crate::provider::HeaderPatchCtx {
        request_kind: ProviderRequestKind::Operation(prepared.meta.upstream_endpoint),
        body: &prepared.upstream_body,
        bearer_token: None,
        content_encoding: prepared.content_encoding.map(|encoding| encoding.as_str()),
        stream: prepared.meta.stream,
        initiator: prepared.meta.initiator.as_deref().unwrap_or("user"),
        inbound_headers: &inbound_lh,
        vars: &prepared.vars,
        agent_id: &tokn_core::AgentId::Opencode,
      },
    )
    .ok();
  let headers: reqwest::header::HeaderMap = headers.into();
  Ok(DryRunOutput {
    account_id: prepared.account.id(),
    provider_id: prepared.account.provider.info().id.clone(),
    model: prepared.meta.upstream_model,
    endpoint: prepared.meta.upstream_endpoint,
    headers,
    body: prepared.debug_outbound_body,
  })
}

const ROUTER_CONTROLLED_HEADERS: &[&str] = &[
  "accept",
  "accept-encoding",
  "authorization",
  "connection",
  "content-length",
  "content-type",
  "host",
  "te",
  "transfer-encoding",
];

fn normalize_header_name(name: &str) -> String {
  name.trim().to_ascii_lowercase()
}

fn is_router_controlled(name: &str) -> bool {
  let n = normalize_header_name(name);
  ROUTER_CONTROLLED_HEADERS.contains(&n.as_str())
}

fn compose_with_schema(
  schema: &ResolvedSchema,
  vars: &TemplateVars,
  inbound: &tokn_headers::HeaderMap,
) -> tokn_headers::HeaderMap {
  let agent_map = schema.agent.build_outbound(vars, inbound);
  let overlay_map = schema.overlay.map(|kind| match kind {
    OverlayKind::Copilot => {
      use tokn_headers::HeaderSchema as _;
      CopilotOverlay::build(vars, inbound).dump()
    }
    OverlayKind::Codex => {
      use tokn_headers::HeaderSchema as _;
      CodexOverlay::build(vars, inbound).dump()
    }
  });
  ResolvedSchema::compose(agent_map, overlay_map)
}

fn parse_inbound_vars(inbound: &reqwest::header::HeaderMap) -> TemplateVars {
  let inbound_headers: tokn_headers::HeaderMap = inbound.into();
  build_template_vars(&inbound_headers)
}

fn provider_headers(headers: &reqwest::header::HeaderMap) -> reqwest::header::HeaderMap {
  headers
    .iter()
    .filter(|(name, _)| !crate::api::is_router_owned_header(name))
    .map(|(name, value)| (name.clone(), value.clone()))
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::api::build_state;
  use crate::config::{Account as AccountCfg, Config};
  use crate::util::secret::Secret;
  use std::sync::Arc;
  use tokn_core::account::AccountConfig;
  use tokn_core::event::EventBus;

  fn openai_account() -> AccountCfg {
    AccountCfg {
      id: "acct".into(),
      provider: crate::provider::ID_OPENAI.into(),
      enabled: true,
      tier: tokn_core::account::AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: None,
      username: None,
      api_key: Some(Secret::new("sk-test".into())),
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: toml::Table::new(),
    }
  }

  fn core_account(cfg: AccountCfg) -> AccountConfig {
    let raw = toml::to_string(&cfg).unwrap();
    toml::from_str(&raw).unwrap()
  }

  #[test]
  fn dry_run_ignores_account_behave_as_setting() {
    let cfg = Config::default();
    let mut account = openai_account();
    account
      .settings
      .insert("behave_as".into(), toml::Value::String("codex".into()));
    let state = build_state(&cfg, &[core_account(account)], Arc::new(EventBus::noop())).unwrap();

    let out = dry_run_request(
      &state,
      DryRunEndpoint::ChatCompletions,
      reqwest::header::HeaderMap::new(),
      serde_json::json!({
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "hi"}]
      }),
      Bytes::from_static(br#"{"model":"gpt-4.1","messages":[{"role":"user","content":"hi"}]}"#),
      None,
    )
    .unwrap();

    let user_agent = out.headers.get("user-agent").and_then(|value| value.to_str().ok());
    assert_eq!(
      user_agent,
      Some("opencode/1.14.28 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13")
    );
    assert!(out.headers.get("originator").is_none());
  }

  #[test]
  fn parse_inbound_vars_uses_shared_session_and_project_headers() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("session-id", reqwest::header::HeaderValue::from_static("session-1"));
    headers.insert(
      "x-opencode-project",
      reqwest::header::HeaderValue::from_static("/tmp/project"),
    );
    headers.insert(
      "x-interaction-id",
      reqwest::header::HeaderValue::from_static("interaction-1"),
    );

    let vars = parse_inbound_vars(&headers);

    assert_eq!(vars.session_id.as_deref(), Some("session-1"));
    assert_eq!(vars.project_cwd.as_deref(), Some("/tmp/project"));
    assert_eq!(vars.interaction_id.as_deref(), Some("interaction-1"));
  }
}

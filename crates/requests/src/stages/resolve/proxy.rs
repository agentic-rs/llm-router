//! Resolve stage for the MITM proxy passthrough pipeline.
//!
//! Unlike [`PoolResolve`](super::PoolResolve), the proxy variant has **no
//! account selection** — the intercepted TLS host (e.g. `api.openai.com`)
//! is the upstream, and the client's own `Authorization` header reaches
//! the upstream untouched. We still need to satisfy the [`Resolved`]
//! shape, so this stage:
//!
//! * Reads `proxy.host` and `proxy.provider_id` from
//!   [`PipelineCtx::config`] (the [`RunConfig`] populated by the proxy
//!   transport layer before executing the request service).
//! * Picks a dummy `account_id` (`"proxy"`) and a `provider_id` set to
//!   either the caller-supplied value or the host.
//! * Constructs a [`ProxyStubProvider`] inside an [`AccountHandle`]; the
//!   handle is required by the [`Resolved`] struct contract but is never
//!   read by [`ProxySend`](super::super::send::ProxySend), which builds
//!   the outbound request directly from the bag.
//!
//! [`RunConfig`]: crate::RunConfig
//! [`AccountHandle`]: tokn_accounts::AccountHandle

use crate::event::Stage;
use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::{PipelineError, RequestsError};
use crate::pipeline::stages::{Extracted, ResolveStage, Resolved, ResolvedRoute};
use async_trait::async_trait;
use serde_json::Value;
use smol_str::SmolStr;
use std::sync::Arc;
use tokn_accounts::{AccountHandle, AccountPool, EndpointAcquire, RouteResolution, RouteSelector, SessionAcquire};
use tokn_config::RouteMode;
use tokn_core::account::AccountConfig;
use tokn_core::provider::{AuthKind, ModelCache, Provider, ProviderInfo, ProviderRequestKind};

/// Config keys consumed by [`ProxyResolve`]. The proxy transport layer
/// is responsible for populating these before executing the request service.
pub mod keys {
  pub const HOST: &str = "proxy.host";
  pub const PROVIDER_ID: &str = "proxy.provider_id";
  pub const ACCOUNT_ID: &str = "proxy.account_id";
  pub const PATH: &str = "proxy.path";
}

pub struct ProxyResolve;

pub struct ProxyProviderResolve {
  pool: Arc<AccountPool>,
}

impl ProxyProviderResolve {
  pub fn new(pool: Arc<AccountPool>) -> Self {
    Self { pool }
  }
}

#[async_trait]
impl ResolveStage for ProxyResolve {
  async fn resolve(&self, ctx: &PipelineCtx, extracted: &Extracted) -> Result<Resolved, PipelineError> {
    let host = ctx.config.get_str(keys::HOST).ok_or_else(|| {
      let msg = format!("proxy passthrough pipeline requires `{}` in RunConfig", keys::HOST);
      PipelineError::permanent(Stage::Resolve, RequestsError::Other { source: msg.into() })
    })?;
    let provider_id = ctx.config.get_str(keys::PROVIDER_ID).unwrap_or(host);
    let account_id = ctx.config.get_str(keys::ACCOUNT_ID).unwrap_or("proxy");
    let provider_request_kind = ctx
      .request_endpoint
      .resolved()
      .map(ProviderRequestKind::Operation)
      .or_else(|| {
        ctx
          .config
          .get_str(keys::PATH)
          .map(ProviderRequestKind::from_provider_path)
      })
      .unwrap_or(ProviderRequestKind::Opaque);
    Ok(Resolved {
      agent_id: extracted.agent_id.clone(),
      model: extracted.model.clone(),
      upstream_model: extracted.model.clone(),
      route: match ctx.request_endpoint.resolved() {
        Some(endpoint) => ResolvedRoute::operation(endpoint, endpoint),
        None => ResolvedRoute::provider_traffic(provider_request_kind),
      },
      account_id: SmolStr::new(account_id),
      provider_id: SmolStr::new(provider_id),
      account_handle: stub_handle(account_id, provider_id),
    })
  }
}

#[async_trait]
impl ResolveStage for ProxyProviderResolve {
  async fn resolve(&self, ctx: &PipelineCtx, extracted: &Extracted) -> Result<Resolved, PipelineError> {
    let provider_id = ctx.config.get_str(keys::PROVIDER_ID).ok_or_else(|| {
      PipelineError::permanent(
        Stage::Resolve,
        RequestsError::Other {
          source: format!("proxy switch pipeline requires `{}` in RunConfig", keys::PROVIDER_ID).into(),
        },
      )
    })?;
    let allowed_providers = super::pool::allowed_provider_ids(ctx)?;
    if allowed_providers
      .as_ref()
      .is_some_and(|providers| !providers.contains(provider_id))
    {
      return Err(PipelineError::permanent(
        Stage::Resolve,
        RequestsError::ProviderAccessDenied,
      ));
    }

    let Some(request_endpoint) = ctx.request_endpoint.resolved() else {
      let provider_request_kind = ctx
        .config
        .get_str(keys::PATH)
        .map(ProviderRequestKind::from_provider_path)
        .unwrap_or(ProviderRequestKind::Opaque);
      return match self.pool.acquire_provider(extracted.session_id.as_deref(), provider_id) {
        SessionAcquire::Account(acct) => Ok(Resolved {
          agent_id: extracted.agent_id.clone(),
          model: extracted.model.clone(),
          upstream_model: extracted.model.clone(),
          route: ResolvedRoute::provider_traffic(provider_request_kind),
          account_id: SmolStr::from(acct.id()),
          provider_id: SmolStr::from(acct.provider.info().id.as_str()),
          account_handle: acct,
        }),
        SessionAcquire::SessionExpired => Err(PipelineError::permanent(
          Stage::Resolve,
          RequestsError::SessionExpired {
            session_id: extracted.session_id.clone().unwrap_or_default(),
          },
        )),
        SessionAcquire::None => Err(PipelineError::permanent(
          Stage::Resolve,
          RequestsError::NoProviderAccount {
            provider_id: SmolStr::new(provider_id),
          },
        )),
      };
    };

    let route = RouteResolution {
      mode: RouteMode::Switch,
      requested_model: extracted.model.to_string(),
      upstream_model: extracted.model.to_string(),
      selector: RouteSelector::Provider(provider_id.to_string()),
    };
    match self
      .pool
      .acquire_for_route(extracted.session_id.as_deref(), &route, request_endpoint)
    {
      EndpointAcquire::Account { acct, endpoint } => Ok(Resolved {
        agent_id: extracted.agent_id.clone(),
        model: extracted.model.clone(),
        upstream_model: SmolStr::from(route.upstream_model.as_str()),
        route: ResolvedRoute::operation(request_endpoint, endpoint),
        account_id: SmolStr::from(acct.id()),
        provider_id: SmolStr::from(acct.provider.info().id.as_str()),
        account_handle: acct,
      }),
      EndpointAcquire::SessionExpired => Err(PipelineError::permanent(
        Stage::Resolve,
        RequestsError::SessionExpired {
          session_id: extracted.session_id.clone().unwrap_or_default(),
        },
      )),
      EndpointAcquire::None => Err(PipelineError::permanent(
        Stage::Resolve,
        RequestsError::NoAccount {
          endpoint: request_endpoint,
          model: extracted.model.clone(),
        },
      )),
    }
  }
}

/// Sentinel [`AccountHandle`] for the proxy pipeline. Carries enough
/// metadata to satisfy the [`Resolved`] type contract but is **never
/// consulted** by [`ProxySend`](super::super::send::ProxySend) — the
/// outbound request is built directly from `ctx.config` + the inbound
/// bytes + the pruned headers from [`PassthroughBuildHeaders`].
pub(crate) fn stub_handle(account_id: &str, provider_id: &str) -> Arc<AccountHandle> {
  let cfg = AccountConfig {
    id: account_id.to_string(),
    provider: provider_id.to_string(),
    enabled: true,
    tier: Default::default(),
    tags: Vec::new(),
    label: None,
    base_url: None,
    headers: Default::default(),
    auth_type: None,
    username: None,
    api_key: None,
    api_key_expires_at: None,
    access_token: None,
    access_token_expires_at: None,
    id_token: None,
    refresh_token: None,
    provider_account_id: None,
    extra: Default::default(),
    refresh_url: None,
    last_refresh: None,
    settings: Default::default(),
  };
  let provider = Arc::new(ProxyStubProvider::new(provider_id));
  Arc::new(AccountHandle::new(Arc::new(cfg), provider))
}

/// Stub provider that returns its [`ProviderInfo`] but panics on any
/// outbound call. The proxy passthrough pipeline never invokes
/// `Provider::chat / responses / messages` (those would route through
/// `DefaultSend`; the proxy uses `ProxySend` instead). The panic is a
/// loud invariant check: if someone ever wires this stub into a path
/// that calls the provider's request methods, we want to know
/// immediately rather than silently fall back to a 500.
pub struct ProxyStubProvider {
  info: ProviderInfo,
}

impl ProxyStubProvider {
  fn new(provider_id: &str) -> Self {
    Self {
      info: ProviderInfo {
        id: provider_id.to_string(),
        aliases: &[],
        display_name: "proxy-stub",
        upstream_url: String::new(),
        auth_kind: AuthKind::StaticApiKey,
        default_models: Vec::new(),
        default_endpoints: &[],
        model_cache: Arc::new(ModelCache::default()),
      },
    }
  }
}

#[async_trait]
impl Provider for ProxyStubProvider {
  fn id(&self) -> &str {
    &self.info.id
  }

  fn info(&self) -> &ProviderInfo {
    &self.info
  }

  async fn list_models(&self, _http: &reqwest::Client) -> tokn_core::provider::error::Result<Value> {
    Ok(Value::Null)
  }

  async fn chat(
    &self,
    _ctx: tokn_core::provider::RequestCtx<'_>,
  ) -> tokn_core::provider::error::Result<reqwest::Response> {
    unreachable!("ProxyStubProvider::chat called; proxy pipeline must use ProxySend, not DefaultSend")
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::EventBus;
  use crate::pipeline::config::RunConfig;
  use crate::pipeline::stages::Extracted;
  use bytes::Bytes;
  use tokn_core::provider::Endpoint;
  use tokn_headers::HeaderMap;

  fn fake_extracted() -> Extracted {
    Extracted {
      agent_id: None,
      model: SmolStr::new("gpt-4"),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: None,
      header_initiator: None,
      route_mode_hint: None,
      headers: HeaderMap::new(),
      raw_body: Bytes::new(),
      decoded_body: Bytes::new(),
      body_json: Arc::new(Value::Null),
      content_encoding: None,
    }
  }

  fn ctx_with(config: RunConfig) -> PipelineCtx {
    PipelineCtx::new_with_config(
      "req-px",
      Endpoint::ChatCompletions.into(),
      Arc::new(EventBus::new(64)),
      Arc::new(config),
    )
  }

  #[tokio::test]
  async fn reads_host_from_config() {
    let cfg = RunConfig::builder().with_str(keys::HOST, "api.openai.com").build();
    let res = ProxyResolve.resolve(&ctx_with(cfg), &fake_extracted()).await.unwrap();
    assert_eq!(res.account_id, "proxy");
    assert_eq!(res.provider_id, "api.openai.com");
    assert_eq!(res.upstream_model, "gpt-4");
    assert_eq!(res.route.upstream_endpoint(), Some(Endpoint::ChatCompletions));
  }

  #[tokio::test]
  async fn missing_host_is_permanent_error() {
    let err = ProxyResolve
      .resolve(&ctx_with(RunConfig::default()), &fake_extracted())
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::Resolve);
    assert!(!err.recoverable);
    assert!(err.message().contains("proxy.host"));
  }

  #[tokio::test]
  async fn explicit_provider_id_and_account_id_override_defaults() {
    let cfg = RunConfig::builder()
      .with_str(keys::HOST, "api.openai.com")
      .with_str(keys::PROVIDER_ID, "openai")
      .with_str(keys::ACCOUNT_ID, "user-bearer")
      .build();
    let res = ProxyResolve.resolve(&ctx_with(cfg), &fake_extracted()).await.unwrap();
    assert_eq!(res.account_id, "user-bearer");
    assert_eq!(res.provider_id, "openai");
  }

  #[tokio::test]
  async fn proxy_provider_resolve_selects_account_for_provider() {
    let cfg = RunConfig::builder().with_str(keys::PROVIDER_ID, "openai").build();
    let account = AccountConfig {
      id: "acct-openai".into(),
      provider: "openai".into(),
      enabled: true,
      tier: Default::default(),
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: Some(tokn_core::account::AuthType::Bearer),
      username: None,
      api_key: Some(tokn_core::account::Secret::new("sk-test".to_string())),
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: Default::default(),
    };
    let mut router_cfg = tokn_config::Config::default();
    router_cfg.pool.failure_cooldown_secs = 0;
    let pool = tokn_accounts::AccountPool::from_accounts_with(&[account], &router_cfg, |cfg| {
      tokn_accounts::registry::build_for_account(cfg)
    })
    .unwrap();

    let res = ProxyProviderResolve::new(pool)
      .resolve(&ctx_with(cfg), &fake_extracted())
      .await
      .unwrap();
    assert_eq!(res.account_id, "acct-openai");
    assert_eq!(res.provider_id, "openai");
  }
}

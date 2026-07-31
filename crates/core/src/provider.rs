use crate::account::AccountConfig;
use crate::upstream_url::{CanonicalUpstreamUrl, CleartextHttpPolicy, InvalidUpstreamUrl};
use async_trait::async_trait;
use bytes::Bytes;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock, RwLock};
use tokn_headers::keys::{AUTHORIZATION, CHATGPT_ACCOUNT_ID, COOKIE, X_API_KEY};
pub use tokn_headers::TemplateVars;
use tokn_headers::{AgentId, HeaderMap};

pub mod error;

pub use error::{Error, Result};

pub const ID_GITHUB_COPILOT: &str = "github-copilot";
pub const ID_DEEPSEEK: &str = "deepseek";
pub const ID_LLAMA_CPP: &str = "llama-cpp";
pub const ID_OPENAI: &str = "openai";
pub const ID_CODEX: &str = "codex";
pub const ID_ZAI_CODING_PLAN: &str = "zai-coding-plan";
pub const ID_ZAI: &str = "zai";
pub const ID_ZHIPUAI_CODING_PLAN: &str = "zhipuai-coding-plan";
pub const ID_ZHIPUAI: &str = "zhipuai";
pub const ZAI_PROVIDERS: &[&str] = &[ID_ZAI_CODING_PLAN, ID_ZAI, ID_ZHIPUAI_CODING_PLAN, ID_ZHIPUAI];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
  None,
  OAuthDeviceFlow,
  StaticApiKey,
}

#[derive(Debug, Clone, Serialize)]
pub struct Modalities {
  pub text: bool,
  pub audio: bool,
  pub image: bool,
  pub video: bool,
  pub pdf: bool,
}

impl Modalities {
  #[allow(dead_code)]
  pub const TEXT_ONLY: Self = Self {
    text: true,
    audio: false,
    image: false,
    video: false,
    pdf: false,
  };
  #[allow(dead_code)]
  pub const TEXT_IMAGE: Self = Self {
    text: true,
    audio: false,
    image: true,
    video: false,
    pdf: false,
  };
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Interleaved {
  Disabled(bool),
  Field { field: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
  pub temperature: bool,
  pub reasoning: bool,
  pub attachment: bool,
  pub toolcall: bool,
  pub input: Modalities,
  pub output: Modalities,
  pub interleaved: Interleaved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cost {
  pub input: f64,
  pub output: f64,
  pub cache: Option<CacheCost>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheCost {
  pub read: f64,
  pub write: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Limits {
  pub context: u32,
  pub output: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelInfo {
  pub id: String,
  pub name: String,
  pub capabilities: Capabilities,
  pub cost: Option<Cost>,
  pub limit: Limits,
  pub release_date: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
  pub id: String,
  pub aliases: &'static [&'static str],
  pub display_name: &'static str,
  pub upstream_url: String,
  pub auth_kind: AuthKind,
  pub default_models: Vec<ModelInfo>,
  /// Endpoints this provider serves when no per-model rule narrows the
  /// answer. Should mirror the `endpoints` slice on the corresponding
  /// `ProviderDescriptor` (a registry-time test enforces this).
  pub default_endpoints: &'static [Endpoint],
  /// Cache of model ids learned from the upstream `/models` call. Empty
  /// until the first successful `Provider::list_models` warms it. Used
  /// by the default `has_model` impl as the source of truth, with
  /// `default_models` as the cold-start fallback.
  #[serde(skip)]
  pub model_cache: Arc<ModelCache>,
}

/// In-memory cache of model ids advertised by a provider's upstream
/// `/models` endpoint. Warmed lazily by the routing layer the first time
/// it sees the provider; subsequent reads are lock-free fast paths.
#[derive(Debug, Default)]
pub struct ModelCache {
  inner: RwLock<Option<HashSet<String>>>,
}

impl ModelCache {
  pub fn set(&self, ids: HashSet<String>) {
    if let Ok(mut g) = self.inner.write() {
      *g = Some(ids);
    }
  }

  pub fn contains(&self, id: &str) -> bool {
    self
      .inner
      .read()
      .ok()
      .and_then(|g| g.as_ref().map(|s| s.contains(id)))
      .unwrap_or(false)
  }

  pub fn is_warm(&self) -> bool {
    self.inner.read().ok().map(|g| g.is_some()).unwrap_or(false)
  }

  pub fn snapshot(&self) -> Option<HashSet<String>> {
    self.inner.read().ok().and_then(|g| g.clone())
  }
}

/// Runtime destination shared by every account binding for one configured
/// upstream.
///
/// Construct one target per upstream id, then clone it when binding eligible
/// accounts. Clones intentionally share the model cache; constructing another
/// target, even for the same URL, creates an independent cache.
#[derive(Clone, Debug)]
pub struct ProviderTarget {
  base_url: CanonicalUpstreamUrl,
  model_cache: Arc<ModelCache>,
}

impl ProviderTarget {
  pub fn new(base_url: CanonicalUpstreamUrl) -> Self {
    Self {
      base_url,
      model_cache: Arc::new(ModelCache::default()),
    }
  }

  pub fn parse(base_url: &str, cleartext: CleartextHttpPolicy) -> Result<Self, InvalidUpstreamUrl> {
    CanonicalUpstreamUrl::parse(base_url, cleartext).map(Self::new)
  }

  pub fn base_url(&self) -> &CanonicalUpstreamUrl {
    &self.base_url
  }

  pub fn model_cache(&self) -> &Arc<ModelCache> {
    &self.model_cache
  }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
  ChatCompletions,
  Responses,
  Messages,
}

impl Endpoint {
  pub fn as_str(self) -> &'static str {
    match self {
      Endpoint::ChatCompletions => "chat_completions",
      Endpoint::Responses => "responses",
      Endpoint::Messages => "messages",
    }
  }

  /// Best-effort guess at which [`Endpoint`] variant a given path
  /// represents. Used only to populate [`tokn_requests::RawInbound::endpoint`];
  /// the proxy passthrough pipeline never branches on it.
  pub fn infer_from(path: impl AsRef<str>) -> Option<Self> {
    let path = path.as_ref();
    if path.ends_with("/chat/completions") {
      Some(Endpoint::ChatCompletions)
    } else if path.ends_with("/responses") {
      Some(Endpoint::Responses)
    } else if path.ends_with("/messages") {
      Some(Endpoint::Messages)
    } else {
      None
    }
  }
}

impl std::fmt::Display for Endpoint {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Per-provider declarative rule mapping a model id glob pattern to the
/// set of endpoints that model is allowed to be served on.
///
/// Patterns use a tiny `*`-only glob (no character classes, no `?`).
/// Examples: `"claude-*"`, `"gpt-5*"`, `"o4-mini"`.
///
/// Lives in `tokn-core` so both [`ProviderInfo`] and the descriptor type
/// in `tokn-auth` can reference it without a dependency cycle.
#[derive(Copy, Clone, Debug)]
pub struct EndpointRule {
  pub pattern: &'static str,
  pub endpoints: &'static [Endpoint],
}

/// Walk `rules` in order; the first pattern that matches `model` wins.
/// Returns `Some(true)` if that rule allows `endpoint`, `Some(false)` if
/// it explicitly does not, and `None` if no rule matched.
pub fn match_endpoint_rule(rules: &[EndpointRule], model: &str, endpoint: Endpoint) -> Option<bool> {
  for rule in rules {
    if glob_match(rule.pattern, model) {
      return Some(rule.endpoints.contains(&endpoint));
    }
  }
  None
}

/// Tiny `*`-only glob matcher. `*` matches any (possibly empty) run of
/// characters; everything else matches literally. ASCII case-sensitive.
pub fn glob_match(pattern: &str, input: &str) -> bool {
  let p = pattern.as_bytes();
  let s = input.as_bytes();
  fn rec(p: &[u8], s: &[u8]) -> bool {
    let mut pi = 0;
    let mut si = 0;
    while pi < p.len() {
      if p[pi] == b'*' {
        // Collapse consecutive '*'.
        while pi < p.len() && p[pi] == b'*' {
          pi += 1;
        }
        if pi == p.len() {
          return true;
        }
        let rest = &p[pi..];
        while si <= s.len() {
          if rec(rest, &s[si..]) {
            return true;
          }
          si += 1;
        }
        return false;
      } else {
        if si >= s.len() || p[pi] != s[si] {
          return false;
        }
        pi += 1;
        si += 1;
      }
    }
    si == s.len()
  }
  rec(p, s)
}

pub struct RequestCtx<'a> {
  pub endpoint: Endpoint,
  pub http: &'a reqwest::Client,
  pub body: &'a Value,
  pub body_bytes: Option<&'a Bytes>,
  pub content_encoding: Option<&'a str>,
  pub stream: bool,
  pub initiator: &'a str,
  pub inbound_headers: &'a HeaderMap,
  pub client_headers: Option<HeaderMap>,
  pub outbound: Option<OutboundCapture>,
  pub vars: TemplateVars,
  pub agent_id: AgentId,
}

impl RequestCtx<'_> {
  pub fn request_body_bytes(&self) -> Bytes {
    self
      .body_bytes
      .cloned()
      .unwrap_or_else(|| Bytes::from(serde_json::to_vec(self.body).unwrap_or_default()))
  }

  pub fn capture_outbound(&self, method: &str, url: &str, headers: &HeaderMap, body: Bytes) {
    if let Some(slot) = self.outbound.as_ref() {
      let _ = slot.set(crate::db::OutboundSnapshot {
        method: Some(method.to_string()),
        url: Some(url.to_string()),
        status: None,
        req_headers: headers.clone(),
        req_body: body,
        resp_headers: HeaderMap::new(),
        resp_body: Bytes::new(),
      });
    }
  }
}

pub type OutboundCapture = Arc<OnceLock<crate::db::OutboundSnapshot>>;

pub fn new_outbound_capture() -> OutboundCapture {
  Arc::new(OnceLock::new())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRequestKind {
  Operation(Endpoint),
  Models,
  Opaque,
}

impl ProviderRequestKind {
  pub fn endpoint(self) -> Option<Endpoint> {
    match self {
      Self::Operation(endpoint) => Some(endpoint),
      Self::Models | Self::Opaque => None,
    }
  }

  pub fn from_provider_path(path: &str) -> Self {
    let path_only = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    if path_only.ends_with("/models") {
      Self::Models
    } else {
      Self::Opaque
    }
  }
}

/// Credential-only inputs for provider-owned authorization patches.
///
/// This deliberately excludes payload and header-normalization state so
/// opaque relay requests can replace account credentials without changing
/// the client's remaining wire headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialPatchCtx<'a> {
  pub request_kind: ProviderRequestKind,
  pub bearer_token: Option<&'a str>,
}

pub struct HeaderPatchCtx<'a> {
  pub request_kind: ProviderRequestKind,
  pub body: &'a Value,
  pub bearer_token: Option<&'a str>,
  pub content_encoding: Option<&'a str>,
  pub stream: bool,
  pub initiator: &'a str,
  pub inbound_headers: &'a HeaderMap,
  pub vars: &'a TemplateVars,
  pub agent_id: &'a AgentId,
}

impl HeaderPatchCtx<'_> {
  fn credential_patch_ctx(&self) -> CredentialPatchCtx<'_> {
    CredentialPatchCtx {
      request_kind: self.request_kind,
      bearer_token: self.bearer_token,
    }
  }

  pub fn endpoint(&self) -> Option<Endpoint> {
    self.request_kind.endpoint()
  }

  pub fn operation_endpoint(&self) -> Endpoint {
    self
      .endpoint()
      .expect("generation endpoint required for operation header patching")
  }
}

#[async_trait]
pub trait Provider: Send + Sync {
  fn id(&self) -> &str;
  fn info(&self) -> &ProviderInfo;

  fn input_transformer(&self) -> Option<&dyn crate::pipeline::InputTransformer> {
    None
  }

  fn model_info(&self, model: &str) -> Option<&ModelInfo> {
    self.info().default_models.iter().find(|m| m.id == model)
  }

  /// Does this provider serve `model`?
  ///
  /// Source-of-truth precedence:
  /// 1. Warm upstream `/models` cache (`ProviderInfo::model_cache`).
  /// 2. Catalogue snapshot (`ProviderInfo::default_models`) as cold-start
  ///    fallback.
  fn has_model(&self, model: &str) -> bool {
    if model.is_empty() {
      return true;
    }
    let info = self.info();
    if info.model_cache.is_warm() {
      return info.model_cache.contains(model);
    }
    info.default_models.iter().any(|m| m.id == model)
  }

  /// Per-model endpoint rules declared by the provider.
  ///
  /// - `Some(&[])` — no rules; every model resolves via
  ///   [`ProviderInfo::default_endpoints`].
  /// - `Some(non_empty)` — first matching pattern wins; if no pattern
  ///   matches, falls back to `default_endpoints`.
  /// - `None` — provider opts out of the static rule table; it is
  ///   expected to override [`Provider::has_endpoint`] itself. The
  ///   default [`Provider::has_endpoint`] in that case still consults
  ///   `default_endpoints`.
  fn endpoint_rules(&self) -> Option<&'static [EndpointRule]> {
    Some(&[])
  }

  /// Pure endpoint-capability lookup for a given model. No identity
  /// gating — call [`Provider::has_model`] separately if you need it.
  ///
  /// Default impl: consult the static rule table from
  /// [`Provider::endpoint_rules`] (when present); on miss, defer to
  /// [`ProviderInfo::default_endpoints`]. Providers with bespoke logic
  /// can override this directly (typically pairing with
  /// `endpoint_rules() = None`).
  fn has_endpoint(&self, model: &str, endpoint: Endpoint) -> bool {
    if let Some(rules) = self.endpoint_rules() {
      if let Some(decision) = match_endpoint_rule(rules, model, endpoint) {
        return decision;
      }
    }
    self.info().default_endpoints.contains(&endpoint)
  }

  /// Combined "does this provider serve this model on this endpoint?"
  /// gate. Default impl: identity check via [`Provider::has_model`],
  /// then capability check via [`Provider::has_endpoint`].
  ///
  /// The empty-model case (used by routing's `Any` selector) skips the
  /// identity check.
  fn supports(&self, model: &str, endpoint: Endpoint) -> bool {
    if !model.is_empty() && !self.has_model(model) {
      return false;
    }
    self.has_endpoint(model, endpoint)
  }

  /// Provider-owned credential injection.
  ///
  /// This phase should only add account-derived credential material such as
  /// bearer tokens, API keys, or provider account identifiers. These values
  /// are treated as credentials, not ordinary header fallbacks. Final
  /// transport/default enforcement belongs in [`Provider::normalize_headers`].
  ///
  /// Provider implementations must override this hook rather than relying on
  /// a custom [`Provider::patch_headers`] implementation. Both managed header
  /// patching and opaque request authorization call it through
  /// [`Provider::replace_credentials`].
  fn inject_credentials(&self, _headers: &mut HeaderMap, _ctx: &CredentialPatchCtx<'_>) -> Result<()> {
    Ok(())
  }

  /// Remove client account credentials, then inject the selected account's
  /// provider-owned replacements.
  ///
  /// Cookie authentication is credential material too: retaining it beside a
  /// selected bearer or API key could authenticate as a different account.
  fn replace_credentials(&self, headers: &mut HeaderMap, ctx: &CredentialPatchCtx<'_>) -> Result<()> {
    for name in [&AUTHORIZATION, &X_API_KEY, &CHATGPT_ACCOUNT_ID, &COOKIE] {
      headers.remove(name);
    }
    self.inject_credentials(headers, ctx)
  }

  fn patch_headers(&self, headers: &mut HeaderMap, ctx: &HeaderPatchCtx<'_>) -> Result<()> {
    self.replace_credentials(headers, &ctx.credential_patch_ctx())?;
    if let Some(new_headers) = self.normalize_headers(headers, ctx)? {
      *headers = new_headers;
    }
    Ok(())
  }

  /// Authorize a request without normalizing its remaining headers.
  ///
  /// This is the provider hook for opaque relay traffic. Static providers use
  /// the default credential injector; providers with asynchronously refreshed
  /// credentials can override it. Payload-dependent normalization must remain
  /// in [`Provider::patch_headers`] and is intentionally not called here.
  async fn authorize_request(
    &self,
    _http: &reqwest::Client,
    headers: &mut HeaderMap,
    request_kind: ProviderRequestKind,
  ) -> Result<()> {
    self.replace_credentials(
      headers,
      &CredentialPatchCtx {
        request_kind,
        bearer_token: None,
      },
    )
  }

  /// Final provider-owned header shape enforcement.
  ///
  /// Implementations use this after credential injection to canonicalize
  /// provider-specific order and casing, remove forbidden inbound residue, and
  /// fill required defaults.
  ///
  /// Return `Ok(None)` when the existing map is already correct (the caller
  /// keeps it). Return `Ok(Some(new_map))` when the provider rebuilt the map
  /// and the caller should replace it.
  fn normalize_headers(&self, _headers: &mut HeaderMap, _ctx: &HeaderPatchCtx<'_>) -> Result<Option<HeaderMap>> {
    Ok(None)
  }

  async fn list_models(&self, http: &reqwest::Client) -> Result<Value>;
  async fn chat(&self, ctx: RequestCtx<'_>) -> Result<reqwest::Response>;

  async fn responses(&self, _ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    error::UnsupportedEndpointSnafu {
      provider: self.info().id.clone(),
      endpoint: "/v1/responses",
    }
    .fail()
  }

  async fn messages(&self, _ctx: RequestCtx<'_>) -> Result<reqwest::Response> {
    error::UnsupportedEndpointSnafu {
      provider: self.info().id.clone(),
      endpoint: "/v1/messages",
    }
    .fail()
  }

  fn on_unauthorized(&self) {}

  fn needs_refresh(&self, _cfg: &AccountConfig) -> bool {
    false
  }

  async fn refresh(&self, cfg: &AccountConfig, _http: &reqwest::Client) -> Result<AccountConfig> {
    Ok(cfg.clone())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn glob_literal() {
    assert!(glob_match("foo", "foo"));
    assert!(!glob_match("foo", "foobar"));
    assert!(!glob_match("foo", "fo"));
  }

  #[test]
  fn glob_star_suffix() {
    assert!(glob_match("claude-*", "claude-3"));
    assert!(glob_match("claude-*", "claude-"));
    assert!(!glob_match("claude-*", "claude"));
    assert!(!glob_match("claude-*", "gpt-4"));
  }

  #[test]
  fn glob_star_prefix() {
    assert!(glob_match("*-mini", "o4-mini"));
    assert!(!glob_match("*-mini", "o4-mini-2"));
  }

  #[test]
  fn glob_star_middle_and_multiple() {
    assert!(glob_match("gpt-*-mini", "gpt-4-mini"));
    assert!(glob_match("gpt-*-mini", "gpt--mini"));
    assert!(!glob_match("gpt-*-mini", "gpt-mini"));
    assert!(glob_match("**", "anything"));
    assert!(glob_match("*", ""));
    assert!(!glob_match("a*b", "axc"));
  }

  #[test]
  fn rule_matching_first_wins() {
    static RULES: &[EndpointRule] = &[
      EndpointRule {
        pattern: "claude-*",
        endpoints: &[Endpoint::Messages, Endpoint::ChatCompletions],
      },
      EndpointRule {
        pattern: "*",
        endpoints: &[Endpoint::ChatCompletions],
      },
    ];
    assert_eq!(match_endpoint_rule(RULES, "claude-3", Endpoint::Messages), Some(true));
    assert_eq!(match_endpoint_rule(RULES, "claude-3", Endpoint::Responses), Some(false));
    assert_eq!(
      match_endpoint_rule(RULES, "gpt-4", Endpoint::ChatCompletions),
      Some(true)
    );
    assert_eq!(match_endpoint_rule(RULES, "gpt-4", Endpoint::Messages), Some(false));
    assert_eq!(match_endpoint_rule(&[], "anything", Endpoint::ChatCompletions), None);
  }

  #[test]
  fn model_cache_warm_then_contains() {
    let c = ModelCache::default();
    assert!(!c.is_warm());
    assert!(!c.contains("foo"));
    let mut s = HashSet::new();
    s.insert("foo".into());
    c.set(s);
    assert!(c.is_warm());
    assert!(c.contains("foo"));
    assert!(!c.contains("bar"));
  }

  #[test]
  fn provider_target_clones_share_only_their_upstream_cache() {
    let base_url = CanonicalUpstreamUrl::parse(
      "https://api.example.com/v1",
      crate::upstream_url::CleartextHttpPolicy::LoopbackOnly,
    )
    .unwrap();
    let first = ProviderTarget::new(base_url.clone());
    let first_clone = first.clone();
    let second = ProviderTarget::new(base_url);

    assert!(Arc::ptr_eq(first.model_cache(), first_clone.model_cache()));
    assert!(!Arc::ptr_eq(first.model_cache(), second.model_cache()));

    first.model_cache().set(HashSet::from(["gpt-test".into()]));
    assert!(first_clone.model_cache().contains("gpt-test"));
    assert!(!second.model_cache().is_warm());
  }

  // --- has_endpoint / supports layering tests ---

  use async_trait::async_trait;
  use serde_json::Value;

  struct StubProvider {
    info: ProviderInfo,
    rules: Option<&'static [EndpointRule]>,
  }

  #[async_trait]
  impl Provider for StubProvider {
    fn id(&self) -> &str {
      &self.info.id
    }
    fn info(&self) -> &ProviderInfo {
      &self.info
    }
    fn endpoint_rules(&self) -> Option<&'static [EndpointRule]> {
      self.rules
    }
    async fn list_models(&self, _http: &reqwest::Client) -> error::Result<Value> {
      Ok(Value::Null)
    }
    async fn chat(&self, _ctx: RequestCtx<'_>) -> error::Result<reqwest::Response> {
      unimplemented!()
    }
  }

  fn stub(rules: Option<&'static [EndpointRule]>, defaults: &'static [Endpoint]) -> StubProvider {
    StubProvider {
      info: ProviderInfo {
        id: "stub".into(),
        aliases: &[],
        display_name: "stub",
        upstream_url: String::new(),
        auth_kind: AuthKind::StaticApiKey,
        default_models: vec![],
        default_endpoints: defaults,
        model_cache: Arc::new(ModelCache::default()),
      },
      rules,
    }
  }

  static CLAUDE_RULES: &[EndpointRule] = &[EndpointRule {
    pattern: "claude-*",
    endpoints: &[Endpoint::Messages, Endpoint::ChatCompletions],
  }];

  #[test]
  fn has_endpoint_matched_rule_wins_over_defaults() {
    let p = stub(Some(CLAUDE_RULES), &[Endpoint::Responses]);
    // Rule matches: rule decides, defaults ignored.
    assert!(p.has_endpoint("claude-3", Endpoint::Messages));
    assert!(!p.has_endpoint("claude-3", Endpoint::Responses));
  }

  #[test]
  fn has_endpoint_unmatched_rule_falls_back_to_defaults() {
    let p = stub(Some(CLAUDE_RULES), &[Endpoint::Responses]);
    assert!(p.has_endpoint("gpt-4", Endpoint::Responses));
    assert!(!p.has_endpoint("gpt-4", Endpoint::Messages));
  }

  #[test]
  fn has_endpoint_none_rules_uses_defaults_only() {
    let p = stub(None, &[Endpoint::ChatCompletions]);
    assert!(p.has_endpoint("anything", Endpoint::ChatCompletions));
    assert!(!p.has_endpoint("anything", Endpoint::Responses));
  }

  #[test]
  fn supports_empty_model_skips_identity_check() {
    // No default_models, no cache → has_model("x") = false. Empty model
    // bypasses identity and goes straight to has_endpoint.
    let p = stub(Some(&[]), &[Endpoint::ChatCompletions]);
    assert!(p.supports("", Endpoint::ChatCompletions));
    assert!(!p.supports("", Endpoint::Messages));
    // Non-empty unknown model → identity gate denies.
    assert!(!p.supports("unknown", Endpoint::ChatCompletions));
  }
}

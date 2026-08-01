//! `/copilot_internal/user` — per-user plan + per-feature quota snapshots.
//!
//! Unlike the token-exchange endpoint (which returns `null` quotas for paid
//! plans), this endpoint exposes the live `quota_snapshots` that the GitHub
//! billing UI displays: remaining premium interactions, chat/completions
//! entitlement, monthly reset date, etc. We only call it from the CLI's
//! `account list` quota probe — not from the request hot path.

use crate::config::CopilotHeaders;
use crate::provider::Result;
use crate::util::redact::token_fingerprint;
use crate::COPILOT_USER_INFO_URL;
use serde::Deserialize;
use std::collections::BTreeMap;
use tracing::{debug, instrument};

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CopilotUserInfo {
  /// Marketing plan name, e.g. `"individual_pro"`, `"business"`, `"free"`.
  #[serde(default)]
  pub copilot_plan: Option<String>,

  /// ISO-8601 date when the monthly quotas reset (anchor day of billing
  /// cycle), e.g. `"2026-05-01"`.
  #[serde(default)]
  pub quota_reset_date: Option<String>,

  /// Per-feature snapshots, keyed by `quota_id` (`"chat"`,
  /// `"completions"`, `"premium_interactions"`, …). Always present on
  /// paid plans; may be empty / absent on free.
  #[serde(default)]
  pub quota_snapshots: BTreeMap<String, QuotaSnapshot>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct QuotaSnapshot {
  /// Numeric `quota_id` echo, e.g. `"premium_interactions"`.
  #[serde(default)]
  #[allow(dead_code)]
  pub quota_id: Option<String>,
  /// `true` when this feature is unmetered for the plan (e.g. chat on Plus).
  #[serde(default)]
  pub unlimited: bool,
  /// Remaining count for the current cycle (integer; e.g. `1244`).
  #[serde(default)]
  pub remaining: Option<u64>,
  /// Monthly entitlement, e.g. `1500` premium interactions.
  #[serde(default)]
  pub entitlement: Option<u64>,
  /// 0–100 (server-computed); useful for unlimited plans where
  /// `remaining` / `entitlement` are both 0.
  #[serde(default)]
  #[allow(dead_code)]
  pub percent_remaining: Option<f64>,
}

/// Fetch the live user info + quota snapshots.
///
/// Auth uses the long-lived `github_token` (same credential as
/// `token::exchange`), not a short-lived api_token.
#[instrument(
  name = "copilot_user_info",
  skip_all,
  fields(
    github_token_fp = %token_fingerprint(github_token),
    status = tracing::field::Empty,
    plan = tracing::field::Empty,
    quotas = tracing::field::Empty,
  ),
)]
pub async fn fetch(client: &reqwest::Client, github_token: &str, headers: &CopilotHeaders) -> Result<CopilotUserInfo> {
  let h = crate::headers::token_exchange_headers(github_token, headers)?;
  debug!("fetching copilot user info");
  let resp = crate::util::http::send(
    client,
    reqwest::Method::GET,
    COPILOT_USER_INFO_URL,
    h,
    None,
    "copilot user-info",
  )
  .await?;
  let status = resp.status();
  tracing::Span::current().record("status", status.as_u16());
  let parsed: CopilotUserInfo = crate::util::http::read_json(resp, "copilot user-info").await?;
  let span = tracing::Span::current();
  if let Some(p) = parsed.copilot_plan.as_deref() {
    span.record("plan", p);
  }
  span.record("quotas", parsed.quota_snapshots.len());
  Ok(parsed)
}

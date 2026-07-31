//! [`ProviderAuth`] impl for the Z.ai family (zai, zhipuai, *-coding-plan).
//!
//! Z.ai is a static-API-key provider: there is nothing to refresh, but we
//! still expose [`Self::verify_credential`] (a cheap `GET /models` probe)
//! and [`Self::probe_quota`] (the existing monitor endpoint).

use async_trait::async_trait;
use tokn_auth::{AuthError, ProviderAuth, QuotaSnapshot, RefreshOutcome, Result, VerifyOutcome};
use tokn_core::account::AccountConfig;

/// Singleton ZSt impl. Same instance handles every Z.ai alias because the
/// auth flow is identical; the provider id stored on the account is what
/// determines the upstream host.
pub struct ZaiAuth {
  /// The provider id reported via [`ProviderAuth::id`]. Z.ai has four
  /// aliases that share the same auth flow — we register one impl per
  /// alias so the dispatch table can do an exact-match lookup.
  id: &'static str,
}

impl ZaiAuth {
  pub const fn new(id: &'static str) -> Self {
    Self { id }
  }
}

/// Static accessors used by `tokn-auth`'s dispatch table. One per alias.
static ZAI_CODING_PLAN: ZaiAuth = ZaiAuth::new("zai-coding-plan");
static ZAI: ZaiAuth = ZaiAuth::new("zai");
static ZHIPUAI_CODING_PLAN: ZaiAuth = ZaiAuth::new("zhipuai-coding-plan");
static ZHIPUAI: ZaiAuth = ZaiAuth::new("zhipuai");

pub fn zai_coding_plan_auth() -> &'static dyn ProviderAuth {
  &ZAI_CODING_PLAN
}
pub fn zai_auth() -> &'static dyn ProviderAuth {
  &ZAI
}
pub fn zhipuai_coding_plan_auth() -> &'static dyn ProviderAuth {
  &ZHIPUAI_CODING_PLAN
}
pub fn zhipuai_auth() -> &'static dyn ProviderAuth {
  &ZHIPUAI
}

#[async_trait]
impl ProviderAuth for ZaiAuth {
  fn id(&self) -> &'static str {
    self.id
  }

  fn supports_device_flow(&self) -> bool {
    false
  }

  fn supports_static_key(&self) -> bool {
    true
  }

  fn default_account_id(&self) -> &'static str {
    // The "coding-plan" alias is keyed against an account commonly named
    // "coding-plan" in shared docs; surface that as the suggested id.
    if self.id == "zai-coding-plan" || self.id == "zhipuai-coding-plan" {
      "coding-plan"
    } else {
      self.id
    }
  }

  fn default_base_url(&self) -> Option<&'static str> {
    crate::zai::default_base_url(self.id)
  }

  async fn refresh_credential(&self, _client: &reqwest::Client, _account: &AccountConfig) -> Result<RefreshOutcome> {
    // Static API key: nothing to refresh.
    Ok(RefreshOutcome::NotApplicable)
  }

  async fn verify_credential(&self, client: &reqwest::Client, account: &AccountConfig) -> Result<VerifyOutcome> {
    let key = account.api_key.as_ref().ok_or(AuthError::MissingCredential {
      account: account.id.clone(),
      field: "api_key",
    })?;
    let base = account.base_url.clone().unwrap_or_else(|| {
      crate::zai::default_base_url(self.id)
        .expect("registered Z.ai auth provider id")
        .to_string()
    });
    let url = format!("{}/models", base.trim_end_matches('/'));
    let resp = client
      .get(&url)
      .header("authorization", format!("Bearer {}", key.expose()))
      .header("accept", "application/json")
      .send()
      .await
      .map_err(|e| AuthError::Network(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
      Ok(VerifyOutcome::default())
    } else {
      let body = resp.text().await.unwrap_or_default();
      Err(AuthError::Upstream(format!(
        "Z.ai rejected the key (HTTP {status}): {}",
        body.chars().take(200).collect::<String>()
      )))
    }
  }

  async fn probe_quota(&self, client: &reqwest::Client, account: &AccountConfig) -> Result<QuotaSnapshot> {
    let key = account.api_key.as_ref().ok_or(AuthError::MissingCredential {
      account: account.id.clone(),
      field: "api_key",
    })?;
    let raw = crate::quota::fetch(client, &account.provider, key.expose())
      .await
      .map_err(|e| AuthError::Upstream(e.to_string()))?;

    // Build a one-line headline: prefer the weekly bucket, fall back to
    // 5-hour or MCP-monthly.
    let headline = if let Some(w) = &raw.weekly {
      Some(format!("weekly: {:.1}% used", w.percent_used))
    } else if let Some(h) = &raw.five_hour {
      Some(format!("5h: {:.1}% used", h.percent_used))
    } else {
      raw.mcp_monthly.as_ref().map(|m| format!("mcp: {}/{}", m.used, m.total))
    };

    // Map every advertised bucket into UsageBucket for richer display.
    let mut secondary: Vec<tokn_auth::UsageBucket> = Vec::new();
    if let Some(b) = &raw.five_hour {
      secondary.push(tokn_auth::UsageBucket {
        label: "5h tokens".to_string(),
        used: None,
        total: b.total,
        percent_used: Some(b.percent_used),
        reset_at_ms: b.next_reset_ms,
      });
    }
    if let Some(b) = &raw.weekly {
      secondary.push(tokn_auth::UsageBucket {
        label: "weekly tokens".to_string(),
        used: None,
        total: b.total,
        percent_used: Some(b.percent_used),
        reset_at_ms: b.next_reset_ms,
      });
    }
    if let Some(m) = &raw.mcp_monthly {
      secondary.push(tokn_auth::UsageBucket {
        label: "mcp monthly".to_string(),
        used: Some(m.used),
        total: Some(m.total),
        percent_used: Some(m.percent_used),
        reset_at_ms: m.next_reset_ms,
      });
    }

    Ok(QuotaSnapshot {
      plan: raw.level.clone(),
      headline,
      reset_date: None,
      metered: None,
      secondary,
      // `ZaiQuota` doesn't impl Serialize; serialise a minimal view.
      provider_extra: serde_json::json!({
        "level": raw.level,
        "five_hour_percent": raw.five_hour.as_ref().map(|b| b.percent_used),
        "weekly_percent": raw.weekly.as_ref().map(|b| b.percent_used),
        "mcp_used": raw.mcp_monthly.as_ref().map(|b| b.used),
        "mcp_total": raw.mcp_monthly.as_ref().map(|b| b.total),
      }),
    })
  }
}

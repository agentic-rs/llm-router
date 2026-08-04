use crate::config::CopilotHeaders;
use crate::provider::Result;
use crate::util::redact::token_fingerprint;
use serde_json::Value;
use tokn_core::upstream_url::CanonicalUpstreamUrl;
use tracing::{debug, instrument};

#[instrument(
  name = "copilot_list_models",
  skip_all,
  fields(
    api_token_fp = %token_fingerprint(api_token),
    status = tracing::field::Empty,
    count = tracing::field::Empty,
  ),
)]
pub async fn list(
  client: &reqwest::Client,
  base_url: &CanonicalUpstreamUrl,
  api_token: &str,
  headers: &CopilotHeaders,
) -> Result<Value> {
  let h = crate::headers::copilot_request_headers(api_token, headers, false, "user")?;
  let url = base_url.operation_url(["models"])?;
  debug!("fetching copilot model list");
  let resp = crate::util::http::send(client, reqwest::Method::GET, url.as_str(), h, None, None, "list models").await?;
  let status = resp.status();
  tracing::Span::current().record("status", status.as_u16());
  let v: Value = crate::util::http::read_json(resp, "list models").await?;
  let count = v.get("data").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0);
  tracing::Span::current().record("count", count);
  Ok(v)
}

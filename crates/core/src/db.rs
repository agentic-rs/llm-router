use bytes::Bytes;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct DbPaths {
  pub usage_db: PathBuf,
  pub sessions_db: PathBuf,
  pub requests_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource {
  Header,
  Auto,
}

impl SessionSource {
  pub fn as_str(self) -> &'static str {
    match self {
      SessionSource::Header => "header",
      SessionSource::Auto => "auto",
    }
  }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UsageDetails {
  pub cache_read: Option<u64>,
  pub cache_write: Option<u64>,
  pub reasoning: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageType {
  Chat,
  Responses,
  Messages,
}

impl UsageType {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Chat => "chat",
      Self::Responses => "responses",
      Self::Messages => "messages",
    }
  }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Usage {
  /// Total prompt/input tokens (includes any cached tokens).
  pub input_tokens: Option<u64>,
  /// Completion/output tokens.
  pub output_tokens: Option<u64>,
  /// Provider-reported total tokens. This is intentionally not derived.
  pub total_tokens: Option<u64>,
  pub usage_type: Option<UsageType>,
  pub details: UsageDetails,
}

#[derive(Debug, Clone)]
pub struct MessageRecord {
  pub role: String,
  pub status: Option<u16>,
  pub parts: Vec<PartRecord>,
}

#[derive(Debug, Clone)]
pub struct PartRecord {
  pub part_type: String,
  pub content: Bytes,
}

#[derive(Debug, Clone, Default)]
pub struct HttpSnapshot {
  pub url: Option<String>,
  pub method: Option<String>,
  /// Response status (req side has no status).
  pub status: Option<u16>,
  pub req_headers: tokn_headers::HeaderMap,
  pub req_body: Bytes,
  pub resp_headers: tokn_headers::HeaderMap,
  pub resp_body: Bytes,
}

pub type OutboundSnapshot = HttpSnapshot;

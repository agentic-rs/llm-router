/// Endpoint family that reported token usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UsageKind {
  ChatCompletions,
  Responses,
  Messages,
}

/// Provider-reported token accounting for one request attempt.
///
/// Values remain optional because providers and streaming protocols expose
/// different subsets. `total` is never inferred when the provider omitted it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenUsage {
  pub kind: Option<UsageKind>,
  pub input: Option<u64>,
  pub output: Option<u64>,
  pub total: Option<u64>,
  pub cache_read: Option<u64>,
  pub cache_write: Option<u64>,
  pub reasoning: Option<u64>,
}

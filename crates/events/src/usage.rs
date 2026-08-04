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

impl TokenUsage {
  /// Applies a sparse usage update without erasing previously observed fields.
  ///
  /// Providers may report token categories at different streaming boundaries.
  /// A `Some` value replaces the known value for that field; `None` means the
  /// update carries no new information for that field.
  pub fn merge_from(&mut self, update: &Self) {
    if update.kind.is_some() {
      self.kind = update.kind;
    }
    if update.input.is_some() {
      self.input = update.input;
    }
    if update.output.is_some() {
      self.output = update.output;
    }
    if update.total.is_some() {
      self.total = update.total;
    }
    if update.cache_read.is_some() {
      self.cache_read = update.cache_read;
    }
    if update.cache_write.is_some() {
      self.cache_write = update.cache_write;
    }
    if update.reasoning.is_some() {
      self.reasoning = update.reasoning;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sparse_updates_preserve_fields_the_update_omits() {
    let mut usage = TokenUsage {
      kind: Some(UsageKind::Responses),
      input: Some(10),
      cache_read: Some(4),
      ..TokenUsage::default()
    };

    usage.merge_from(&TokenUsage {
      output: Some(6),
      total: Some(16),
      ..TokenUsage::default()
    });

    assert_eq!(
      usage,
      TokenUsage {
        kind: Some(UsageKind::Responses),
        input: Some(10),
        output: Some(6),
        total: Some(16),
        cache_read: Some(4),
        ..TokenUsage::default()
      }
    );
  }
}

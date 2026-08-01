//! Shared terminal progress surface for interactive CLI work.

use indicatif::{MultiProgress, ProgressDrawTarget};
use std::sync::OnceLock;

static MULTI: OnceLock<MultiProgress> = OnceLock::new();

/// Returns the process-wide progress surface shared by interactive commands
/// and the tracing writer.
pub fn multi() -> &'static MultiProgress {
  MULTI.get_or_init(|| MultiProgress::with_draw_target(ProgressDrawTarget::stdout()))
}

//! Request execution contracts and the legacy composable request pipeline.
//!
//! [`execution`] is the post-dispatch boundary for the v2 runtime. Its
//! borrowed types pin one HTTP attempt to the exact target selected by the
//! router without copying provider, account, or upstream identity.
//!
//! The remaining modules implement the legacy six-stage pipeline:
//!
//! ```text
//! Extract → Resolve → BuildHeaders → ConvertRequest → Send → ConvertResponse
//! ```
//!
//! The v2 execution contract is deliberately outside that pipeline. It does
//! not add a seventh stage or adapt linked v2 targets into legacy route data.

pub mod event;
pub mod executor;
pub mod execution;
pub mod pipeline;
pub mod profile;
pub mod stages;
pub mod utils;

#[cfg(test)]
pub(crate) mod test_support;

pub use event::{CustomEvent, Event, EventBus, EventPayload, Stage, StageEvent};
pub use executor::{ExecutionRequest, PipelineRequestContext, PipelineResponseKind, RequestError, RequestService};
pub use pipeline::{
  ctx::PipelineCtx, error::PipelineError, stages as stage_traits, Pipeline, PipelineRunner, RawInbound, RetryPolicy,
  RunConfig, RunConfigBuilder,
};
pub use profile::Profile;

//! `requests`: greenfield reimplementation of the request pipeline.
//!
//! This crate is a library-only scaffold for the 6-stage pipeline:
//!
//! ```text
//! Extract → Resolve → BuildHeaders → ConvertRequest → Send → ConvertResponse
//! ```
//!
//! Status (PR1): the trait surface and event system are complete. Concrete
//! implementations are provided for the front half (`Extract`, `Resolve`).
//! The back-half stages exist as traits with no-op implementations so the
//! pipeline runner compiles end-to-end; the smoke tests opt into a degenerate
//! Profile that stops after `Resolve` and reports success.
//!
//! Hooks (pre/post) are deliberately omitted from PR1. Per-stage wrapping is
//! expected to be expressed via composition of stage trait impls (decorator
//! pattern) in later PRs.

pub mod event;
pub mod executor;
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

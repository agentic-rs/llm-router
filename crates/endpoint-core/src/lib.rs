//! Shared primitives and traits for typed LLM endpoint wire schemas.
//!
//! This crate intentionally has no knowledge of any specific endpoint
//! beyond identifying which endpoints exist. Endpoint-specific request,
//! response, item, and event types live in the per-endpoint crates and
//! implement the traits exposed here.

pub mod endpoint;
pub mod extras;
pub mod finish;
pub mod lenient;
pub mod role;
pub mod tool;
pub mod traits;

#[cfg(debug_assertions)]
mod extra_keys_impls;

pub use endpoint::{Endpoint, UnknownEndpoint};
pub use extras::Extras;
#[cfg(debug_assertions)]
pub use extras::{join_path, push_extras, ExtraKeys};
pub use finish::FinishReason;
pub use lenient::{
  drain_into_extras, peel_lenient, take_optional, take_optional_default, take_required, LenientFields,
};
pub use role::Role;
pub use tool::{ToolCall, ToolChoice, ToolDef};
pub use traits::{EndpointEvent, EndpointItem, EndpointRequest, EndpointResponse};

//! ConvertRequest stage implementations.
//!
//! Two stage impls live here:
//!
//! * [`NoopConvertRequest`] — echoes the inbound body verbatim. Useful
//!   for tests + transitional Profiles that don't need cross-endpoint
//!   shape changes.
//! * [`DefaultConvertRequest`] — the production stage. Rewrites the
//!   model id, cross-codecs the body between endpoints (chat /
//!   responses / messages) when the inbound endpoint differs from the
//!   account's upstream endpoint, runs the provider's
//!   [`InputTransformer`] (when any), and re-serializes / re-compresses
//!   the result so [`Send`] can drop it straight onto the wire.
//!
//! [`InputTransformer`]: tokn_core::pipeline::InputTransformer
//! [`Send`]: crate::pipeline::stages::SendStage

mod default;
mod noop;
mod passthrough;

pub use default::DefaultConvertRequest;
pub use noop::NoopConvertRequest;
pub use passthrough::PassthroughConvertRequest;

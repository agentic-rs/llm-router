//! Typed wire schemas for the Anthropic Messages API.

pub mod content;
pub mod event;
pub mod message;
pub mod parameters;
pub mod request;
pub mod response;
pub mod usage;

#[cfg(debug_assertions)]
mod extra_keys_impls;

pub use content::{ContentBlock, ContentBlockDelta};
pub use event::MessagesEvent;
pub use message::Message;
pub use parameters::{MessagesExtraParameters, MessagesRequestParameters};
pub use request::{MessagesRequest, MessagesToolChoice, MessagesToolDef, SystemPrompt, DEFAULT_MESSAGES_MAX_TOKENS};
pub use response::MessagesResponse;
pub use usage::MessagesUsage;

use tokn_endpoint_core::{Endpoint, EndpointEvent, EndpointItem, EndpointRequest, EndpointResponse};

impl EndpointRequest for MessagesRequest {
  const ENDPOINT: Endpoint = Endpoint::Messages;
}

impl EndpointResponse for MessagesResponse {
  const ENDPOINT: Endpoint = Endpoint::Messages;
}

impl EndpointItem for Message {
  const ENDPOINT: Endpoint = Endpoint::Messages;
}

impl EndpointEvent for MessagesEvent {
  const ENDPOINT: Endpoint = Endpoint::Messages;

  fn event_name(&self) -> &str {
    self.kind()
  }
}

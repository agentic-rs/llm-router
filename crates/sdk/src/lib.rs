//! Embedded SDK for routing LLM requests through configured providers.
//!
//! A [`Client`] binds one managed profile from the strict version 2 gateway
//! configuration, then executes requests in-process through the same linked
//! account selection, conversion, and provider implementation used by serving.
//! Build separate clients when an application needs separate profiles.

mod client;
mod endpoint;
mod error;
mod generate;
mod response;

pub use client::{Client, ClientBuilder, RequestOptions};
pub use endpoint::{ChatCompletions, Messages, Responses};
pub use error::{Error, Result};
pub use generate::{
  GenerateCall, GenerateEvent, GenerateRequest, GenerateRequestBuilder, GenerateResponse, GenerateStream, Message,
  Role, TextStream, Tool, ToolCall, ToolChoice, Usage,
};
pub use response::{BufferedResponse, ByteStream, RawResponse, ResponseBody, StreamResponse};

pub use tokn_core::generation::{
  GenerationOptions, GenerationOptionsError, ReasoningEffort, ReasoningMode, ReasoningOptions, ReasoningSummary,
};
pub use tokn_core::provider::Endpoint;
pub use tokn_endpoint_chat_completions as chat_completions;
pub use tokn_endpoint_messages as messages;
pub use tokn_endpoint_responses as responses;

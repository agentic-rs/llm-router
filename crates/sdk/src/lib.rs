//! Embedded SDK for routing LLM requests through configured providers.
//!
//! [`Client`] loads the same configuration and credential files as the
//! `tokn-gateway` runtime, then executes requests in-process through the shared
//! account pool, routing, conversion, retry, and provider implementations.

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

pub use tokn_core::provider::Endpoint;
pub use tokn_endpoint_chat_completions as chat_completions;
pub use tokn_endpoint_messages as messages;
pub use tokn_endpoint_responses as responses;

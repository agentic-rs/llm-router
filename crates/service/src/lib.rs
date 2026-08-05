//! Config-independent HTTP and Tower contracts for low-level tokn services.
//!
//! This crate deliberately has no dependency on tokn configuration, account
//! pools, persistence, provider implementations, or built-in header policy.
//! Higher-level crates compile those concerns into an [`HttpService`].

pub mod body;
mod service;

use std::error::Error as StdError;

pub use body::{Body, BodyError};
pub use service::{HttpService, ServiceError};

/// Type-erased thread-safe error used by streaming bodies.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Native low-level HTTP request.
pub type Request = http::Request<Body>;

/// Native low-level HTTP response.
pub type Response = http::Response<Body>;

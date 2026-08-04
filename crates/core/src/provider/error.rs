//! Provider-layer errors.

use snafu::Snafu;

use crate::upstream_url::{InvalidOperationPath, InvalidUpstreamUrl};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
  #[snafu(display("account '{account}' missing required credential: {what}"))]
  MissingCredential { account: String, what: &'static str },

  #[snafu(display("provider mismatch: {expected} expected, got '{got}'"))]
  ProviderMismatch { expected: &'static str, got: String },

  #[snafu(display("unknown provider '{id}' for account '{account}'"))]
  UnknownProvider { id: String, account: String },

  #[snafu(display("invalid upstream URL for account '{account}': {source}"))]
  InvalidUpstreamUrl {
    account: String,
    source: InvalidUpstreamUrl,
  },

  #[snafu(display("invalid upstream operation path: {source}"))]
  InvalidOperationPath { source: InvalidOperationPath },

  #[snafu(display("invalid HTTP header value for '{name}'"))]
  HeaderValue {
    name: String,
    source: reqwest::header::InvalidHeaderValue,
  },

  #[snafu(display("invalid HTTP header name '{name}'"))]
  HeaderName {
    name: String,
    source: reqwest::header::InvalidHeaderName,
  },

  #[snafu(display("{what}: HTTP request failed: {source}"))]
  Http { what: &'static str, source: reqwest::Error },

  #[snafu(display("outbound request observation failed: {message}"))]
  RequestObservation { message: String },

  #[snafu(display("{what}: upstream returned {status}: {body}"))]
  HttpStatus {
    what: &'static str,
    status: reqwest::StatusCode,
    body: String,
  },

  #[snafu(display("{what}: failed to parse JSON: {body}"))]
  Json {
    what: &'static str,
    body: String,
    source: serde_json::Error,
  },

  #[snafu(display("provider '{provider}' does not implement {endpoint}"))]
  UnsupportedEndpoint { provider: String, endpoint: &'static str },

  #[snafu(display("device code expired before authorization"))]
  DeviceCodeExpired,

  #[snafu(display("user denied authorization"))]
  AccessDenied,

  #[snafu(display("oauth error: {code}: {body}"))]
  OAuth { code: String, body: String },

  #[snafu(display("unexpected oauth token response: {body}"))]
  OAuthUnexpected { body: String },

  #[snafu(display("profiles: {message}"))]
  Profiles { message: String },
}

impl From<InvalidOperationPath> for Error {
  fn from(source: InvalidOperationPath) -> Self {
    Self::InvalidOperationPath { source }
  }
}

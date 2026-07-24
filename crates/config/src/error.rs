//! Config-loader errors.

use snafu::Snafu;
use std::path::PathBuf;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
  #[snafu(display("read config `{}`", path.display()))]
  Read { path: PathBuf, source: std::io::Error },

  #[snafu(display("parse config `{}`", path.display()))]
  Parse { path: PathBuf, source: toml::de::Error },

  #[snafu(display("parse config `{}` as editable document", path.display()))]
  ParseEdit {
    path: PathBuf,
    source: toml_edit::TomlError,
  },

  #[snafu(display("serialize config to TOML"))]
  Serialize { source: toml::ser::Error },

  #[snafu(display("create directory `{}`", path.display()))]
  CreateDir { path: PathBuf, source: std::io::Error },

  #[snafu(display("write `{}`", path.display()))]
  Write { path: PathBuf, source: std::io::Error },

  #[snafu(display("set permissions on `{}`", path.display()))]
  SetPermissions { path: PathBuf, source: std::io::Error },

  #[snafu(display("rename `{}` -> `{}`", from.display(), to.display()))]
  Rename {
    from: PathBuf,
    to: PathBuf,
    source: std::io::Error,
  },

  #[snafu(display("could not resolve XDG project dirs"))]
  NoProjectDirs,

  #[snafu(display("[proxy].url is not a valid URL `{url}`: {message}"))]
  ProxyUrl { url: String, message: String },

  #[snafu(display("[proxy].url has unsupported scheme: {scheme}"))]
  ProxyScheme { scheme: String },

  #[snafu(display("[proxy_mode].intercept_hosts contains an invalid hostname: {host:?}"))]
  ProxyInterceptHost { host: String },

  #[snafu(display("[proxy_mode].passthrough_hosts contains an invalid hostname: {host:?}"))]
  ProxyPassthroughHost { host: String },

  #[snafu(display("[server.cors] must set allowed_origins or allow_localhost when CORS is enabled"))]
  CorsOriginsEmpty,

  #[snafu(display("[server.cors].allowed_origins contains an invalid origin {origin:?}: {message}"))]
  InvalidCorsOrigin { origin: String, message: String },

  #[snafu(display("invalid header name in [copilot.extra_headers]: {name:?}"))]
  InvalidHeaderName { name: String },

  #[snafu(display("header {name:?} is reserved and cannot be set via extra_headers"))]
  ReservedHeader { name: String },

  #[snafu(display("account `{id}` is invalid: {message}"))]
  InvalidAccount { id: String, message: String },

  #[snafu(display("validation failed: edited config no longer parses"))]
  EditValidate { source: toml::de::Error },

  #[snafu(display("validation failed: {section}"))]
  EditValidateSection { section: &'static str, source: Box<Error> },

  #[snafu(display("{message}"))]
  Other { message: String },
}

impl From<anyhow::Error> for Error {
  fn from(e: anyhow::Error) -> Self {
    Error::Other {
      message: format!("{e:#}"),
    }
  }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

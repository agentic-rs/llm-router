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

  #[snafu(display(
    "config `{}` uses schema version 2 and cannot be handled by the legacy config API; use the v2 loader",
    path.display()
  ))]
  V2ConfigRequiresV2Loader { path: PathBuf },

  #[snafu(display("config `{}` has a non-integer `schema_version`", path.display()))]
  InvalidSchemaVersion { path: PathBuf },

  #[snafu(display(
    "config `{}` uses unsupported schema version {found}; expected an unversioned legacy config or version 2",
    path.display()
  ))]
  UnsupportedSchemaVersion { path: PathBuf, found: i64 },

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

  #[snafu(display(
    "lock config `{}` using `{}`: {source}",
    path.display(),
    lock_path.display()
  ))]
  ConfigLock {
    path: PathBuf,
    lock_path: PathBuf,
    source: std::io::Error,
  },

  #[snafu(display(
    "config `{}` is being modified by another process (lock `{}` is held); retry the operation",
    path.display(),
    lock_path.display()
  ))]
  ConfigLocked { path: PathBuf, lock_path: PathBuf },

  #[snafu(display(
    "refusing to use symbolic-link config lock `{}` for `{}`",
    lock_path.display(),
    path.display()
  ))]
  ConfigLockSymlink { path: PathBuf, lock_path: PathBuf },

  #[snafu(display(
    "config lock `{}` for `{}` changed while it was being acquired; retry the operation",
    lock_path.display(),
    path.display()
  ))]
  ConfigLockChanged { path: PathBuf, lock_path: PathBuf },

  #[snafu(display("config path `{}` has no file name and cannot be locked", path.display()))]
  InvalidConfigLockPath { path: PathBuf },

  #[snafu(display(
    "resolve config directory `{}` for `{}`",
    parent.display(),
    path.display()
  ))]
  ResolveConfigDirectory {
    path: PathBuf,
    parent: PathBuf,
    source: std::io::Error,
  },

  #[snafu(display("refusing to replace config symlink `{}`", path.display()))]
  ConfigSymlink { path: PathBuf },

  #[snafu(display("refusing to read symbolic-link config source `{}`", path.display()))]
  ConfigSourceSymlink { path: PathBuf },

  #[snafu(display("config source `{}` must be {expected}", path.display()))]
  InvalidConfigSourceType { path: PathBuf, expected: &'static str },

  #[snafu(display("config source `{}` changed while it was being captured; retry the operation", path.display()))]
  ConfigSourceChanged { path: PathBuf },

  #[snafu(display(
    "effective config sources for `{}` changed while they were being loaded or validated; retry the operation",
    path.display()
  ))]
  ConfigSourcesChanged { path: PathBuf },

  #[snafu(display(
    "config lock for `{}` cannot validate source snapshot for `{}`",
    lock_root.display(),
    snapshot_root.display()
  ))]
  ConfigSnapshotLockMismatch { snapshot_root: PathBuf, lock_root: PathBuf },

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

  #[snafu(display("[proxy].url is not a valid URL: {message}"))]
  ProxyUrl { message: String },

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

/// Failure from an exact-preimage configuration edit.
///
/// This is separate from [`Error`] so adding conflict detection does not add a
/// variant to that existing public error enum.
#[derive(Debug)]
#[non_exhaustive]
pub enum GuardedEditError {
  Changed { path: PathBuf },
  Config(Error),
}

impl std::fmt::Display for GuardedEditError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Changed { path } => write!(
        formatter,
        "config `{}` changed before it could be edited; retry the operation",
        path.display()
      ),
      Self::Config(source) => source.fmt(formatter),
    }
  }
}

impl std::error::Error for GuardedEditError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Changed { .. } => None,
      Self::Config(source) => Some(source),
    }
  }
}

impl From<Error> for GuardedEditError {
  fn from(source: Error) -> Self {
    Self::Config(source)
  }
}

pub type GuardedEditResult<T> = std::result::Result<T, GuardedEditError>;

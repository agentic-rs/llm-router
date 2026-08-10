use std::fmt;
use std::path::PathBuf;
use tokn_policy::InvalidIdentifier;

#[derive(Debug)]
pub enum Error {
  Read { path: PathBuf, source: std::io::Error },
  Parse { path: PathBuf, source: toml::de::Error },
  MissingSchemaVersion { path: PathBuf },
  InvalidSchemaVersion { path: PathBuf },
  UnsupportedSchemaVersion { path: PathBuf, found: i64 },
  Compile { path: PathBuf, source: Box<CompileError> },
}

impl fmt::Display for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Read { path, .. } => write!(formatter, "read v2 config `{}`", path.display()),
      Self::Parse { path, .. } => write!(formatter, "parse v2 config `{}`", path.display()),
      Self::MissingSchemaVersion { path } => {
        write!(
          formatter,
          "v2 config `{}` is missing integer `schema_version`",
          path.display()
        )
      }
      Self::InvalidSchemaVersion { path } => {
        write!(
          formatter,
          "v2 config `{}` has a non-integer `schema_version`",
          path.display()
        )
      }
      Self::UnsupportedSchemaVersion { path, found } => write!(
        formatter,
        "config `{}` uses unsupported schema version {found}; expected 2",
        path.display()
      ),
      Self::Compile { path, source } => write!(formatter, "invalid v2 config `{}`: {source}", path.display()),
    }
  }
}

impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Read { source, .. } => Some(source),
      Self::Parse { source, .. } => Some(source),
      Self::Compile { source, .. } => Some(source.as_ref()),
      Self::MissingSchemaVersion { .. } | Self::InvalidSchemaVersion { .. } | Self::UnsupportedSchemaVersion { .. } => {
        None
      }
    }
  }
}

#[derive(Debug)]
pub enum CompileError {
  InvalidIdentifier {
    resource: &'static str,
    source: InvalidIdentifier,
  },
  EmptyRegistry {
    resource: &'static str,
  },
  DuplicateId {
    resource: &'static str,
    id: String,
  },
  DuplicateBind {
    first_listener: String,
    first_bind: String,
    second_listener: String,
    second_bind: String,
  },
  DuplicateOrigin {
    origin: String,
    first_provider: String,
    second_provider: String,
  },
  UnresolvedReference {
    owner_kind: &'static str,
    owner: String,
    field: &'static str,
    target_kind: &'static str,
    target: String,
  },
  InvalidValue {
    location: String,
    message: String,
  },
}

impl fmt::Display for CompileError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidIdentifier { resource, source } => write!(formatter, "invalid {resource}: {source}"),
      Self::EmptyRegistry { resource } => write!(formatter, "at least one {resource} must be configured"),
      Self::DuplicateId { resource, id } => write!(formatter, "duplicate {resource} id `{id}`"),
      Self::DuplicateBind {
        first_listener,
        first_bind,
        second_listener,
        second_bind,
      } => write!(
        formatter,
        "listener `{first_listener}` bind `{first_bind}` overlaps listener `{second_listener}` bind `{second_bind}`"
      ),
      Self::DuplicateOrigin {
        origin,
        first_provider,
        second_provider,
      } => write!(
        formatter,
        "providers `{first_provider}` and `{second_provider}` both own origin `{origin}`"
      ),
      Self::UnresolvedReference {
        owner_kind,
        owner,
        field,
        target_kind,
        target,
      } => write!(
        formatter,
        "{owner_kind} `{owner}` field `{field}` references unknown {target_kind} `{target}`"
      ),
      Self::InvalidValue { location, message } => write!(formatter, "{location}: {message}"),
    }
  }
}

impl std::error::Error for CompileError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::InvalidIdentifier { source, .. } => Some(source),
      _ => None,
    }
  }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

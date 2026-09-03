//! Catalogue source resolution.
//!
//! At process start we pick exactly one source and freeze it: either the
//! disk cache (if a previous `tokn-router update` left one) or the snapshot
//! embedded at build time. There is no auto-refresh — the explicit `update`
//! subcommand is the only way to grow the cached copy.

use snafu::{ResultExt, Snafu};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

use super::schema::Catalogue;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
  #[snafu(display("HTTP GET {url} failed"))]
  Fetch { url: String, source: reqwest::Error },

  #[snafu(display("read response body from {url}"))]
  ReadBody { url: String, source: reqwest::Error },

  #[snafu(display("{url} returned HTTP {status}"))]
  HttpStatus { url: String, status: reqwest::StatusCode },

  #[snafu(display("parse {url} as models.dev catalogue"))]
  Parse { url: String, source: serde_json::Error },

  #[snafu(display("{url} returned an empty catalogue"))]
  EmptyCatalogue { url: String },

  #[snafu(display("could not resolve a cache directory"))]
  NoCacheDir,

  #[snafu(display("create cache dir `{}`", path.display()))]
  CreateCacheDir { path: PathBuf, source: std::io::Error },

  #[snafu(display("write `{}`", path.display()))]
  Write { path: PathBuf, source: std::io::Error },

  #[snafu(display("atomic rename to `{}`", path.display()))]
  Rename { path: PathBuf, source: std::io::Error },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Where the loaded catalogue came from. Surfaced by `update --status`.
#[derive(Debug, Clone)]
pub enum Source {
  /// Compile-time `include_bytes!` of `models.dev/api.json`.
  Embedded,
  /// On-disk JSON, written by `tokn-router update`.
  DiskCache(PathBuf),
}

/// The embedded snapshot, baked in by `build.rs`.
const EMBEDDED: &[u8] = include_bytes!(env!("MODELS_DEV_SNAPSHOT_PATH"));

static GLOBAL: OnceLock<(Catalogue, Source)> = OnceLock::new();

/// Path of the on-disk catalogue cache, if we can determine an XDG cache dir.
pub fn cache_path() -> Option<PathBuf> {
  tokn_core::util::paths::cache_dir().map(|dir| dir.join("catalogue.json"))
}

/// Borrow the global catalogue, loading it on first call.
///
/// Lookup order:
///   1. On-disk cache at [`cache_path`] — the result of a successful
///      `tokn-router update`.
///   2. The embedded snapshot — always present, always parses.
///
/// If the disk cache exists but fails to parse we log a warning and fall
/// back to the embedded copy.
pub fn global() -> &'static Catalogue {
  &load_global().0
}

/// Same as [`global`] but also returns where the data came from.
pub fn global_with_source() -> &'static (Catalogue, Source) {
  load_global()
}

fn load_global() -> &'static (Catalogue, Source) {
  GLOBAL.get_or_init(|| {
    let (cat, src) = match try_disk_cache() {
      Some((c, p)) => (c, Source::DiskCache(p)),
      None => (parse_embedded(), Source::Embedded),
    };
    let providers = cat.len();
    let models: usize = cat.values().map(|p| p.models.len()).sum();
    match &src {
      Source::DiskCache(p) => {
        tracing::info!(source = "disk_cache", path = %p.display(), providers, models, "models.dev catalogue loaded");
      }
      Source::Embedded => {
        tracing::info!(source = "embedded", providers, models, "models.dev catalogue loaded");
      }
    }
    (cat, src)
  })
}

fn try_disk_cache() -> Option<(Catalogue, PathBuf)> {
  let path = cache_path()?;
  let bytes = std::fs::read(&path).ok()?;
  match serde_json::from_slice::<Catalogue>(&bytes) {
    Ok(c) => Some((c, path)),
    Err(e) => {
      tracing::warn!(
          cache = %path.display(),
          error = %e,
          "models.dev cache failed to parse; falling back to embedded snapshot"
      );
      None
    }
  }
}

fn parse_embedded() -> Catalogue {
  serde_json::from_slice(EMBEDDED).expect("embedded models.dev snapshot must parse — fix build.rs")
}

/// Outcome of a successful `tokn-router update` run.
#[derive(Debug)]
pub struct UpdateReport {
  pub providers: usize,
  pub models: usize,
  pub bytes: u64,
  pub path: PathBuf,
  pub elapsed: std::time::Duration,
}

/// Fetch `url`, validate, atomically replace the on-disk cache.
///
/// The fetched bytes must:
///   * parse as our [`Catalogue`] schema, and
///   * contain at least one provider (defends against silent empty payloads).
#[tracing::instrument(name = "catalogue_update", skip_all, fields(%url, status = tracing::field::Empty, providers = tracing::field::Empty, models = tracing::field::Empty, bytes = tracing::field::Empty))]
pub async fn fetch_and_persist(http: &reqwest::Client, url: &str) -> Result<UpdateReport> {
  let started = Instant::now();
  tracing::debug!("fetching catalogue");
  let resp = http
    .get(url)
    .send()
    .await
    .context(FetchSnafu { url: url.to_string() })?;
  let status = resp.status();
  tracing::Span::current().record("status", status.as_u16());
  let body = resp.bytes().await.context(ReadBodySnafu { url: url.to_string() })?;
  if !status.is_success() {
    return HttpStatusSnafu {
      url: url.to_string(),
      status,
    }
    .fail();
  }
  let parsed: Catalogue = serde_json::from_slice(&body).context(ParseSnafu { url: url.to_string() })?;
  if parsed.is_empty() {
    return EmptyCatalogueSnafu { url: url.to_string() }.fail();
  }
  let models: usize = parsed.values().map(|p| p.models.len()).sum();
  let span = tracing::Span::current();
  span.record("providers", parsed.len());
  span.record("models", models);
  span.record("bytes", body.len() as u64);

  let path = cache_path().ok_or(Error::NoCacheDir)?;
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).context(CreateCacheDirSnafu {
      path: parent.to_path_buf(),
    })?;
  }

  // Atomic rename: write a sibling `.tmp` then rename onto the final path.
  let tmp = path.with_extension("json.tmp");
  std::fs::write(&tmp, &body).context(WriteSnafu { path: tmp.clone() })?;
  std::fs::rename(&tmp, &path).context(RenameSnafu { path: path.clone() })?;
  tracing::info!(path = %path.display(), providers = parsed.len(), models, "catalogue updated");

  Ok(UpdateReport {
    providers: parsed.len(),
    models,
    bytes: body.len() as u64,
    path,
    elapsed: started.elapsed(),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn embedded_snapshot_parses() {
    let c = parse_embedded();
    assert!(!c.is_empty(), "embedded snapshot must contain providers");
    assert!(c.contains_key("github-copilot"), "missing github-copilot");
    for id in ["zai", "zai-coding-plan", "zhipuai", "zhipuai-coding-plan"] {
      assert!(c.contains_key(id), "missing provider {id}");
    }
  }

  #[test]
  fn copilot_has_models() {
    let c = parse_embedded();
    let p = c.get("github-copilot").unwrap();
    assert!(!p.models.is_empty(), "github-copilot has no models");
  }

  #[test]
  fn embedded_deepseek_efforts_are_model_specific() {
    let catalogue = parse_embedded();
    let models = &catalogue["deepseek"].models;
    assert_eq!(
      serde_json::to_value(models["deepseek-v4-flash"].reasoning_efforts()).unwrap(),
      serde_json::json!(["low", "high", "max"])
    );
    assert_eq!(
      serde_json::to_value(models["deepseek-v4-pro"].reasoning_efforts()).unwrap(),
      serde_json::json!(["high", "max"])
    );
    assert!(models["deepseek-reasoner"].reasoning_efforts().is_none());
  }
}

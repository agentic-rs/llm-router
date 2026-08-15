use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use time::{Date, Duration, Month, OffsetDateTime};
use tokio::sync::{mpsc, oneshot};

const SCAN_INTERVAL: StdDuration = StdDuration::from_secs(6 * 60 * 60);
const MAINTENANCE_LOCK_FILE: &str = ".tokn-requests-maintenance.lock";
const SECONDS_PER_DAY: i64 = 86_400;
static PRUNE_QUARANTINE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveStats {
  pub archived: usize,
  pub skipped_existing: usize,
  pub failed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruneReport {
  pub cutoff: Date,
  pub entries: Vec<PruneEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruneEntry {
  pub path: PathBuf,
  pub archive: PathBuf,
  pub outcome: PruneOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PruneOutcome {
  Verified {
    sha256: String,
  },
  Deleted {
    sha256: String,
  },
  MissingArchive,
  HashMismatch {
    source_sha256: String,
    archived_sha256: String,
  },
  Failed {
    error: String,
  },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PruneProgressEvent {
  Started {
    files_total: usize,
  },
  FileStarted {
    path: PathBuf,
    file_index: usize,
    files_total: usize,
    bytes_total: u64,
  },
  FileProgress {
    bytes_processed: u64,
    bytes_total: u64,
  },
  FileFinished {
    path: PathBuf,
    file_index: usize,
    files_total: usize,
  },
  Finished {
    files_total: usize,
  },
}

pub(crate) struct RequestMaintenanceLock {
  _file: File,
}

struct StableFile {
  path: PathBuf,
  file: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveFormat {
  Zstd,
  Xz,
}

impl ArchiveFormat {
  fn resolve(configured_extension: Option<&str>) -> Self {
    let Some(value) = configured_extension.map(str::trim).filter(|value| !value.is_empty()) else {
      return Self::default();
    };
    let normalized = value.trim_start_matches('.').to_ascii_lowercase();
    match normalized.as_str() {
      "zstd" | "db.zstd" => Self::Zstd,
      "xz" | "db.xz" | "lzma" | "db.lzma" if cfg!(feature = "lzma") => Self::Xz,
      "xz" | "db.xz" | "lzma" | "db.lzma" => {
        tracing::warn!(
          archive_extension = value,
          "LZMA archive extension requested without lzma feature; falling back to zstd"
        );
        Self::Zstd
      }
      _ => {
        tracing::warn!(
          archive_extension = value,
          "unsupported archive extension; falling back to zstd"
        );
        Self::Zstd
      }
    }
  }

  fn extension(self) -> &'static str {
    match self {
      Self::Zstd => "db.zstd",
      Self::Xz => "db.xz",
    }
  }
}

impl Default for ArchiveFormat {
  fn default() -> Self {
    if cfg!(feature = "lzma") {
      Self::Xz
    } else {
      Self::Zstd
    }
  }
}

impl RequestMaintenanceLock {
  fn acquire(dir: &Path) -> io::Result<Self> {
    let lock_path = dir.join(MAINTENANCE_LOCK_FILE);
    let file = open_maintenance_lock(&lock_path)?;
    match file.try_lock() {
      Ok(()) => {
        revalidate_opened_file(&lock_path, &file, true)?;
        Ok(Self { _file: file })
      }
      Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        format!(
          "request database maintenance is already running for {}; retry the command",
          dir.display()
        ),
      )),
      Err(fs::TryLockError::Error(error)) => Err(error),
    }
  }

  pub(crate) fn acquire_writer(dir: &Path) -> io::Result<Self> {
    let lock_path = dir.join(MAINTENANCE_LOCK_FILE);
    let file = open_maintenance_lock(&lock_path)?;
    file.lock()?;
    revalidate_opened_file(&lock_path, &file, true)?;
    Ok(Self { _file: file })
  }
}

impl StableFile {
  fn open(path: &Path) -> io::Result<Self> {
    validate_regular_file_path(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options.open(path)?;
    revalidate_opened_file(path, &file, true)?;
    Ok(Self {
      path: path.to_path_buf(),
      file,
    })
  }

  fn revalidate(&self) -> io::Result<()> {
    self.revalidate_at(&self.path)
  }

  fn revalidate_at(&self, path: &Path) -> io::Result<()> {
    revalidate_opened_file(path, &self.file, true)
  }

  fn rewind(&mut self) -> io::Result<()> {
    self.file.rewind()
  }
}

fn open_maintenance_lock(path: &Path) -> io::Result<File> {
  validate_regular_file_path(path, true)?;
  let mut options = OpenOptions::new();
  options.create(true).truncate(false).read(true).write(true);
  configure_no_follow(&mut options);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
  }
  let file = options.open(path)?;
  revalidate_opened_file(path, &file, true)?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
  }
  Ok(file)
}

#[cfg(unix)]
fn configure_no_follow(options: &mut OpenOptions) {
  use std::os::unix::fs::OpenOptionsExt;
  options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
  use std::os::windows::fs::OpenOptionsExt;
  const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
  options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow(_options: &mut OpenOptions) {}

fn validate_regular_file_path(path: &Path, allow_missing: bool) -> io::Result<()> {
  match fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_symlink() => Err(invalid_file(path, "must not be a symlink")),
    Ok(metadata) if !metadata.is_file() => Err(invalid_file(path, "must be a regular file")),
    Ok(_) => Ok(()),
    Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => Ok(()),
    Err(error) => Err(error),
  }
}

fn revalidate_opened_file(path: &Path, file: &File, require_single_link: bool) -> io::Result<()> {
  validate_regular_file_path(path, false)?;
  #[cfg(any(unix, windows))]
  {
    let opened = same_file::Handle::from_file(file.try_clone()?)?;
    let linked = same_file::Handle::from_path(path)?;
    if opened != linked {
      return Err(invalid_file(path, "changed while it was being opened or used"));
    }
  }
  #[cfg(any(unix, windows))]
  if require_single_link && file_link_count(file)? != 1 {
    return Err(invalid_file(path, "must not have multiple hard links"));
  }
  #[cfg(not(any(unix, windows)))]
  let _ = require_single_link;
  Ok(())
}

#[cfg(unix)]
fn file_link_count(file: &File) -> io::Result<u64> {
  use std::os::unix::fs::MetadataExt;
  Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn file_link_count(file: &File) -> io::Result<u64> {
  use std::os::windows::io::AsRawHandle;
  use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

  let mut info = BY_HANDLE_FILE_INFORMATION::default();
  // SAFETY: the raw handle remains owned by `file` and `info` is writable for the duration of the call.
  if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
    return Err(io::Error::last_os_error());
  }
  Ok(u64::from(info.nNumberOfLinks))
}

fn invalid_file(path: &Path, reason: &str) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidInput, format!("{} {reason}", path.display()))
}

#[derive(Clone, Debug)]
pub enum ArchiveEvent {
  ScanStarted {
    dir: PathBuf,
  },
  FileStarted {
    id: String,
    path: PathBuf,
    archive: PathBuf,
    total_bytes: u64,
  },
  FileProgress {
    id: String,
    bytes_read: u64,
    total_bytes: u64,
  },
  FileCompleted {
    id: String,
    path: PathBuf,
    archive: PathBuf,
    bytes_in: u64,
    bytes_out: u64,
  },
  FileSkipped {
    path: PathBuf,
    archive: PathBuf,
  },
  FileFailed {
    id: String,
    path: PathBuf,
    archive: PathBuf,
    error: String,
  },
  ScanCompleted {
    dir: PathBuf,
    stats: ArchiveStats,
  },
}

enum ArchiveBusMessage {
  Event(ArchiveEvent),
  Shutdown(oneshot::Sender<()>),
}

pub trait ArchiveEmitter: Send + Sync {
  fn emit(&self, event: ArchiveEvent);
}

#[derive(Clone)]
pub struct ArchiveEventBus {
  tx: mpsc::Sender<ArchiveBusMessage>,
}

pub struct ArchiveEventReceiver {
  rx: mpsc::Receiver<ArchiveBusMessage>,
}

pub trait ArchiveEventHandler: Send + 'static {
  fn handle(&mut self, event: &ArchiveEvent);
  fn flush(&mut self) {}
}

pub struct ArchiveRuntime {
  bus: ArchiveEventBus,
  worker: tokio::task::JoinHandle<()>,
  cancelled: Arc<AtomicBool>,
  _event_thread: std::thread::JoinHandle<()>,
}

impl ArchiveEventBus {
  pub fn new(capacity: usize) -> (Self, ArchiveEventReceiver) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    (Self { tx }, ArchiveEventReceiver { rx })
  }

  pub async fn shutdown(&self) {
    let (tx, rx) = oneshot::channel();
    let _ = self.tx.send(ArchiveBusMessage::Shutdown(tx)).await;
    let _ = rx.await;
  }
}

impl ArchiveEmitter for ArchiveEventBus {
  fn emit(&self, event: ArchiveEvent) {
    match self.tx.try_send(ArchiveBusMessage::Event(event)) {
      Ok(()) => {}
      Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!("archive event bus full, dropping event"),
      Err(mpsc::error::TrySendError::Closed(_)) => tracing::warn!("archive event bus closed, dropping event"),
    }
  }
}

impl ArchiveEventReceiver {
  fn blocking_recv(&mut self) -> Option<ArchiveBusMessage> {
    self.rx.blocking_recv()
  }
}

impl ArchiveRuntime {
  pub async fn shutdown(self) {
    self.cancelled.store(true, Ordering::Relaxed);
    if let Err(err) = self.worker.await {
      if !err.is_cancelled() {
        tracing::warn!(error = %err, "request db archival worker shutdown failed");
      }
    }
    self.bus.shutdown().await;
  }
}

pub fn spawn_archive_event_loop(
  mut receiver: ArchiveEventReceiver,
  mut handlers: Vec<Box<dyn ArchiveEventHandler>>,
) -> std::thread::JoinHandle<()> {
  std::thread::spawn(move || {
    let mut flushed = false;
    while let Some(message) = receiver.blocking_recv() {
      match message {
        ArchiveBusMessage::Event(event) => {
          for handler in &mut handlers {
            handler.handle(&event);
          }
        }
        ArchiveBusMessage::Shutdown(done) => {
          for handler in &mut handlers {
            handler.flush();
          }
          flushed = true;
          let _ = done.send(());
          break;
        }
      }
    }
    if !flushed {
      for handler in &mut handlers {
        handler.flush();
      }
    }
  })
}

pub fn start_request_archive_worker(
  requests_dir: PathBuf,
  archive_extension: Option<&str>,
  archive_after_days: i64,
  handlers: Vec<Box<dyn ArchiveEventHandler>>,
) -> Option<ArchiveRuntime> {
  let Ok(handle) = tokio::runtime::Handle::try_current() else {
    tracing::warn!(path = %requests_dir.display(), "request db archival disabled: no tokio runtime");
    return None;
  };

  let (bus, receiver) = ArchiveEventBus::new(1024);
  let event_thread = spawn_archive_event_loop(receiver, handlers);
  let worker_bus = bus.clone();
  let cancelled = Arc::new(AtomicBool::new(false));
  let worker_cancelled = cancelled.clone();
  let format = ArchiveFormat::resolve(archive_extension);
  let worker = handle.spawn(async move {
    loop {
      if worker_cancelled.load(Ordering::Relaxed) {
        break;
      }
      let dir = requests_dir.clone();
      let events = worker_bus.clone();
      let scan_cancelled = worker_cancelled.clone();
      match tokio::task::spawn_blocking(move || {
        archive_requests_once_with_events(
          &dir,
          OffsetDateTime::now_utc().date(),
          archive_after_days,
          format,
          Some(&events),
          Some(scan_cancelled.as_ref()),
        )
      })
      .await
      {
        Ok(Ok(stats)) if stats.archived > 0 || stats.skipped_existing > 0 || stats.failed > 0 => {
          tracing::info!(
            path = %requests_dir.display(),
            archived = stats.archived,
            skipped_existing = stats.skipped_existing,
            failed = stats.failed,
            "request db archival scan completed"
          );
        }
        Ok(Ok(_)) => {}
        Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => {}
        Ok(Err(err)) => tracing::warn!(path = %requests_dir.display(), error = %err, "request db archival scan failed"),
        Err(err) => tracing::warn!(path = %requests_dir.display(), error = %err, "request db archival worker failed"),
      }
      tokio::select! {
        _ = tokio::time::sleep(SCAN_INTERVAL) => {}
        _ = wait_cancelled(worker_cancelled.clone()) => break,
      }
    }
  });

  Some(ArchiveRuntime {
    bus,
    worker,
    cancelled,
    _event_thread: event_thread,
  })
}

async fn wait_cancelled(cancelled: Arc<AtomicBool>) {
  while !cancelled.load(Ordering::Relaxed) {
    tokio::time::sleep(StdDuration::from_millis(100)).await;
  }
}

/// Verify old request database archives and optionally remove their source
/// `.db` files. Archive bytes are decompressed before hashing so the digest is
/// compared against the original database content.
pub fn prune_request_dbs(
  dir: &Path,
  archive_extension: Option<&str>,
  prune_after_days: i64,
  commit: bool,
) -> io::Result<PruneReport> {
  prune_request_dbs_with_progress(dir, archive_extension, prune_after_days, commit, |_| {})
}

pub fn prune_request_dbs_with_progress(
  dir: &Path,
  archive_extension: Option<&str>,
  prune_after_days: i64,
  commit: bool,
  mut progress: impl FnMut(PruneProgressEvent),
) -> io::Result<PruneReport> {
  prune_request_dbs_once_with_progress(
    dir,
    OffsetDateTime::now_utc().date(),
    prune_after_days,
    ArchiveFormat::resolve(archive_extension),
    commit,
    &mut progress,
  )
}

#[cfg(test)]
fn prune_request_dbs_once(
  dir: &Path,
  today: Date,
  prune_after_days: i64,
  format: ArchiveFormat,
  commit: bool,
) -> io::Result<PruneReport> {
  prune_request_dbs_once_with_progress(
    dir,
    today,
    prune_after_days,
    format,
    commit,
    &mut |_: PruneProgressEvent| {},
  )
}

fn prune_request_dbs_once_with_progress(
  dir: &Path,
  today: Date,
  prune_after_days: i64,
  format: ArchiveFormat,
  commit: bool,
  progress: &mut impl FnMut(PruneProgressEvent),
) -> io::Result<PruneReport> {
  let cutoff = retention_cutoff(today, prune_after_days, "prune")?;
  let mut report = PruneReport {
    cutoff,
    entries: Vec::new(),
  };
  let _lock = match RequestMaintenanceLock::acquire(dir) {
    Ok(lock) => lock,
    Err(error) if error.kind() == io::ErrorKind::NotFound => {
      progress(PruneProgressEvent::Started { files_total: 0 });
      progress(PruneProgressEvent::Finished { files_total: 0 });
      return Ok(report);
    }
    Err(error) => return Err(error),
  };
  let mut paths = Vec::new();
  for entry in fs::read_dir(dir)? {
    let path = entry?.path();
    if is_archivable_request_db(&path, cutoff) {
      paths.push(path);
    }
  }
  paths.sort();

  let files_total = paths.len();
  progress(PruneProgressEvent::Started { files_total });
  for (file_index, path) in paths.into_iter().enumerate() {
    let archive = archive_path(&path, format);
    let bytes_per_pass = fs::symlink_metadata(&path).map(|metadata| metadata.len()).unwrap_or(0);
    let bytes_total = bytes_per_pass.saturating_mul(if commit { 4 } else { 2 });
    progress(PruneProgressEvent::FileStarted {
      path: path.clone(),
      file_index,
      files_total,
      bytes_total,
    });
    let mut bytes_processed = 0u64;
    let mut report_bytes = |bytes: u64| {
      bytes_processed = bytes_processed.saturating_add(bytes);
      progress(PruneProgressEvent::FileProgress {
        bytes_processed,
        bytes_total,
      });
    };
    let outcome = prune_request_db(&path, &archive, format, commit, &mut report_bytes);
    progress(PruneProgressEvent::FileFinished {
      path: path.clone(),
      file_index,
      files_total,
    });
    report.entries.push(PruneEntry { path, archive, outcome });
  }
  progress(PruneProgressEvent::Finished { files_total });
  Ok(report)
}

fn prune_request_db(
  db: &Path,
  archive: &Path,
  format: ArchiveFormat,
  commit: bool,
  progress: &mut impl FnMut(u64),
) -> PruneOutcome {
  let mut archive_file = match StableFile::open(archive) {
    Ok(file) => file,
    Err(error) if error.kind() == io::ErrorKind::NotFound => return PruneOutcome::MissingArchive,
    Err(error) => {
      return PruneOutcome::Failed {
        error: format!("open archive {}: {error}", archive.display()),
      };
    }
  };
  let mut source_file = match StableFile::open(db) {
    Ok(file) => file,
    Err(error) => {
      return PruneOutcome::Failed {
        error: format!("open request database {}: {error}", db.display()),
      };
    }
  };

  let archived_digest = match hash_archive(&mut archive_file, format, progress) {
    Ok(digest) => digest,
    Err(error) => {
      return PruneOutcome::Failed {
        error: format!("verify archive {}: {error}", archive.display()),
      };
    }
  };
  let source_digest = match hash_file(&mut source_file, progress) {
    Ok(digest) => digest,
    Err(error) => {
      return PruneOutcome::Failed {
        error: format!("hash request database {}: {error}", db.display()),
      };
    }
  };
  let source_sha256 = hex_digest(&source_digest);
  if source_digest != archived_digest {
    return PruneOutcome::HashMismatch {
      source_sha256,
      archived_sha256: hex_digest(&archived_digest),
    };
  }
  if !commit {
    return PruneOutcome::Verified { sha256: source_sha256 };
  }

  match hash_archive(&mut archive_file, format, progress) {
    Ok(current_digest) if current_digest == archived_digest => {}
    Ok(_) => {
      return PruneOutcome::Failed {
        error: format!("archive {} changed during verification", archive.display()),
      };
    }
    Err(error) => {
      return PruneOutcome::Failed {
        error: format!("recheck archive {}: {error}", archive.display()),
      };
    }
  }
  match hash_file(&mut source_file, progress) {
    Ok(current_digest) if current_digest == source_digest => {}
    Ok(_) => {
      return PruneOutcome::Failed {
        error: format!("request database {} changed during verification", db.display()),
      };
    }
    Err(error) => {
      return PruneOutcome::Failed {
        error: format!("recheck request database {}: {error}", db.display()),
      };
    }
  }
  if let Err(error) = archive_file.revalidate() {
    return PruneOutcome::Failed {
      error: format!("revalidate archive {} before deletion: {error}", archive.display()),
    };
  }
  match remove_stable_file(source_file) {
    Ok(()) => PruneOutcome::Deleted { sha256: source_sha256 },
    Err(error) => PruneOutcome::Failed {
      error: format!("delete verified request database {}: {error}", db.display()),
    },
  }
}

fn hash_file(file: &mut StableFile, progress: &mut impl FnMut(u64)) -> io::Result<[u8; 32]> {
  file.rewind()?;
  let digest = hash_reader(&mut file.file, progress)?;
  file.revalidate()?;
  Ok(digest)
}

fn hash_archive(file: &mut StableFile, format: ArchiveFormat, progress: &mut impl FnMut(u64)) -> io::Result<[u8; 32]> {
  file.rewind()?;
  let digest = match format {
    ArchiveFormat::Zstd => hash_reader(zstd::stream::read::Decoder::new(&mut file.file)?, progress),
    ArchiveFormat::Xz => hash_xz_archive(&mut file.file, progress),
  }?;
  file.revalidate()?;
  Ok(digest)
}

fn remove_stable_file(file: StableFile) -> io::Result<()> {
  file.revalidate()?;
  let quarantine = unused_quarantine_path(&file.path)?;
  fs::rename(&file.path, &quarantine)?;
  if let Err(error) = file.revalidate_at(&quarantine) {
    return Err(restore_quarantined_file(&quarantine, &file.path, error));
  }
  if let Err(error) = fs::remove_file(&quarantine) {
    return Err(restore_quarantined_file(&quarantine, &file.path, error));
  }
  Ok(())
}

fn unused_quarantine_path(path: &Path) -> io::Result<PathBuf> {
  let parent = path.parent().unwrap_or_else(|| Path::new("."));
  let name = path
    .file_name()
    .ok_or_else(|| invalid_file(path, "must name a file"))?
    .to_string_lossy();
  loop {
    let sequence = PRUNE_QUARANTINE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let candidate = parent.join(format!(".{name}.prune-{}-{sequence}.tmp", std::process::id()));
    match fs::symlink_metadata(&candidate) {
      Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
      Err(error) => return Err(error),
      Ok(_) => {}
    }
  }
}

fn restore_quarantined_file(quarantine: &Path, original: &Path, cause: io::Error) -> io::Error {
  match fs::symlink_metadata(original) {
    Ok(_) => {
      return io::Error::new(
        cause.kind(),
        format!(
          "{cause}; verified data was retained at {} because {} was recreated",
          quarantine.display(),
          original.display()
        ),
      );
    }
    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
    Err(error) => {
      return io::Error::new(
        cause.kind(),
        format!(
          "{cause}; verified data was retained at {} because inspecting {} failed: {error}",
          quarantine.display(),
          original.display()
        ),
      );
    }
  }
  match fs::rename(quarantine, original) {
    Ok(()) => cause,
    Err(restore_error) => io::Error::new(
      cause.kind(),
      format!(
        "{cause}; verified data was retained at {} because restoring {} failed: {restore_error}",
        quarantine.display(),
        original.display()
      ),
    ),
  }
}

fn hash_reader(mut reader: impl Read, progress: &mut impl FnMut(u64)) -> io::Result<[u8; 32]> {
  let mut digest = Sha256::new();
  let mut buffer = [0u8; 64 * 1024];
  loop {
    let read = reader.read(&mut buffer)?;
    if read == 0 {
      break;
    }
    digest.update(&buffer[..read]);
    progress(read as u64);
  }
  Ok(digest.finalize().into())
}

fn hex_digest(digest: &[u8; 32]) -> String {
  let mut encoded = String::with_capacity(digest.len() * 2);
  for byte in digest {
    write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
  }
  encoded
}

fn retention_cutoff(today: Date, retention_days: i64, operation: &str) -> io::Result<Date> {
  if retention_days <= 0 {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("{operation}_after_days must be greater than zero"),
    ));
  }
  let seconds = retention_days.checked_mul(SECONDS_PER_DAY).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("{operation}_after_days is too large for a time duration"),
    )
  })?;
  today.checked_sub(Duration::seconds(seconds)).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("{operation} retention cutoff is outside the supported date range"),
    )
  })
}

#[cfg(feature = "lzma")]
fn hash_xz_archive(file: impl Read, progress: &mut impl FnMut(u64)) -> io::Result<[u8; 32]> {
  hash_reader(lzma_rust2::XzReader::new(file, false), progress)
}

#[cfg(not(feature = "lzma"))]
fn hash_xz_archive(_file: impl Read, _progress: &mut impl FnMut(u64)) -> io::Result<[u8; 32]> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "xz archive decompression requires the lzma feature",
  ))
}

#[cfg(test)]
pub fn archive_requests_once(
  dir: &Path,
  today: Date,
  archive_after_days: i64,
  format: ArchiveFormat,
) -> io::Result<ArchiveStats> {
  archive_requests_once_with_events(dir, today, archive_after_days, format, None, None)
}

fn archive_requests_once_with_events(
  dir: &Path,
  today: Date,
  archive_after_days: i64,
  format: ArchiveFormat,
  events: Option<&dyn ArchiveEmitter>,
  cancelled: Option<&AtomicBool>,
) -> io::Result<ArchiveStats> {
  let cutoff = retention_cutoff(today, archive_after_days, "archive")?;
  let _lock = match RequestMaintenanceLock::acquire(dir) {
    Ok(lock) => lock,
    Err(error) if error.kind() == io::ErrorKind::NotFound => return empty_archive_scan(dir, events),
    Err(error) => return Err(error),
  };
  archive_requests_once_locked(dir, cutoff, format, events, cancelled)
}

fn empty_archive_scan(dir: &Path, events: Option<&dyn ArchiveEmitter>) -> io::Result<ArchiveStats> {
  let stats = ArchiveStats::default();
  emit(events, ArchiveEvent::ScanStarted { dir: dir.to_path_buf() });
  emit(
    events,
    ArchiveEvent::ScanCompleted {
      dir: dir.to_path_buf(),
      stats: stats.clone(),
    },
  );
  Ok(stats)
}

fn archive_requests_once_locked(
  dir: &Path,
  cutoff: Date,
  format: ArchiveFormat,
  events: Option<&dyn ArchiveEmitter>,
  cancelled: Option<&AtomicBool>,
) -> io::Result<ArchiveStats> {
  let mut stats = ArchiveStats::default();
  emit(events, ArchiveEvent::ScanStarted { dir: dir.to_path_buf() });
  for entry in fs::read_dir(dir)? {
    check_cancelled(cancelled)?;
    let entry = entry?;
    let path = entry.path();
    if !is_archivable_request_db(&path, cutoff) {
      continue;
    }

    let archive = archive_path(&path, format);
    let id = archive_id(&path);
    if archive.exists() {
      stats.skipped_existing += 1;
      emit(events, ArchiveEvent::FileSkipped { path, archive });
      continue;
    }

    match compress_db(&path, &archive, format, events, cancelled, &id) {
      Ok(()) => stats.archived += 1,
      Err(err) if err.kind() == io::ErrorKind::Interrupted => return Err(err),
      Err(err) => {
        stats.failed += 1;
        emit(
          events,
          ArchiveEvent::FileFailed {
            id,
            path: path.clone(),
            archive: archive.clone(),
            error: err.to_string(),
          },
        );
        tracing::warn!(path = %path.display(), archive = %archive.display(), error = %err, "request db archive failed");
      }
    }
  }

  emit(
    events,
    ArchiveEvent::ScanCompleted {
      dir: dir.to_path_buf(),
      stats: stats.clone(),
    },
  );
  Ok(stats)
}

fn is_archivable_request_db(path: &Path, cutoff: Date) -> bool {
  if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
    || path.extension().and_then(|v| v.to_str()) != Some("db")
  {
    return false;
  }
  let Some(stem) = path.file_stem().and_then(|v| v.to_str()) else {
    return false;
  };
  parse_day(stem).is_some_and(|day| day <= cutoff)
}

fn archive_path(path: &Path, format: ArchiveFormat) -> PathBuf {
  path.with_extension(format.extension())
}

fn temp_archive_path(archive: &Path) -> PathBuf {
  let mut name = archive
    .file_name()
    .and_then(|v| v.to_str())
    .unwrap_or("archive.db.zstd")
    .to_string();
  name.push_str(".tmp");
  archive.with_file_name(name)
}

fn compress_db(
  db: &Path,
  archive: &Path,
  format: ArchiveFormat,
  events: Option<&dyn ArchiveEmitter>,
  cancelled: Option<&AtomicBool>,
  id: &str,
) -> io::Result<()> {
  let temp = temp_archive_path(archive);
  if temp.exists() {
    fs::remove_file(&temp)?;
  }

  let total_bytes = fs::metadata(db)?.len();
  emit(
    events,
    ArchiveEvent::FileStarted {
      id: id.to_string(),
      path: db.to_path_buf(),
      archive: archive.to_path_buf(),
      total_bytes,
    },
  );

  let result = (|| {
    let mut input = BufReader::new(File::open(db)?);
    let output = BufWriter::new(File::create(&temp)?);
    let mut buf = [0u8; 64 * 1024];
    let mut bytes_read = 0u64;
    encode_archive(output, format, |encoder| {
      loop {
        check_cancelled(cancelled)?;
        let n = input.read(&mut buf)?;
        if n == 0 {
          break;
        }
        encoder.write_all(&buf[..n])?;
        bytes_read = bytes_read.saturating_add(n as u64);
        check_cancelled(cancelled)?;
        emit(
          events,
          ArchiveEvent::FileProgress {
            id: id.to_string(),
            bytes_read,
            total_bytes,
          },
        );
      }
      Ok(())
    })?;
    if fs::metadata(&temp)?.len() == 0 {
      return Err(io::Error::new(io::ErrorKind::WriteZero, "empty archive"));
    }
    fs::rename(&temp, archive)
  })();

  if result.is_err() {
    let _ = fs::remove_file(&temp);
  } else {
    let bytes_out = fs::metadata(archive)?.len();
    emit(
      events,
      ArchiveEvent::FileCompleted {
        id: id.to_string(),
        path: db.to_path_buf(),
        archive: archive.to_path_buf(),
        bytes_in: total_bytes,
        bytes_out,
      },
    );
  }
  result
}

fn encode_archive<W, F>(output: W, format: ArchiveFormat, write_body: F) -> io::Result<()>
where
  W: Write,
  F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
  match format {
    ArchiveFormat::Zstd => encode_zstd(output, write_body),
    ArchiveFormat::Xz => encode_xz(output, write_body),
  }
}

fn encode_zstd<W, F>(output: W, write_body: F) -> io::Result<()>
where
  W: Write,
  F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
  let mut encoder = zstd::Encoder::new(output, 0)?;
  write_body(&mut encoder)?;
  let mut output = encoder.finish()?;
  output.flush()
}

#[cfg(feature = "lzma")]
fn encode_xz<W, F>(output: W, write_body: F) -> io::Result<()>
where
  W: Write,
  F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
  let options = lzma_rust2::XzOptions::with_preset(6);
  let mut encoder = lzma_rust2::XzWriter::new(output, options)?;
  write_body(&mut encoder)?;
  let mut output = encoder.finish()?;
  output.flush()
}

#[cfg(not(feature = "lzma"))]
fn encode_xz<W, F>(output: W, write_body: F) -> io::Result<()>
where
  W: Write,
  F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
  let _ = output;
  let _ = write_body;
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "xz archive compression requires the lzma feature",
  ))
}

fn archive_id(path: &Path) -> String {
  path.to_string_lossy().into_owned()
}

fn emit(events: Option<&dyn ArchiveEmitter>, event: ArchiveEvent) {
  if let Some(events) = events {
    events.emit(event);
  }
}

fn check_cancelled(cancelled: Option<&AtomicBool>) -> io::Result<()> {
  if cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Relaxed)) {
    Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "archive compression cancelled",
    ))
  } else {
    Ok(())
  }
}

fn parse_day(value: &str) -> Option<Date> {
  let mut parts = value.split('-');
  let year = parts.next()?.parse::<i32>().ok()?;
  let month = parts.next()?.parse::<u8>().ok()?;
  let day = parts.next()?.parse::<u8>().ok()?;
  if parts.next().is_some() {
    return None;
  }
  Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::RequestEventHandler;
  use parking_lot::Mutex;
  use std::io::{Read, Write};
  use std::sync::mpsc;
  use std::thread;
  use std::time::Duration as ThreadDuration;
  use time::macros::date;
  use tokn_core::event::{Event, EventHandler};
  use tokn_core::provider::Endpoint;
  use tokn_core::request_event::{RequestEndpoint, RequestEvent, RequestEventPayload, StageEvent};

  #[derive(Default)]
  struct CollectingEmitter {
    events: Mutex<Vec<ArchiveEvent>>,
  }

  impl ArchiveEmitter for CollectingEmitter {
    fn emit(&self, event: ArchiveEvent) {
      self.events.lock().push(event);
    }
  }

  fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("tokn-router-archive-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&p).unwrap();
    p
  }

  fn write_db(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    path
  }

  fn archive_format() -> ArchiveFormat {
    ArchiveFormat::resolve(Some("xz"))
  }

  fn started_event(request_id: &str, ts: i64) -> Event {
    Event::Requests(RequestEvent {
      request_id: request_id.into(),
      attempt: 0,
      ts,
      payload: RequestEventPayload::Stage(StageEvent::Started {
        request_endpoint: RequestEndpoint::Known(Endpoint::Responses),
      }),
    })
  }

  fn completed_event(request_id: &str, ts: i64) -> Event {
    Event::Requests(RequestEvent {
      request_id: request_id.into(),
      attempt: 0,
      ts,
      payload: RequestEventPayload::Stage(StageEvent::Completed {
        success: true,
        attempts: 1,
      }),
    })
  }

  #[test]
  fn archives_eligible_daily_db_without_removing_original() {
    let dir = tempdir();
    let db = write_db(&dir, "2026-05-02.db", b"sqlite-ish bytes");
    let format = archive_format();

    let stats = archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();

    assert_eq!(stats.archived, 1);
    assert!(db.exists());
    let archive = dir.join(format!("2026-05-02.{}", format.extension()));
    assert!(archive.exists());

    let mut decoded = Vec::new();
    decode_archive(&archive, format, &mut decoded);
    assert_eq!(decoded, b"sqlite-ish bytes");
  }

  #[test]
  fn skips_recent_non_daily_and_existing_archives() {
    let dir = tempdir();
    let format = archive_format();
    write_db(&dir, "2026-05-03.db", b"recent");
    write_db(&dir, "usage.db", b"not daily");
    write_db(&dir, &format!("2026-05-01.{}", format.extension()), b"already archived");
    write_db(&dir, "2026-05-01.db", b"old");

    let stats = archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();

    assert_eq!(stats.archived, 0);
    assert_eq!(stats.skipped_existing, 1);
    assert!(!dir.join(format!("usage.{}", format.extension())).exists());
    assert!(!dir.join(format!("2026-05-03.{}", format.extension())).exists());
  }

  #[test]
  fn out_of_range_retention_cutoffs_return_errors() {
    let dir = tempdir();
    let format = archive_format();

    let archive_error = archive_requests_once(&dir, date!(2026 - 05 - 09), 1_000_000_000, format).unwrap_err();
    let prune_error = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 1_000_000_000, format, false).unwrap_err();

    assert_eq!(archive_error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(prune_error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
      archive_error.to_string(),
      "archive retention cutoff is outside the supported date range"
    );
    assert_eq!(
      prune_error.to_string(),
      "prune retention cutoff is outside the supported date range"
    );
  }

  #[test]
  fn missing_request_directory_is_an_empty_locked_scan() {
    let dir = tempdir().join("missing");
    let format = archive_format();

    let archive = archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();
    let prune = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 7, format, false).unwrap();

    assert_eq!(archive, ArchiveStats::default());
    assert!(prune.entries.is_empty());
    assert!(!dir.exists());
  }

  #[test]
  fn prune_dry_run_verifies_without_deleting_source() {
    let dir = tempdir();
    let db = write_db(&dir, "2026-05-01.db", b"verified request database");
    let format = archive_format();
    archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();

    let report = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 7, format, false).unwrap();

    assert_eq!(report.cutoff, date!(2026 - 05 - 02));
    assert_eq!(report.entries.len(), 1);
    assert!(matches!(
      report.entries[0].outcome,
      PruneOutcome::Verified { ref sha256 } if sha256.len() == 64
    ));
    assert!(db.exists());
  }

  #[test]
  fn prune_reports_file_and_byte_progress() {
    let dir = tempdir();
    let contents = b"verified request database";
    write_db(&dir, "2026-05-01.db", contents);
    let format = archive_format();
    archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();
    let mut events = Vec::new();

    let report = prune_request_dbs_once_with_progress(&dir, date!(2026 - 05 - 09), 7, format, false, &mut |event| {
      events.push(event)
    })
    .unwrap();

    assert_eq!(report.entries.len(), 1);
    assert!(matches!(
      events.first(),
      Some(PruneProgressEvent::Started { files_total: 1 })
    ));
    assert!(matches!(
      events.get(1),
      Some(PruneProgressEvent::FileStarted {
        file_index: 0,
        files_total: 1,
        bytes_total,
        ..
      }) if *bytes_total == (contents.len() * 2) as u64
    ));
    assert!(events.iter().any(|event| matches!(
      event,
      PruneProgressEvent::FileProgress {
        bytes_processed,
        bytes_total,
        ..
      } if bytes_processed == bytes_total && *bytes_total == (contents.len() * 2) as u64
    )));
    assert!(matches!(
      events.get(events.len() - 2),
      Some(PruneProgressEvent::FileFinished {
        file_index: 0,
        files_total: 1,
        ..
      })
    ));
    assert!(matches!(
      events.last(),
      Some(PruneProgressEvent::Finished { files_total: 1 })
    ));
  }

  #[test]
  fn prune_commit_deletes_only_sha256_verified_source() {
    let dir = tempdir();
    let db = write_db(&dir, "2026-05-01.db", b"verified request database");
    let format = archive_format();
    archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();

    let report = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 7, format, true).unwrap();

    assert!(matches!(
      report.entries[0].outcome,
      PruneOutcome::Deleted { ref sha256 } if sha256.len() == 64
    ));
    assert!(!db.exists());
    assert!(report.entries[0].archive.exists());
  }

  #[test]
  fn prune_preserves_replacement_source_file() {
    let dir = tempdir();
    let db = write_db(&dir, "2026-05-01.db", b"verified request database");
    let original = dir.join("2026-05-01.db.original");
    let format = archive_format();
    archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();
    let mut replaced = false;

    let report = prune_request_dbs_once_with_progress(&dir, date!(2026 - 05 - 09), 7, format, true, &mut |event| {
      if !replaced && matches!(event, PruneProgressEvent::FileProgress { .. }) {
        fs::rename(&db, &original).unwrap();
        fs::write(&db, b"replacement request database").unwrap();
        replaced = true;
      }
    })
    .unwrap();

    assert!(matches!(report.entries[0].outcome, PruneOutcome::Failed { .. }));
    assert_eq!(fs::read(&db).unwrap(), b"replacement request database");
    assert_eq!(fs::read(&original).unwrap(), b"verified request database");
  }

  #[test]
  fn concurrent_request_write_waits_for_prune_and_is_preserved() {
    let dir = tempdir();
    let format = archive_format();
    let ts = date!(2026 - 05 - 01).midnight().assume_utc().unix_timestamp() * 1_000;
    let mut handler = RequestEventHandler::new(dir.clone()).unwrap();
    handler.handle(&started_event("old-request", ts));
    handler.handle(&completed_event("old-request", ts + 1));
    archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();

    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let mut writer = Some(handler);
    let mut writer_thread = None;
    let mut launched = false;
    let report = prune_request_dbs_once_with_progress(&dir, date!(2026 - 05 - 09), 7, format, true, &mut |event| {
      if !launched && matches!(event, PruneProgressEvent::FileProgress { .. }) {
        launched = true;
        let mut handler = writer.take().unwrap();
        let started_tx = started_tx.clone();
        let done_tx = done_tx.clone();
        writer_thread = Some(thread::spawn(move || {
          started_tx.send(()).unwrap();
          handler.handle(&started_event("concurrent-request", ts + 1));
          done_tx.send(()).unwrap();
        }));
        started_rx.recv_timeout(ThreadDuration::from_secs(1)).unwrap();
        assert!(done_rx.recv_timeout(ThreadDuration::from_millis(100)).is_err());
      }
    })
    .unwrap();

    assert!(matches!(report.entries[0].outcome, PruneOutcome::Deleted { .. }));
    done_rx.recv_timeout(ThreadDuration::from_secs(5)).unwrap();
    writer_thread.unwrap().join().unwrap();
    let db = dir.join("2026-05-01.db");
    assert!(db.exists());
    let connection = rusqlite::Connection::open(db).unwrap();
    let count: i64 = connection
      .query_row(
        "SELECT COUNT(*) FROM requests WHERE request_id = 'concurrent-request'",
        [],
        |row| row.get(0),
      )
      .unwrap();
    assert_eq!(count, 1);
  }

  #[test]
  fn prune_keeps_source_when_archive_content_does_not_match() {
    let dir = tempdir();
    let db = write_db(&dir, "2026-05-01.db", b"original request database");
    let format = archive_format();
    archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();
    fs::write(&db, b"changed request database").unwrap();

    let report = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 7, format, true).unwrap();

    assert!(matches!(
      report.entries[0].outcome,
      PruneOutcome::HashMismatch {
        ref source_sha256,
        ref archived_sha256,
      } if source_sha256.len() == 64 && archived_sha256.len() == 64 && source_sha256 != archived_sha256
    ));
    assert!(db.exists());
  }

  #[test]
  fn prune_keeps_source_when_archive_is_missing_or_corrupt() {
    let dir = tempdir();
    let missing = write_db(&dir, "2026-05-01.db", b"missing archive");
    let corrupt = write_db(&dir, "2026-05-02.db", b"corrupt archive");
    let format = archive_format();
    fs::write(archive_path(&corrupt, format), b"not an archive").unwrap();

    let report = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 7, format, true).unwrap();

    assert_eq!(report.entries.len(), 2);
    assert!(matches!(report.entries[0].outcome, PruneOutcome::MissingArchive));
    assert!(matches!(report.entries[1].outcome, PruneOutcome::Failed { .. }));
    assert!(missing.exists());
    assert!(corrupt.exists());
  }

  #[test]
  fn maintenance_lock_prevents_overlapping_archive_and_prune_scans() {
    let dir = tempdir();
    write_db(&dir, "2026-05-01.db", b"old");
    let _lock = RequestMaintenanceLock::acquire(&dir).unwrap();

    let archive_error = archive_requests_once(&dir, date!(2026 - 05 - 09), 7, archive_format()).unwrap_err();
    let prune_error = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 7, archive_format(), false).unwrap_err();

    assert_eq!(archive_error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(prune_error.kind(), io::ErrorKind::WouldBlock);
  }

  #[cfg(unix)]
  #[test]
  fn maintenance_lock_rejects_symlinks_without_opening_the_target() {
    use std::os::unix::fs::symlink;

    let dir = tempdir();
    let target = dir.join("lock-target");
    fs::write(&target, b"unchanged").unwrap();
    symlink(&target, dir.join(MAINTENANCE_LOCK_FILE)).unwrap();

    let error = match RequestMaintenanceLock::acquire(&dir) {
      Ok(_) => panic!("symlinked maintenance lock was accepted"),
      Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(fs::read(target).unwrap(), b"unchanged");
  }

  #[test]
  fn prune_rejects_multiply_linked_source_files() {
    let dir = tempdir();
    let db = write_db(&dir, "2026-05-01.db", b"verified request database");
    let alias = dir.join("request-database-alias");
    let format = archive_format();
    archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();
    fs::hard_link(&db, &alias).unwrap();

    let report = prune_request_dbs_once(&dir, date!(2026 - 05 - 09), 7, format, true).unwrap();

    assert!(matches!(report.entries[0].outcome, PruneOutcome::Failed { .. }));
    assert!(db.exists());
    assert!(alias.exists());
  }

  #[test]
  fn replaces_stale_temp_on_success() {
    let dir = tempdir();
    let format = archive_format();
    write_db(&dir, "2026-05-01.db", b"old");
    let tmp_path = dir.join(format!("2026-05-01.{}.tmp", format.extension()));
    let mut tmp = File::create(&tmp_path).unwrap();
    tmp.write_all(b"stale").unwrap();
    drop(tmp);

    let stats = archive_requests_once(&dir, date!(2026 - 05 - 09), 7, format).unwrap();

    assert_eq!(stats.archived, 1);
    assert!(!tmp_path.exists());
    assert!(dir.join(format!("2026-05-01.{}", format.extension())).exists());
  }

  #[test]
  fn uses_selected_archive_extension() {
    assert_eq!(
      archive_path(Path::new("2026-05-01.db"), ArchiveFormat::Zstd),
      PathBuf::from("2026-05-01.db.zstd")
    );
    if cfg!(feature = "lzma") {
      assert_eq!(
        archive_path(Path::new("2026-05-01.db"), ArchiveFormat::Xz),
        PathBuf::from("2026-05-01.db.xz")
      );
    }
  }

  #[test]
  fn resolves_configured_extension_or_falls_back_to_zstd() {
    assert_eq!(ArchiveFormat::resolve(None), ArchiveFormat::default());
    assert_eq!(ArchiveFormat::resolve(Some(".zstd")), ArchiveFormat::Zstd);
    assert_eq!(ArchiveFormat::resolve(Some("db.zstd")), ArchiveFormat::Zstd);
    assert_eq!(ArchiveFormat::resolve(Some("not-supported")), ArchiveFormat::Zstd);
    let expected_xz = if cfg!(feature = "lzma") {
      ArchiveFormat::Xz
    } else {
      ArchiveFormat::Zstd
    };
    assert_eq!(ArchiveFormat::resolve(Some(".xz")), expected_xz);
    assert_eq!(ArchiveFormat::resolve(Some("lzma")), expected_xz);
  }

  #[test]
  fn emits_archive_progress_events() {
    let dir = tempdir();
    write_db(&dir, "2026-05-01.db", b"old enough to archive");
    let emitter = Arc::new(CollectingEmitter::default());

    let stats = archive_requests_once_with_events(
      &dir,
      date!(2026 - 05 - 09),
      7,
      archive_format(),
      Some(emitter.as_ref()),
      None,
    )
    .unwrap();

    assert_eq!(stats.archived, 1);
    let events = emitter.events.lock();
    assert!(events
      .iter()
      .any(|event| matches!(event, ArchiveEvent::ScanStarted { .. })));
    assert!(events
      .iter()
      .any(|event| matches!(event, ArchiveEvent::FileStarted { .. })));
    assert!(events
      .iter()
      .any(|event| matches!(event, ArchiveEvent::FileProgress { .. })));
    assert!(events
      .iter()
      .any(|event| matches!(event, ArchiveEvent::FileCompleted { .. })));
    assert!(events
      .iter()
      .any(|event| matches!(event, ArchiveEvent::ScanCompleted { .. })));
  }

  #[test]
  fn cancellation_interrupts_compression_and_removes_temp_archive() {
    let dir = tempdir();
    write_db(&dir, "2026-05-01.db", &vec![b'x'; 1024 * 1024]);
    let cancelled = AtomicBool::new(true);

    let err =
      archive_requests_once_with_events(&dir, date!(2026 - 05 - 09), 7, archive_format(), None, Some(&cancelled))
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    assert!(!dir
      .join(format!("2026-05-01.{}", archive_format().extension()))
      .exists());
    assert!(!dir
      .join(format!("2026-05-01.{}.tmp", archive_format().extension()))
      .exists());
  }

  fn decode_archive(path: &Path, format: ArchiveFormat, out: &mut Vec<u8>) {
    match format {
      ArchiveFormat::Zstd => {
        zstd::stream::read::Decoder::new(File::open(path).unwrap())
          .unwrap()
          .read_to_end(out)
          .unwrap();
      }
      ArchiveFormat::Xz => decode_xz_archive(path, out),
    }
  }

  #[cfg(feature = "lzma")]
  fn decode_xz_archive(path: &Path, out: &mut Vec<u8>) {
    lzma_rust2::XzReader::new(File::open(path).unwrap(), false)
      .read_to_end(out)
      .unwrap();
  }

  #[cfg(not(feature = "lzma"))]
  fn decode_xz_archive(_path: &Path, _out: &mut Vec<u8>) {
    panic!("xz decoding requires lzma feature");
  }
}

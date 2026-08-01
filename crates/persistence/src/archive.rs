use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use time::{Date, Duration, Month, OffsetDateTime};
use tokio::sync::{mpsc, oneshot};

const RETENTION_DAYS: i64 = 7;
const SCAN_INTERVAL: StdDuration = StdDuration::from_secs(6 * 60 * 60);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveStats {
  pub archived: usize,
  pub skipped_existing: usize,
  pub failed: usize,
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
          RETENTION_DAYS,
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

#[cfg(test)]
pub fn archive_requests_once(
  dir: &Path,
  today: Date,
  retention_days: i64,
  format: ArchiveFormat,
) -> io::Result<ArchiveStats> {
  archive_requests_once_with_events(dir, today, retention_days, format, None, None)
}

fn archive_requests_once_with_events(
  dir: &Path,
  today: Date,
  retention_days: i64,
  format: ArchiveFormat,
  events: Option<&dyn ArchiveEmitter>,
  cancelled: Option<&AtomicBool>,
) -> io::Result<ArchiveStats> {
  let mut stats = ArchiveStats::default();
  let cutoff = today - Duration::days(retention_days);
  emit(events, ArchiveEvent::ScanStarted { dir: dir.to_path_buf() });
  if !dir.exists() {
    emit(
      events,
      ArchiveEvent::ScanCompleted {
        dir: dir.to_path_buf(),
        stats: stats.clone(),
      },
    );
    return Ok(stats);
  }

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
  if !path.is_file() || path.extension().and_then(|v| v.to_str()) != Some("db") {
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
  use parking_lot::Mutex;
  use std::io::{Read, Write};
  use time::macros::date;

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

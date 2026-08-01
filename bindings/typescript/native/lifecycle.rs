use crate::error::{native_error, CANCELLED, CLIENT_CLOSED, INTERNAL_ERROR};
use napi::Result;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use tokio::sync::{watch, Notify};
use tokn_sdk::Client;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CancelReason {
  Live = 0,
  User = 1,
  StreamClosed = 2,
  ClientClosed = 3,
}

impl CancelReason {
  fn from_raw(value: u8) -> Self {
    match value {
      1 => Self::User,
      2 => Self::StreamClosed,
      3 => Self::ClientClosed,
      _ => Self::Live,
    }
  }
}

type Cleanup = Box<dyn FnOnce() + Send + 'static>;

pub(crate) struct Cancellation {
  reason: AtomicU8,
  notify: Notify,
  cleanup: Mutex<Option<Cleanup>>,
}

impl Cancellation {
  pub(crate) fn new() -> Self {
    Self {
      reason: AtomicU8::new(CancelReason::Live as u8),
      notify: Notify::new(),
      cleanup: Mutex::new(None),
    }
  }

  pub(crate) fn reason(&self) -> CancelReason {
    CancelReason::from_raw(self.reason.load(Ordering::Acquire))
  }

  pub(crate) fn is_cancelled(&self) -> bool {
    self.reason() != CancelReason::Live
  }

  pub(crate) fn cancel(&self, reason: CancelReason) {
    if reason == CancelReason::Live {
      debug_assert_ne!(reason, CancelReason::Live);
      return;
    }
    if self
      .reason
      .compare_exchange(
        CancelReason::Live as u8,
        reason as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
      )
      .is_err()
    {
      return;
    }

    let cleanup = lock_unpoisoned(&self.cleanup).take();
    self.notify.notify_waiters();
    if let Some(cleanup) = cleanup {
      cleanup();
    }
  }

  pub(crate) fn set_cleanup(&self, cleanup: impl FnOnce() + Send + 'static) {
    let mut cleanup = Some(Box::new(cleanup) as Cleanup);
    {
      let mut stored = lock_unpoisoned(&self.cleanup);
      if self.reason() == CancelReason::Live {
        *stored = cleanup.take();
      }
    }
    if let Some(cleanup) = cleanup {
      cleanup();
    }
  }

  pub(crate) async fn cancelled(&self) -> CancelReason {
    loop {
      let notified = self.notify.notified();
      let reason = self.reason();
      if reason != CancelReason::Live {
        return reason;
      }
      notified.await;
    }
  }

  pub(crate) fn error_if_cancelled(&self) -> Result<()> {
    match self.reason() {
      CancelReason::Live => Ok(()),
      reason => Err(cancellation_error(reason)),
    }
  }
}

pub(crate) fn cancellation_error(reason: CancelReason) -> napi::Error {
  match reason {
    CancelReason::ClientClosed => native_error(CLIENT_CLOSED, "client is closed"),
    CancelReason::Live => native_error(INTERNAL_ERROR, "cancellation requested for a live operation"),
    CancelReason::User | CancelReason::StreamClosed => native_error(CANCELLED, "operation was cancelled"),
  }
}

pub(crate) struct ClientState {
  pub(crate) client: Arc<Client>,
  closed: AtomicU8,
  next_operation_id: AtomicU64,
  active: Mutex<HashMap<u64, Weak<Cancellation>>>,
  active_count: watch::Sender<usize>,
  pub(crate) reload_lock: Arc<tokio::sync::Mutex<()>>,
}

impl ClientState {
  pub(crate) fn new(client: Client) -> Arc<Self> {
    let (active_count, _) = watch::channel(0);
    Arc::new(Self {
      client: Arc::new(client),
      closed: AtomicU8::new(0),
      next_operation_id: AtomicU64::new(1),
      active: Mutex::new(HashMap::new()),
      active_count,
      reload_lock: Arc::new(tokio::sync::Mutex::new(())),
    })
  }

  pub(crate) fn is_closed(&self) -> bool {
    self.closed.load(Ordering::Acquire) != 0
  }

  pub(crate) fn register(self: &Arc<Self>, cancellation: Arc<Cancellation>) -> Result<OperationGuard> {
    if self.is_closed() {
      return Err(native_error(CLIENT_CLOSED, "client is closed"));
    }
    cancellation.error_if_cancelled()?;

    let mut active = lock_unpoisoned(&self.active);
    if self.is_closed() {
      return Err(native_error(CLIENT_CLOSED, "client is closed"));
    }
    cancellation.error_if_cancelled()?;

    let id = self.next_operation_id.fetch_add(1, Ordering::Relaxed);
    active.insert(id, Arc::downgrade(&cancellation));
    self.active_count.send_replace(active.len());
    Ok(OperationGuard {
      id,
      state: self.clone(),
    })
  }

  pub(crate) fn begin_close(&self) {
    if self.closed.swap(1, Ordering::AcqRel) != 0 {
      return;
    }

    let cancellations = {
      let active = lock_unpoisoned(&self.active);
      active.values().filter_map(Weak::upgrade).collect::<Vec<_>>()
    };
    for cancellation in cancellations {
      cancellation.cancel(CancelReason::ClientClosed);
    }
  }

  pub(crate) async fn close(&self) {
    let mut active_count = self.active_count.subscribe();
    self.begin_close();
    while *active_count.borrow_and_update() != 0 {
      if active_count.changed().await.is_err() {
        break;
      }
    }
  }

  fn finish(&self, id: u64) {
    let mut active = lock_unpoisoned(&self.active);
    active.remove(&id);
    self.active_count.send_replace(active.len());
  }
}

pub(crate) struct OperationGuard {
  id: u64,
  state: Arc<ClientState>,
}

impl Drop for OperationGuard {
  fn drop(&mut self) {
    self.state.finish(self.id);
  }
}

pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::error::INTERNAL_ERROR;
  use std::fs;
  use std::path::PathBuf;
  use std::sync::atomic::AtomicU64;
  use std::time::Duration;

  static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

  struct ClientFixture {
    root: PathBuf,
  }

  impl ClientFixture {
    fn new() -> Self {
      let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
      let root = std::env::temp_dir().join(format!("tokn-typescript-lifecycle-{}-{id}", std::process::id()));
      fs::create_dir(&root).expect("create lifecycle fixture directory");
      fs::write(
        root.join("config.toml"),
        r#"schema_version = 2

[profiles.lifecycle]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "default"
upstream = { kind = "fixed", upstream = "local" }
model = { kind = "qualified", namespace = "provider" }
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["llama-cpp"]

[upstreams.local]
provider = "llama-cpp"
base_url = "http://127.0.0.1:1"
accounts = ["local"]
"#,
      )
      .expect("write lifecycle fixture config");
      fs::write(
        root.join("auth.yaml"),
        "version: 1\naccounts:\n  - id: local\n    provider: llama-cpp\n",
      )
      .expect("write lifecycle fixture credentials");
      Self { root }
    }

    fn client(&self) -> Client {
      Client::builder()
        .config_path(self.root.join("config.toml"))
        .auth_path(self.root.join("auth.yaml"))
        .profile("lifecycle")
        .build()
        .expect("build lifecycle fixture client")
    }
  }

  impl Drop for ClientFixture {
    fn drop(&mut self) {
      let _ = fs::remove_dir_all(&self.root);
    }
  }

  fn error_code(error: &napi::Error) -> String {
    let payload = error
      .reason
      .strip_prefix("TOKN_ERROR:")
      .expect("structured native error");
    let payload: serde_json::Value = serde_json::from_str(payload).expect("valid native error JSON");
    payload["code"]
      .as_str()
      .expect("native error code must be a string")
      .to_owned()
  }

  #[tokio::test]
  async fn cancellation_cannot_miss_a_notification() {
    let cancellation = Arc::new(Cancellation::new());
    cancellation.cancel(CancelReason::User);
    assert_eq!(cancellation.cancelled().await, CancelReason::User);
  }

  #[test]
  fn cleanup_runs_when_registered_after_cancellation() {
    let cancellation = Cancellation::new();
    cancellation.cancel(CancelReason::User);
    let called = Arc::new(AtomicU8::new(0));
    let called_by_cleanup = called.clone();
    cancellation.set_cleanup(move || {
      called_by_cleanup.store(1, Ordering::Release);
    });
    assert_eq!(called.load(Ordering::Acquire), 1);
  }

  #[test]
  fn live_reason_is_an_internal_invariant_error() {
    let error = cancellation_error(CancelReason::Live);
    assert_eq!(error_code(&error), INTERNAL_ERROR);
  }

  #[tokio::test]
  async fn close_drains_registered_operations_and_rejects_new_ones() {
    let fixture = ClientFixture::new();
    let state = ClientState::new(fixture.client());
    let cancellation = Arc::new(Cancellation::new());
    let operation = state.register(cancellation.clone()).expect("register operation");

    let closing_state = state.clone();
    let close = tokio::spawn(async move {
      closing_state.close().await;
    });
    tokio::time::timeout(Duration::from_secs(1), async {
      while !state.is_closed() {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("close should begin promptly");

    assert!(!close.is_finished(), "close must wait for the registered operation");
    assert_eq!(cancellation.reason(), CancelReason::ClientClosed);

    let error = state
      .register(Arc::new(Cancellation::new()))
      .err()
      .expect("registration after close must fail");
    assert_eq!(error_code(&error), CLIENT_CLOSED);

    drop(operation);
    tokio::time::timeout(Duration::from_secs(1), close)
      .await
      .expect("close should finish after operations drain")
      .expect("close task should not panic");
  }
}

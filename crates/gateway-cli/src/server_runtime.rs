use crate::config::Config;
use crate::db::archive::{ArchiveEventHandler, ArchiveRuntime};
use crate::progress::{ArchiveProgressEventHandler, ProgressEventHandler, ProgressLogEventHandler};
use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokn_auth::AuthStore;
use tokn_config::v2::CompiledConfig;
use tokn_core::account::AccountConfig;
use tokn_core::event::{EventBus, EventHandler};
use tokn_router::runtime::{
  bind_gateway_listeners, link_builtin_gateway_runtime, materialize_listeners, BoundGatewayListeners,
  GatewayServerState, GatewayServingDefaults, RequestBodyLimits,
};

#[allow(dead_code)]
type EventBusParts = (
  Arc<EventBus>,
  broadcast::Receiver<Arc<tokn_core::event::Event>>,
  Vec<Box<dyn EventHandler>>,
  Option<ArchiveRuntime>,
);

/// Build the event bus and its persistence/progress handlers.
#[allow(dead_code)]
pub fn build_event_bus(cfg: &Config) -> Result<EventBusParts> {
  let capacity = cfg.db.write_queue_capacity.max(256);
  let bus = EventBus::new(capacity);
  let receiver = bus.subscribe();
  let mut handlers: Vec<Box<dyn EventHandler>> = Vec::new();
  let mut archive_handlers: Vec<Box<dyn ArchiveEventHandler>> = Vec::new();
  let tty_progress = std::io::stdout().is_terminal();

  if cfg.db.enabled {
    let paths = cfg.db.resolve_paths()?;
    let request_handler = tokn_persistence::RequestEventHandler::new(paths.requests_dir)?;
    let usage_handler = tokn_persistence::UsageEventHandler::new(paths.usage_db)?;
    handlers.push(Box::new(request_handler));
    handlers.push(Box::new(usage_handler));
    if cfg.db.record_sessions {
      let session_handler = tokn_persistence::SessionEventHandler::new(paths.sessions_db)?;
      handlers.push(Box::new(session_handler));
    }
  }

  match crate::logging::resolve_logs_dir(&cfg.logging) {
    Ok(dir) => match ProgressLogEventHandler::new(&dir) {
      Ok(handler) => handlers.push(Box::new(handler)),
      Err(e) => tracing::warn!(path = %dir.display(), error = %e, "progress log disabled"),
    },
    Err(e) => tracing::warn!(error = %e, "progress log disabled"),
  }

  if tty_progress {
    handlers.push(Box::new(ProgressEventHandler::new()));
    archive_handlers.push(Box::new(ArchiveProgressEventHandler::new()));
  }

  let archive_runtime = if cfg.db.enabled {
    let paths = cfg.db.resolve_paths()?;
    crate::db::archive::start_request_archive_worker(
      paths.requests_dir,
      cfg.db.archive_extension.as_deref(),
      archive_handlers,
    )
  } else {
    None
  };

  Ok((Arc::new(bus), receiver, handlers, archive_runtime))
}

/// Load accounts from the default root `auth.yaml` and `auth.d` fragments.
pub fn load_default_accounts() -> Result<Vec<AccountConfig>> {
  let store = AuthStore::load(None, None)?;
  Ok(store.accounts)
}

/// Prepare and atomically bind every listener in one compiled v2 generation.
///
/// Runtime linking, file-backed listener resources, and outbound transports
/// are all prepared before socket acquisition begins. The router's binder
/// then acquires the complete listener set without starting accept loops and
/// releases earlier sockets if any later bind fails.
pub async fn bind_compiled_gateway(
  compiled: &CompiledConfig,
  accounts: &[AccountConfig],
  local_access_db_path: Option<&Path>,
) -> Result<BoundGatewayListeners> {
  if compiled.gateway().listeners().is_empty() {
    bail!("compiled gateway has no listeners to serve");
  }
  let runtime = Arc::new(
    link_builtin_gateway_runtime(compiled.gateway(), accounts).context("failed to link compiled gateway runtime")?,
  );
  let outbound = compiled.service().outbound().to_http_client_options();
  let request_limits = compiled.service().request_limits();
  let serving_defaults = GatewayServingDefaults::new(RequestBodyLimits::new(
    request_limits.max_wire_bytes(),
    request_limits.max_decoded_bytes(),
  ));
  let serving = Arc::new(
    GatewayServerState::build(runtime, &outbound, serving_defaults)
      .context("failed to prepare compiled gateway serving state")?,
  );
  let listener_resources = materialize_listeners(serving.runtime().listeners(), local_access_db_path)
    .context("failed to prepare compiled gateway listener resources")?;

  bind_gateway_listeners(serving, listener_resources)
    .await
    .context("failed to bind compiled gateway listeners")
}

#[allow(dead_code)]
pub fn build_state(
  cfg: &Config,
  accounts: &[AccountConfig],
  events: Arc<EventBus>,
) -> Result<tokn_router::api::AppState> {
  tokn_router::api::build_state(cfg, accounts, events)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
  use std::time::Duration;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpStream;
  use tokio::sync::oneshot;
  use tokio::time::timeout;

  const TEST_TIMEOUT: Duration = Duration::from_secs(2);

  fn compile_reject_only_gateway(listeners: &[(&str, SocketAddr)]) -> CompiledConfig {
    let mut config = String::from("schema_version = 2\n");
    for (id, address) in listeners {
      config.push_str(&format!(
        r#"
[listeners.{id}]
kind = "llm_api"
bind = "{address}"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
"#,
      ));
    }
    tokn_config::v2::parse(&config, Path::new("compiled-gateway.toml")).unwrap()
  }

  fn persistence_config(record_sessions: bool) -> (Config, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("tokn-server-runtime-test-{}", uuid::Uuid::new_v4()));
    let sessions_db = root.join("sessions.db");
    let mut cfg = Config::default();
    cfg.db.usage_db_path = Some(root.join("usage.db"));
    cfg.db.sessions_db_path = Some(sessions_db.clone());
    cfg.db.requests_dir = Some(root.join("requests"));
    cfg.db.record_sessions = record_sessions;
    cfg.logging.dir = Some(root.join("logs"));
    (cfg, sessions_db)
  }

  #[test]
  fn build_event_bus_opens_sessions_db_when_recording_is_enabled() {
    let (cfg, sessions_db) = persistence_config(true);

    let _parts = build_event_bus(&cfg).expect("event bus should initialize persistence");

    assert!(sessions_db.is_file());
  }

  #[test]
  fn build_event_bus_leaves_sessions_db_absent_when_recording_is_disabled() {
    let (cfg, sessions_db) = persistence_config(false);

    let _parts = build_event_bus(&cfg).expect("event bus should initialize other persistence");

    assert!(!sessions_db.exists());
  }

  #[tokio::test]
  async fn serving_rejects_a_headless_embedded_config() {
    let compiled = tokn_config::v2::parse("schema_version = 2\n", Path::new("embedded.toml")).unwrap();

    let error = bind_compiled_gateway(&compiled, &[], None).await.unwrap_err();

    assert_eq!(error.to_string(), "compiled gateway has no listeners to serve");
  }

  #[tokio::test]
  async fn binds_reject_only_compiled_gateway() {
    let reservation = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    let compiled = compile_reject_only_gateway(&[("api", address)]);
    drop(reservation);

    let bound = bind_compiled_gateway(&compiled, &[], None).await.unwrap();

    assert_eq!(bound.len(), 1);
    let (listener_id, listener) = bound.listeners().next().unwrap();
    assert_eq!(listener_id.as_str(), "api");
    assert_eq!(listener.local_addr().unwrap(), address);
  }

  #[tokio::test]
  async fn compiled_gateway_bind_failure_releases_earlier_sockets() {
    let mut reservations = (0..2)
      .map(|_| StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
      .collect::<Vec<_>>();
    let first_address = reservations[0].local_addr().unwrap();
    let second_address = reservations[1].local_addr().unwrap();
    let second_reservation = reservations.pop().unwrap();
    drop(reservations);
    let compiled = compile_reject_only_gateway(&[("a-first", first_address), ("b-second", second_address)]);

    let error = bind_compiled_gateway(&compiled, &[], None).await.unwrap_err();
    let bind_error = error
      .downcast_ref::<tokn_router::runtime::ListenerBindError>()
      .expect("the startup error must retain the listener bind failure");
    assert!(matches!(
      bind_error,
      tokn_router::runtime::ListenerBindError::Bind {
        listener,
        address,
        ..
      } if listener.as_str() == "b-second" && *address == second_address
    ));

    let rebound = StdTcpListener::bind(first_address).expect("the earlier socket must be released after rollback");
    assert_eq!(rebound.local_addr().unwrap(), first_address);
    drop(second_reservation);
  }

  #[tokio::test]
  async fn compiled_gateway_serves_and_stops_two_reject_only_listeners() {
    let reservations = (0..2)
      .map(|_| StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
      .collect::<Vec<_>>();
    let first_address = reservations[0].local_addr().unwrap();
    let second_address = reservations[1].local_addr().unwrap();
    let compiled = compile_reject_only_gateway(&[("first", first_address), ("second", second_address)]);
    drop(reservations);

    let bound = bind_compiled_gateway(&compiled, &[], None).await.unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
      tokn_router::runtime::serve_gateway_listeners(bound, async {
        let _ = shutdown_rx.await;
      })
      .await
    });

    for (listener, address) in [("first", first_address), ("second", second_address)] {
      let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
      client
        .write_all(
          format!("GET /from-{listener} HTTP/1.1\r\nHost: {listener}.example\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
      let mut response = Vec::new();
      timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
      let response = std::str::from_utf8(&response).unwrap();
      assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "listener {listener} returned an unexpected response: {response:?}"
      );
      assert!(
        response.contains("\"code\":\"route_rejected\""),
        "listener {listener} did not apply its reject policy: {response:?}"
      );
    }

    shutdown_tx.send(()).unwrap();
    timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().unwrap();
  }
}

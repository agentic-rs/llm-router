use crate::config::Config;
use crate::db::archive::{ArchiveEventHandler, ArchiveRuntime};
use crate::progress::{ArchiveProgressEventHandler, ProgressEventHandler, ProgressLogEventHandler};
use anyhow::{Context, Result};
use axum::Router;
use std::future::Future;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokn_accounts::registry::Registry;
use tokn_auth::AuthStore;
use tokn_config::{v2::CompiledConfig, RouteMode};
use tokn_core::account::AccountConfig;
use tokn_core::event::{EventBus, EventHandler};
use tokn_router::runtime::{
  bind_gateway_listeners, link_gateway_runtime, materialize_listeners, BoundGatewayListeners, GatewayServerState,
  GatewayServingDefaults, RequestBodyLimits, RuntimeNameRegistry,
};

type EventBusParts = (
  Arc<EventBus>,
  broadcast::Receiver<Arc<tokn_core::event::Event>>,
  Vec<Box<dyn EventHandler>>,
  Option<ArchiveRuntime>,
);

/// Build the event bus and its persistence/progress handlers.
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

/// Load accounts from the root `auth.yaml` and any `auth.d` fragments.
///
/// `config_path` is accepted for compatibility with call sites that already
/// have the effective config path; legacy schema migration runs before latest
/// config/auth loading.
pub fn load_accounts(config_path: Option<&Path>) -> Result<Vec<AccountConfig>> {
  let store = AuthStore::load(None, config_path)?;
  Ok(store.accounts)
}

pub fn load_access_store(enabled: bool) -> Result<Arc<tokn_access::AccessStore>> {
  if enabled {
    Ok(Arc::new(tokn_access::AccessStore::open_default()?))
  } else {
    Ok(Arc::new(tokn_access::AccessStore::disabled()))
  }
}

/// Prepare and atomically bind every listener in one compiled v2 generation.
///
/// Runtime linking, file-backed listener resources, and outbound transports
/// are all prepared before socket acquisition begins. The router's binder
/// then acquires the complete listener set without starting accept loops and
/// releases earlier sockets if any later bind fails.
#[allow(dead_code)] // Wired into command dispatch by the subsequent v2 CLI cutover.
pub async fn bind_compiled_gateway(
  compiled: &CompiledConfig,
  accounts: &[AccountConfig],
  local_access_db_path: Option<&Path>,
) -> Result<BoundGatewayListeners> {
  let provider_registry = Registry::builtin();
  let runtime_names = RuntimeNameRegistry::builtin();
  let runtime = Arc::new(
    link_gateway_runtime(compiled.gateway(), accounts, &provider_registry, &runtime_names)
      .context("failed to link compiled gateway runtime")?,
  );
  let listener_resources = materialize_listeners(runtime.listeners(), local_access_db_path)
    .context("failed to prepare compiled gateway listener resources")?;

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

  bind_gateway_listeners(serving, listener_resources)
    .await
    .context("failed to bind compiled gateway listeners")
}

pub fn build_state(
  cfg: &Config,
  accounts: &[AccountConfig],
  events: Arc<EventBus>,
) -> Result<tokn_router::api::AppState> {
  tokn_router::api::build_state(cfg, accounts, events)
}

pub fn build_state_for_route_mode(
  cfg: &Config,
  accounts: &[AccountConfig],
  events: Arc<EventBus>,
  route_mode: RouteMode,
) -> Result<tokn_router::api::AppState> {
  let mut cfg = cfg.clone();
  cfg.server.route_mode = route_mode;
  cfg.defaults.mode = route_mode;
  build_state(&cfg, accounts, events)
}

pub fn build_proxy_state_for_route_mode(
  cfg: &Config,
  accounts: &[AccountConfig],
  events: Arc<EventBus>,
  route_mode: RouteMode,
) -> Result<tokn_router::api::AppState> {
  let mut cfg = cfg.clone();
  cfg.server.route_mode = route_mode;
  cfg.defaults.mode = route_mode;
  tokn_router::api::build_proxy_state(&cfg, accounts, events)
}

pub fn resolve_bind_addr(host: &str, port: u16, insecure_allow_remote: bool) -> Result<SocketAddr> {
  ensure_bind_host(host, insecure_allow_remote)?;
  Ok(format!("{host}:{port}").parse()?)
}

pub async fn serve_http<F>(app: Router, addr: SocketAddr, shutdown: F) -> Result<()>
where
  F: Future<Output = ()> + Send + 'static,
{
  let listener = tokio::net::TcpListener::bind(addr).await?;
  tracing::info!(%addr, "tokn-router listening");
  axum::serve(listener, app).with_graceful_shutdown(shutdown).await?;
  Ok(())
}

pub fn is_loopback(host: &str) -> bool {
  matches!(host, "127.0.0.1" | "::1" | "localhost")
    || host
      .parse::<std::net::IpAddr>()
      .map(|ip| ip.is_loopback())
      .unwrap_or(false)
}

pub fn ensure_bind_host(host: &str, insecure_allow_remote: bool) -> Result<()> {
  if !insecure_allow_remote && !is_loopback(host) {
    anyhow::bail!(
      "refusing to bind to non-loopback host '{host}' without --insecure-allow-remote; API-key auth does not cover tunnels, passthrough traffic, or helper routes"
    );
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::{Ipv4Addr, TcpListener as StdTcpListener};

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

  #[test]
  fn rejects_non_loopback_without_insecure_allow_remote() {
    let err = ensure_bind_host("0.0.0.0", false).expect_err("remote bind should be rejected");
    assert!(
      err.to_string().contains("--insecure-allow-remote"),
      "unexpected error: {err}"
    );
  }

  #[test]
  fn accepts_non_loopback_with_insecure_allow_remote() {
    ensure_bind_host("0.0.0.0", true).expect("remote bind should be allowed");
  }

  #[test]
  fn accepts_loopback_without_insecure_allow_remote() {
    ensure_bind_host("127.0.0.1", false).expect("loopback bind should be allowed");
  }
}

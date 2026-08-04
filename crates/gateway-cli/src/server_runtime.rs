use crate::progress::{ArchiveProgressEventHandler, ProgressEventHandler};
use anyhow::{anyhow, bail, Context, Result};
use std::future::Future;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use tokn_auth::AuthStore;
use tokn_config::v2::{CompiledConfig, PersistencePlan};
use tokn_core::account::AccountConfig;
use tokn_events::{
  ConsumerResult, EventConsumer, EventHub, EventSeq, GatewayEvent, HubBuilder, HubFailure, Publisher, WaitFailedError,
};
use tokn_persistence::{
  archive::{start_request_archive_worker, ArchiveEventHandler, ArchiveRuntime},
  RequestPersistenceConsumer, RequestPersistenceOptions, SessionPersistenceConsumer, UsagePersistenceConsumer,
};
use tokn_requests::RequestLifecycleEmitter;
use tokn_router::runtime::{
  bind_gateway_listeners, link_builtin_gateway_runtime, materialize_listeners, BoundGatewayListeners,
  GatewayServerState, GatewayServingDefaults, RequestBodyLimits,
};

/// CLI ownership for one generation's ordered request event dispatcher.
///
/// The router only receives the cloneable emitter. The CLI retains the hub so
/// consumer failure can stop serving and accepted events can be drained before
/// process exit.
pub struct GatewayEventRuntime {
  emitter: RequestLifecycleEmitter,
  supervisor: Publisher<GatewayEvent>,
  hub: EventHub<GatewayEvent>,
  archive: Option<ArchiveRuntime>,
}

impl GatewayEventRuntime {
  pub fn emitter(&self) -> RequestLifecycleEmitter {
    self.emitter.clone()
  }

  pub(crate) async fn shutdown(self) -> Result<()> {
    let Self {
      emitter,
      supervisor,
      hub,
      archive,
    } = self;
    drop(emitter);
    drop(supervisor);
    if let Some(archive) = archive {
      archive.shutdown().await;
    }
    hub
      .shutdown()
      .await
      .context("drain and shut down the gateway event hub")?;
    Ok(())
  }
}

/// A deliberate event sink for persistence-disabled, non-interactive CLI
/// runs. Keeping the hub active means router publication and supervision use
/// the same lifecycle contract in every serve mode without creating DB state.
struct DiscardEventConsumer;

impl EventConsumer<GatewayEvent> for DiscardEventConsumer {
  fn name(&self) -> &str {
    "cli.discard_request_events"
  }

  fn handle(&mut self, _sequence: EventSeq, _event: &GatewayEvent) -> ConsumerResult {
    Ok(())
  }
}

/// Build the single ordered event hub used by one compiled v2 generation.
pub fn build_gateway_event_runtime(persistence: &PersistencePlan) -> Result<GatewayEventRuntime> {
  build_gateway_event_runtime_with_progress(persistence, std::io::stdout().is_terminal())
}

fn build_gateway_event_runtime_with_progress(
  persistence: &PersistencePlan,
  interactive_progress: bool,
) -> Result<GatewayEventRuntime> {
  let mut builder = HubBuilder::new().capacity(persistence.write_queue_capacity());
  let mut consumer_count = 0usize;
  let paths = persistence
    .enabled()
    .then(|| persistence.resolve_paths().context("resolve gateway persistence paths"))
    .transpose()?;

  if let Some(paths) = &paths {
    let version = tokn_core::util::version::full();
    let requests = RequestPersistenceConsumer::open_with_options(
      &paths.requests_dir,
      version,
      RequestPersistenceOptions {
        record_request_bodies: persistence.record_request_bodies(),
        body_max_bytes: persistence.body_max_bytes(),
      },
    )
    .with_context(|| format!("open request persistence at `{}`", paths.requests_dir.display()))?;
    let usage = UsagePersistenceConsumer::open(&paths.usage_db, version)
      .with_context(|| format!("open usage persistence at `{}`", paths.usage_db.display()))?;
    builder = builder.consumer(requests).consumer(usage);
    consumer_count += 2;

    if persistence.record_sessions() {
      let sessions = SessionPersistenceConsumer::open(&paths.sessions_db)
        .with_context(|| format!("open session persistence at `{}`", paths.sessions_db.display()))?;
      builder = builder.consumer(sessions);
      consumer_count += 1;
    }
  }

  if interactive_progress {
    builder = builder.consumer(ProgressEventHandler::new());
    consumer_count += 1;
  }
  if consumer_count == 0 {
    builder = builder.consumer(DiscardEventConsumer);
  }

  let (supervisor, hub) = builder.start().context("start the gateway event hub")?;
  let emitter = RequestLifecycleEmitter::new(supervisor.clone());
  let archive_handlers: Vec<Box<dyn ArchiveEventHandler>> = if interactive_progress {
    vec![Box::new(ArchiveProgressEventHandler::new())]
  } else {
    Vec::new()
  };
  let archive = paths.and_then(|paths| {
    start_request_archive_worker(paths.requests_dir, persistence.archive_extension(), archive_handlers)
  });
  Ok(GatewayEventRuntime {
    emitter,
    supervisor,
    hub,
    archive,
  })
}

#[derive(Debug)]
enum GatewayShutdownCause {
  Requested,
  EventHubFailed(Arc<HubFailure>),
  EventHubClosed,
}

async fn wait_for_gateway_shutdown<F>(supervisor: Publisher<GatewayEvent>, shutdown: F) -> GatewayShutdownCause
where
  F: Future<Output = ()> + Send,
{
  tokio::select! {
    _ = shutdown => GatewayShutdownCause::Requested,
    result = supervisor.wait_failed() => match result {
      Ok(failure) => GatewayShutdownCause::EventHubFailed(failure),
      Err(WaitFailedError::Closed(_)) => GatewayShutdownCause::EventHubClosed,
    }
  }
}

/// Serve a bound generation while supervising and finally draining its event
/// hub. A failed persistence/progress consumer is a serving failure rather
/// than a detached background error.
pub async fn serve_bound_gateway<F>(
  bound: BoundGatewayListeners,
  events: GatewayEventRuntime,
  shutdown: F,
) -> Result<()>
where
  F: Future<Output = ()> + Send,
{
  let supervisor = events.supervisor.clone();
  let (cause_tx, cause_rx) = tokio::sync::oneshot::channel();
  let serve_result = tokn_router::runtime::serve_gateway_listeners(bound, async move {
    let cause = wait_for_gateway_shutdown(supervisor, shutdown).await;
    let _ = cause_tx.send(cause);
  })
  .await;
  let cause = cause_rx.await.ok();
  let shutdown_result = events.shutdown().await;

  if let Err(error) = serve_result {
    return match shutdown_result {
      Ok(()) => Err(error).context("serve compiled gateway listeners"),
      Err(shutdown_error) => Err(anyhow!(
        "serve compiled gateway listeners failed: {error}; gateway event runtime shutdown also failed: {shutdown_error}"
      )),
    };
  }

  match cause {
    Some(GatewayShutdownCause::EventHubFailed(failure)) => {
      return match shutdown_result {
        Ok(()) => Err(anyhow!("gateway event hub failed while serving: {failure}")),
        Err(shutdown_error) => Err(anyhow!(
          "gateway event hub failed while serving: {failure}; event runtime shutdown also failed: {shutdown_error}"
        )),
      };
    }
    Some(GatewayShutdownCause::EventHubClosed) => {
      return match shutdown_result {
        Ok(()) => Err(anyhow!("gateway event hub closed unexpectedly while serving")),
        Err(shutdown_error) => Err(anyhow!(
          "gateway event hub closed unexpectedly while serving; event runtime shutdown also failed: {shutdown_error}"
        )),
      };
    }
    Some(GatewayShutdownCause::Requested) => {}
    None => return Err(anyhow!("gateway listeners stopped without a shutdown cause")),
  }

  shutdown_result
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
#[cfg(test)]
pub async fn bind_compiled_gateway(
  compiled: &CompiledConfig,
  accounts: &[AccountConfig],
  local_access_db_path: Option<&Path>,
) -> Result<BoundGatewayListeners> {
  bind_compiled_gateway_with_events(
    compiled,
    accounts,
    local_access_db_path,
    RequestLifecycleEmitter::disabled(),
  )
  .await
}

/// Prepare and bind a generation with a caller-owned lifecycle emitter.
pub async fn bind_compiled_gateway_with_events(
  compiled: &CompiledConfig,
  accounts: &[AccountConfig],
  local_access_db_path: Option<&Path>,
  request_events: RequestLifecycleEmitter,
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
    GatewayServerState::build_with_events(runtime, &outbound, serving_defaults, request_events)
      .context("failed to prepare compiled gateway serving state")?,
  );
  let listener_resources = materialize_listeners(serving.runtime().listeners(), local_access_db_path)
    .context("failed to prepare compiled gateway listener resources")?;

  bind_gateway_listeners(serving, listener_resources)
    .await
    .context("failed to bind compiled gateway listeners")
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io;
  use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::time::Duration;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpStream;
  use tokio::sync::oneshot;
  use tokio::time::timeout;
  use tokn_events::{
    CapturedHeaders, CapturedUri, Correlation, IngressKind, RequestId, RequestSource, RequestStarted, TrafficEvent,
    TrafficEventKind,
  };

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

  fn compile_persistence(root: &Path, enabled: bool, record_sessions: bool) -> CompiledConfig {
    let usage_db = toml::Value::String(root.join("usage.db").to_string_lossy().into_owned());
    let sessions_db = toml::Value::String(root.join("sessions.db").to_string_lossy().into_owned());
    let requests_dir = toml::Value::String(root.join("requests").to_string_lossy().into_owned());
    let config = format!(
      r#"
schema_version = 2

[service.persistence]
enabled = {enabled}
usage_db_path = {usage_db}
sessions_db_path = {sessions_db}
requests_dir = {requests_dir}
record_sessions = {record_sessions}
record_request_bodies = false
body_max_bytes = 37
write_queue_capacity = 257
archive_extension = "zstd"
"#,
    );
    tokn_config::v2::parse(&config, Path::new("persistence.toml")).unwrap()
  }

  #[test]
  fn persistence_fixture_quotes_windows_paths_as_toml_strings() {
    let root = Path::new(r"C:\Users\runner\AppData\Local\Temp");
    let compiled = compile_persistence(root, true, false);
    let paths = compiled.service().persistence().resolve_paths().unwrap();

    assert_eq!(paths.usage_db, root.join("usage.db"));
    assert_eq!(paths.sessions_db, root.join("sessions.db"));
    assert_eq!(paths.requests_dir, root.join("requests"));
  }

  fn test_event() -> GatewayEvent {
    GatewayEvent::Traffic(TrafficEvent {
      request_id: RequestId::new("cli-runtime-test").unwrap(),
      sequence: 1,
      at_unix_ms: 1,
      elapsed_ms: 0,
      kind: TrafficEventKind::Started(RequestStarted {
        source: RequestSource::Listener {
          listener_id: "test".into(),
          ingress: IngressKind::LlmApi,
          local_addr: None,
          peer_addr: None,
        },
        http_version: Some("HTTP/1.1".into()),
        method: "GET".into(),
        target: CapturedUri::exact("/test"),
        headers: CapturedHeaders::default(),
        body_present: false,
        correlation: Correlation::default(),
      }),
    })
  }

  struct CountingConsumer {
    handled: Arc<AtomicUsize>,
    flushed: Arc<AtomicUsize>,
  }

  impl EventConsumer<GatewayEvent> for CountingConsumer {
    fn name(&self) -> &str {
      "test.counting"
    }

    fn handle(&mut self, _sequence: EventSeq, _event: &GatewayEvent) -> ConsumerResult {
      self.handled.fetch_add(1, Ordering::SeqCst);
      Ok(())
    }

    fn flush(&mut self) -> ConsumerResult {
      self.flushed.fetch_add(1, Ordering::SeqCst);
      Ok(())
    }
  }

  struct FailingConsumer;

  impl EventConsumer<GatewayEvent> for FailingConsumer {
    fn name(&self) -> &str {
      "test.failing"
    }

    fn handle(&mut self, _sequence: EventSeq, _event: &GatewayEvent) -> ConsumerResult {
      Err(Box::new(io::Error::other("injected consumer failure")))
    }
  }

  fn test_event_runtime<C>(consumer: C) -> (Publisher<GatewayEvent>, GatewayEventRuntime)
  where
    C: EventConsumer<GatewayEvent>,
  {
    let (publisher, hub) = HubBuilder::new().capacity(8).consumer(consumer).start().unwrap();
    let runtime = GatewayEventRuntime {
      emitter: RequestLifecycleEmitter::new(publisher.clone()),
      supervisor: publisher.clone(),
      hub,
      archive: None,
    };
    (publisher, runtime)
  }

  #[tokio::test]
  async fn v2_event_runtime_opens_only_configured_compatibility_databases() {
    let enabled_root = tempfile::tempdir().unwrap();
    let enabled = compile_persistence(enabled_root.path(), true, false);
    let runtime = build_gateway_event_runtime_with_progress(enabled.service().persistence(), false).unwrap();

    assert!(enabled_root.path().join("usage.db").is_file());
    assert!(enabled_root.path().join("requests").is_dir());
    assert!(!enabled_root.path().join("sessions.db").exists());
    runtime.shutdown().await.unwrap();

    let disabled_root = tempfile::tempdir().unwrap();
    let disabled = compile_persistence(disabled_root.path(), false, true);
    let runtime = build_gateway_event_runtime_with_progress(disabled.service().persistence(), false).unwrap();

    assert!(!disabled_root.path().join("usage.db").exists());
    assert!(!disabled_root.path().join("requests").exists());
    assert!(!disabled_root.path().join("sessions.db").exists());
    runtime.shutdown().await.unwrap();
  }

  #[tokio::test]
  async fn requested_shutdown_drains_and_flushes_the_event_hub() {
    let reservation = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    let compiled = compile_reject_only_gateway(&[("api", address)]);
    drop(reservation);

    let handled = Arc::new(AtomicUsize::new(0));
    let flushed = Arc::new(AtomicUsize::new(0));
    let (publisher, events) = test_event_runtime(CountingConsumer {
      handled: Arc::clone(&handled),
      flushed: Arc::clone(&flushed),
    });
    let bound = bind_compiled_gateway_with_events(&compiled, &[], None, events.emitter())
      .await
      .unwrap();
    publisher.publish(test_event()).await.unwrap();

    serve_bound_gateway(bound, events, async {}).await.unwrap();

    assert_eq!(handled.load(Ordering::SeqCst), 1);
    assert_eq!(flushed.load(Ordering::SeqCst), 1);
  }

  #[tokio::test]
  async fn consumer_failure_stops_serving_and_is_reported() {
    let reservation = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    let compiled = compile_reject_only_gateway(&[("api", address)]);
    drop(reservation);

    let (publisher, events) = test_event_runtime(FailingConsumer);
    let bound = bind_compiled_gateway_with_events(&compiled, &[], None, events.emitter())
      .await
      .unwrap();
    let server = tokio::spawn(serve_bound_gateway(bound, events, std::future::pending()));
    publisher.publish(test_event()).await.unwrap();

    let error = timeout(TEST_TIMEOUT, server)
      .await
      .expect("consumer failure should stop the listener")
      .unwrap()
      .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("gateway event hub failed while serving"), "{message}");
    assert!(message.contains("test.failing"), "{message}");
    assert!(message.contains("injected consumer failure"), "{message}");
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

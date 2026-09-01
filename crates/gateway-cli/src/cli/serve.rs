use crate::cli::config_cmd::RouteModeArg;
use crate::config::Config;
use anyhow::{Context, Result};
use clap::Args;
use futures::future::BoxFuture;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tokn_core::event::EventBus;
use tokn_router_legacy_config::v2::{
  project_v2_config, V2ForwardProxyProjectionOptions, V2ProjectionOptions, V2ProjectionWarning,
};

#[derive(Args, Debug)]
pub struct ServeArgs {
  #[arg(long)]
  pub host: Option<String>,
  #[arg(long)]
  pub port: Option<u16>,
  /// Also project and run the legacy proxy as a v2 forward-proxy listener.
  #[arg(long)]
  pub with_proxy: bool,
  /// Override the projected proxy listener's static route mode.
  #[arg(long, value_enum, requires = "with_proxy")]
  pub proxy_route_mode: Option<RouteModeArg>,
  /// Allow non-loopback binding. Projected v2 listeners also require [api_key].
  #[arg(long)]
  pub insecure_allow_remote: bool,
  /// Skip outbound proxy for this run.
  #[arg(long)]
  pub no_proxy: bool,
}

pub async fn run(cfg_path: Option<PathBuf>, args: ServeArgs) -> Result<()> {
  let resolved_cfg_path = cfg_path.map(Ok).unwrap_or_else(tokn_config::paths::config_path)?;
  match tokn_config::detect_config_schema(&resolved_cfg_path)? {
    tokn_config::ConfigSchema::Legacy => run_projected_legacy(resolved_cfg_path, args).await,
    tokn_config::ConfigSchema::V2 => run_v2(resolved_cfg_path, args).await,
  }
}

async fn run_projected_legacy(config_path: PathBuf, args: ServeArgs) -> Result<()> {
  let (legacy, resolved_config_path) = Config::load(Some(&config_path))?;
  let accounts = crate::server_runtime::load_accounts(Some(&resolved_config_path))?;
  let (compiled, accounts, warnings, args) = prepare_projected_legacy_runtime(legacy, accounts, args)?;
  log_projection_warnings(&resolved_config_path, &warnings);
  run_v2_runtime(compiled, accounts, args).await
}

async fn run_v2(config_path: PathBuf, args: ServeArgs) -> Result<()> {
  if args.with_proxy || args.proxy_route_mode.is_some() {
    anyhow::bail!(
      "v2 listeners are declared in config; remove --with-proxy/--proxy-route-mode and configure a forward_proxy listener"
    );
  }

  let compiled = tokn_config::v2::load_config(&config_path)?;
  let accounts = crate::server_runtime::load_accounts(Some(&config_path))?;
  run_v2_runtime(compiled, accounts, args).await
}

fn prepare_projected_legacy_runtime(
  mut legacy: Config,
  accounts: Vec<tokn_core::account::AccountConfig>,
  mut args: ServeArgs,
) -> Result<(
  tokn_config::v2::CompiledConfig,
  Vec<tokn_core::account::AccountConfig>,
  Vec<V2ProjectionWarning>,
  ServeArgs,
)> {
  if !args.with_proxy && args.proxy_route_mode.is_some() {
    anyhow::bail!("--proxy-route-mode requires --with-proxy");
  }
  if let Some(host) = args.host.take() {
    legacy.server.host = host;
  }
  if let Some(port) = args.port.take() {
    legacy.server.port = port;
  }
  if args.no_proxy {
    legacy.proxy = crate::config::ProxyConfig::default();
  }
  if args.with_proxy && args.insecure_allow_remote && legacy.proxy_mode.host == tokn_config::DEFAULT_HOST {
    legacy.proxy_mode.host = legacy.server.host.clone();
  }
  let forward_proxy = if args.with_proxy {
    let route_mode = args
      .proxy_route_mode
      .take()
      .map(Into::into)
      .unwrap_or(legacy.proxy_mode.route_mode);
    let registry = tokn_router::accounts::registry::Registry::builtin();
    let provider_hosts = registry
      .iter()
      .map(|descriptor| {
        (
          descriptor.id.to_string(),
          descriptor.hosts.iter().map(|host| (*host).to_string()).collect(),
        )
      })
      .collect::<BTreeMap<_, _>>();
    Some(V2ForwardProxyProjectionOptions {
      route_mode,
      default_intercept_hosts: tokn_router::proxy_default_intercept_hosts()
        .map(str::to_string)
        .collect(),
      provider_hosts,
    })
  } else {
    None
  };
  args.with_proxy = false;

  let projection = project_v2_config(
    &legacy,
    &accounts,
    V2ProjectionOptions {
      allow_insecure_public_listener: args.insecure_allow_remote,
      forward_proxy,
      ..V2ProjectionOptions::default()
    },
  )
  .context("project legacy config into the in-memory v2 runtime")?;
  let (_, compiled, accounts, warnings) = projection.into_parts();
  Ok((compiled, accounts, warnings, args))
}

fn log_projection_warnings(config_path: &std::path::Path, warnings: &[V2ProjectionWarning]) {
  tracing::warn!(
    config = %config_path.display(),
    warning_count = warnings.len(),
    "legacy config is running through the in-memory v2 runtime"
  );
  for warning in warnings {
    tracing::warn!(config = %config_path.display(), warning = %warning, "legacy-to-v2 projection warning");
  }
}

async fn run_v2_runtime(
  compiled: tokn_config::v2::CompiledConfig,
  accounts: Vec<tokn_core::account::AccountConfig>,
  args: ServeArgs,
) -> Result<()> {
  let (plan, service) = compiled.into_parts();
  let needs_access = plan
    .listeners()
    .values()
    .any(|listener| listener.client_auth() == tokn_policy::ClientAuthPlan::LocalKeys);
  let access = crate::server_runtime::load_access_store(needs_access)?;
  let (events, receiver, handlers, archive_runtime) = crate::server_runtime::build_v2_event_bus(service.persistence())?;
  let _event_thread = tokn_core::event::spawn_event_loop(receiver, handlers);
  let result = serve_v2_plan(
    plan,
    service,
    &accounts,
    access,
    events.clone(),
    args,
    shutdown_channel(),
  )
  .await;

  if let Some(archive_runtime) = archive_runtime {
    archive_runtime.shutdown().await;
  }
  events.shutdown().await;
  result
}

async fn serve_v2_plan(
  plan: tokn_policy::GatewayPlan,
  service: tokn_config::v2::ServicePlan,
  accounts: &[tokn_core::account::AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
  args: ServeArgs,
  shutdown: watch::Receiver<bool>,
) -> Result<()> {
  let states = tokn_router::v2::build_runtime_states_with_service(plan, service, accounts, access, events)?;
  let proxy_states = states.forward_proxy;
  let states = states.llm_api;
  let listener_count = states.len() + proxy_states.len();
  if listener_count != 1 && (args.host.is_some() || args.port.is_some()) {
    anyhow::bail!("--host and --port can only override a v2 config with exactly one listener");
  }

  let mut servers = Vec::<BoxFuture<'static, Result<()>>>::with_capacity(listener_count);
  for state in states {
    let configured = state.bind();
    let addr = if args.host.is_some() || args.port.is_some() {
      let host = args.host.clone().unwrap_or_else(|| configured.ip().to_string());
      let port = args.port.unwrap_or(configured.port());
      crate::server_runtime::resolve_bind_addr(&host, port, args.insecure_allow_remote)
        .with_context(|| format!("parse v2 bind address {host}:{port}"))?
    } else {
      configured
    };
    tracing::info!(listener = %state.listener_id(), %addr, "tokn-router v2 listener starting");
    let app = tokn_router::v2::router(state);
    let shutdown = shutdown.clone();
    servers.push(Box::pin(async move {
      crate::server_runtime::serve_http(app, addr, wait_for_shutdown(shutdown)).await
    }));
  }
  for state in proxy_states {
    let configured = state.bind();
    let addr = if args.host.is_some() || args.port.is_some() {
      let host = args.host.clone().unwrap_or_else(|| configured.ip().to_string());
      let port = args.port.unwrap_or(configured.port());
      crate::server_runtime::resolve_bind_addr(&host, port, args.insecure_allow_remote)
        .with_context(|| format!("parse v2 bind address {host}:{port}"))?
    } else {
      configured
    };
    tracing::info!(listener = %state.listener_id(), %addr, "tokn-router v2 forward proxy starting");
    let shutdown = shutdown.clone();
    servers.push(Box::pin(async move {
      tokn_router::v2::serve_forward_proxy(state, addr, wait_for_shutdown(shutdown)).await
    }));
  }
  futures::future::try_join_all(servers).await.map(|_| ())
}

fn shutdown_channel() -> watch::Receiver<bool> {
  let (tx, rx) = watch::channel(false);
  tokio::spawn(async move {
    let _ = tokio::signal::ctrl_c().await;
    let _ = tx.send(true);
  });
  rx
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
  if *shutdown.borrow() {
    return;
  }
  let _ = shutdown.changed().await;
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::path::Path;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::{TcpListener, TcpStream};

  fn unused_loopback_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
  }

  fn v2_serve_args() -> ServeArgs {
    ServeArgs {
      host: None,
      port: None,
      with_proxy: false,
      proxy_route_mode: None,
      insecure_allow_remote: false,
      no_proxy: false,
    }
  }

  fn account(id: &str, provider: &str) -> tokn_core::account::AccountConfig {
    toml::from_str(&format!(
      "id = {id:?}\nprovider = {provider:?}\nenabled = true\napi_key = \"test-key\"\n"
    ))
    .unwrap()
  }

  fn v2_listener_plan(api_addr: std::net::SocketAddr, proxy_addr: std::net::SocketAddr) -> tokn_policy::GatewayPlan {
    let config = format!(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "{api_addr}"
client_auth = "none"
default_http_action = {{ kind = "reject" }}

[listeners.proxy]
kind = "forward_proxy"
bind = "{proxy_addr}"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
default_connect = "reject"
"#
    );
    tokn_config::v2::parse(&config, Path::new("v2-serve-test.toml")).unwrap()
  }

  async fn wait_for_listener(addr: std::net::SocketAddr) {
    for _ in 0..50 {
      if TcpStream::connect(addr).await.is_ok() {
        return;
      }
      tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("listener did not start at {addr}");
  }

  async fn assert_connect_rejected(addr: std::net::SocketAddr) {
    let mut proxy = TcpStream::connect(addr).await.unwrap();
    proxy
      .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
      .await
      .unwrap();
    let mut response = Vec::new();
    proxy.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403 Forbidden"));
  }

  #[test]
  fn detects_v2_config_without_treating_legacy_as_v2() {
    let directory = tempfile::tempdir().unwrap();
    let v2_path = directory.path().join("v2.toml");
    let legacy_path = directory.path().join("legacy.toml");
    std::fs::write(&v2_path, "schema_version = 2\n").unwrap();
    std::fs::write(&legacy_path, "[server]\nport = 4141\n").unwrap();

    assert_eq!(
      tokn_config::detect_config_schema(&v2_path).unwrap(),
      tokn_config::ConfigSchema::V2
    );
    assert_eq!(
      tokn_config::detect_config_schema(&legacy_path).unwrap(),
      tokn_config::ConfigSchema::Legacy
    );
    assert_eq!(
      tokn_config::detect_config_schema(&directory.path().join("missing.toml")).unwrap(),
      tokn_config::ConfigSchema::Legacy
    );
  }

  #[test]
  fn invalid_toml_is_not_silently_treated_as_legacy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.toml");
    std::fs::write(&path, "schema_version = [").unwrap();

    assert!(tokn_config::detect_config_schema(&path).is_err());
  }

  #[test]
  fn legacy_serve_prepares_a_linkable_v2_runtime_without_proxy_settings() {
    let mut legacy = Config::default();
    legacy.server.port = 5151;
    legacy.proxy.url = Some("http://proxy.example:8080".into());
    let mut args = v2_serve_args();
    args.port = Some(5252);
    args.no_proxy = true;

    let (compiled, accounts, warnings, args) =
      prepare_projected_legacy_runtime(legacy, vec![account("primary", "openai")], args).unwrap();

    assert_eq!(compiled.gateway().listeners()["api"].bind().port(), 5252);
    assert!(compiled.service().outbound().proxy_url().is_none());
    assert_eq!(accounts.len(), 1);
    assert!(args.host.is_none());
    assert!(args.port.is_none());
    assert!(warnings.iter().any(|warning| matches!(
      warning,
      V2ProjectionWarning::BehaviorChange(tokn_router_legacy_config::v2::V2BehaviorChange::ManagedSelectionOrder)
    )));

    let (plan, service) = compiled.into_parts();
    let states = tokn_router::v2::build_runtime_states_with_service(
      plan,
      service,
      &accounts,
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
    )
    .unwrap();
    assert_eq!(states.llm_api.len(), 1);
    assert!(states.forward_proxy.is_empty());
  }

  #[test]
  fn projected_legacy_serve_requires_explicit_authenticated_remote_bind() {
    let mut legacy = Config::default();
    legacy.server.host = "0.0.0.0".into();
    let accounts = vec![account("primary", "openai")];

    let error = prepare_projected_legacy_runtime(legacy.clone(), accounts.clone(), v2_serve_args()).unwrap_err();
    assert!(format!("{error:#}").contains("requires an explicit public-listener review"));

    legacy.api_key.enabled = true;
    let mut args = v2_serve_args();
    args.insecure_allow_remote = true;
    let (compiled, _, warnings, _) = prepare_projected_legacy_runtime(legacy, accounts, args).unwrap();
    assert_eq!(
      compiled.gateway().listeners()["api"].bind(),
      "0.0.0.0:4141".parse().unwrap()
    );
    assert!(warnings
      .iter()
      .any(|warning| matches!(warning, V2ProjectionWarning::RemoteApiBindAllowed { .. })));
  }

  #[test]
  fn projected_legacy_serve_builds_both_v2_listeners() {
    let ca = tempfile::tempdir().unwrap();
    let mut legacy = Config::default();
    legacy.proxy_mode.ca_dir = Some(ca.path().to_path_buf());
    let mut args = v2_serve_args();
    args.with_proxy = true;
    args.proxy_route_mode = Some(RouteModeArg::Passthrough);
    let (compiled, accounts, warnings, args) =
      prepare_projected_legacy_runtime(legacy, vec![account("primary", "openai")], args).unwrap();

    assert_eq!(compiled.gateway().listeners().len(), 2);
    assert!(warnings.iter().any(|warning| matches!(
      warning,
      V2ProjectionWarning::BehaviorChange(tokn_router_legacy_config::v2::V2BehaviorChange::ProxyRequestModeOverrides)
    )));
    assert!(!args.with_proxy);
    assert!(args.proxy_route_mode.is_none());

    let (plan, service) = compiled.into_parts();
    let states = tokn_router::v2::build_runtime_states_with_service(
      plan,
      service,
      &accounts,
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
    )
    .unwrap();
    assert_eq!(states.llm_api.len(), 1);
    assert_eq!(states.forward_proxy.len(), 1);
    assert!(ca.path().join("ca.crt").exists());
  }

  #[test]
  fn projected_remote_legacy_proxy_follows_api_host_and_requires_authentication() {
    let mut legacy = Config::default();
    legacy.server.host = "0.0.0.0".into();
    let mut args = v2_serve_args();
    args.with_proxy = true;
    args.insecure_allow_remote = true;

    let error = prepare_projected_legacy_runtime(legacy.clone(), vec![account("primary", "openai")], args).unwrap_err();
    assert!(format!("{error:#}").contains("unauthenticated listeners must bind to a loopback address"));

    legacy.api_key.enabled = true;
    let mut args = v2_serve_args();
    args.with_proxy = true;
    args.insecure_allow_remote = true;
    let (compiled, _, warnings, _) =
      prepare_projected_legacy_runtime(legacy, vec![account("primary", "openai")], args).unwrap();
    assert_eq!(
      compiled.gateway().listeners()["proxy"].bind(),
      "0.0.0.0:4142".parse().unwrap()
    );
    assert!(warnings
      .iter()
      .any(|warning| matches!(warning, V2ProjectionWarning::RemoteForwardProxyBindAllowed { .. })));
  }

  #[tokio::test]
  async fn projected_legacy_proxy_serves_passthrough_http() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let received = tokio::spawn(async move {
      let (mut stream, _) = upstream.accept().await.unwrap();
      let mut request = Vec::new();
      let mut buffer = [0_u8; 1024];
      loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") && request.ends_with(b"hello") {
          break;
        }
      }
      stream
        .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld")
        .await
        .unwrap();
      request
    });

    let ca = tempfile::tempdir().unwrap();
    let api_addr = unused_loopback_addr();
    let proxy_addr = unused_loopback_addr();
    let mut legacy = Config::default();
    legacy.server.host = api_addr.ip().to_string();
    legacy.server.port = api_addr.port();
    legacy.proxy_mode.host = proxy_addr.ip().to_string();
    legacy.proxy_mode.port = proxy_addr.port();
    legacy.proxy_mode.ca_dir = Some(ca.path().to_path_buf());
    let mut args = v2_serve_args();
    args.with_proxy = true;
    args.proxy_route_mode = Some(RouteModeArg::Passthrough);
    let (compiled, accounts, _, args) =
      prepare_projected_legacy_runtime(legacy, vec![account("primary", "openai")], args).unwrap();
    let (plan, service) = compiled.into_parts();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
      serve_v2_plan(
        plan,
        service,
        &accounts,
        Arc::new(tokn_access::AccessStore::disabled()),
        Arc::new(EventBus::noop()),
        args,
        shutdown_rx,
      )
      .await
    });
    wait_for_listener(api_addr).await;
    wait_for_listener(proxy_addr).await;

    let mut proxy = TcpStream::connect(proxy_addr).await.unwrap();
    proxy
      .write_all(
        format!(
          "POST http://{upstream_addr}/custom HTTP/1.1\r\nHost: {upstream_addr}\r\nAuthorization: Bearer client-secret\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        )
        .as_bytes(),
      )
      .await
      .unwrap();
    let mut response = Vec::new();
    proxy.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 201 Created"));

    let request = String::from_utf8(received.await.unwrap()).unwrap();
    assert!(request.starts_with("POST /custom HTTP/1.1\r\n"));
    assert!(request
      .to_ascii_lowercase()
      .contains("authorization: bearer client-secret\r\n"));
    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
  }

  #[tokio::test]
  async fn v2_rejects_legacy_proxy_flags_before_loading_config() {
    let args = ServeArgs {
      host: None,
      port: None,
      with_proxy: true,
      proxy_route_mode: None,
      insecure_allow_remote: false,
      no_proxy: false,
    };

    let error = run_v2(PathBuf::from("missing.toml"), args).await.unwrap_err();
    assert!(error.to_string().contains("v2 listeners are declared in config"));
  }

  #[tokio::test]
  async fn v2_serves_llm_api_and_forward_proxy_listeners_together() {
    let api_addr = unused_loopback_addr();
    let proxy_addr = unused_loopback_addr();
    let plan = v2_listener_plan(api_addr, proxy_addr);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(serve_v2_plan(
      plan,
      tokn_config::v2::ServicePlan::default(),
      &[],
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
      v2_serve_args(),
      shutdown_rx,
    ));

    wait_for_listener(api_addr).await;
    wait_for_listener(proxy_addr).await;

    let mut api = TcpStream::connect(api_addr).await.unwrap();
    api
      .write_all(
        b"POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
      )
      .await
      .unwrap();
    let mut api_response = Vec::new();
    api.read_to_end(&mut api_response).await.unwrap();
    assert!(api_response.starts_with(b"HTTP/1.1 403 Forbidden"));

    assert_connect_rejected(proxy_addr).await;

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
  }

  #[tokio::test]
  async fn v2_listener_override_requires_exactly_one_listener() {
    let plan = v2_listener_plan(unused_loopback_addr(), unused_loopback_addr());
    let mut args = v2_serve_args();
    args.port = Some(4141);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let error = serve_v2_plan(
      plan,
      tokn_config::v2::ServicePlan::default(),
      &[],
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
      args,
      shutdown_rx,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("exactly one listener"));
  }

  #[tokio::test]
  async fn v2_applies_bind_override_to_single_forward_proxy_listener() {
    let configured_addr = unused_loopback_addr();
    let override_addr = unused_loopback_addr();
    let config = format!(
      r#"
schema_version = 2

[listeners.proxy]
kind = "forward_proxy"
bind = "{configured_addr}"
client_auth = "none"
default_http_action = {{ kind = "reject" }}
default_connect = "reject"
"#
    );
    let plan = tokn_config::v2::parse(&config, Path::new("v2-proxy-override.toml")).unwrap();
    let mut args = v2_serve_args();
    args.host = Some(override_addr.ip().to_string());
    args.port = Some(override_addr.port());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(serve_v2_plan(
      plan,
      tokn_config::v2::ServicePlan::default(),
      &[],
      Arc::new(tokn_access::AccessStore::disabled()),
      Arc::new(EventBus::noop()),
      args,
      shutdown_rx,
    ));

    wait_for_listener(override_addr).await;
    assert_connect_rejected(override_addr).await;

    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
  }
}

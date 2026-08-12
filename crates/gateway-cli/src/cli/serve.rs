use crate::cli::config_cmd::RouteModeArg;
use crate::cli::lan_bootstrap;
use crate::config::Config;
use anyhow::{Context, Result};
use clap::Args;
use futures::future::BoxFuture;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tokn_config::{RouteMode, DEFAULT_HOST};
use tokn_core::event::EventBus;

#[derive(Args, Debug)]
pub struct ServeArgs {
  #[arg(long)]
  pub host: Option<String>,
  #[arg(long)]
  pub port: Option<u16>,
  /// Also run the local MITM proxy in the same process.
  #[arg(long)]
  pub with_proxy: bool,
  /// Override the proxy listener's default route mode when `--with-proxy` is enabled.
  #[arg(long, value_enum, requires = "with_proxy")]
  pub proxy_route_mode: Option<RouteModeArg>,
  /// Allow non-loopback binding. Enable [api_key] for managed API and intercepted proxy requests.
  #[arg(long)]
  pub insecure_allow_remote: bool,
  /// Skip outbound proxy for this run.
  #[arg(long)]
  pub no_proxy: bool,
}

pub async fn run(cfg_path: Option<PathBuf>, args: ServeArgs) -> Result<()> {
  let resolved_cfg_path = cfg_path
    .clone()
    .map(Ok)
    .unwrap_or_else(tokn_config::paths::config_path)?;
  if is_v2_config(&resolved_cfg_path)? {
    return run_v2(resolved_cfg_path, args).await;
  }
  run_legacy(cfg_path, args).await
}

async fn run_legacy(cfg_path: Option<PathBuf>, args: ServeArgs) -> Result<()> {
  let (mut cfg, resolved_cfg_path) = Config::load(cfg_path.as_deref())?;
  if args.no_proxy {
    cfg.proxy = crate::config::ProxyConfig::default();
  }
  let accounts = crate::server_runtime::load_accounts(Some(&resolved_cfg_path))?;
  let access = crate::server_runtime::load_access_store(cfg.api_key.enabled)?;

  let host = args.host.unwrap_or_else(|| cfg.server.host.clone());
  let port = args.port.unwrap_or(cfg.server.port);
  let addr = crate::server_runtime::resolve_bind_addr(&host, port, args.insecure_allow_remote)
    .with_context(|| format!("parse bind addr {host}:{port}"))?;

  let (events, receiver, handlers, archive_runtime) = crate::server_runtime::build_event_bus(&cfg)?;
  let _event_thread = tokn_core::event::spawn_event_loop(receiver, handlers);
  let server_mode = effective_server_mode(&cfg);
  let proxy_route_override = args.proxy_route_mode.map(Into::into);
  let proxy_mode = proxy_route_override.unwrap_or(cfg.proxy_mode.route_mode);
  let mut app_state = crate::server_runtime::build_state_for_route_mode(&cfg, &accounts, events.clone(), server_mode)?;
  app_state.access = access.clone();
  let n = app_state.pool.len();
  let app_live = tokn_router::api::LiveAppState::new(app_state);
  let proxy_live = if args.with_proxy {
    let mut proxy_state =
      crate::server_runtime::build_proxy_state_for_route_mode(&cfg, &accounts, events.clone(), proxy_mode)?;
    proxy_state.access = access;
    Some(tokn_router::api::LiveAppState::new(proxy_state))
  } else {
    None
  };
  if !args.insecure_allow_remote {
    install_reload_endpoint(
      &app_live,
      proxy_live.clone(),
      resolved_cfg_path.clone(),
      args.no_proxy,
      args.with_proxy,
      proxy_route_override,
      events.clone(),
    );
  }
  let mut app = tokn_router::api::router_live(app_live);

  tracing::info!(%addr, accounts = n, route_mode = route_mode_name(server_mode), "tokn-router listening");

  let result = if args.with_proxy {
    let proxy_host = proxy_host_for_with_proxy(&host, &cfg.proxy_mode.host, args.insecure_allow_remote);
    let proxy_port = cfg.proxy_mode.port;
    let proxy_addr = crate::server_runtime::resolve_bind_addr(&proxy_host, proxy_port, args.insecure_allow_remote)
      .with_context(|| format!("parse bind addr {proxy_host}:{proxy_port}"))?;
    let ca_dir = cfg.proxy_mode.resolved_ca_dir()?;
    let ca = tokn_router::proxy::load_or_generate_ca(&ca_dir, false)?;
    let ca_fingerprint = ca.fingerprint_sha256();
    let bootstrap = if args.insecure_allow_remote {
      Some(lan_bootstrap::BootstrapState::new(&ca, port, proxy_port)?)
    } else {
      None
    };
    let plain_http_handler = bootstrap.clone().map(lan_bootstrap::proxy_plain_http_handler);
    if let Some(bootstrap) = bootstrap {
      app = app.merge(lan_bootstrap::router(bootstrap));
      println!("LAN bootstrap: {}", lan_bootstrap::display_bootstrap_url(&host, port));
      println!(
        "LAN proxy bootstrap: {}",
        lan_bootstrap::display_bootstrap_url(&proxy_host, proxy_port)
      );
      println!("LAN bootstrap CA sha256: {ca_fingerprint}");
    }
    println!("tokn-router proxy listening on http://{proxy_addr}");
    println!("CA: {} (sha256:{ca_fingerprint})", ca.cert_path().display());
    println!("Proxy route mode: {}", route_mode_name(proxy_mode));

    let proxy_state = proxy_live.expect("proxy live state is constructed when --with-proxy is set");
    let proxy_options = tokn_router::proxy::ProxyOptions {
      addr: proxy_addr,
      ca_dir,
      intercept_hosts: cfg.proxy_mode.intercept_hosts.clone(),
      passthrough_hosts: cfg.proxy_mode.passthrough_hosts.clone(),
      outbound_proxy: cfg.proxy.to_http_options(),
      plain_http_handler,
    };
    let shutdown = shutdown_channel();
    tokio::try_join!(
      crate::server_runtime::serve_http(app, addr, wait_for_shutdown(shutdown.clone())),
      tokn_router::proxy::serve_live(proxy_state, proxy_options, wait_for_shutdown(shutdown)),
    )
    .map(|_| ())
  } else {
    crate::server_runtime::serve_http(app, addr, async {
      let _ = tokio::signal::ctrl_c().await;
    })
    .await
  };

  if let Some(archive_runtime) = archive_runtime {
    archive_runtime.shutdown().await;
  }
  events.shutdown().await;
  result
}

async fn run_v2(config_path: PathBuf, args: ServeArgs) -> Result<()> {
  if args.with_proxy || args.proxy_route_mode.is_some() {
    anyhow::bail!(
      "v2 listeners are declared in config; remove --with-proxy/--proxy-route-mode and configure a forward_proxy listener"
    );
  }

  let plan = tokn_config::v2::load(&config_path)?;
  let accounts = crate::server_runtime::load_accounts(Some(&config_path))?;
  let needs_access = plan
    .listeners()
    .values()
    .any(|listener| listener.client_auth() == tokn_policy::ClientAuthPlan::LocalKeys);
  let access = crate::server_runtime::load_access_store(needs_access)?;
  // V2 does not expose operational event/database settings yet. Keep the
  // existing defaults, including the default app-data database path.
  let operational = Config::default();
  let (events, receiver, handlers, archive_runtime) = crate::server_runtime::build_event_bus(&operational)?;
  let _event_thread = tokn_core::event::spawn_event_loop(receiver, handlers);
  let result = serve_v2_plan(plan, &accounts, access, events.clone(), args, shutdown_channel()).await;

  if let Some(archive_runtime) = archive_runtime {
    archive_runtime.shutdown().await;
  }
  events.shutdown().await;
  result
}

async fn serve_v2_plan(
  plan: tokn_policy::GatewayPlan,
  accounts: &[tokn_core::account::AccountConfig],
  access: Arc<tokn_access::AccessStore>,
  events: Arc<EventBus>,
  args: ServeArgs,
  shutdown: watch::Receiver<bool>,
) -> Result<()> {
  let proxy_states = tokn_router::v2::build_forward_proxy_states(&plan, access.clone())?;
  let states = tokn_router::v2::build_states(plan, accounts, access, events)?;
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

fn is_v2_config(path: &Path) -> Result<bool> {
  if !path.exists() {
    return Ok(false);
  }
  let contents = std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
  let document: toml::Value = toml::from_str(&contents).with_context(|| format!("parse config {}", path.display()))?;
  Ok(document.get("schema_version").and_then(toml::Value::as_integer) == Some(2))
}

struct ReloadState {
  generation: u64,
}

#[allow(clippy::too_many_arguments)]
fn install_reload_endpoint(
  app_live: &tokn_router::api::LiveAppState,
  proxy_live: Option<tokn_router::api::LiveAppState>,
  config_path: PathBuf,
  no_proxy: bool,
  with_proxy: bool,
  proxy_route_override: Option<RouteMode>,
  events: Arc<EventBus>,
) {
  let lock = Arc::new(Mutex::new(ReloadState { generation: 0 }));
  let app_live_for_reload = app_live.clone();
  let reloader = tokn_router::api::AdminReloader::new(move || {
    let app_live = app_live_for_reload.clone();
    let proxy_live = proxy_live.clone();
    let config_path = config_path.clone();
    let events = events.clone();
    let lock = lock.clone();
    async move {
      let mut guard = lock.lock().await;
      let (mut cfg, resolved_cfg_path) = Config::load(Some(&config_path)).map_err(|e| e.to_string())?;
      if no_proxy {
        cfg.proxy = crate::config::ProxyConfig::default();
      }
      let accounts = crate::server_runtime::load_accounts(Some(&resolved_cfg_path)).map_err(|e| e.to_string())?;
      let server_mode = effective_server_mode(&cfg);
      let proxy_mode = proxy_route_override.unwrap_or(cfg.proxy_mode.route_mode);
      let mut app_state =
        crate::server_runtime::build_state_for_route_mode(&cfg, &accounts, events.clone(), server_mode)
          .map_err(|e| e.to_string())?;
      let access = crate::server_runtime::load_access_store(cfg.api_key.enabled).map_err(|e| e.to_string())?;
      app_state.access = access.clone();
      let proxy_state = if with_proxy {
        let mut state =
          crate::server_runtime::build_proxy_state_for_route_mode(&cfg, &accounts, events.clone(), proxy_mode)
            .map_err(|e| e.to_string())?;
        state.access = access;
        Some(state)
      } else {
        None
      };

      app_live.swap(app_state);
      if let (Some(live), Some(state)) = (proxy_live, proxy_state) {
        live.swap(state);
      }
      guard.generation = guard.generation.saturating_add(1);
      tracing::info!(
        generation = guard.generation,
        accounts = accounts.len(),
        route_mode = route_mode_name(server_mode),
        "config reloaded"
      );
      Ok(tokn_router::api::ReloadReport {
        status: "reloaded",
        generation: guard.generation,
        accounts: accounts.len(),
        route_mode: route_mode_name(server_mode),
      })
    }
  });
  if app_live.set_admin_reloader(reloader).is_err() {
    tracing::warn!("admin config reload endpoint was already configured");
  }
}

fn effective_server_mode(cfg: &Config) -> RouteMode {
  if cfg.defaults.mode == RouteMode::Route && cfg.server.route_mode != RouteMode::Route {
    cfg.server.route_mode
  } else {
    cfg.defaults.mode
  }
}

#[cfg(test)]
fn shared_route_mode(server_mode: RouteMode, proxy_mode: RouteMode, with_proxy: bool) -> RouteMode {
  if !with_proxy || server_mode != RouteMode::Passthrough {
    server_mode
  } else {
    proxy_mode
  }
}

fn proxy_host_for_with_proxy(server_host: &str, configured_proxy_host: &str, insecure_allow_remote: bool) -> String {
  if insecure_allow_remote && configured_proxy_host == DEFAULT_HOST {
    server_host.to_string()
  } else {
    configured_proxy_host.to_string()
  }
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

fn route_mode_name(mode: RouteMode) -> &'static str {
  match mode {
    RouteMode::Passthrough => "passthrough",
    RouteMode::Switch => "switch",
    RouteMode::Exact => "exact",
    RouteMode::Route => "route",
    RouteMode::Fuzzy => "fuzzy",
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpStream;

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

    assert!(is_v2_config(&v2_path).unwrap());
    assert!(!is_v2_config(&legacy_path).unwrap());
    assert!(!is_v2_config(&directory.path().join("missing.toml")).unwrap());
  }

  #[test]
  fn invalid_toml_is_not_silently_treated_as_legacy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.toml");
    std::fs::write(&path, "schema_version = [").unwrap();

    assert!(is_v2_config(&path).is_err());
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

  #[test]
  fn shared_mode_prefers_non_passthrough_listener_when_needed() {
    assert_eq!(
      shared_route_mode(RouteMode::Passthrough, RouteMode::Exact, true),
      RouteMode::Exact
    );
    assert_eq!(
      shared_route_mode(RouteMode::Route, RouteMode::Passthrough, true),
      RouteMode::Route
    );
    assert_eq!(
      shared_route_mode(RouteMode::Passthrough, RouteMode::Passthrough, true),
      RouteMode::Passthrough
    );
  }

  #[test]
  fn lan_mode_proxy_host_follows_server_host_when_proxy_host_is_default() {
    assert_eq!(proxy_host_for_with_proxy("0.0.0.0", DEFAULT_HOST, true), "0.0.0.0");
  }

  #[test]
  fn lan_mode_proxy_host_preserves_explicit_proxy_host() {
    assert_eq!(
      proxy_host_for_with_proxy("0.0.0.0", "192.168.1.22", true),
      "192.168.1.22"
    );
  }

  #[test]
  fn local_mode_proxy_host_keeps_default_loopback() {
    assert_eq!(proxy_host_for_with_proxy("0.0.0.0", DEFAULT_HOST, false), DEFAULT_HOST);
  }
}

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use tokn_policy::{ForwardProxyListenerPlan, GatewayPlan, ListenerPlan};

const DEFAULT_CLIENT_NO_PROXY: &[&str] = &["localhost", "127.0.0.1", "::1"];

#[derive(Args, Debug)]
pub struct ProxyArgs {
  /// Compiled forward-proxy listener id. Required when more than one exists.
  #[arg(long, global = true)]
  pub listener: Option<String>,

  #[command(subcommand)]
  pub cmd: ProxyCmd,
}

#[derive(Subcommand, Debug)]
pub enum ProxyCmd {
  /// Print shell environment exports for proxy + CA trust
  Env(EnvArgs),
  /// Enter a shell with proxy + CA env vars set
  Shell(ShellArgs),
  /// Run a known coding agent with proxy + CA env vars set
  Run(RunArgs),
  /// Run an arbitrary command with proxy + CA env vars set
  Exec(ExecArgs),
  /// Run Codex with proxy + CA env vars set
  Codex(AgentProxyArgs),
  /// Run opencode with proxy + CA env vars set
  Opencode(AgentProxyArgs),
  /// Run pi with proxy + CA env vars set
  Pi(AgentProxyArgs),
  /// Inspect or regenerate the local proxy CA
  Ca(CaArgs),
}

#[derive(Args, Debug)]
pub struct EnvArgs {
  #[arg(long, value_enum, default_value_t = Shell::Sh)]
  pub shell: Shell,
  /// Output encoding. JSON is the stable machine-readable interface.
  #[arg(long, value_enum, default_value_t = EnvFormat::Shell)]
  pub format: EnvFormat,
}

#[derive(Args, Debug)]
pub struct ShellArgs {
  #[arg(long)]
  pub shell: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct AgentProxyArgs {
  /// Run via npx instead of a local executable.
  #[arg(long)]
  pub npx: bool,
  /// Arguments forwarded to the agent command.
  #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
  pub args: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
  /// Run via npx instead of a local executable.
  #[arg(long)]
  pub npx: bool,
  /// Agent preset to run.
  #[arg(value_enum)]
  pub agent: AgentKind,
  /// Arguments forwarded to the agent command.
  #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
  pub args: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ExecArgs {
  /// Command and arguments to run.
  #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
  pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct CaArgs {
  #[command(subcommand)]
  pub cmd: CaCmd,
}

#[derive(Subcommand, Debug)]
pub enum CaCmd {
  /// Print the CA cert path
  Path,
  /// Print CA details
  Show,
  /// Regenerate the CA and overwrite existing files
  Regenerate,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Shell {
  Sh,
  Fish,
  Pwsh,
  Bash,
  Zsh,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum EnvFormat {
  Shell,
  Json,
}

pub async fn run(cfg_path: Option<PathBuf>, args: ProxyArgs) -> Result<()> {
  let listener = resolve_proxy_listener(cfg_path.as_deref(), args.listener.as_deref())?;
  match args.cmd {
    ProxyCmd::Env(args) => env(&listener, args).await,
    ProxyCmd::Shell(args) => shell(&listener, args).await,
    ProxyCmd::Run(args) => {
      agent(
        &listener,
        args.agent,
        AgentProxyArgs {
          npx: args.npx,
          args: args.args,
        },
      )
      .await
    }
    ProxyCmd::Exec(args) => exec(&listener, args).await,
    ProxyCmd::Codex(args) => agent(&listener, AgentKind::Codex, args).await,
    ProxyCmd::Opencode(args) => agent(&listener, AgentKind::Opencode, args).await,
    ProxyCmd::Pi(args) => agent(&listener, AgentKind::Pi, args).await,
    ProxyCmd::Ca(args) => ca(&listener, args).await,
  }
}

async fn env(listener: &ProxyListenerConfig, args: EnvArgs) -> Result<()> {
  let env = resolved_proxy_env(listener)?;
  match args.format {
    EnvFormat::Json => print_json(&env)?,
    EnvFormat::Shell => match args.shell {
      Shell::Sh | Shell::Bash | Shell::Zsh => print_sh(&env),
      Shell::Fish => print_fish(&env),
      Shell::Pwsh => print_pwsh(&env),
    },
  }
  Ok(())
}

async fn shell(listener: &ProxyListenerConfig, args: ShellArgs) -> Result<()> {
  let env = resolved_proxy_env(listener)?;
  let shell = detect_shell(args.shell.as_deref())?;
  println!("Entering proxy shell: {}", shell.path.display());
  println!("HTTPS_PROXY={}", env.get("HTTPS_PROXY").unwrap_or(""));
  println!("SSL_CERT_FILE={}", env.get("SSL_CERT_FILE").unwrap_or(""));
  println!("Type 'exit' to leave this shell.");
  let mut cmd = Command::new(&shell.path);
  cmd.envs(env.vars.iter().map(|(k, v)| (k.as_str(), v.as_str())));
  apply_shell_arg0(&mut cmd, shell.arg0.as_deref());
  let status = cmd
    .status()
    .with_context(|| format!("launch shell {}", shell.path.display()))?;
  if !status.success() {
    anyhow::bail!("shell exited with status {status}");
  }
  Ok(())
}

async fn agent(listener: &ProxyListenerConfig, kind: AgentKind, args: AgentProxyArgs) -> Result<()> {
  let env = resolved_proxy_env(listener)?;
  let spec = agent_command_spec(kind, args.npx, args.args);
  run_with_proxy_env(kind.name(), &env, spec)
}

async fn exec(listener: &ProxyListenerConfig, args: ExecArgs) -> Result<()> {
  let env = resolved_proxy_env(listener)?;
  let spec = CommandSpec::from_argv(args.command)?;
  run_with_proxy_env("command", &env, spec)
}

fn run_with_proxy_env(label: &str, env: &ProxyEnv, spec: CommandSpec) -> Result<()> {
  eprintln!("Running {label} with proxy env: {}", spec.display());
  eprintln!("HTTPS_PROXY={}", env.get("HTTPS_PROXY").unwrap_or(""));
  eprintln!("SSL_CERT_FILE={}", env.get("SSL_CERT_FILE").unwrap_or(""));

  let mut cmd = Command::new(&spec.program);
  cmd.args(&spec.args);
  cmd.envs(env.vars.iter().map(|(k, v)| (k.as_str(), v.as_str())));
  let status = cmd.status().with_context(|| format!("launch {}", spec.display()))?;
  if !status.success() {
    anyhow::bail!("{label} exited with status {status}");
  }
  Ok(())
}

async fn ca(listener: &ProxyListenerConfig, args: CaArgs) -> Result<()> {
  let ca_dir = listener.ca_dir.as_deref().with_context(|| {
    format!(
      "forward-proxy listener '{}' has no interception CA; configure ca_dir and at least one intercept action",
      listener.id
    )
  })?;
  match args.cmd {
    CaCmd::Path => {
      let ca = tokn_router::runtime::load_or_generate_ca(ca_dir, false)?;
      println!("{}", ca.cert_path().display());
    }
    CaCmd::Show => {
      let ca = tokn_router::runtime::load_or_generate_ca(ca_dir, false)?;
      println!("cert: {}", ca.cert_path().display());
      println!("bundle: {}", ca.ensure_bundle()?.display());
      println!("key: {}", ca.key_path().display());
      println!("sha256: {}", ca.fingerprint_sha256());
    }
    CaCmd::Regenerate => {
      let ca = tokn_router::runtime::load_or_generate_ca(ca_dir, true)?;
      println!("regenerated CA at {}", ca.cert_path().display());
      println!("sha256: {}", ca.fingerprint_sha256());
    }
  }
  Ok(())
}

fn print_sh(env: &ProxyEnv) {
  for (key, value) in &env.vars {
    println!("export {key}={}", quote_sh(value));
  }
}

fn print_fish(env: &ProxyEnv) {
  for (key, value) in &env.vars {
    println!("set -gx {key} {}", quote_fish(value));
  }
}

fn print_pwsh(env: &ProxyEnv) {
  for (key, value) in &env.vars {
    println!("$Env:{key} = {}", quote_pwsh(value));
  }
}

fn print_json(env: &ProxyEnv) -> Result<()> {
  let vars = env
    .vars
    .iter()
    .map(|(key, value)| (key.as_str(), value.as_str()))
    .collect::<BTreeMap<_, _>>();
  println!("{}", serde_json::to_string(&vars)?);
  Ok(())
}

fn quote_sh(value: &str) -> String {
  format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn quote_fish(value: &str) -> String {
  format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn quote_pwsh(value: &str) -> String {
  format!("'{}'", value.replace('\'', "''"))
}

fn resolved_proxy_env(listener: &ProxyListenerConfig) -> Result<ProxyEnv> {
  let proxy_url = format!("http://{}", listener.client_addr);
  let mut vars = vec![
    ("HTTPS_PROXY".into(), proxy_url.clone()),
    ("HTTP_PROXY".into(), proxy_url),
    ("NO_PROXY".into(), client_no_proxy_value(&listener.no_proxy)),
  ];
  if let Some(ca_dir) = &listener.ca_dir {
    let ca = tokn_router::runtime::load_or_generate_ca(ca_dir, false)?;
    let cert = ca.cert_path().display().to_string();
    let bundle = ca.ensure_bundle()?.display().to_string();
    vars.extend([
      ("SSL_CERT_FILE".into(), bundle.clone()),
      ("NODE_EXTRA_CA_CERTS".into(), cert),
      ("CODEX_CA_CERTIFICATE".into(), bundle.clone()),
      ("REQUESTS_CA_BUNDLE".into(), bundle.clone()),
      ("CURL_CA_BUNDLE".into(), bundle.clone()),
      ("GIT_SSL_CAINFO".into(), bundle),
    ]);
  }
  Ok(ProxyEnv { vars })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProxyListenerConfig {
  id: String,
  client_addr: SocketAddr,
  ca_dir: Option<PathBuf>,
  no_proxy: Vec<String>,
}

fn resolve_proxy_listener(config_path: Option<&Path>, requested_listener: Option<&str>) -> Result<ProxyListenerConfig> {
  let config_path = match config_path {
    Some(path) => path.to_path_buf(),
    None => tokn_config::paths::config_path().context("resolve the default gateway config path")?,
  };
  let compiled = tokn_config::v2::load(&config_path)
    .with_context(|| format!("load compiled gateway config `{}`", config_path.display()))?;
  select_proxy_listener(
    compiled.gateway(),
    requested_listener,
    compiled.service().outbound().no_proxy(),
  )
}

fn select_proxy_listener(
  gateway: &GatewayPlan,
  requested_listener: Option<&str>,
  no_proxy: &[String],
) -> Result<ProxyListenerConfig> {
  let selected = if let Some(requested) = requested_listener {
    let (id, listener) = gateway
      .listeners()
      .iter()
      .find(|(id, _)| id.as_str() == requested)
      .with_context(|| format!("compiled config has no listener named '{requested}'"))?;
    let ListenerPlan::ForwardProxy(listener) = listener else {
      anyhow::bail!("listener '{requested}' is not a forward_proxy listener");
    };
    (id, listener)
  } else {
    let mut candidates = gateway.listeners().iter().filter_map(|(id, listener)| match listener {
      ListenerPlan::ForwardProxy(listener) => Some((id, listener)),
      ListenerPlan::LlmApi(_) => None,
    });
    let first = candidates
      .next()
      .context("compiled config has no forward_proxy listener")?;
    let remaining = candidates.map(|(id, _)| id.as_str()).collect::<Vec<_>>();
    if !remaining.is_empty() {
      let mut ids = vec![first.0.as_str()];
      ids.extend(remaining);
      anyhow::bail!(
        "compiled config has multiple forward_proxy listeners ({}); select one with --listener",
        ids.join(", ")
      );
    }
    first
  };

  Ok(proxy_listener_config(selected.0.as_str(), selected.1, no_proxy))
}

fn proxy_listener_config(id: &str, listener: &ForwardProxyListenerPlan, no_proxy: &[String]) -> ProxyListenerConfig {
  ProxyListenerConfig {
    id: id.to_string(),
    client_addr: client_proxy_addr(listener.bind()),
    ca_dir: listener.tls().map(|tls| tls.ca_dir().to_path_buf()),
    no_proxy: no_proxy.to_vec(),
  }
}

fn client_proxy_addr(bind: SocketAddr) -> SocketAddr {
  let ip = match bind.ip() {
    IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
    ip => ip,
  };
  SocketAddr::new(ip, bind.port())
}

fn client_no_proxy_value(configured: &[String]) -> String {
  let mut seen = HashSet::new();
  DEFAULT_CLIENT_NO_PROXY
    .iter()
    .copied()
    .map(str::to_string)
    .chain(configured.iter().map(|entry| entry.trim().to_string()))
    .filter(|entry| !entry.is_empty())
    .filter(|entry| seen.insert(entry.clone()))
    .collect::<Vec<_>>()
    .join(",")
}

#[derive(Debug)]
struct ProxyEnv {
  vars: Vec<(String, String)>,
}

impl ProxyEnv {
  fn get(&self, key: &str) -> Option<&str> {
    self.vars.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
  }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum AgentKind {
  Codex,
  Opencode,
  Pi,
}

impl AgentKind {
  fn name(self) -> &'static str {
    match self {
      Self::Codex => "codex",
      Self::Opencode => "opencode",
      Self::Pi => "pi",
    }
  }

  fn npx_package(self) -> &'static str {
    match self {
      Self::Codex => "@openai/codex",
      Self::Opencode => "opencode-ai",
      Self::Pi => "@earendil-works/pi-coding-agent",
    }
  }
}

#[derive(Debug, Eq, PartialEq)]
struct CommandSpec {
  program: String,
  args: Vec<String>,
}

impl CommandSpec {
  fn from_argv(argv: Vec<String>) -> Result<Self> {
    let mut argv = argv.into_iter();
    let program = argv.next().context("missing command to execute")?;
    Ok(Self {
      program,
      args: argv.collect(),
    })
  }

  fn display(&self) -> String {
    std::iter::once(self.program.as_str())
      .chain(self.args.iter().map(String::as_str))
      .collect::<Vec<_>>()
      .join(" ")
  }
}

fn agent_command_spec(kind: AgentKind, npx: bool, forwarded_args: Vec<String>) -> CommandSpec {
  if npx {
    CommandSpec {
      program: "npx".into(),
      args: ["-y".into(), kind.npx_package().into()]
        .into_iter()
        .chain(forwarded_args)
        .collect(),
    }
  } else {
    CommandSpec {
      program: kind.name().into(),
      args: forwarded_args,
    }
  }
}

#[derive(Debug)]
struct ShellExec {
  path: PathBuf,
  arg0: Option<String>,
}

fn detect_shell(explicit: Option<&Path>) -> Result<ShellExec> {
  if let Some(path) = explicit {
    return Ok(ShellExec {
      path: path.to_path_buf(),
      arg0: shell_arg0(path),
    });
  }

  if let Some(shell) = std::env::var_os("SHELL") {
    let path = PathBuf::from(shell);
    return Ok(ShellExec {
      arg0: shell_arg0(&path),
      path,
    });
  }

  if let Some(comspec) = std::env::var_os("COMSPEC") {
    let path = PathBuf::from(comspec);
    return Ok(ShellExec {
      arg0: shell_arg0(&path),
      path,
    });
  }

  #[cfg(windows)]
  let path = PathBuf::from("cmd.exe");
  #[cfg(not(windows))]
  let path = PathBuf::from("/bin/sh");
  Ok(ShellExec {
    arg0: shell_arg0(&path),
    path,
  })
}

fn shell_arg0(path: &Path) -> Option<String> {
  path.file_name().and_then(|name| name.to_str()).map(|s| s.to_string())
}

#[cfg(unix)]
fn apply_shell_arg0(cmd: &mut Command, arg0: Option<&str>) {
  if let Some(arg0) = arg0 {
    cmd.arg0(arg0);
  }
}

#[cfg(not(unix))]
fn apply_shell_arg0(_cmd: &mut Command, _arg0: Option<&str>) {}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::{Cli, Cmd};
  use clap::Parser;

  fn compiled(source: &str) -> tokn_config::v2::CompiledConfig {
    tokn_config::v2::parse(source, Path::new("/tmp/proxy-helper.toml")).unwrap()
  }

  #[test]
  fn sole_compiled_proxy_is_selected_and_wildcard_bind_becomes_loopback() {
    let compiled = compiled(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }

[listeners.proxy]
kind = "forward_proxy"
bind = "0.0.0.0:4142"
client_auth = "local_keys"
allow_insecure_public = true
default_http_action = { kind = "reject" }
default_connect = "intercept"
ca_dir = "ca"
"#,
    );
    let selected = select_proxy_listener(compiled.gateway(), None, &["internal.example".into()]).unwrap();

    assert_eq!(selected.id, "proxy");
    assert_eq!(selected.client_addr, "127.0.0.1:4142".parse().unwrap());
    assert_eq!(selected.ca_dir, Some(PathBuf::from("/tmp/ca")));
    assert_eq!(selected.no_proxy, ["internal.example"]);
  }

  #[test]
  fn multiple_compiled_proxies_require_an_explicit_listener() {
    let compiled = compiled(
      r#"
schema_version = 2

[listeners.alpha]
kind = "forward_proxy"
bind = "127.0.0.1:4142"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"

[listeners.beta]
kind = "forward_proxy"
bind = "[::]:4242"
client_auth = "local_keys"
allow_insecure_public = true
default_http_action = { kind = "reject" }
default_connect = "tunnel"
"#,
    );

    let error = select_proxy_listener(compiled.gateway(), None, &[]).unwrap_err();
    assert!(error.to_string().contains("alpha, beta"));
    let selected = select_proxy_listener(compiled.gateway(), Some("beta"), &[]).unwrap();
    assert_eq!(selected.client_addr, "[::1]:4242".parse().unwrap());
    assert!(selected.ca_dir.is_none());
    let env = resolved_proxy_env(&selected).unwrap();
    assert_eq!(env.get("HTTPS_PROXY"), Some("http://[::1]:4242"));
    assert_eq!(env.get("SSL_CERT_FILE"), None);
  }

  #[test]
  fn explicit_listener_must_exist_and_be_a_forward_proxy() {
    let compiled = compiled(
      r#"
schema_version = 2

[listeners.api]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
default_http_action = { kind = "reject" }
"#,
    );

    assert!(select_proxy_listener(compiled.gateway(), Some("missing"), &[])
      .unwrap_err()
      .to_string()
      .contains("no listener named 'missing'"));
    assert!(select_proxy_listener(compiled.gateway(), Some("api"), &[])
      .unwrap_err()
      .to_string()
      .contains("is not a forward_proxy"));
  }

  #[test]
  fn client_no_proxy_includes_configured_entries() {
    let configured = vec!["internal.local".into(), "10.0.0.0/8".into()];

    assert_eq!(
      client_no_proxy_value(&configured),
      "localhost,127.0.0.1,::1,internal.local,10.0.0.0/8"
    );
  }

  #[test]
  fn client_no_proxy_deduplicates_defaults_and_skips_empty_entries() {
    let configured = vec![
      "localhost".into(),
      " ".into(),
      "::1".into(),
      "internal.local".into(),
      "internal.local".into(),
    ];

    assert_eq!(
      client_no_proxy_value(&configured),
      "localhost,127.0.0.1,::1,internal.local"
    );
  }

  #[test]
  fn local_agent_command_uses_agent_binary_and_forwards_args() {
    assert_eq!(
      agent_command_spec(AgentKind::Codex, false, vec!["--model".into(), "gpt-5".into()]),
      CommandSpec {
        program: "codex".into(),
        args: vec!["--model".into(), "gpt-5".into()],
      }
    );
  }

  #[test]
  fn npx_agent_command_uses_agent_package_and_forwards_args() {
    assert_eq!(
      agent_command_spec(AgentKind::Opencode, true, vec!["run".into()]),
      CommandSpec {
        program: "npx".into(),
        args: vec!["-y".into(), "opencode-ai".into(), "run".into()],
      }
    );
    assert_eq!(
      agent_command_spec(AgentKind::Pi, true, Vec::new()),
      CommandSpec {
        program: "npx".into(),
        args: vec!["-y".into(), "@earendil-works/pi-coding-agent".into()],
      }
    );
  }

  #[test]
  fn command_spec_rejects_empty_argv() {
    assert!(CommandSpec::from_argv(Vec::new()).is_err());
  }

  #[test]
  fn shell_exports_quote_untrusted_values() {
    let value = "path with spaces/'quoted'/$HOME\\bundle";

    assert_eq!(quote_sh(value), r#"'path with spaces/'"'"'quoted'"'"'/$HOME\bundle'"#);
    assert_eq!(quote_fish(value), r#"'path with spaces/\'quoted\'/$HOME\\bundle'"#);
    assert_eq!(quote_pwsh(value), r#"'path with spaces/''quoted''/$HOME\bundle'"#);
  }

  #[test]
  fn proxy_env_runner_returns_success_for_successful_child() {
    if std::env::var_os("TOKN_PROXY_TEST_CHILD").is_some() {
      return;
    }

    let mut env = ProxyEnv {
      vars: vec![
        ("HTTPS_PROXY".into(), "http://127.0.0.1:4142".into()),
        ("SSL_CERT_FILE".into(), "ca-bundle.crt".into()),
      ],
    };
    env.vars.push(("TOKN_PROXY_TEST_CHILD".into(), "1".into()));
    let spec = CommandSpec {
      program: std::env::current_exe().unwrap().display().to_string(),
      args: vec![
        "cli::proxy::tests::proxy_env_runner_returns_success_for_successful_child".into(),
        "--exact".into(),
      ],
    };

    run_with_proxy_env("test", &env, spec).unwrap();
  }

  #[test]
  fn proxy_env_runner_reports_failed_child_status() {
    if std::env::var_os("TOKN_PROXY_TEST_CHILD").is_some() {
      std::process::exit(7);
    }

    let env = ProxyEnv {
      vars: vec![
        ("HTTPS_PROXY".into(), "http://127.0.0.1:4142".into()),
        ("SSL_CERT_FILE".into(), "ca-bundle.crt".into()),
      ],
    };
    let spec = CommandSpec {
      program: std::env::current_exe().unwrap().display().to_string(),
      args: vec![
        "cli::proxy::tests::proxy_env_runner_reports_failed_child_status".into(),
        "--exact".into(),
      ],
    };

    let mut spec_env = env;
    spec_env.vars.push(("TOKN_PROXY_TEST_CHILD".into(), "1".into()));
    let err = run_with_proxy_env("test", &spec_env, spec).unwrap_err();
    assert!(err.to_string().contains("test exited with status"));
  }

  #[test]
  fn proxy_requires_a_subcommand() {
    assert!(Cli::try_parse_from(["tokn-router", "proxy"]).is_err());
  }

  #[test]
  fn proxy_start_is_retired_in_favor_of_compiled_listeners() {
    assert!(Cli::try_parse_from(["tokn-router", "proxy", "start"]).is_err());
  }

  #[test]
  fn proxy_run_parses_agent_preset_and_forwarded_args() {
    let cli = Cli::try_parse_from([
      "tokn-router",
      "proxy",
      "--listener",
      "proxy-b",
      "run",
      "--npx",
      "pi",
      "--mode",
      "json",
      "--print",
      "hello",
    ])
    .unwrap();

    let Cmd::Proxy(proxy) = cli.cmd else {
      panic!("expected proxy command");
    };
    assert_eq!(proxy.listener.as_deref(), Some("proxy-b"));
    let ProxyCmd::Run(args) = proxy.cmd else {
      panic!("expected proxy run command");
    };
    assert!(args.npx);
    assert_eq!(args.agent, AgentKind::Pi);
    assert_eq!(args.args, ["--mode", "json", "--print", "hello"]);
  }

  #[test]
  fn proxy_exec_parses_command_line() {
    let cli = Cli::try_parse_from(["tokn-router", "proxy", "exec", "printenv", "HTTPS_PROXY"]).unwrap();

    let Cmd::Proxy(proxy) = cli.cmd else {
      panic!("expected proxy command");
    };
    let ProxyCmd::Exec(args) = proxy.cmd else {
      panic!("expected proxy exec command");
    };
    assert_eq!(args.command, ["printenv", "HTTPS_PROXY"]);
    assert_eq!(
      CommandSpec::from_argv(args.command).unwrap(),
      CommandSpec {
        program: "printenv".into(),
        args: vec!["HTTPS_PROXY".into()],
      }
    );
  }
}

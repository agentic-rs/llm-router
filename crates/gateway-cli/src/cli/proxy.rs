use crate::config::Config;
use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const DEFAULT_CLIENT_NO_PROXY: &[&str] = &["localhost", "127.0.0.1", "::1"];

#[derive(Args, Debug)]
pub struct ProxyArgs {
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

pub async fn run(cfg_path: Option<PathBuf>, args: ProxyArgs) -> Result<()> {
  match args.cmd {
    ProxyCmd::Env(args) => env(cfg_path, args).await,
    ProxyCmd::Shell(args) => shell(cfg_path, args).await,
    ProxyCmd::Run(args) => {
      agent(
        cfg_path,
        args.agent,
        AgentProxyArgs {
          npx: args.npx,
          args: args.args,
        },
      )
      .await
    }
    ProxyCmd::Exec(args) => exec(cfg_path, args).await,
    ProxyCmd::Codex(args) => agent(cfg_path, AgentKind::Codex, args).await,
    ProxyCmd::Opencode(args) => agent(cfg_path, AgentKind::Opencode, args).await,
    ProxyCmd::Pi(args) => agent(cfg_path, AgentKind::Pi, args).await,
    ProxyCmd::Ca(args) => ca(cfg_path, args).await,
  }
}

async fn env(cfg_path: Option<PathBuf>, args: EnvArgs) -> Result<()> {
  let env = resolved_proxy_env(cfg_path.as_deref())?;
  match args.shell {
    Shell::Sh | Shell::Bash | Shell::Zsh => print_sh(&env),
    Shell::Fish => print_fish(&env),
    Shell::Pwsh => print_pwsh(&env),
  }
  Ok(())
}

async fn shell(cfg_path: Option<PathBuf>, args: ShellArgs) -> Result<()> {
  let env = resolved_proxy_env(cfg_path.as_deref())?;
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

async fn agent(cfg_path: Option<PathBuf>, kind: AgentKind, args: AgentProxyArgs) -> Result<()> {
  let env = resolved_proxy_env(cfg_path.as_deref())?;
  let spec = agent_command_spec(kind, args.npx, args.args);
  run_with_proxy_env(kind.name(), &env, spec)
}

async fn exec(cfg_path: Option<PathBuf>, args: ExecArgs) -> Result<()> {
  let env = resolved_proxy_env(cfg_path.as_deref())?;
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

async fn ca(cfg_path: Option<PathBuf>, args: CaArgs) -> Result<()> {
  let (cfg, _) = Config::load(cfg_path.as_deref())?;
  let ca_dir = cfg.proxy_mode.resolved_ca_dir()?;
  match args.cmd {
    CaCmd::Path => {
      let ca = tokn_router::runtime::load_or_generate_ca(&ca_dir, false)?;
      println!("{}", ca.cert_path().display());
    }
    CaCmd::Show => {
      let ca = tokn_router::runtime::load_or_generate_ca(&ca_dir, false)?;
      println!("cert: {}", ca.cert_path().display());
      println!("bundle: {}", ca.ensure_bundle()?.display());
      println!("key: {}", ca.key_path().display());
      println!("sha256: {}", ca.fingerprint_sha256());
    }
    CaCmd::Regenerate => {
      let ca = tokn_router::runtime::load_or_generate_ca(&ca_dir, true)?;
      println!("regenerated CA at {}", ca.cert_path().display());
      println!("sha256: {}", ca.fingerprint_sha256());
    }
  }
  Ok(())
}

fn print_sh(env: &ProxyEnv) {
  for (key, value) in &env.vars {
    println!("export {key}={value}");
  }
}

fn print_fish(env: &ProxyEnv) {
  for (key, value) in &env.vars {
    println!("set -gx {key} {value}");
  }
}

fn print_pwsh(env: &ProxyEnv) {
  for (key, value) in &env.vars {
    println!("$Env:{key} = '{value}'");
  }
}

fn resolved_proxy_env(cfg_path: Option<&Path>) -> Result<ProxyEnv> {
  let (cfg, _) = Config::load(cfg_path)?;
  let ca_dir = cfg.proxy_mode.resolved_ca_dir()?;
  let ca = tokn_router::runtime::load_or_generate_ca(&ca_dir, false)?;
  let proxy_url = format!("http://{}:{}", cfg.proxy_mode.host, cfg.proxy_mode.port);
  let cert = ca.cert_path().display().to_string();
  let bundle = ca.ensure_bundle()?.display().to_string();
  let no_proxy = client_no_proxy_value(&cfg.proxy.no_proxy);
  Ok(ProxyEnv {
    vars: vec![
      ("HTTPS_PROXY".into(), proxy_url.clone()),
      ("HTTP_PROXY".into(), proxy_url),
      ("NO_PROXY".into(), no_proxy),
      ("SSL_CERT_FILE".into(), bundle.clone()),
      ("NODE_EXTRA_CA_CERTS".into(), cert),
      ("CODEX_CA_CERTIFICATE".into(), bundle.clone()),
      ("REQUESTS_CA_BUNDLE".into(), bundle.clone()),
      ("CURL_CA_BUNDLE".into(), bundle.clone()),
      ("GIT_SSL_CAINFO".into(), bundle),
    ],
  })
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

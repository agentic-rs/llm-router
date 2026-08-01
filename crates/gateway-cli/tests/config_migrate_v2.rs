use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EMBEDDED_SECRET: &str = "migration-secret-must-not-escape";

struct Fixture {
  _directory: tempfile::TempDir,
  home: PathBuf,
  router_home: PathBuf,
  config_path: PathBuf,
  config_contents: Vec<u8>,
}

impl Fixture {
  fn new() -> Self {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    let router_home = home.join(".tokn/router");
    let config_path = router_home.join("config.toml");
    fs::create_dir_all(&router_home).unwrap();
    let config_contents = format!(
      r#"
[logging]
target = "file"

[[accounts]]
id = "embedded"
provider = "openai"
enabled = true
api_key = {EMBEDDED_SECRET:?}
"#,
    )
    .into_bytes();
    fs::write(&config_path, &config_contents).unwrap();
    Self {
      _directory: directory,
      home,
      router_home,
      config_path,
      config_contents,
    }
  }

  fn run(&self, activation: &str) -> Output {
    self.run_with_args(activation, &[])
  }

  fn command(&self) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tokn-gateway"));
    command
      .arg("--config")
      .arg(&self.config_path)
      .env("HOME", &self.home)
      .env("TOKN_ROUTER_HOME", &self.router_home)
      .env("XDG_CONFIG_HOME", self.home.join(".config"))
      .env("XDG_DATA_HOME", self.home.join(".local/share"))
      .env("XDG_CACHE_HOME", self.home.join(".cache"));
    command
  }

  fn run_config(&self, args: &[&str]) -> Output {
    self
      .command()
      .arg("config")
      .args(args)
      .output()
      .expect("run a config command")
  }

  fn run_with_args(&self, activation: &str, args: &[&str]) -> Output {
    self
      .command()
      .args(["config", "migrate-v2", "--activate", activation])
      .args(args)
      .output()
      .expect("run the gateway CLI")
  }

  fn assert_config_unchanged(&self) {
    assert_eq!(fs::read(&self.config_path).unwrap(), self.config_contents);
  }

  fn assert_no_logging_state(&self) {
    assert!(!self.router_home.join("logs").exists());
  }
}

fn stdout(output: &Output) -> &str {
  std::str::from_utf8(&output.stdout).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> &str {
  std::str::from_utf8(&output.stderr).expect("stderr should be UTF-8")
}

fn assert_secret_absent(output: &Output) {
  assert!(!stdout(output).contains(EMBEDDED_SECRET));
  assert!(!stderr(output).contains(EMBEDDED_SECRET));
}

#[cfg(unix)]
fn assert_private_file(path: &Path) {
  use std::os::unix::fs::PermissionsExt;

  let metadata = fs::symlink_metadata(path).unwrap();
  assert!(metadata.is_file(), "{} is not a regular file", path.display());
  assert_eq!(
    metadata.permissions().mode() & 0o777,
    0o600,
    "{} is not private",
    path.display()
  );
}

#[cfg(not(unix))]
fn assert_private_file(_path: &Path) {}

#[test]
fn dry_run_bypasses_legacy_home_and_logging_side_effects() {
  let fixture = Fixture::new();

  let output = fixture.run("api");

  assert!(output.status.success(), "stderr: {}", stderr(&output));
  tokn_config::v2::parse(stdout(&output), &fixture.config_path).expect("stdout should be an exact v2 config");
  assert!(!stdout(&output).contains("warning:"));
  assert_secret_absent(&output);
  assert!(!stderr(&output).is_empty());
  assert!(stderr(&output).lines().all(|line| line.starts_with("warning: ")));
  assert!(!stderr(&output).contains("migrated legacy tokn-router config"));
  fixture.assert_config_unchanged();
  assert!(!fixture.router_home.join("auth.yaml").exists());
  fixture.assert_no_logging_state();
}

#[test]
fn ordinary_read_only_config_bypasses_legacy_home_and_logging_side_effects() {
  let fixture = Fixture::new();

  let output = fixture.run_config(&["get", "logging.target"]);

  assert!(output.status.success(), "stderr: {}", stderr(&output));
  assert_eq!(stdout(&output), "file\n");
  assert!(!stderr(&output).contains("migrated legacy tokn-router config"));
  assert_secret_absent(&output);
  fixture.assert_config_unchanged();
  assert!(!fixture.router_home.join("auth.yaml").exists());
  fixture.assert_no_logging_state();
}

#[test]
fn ordinary_mutating_config_bypasses_legacy_home_and_logging_side_effects() {
  let fixture = Fixture::new();

  let output = fixture.run_config(&["set", "logging.target", "stderr"]);

  assert!(output.status.success(), "stderr: {}", stderr(&output));
  assert_eq!(stdout(&output), "set logging.target\n");
  assert!(!stderr(&output).contains("migrated legacy tokn-router config"));
  assert_secret_absent(&output);
  let config = fs::read_to_string(&fixture.config_path).unwrap();
  assert!(config.contains("target = \"stderr\""));
  assert!(config.contains(EMBEDDED_SECRET));
  assert!(!fixture.router_home.join("auth.yaml").exists());
  fixture.assert_no_logging_state();
}

#[test]
fn apply_activates_v2_with_durable_private_credentials_and_exact_backup() {
  let fixture = Fixture::new();
  let auth_path = fixture.router_home.join("auth.yaml");
  let backup_path = fixture.router_home.join("config.toml.legacy-v1.bak");

  let output = fixture.run_with_args("api", &["--apply", "--yes"]);

  assert!(output.status.success(), "stderr: {}", stderr(&output));
  assert!(stdout(&output).is_empty());
  assert_secret_absent(&output);
  assert!(stderr(&output).contains("auth: install 1 embedded account(s)"));
  assert!(stderr(&output).contains("activated version 2 config"));
  assert!(stderr(&output).contains("embedded credentials were installed in modern auth"));
  assert!(!stderr(&output).contains("migrated legacy tokn-router config"));

  let activated = fs::read_to_string(&fixture.config_path).unwrap();
  assert!(!activated.contains(EMBEDDED_SECRET));
  let compiled = tokn_config::v2::parse(&activated, &fixture.config_path).expect("active config should be valid v2");
  let store = tokn_auth::AuthStore::load(Some(&auth_path), None).expect("modern auth should be durable");
  assert!(store.has_persisted_sources());
  let account = store.get("embedded").expect("embedded account should be imported");
  assert_eq!(account.provider, "openai");
  assert_eq!(account.api_key.as_ref().unwrap().expose(), EMBEDDED_SECRET);
  tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), &store.accounts)
    .expect("active config should link with durable auth");

  let auth_contents = fs::read_to_string(&auth_path).unwrap();
  assert!(auth_contents.contains(EMBEDDED_SECRET));
  assert_eq!(fs::read(&backup_path).unwrap(), fixture.config_contents);
  assert!(fs::read_to_string(&backup_path).unwrap().contains(EMBEDDED_SECRET));
  assert_private_file(&auth_path);
  assert_private_file(&backup_path);
  fixture.assert_no_logging_state();
}

#[test]
fn empty_modern_auth_is_authoritative_over_embedded_accounts() {
  let fixture = Fixture::new();
  let auth_path = fixture.router_home.join("auth.yaml");
  let auth_contents = b"version: 1\naccounts: []\n";
  fs::write(&auth_path, auth_contents).unwrap();

  let output = fixture.run("api");

  assert!(!output.status.success());
  assert!(stdout(&output).is_empty());
  assert!(stderr(&output).contains("cannot migrate managed listeners without supplied accounts"));
  assert!(!stderr(&output).contains("migrated legacy tokn-router config"));
  assert_secret_absent(&output);
  fixture.assert_config_unchanged();
  assert_eq!(fs::read(auth_path).unwrap(), auth_contents);
  fixture.assert_no_logging_state();
}

#[test]
fn proxy_and_combined_dry_runs_emit_linkable_v2_without_side_effects() {
  for activation in ["proxy", "both"] {
    let fixture = Fixture::new();

    let output = fixture.run(activation);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let compiled = tokn_config::v2::parse(stdout(&output), &fixture.config_path)
      .unwrap_or_else(|error| panic!("{activation} output should compile: {error}"));
    let accounts = vec![toml::from_str::<tokn_core::account::AccountConfig>(
      r#"
id = "embedded"
provider = "openai"
enabled = true
api_key = "test-key"
"#,
    )
    .unwrap()];
    tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), &accounts)
      .unwrap_or_else(|error| panic!("{activation} output should link: {error}"));
    assert!(matches!(
      compiled.gateway().listeners()["proxy"],
      tokn_policy::ListenerPlan::ForwardProxy(_)
    ));
    assert_eq!(compiled.gateway().listeners().contains_key("api"), activation == "both");
    assert!(stderr(&output).contains("request-time proxy mode overrides"));
    assert_secret_absent(&output);
    fixture.assert_config_unchanged();
    assert!(!fixture.router_home.join("auth.yaml").exists());
    fixture.assert_no_logging_state();
  }
}

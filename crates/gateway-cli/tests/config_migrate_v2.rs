use std::fs;
use std::path::PathBuf;
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
    Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
      .args(["config", "migrate-v2", "--activate", activation])
      .env("HOME", &self.home)
      .env("XDG_CONFIG_HOME", self.home.join(".config"))
      .env("XDG_DATA_HOME", self.home.join(".local/share"))
      .env("XDG_CACHE_HOME", self.home.join(".cache"))
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
fn empty_modern_auth_is_authoritative_over_embedded_accounts() {
  let fixture = Fixture::new();
  let auth_path = fixture.router_home.join("auth.yaml");
  let auth_contents = b"version: 1\naccounts: []\n";
  fs::write(&auth_path, auth_contents).unwrap();

  let output = fixture.run("api");

  assert!(!output.status.success());
  assert!(stdout(&output).is_empty());
  assert!(stderr(&output).contains("cannot migrate an API gateway without supplied accounts"));
  assert!(!stderr(&output).contains("migrated legacy tokn-router config"));
  assert_secret_absent(&output);
  fixture.assert_config_unchanged();
  assert_eq!(fs::read(auth_path).unwrap(), auth_contents);
  fixture.assert_no_logging_state();
}

#[test]
fn unsupported_proxy_error_does_not_disclose_embedded_credentials() {
  let fixture = Fixture::new();

  let output = fixture.run("proxy");

  assert!(!output.status.success());
  assert!(stdout(&output).is_empty());
  assert!(stderr(&output).contains("does not yet support the Proxy listener selection"));
  assert_secret_absent(&output);
  fixture.assert_config_unchanged();
  assert!(!fixture.router_home.join("auth.yaml").exists());
  fixture.assert_no_logging_state();
}

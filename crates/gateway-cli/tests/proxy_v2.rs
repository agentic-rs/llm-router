use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
  _directory: tempfile::TempDir,
  home: PathBuf,
  config_path: PathBuf,
}

impl Fixture {
  fn new(config: &str) -> Self {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    let config_path = directory.path().join("gateway.toml");
    fs::create_dir(&home).unwrap();
    fs::write(&config_path, config).unwrap();
    Self {
      _directory: directory,
      home,
      config_path,
    }
  }

  fn run(&self, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
      .arg("--config")
      .arg(&self.config_path)
      .arg("proxy")
      .args(args)
      .env("HOME", &self.home)
      .env("TOKN_ROUTER_HOME", self.home.join(".tokn/router"))
      .env("XDG_CONFIG_HOME", self.home.join(".config"))
      .env("XDG_DATA_HOME", self.home.join(".local/share"))
      .env("XDG_CACHE_HOME", self.home.join(".cache"))
      .output()
      .expect("run the gateway CLI")
  }

  fn assert_no_legacy_state(&self) {
    assert!(!self.home.join(".tokn/router").exists());
  }
}

fn stdout(output: &Output) -> &str {
  std::str::from_utf8(&output.stdout).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> &str {
  std::str::from_utf8(&output.stderr).expect("stderr should be UTF-8")
}

fn json_env(output: &Output) -> serde_json::Map<String, serde_json::Value> {
  serde_json::from_slice::<serde_json::Value>(&output.stdout)
    .expect("stdout should be JSON")
    .as_object()
    .expect("proxy env JSON should be an object")
    .clone()
}

fn assert_export(output: &Output, key: &str, value: &str) {
  assert!(
    stdout(output)
      .lines()
      .any(|line| line == format!("export {key}='{value}'")),
    "missing {key} export in stdout:\n{}",
    stdout(output)
  );
}

fn assert_no_export(output: &Output, key: &str) {
  assert!(
    !stdout(output)
      .lines()
      .any(|line| line.starts_with(&format!("export {key}="))),
    "unexpected {key} export in stdout:\n{}",
    stdout(output)
  );
}

#[test]
fn tunnel_only_proxy_env_uses_v2_listener_without_legacy_startup() {
  let fixture = Fixture::new(
    r#"
schema_version = 2

[service.outbound]
proxy_url = "http://127.0.0.1:8181"
no_proxy = ["internal.example"]

[listeners.proxy]
kind = "forward_proxy"
bind = "0.0.0.0:4142"
client_auth = "local_keys"
allow_insecure_public = true
default_http_action = { kind = "reject" }
default_connect = "tunnel"
"#,
  );

  let output = fixture.run(&["env"]);

  assert!(output.status.success(), "stderr: {}", stderr(&output));
  assert_export(&output, "HTTP_PROXY", "http://127.0.0.1:4142");
  assert_export(&output, "HTTPS_PROXY", "http://127.0.0.1:4142");
  assert_export(&output, "NO_PROXY", "localhost,127.0.0.1,::1,internal.example");
  assert_no_export(&output, "SSL_CERT_FILE");
  assert_no_export(&output, "NODE_EXTRA_CA_CERTS");
  fixture.assert_no_legacy_state();
}

#[test]
fn multiple_v2_proxy_listeners_require_and_honor_explicit_selection() {
  let fixture = Fixture::new(
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
bind = "127.0.0.1:4242"
client_auth = "none"
default_http_action = { kind = "reject" }
default_connect = "tunnel"
"#,
  );

  let ambiguous = fixture.run(&["env"]);
  assert!(!ambiguous.status.success());
  assert!(
    stderr(&ambiguous).contains("multiple forward_proxy listeners (alpha, beta); select one with --listener"),
    "stderr: {}",
    stderr(&ambiguous)
  );
  assert!(stdout(&ambiguous).is_empty());

  let selected = fixture.run(&["--listener", "beta", "env", "--format", "json"]);
  assert!(selected.status.success(), "stderr: {}", stderr(&selected));
  let env = json_env(&selected);
  assert_eq!(env["HTTP_PROXY"], "http://127.0.0.1:4242");
  assert_eq!(env["HTTPS_PROXY"], "http://127.0.0.1:4242");
  assert!(!env.contains_key("SSL_CERT_FILE"));
  fixture.assert_no_legacy_state();
}

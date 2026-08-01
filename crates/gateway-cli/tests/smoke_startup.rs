use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn smoke(home: &Path, args: &[&str]) -> Output {
  Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
    .arg("smoke")
    .args(args)
    .env("HOME", home)
    .env("XDG_CONFIG_HOME", home.join(".config"))
    .env("XDG_DATA_HOME", home.join(".local/share"))
    .env("XDG_CACHE_HOME", home.join(".cache"))
    .output()
    .expect("run smoke command")
}

fn stderr(output: &Output) -> String {
  String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn static_smoke_inspection_needs_no_config_and_creates_no_legacy_home() {
  for args in [
    &["provider", "openai", "--format", "json"][..],
    &["model", "--all", "--format", "json"][..],
  ] {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();

    let output = smoke(&home, args);

    assert!(output.status.success(), "{}", stderr(&output));
    serde_json::from_slice::<Value>(&output.stdout).expect("smoke stdout is one JSON value");
    assert!(!home.join(".tokn/router").exists());
  }
}

#[test]
fn live_provider_missing_v2_config_creates_no_legacy_home() {
  let temp = tempfile::tempdir().unwrap();
  let home = temp.path().join("home");
  fs::create_dir(&home).unwrap();

  let output = smoke(&home, &["provider", "openai", "--live"]);

  assert!(!output.status.success(), "live provider unexpectedly succeeded");
  assert!(!home.join(".tokn/router").exists(), "{}", stderr(&output));
}

#[test]
fn live_provider_invalid_v2_config_does_not_extract_legacy_accounts() {
  let temp = tempfile::tempdir().unwrap();
  let home = temp.path().join("home");
  let router_home = home.join(".tokn/router");
  fs::create_dir_all(&router_home).unwrap();
  fs::write(
    router_home.join("config.toml"),
    r#"
schema_version = 2

[[accounts]]
id = "legacy"
provider = "openai"
enabled = true
api_key = "secret"
"#,
  )
  .unwrap();

  let output = smoke(&home, &["provider", "openai", "--live"]);

  assert!(!output.status.success(), "invalid v2 config unexpectedly succeeded");
  assert!(!router_home.join("auth.yaml").exists(), "{}", stderr(&output));
}

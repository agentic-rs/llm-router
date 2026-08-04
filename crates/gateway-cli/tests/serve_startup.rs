use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run_serve(home: &Path) -> Output {
  Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
    .arg("serve")
    .env("HOME", home)
    .env("TOKN_ROUTER_HOME", home.join(".tokn/router"))
    .env("XDG_CONFIG_HOME", home.join(".config"))
    .env("XDG_DATA_HOME", home.join(".local/share"))
    .env("XDG_CACHE_HOME", home.join(".cache"))
    .output()
    .expect("run the gateway CLI")
}

fn stderr(output: &Output) -> String {
  String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn missing_default_v2_config_does_not_create_legacy_home() {
  let temp = tempfile::tempdir().unwrap();
  let home = temp.path().join("home");
  fs::create_dir(&home).unwrap();

  let output = run_serve(&home);

  assert!(!output.status.success(), "serve unexpectedly succeeded");
  assert!(
    !home.join(".tokn/router").exists(),
    "v2 serve created legacy state before reporting its error: {}",
    stderr(&output)
  );
}

#[test]
fn invalid_default_v2_config_does_not_extract_legacy_accounts() {
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

  let output = run_serve(&home);

  assert!(
    !output.status.success(),
    "serve unexpectedly accepted an invalid v2 config"
  );
  assert!(
    !router_home.join("auth.yaml").exists(),
    "v2 serve extracted legacy credentials before reporting its error: {}",
    stderr(&output)
  );
}

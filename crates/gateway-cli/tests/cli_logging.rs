use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const MINIMAL_CONFIG: &str = r#"
schema_version = 2
[listeners.local]
kind = "llm_api"
bind = "127.0.0.1:4141"
client_auth = "none"
"#;

fn run_cli(path: &Path, args: &[&str]) -> Output {
  Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
    .arg("--config")
    .arg(path)
    .args(args)
    .env_remove("RUST_LOG")
    .output()
    .unwrap()
}

#[test]
fn native_v2_cli_honors_file_and_stderr_logging_targets() {
  for target in ["file", "both", "stderr"] {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let logs = directory.path().join("logs");
    let mut config = tokn_config::v2::decode(MINIMAL_CONFIG, &path).unwrap();
    config.service.logging.target = match target {
      "file" => tokn_config::LogTarget::File,
      "both" => tokn_config::LogTarget::Both,
      _ => tokn_config::LogTarget::Stderr,
    };
    config.service.logging.dir = Some(logs.clone());
    config.service.logging.format = tokn_config::LogFormat::Json;
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();

    let output = run_cli(&path, &["config", "get", "schema_version"]);

    assert!(
      output.status.success(),
      "{target}: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "2");
    if target == "stderr" {
      assert!(!logs.exists());
    } else {
      let files = fs::read_dir(&logs).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
      assert_eq!(files.len(), 1, "{target}");
      assert!(files[0].file_name().to_string_lossy().starts_with("tokn-router.log."));
    }
  }
}

#[test]
fn migration_preview_never_initializes_file_logging() {
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("config.toml");
  let logs = directory.path().join("logs");
  let mut config = tokn_config::v2::decode(MINIMAL_CONFIG, &path).unwrap();
  config.service.logging.dir = Some(logs.clone());
  fs::write(&path, toml::to_string(&config).unwrap()).unwrap();

  let output = run_cli(&path, &["config", "migrate-v2"]);

  assert!(!output.status.success());
  assert!(String::from_utf8_lossy(&output.stderr).contains("already uses schema_version = 2"));
  assert!(output.stdout.is_empty());
  assert!(!logs.exists());
}

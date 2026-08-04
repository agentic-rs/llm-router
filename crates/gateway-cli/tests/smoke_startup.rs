use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tokn_mock_server::{MockEndpoint, MockLlmConfig, MockLlmServer, MockResponse, MockRoute};

fn smoke(home: &Path, args: &[&str]) -> Output {
  Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
    .arg("smoke")
    .args(args)
    .env("HOME", home)
    .env("TOKN_ROUTER_HOME", home.join(".tokn/router"))
    .env("XDG_CONFIG_HOME", home.join(".config"))
    .env("XDG_DATA_HOME", home.join(".local/share"))
    .env("XDG_CACHE_HOME", home.join(".cache"))
    .output()
    .expect("run smoke command")
}

fn stderr(output: &Output) -> String {
  String::from_utf8_lossy(&output.stderr).into_owned()
}

async fn smoke_async(home: &Path, args: &[&str]) -> Output {
  let home = home.to_path_buf();
  let args = args.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>();
  tokio::task::spawn_blocking(move || {
    Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
      .arg("smoke")
      .args(args)
      .env("HOME", &home)
      .env("TOKN_ROUTER_HOME", home.join(".tokn/router"))
      .env("XDG_CONFIG_HOME", home.join(".config"))
      .env("XDG_DATA_HOME", home.join(".local/share"))
      .env("XDG_CACHE_HOME", home.join(".cache"))
      .output()
      .expect("run asynchronous smoke command")
  })
  .await
  .expect("join smoke command")
}

fn write_managed_fixture(home: &Path, base_url: &str) {
  let router_home = home.join(".tokn/router");
  fs::create_dir_all(&router_home).unwrap();
  fs::write(
    router_home.join("config.toml"),
    format!(
      r#"schema_version = 2

[profiles.work]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "default"
upstream = {{ kind = "fixed", upstream = "local" }}
model = {{ kind = "qualified", namespace = "provider" }}
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["llama-cpp"]

[upstreams.local]
provider = "llama-cpp"
base_url = "{base_url}"
accounts = ["local"]
"#
    ),
  )
  .unwrap();
  fs::write(
    router_home.join("auth.yaml"),
    "version: 1\naccounts:\n  - id: local\n    provider: llama-cpp\n",
  )
  .unwrap();
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
fn managed_send_missing_v2_config_creates_no_legacy_home() {
  let temp = tempfile::tempdir().unwrap();
  let home = temp.path().join("home");
  fs::create_dir(&home).unwrap();

  let output = smoke(
    &home,
    &["send", "--profile", "default", "--model", "openai/gpt-5", "hello"],
  );

  assert!(!output.status.success(), "managed send unexpectedly succeeded");
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

#[test]
fn managed_send_invalid_v2_config_does_not_extract_legacy_accounts() {
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

  let output = smoke(
    &home,
    &["send", "--profile", "default", "--model", "openai/gpt-5", "hello"],
  );

  assert!(!output.status.success(), "invalid v2 config unexpectedly succeeded");
  assert!(!router_home.join("auth.yaml").exists(), "{}", stderr(&output));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_send_buffered_json_is_one_selection_document() {
  let mock = MockLlmServer::start(MockLlmConfig::default()).await;
  let temp = tempfile::tempdir().unwrap();
  let home = temp.path().join("home");
  write_managed_fixture(&home, mock.base_url());

  let output = smoke_async(
    &home,
    &[
      "send",
      "--profile",
      "work",
      "--model",
      "llama-cpp/mock-model",
      "--format",
      "json",
      "hello",
    ],
  )
  .await;

  assert!(output.status.success(), "{}", stderr(&output));
  let report: Value = serde_json::from_slice(&output.stdout).expect("smoke stdout is one JSON value");
  assert_eq!(report["site"]["profile"], "work");
  assert_eq!(report["site"]["route"], "managed");
  assert_eq!(report["selection"]["account"], "local");
  assert_eq!(report["selection"]["provider"], "llama-cpp");
  assert_eq!(report["selection"]["upstream"], "local");
  assert_eq!(report["selection"]["requested_model"], "llama-cpp/mock-model");
  assert_eq!(report["response"]["status"], 200);
  assert_eq!(report["response"]["body"]["id"], "chatcmpl-mock");
  assert_eq!(mock.last_request().unwrap().path, "/chat/completions");

  mock.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_send_stream_keeps_stdout_as_raw_sse() {
  let mock = MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::chat_completions_stream())).await;
  let temp = tempfile::tempdir().unwrap();
  let home = temp.path().join("home");
  write_managed_fixture(&home, mock.base_url());

  let output = smoke_async(
    &home,
    &[
      "send",
      "--profile",
      "work",
      "--model",
      "llama-cpp/mock-model",
      "--stream",
      "hello",
    ],
  )
  .await;

  assert!(output.status.success(), "{}", stderr(&output));
  let stdout = String::from_utf8_lossy(&output.stdout);
  assert!(
    stdout.starts_with("event: ") || stdout.starts_with("data: "),
    "{stdout}"
  );
  assert!(stdout.contains("data: "), "{stdout}");
  assert!(!stdout.contains("profile:"), "{stdout}");
  assert!(stderr(&output).contains("profile:   work"));
  assert_eq!(mock.last_request().unwrap().path, "/chat/completions");

  mock.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_send_non_success_prints_response_then_fails() {
  let mut failure = MockResponse::json(serde_json::json!({"error": {"message": "mock failure"}}));
  failure.status = "502".parse().unwrap();
  let mock =
    MockLlmServer::start(MockLlmConfig::default().with_route(MockRoute::new(MockEndpoint::ChatCompletions, failure)))
      .await;
  let temp = tempfile::tempdir().unwrap();
  let home = temp.path().join("home");
  write_managed_fixture(&home, mock.base_url());

  let output = smoke_async(
    &home,
    &[
      "send",
      "--profile",
      "work",
      "--model",
      "llama-cpp/mock-model",
      "--format",
      "json",
      "hello",
    ],
  )
  .await;

  assert!(!output.status.success(), "non-success upstream unexpectedly succeeded");
  let report: Value = serde_json::from_slice(&output.stdout).expect("failure stdout is one JSON value");
  assert_eq!(report["success"], false);
  assert_eq!(report["response"]["status"], 502);
  assert_eq!(report["response"]["body"]["error"]["message"], "mock failure");
  assert!(stderr(&output).contains("managed upstream returned HTTP 502"));

  mock.shutdown().await;
}

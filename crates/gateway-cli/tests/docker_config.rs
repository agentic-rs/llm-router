use std::path::Path;
use std::process::Command;
use tokn_policy::{ClientAuthPlan, ListenerPlan};

#[test]
fn docker_command_is_accepted_and_leaves_listener_policy_in_config() {
  let dockerfile = include_str!("../../../Dockerfile");
  let command = dockerfile.lines().find_map(|line| line.strip_prefix("CMD ")).unwrap();
  let args: Vec<String> = serde_json::from_str(command).unwrap();
  assert_eq!(args, ["serve"]);
  let output = Command::new(env!("CARGO_BIN_EXE_tokn-gateway"))
    .args(args)
    .arg("--help")
    .output()
    .unwrap();
  assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn docker_example_requires_authentication_and_explicit_public_opt_in() {
  let source = include_str!("../../../examples/docker/config.toml");
  let path = Path::new("docker/config.toml");
  let config = tokn_config::v2::parse_config(source, path).unwrap();
  let listener = config.gateway().listeners().values().next().unwrap();
  let ListenerPlan::LlmApi(listener) = listener else {
    panic!("API listener")
  };
  assert!(!listener.bind().ip().is_loopback());
  assert_eq!(listener.client_auth(), ClientAuthPlan::LocalKeys);
  for unsafe_config in [
    source.replace("client_auth = \"local_keys\"", "client_auth = \"none\""),
    source.replace("allow_insecure_public = true", "allow_insecure_public = false"),
  ] {
    assert!(tokn_config::v2::parse_config(&unsafe_config, path).is_err());
  }
}

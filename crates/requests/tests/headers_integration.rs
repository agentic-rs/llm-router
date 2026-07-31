mod support;

use smol_str::SmolStr;
use std::sync::Arc;
use support::*;
use tokn_accounts::AccountHandle;
use tokn_core::provider::{Endpoint, HeaderPatchCtx, ProviderRequestKind};
use tokn_core::AgentId;
use tokn_mock_server::{MockAuthConfig, MockLlmConfig, MockLlmServer};
use tokn_requests::event::{EventPayload, StageEvent};
use tokn_requests::stage_traits::{BuildHeadersStage, ExtractStage, Resolved, ResolvedRoute};
use tokn_requests::stages::{
  AccountSelector, DefaultBuildHeaders, DefaultConvertRequest, DefaultConvertResponse, DefaultExtract, DefaultSend,
  PoolResolve, SelectorOutcome,
};
use tokn_requests::{PipelineError, PipelineRunner, Profile};

const CODEX_CLI_OPENAI_SEND_HEADERS_YAML: &str = include_str!("fixtures/agent_id_headers/codex-cli_openai_send.yaml");
const OPENCODE_OPENAI_SEND_HEADERS_YAML: &str = include_str!("fixtures/agent_id_headers/opencode_openai_send.yaml");
const CLAUDE_CODE_OPENAI_SEND_HEADERS_YAML: &str =
  include_str!("fixtures/agent_id_headers/claude-code_openai_send.yaml");
const CLINE_OPENAI_SEND_HEADERS_YAML: &str = include_str!("fixtures/agent_id_headers/cline_openai_send.yaml");
const COPILOT_CLI_OPENAI_SEND_HEADERS_YAML: &str =
  include_str!("fixtures/agent_id_headers/copilot-cli_openai_send.yaml");

const HEADERS_INPUT_CODEX_CLI_YAML: &str = include_str!("fixtures/headers/input/codex-cli.yaml");
const HEADERS_INPUT_OPENCODE_YAML: &str = include_str!("fixtures/headers/input/opencode.yaml");
const HEADERS_OUTPUT_CODEX_RESPONSES_CODEX_CLI_YAML: &str =
  include_str!("fixtures/headers/output/codex_responses_codex-cli.yaml");
const HEADERS_OUTPUT_CODEX_RESPONSES_OPENCODE_YAML: &str =
  include_str!("fixtures/headers/output/codex_responses_opencode.yaml");
const HEADERS_OUTPUT_COPILOT_RESPONSES_CODEX_CLI_YAML: &str =
  include_str!("fixtures/headers/output/copilot_responses_codex-cli.yaml");

struct AgentHeaderCase {
  name: &'static str,
  agent_id: AgentId,
  provider_id: &'static str,
  fixture_yaml: &'static str,
}

struct HeaderScenario {
  name: &'static str,
  provider_id: &'static str,
  agent_id: AgentId,
  endpoint: Endpoint,
  model: &'static str,
  input_yaml: &'static str,
  output_yaml: &'static str,
}

struct HeaderScenarioSelector {
  provider_id: &'static str,
  endpoint: Endpoint,
  model: &'static str,
  handle: Arc<AccountHandle>,
}

#[async_trait::async_trait]
impl AccountSelector for HeaderScenarioSelector {
  async fn select(
    &self,
    _ctx: &tokn_requests::pipeline::ctx::PipelineCtx,
    _ex: &tokn_requests::stage_traits::Extracted,
  ) -> Result<SelectorOutcome, PipelineError> {
    Ok(SelectorOutcome::Selected {
      account_id: SmolStr::new(self.handle.config.load().id.clone()),
      provider_id: SmolStr::new(self.provider_id),
      upstream_endpoint: Some(self.endpoint),
      upstream_model: SmolStr::new(self.model),
      account_handle: self.handle.clone(),
    })
  }
}

#[tokio::test]
async fn full_pipeline_agent_id_shapes_headers_seen_by_send() {
  let cases = [
    AgentHeaderCase {
      name: "opencode_openai",
      agent_id: AgentId::Opencode,
      provider_id: "openai",
      fixture_yaml: OPENCODE_OPENAI_SEND_HEADERS_YAML,
    },
    AgentHeaderCase {
      name: "codex_cli_openai",
      agent_id: AgentId::CodexCli,
      provider_id: "openai",
      fixture_yaml: CODEX_CLI_OPENAI_SEND_HEADERS_YAML,
    },
    AgentHeaderCase {
      name: "claude_code_openai",
      agent_id: AgentId::ClaudeCode,
      provider_id: "openai",
      fixture_yaml: CLAUDE_CODE_OPENAI_SEND_HEADERS_YAML,
    },
    AgentHeaderCase {
      name: "cline_openai",
      agent_id: AgentId::Cline,
      provider_id: "openai",
      fixture_yaml: CLINE_OPENAI_SEND_HEADERS_YAML,
    },
    AgentHeaderCase {
      name: "copilot_cli_openai",
      agent_id: AgentId::CopilotCli,
      provider_id: "openai",
      fixture_yaml: COPILOT_CLI_OPENAI_SEND_HEADERS_YAML,
    },
  ];

  for case in cases {
    let (bus, _log) = capture_bus();
    let (handle, seen_client_headers) = recording_handle(
      case.provider_id,
      "acct-1",
      ok_response(
        200,
        r#"{"id":"resp-agent-id","choices":[{"message":{"role":"assistant","content":"hi"}}]}"#,
      ),
    );
    let selector = Arc::new(HeaderScenarioSelector {
      provider_id: case.provider_id,
      endpoint: Endpoint::ChatCompletions,
      model: "glm-4",
      handle,
    });

    let profile = Arc::new(Profile::full(
      "smoke-agent-id-headers",
      Arc::new(FixedAgentExtract {
        agent_id: case.agent_id.clone(),
      }),
      Arc::new(PoolResolve::new(selector)),
      Arc::new(DefaultBuildHeaders::with_provider_defaults()),
      Arc::new(DefaultConvertRequest),
      Arc::new(DefaultSend::new(reqwest::Client::new())),
      Arc::new(DefaultConvertResponse::new()),
    ));
    let runner = PipelineRunner::new(profile, bus);

    runner
      .run(raw_chat("glm-4"))
      .await
      .unwrap_or_else(|err| panic!("{}: pipeline should succeed: {err}", case.name));

    let seen = seen_client_headers
      .lock()
      .unwrap()
      .clone()
      .unwrap_or_else(|| panic!("{}: provider should observe client headers", case.name));
    assert_headers_match_fixture(&seen, case.fixture_yaml, case.name);
  }
}

#[tokio::test]
async fn provider_headers_patch_from_fixtures() {
  let scenarios = [
    HeaderScenario {
      name: "codex_responses_opencode",
      provider_id: "codex",
      agent_id: AgentId::Opencode,
      endpoint: Endpoint::Responses,
      model: "gpt-5-codex",
      input_yaml: HEADERS_INPUT_OPENCODE_YAML,
      output_yaml: HEADERS_OUTPUT_CODEX_RESPONSES_OPENCODE_YAML,
    },
    HeaderScenario {
      name: "codex_responses_codex-cli",
      provider_id: "codex",
      agent_id: AgentId::CodexCli,
      endpoint: Endpoint::Responses,
      model: "gpt-5-codex",
      input_yaml: HEADERS_INPUT_CODEX_CLI_YAML,
      output_yaml: HEADERS_OUTPUT_CODEX_RESPONSES_CODEX_CLI_YAML,
    },
    HeaderScenario {
      name: "copilot_responses_codex-cli",
      provider_id: "github-copilot",
      agent_id: AgentId::CodexCli,
      endpoint: Endpoint::Responses,
      model: "gpt-5",
      input_yaml: HEADERS_INPUT_OPENCODE_YAML,
      output_yaml: HEADERS_OUTPUT_COPILOT_RESPONSES_CODEX_CLI_YAML,
    },
  ];

  for scenario in scenarios {
    let provider = provider_fixture(scenario.provider_id);
    let ctx = tokn_requests::PipelineCtx::new(
      format!("req-{}-headers", scenario.name),
      scenario.endpoint.into(),
      Arc::new(tokn_requests::EventBus::new(64)),
    );
    let mut extracted = DefaultExtract
      .extract(
        &ctx,
        raw_responses(scenario.model, headers_from_fixture(scenario.input_yaml), false),
      )
      .await
      .unwrap_or_else(|err| panic!("{}: extract should succeed: {err}", scenario.name));
    extracted.agent_id = Some(scenario.agent_id.clone());
    let resolved = Resolved {
      agent_id: Some(scenario.agent_id.clone()),
      model: extracted.model.clone(),
      upstream_model: SmolStr::new(scenario.model),
      route: ResolvedRoute::operation(scenario.endpoint, scenario.endpoint),
      account_id: SmolStr::new(provider.handle.config.load().id.clone()),
      provider_id: SmolStr::new(scenario.provider_id),
      account_handle: provider.handle.clone(),
    };
    let built = DefaultBuildHeaders::with_provider_defaults()
      .build_headers(&ctx, &extracted, &resolved)
      .await
      .unwrap_or_else(|err| panic!("{}: build_headers should succeed: {err}", scenario.name));
    let mut headers = built.headers.clone();
    resolved
      .account_handle
      .provider
      .patch_headers(
        &mut headers,
        &HeaderPatchCtx {
          request_kind: ProviderRequestKind::Operation(scenario.endpoint),
          body: extracted.body_json.as_ref(),
          bearer_token: provider.bearer_token,
          content_encoding: extracted.content_encoding.map(|encoding| encoding.as_str()),
          stream: extracted.stream,
          initiator: extracted.initiator.as_deref().unwrap_or("user"),
          inbound_headers: &extracted.headers,
          vars: &built.vars,
          wire_identity: Some(&built.agent_id),
        },
      )
      .unwrap_or_else(|err| panic!("{}: patch_headers should succeed: {err}", scenario.name));

    assert_headers_match_fixture(&headers, scenario.output_yaml, scenario.name);
  }
}

#[tokio::test]
async fn full_pipeline_codex_headers_are_captured_after_build_and_patch() {
  let server = MockLlmServer::start(MockLlmConfig::default().with_auth(MockAuthConfig::bearer(["atk-codex"]))).await;
  let (bus, log) = capture_bus();
  let selector = Arc::new(HeaderScenarioSelector {
    provider_id: "codex",
    endpoint: Endpoint::Responses,
    model: "gpt-5-codex",
    handle: codex_handle(server.base_url()),
  });

  let profile = Arc::new(Profile::full(
    "smoke-codex-headers",
    Arc::new(FixedAgentExtract {
      agent_id: AgentId::CodexCli,
    }),
    Arc::new(PoolResolve::new(selector)),
    Arc::new(DefaultBuildHeaders::with_provider_defaults()),
    Arc::new(DefaultConvertRequest),
    Arc::new(DefaultSend::new(reqwest::Client::new())),
    Arc::new(DefaultConvertResponse::new()),
  ));
  let runner = PipelineRunner::new(profile, bus);

  let converted = runner
    .run(raw_responses(
      "gpt-5-codex",
      headers_from_fixture(HEADERS_INPUT_CODEX_CLI_YAML),
      false,
    ))
    .await
    .expect("codex responses pipeline must succeed");

  assert_eq!(converted.status, 200);
  let events = drain_until_completed(&log).await;
  let built_headers = events
    .iter()
    .find_map(|event| match &event.payload {
      EventPayload::Stage(StageEvent::BuildHeaders(headers)) => Some(headers.headers.clone()),
      _ => None,
    })
    .expect("BuildHeaders event should be emitted before Send");
  assert_eq!(
    built_headers.get("session_id").map(|value| value.as_str()),
    Some("019e271b-4023-7081-be3e-7a69d97138a2"),
    "BuildHeaders should carry session correlation before provider auth patching"
  );
  assert_eq!(
    built_headers.get("OpenAI-Beta").map(|value| value.as_str()),
    Some("responses=v1"),
    "BuildHeaders should include the Codex overlay beta before provider normalization"
  );

  let captured = server
    .last_request()
    .expect("mock server should capture the upstream request");
  assert_eq!(captured.path, "/responses");
  for HeaderFixtureEntry { name, value } in load_header_fixture(HEADERS_OUTPUT_CODEX_RESPONSES_CODEX_CLI_YAML) {
    assert_eq!(
      captured.header(&name),
      Some(value.as_str()),
      "captured Codex output header mismatch for {name}"
    );
  }
}

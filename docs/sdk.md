# Embedded SDKs

The SDKs execute requests in-process through the same configuration,
credentials, account pool, routing, conversion, retry, and provider
implementations as the gateway. They do not require a gateway process.

## Rust

The `tokn-sdk` crate is the stable façade. It provides:

- default and explicit `config.toml` / `auth.yaml` loading, including
  `config.d` and `auth.d`;
- atomic `reload()` of configuration and credentials;
- default and per-request profile selection;
- a provider-neutral generation builder with friendly text, reasoning, tool
  call, usage, and streaming outputs;
- owned, serializable requests that can be transformed or bound to a client
  later;
- typed clients for Responses, Chat Completions, and Messages;
- a raw JSON request escape hatch;
- buffered typed responses and live byte streams.

The client-bound builder is the shortest path for a one-off request:

```rust
let response = client
  .generate("smart")
  .system("You are a Rust expert.")
  .prompt("Explain this function.")
  .send()
  .await?;

println!("{}", response.text);
```

Generation controls use provider-neutral names and are mapped after the route
selects an upstream endpoint:

```rust
use tokn_sdk::{
  GenerateRequest, ReasoningEffort, ReasoningMode, ReasoningSummary,
};

let openai_request = GenerateRequest::builder("gpt-5")
  .prompt("Solve this step by step.")
  .max_tokens(2048)
  .reasoning_effort(ReasoningEffort::High)
  .reasoning_summary(ReasoningSummary::Auto)
  .build()?;

let llama_request = GenerateRequest::builder("local-llama")
  .prompt("Compare these implementations.")
  .top_p(0.9)
  .top_k(40)
  .max_tokens(2048)
  .build()?;

let claude_request = GenerateRequest::builder("claude-sonnet-4.6")
  .prompt("Plan this migration.")
  .max_tokens(2048)
  .reasoning_mode(ReasoningMode::Adaptive)
  .reasoning_effort(ReasoningEffort::High)
  .build()?;
```

`max_tokens()` is an alias for the neutral `max_output_tokens()` control.
Managed routes serialize that limit as `max_output_tokens` for Responses,
`max_completion_tokens` for OpenAI Chat Completions, and `max_tokens` for
other Chat Completions or Messages routes. Codex account
routes reject an explicit limit because that backend does not preserve it.
The examples assume those selectors route to OpenAI Responses, llama.cpp Chat
Completions, and Copilot's Claude Chat Completions fallback; use selectors from
your own configuration.
`top_p()` remains portable across compatible routes and is validated in the
inclusive range 0 through 1. Responses supports reasoning effort and summary
but not `top_k` or an enabled/adaptive mode. Typed `top_k` is currently
supported on llama.cpp Chat Completions; llama.cpp has no portable reasoning
control. Known non-reasoning models reject typed reasoning locally.

DeepSeek exposes only `high` and `max` effort. The SDK rejects compatibility
aliases that DeepSeek would otherwise silently promote; it also rejects
`temperature` or `top_p` when DeepSeek thinking would ignore them. Claude
supports adaptive reasoning on 4.6 and newer models but not a reasoning
summary. Manual Claude reasoning requires `ReasoningMode::Enabled`, an
explicit `max_tokens()` limit, a budget of at least 1024 tokens, and
`budget_tokens < max_tokens`; manual mode is rejected on 4.7 and newer models,
while adaptive mode is rejected on 4.5 and older models. Claude effort is also
checked against the selected model generation—for example, Sonnet 4.5 has no
effort control, Opus 4.5 supports through `high`, 4.6 supports through `max`,
and current Opus 4.7 supports `xhigh`. Incompatible sampling values are
rejected while Claude thinking is enabled, as are explicit sampling controls
on Claude generations that do not accept them.

Unsupported explicit controls fail clearly after routing rather than being
silently dropped or reinterpreted. Raw endpoint clients remain the escape
hatch for an exact provider wire shape.

`passthrough` and `switch` profiles preserve the generated Responses payload
verbatim, so they reject typed `top_k` and reasoning controls that would
require post-route lowering. Use an `exact`, `route`, or `fuzzy` profile for
the provider-neutral control API.

Build a request without a client when it needs to be serialized, transformed,
queued, or reused:

```rust
let request = GenerateRequest::builder("smart")
  .prompt("Explain this function.")
  .temperature(0.2)
  .build()?;

let serialized = serde_json::to_string(&request)?;
let request: GenerateRequest = serde_json::from_str(&serialized)?;
let response = client.send(&request).await?;
```

The same owned request can instead be rebound for fluent execution:

```rust
let response = request.bind(&client).send().await?;
```

The façade deliberately hides router `AppState`, account handles, and request
pipeline stages. Those remain implementation details and can evolve without
breaking SDK consumers. Typed endpoint clients and raw JSON remain available
when an exact endpoint wire shape is required.

## Python

The `bindings/python` package is a mixed Python/Rust package built with
Maturin and PyO3. Its native module owns an `Arc<tokn_sdk::Client>`, while the
public generation models are dependency-free Python dataclasses.

The client-bound builder mirrors the Rust API:

```python
from tokn import Client

client = Client()

response = await (
  client.generate("smart")
  .system("You are a Python expert.")
  .prompt("Explain this function.")
  .temperature(0.2)
  .send()
)

print(response.text)
```

Python exposes the same neutral generation controls:

```python
from tokn import (
  GenerateRequest,
  ReasoningEffort,
  ReasoningMode,
  ReasoningSummary,
)

openai_request = (
  GenerateRequest.builder("gpt-5")
  .prompt("Solve this step by step.")
  .max_tokens(2048)
  .reasoning_effort(ReasoningEffort.HIGH)
  .reasoning_summary(ReasoningSummary.AUTO)
  .build()
)

llama_request = (
  GenerateRequest.builder("local-llama")
  .prompt("Compare these implementations.")
  .top_p(0.9)
  .top_k(40)
  .max_tokens(2048)
  .build()
)

claude_request = (
  GenerateRequest.builder("claude-sonnet-4.6")
  .prompt("Plan this migration.")
  .max_tokens(2048)
  .reasoning_mode(ReasoningMode.ADAPTIVE)
  .reasoning_effort(ReasoningEffort.HIGH)
  .build()
)
```

As in Rust, `max_tokens()` aliases `max_output_tokens()`. Reasoning modes,
summaries, and `top_k` remain provider- and model-dependent; the three examples
deliberately keep each request to controls its route can represent.
Unsupported explicit controls fail clearly after routing. Use the raw endpoint
clients when the application needs to control the exact wire representation.

`GenerateRequest` is owned and independent from a client, so it can be
serialized, transformed, queued, and later sent or bound:

```python
from tokn import Client, GenerateRequest, Message

client = Client()
request = GenerateRequest(
  model="smart",
  messages=[Message.user("Explain this function.")],
)

serialized = request.to_json()
request = GenerateRequest.from_json(serialized).with_changes(
  max_output_tokens=128,
)
response = await client.send(request)
```

`client.stream(request)` yields typed semantic events and
`client.stream_text(request)` yields only text deltas. The endpoint clients
remain available as raw mapping and byte-stream escape hatches. All calls are
`async`; Python never reads or interprets credential files itself.

## Node.js and Bun

Node.js and Bun should share one N-API package backed by `tokn-sdk`; they
should not implement routing or credential handling in TypeScript. The
binding should follow the Python wire boundary:

- JSON-compatible request and response objects;
- `Promise<Response>` for buffered calls;
- an async iterable of `Uint8Array` for streams;
- synchronous construction and `reload()`;
- the same endpoint names and snake_case request-option fields.

Use `napi-rs` with a dedicated Tokio runtime bridge. Publish platform-specific
native packages behind one JavaScript package, and test the same package under
both Node.js and Bun. This is the next language milestone after the Rust and
Python APIs stabilize.

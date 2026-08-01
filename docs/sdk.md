# Embedded SDKs

The SDKs execute requests in-process through one managed profile from the
same version 2 configuration, credentials, account selection, conversion, and
provider implementations as the gateway. They do not require a listener or a
gateway process.

## Rust

The `tokn-sdk` crate is the stable façade. It provides:

- strict version 2 `config.toml` loading plus `auth.yaml` and `auth.d`;
- atomic `reload()` of configuration and credentials;
- one client-bound managed profile, with `default` used when omitted;
- a provider-neutral generation builder with friendly text, reasoning, tool
  call, usage, and streaming outputs;
- owned, serializable requests that can be transformed or bound to a client
  later;
- typed clients for Responses, Chat Completions, and Messages;
- a raw JSON request escape hatch;
- buffered typed responses and live byte streams.

### Lifecycle events

Embedded requests can publish the same comprehensive lifecycle events as the
listener runtime. The application owns the event hub and its consumers; the
SDK only retains a clone of the supplied publisher:

```rust
use tokn_sdk::{events::*, Client};

struct PrintEvents;

impl EventConsumer<GatewayEvent> for PrintEvents {
  fn name(&self) -> &str {
    "print-events"
  }

  fn handle(&mut self, sequence: EventSeq, event: &GatewayEvent) -> ConsumerResult {
    println!("{sequence}: {event:?}");
    Ok(())
  }
}

let (publisher, hub) = HubBuilder::new()
  .consumer(PrintEvents)
  .start()?;
let client = Client::builder()
  .event_publisher(publisher)
  .build()?;

let response = client
  .generate("smart")
  .prompt("Explain this function.")
  .send()
  .await?;

drop(response);
drop(client);
hub.shutdown().await?;
```

Reliable lifecycle boundaries use the hub's bounded queue and can backpressure
request execution. High-volume progress observations may be coalesced, while
request and attempt boundaries remain ordered and reliable. Omitting
`event_publisher()` disables publication without starting an internal hub.

The lifecycle begins only after the SDK has constructed the managed gateway
request. Typed request serialization failures and invalid `RequestOptions`
header names or values are SDK-local errors, so they do not emit
`Started`/`Finished`. Once managed execution begins, profile, body, selection,
and upstream-attempt failures are enclosed by those lifecycle boundaries.

The publisher is fixed for the client's lifetime and reused by every successful
reload. A failed reload leaves both the previous runtime snapshot and the same
publisher usable. The SDK never closes the hub, including when `Client` is
dropped. Before calling `hub.shutdown()`, stop starting requests, await all
buffered calls, and fully drain or drop every raw or semantic stream so each
stream-owned lifecycle can publish its terminal facts. Raw streams retain
transport EOF/drop semantics. Friendly semantic streams finish promptly when
they recognize a protocol terminal, even if the peer keeps the HTTP connection
open; the corresponding lifecycle terminal batch is submitted before semantic
completion is exposed. A terminal publication failure is surfaced to the
semantic stream consumer, while dropping a semantic stream before its terminal
cancels the request lifecycle.

Profile selection happens once, when the client is built:

```rust
let client = tokn_sdk::Client::builder()
  .profile("coding")
  .build()?;
```

Omit `profile()` to use the conventional `default` profile. Each reload keeps
that profile and the resolved config/auth paths fixed while atomically
replacing the linked runtime generation.

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
silently dropped or reinterpreted. Raw endpoint clients accept endpoint-shaped
request and response types; the managed route still owns upstream translation.

The embedded SDK accepts managed profiles only. Relay and transparent routes
belong to listener-backed HTTP/proxy serving and are rejected when the client
is built. To use multiple profiles in one process, build one client per
profile; request options cannot override the client-bound profile.

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
selection tokens. Those remain implementation details and can evolve without
breaking SDK consumers. Typed endpoint clients and raw JSON remain available
when direct endpoint request/response types are required.

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
clients when the application needs a typed Responses, Chat Completions, or
Messages request rather than the provider-neutral generation builder.

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

`bindings/typescript` is the ESM `@tokn/sdk` package for Node.js 22 and newer
and Bun. Its TypeScript façade exposes plain JSON-compatible objects while a
private N-API binding runs `tokn-sdk` in-process. TypeScript does not load
configuration or credentials itself.

Create and close the client asynchronously:

```ts
import { Client } from "@tokn/sdk";

const client = await Client.create();

try {
  const response = await client
    .generate("smart")
    .system("You are a TypeScript expert.")
    .prompt("Explain this function.")
    .temperature(0.2)
    .send();

  console.log(response.text);
} finally {
  await client.close();
}
```

The client-bound builder and detached request builder expose the same neutral
controls as Rust and Python. Builder methods use normal TypeScript casing;
every serializable field stays `snake_case`:

```ts
import { request } from "@tokn/sdk";

const value = request("smart")
  .prompt("Plan this migration.")
  .topP(0.9)
  .topK(40)
  .maxTokens(2048)
  .reasoningMode("adaptive")
  .reasoningEffort("high")
  .build();

const serialized = JSON.stringify(value);
const response = await client.send(JSON.parse(serialized));
```

Object input is also a first-class API:

```ts
const response = await client.send({
  model: "smart",
  prompt: "Explain this function.",
  top_p: 0.9,
  max_output_tokens: 256,
  reasoning: {
    effort: "high",
    summary: "auto",
  },
});
```

`client.generateStream()` yields typed semantic events,
`client.textStream()` yields text deltas, and raw endpoint streams yield
`Uint8Array`. Streams are pull-based async iterables with explicit `close()`;
breaking out of `for await` also closes them. Buffered calls and stream
startup accept an `AbortSignal`, which cancels the Rust operation rather than
only abandoning its JavaScript promise.

The raw endpoint namespaces remain available for typed endpoint shapes:

```ts
const response = await client.chat.completions.create(
  {
    model: "smart",
    messages: [{ role: "user", content: "Hello" }],
  },
  {
    request_id: crypto.randomUUID(),
  },
);
```

`Client.create()`, `reload()`, and `close()` are async so configuration I/O,
credential loading, and shutdown never block the JavaScript event loop.
Native failures are mapped to stable `ToknError` subclasses and codes;
provider status failures also retain their HTTP status and response body.

Build the package from the repository with:

```sh
cd bindings/typescript
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

The generated `_native.cjs` loader is private. The repository package is also
marked private for now: it can be built and linked from a checkout, but it
cannot be published accidentally before its platform artifacts are assembled.
The eventual registry release will keep one public `@tokn/sdk` façade and use
exact-version optional packages for Linux x64 glibc, macOS arm64, and Windows
x64 MSVC.

CI builds the native binding and runs the façade against it with Node.js 22
and Bun 1.3.13 on all three platforms, plus Node.js 24 on Linux. The macOS
artifact is built with an 11.0 deployment target, although the blocking
runtime job currently runs on macOS 15. Before the private guard is removed,
Linux release builds must pin and verify a glibc floor instead of treating
`ubuntu-latest` as a compatibility guarantee, and CI must install-test the
assembled root and platform tarballs with both runtimes. Publication is
intentionally separate from the repository's existing CLI release workflow.

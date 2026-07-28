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
breaking SDK consumers. Provider-specific controls that do not have equivalent
semantics across endpoints, such as reasoning configuration, remain available
through the typed endpoint clients and raw JSON escape hatch.

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

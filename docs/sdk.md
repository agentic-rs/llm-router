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
- typed clients for Responses, Chat Completions, and Messages;
- a raw JSON request escape hatch;
- buffered typed responses and live byte streams.

The façade deliberately hides router `AppState`, account handles, and request
pipeline stages. Those remain implementation details and can evolve without
breaking SDK consumers.

## Python

The `bindings/python` package is a mixed Python/Rust package built with
Maturin and PyO3. Its public API accepts and returns ordinary Python mappings,
while its native module owns an `Arc<tokn_sdk::Client>`.

Python endpoint calls are `async`. Streaming calls return an async iterator of
bytes so SSE framing is preserved exactly. Python never reads or interprets
credential files itself.

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

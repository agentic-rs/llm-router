# @tokn/sdk

Embedded TypeScript SDK for routing LLM requests through a managed profile in
a strict `schema_version = 2` tokn gateway configuration.

The package is an ESM package for Node.js 22+ and Bun. Its public API is
TypeScript, while routing and provider execution run in-process through the
same Rust engine as `tokn-gateway`.

Each client is bound to one managed profile for its complete lifetime. The
profile may point at a listener-free route, so embedding the SDK does not
require starting a gateway server. Build another client when an application
needs another profile; requests cannot override the client-bound profile.

The repository package is currently a source preview and is deliberately
marked private. Build it from this checkout and link the directory into an
application; npm publication stays disabled until the release pipeline builds,
assembles, and install-tests every declared native package.

## Configuration

The SDK loads the compiled v2 gateway graph and the normal tokn credential
store. A minimal listener-free profile can use a fixed upstream and
provider-qualified model names:

```toml
schema_version = 2

[profiles.work]
route = "managed"

[routes.managed]
kind = "managed"
account_pool = "default"
upstream = { kind = "fixed", upstream = "local" }
model = { kind = "qualified", namespace = "provider" }
operation = "translate_compatible"

[account_pools.default]
active_accounts = ["*"]
providers = ["llama-cpp"]

[upstreams.local]
provider = "llama-cpp"
base_url = "http://127.0.0.1:8080/v1"
accounts = ["local-llama"]
```

Only managed profiles can be embedded. Relay and transparent routes require a
listener-backed gateway. `Client.create()` uses the conventional `default`
profile when `profile` is omitted. The immutable selection is available as
the read-only `client.profile` property.

## Usage

```ts
import { Client } from "@tokn/sdk";

const client = await Client.create({ profile: "work" });

try {
  const response = await client
    .generate("llama-cpp/qwen3")
    .system("You are a TypeScript expert.")
    .prompt("Explain this function.")
    .temperature(0.2)
    .send();

  console.log(response.text);
} finally {
  await client.close();
}
```

Requests can also be plain, owned objects that are easy to serialize, queue,
or transform:

```ts
const request = {
  model: "llama-cpp/qwen3",
  prompt: "Plan this migration.",
  top_p: 0.9,
  max_output_tokens: 2048,
  reasoning: {
    effort: "high",
    summary: "auto",
  },
} as const;

const response = await client.send(request);
```

Builder methods use camelCase. Fields that cross the serialization boundary
use snake_case.

## Streaming and cancellation

Generation streams are pull-based async iterables:

```ts
const controller = new AbortController();
const stream = await client.textStream(
  {
    model: "llama-cpp/qwen3",
    prompt: "Write a short explanation.",
  },
  { signal: controller.signal },
);

try {
  for await (const text of stream) {
    process.stdout.write(text);
  }
} finally {
  await stream.close();
}
```

Breaking from a `for await` loop closes the stream automatically. Passing an
`AbortSignal` cancels the underlying Rust operation, including an idle stream
read.

## Raw endpoints

The provider-neutral API is the default. Endpoint-shaped requests are also
available when an application needs to provide Chat Completions, Responses,
or Messages JSON directly. The managed profile may still translate that
request for its selected upstream:

```ts
const response = await client.chat.completions.create(
  {
    model: "llama-cpp/qwen3",
    messages: [{ role: "user", content: "Hello" }],
  },
  {
    request_id: crypto.randomUUID(),
  },
);
```

## Development

From this directory:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

`pnpm build` compiles both the host N-API addon and the TypeScript façade.
An application can then depend on this directory with a local `link:` or
workspace dependency.

The future registry release will use one small root package plus an
exact-version native package selected for the host platform. Before the
private guard is removed, that pipeline must also pin and verify the Linux
glibc floor and install-test assembled tarballs with both Node.js and Bun.

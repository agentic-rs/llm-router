# @tokn/sdk

Embedded TypeScript SDK for routing LLM requests through the providers,
profiles, configuration, and credentials already managed by tokn.

The package is an ESM package for Node.js 22+ and Bun. Its public API is
TypeScript, while routing and provider execution run in-process through the
same Rust engine as `tokn-gateway`.

The repository package is currently a source preview and is deliberately
marked private. Build it from this checkout and link the directory into an
application; npm publication stays disabled until the release pipeline builds,
assembles, and install-tests every declared native package.

## Usage

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

Requests can also be plain, owned objects that are easy to serialize, queue,
or transform:

```ts
const request = {
  model: "smart",
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
    model: "smart",
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

The provider-neutral API is the default. Raw endpoint namespaces remain
available when an application needs an exact wire shape:

```ts
const response = await client.chat.completions.create(
  {
    model: "smart",
    messages: [{ role: "user", content: "Hello" }],
  },
  {
    profile: "work",
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

import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import {
  APIStatusError,
  CancelledError,
  Client,
  ClientClosedError,
  ConfigurationError,
  InternalError,
  RequestError,
  SerializationError,
  type GenerateEvent,
  type JsonValue,
} from "../src/index.js";
import { setNativeBindingForTests } from "../src/native.js";
import type {
  NativeBinding,
  NativeByteStream,
  NativeCancellation,
  NativeClient,
  NativeGenerateStream,
  NativeRequestEventStream,
  NativeResponse,
  NativeTextStream,
} from "../src/native.js";

function nativeError(
  code: string,
  message: string,
  details: { readonly status?: number; readonly body?: string } = {},
): Error {
  return new Error(`TOKN_ERROR:${JSON.stringify({ code, message, ...details })}`);
}

class FakeCancellation implements NativeCancellation {
  aborted = false;
  private readonly listeners = new Set<() => void>();

  cancel(): void {
    if (this.aborted) {
      return;
    }
    this.aborted = true;
    for (const listener of this.listeners) {
      listener();
    }
    this.listeners.clear();
  }

  untilCancelled(): Promise<never> {
    if (this.aborted) {
      return Promise.reject(nativeError("cancelled", "operation was cancelled"));
    }
    return new Promise((_, reject) => {
      this.listeners.add(() => {
        reject(nativeError("cancelled", "operation was cancelled"));
      });
    });
  }
}

class FakePullStream<T> {
  readonly values: T[];
  closeCalls = 0;

  constructor(values: T[]) {
    this.values = [...values];
  }

  async next(): Promise<T | null> {
    return this.values.shift() ?? null;
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
  }
}

class FakeClient implements NativeClient {
  readonly configPath = "/config.toml";
  readonly authPath = "/auth.yaml";
  closeCalls = 0;
  reloadCalls = 0;
  lastRequestJson: string | undefined;
  lastEndpoint: string | undefined;
  lastBodyJson: string | undefined;
  lastOptionsJson: string | null | undefined;
  lastCancellation: FakeCancellation | undefined;
  blockGenerate = false;
  generateError: Error | undefined;
  generateResponseJson: string | undefined;
  byteStream = new FakePullStream<Uint8Array>([
    new Uint8Array([1, 2]),
    new Uint8Array([3]),
  ]) as NativeByteStream & FakePullStream<Uint8Array>;
  eventStream = new FakePullStream<string>([
    JSON.stringify({ type: "text_delta", text: "hello" }),
    JSON.stringify({ type: "completed", finish_reason: "stop" }),
  ]) as NativeGenerateStream & FakePullStream<string>;
  requestEventStream = new FakePullStream<string>([
    JSON.stringify({
      request_id: "request-1",
      attempt: 0,
      ts: 1,
      payload: { category: "stage", event: { type: "started", data: { request_endpoint: "responses" } } },
    }),
  ]) as NativeRequestEventStream & FakePullStream<string>;
  textOutputStream = new FakePullStream<string>(["hello", " world"]) as NativeTextStream &
    FakePullStream<string>;

  constructor() {
    Object.assign(this.byteStream, {
      status: 200,
      headersJson: JSON.stringify({ "content-type": "application/octet-stream" }),
    });
  }

  async reload(cancellation: NativeCancellation): Promise<void> {
    this.reloadCalls += 1;
    this.lastCancellation = cancellation as FakeCancellation;
  }

  subscribeEvents(): NativeRequestEventStream {
    return this.requestEventStream;
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
  }

  async request(
    endpoint: string,
    bodyJson: string,
    optionsJson: string | null,
    cancellation: NativeCancellation,
  ): Promise<NativeResponse> {
    this.lastEndpoint = endpoint;
    this.lastBodyJson = bodyJson;
    this.lastOptionsJson = optionsJson;
    this.lastCancellation = cancellation as FakeCancellation;
    return {
      status: 201,
      headersJson: JSON.stringify({ "x-test": ["one", "two"] }),
      bodyJson: JSON.stringify({ id: "response-1" }),
    };
  }

  async stream(
    endpoint: string,
    bodyJson: string,
    optionsJson: string | null,
    cancellation: NativeCancellation,
  ): Promise<NativeByteStream> {
    this.lastEndpoint = endpoint;
    this.lastBodyJson = bodyJson;
    this.lastOptionsJson = optionsJson;
    this.lastCancellation = cancellation as FakeCancellation;
    return this.byteStream;
  }

  async sendGenerate(requestJson: string, cancellation: NativeCancellation): Promise<string> {
    this.lastRequestJson = requestJson;
    this.lastCancellation = cancellation as FakeCancellation;
    if (this.generateError !== undefined) {
      throw this.generateError;
    }
    if (this.blockGenerate) {
      return await this.lastCancellation.untilCancelled();
    }
    return this.generateResponseJson ?? JSON.stringify({
      http_status: 200,
      headers: { "content-type": "application/json" },
      id: "response-1",
      model: "smart",
      status: "completed",
      finish_reason: "stop",
      text: "hello",
      reasoning: null,
      tool_calls: [],
      usage: null,
      raw: { id: "response-1" },
    });
  }

  async generateStream(requestJson: string, cancellation: NativeCancellation): Promise<NativeGenerateStream> {
    this.lastRequestJson = requestJson;
    this.lastCancellation = cancellation as FakeCancellation;
    return this.eventStream;
  }

  async textStream(requestJson: string, cancellation: NativeCancellation): Promise<NativeTextStream> {
    this.lastRequestJson = requestJson;
    this.lastCancellation = cancellation as FakeCancellation;
    return this.textOutputStream;
  }
}

function fakeBinding(client: FakeClient): NativeBinding & { readonly options: string[] } {
  const options: string[] = [];
  return {
    options,
    NativeCancellation: FakeCancellation,
    nativeAbiVersion(): number {
      return 1;
    },
    async createClient(optionsJson: string): Promise<NativeClient> {
      options.push(optionsJson);
      return client;
    },
  };
}

afterEach(() => {
  setNativeBindingForTests(undefined);
});

test("Client.create is async and exposes resolved source paths", async () => {
  const native = new FakeClient();
  const binding = fakeBinding(native);
  setNativeBindingForTests(binding);

  const client = await Client.create({
    config_path: "/custom/config.toml",
    auth_path: "/custom/auth.yaml",
    profile: "work",
  });

  assert.equal(client.configPath, "/config.toml");
  assert.equal(client.authPath, "/auth.yaml");
  assert.deepEqual(JSON.parse(binding.options[0] ?? ""), {
    config_path: "/custom/config.toml",
    auth_path: "/custom/auth.yaml",
    profile: "work",
  });
});

test("Client.create rejects unknown options before calling native code", async () => {
  const native = new FakeClient();
  const binding = fakeBinding(native);
  setNativeBindingForTests(binding);

  await assert.rejects(
    Client.create({ profile: "work", unexpected: true } as never),
    (error: unknown) =>
      error instanceof RequestError &&
      error.message === "unknown client option 'unexpected'",
  );
  assert.deepEqual(binding.options, []);
});

test("native binding validation uses the public configuration error type", async () => {
  setNativeBindingForTests({} as NativeBinding);
  await assert.rejects(
    Client.create(),
    (error: unknown) =>
      error instanceof ConfigurationError &&
      error.message === "the native @tokn/sdk binding does not expose the expected API",
  );

  setNativeBindingForTests({
    ...fakeBinding(new FakeClient()),
    nativeAbiVersion: () => 2,
  });
  await assert.rejects(
    Client.create(),
    (error: unknown) =>
      error instanceof ConfigurationError &&
      error.message === "the native @tokn/sdk binding uses an unsupported ABI version",
  );
});

test("reload delegates to the native client", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();

  await client.reload();
  assert.equal(native.reloadCalls, 1);
});

test("request lifecycle subscriptions expose structured events", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();
  const events = client.subscribeEvents();

  assert.deepEqual(await events.next(), {
    done: false,
    value: {
      request_id: "request-1",
      attempt: 0,
      ts: 1,
      payload: { category: "stage", event: { type: "started", data: { request_endpoint: "responses" } } },
    },
  });
  await events.close();
  assert.equal(native.requestEventStream.closeCalls, 1);
});

test("client-bound generation keeps the fluent UX while sending a plain request", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();

  const response = await client
    .generate("smart")
    .system("Be concise.")
    .prompt("Hello")
    .topP(0.8)
    .maxTokens(256)
    .send();

  assert.equal(response.text, "hello");
  assert.deepEqual(JSON.parse(native.lastRequestJson ?? ""), {
    model: "smart",
    messages: [
      { role: "system", content: "Be concise." },
      { role: "user", content: "Hello" },
    ],
    top_p: 0.8,
    max_output_tokens: 256,
  });
});

test("raw endpoint namespaces and methods share the same request path", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();

  const response = await client.chat.completions.create<{ readonly id: string }>(
    { model: "smart", messages: [] },
    { profile: "work", request_id: "request-1" },
  );

  assert.equal(response.status, 201);
  assert.equal(response.data.id, "response-1");
  assert.equal(native.lastEndpoint, "chat_completions");
  assert.deepEqual(JSON.parse(native.lastOptionsJson ?? ""), {
    profile: "work",
    request_id: "request-1",
  });
  assert.deepEqual(response.headers["x-test"], ["one", "two"]);
});

test("AbortSignal cancels the native operation", async () => {
  const native = new FakeClient();
  native.blockGenerate = true;
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();
  const controller = new AbortController();

  const pending = client.send(
    { model: "smart", messages: [{ role: "user", content: "Hello" }] },
    { signal: controller.signal },
  );
  controller.abort();

  await assert.rejects(
    pending,
    (error: unknown) => error instanceof CancelledError && error.code === "cancelled",
  );
  assert.equal(native.lastCancellation?.aborted, true);
});

test("native status errors become stable public error classes", async () => {
  const native = new FakeClient();
  native.generateError = nativeError("api_status_error", "rate limited", {
    status: 429,
    body: '{"error":"slow down"}',
  });
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();

  await assert.rejects(
    client.send({ model: "smart", prompt: "Hello" }),
    (error: unknown) =>
      error instanceof APIStatusError &&
      error.code === "api_status_error" &&
      error.status === 429 &&
      error.body === '{"error":"slow down"}',
  );
});

test("malformed native error payloads are not exposed in fallback messages", async () => {
  const native = new FakeClient();
  native.generateError = new Error("native bridge failed: TOKN_ERROR:{not-json");
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();

  await assert.rejects(
    client.send({ model: "smart", prompt: "Hello" }),
    (error: unknown) =>
      error instanceof InternalError &&
      error.message === "native bridge failed:" &&
      !error.message.includes("TOKN_ERROR"),
  );
});

test("malformed native generation responses become serialization errors", async () => {
  const native = new FakeClient();
  native.generateResponseJson = JSON.stringify({
    http_status: 200,
    headers: {},
    text: "incomplete",
    raw: {},
  });
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();

  await assert.rejects(
    client.send({ model: "smart", prompt: "Hello" }),
    (error: unknown) => error instanceof SerializationError,
  );
});

test("pull streams support async iteration and explicit cleanup", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();
  const stream = await client.generateStream({ model: "smart", prompt: "Hello" });
  const events: GenerateEvent[] = [];

  for await (const event of stream) {
    events.push(event);
    break;
  }

  assert.deepEqual(events, [{ type: "text_delta", text: "hello" }]);
  assert.equal(native.eventStream.closeCalls, 1);
  assert.equal(native.lastCancellation?.aborted, false);
});

test("malformed native stream events become serialization errors", async () => {
  const native = new FakeClient();
  native.eventStream = new FakePullStream<string>([
    JSON.stringify({ type: "text_delta", text: 42 }),
  ]) as NativeGenerateStream & FakePullStream<string>;
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();
  const stream = await client.generateStream({ model: "smart", prompt: "Hello" });

  await assert.rejects(
    stream.next(),
    (error: unknown) => error instanceof SerializationError,
  );
});

test("aborting an idle stream releases it and rejects the next read", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();
  const controller = new AbortController();
  const stream = await client.textStream(
    { model: "smart", prompt: "Hello" },
    { signal: controller.signal },
  );

  controller.abort();

  await assert.rejects(
    stream.next(),
    (error: unknown) => error instanceof CancelledError,
  );
  await client.close();
  assert.equal(native.textOutputStream.closeCalls, 0);
});

test("raw streams yield Uint8Array chunks and preserve metadata", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();
  const stream = await client.responses.stream({ model: "smart" });
  const chunks: number[][] = [];

  for await (const chunk of stream) {
    chunks.push([...chunk]);
  }

  assert.equal(stream.status, 200);
  assert.equal(stream.headers["content-type"], "application/octet-stream");
  assert.deepEqual(chunks, [
    [1, 2],
    [3],
  ]);
});

test("close is idempotent and rejects later work", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();

  await Promise.all([client.close(), client.close()]);

  assert.equal(native.closeCalls, 1);
  assert.equal(client.isClosed, true);
  await assert.rejects(
    client.request("responses", {} as Record<string, JsonValue>),
    (error: unknown) => error instanceof ClientClosedError,
  );
});

test("closing a client cleans up abandoned streams and their abort listeners", async () => {
  const native = new FakeClient();
  setNativeBindingForTests(fakeBinding(native));
  const client = await Client.create();
  const controller = new AbortController();

  await client.generateStream(
    { model: "smart", prompt: "Hello" },
    { signal: controller.signal },
  );
  const cancellation = native.lastCancellation;
  await client.close();
  controller.abort();

  assert.equal(native.eventStream.closeCalls, 1);
  assert.equal(cancellation?.aborted, false);
});

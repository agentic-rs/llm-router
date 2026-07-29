import assert from "node:assert/strict";
import { test } from "node:test";

import {
  RequestError,
  SerializationError,
  createRequest,
  request,
  userMessage,
} from "../src/index.js";

test("createRequest turns prompt input into an owned wire request", () => {
  const input = {
    model: "smart",
    system: "Be concise.",
    prompt: "Explain this function.",
    options: {
      request_id: "request-1",
    },
  };

  const value = createRequest(input);

  assert.deepEqual(value, {
    model: "smart",
    messages: [
      { role: "system", content: "Be concise." },
      { role: "user", content: "Explain this function." },
    ],
    options: {
      request_id: "request-1",
    },
  });
  assert.equal("prompt" in value, false);
  assert.equal("system" in value, false);
});

test("detached builder exposes neutral generation controls with snake_case wire fields", () => {
  const value = request("smart")
    .system("Use the tools when useful.")
    .prompt("What is the weather?")
    .tool({
      name: "weather",
      description: "Get the weather",
      parameters: {
        type: "object",
        properties: {
          city: { type: "string" },
        },
      },
      strict: true,
    })
    .toolChoice({ tool: "weather" })
    .temperature(0.2)
    .topP(0.9)
    .topK(40)
    .maxTokens(2048)
    .reasoningMode("adaptive")
    .reasoningEffort("high")
    .reasoningSummary("auto")
    .profile("default")
    .requestId("request-1")
    .header("x-example", "value")
    .extra("metadata", { source: "test" })
    .build();

  assert.equal(value.top_p, 0.9);
  assert.equal(value.top_k, 40);
  assert.equal(value.max_output_tokens, 2048);
  assert.deepEqual(value.reasoning, {
    mode: "adaptive",
    effort: "high",
    summary: "auto",
  });
  assert.deepEqual(value.options, {
    profile: "default",
    request_id: "request-1",
    headers: [["x-example", "value"]],
  });
  assert.equal("topP" in value, false);
  assert.equal("maxTokens" in value, false);
});

test("built requests are independent snapshots", () => {
  const builder = request("smart").message(userMessage("first"));
  const first = builder.build();

  builder.prompt("second");
  const second = builder.build();

  assert.equal(first.messages.length, 1);
  assert.equal(second.messages.length, 2);
});

test("request validation catches values JavaScript cannot represent safely", () => {
  assert.throws(
    () => createRequest({ model: "smart", prompt: "hello", max_output_tokens: Number.MAX_SAFE_INTEGER + 1 }),
    (error: unknown) => error instanceof RequestError && error.code === "request_error",
  );
  assert.throws(
    () => createRequest({ model: "smart", prompt: "hello", temperature: Number.NaN }),
    (error: unknown) => error instanceof RequestError && error.message === "temperature must be finite",
  );
  assert.throws(
    () =>
      createRequest({
        model: "smart",
        prompt: "hello",
        extras: { invalid: Number.POSITIVE_INFINITY },
      }),
    (error: unknown) => error instanceof SerializationError,
  );
});

test("JSON serialization omits undefined object properties but rejects undefined array entries", () => {
  const requestWithOptionalProperty = createRequest({
    model: "smart",
    prompt: "hello",
    extras: { metadata: undefined } as never,
  });
  assert.equal(requestWithOptionalProperty.extras, undefined);

  assert.throws(
    () =>
      createRequest({
        model: "smart",
        prompt: "hello",
        extras: { items: [undefined] } as never,
      }),
    (error: unknown) =>
      error instanceof SerializationError &&
      error.message === "extras.items[0] contains a value that JSON cannot represent",
  );
});

test("malformed JavaScript containers produce stable request errors", () => {
  const malformed = [
    { model: "smart", prompt: "hello", tools: {} },
    { model: "smart", prompt: "hello", options: { headers: {} } },
    { model: "smart", prompt: "hello", extras: [] },
    { model: "smart", prompt: "hello", reasoning: [] },
  ];

  for (const input of malformed) {
    assert.throws(
      () => createRequest(input as never),
      (error: unknown) => error instanceof RequestError && error.code === "request_error",
    );
  }
});

test("typed reasoning rejects ambiguous extras", () => {
  assert.throws(
    () =>
      createRequest({
        model: "smart",
        prompt: "hello",
        reasoning: { effort: "high" },
        extras: { reasoning_effort: "low" },
      }),
    (error: unknown) =>
      error instanceof RequestError &&
      error.message === "typed reasoning conflicts with extras['reasoning_effort']",
  );
});

test("reasoning accepts non-empty provider-specific effort and summary values", () => {
  const value = createRequest({
    model: "smart",
    prompt: "hello",
    reasoning: {
      effort: "provider_effort",
      summary: "provider_summary",
    },
  });

  assert.deepEqual(value.reasoning, {
    effort: "provider_effort",
    summary: "provider_summary",
  });
  assert.throws(
    () =>
      createRequest({
        model: "smart",
        prompt: "hello",
        reasoning: { effort: " " },
      }),
    (error: unknown) =>
      error instanceof RequestError &&
      error.message === "reasoning.effort must be a non-empty string",
  );
});

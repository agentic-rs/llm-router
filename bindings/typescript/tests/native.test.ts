import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { CancelledError, Client, ConfigurationError } from "../src/index.js";
import { getNativeBinding } from "../src/native.js";

test("the packaged native addon exposes the supported ABI", () => {
  if (process.env["TOKN_NATIVE_SMOKE"] !== "1") {
    return;
  }
  assert.equal(getNativeBinding().nativeAbiVersion(), 2);
});

test("native configuration failures retain their public error type", async () => {
  if (process.env["TOKN_NATIVE_SMOKE"] !== "1") {
    return;
  }

  const fixtureRoot = await mkdtemp(join(tmpdir(), "tokn-typescript-error-"));
  try {
    await assert.rejects(
      Client.create({
        config_path: join(fixtureRoot, "missing-config.toml"),
        auth_path: join(fixtureRoot, "missing-auth.yaml"),
      }),
      (error: unknown) =>
        error instanceof ConfigurationError &&
        error.code === "configuration_error" &&
        error.cause instanceof Error,
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("the native client loads configured credentials and completes a provider request", async () => {
  if (process.env["TOKN_NATIVE_SMOKE"] !== "1") {
    return;
  }

  const requests: Array<{ readonly path: string; readonly body: Record<string, unknown> }> = [];
  const server = createServer(async (incoming, outgoing) => {
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
    requests.push({ path: incoming.url ?? "", body });

    if (body["stream"] === true && JSON.stringify(body).includes("idle cancellation")) {
      outgoing.writeHead(200, {
        "content-type": "text/event-stream",
      });
      outgoing.flushHeaders();
      outgoing.write(": keep-alive\n\n");
      return;
    }

    if (body["stream"] === true) {
      const payload = [
        {
          id: "chatcmpl-typescript-stream",
          model: "mock-model",
          choices: [{ index: 0, delta: { role: "assistant", content: "native " }, finish_reason: null }],
        },
        {
          id: "chatcmpl-typescript-stream",
          model: "mock-model",
          choices: [{ index: 0, delta: { content: "stream" }, finish_reason: null }],
        },
        {
          id: "chatcmpl-typescript-stream",
          model: "mock-model",
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        },
      ]
        .map((value) => `data: ${JSON.stringify(value)}\n\n`)
        .join("")
        .concat("data: [DONE]\n\n");
      outgoing.writeHead(200, {
        "content-type": "text/event-stream",
        "content-length": Buffer.byteLength(payload),
      });
      outgoing.end(payload);
      return;
    }

    const payload = JSON.stringify({
      id: "chatcmpl-typescript",
      object: "chat.completion",
      model: "mock-model",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: "native answer",
          },
          finish_reason: "stop",
        },
      ],
      usage: {
        prompt_tokens: 1,
        completion_tokens: 2,
        total_tokens: 3,
      },
    });
    outgoing.writeHead(200, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(payload),
    });
    outgoing.end(payload);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");

  const address = server.address();
  assert(address !== null && typeof address === "object");
  const fixtureRoot = await mkdtemp(join(tmpdir(), "tokn-typescript-"));
  const configPath = join(fixtureRoot, "config.toml");
  const authPath = join(fixtureRoot, "auth.yaml");
  await writeFile(
    configPath,
    [
      "schema_version = 2",
      "",
      "[profiles.native]",
      'route = "managed"',
      "",
      "[routes.managed]",
      'kind = "managed"',
      'account_pool = "default"',
      'upstream = { kind = "fixed", upstream = "local" }',
      'model = { kind = "qualified", namespace = "provider" }',
      'operation = "translate_compatible"',
      "",
      "[account_pools.default]",
      'active_accounts = ["*"]',
      'providers = ["llama-cpp"]',
      "",
      "[upstreams.local]",
      'provider = "llama-cpp"',
      `base_url = "http://127.0.0.1:${address.port}"`,
      'accounts = ["local-llama"]',
      "",
    ].join("\n"),
  );
  await writeFile(
    authPath,
    [
      "version: 1",
      "accounts:",
      "  - id: local-llama",
      "    provider: llama-cpp",
      "",
    ].join("\n"),
  );

  let client: Client | undefined;
  try {
    client = await Client.create({
      config_path: configPath,
      auth_path: authPath,
      profile: "native",
    });
    assert.equal(client.profile, "native");
    const response = await client
      .generate("llama-cpp/mock-model")
      .prompt("Exercise the native TypeScript binding.")
      .maxTokens(64)
      .send();

    assert.equal(response.text, "native answer");
    assert.equal(response.finish_reason, "stop");
    assert.equal(response.usage?.total_tokens, 3);
    assert.equal(requests.length, 1);
    assert.equal(requests[0]?.path, "/chat/completions");
    assert.equal(requests[0]?.body["model"], "mock-model");
    assert.equal(requests[0]?.body["max_tokens"], 64);
    assert.equal(requests[0]?.body["stream"] ?? false, false);

    const stream = await client.textStream({
      model: "llama-cpp/mock-model",
      prompt: "Exercise the native pull stream.",
    });
    let streamedText = "";
    for await (const text of stream) {
      streamedText += text;
    }
    assert.equal(streamedText, "native stream");
    assert.equal(requests.length, 2);
    assert.equal(requests[1]?.path, "/chat/completions");
    assert.equal(requests[1]?.body["stream"], true);

    const controller = new AbortController();
    const idleStream = await client.textStream(
      {
        model: "llama-cpp/mock-model",
        prompt: "Exercise idle cancellation.",
      },
      { signal: controller.signal },
    );
    const pendingRead = idleStream.next();
    controller.abort();
    let timeout: NodeJS.Timeout | undefined;
    try {
      await assert.rejects(
        Promise.race([
          pendingRead,
          new Promise<never>((_, reject) => {
            timeout = setTimeout(() => reject(new Error("native stream cancellation timed out")), 5_000);
          }),
        ]),
        (error: unknown) => error instanceof CancelledError,
      );
    } finally {
      clearTimeout(timeout);
      await idleStream.close();
    }
    assert.equal(requests.length, 3);
    assert.equal(requests[2]?.body["stream"], true);
  } finally {
    await client?.close();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error === undefined) {
          resolve();
        } else {
          reject(error);
        }
      });
    });
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

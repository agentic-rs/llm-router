import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Client, ConfigurationError, request } from "../dist/index.js";

test("the compiled package entrypoint exposes the public API and native loader", async () => {
  if (process.env.TOKN_NATIVE_SMOKE !== "1") {
    return;
  }

  assert.deepEqual(request("smart").prompt("Hello").maxTokens(32).build(), {
    model: "smart",
    messages: [{ role: "user", content: "Hello" }],
    max_output_tokens: 32,
  });

  const missingRoot = join(tmpdir(), `tokn-typescript-dist-${randomUUID()}`);
  await assert.rejects(
    Client.create({
      config_path: join(missingRoot, "config.toml"),
      auth_path: join(missingRoot, "auth.yaml"),
    }),
    (error) => error instanceof ConfigurationError && error.code === "configuration_error",
  );
});

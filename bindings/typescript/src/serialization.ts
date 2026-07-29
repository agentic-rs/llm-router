import { SerializationError } from "./errors.js";
import type { JsonObject, JsonValue } from "./types.js";

function assertJson(value: unknown, path: string, seen: Set<object>): asserts value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new SerializationError(`${path} must contain only finite numbers`);
    }
    return;
  }
  if (typeof value !== "object") {
    throw new SerializationError(`${path} contains a value that JSON cannot represent`);
  }
  if (seen.has(value)) {
    throw new SerializationError(`${path} contains a circular reference`);
  }

  seen.add(value);
  try {
    if (Array.isArray(value)) {
      value.forEach((item, index) => assertJson(item, `${path}[${index}]`, seen));
      return;
    }

    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new SerializationError(`${path} must contain only plain objects and arrays`);
    }
    for (const [key, item] of Object.entries(value)) {
      assertJson(item, `${path}.${key}`, seen);
    }
  } finally {
    seen.delete(value);
  }
}

export function serializeJson(value: unknown, label: string): string {
  assertJson(value, label, new Set());
  try {
    return JSON.stringify(value);
  } catch (cause) {
    throw new SerializationError(`failed to serialize ${label}`, { cause });
  }
}

export function parseJson(value: string, label: string): JsonValue {
  try {
    return JSON.parse(value) as JsonValue;
  } catch (cause) {
    throw new SerializationError(`native SDK returned invalid JSON for ${label}`, { cause });
  }
}

export function parseJsonObject(value: string, label: string): JsonObject {
  const parsed = parseJson(value, label);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new SerializationError(`native SDK returned a non-object value for ${label}`);
  }
  return parsed as JsonObject;
}

import { SerializationError } from "./errors.js";
import { parseJsonObject } from "./serialization.js";
import type {
  GenerateEvent,
  GenerateResponse,
  HeaderValue,
  JsonObject,
  JsonValue,
  RequestEvent,
  ToolCall,
  Usage,
} from "./types.js";

function invalid(message: string): never {
  throw new SerializationError(`native SDK returned ${message}`);
}

function isObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNullableString(value: JsonValue | undefined): value is string | null {
  return value === null || typeof value === "string";
}

function isTokenCount(value: JsonValue | undefined): value is number | null {
  return value === null || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);
}

function requireOwn(object: JsonObject, key: string, label: string): JsonValue {
  if (!Object.hasOwn(object, key)) {
    return invalid(`${label} without '${key}'`);
  }
  return object[key] as JsonValue;
}

export function validateNativeHeaders(
  value: JsonObject,
  label: string,
): Readonly<Record<string, HeaderValue>> {
  for (const [name, header] of Object.entries(value)) {
    if (typeof header === "string") {
      continue;
    }
    if (Array.isArray(header) && header.every((item) => typeof item === "string")) {
      continue;
    }
    invalid(`an invalid value for ${label} '${name}'`);
  }
  return value as Readonly<Record<string, HeaderValue>>;
}

export function parseNativeHeaders(value: string, label = "response header"): Readonly<Record<string, HeaderValue>> {
  return validateNativeHeaders(parseJsonObject(value, `${label}s`), label);
}

function validateToolCall(value: JsonValue, label: string): ToolCall {
  if (!isObject(value)) {
    return invalid(`an invalid ${label}`);
  }
  const id = requireOwn(value, "id", label);
  if (!isNullableString(id)) {
    return invalid(`an invalid ${label} id`);
  }
  if (typeof requireOwn(value, "name", label) !== "string") {
    return invalid(`an invalid ${label} name`);
  }
  requireOwn(value, "arguments", label);
  return value as unknown as ToolCall;
}

function validateUsage(value: JsonValue, label: string): Usage {
  if (!isObject(value)) {
    return invalid(`an invalid ${label}`);
  }
  for (const key of ["input_tokens", "output_tokens", "total_tokens"]) {
    if (!isTokenCount(requireOwn(value, key, label))) {
      return invalid(`an invalid ${label} '${key}'`);
    }
  }
  if (value["extras"] !== undefined && !isObject(value["extras"])) {
    return invalid(`an invalid ${label} 'extras'`);
  }
  return value as unknown as Usage;
}

export function parseNativeGenerateResponse(value: string): GenerateResponse {
  const response = parseJsonObject(value, "generation response");
  const httpStatus = requireOwn(response, "http_status", "generation response");
  if (
    typeof httpStatus !== "number" ||
    !Number.isSafeInteger(httpStatus) ||
    httpStatus < 0 ||
    httpStatus > 65_535
  ) {
    return invalid("an invalid generation response HTTP status");
  }

  const headers = requireOwn(response, "headers", "generation response");
  if (!isObject(headers)) {
    return invalid("generation response headers that are not an object");
  }
  validateNativeHeaders(headers, "response header");

  for (const key of ["id", "model", "status", "finish_reason", "reasoning"]) {
    if (!isNullableString(requireOwn(response, key, "generation response"))) {
      return invalid(`an invalid generation response '${key}'`);
    }
  }
  if (typeof requireOwn(response, "text", "generation response") !== "string") {
    return invalid("an invalid generation response 'text'");
  }

  const toolCalls = requireOwn(response, "tool_calls", "generation response");
  if (!Array.isArray(toolCalls)) {
    return invalid("generation response tool calls that are not an array");
  }
  toolCalls.forEach((toolCall, index) => validateToolCall(toolCall, `tool call at index ${index}`));

  const usage = requireOwn(response, "usage", "generation response");
  if (usage !== null) {
    validateUsage(usage, "generation usage");
  }
  requireOwn(response, "raw", "generation response");
  return response as unknown as GenerateResponse;
}

export function parseNativeGenerateEvent(value: string): GenerateEvent {
  const event = parseJsonObject(value, "generation event");
  const type = requireOwn(event, "type", "generation event");
  switch (type) {
    case "text_delta":
    case "reasoning_delta":
      if (typeof requireOwn(event, "text", `${type} event`) !== "string") {
        return invalid(`an invalid ${type} event text`);
      }
      break;
    case "tool_call_delta": {
      const index = requireOwn(event, "index", "tool_call_delta event");
      if (typeof index !== "number" || !Number.isSafeInteger(index) || index < 0) {
        return invalid("an invalid tool_call_delta event index");
      }
      for (const key of ["id", "name"]) {
        if (!isNullableString(requireOwn(event, key, "tool_call_delta event"))) {
          return invalid(`an invalid tool_call_delta event '${key}'`);
        }
      }
      if (typeof requireOwn(event, "arguments_delta", "tool_call_delta event") !== "string") {
        return invalid("an invalid tool_call_delta event arguments_delta");
      }
      break;
    }
    case "usage":
      validateUsage(requireOwn(event, "usage", "usage event"), "stream usage");
      break;
    case "completed":
      if (!isNullableString(requireOwn(event, "finish_reason", "completed event"))) {
        return invalid("an invalid completed event finish_reason");
      }
      break;
    case "other":
      if (typeof requireOwn(event, "kind", "other event") !== "string") {
        return invalid("an invalid other event kind");
      }
      requireOwn(event, "data", "other event");
      break;
    default:
      return invalid("an unsupported generation event");
  }
  return event as unknown as GenerateEvent;
}

export function parseNativeRequestEvent(value: string): RequestEvent {
  const event = parseJsonObject(value, "request lifecycle event");
  if (typeof requireOwn(event, "request_id", "request lifecycle event") !== "string") {
    return invalid("a request lifecycle event without a string request_id");
  }
  for (const key of ["attempt", "ts"]) {
    const field = requireOwn(event, key, "request lifecycle event");
    if (typeof field !== "number" || !Number.isSafeInteger(field)) {
      return invalid(`a request lifecycle event without an integer ${key}`);
    }
  }
  if (!isObject(requireOwn(event, "payload", "request lifecycle event"))) {
    return invalid("a request lifecycle event without an object payload");
  }
  return event as unknown as RequestEvent;
}

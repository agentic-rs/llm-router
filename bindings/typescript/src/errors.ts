export type ToknErrorCode =
  | "configuration_error"
  | "authentication_error"
  | "request_error"
  | "api_status_error"
  | "stream_error"
  | "serialization_error"
  | "cancelled"
  | "client_closed"
  | "internal_error";

export interface ToknErrorOptions extends ErrorOptions {
  readonly status?: number;
  readonly body?: string;
}

export class ToknError extends Error {
  readonly code: ToknErrorCode;
  readonly status: number | undefined;
  readonly body: string | undefined;

  constructor(code: ToknErrorCode, message: string, options: ToknErrorOptions = {}) {
    super(message, options);
    this.name = "ToknError";
    this.code = code;
    this.status = options.status;
    this.body = options.body;
  }
}

export class ConfigurationError extends ToknError {
  constructor(message: string, options: ToknErrorOptions = {}) {
    super("configuration_error", message, options);
    this.name = "ConfigurationError";
  }
}

export class AuthenticationError extends ToknError {
  constructor(message: string, options: ToknErrorOptions = {}) {
    super("authentication_error", message, options);
    this.name = "AuthenticationError";
  }
}

export class RequestError extends ToknError {
  constructor(message: string, options: ToknErrorOptions = {}) {
    super("request_error", message, options);
    this.name = "RequestError";
  }
}

export class APIStatusError extends ToknError {
  constructor(message: string, options: ToknErrorOptions = {}) {
    super("api_status_error", message, options);
    this.name = "APIStatusError";
  }
}

export class StreamError extends ToknError {
  constructor(message: string, options: ToknErrorOptions = {}) {
    super("stream_error", message, options);
    this.name = "StreamError";
  }
}

export class SerializationError extends ToknError {
  constructor(message: string, options: ToknErrorOptions = {}) {
    super("serialization_error", message, options);
    this.name = "SerializationError";
  }
}

export class CancelledError extends ToknError {
  constructor(message = "operation was cancelled", options: ToknErrorOptions = {}) {
    super("cancelled", message, options);
    this.name = "CancelledError";
  }
}

export class ClientClosedError extends ToknError {
  constructor(message = "client is closed", options: ToknErrorOptions = {}) {
    super("client_closed", message, options);
    this.name = "ClientClosedError";
  }
}

export class InternalError extends ToknError {
  constructor(message: string, options: ToknErrorOptions = {}) {
    super("internal_error", message, options);
    this.name = "InternalError";
  }
}

interface NativeErrorPayload {
  readonly code: ToknErrorCode;
  readonly message: string;
  readonly status?: number;
  readonly body?: string;
}

const NATIVE_ERROR_PREFIX = "TOKN_ERROR:";
const ERROR_CODES = new Set<ToknErrorCode>([
  "configuration_error",
  "authentication_error",
  "request_error",
  "api_status_error",
  "stream_error",
  "serialization_error",
  "cancelled",
  "client_closed",
  "internal_error",
]);

function isNativeErrorPayload(value: unknown): value is NativeErrorPayload {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const payload = value as Record<string, unknown>;
  return (
    typeof payload["code"] === "string" &&
    ERROR_CODES.has(payload["code"] as ToknErrorCode) &&
    typeof payload["message"] === "string" &&
    (payload["status"] === undefined || typeof payload["status"] === "number") &&
    (payload["body"] === undefined || typeof payload["body"] === "string")
  );
}

function payloadFromNativeError(error: unknown): NativeErrorPayload | undefined {
  if (isNativeErrorPayload(error)) {
    return error;
  }
  if (!(error instanceof Error)) {
    return undefined;
  }

  const prefixIndex = error.message.indexOf(NATIVE_ERROR_PREFIX);
  if (prefixIndex === -1) {
    return undefined;
  }
  try {
    const payload: unknown = JSON.parse(error.message.slice(prefixIndex + NATIVE_ERROR_PREFIX.length));
    return isNativeErrorPayload(payload) ? payload : undefined;
  } catch {
    return undefined;
  }
}

export function fromNativeError(error: unknown): ToknError {
  if (error instanceof ToknError) {
    return error;
  }

  const payload = payloadFromNativeError(error);
  if (payload === undefined) {
    const message = error instanceof Error ? error.message : "native SDK operation failed";
    return new InternalError(message, { cause: error });
  }

  const options: ToknErrorOptions = {
    cause: error,
    ...(payload.status === undefined ? {} : { status: payload.status }),
    ...(payload.body === undefined ? {} : { body: payload.body }),
  };
  switch (payload.code) {
    case "configuration_error":
      return new ConfigurationError(payload.message, options);
    case "authentication_error":
      return new AuthenticationError(payload.message, options);
    case "request_error":
      return new RequestError(payload.message, options);
    case "api_status_error":
      return new APIStatusError(payload.message, options);
    case "stream_error":
      return new StreamError(payload.message, options);
    case "serialization_error":
      return new SerializationError(payload.message, options);
    case "cancelled":
      return new CancelledError(payload.message, options);
    case "client_closed":
      return new ClientClosedError(payload.message, options);
    case "internal_error":
      return new InternalError(payload.message, options);
  }
}

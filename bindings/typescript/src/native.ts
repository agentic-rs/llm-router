import { createRequire } from "node:module";

import { ConfigurationError } from "./errors.js";

export interface NativeCancellation {
  readonly aborted: boolean;
  cancel(): void;
}

export interface NativeCancellationConstructor {
  new (): NativeCancellation;
}

export interface NativeResponse {
  readonly status: number;
  readonly headersJson: string;
  readonly bodyJson: string;
}

export interface NativeByteStream {
  readonly status: number;
  readonly headersJson: string;
  next(): Promise<Uint8Array | null | undefined>;
  close(): Promise<void>;
}

export interface NativeGenerateStream {
  next(): Promise<string | null | undefined>;
  close(): Promise<void>;
}

export interface NativeTextStream {
  next(): Promise<string | null | undefined>;
  close(): Promise<void>;
}

export interface NativeRequestEventStream {
  next(): Promise<string | null | undefined>;
  close(): Promise<void>;
}

export interface NativeClient {
  readonly configPath: string;
  readonly authPath: string;
  subscribeEvents(): NativeRequestEventStream;
  reload(cancellation: NativeCancellation): Promise<void>;
  close(): Promise<void>;
  request(
    endpoint: string,
    bodyJson: string,
    optionsJson: string | null,
    cancellation: NativeCancellation,
  ): Promise<NativeResponse>;
  stream(
    endpoint: string,
    bodyJson: string,
    optionsJson: string | null,
    cancellation: NativeCancellation,
  ): Promise<NativeByteStream>;
  sendGenerate(requestJson: string, cancellation: NativeCancellation): Promise<string>;
  generateStream(requestJson: string, cancellation: NativeCancellation): Promise<NativeGenerateStream>;
  textStream(requestJson: string, cancellation: NativeCancellation): Promise<NativeTextStream>;
}

export interface NativeBinding {
  readonly NativeCancellation: NativeCancellationConstructor;
  nativeAbiVersion(): number;
  createClient(optionsJson: string): Promise<NativeClient>;
}

let bindingOverride: NativeBinding | undefined;
let loadedBinding: NativeBinding | undefined;

function isNativeBinding(value: unknown): value is NativeBinding {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const binding = value as Partial<NativeBinding>;
  return (
    typeof binding.NativeCancellation === "function" &&
    typeof binding.nativeAbiVersion === "function" &&
    typeof binding.createClient === "function"
  );
}

function validateNativeBinding(value: unknown): NativeBinding {
  if (!isNativeBinding(value)) {
    throw new ConfigurationError("the native @tokn/sdk binding does not expose the expected API");
  }

  let abiVersion: number;
  try {
    abiVersion = value.nativeAbiVersion();
  } catch (cause) {
    throw new ConfigurationError("failed to read the native @tokn/sdk binding ABI version", { cause });
  }
  if (abiVersion !== 1) {
    throw new ConfigurationError("the native @tokn/sdk binding uses an unsupported ABI version");
  }
  return value;
}

export function getNativeBinding(): NativeBinding {
  if (bindingOverride !== undefined) {
    return validateNativeBinding(bindingOverride);
  }
  if (loadedBinding !== undefined) {
    return loadedBinding;
  }

  const require = createRequire(import.meta.url);
  let candidate: unknown;
  try {
    candidate = require("../_native.cjs");
  } catch (cause) {
    throw new ConfigurationError("failed to load the native @tokn/sdk binding", { cause });
  }
  loadedBinding = validateNativeBinding(candidate);
  return loadedBinding;
}

export function setNativeBindingForTests(binding: NativeBinding | undefined): void {
  bindingOverride = binding;
}

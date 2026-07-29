import { createRequire } from "node:module";

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

export interface NativeClient {
  readonly configPath: string;
  readonly authPath: string;
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

export function getNativeBinding(): NativeBinding {
  if (bindingOverride !== undefined) {
    return bindingOverride;
  }
  if (loadedBinding !== undefined) {
    return loadedBinding;
  }

  const require = createRequire(import.meta.url);
  const candidate: unknown = require("../_native.cjs");
  if (!isNativeBinding(candidate)) {
    throw new TypeError("the native @tokn/sdk binding does not expose the expected API");
  }
  if (candidate.nativeAbiVersion() !== 1) {
    throw new TypeError("the native @tokn/sdk binding uses an unsupported ABI version");
  }
  loadedBinding = candidate;
  return candidate;
}

export function setNativeBindingForTests(binding: NativeBinding | undefined): void {
  bindingOverride = binding;
}

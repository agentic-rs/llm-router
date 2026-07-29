import { CancelledError, fromNativeError } from "./errors.js";
import type {
  NativeBinding,
  NativeByteStream,
  NativeCancellation,
  NativeGenerateStream,
  NativeTextStream,
} from "./native.js";
import { parseNativeGenerateEvent, parseNativeHeaders } from "./native-values.js";
import type { GenerateEvent, HeaderValue } from "./types.js";

export class CancellationScope {
  readonly native: NativeCancellation;
  readonly signal: AbortSignal | undefined;
  readonly onAbort: () => void;
  private listening = false;
  private streamAbortHandler: (() => void) | undefined;

  constructor(binding: NativeBinding, signal?: AbortSignal) {
    this.native = new binding.NativeCancellation();
    this.signal = signal;
    this.onAbort = () => {
      this.native.cancel();
      this.streamAbortHandler?.();
    };

    if (signal?.aborted === true) {
      this.native.cancel();
      throw new CancelledError();
    }
    if (signal !== undefined) {
      signal.addEventListener("abort", this.onAbort, { once: true });
      this.listening = true;
    }
  }

  cancel(): void {
    this.native.cancel();
  }

  setStreamAbortHandler(handler: () => void): void {
    this.streamAbortHandler = handler;
  }

  dispose(): void {
    if (this.listening) {
      this.signal?.removeEventListener("abort", this.onAbort);
      this.listening = false;
    }
    this.streamAbortHandler = undefined;
  }
}

export async function runCancellable<T>(
  binding: NativeBinding,
  signal: AbortSignal | undefined,
  operation: (cancellation: NativeCancellation) => Promise<T>,
): Promise<T> {
  const scope = new CancellationScope(binding, signal);
  try {
    return await operation(scope.native);
  } catch (error) {
    throw fromNativeError(error);
  } finally {
    scope.dispose();
  }
}

interface NativePullStream<T> {
  next(): Promise<T | null | undefined>;
  close(): Promise<void>;
}

abstract class PullStream<NativeValue, PublicValue>
  implements AsyncIterableIterator<PublicValue>, AsyncDisposable
{
  private readonly native: NativePullStream<NativeValue>;
  private readonly cancellation: CancellationScope;
  private readonly onFinish: (() => void) | undefined;
  private closed = false;
  private abortPending = false;
  private finished = false;
  private closePromise: Promise<void> | undefined;
  private nextTail: Promise<void> = Promise.resolve();

  protected constructor(
    native: NativePullStream<NativeValue>,
    cancellation: CancellationScope,
    onFinish?: () => void,
  ) {
    this.native = native;
    this.cancellation = cancellation;
    this.onFinish = onFinish;
    this.cancellation.setStreamAbortHandler(() => {
      this.abortPending = true;
      this.finish();
    });
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<PublicValue> {
    return this;
  }

  next(): Promise<IteratorResult<PublicValue>> {
    const result = this.nextTail.then(() => this.readNext());
    this.nextTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async return(): Promise<IteratorResult<PublicValue>> {
    await this.close();
    return { done: true, value: undefined };
  }

  async throw(error?: unknown): Promise<IteratorResult<PublicValue>> {
    await this.close();
    throw error;
  }

  close(): Promise<void> {
    if (this.closePromise !== undefined) {
      return this.closePromise;
    }

    this.closed = true;
    this.cancellation.dispose();
    this.notifyFinished();
    this.closePromise = Promise.resolve()
      .then(() => this.native.close())
      .catch((error: unknown) => {
        throw fromNativeError(error);
      });
    return this.closePromise;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  protected abstract convert(value: NativeValue): PublicValue;

  private async readNext(): Promise<IteratorResult<PublicValue>> {
    if (this.closed) {
      if (this.abortPending) {
        this.abortPending = false;
        throw new CancelledError();
      }
      return { done: true, value: undefined };
    }

    try {
      const value = await this.native.next();
      if (value === null || value === undefined) {
        this.finish();
        return { done: true, value: undefined };
      }
      return { done: false, value: this.convert(value) };
    } catch (error) {
      this.abortPending = false;
      this.finish();
      void Promise.resolve()
        .then(() => this.native.close())
        .catch(() => undefined);
      throw fromNativeError(error);
    }
  }

  private finish(): void {
    this.closed = true;
    this.cancellation.dispose();
    this.notifyFinished();
  }

  private notifyFinished(): void {
    if (this.finished) {
      return;
    }
    this.finished = true;
    this.onFinish?.();
  }
}

export class ByteStreamImpl extends PullStream<Uint8Array, Uint8Array> {
  readonly status: number;
  readonly headers: Readonly<Record<string, HeaderValue>>;

  constructor(native: NativeByteStream, cancellation: CancellationScope, onFinish?: () => void) {
    super(native, cancellation, onFinish);
    this.status = native.status;
    this.headers = parseNativeHeaders(native.headersJson);
  }

  protected convert(value: Uint8Array): Uint8Array {
    return value;
  }
}

export class GenerateStreamImpl extends PullStream<string, GenerateEvent> {
  constructor(native: NativeGenerateStream, cancellation: CancellationScope, onFinish?: () => void) {
    super(native, cancellation, onFinish);
  }

  protected convert(value: string): GenerateEvent {
    return parseNativeGenerateEvent(value);
  }
}

export class TextStreamImpl extends PullStream<string, string> {
  constructor(native: NativeTextStream, cancellation: CancellationScope, onFinish?: () => void) {
    super(native, cancellation, onFinish);
  }

  protected convert(value: string): string {
    return value;
  }
}

import { ClientClosedError, RequestError, fromNativeError } from "./errors.js";
import { getNativeBinding } from "./native.js";
import type {
  NativeBinding,
  NativeByteStream,
  NativeClient,
  NativeGenerateStream,
  NativeResponse,
  NativeTextStream,
} from "./native.js";
import {
  REQUEST_OPTION_NAMES,
  RequestBuilder,
  createRequest,
  normalizeRequestOptions,
} from "./request.js";
import { parseNativeGenerateResponse, parseNativeHeaders } from "./native-values.js";
import { parseJson, serializeJson } from "./serialization.js";
import {
  ByteStreamImpl,
  CancellationScope,
  GenerateStreamImpl,
  TextStreamImpl,
  runCancellable,
} from "./streams.js";
import type {
  ByteStream,
  ClientOptions,
  Endpoint,
  GenerateInput,
  GenerateResponse,
  GenerateStream,
  JsonValue,
  OperationOptions,
  RawRequestOptions,
  RequestOptions,
  Response,
  TextStream,
} from "./types.js";

function validateEndpoint(endpoint: Endpoint): Endpoint {
  if (endpoint !== "responses" && endpoint !== "chat_completions" && endpoint !== "messages") {
    throw new RequestError(`unknown endpoint '${String(endpoint)}'`);
  }
  return endpoint;
}

function clientOptionsJson(options: ClientOptions): string {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw new RequestError("client options must be an object");
  }
  const unknownOption = Object.keys(options).find(
    (name) => name !== "config_path" && name !== "auth_path" && name !== "profile",
  );
  if (unknownOption !== undefined) {
    throw new RequestError(`unknown client option '${unknownOption}'`);
  }
  for (const [name, value] of [
    ["config_path", options.config_path],
    ["auth_path", options.auth_path],
    ["profile", options.profile],
  ] as const) {
    if (value !== undefined && (typeof value !== "string" || value.trim() === "")) {
      throw new RequestError(`${name} must be a non-empty string`);
    }
  }
  return serializeJson(
    {
      ...(options.config_path === undefined ? {} : { config_path: options.config_path }),
      ...(options.auth_path === undefined ? {} : { auth_path: options.auth_path }),
      ...(options.profile === undefined ? {} : { profile: options.profile }),
    },
    "client options",
  );
}

function splitRawOptions(options: RawRequestOptions): {
  readonly signal?: AbortSignal;
  readonly requestOptions?: RequestOptions;
} {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw new RequestError("request options must be an object");
  }
  const unknownOption = Object.keys(options).find(
    (name) => name !== "signal" && !REQUEST_OPTION_NAMES.has(name),
  );
  if (unknownOption !== undefined) {
    throw new RequestError(`unknown request option '${unknownOption}'`);
  }
  const requestOptions = normalizeRequestOptions({
    ...(options.request_id === undefined ? {} : { request_id: options.request_id }),
    ...(options.session_id === undefined ? {} : { session_id: options.session_id }),
    ...(options.project_id === undefined ? {} : { project_id: options.project_id }),
    ...(options.initiator === undefined ? {} : { initiator: options.initiator }),
    ...(options.headers === undefined ? {} : { headers: options.headers }),
  });
  return {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(requestOptions === undefined ? {} : { requestOptions }),
  };
}

function responseFromNative<T>(native: NativeResponse): Response<T> {
  return {
    status: native.status,
    headers: parseNativeHeaders(native.headersJson),
    data: parseJson(native.bodyJson, "response body") as T,
  };
}

function generateResponseFromJson(value: string): GenerateResponse {
  return parseNativeGenerateResponse(value);
}

function optionsJson(options: RequestOptions | undefined): string | null {
  return options === undefined ? null : serializeJson(options, "request options");
}

function rawBodyJson(body: object): string {
  if (body === null || Array.isArray(body)) {
    throw new RequestError("request body must be a JSON object");
  }
  return serializeJson(body, "request body");
}

export class EndpointClient {
  private readonly client: Client;
  private readonly endpoint: Endpoint;

  constructor(client: Client, endpoint: Endpoint) {
    this.client = client;
    this.endpoint = endpoint;
  }

  create<T = JsonValue>(body: object, options: RawRequestOptions = {}): Promise<Response<T>> {
    return this.client.request<T>(this.endpoint, body, options);
  }

  stream(body: object, options: RawRequestOptions = {}): Promise<ByteStream> {
    return this.client.stream(this.endpoint, body, options);
  }
}

export class ChatClient {
  readonly completions: EndpointClient;

  constructor(client: Client) {
    this.completions = new EndpointClient(client, "chat_completions");
  }
}

export class GenerateCall extends RequestBuilder {
  private readonly client: Client;

  constructor(client: Client, model: string) {
    super(model);
    this.client = client;
  }

  send(options: OperationOptions = {}): Promise<GenerateResponse> {
    return this.client.send(this.build(), options);
  }

  stream(options: OperationOptions = {}): Promise<GenerateStream> {
    return this.client.generateStream(this.build(), options);
  }

  textStream(options: OperationOptions = {}): Promise<TextStream> {
    return this.client.textStream(this.build(), options);
  }
}

export class Client implements AsyncDisposable {
  readonly responses: EndpointClient;
  readonly chat: ChatClient;
  readonly messages: EndpointClient;

  private readonly binding: NativeBinding;
  private readonly native: NativeClient;
  private readonly activeStreams = new Set<ByteStream | GenerateStream | TextStream>();
  private closed = false;
  private closePromise: Promise<void> | undefined;

  private constructor(binding: NativeBinding, native: NativeClient) {
    this.binding = binding;
    this.native = native;
    this.responses = new EndpointClient(this, "responses");
    this.chat = new ChatClient(this);
    this.messages = new EndpointClient(this, "messages");
  }

  static async create(options: ClientOptions = {}): Promise<Client> {
    try {
      const binding = getNativeBinding();
      const native = await binding.createClient(clientOptionsJson(options));
      return new Client(binding, native);
    } catch (error) {
      throw fromNativeError(error);
    }
  }

  get configPath(): string {
    return this.native.configPath;
  }

  get authPath(): string {
    return this.native.authPath;
  }

  get profile(): string {
    return this.native.profile;
  }

  get isClosed(): boolean {
    return this.closed;
  }

  async reload(): Promise<void> {
    this.ensureOpen();
    await runCancellable(this.binding, undefined, (cancellation) => this.native.reload(cancellation));
  }

  generate(model: string): GenerateCall;
  generate(request: GenerateInput, options?: OperationOptions): Promise<GenerateResponse>;
  generate(
    requestOrModel: string | GenerateInput,
    options: OperationOptions = {},
  ): GenerateCall | Promise<GenerateResponse> {
    if (typeof requestOrModel === "string") {
      this.ensureOpen();
      return new GenerateCall(this, requestOrModel);
    }
    return this.send(requestOrModel, options);
  }

  async send(request: GenerateInput, options: OperationOptions = {}): Promise<GenerateResponse> {
    this.ensureOpen();
    const requestJson = serializeJson(createRequest(request), "generation request");
    const responseJson = await runCancellable(this.binding, options.signal, (cancellation) =>
      this.native.sendGenerate(requestJson, cancellation),
    );
    return generateResponseFromJson(responseJson);
  }

  async generateStream(request: GenerateInput, options: OperationOptions = {}): Promise<GenerateStream> {
    this.ensureOpen();
    const requestJson = serializeJson(createRequest(request), "generation request");
    const { native, cancellation } = await this.startStream(options.signal, (token) =>
      this.native.generateStream(requestJson, token),
    );
    let stream: GenerateStreamImpl;
    stream = new GenerateStreamImpl(native, cancellation, () => {
      this.activeStreams.delete(stream);
    });
    return await this.registerStream(stream);
  }

  async textStream(request: GenerateInput, options: OperationOptions = {}): Promise<TextStream> {
    this.ensureOpen();
    const requestJson = serializeJson(createRequest(request), "generation request");
    const { native, cancellation } = await this.startStream(options.signal, (token) =>
      this.native.textStream(requestJson, token),
    );
    let stream: TextStreamImpl;
    stream = new TextStreamImpl(native, cancellation, () => {
      this.activeStreams.delete(stream);
    });
    return await this.registerStream(stream);
  }

  async request<T = JsonValue>(
    endpoint: Endpoint,
    body: object,
    options: RawRequestOptions = {},
  ): Promise<Response<T>> {
    this.ensureOpen();
    const rawOptions = splitRawOptions(options);
    const native = await runCancellable(this.binding, rawOptions.signal, (cancellation) =>
      this.native.request(
        validateEndpoint(endpoint),
        rawBodyJson(body),
        optionsJson(rawOptions.requestOptions),
        cancellation,
      ),
    );
    return responseFromNative<T>(native);
  }

  async stream(endpoint: Endpoint, body: object, options: RawRequestOptions = {}): Promise<ByteStream> {
    this.ensureOpen();
    const rawOptions = splitRawOptions(options);
    const bodyJson = rawBodyJson(body);
    const { native, cancellation } = await this.startStream(rawOptions.signal, (token) =>
      this.native.stream(
        validateEndpoint(endpoint),
        bodyJson,
        optionsJson(rawOptions.requestOptions),
        token,
      ),
    );
    let stream: ByteStreamImpl;
    stream = new ByteStreamImpl(native, cancellation, () => {
      this.activeStreams.delete(stream);
    });
    return await this.registerStream(stream);
  }

  close(): Promise<void> {
    if (this.closePromise !== undefined) {
      return this.closePromise;
    }
    this.closed = true;
    const streamCloses = [...this.activeStreams].map((stream) => stream.close());
    const nativeClose = Promise.resolve().then(() => this.native.close());
    this.closePromise = Promise.all([nativeClose, ...streamCloses])
      .then(() => undefined)
      .catch((error: unknown) => {
        throw fromNativeError(error);
      });
    return this.closePromise;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  private ensureOpen(): void {
    if (this.closed) {
      throw new ClientClosedError();
    }
  }

  private async registerStream<T extends ByteStream | GenerateStream | TextStream>(stream: T): Promise<T> {
    if (this.closed) {
      await stream.close();
      throw new ClientClosedError();
    }
    this.activeStreams.add(stream);
    return stream;
  }

  private async startStream<T extends NativeByteStream | NativeGenerateStream | NativeTextStream>(
    signal: AbortSignal | undefined,
    start: (cancellation: CancellationScope["native"]) => Promise<T>,
  ): Promise<{ readonly native: T; readonly cancellation: CancellationScope }> {
    const cancellation = new CancellationScope(this.binding, signal);
    try {
      const native = await start(cancellation.native);
      return { native, cancellation };
    } catch (error) {
      cancellation.cancel();
      cancellation.dispose();
      throw fromNativeError(error);
    }
  }
}

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

export type Endpoint = "responses" | "chat_completions" | "messages";
export type Role = "system" | "user" | "assistant" | "tool";
export type ReasoningMode = "enabled" | "disabled" | "adaptive";
export type ReasoningEffort = "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | (string & {});
export type ReasoningSummary = "auto" | "concise" | "detailed" | (string & {});
export type HeaderValue = string | readonly string[];

export interface ClientOptions {
  readonly config_path?: string;
  readonly auth_path?: string;
  readonly profile?: string;
}

export interface RequestOptions {
  readonly profile?: string;
  readonly request_id?: string;
  readonly session_id?: string;
  readonly project_id?: string;
  readonly initiator?: string;
  readonly headers?: readonly (readonly [name: string, value: string])[];
}

export interface OperationOptions {
  readonly signal?: AbortSignal;
}

export interface RawRequestOptions extends RequestOptions, OperationOptions {}

export interface ReasoningOptions {
  readonly mode?: ReasoningMode;
  readonly effort?: ReasoningEffort;
  readonly budget_tokens?: number;
  readonly summary?: ReasoningSummary;
}

export type ToolChoice = "auto" | "none" | "required" | { readonly tool: string };

export interface Tool {
  readonly name: string;
  readonly parameters?: JsonObject;
  readonly description?: string;
  readonly strict?: boolean;
}

export interface ToolCall {
  readonly id?: string | null;
  readonly name: string;
  readonly arguments: JsonValue;
}

export interface Message {
  readonly role: Role;
  readonly content: string;
  readonly tool_call_id?: string;
  readonly tool_calls?: readonly ToolCall[];
}

export interface GenerateRequest {
  readonly model: string;
  readonly messages: readonly Message[];
  readonly tools?: readonly Tool[];
  readonly tool_choice?: ToolChoice;
  readonly temperature?: number;
  readonly top_p?: number;
  readonly top_k?: number;
  readonly max_output_tokens?: number;
  readonly reasoning?: ReasoningOptions;
  readonly options?: RequestOptions;
  readonly extras?: JsonObject;
}

interface GenerateInputFields extends Omit<GenerateRequest, "messages"> {
  readonly system?: string;
}

export type GenerateInput =
  | (GenerateInputFields & {
      readonly prompt: string;
      readonly messages?: readonly Message[];
    })
  | (GenerateInputFields & {
      readonly prompt?: undefined;
      readonly messages: readonly Message[];
    });

export interface Usage {
  readonly input_tokens: number | null;
  readonly output_tokens: number | null;
  readonly total_tokens: number | null;
  readonly input_tokens_details?: JsonValue;
  readonly output_tokens_details?: JsonValue;
  readonly extras?: JsonObject;
}

export interface GenerateResponse {
  readonly http_status: number;
  readonly headers: Readonly<Record<string, HeaderValue>>;
  readonly id: string | null;
  readonly model: string | null;
  readonly status: string | null;
  readonly finish_reason: string | null;
  readonly text: string;
  readonly reasoning: string | null;
  readonly tool_calls: readonly ToolCall[];
  readonly usage: Usage | null;
  readonly raw: JsonValue;
}

export type GenerateEvent =
  | {
      readonly type: "text_delta";
      readonly text: string;
    }
  | {
      readonly type: "reasoning_delta";
      readonly text: string;
    }
  | {
      readonly type: "tool_call_delta";
      readonly index: number;
      readonly id: string | null;
      readonly name: string | null;
      readonly arguments_delta: string;
    }
  | {
      readonly type: "usage";
      readonly usage: Usage;
    }
  | {
      readonly type: "completed";
      readonly finish_reason: string | null;
    }
  | {
      readonly type: "other";
      readonly kind: string;
      readonly data: JsonValue;
    };

export interface Response<T = JsonValue> {
  readonly status: number;
  readonly headers: Readonly<Record<string, HeaderValue>>;
  readonly data: T;
}

export interface AsyncStream<T> extends AsyncIterableIterator<T>, AsyncDisposable {
  close(): Promise<void>;
}

export interface ByteStream extends AsyncStream<Uint8Array> {
  readonly status: number;
  readonly headers: Readonly<Record<string, HeaderValue>>;
}

export interface GenerateStream extends AsyncStream<GenerateEvent> {}

export interface TextStream extends AsyncStream<string> {}

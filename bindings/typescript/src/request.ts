import { RequestError } from "./errors.js";
import { parseJson, serializeJson } from "./serialization.js";
import type {
  GenerateInput,
  GenerateRequest,
  JsonObject,
  JsonValue,
  Message,
  ReasoningEffort,
  ReasoningMode,
  ReasoningOptions,
  ReasoningSummary,
  RequestOptions,
  Tool,
  ToolCall,
  ToolChoice,
} from "./types.js";

const ROLES = new Set(["system", "user", "assistant", "tool"]);
const REASONING_MODES = new Set(["enabled", "disabled", "adaptive"]);
const REASONING_EXTRAS = new Set(["reasoning", "thinking", "reasoning_effort", "output_config"]);

function fail(message: string): never {
  throw new RequestError(message);
}

function requireString(value: unknown, name: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.trim() === "")) {
    fail(`${name} must be ${allowEmpty ? "a string" : "a non-empty string"}`);
  }
  return value;
}

function optionalString(value: unknown, name: string): string | undefined {
  return value === undefined ? undefined : requireString(value, name);
}

function safeInteger(value: unknown, name: string, minimum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    fail(`${name} must be a safe integer greater than or equal to ${minimum}`);
  }
  return value as number;
}

function cloneJson<T>(value: T, name: string): T {
  return parseJson(serializeJson(value, name), name) as T;
}

function normalizeToolCall(value: ToolCall, name: string): ToolCall {
  if (typeof value !== "object" || value === null) {
    fail(`${name} must be an object`);
  }
  const id = value.id;
  if (id !== undefined && id !== null) {
    requireString(id, `${name}.id`);
  }
  return {
    ...(id === undefined ? {} : { id }),
    name: requireString(value.name, `${name}.name`),
    arguments: cloneJson(value.arguments, `${name}.arguments`),
  };
}

function normalizeMessage(value: Message, index: number): Message {
  if (typeof value !== "object" || value === null) {
    fail(`messages[${index}] must be an object`);
  }
  if (typeof value.role !== "string" || !ROLES.has(value.role)) {
    fail(`messages[${index}].role is not supported`);
  }
  const content = requireString(value.content, `messages[${index}].content`, true);
  const toolCallId = optionalString(value.tool_call_id, `messages[${index}].tool_call_id`);
  const rawToolCalls = value.tool_calls ?? [];
  if (!Array.isArray(rawToolCalls)) {
    fail(`messages[${index}].tool_calls must be an array`);
  }
  const toolCalls = rawToolCalls.map((call, callIndex) =>
    normalizeToolCall(call, `messages[${index}].tool_calls[${callIndex}]`),
  );

  if (value.role !== "assistant" && toolCalls.length !== 0) {
    fail("tool calls are only valid on assistant messages");
  }
  if (value.role === "tool" && toolCallId === undefined) {
    fail("tool results require a non-empty tool_call_id");
  }
  if (value.role !== "tool" && toolCallId !== undefined) {
    fail("tool_call_id is only valid on tool messages");
  }
  if (toolCalls.some((call) => call.id === undefined || call.id === null)) {
    fail("assistant tool calls require non-empty ids and names");
  }

  return {
    role: value.role,
    content,
    ...(toolCallId === undefined ? {} : { tool_call_id: toolCallId }),
    ...(toolCalls.length === 0 ? {} : { tool_calls: toolCalls }),
  };
}

function normalizeTool(value: Tool, index: number): Tool {
  if (typeof value !== "object" || value === null) {
    fail(`tools[${index}] must be an object`);
  }
  if (value.strict !== undefined && typeof value.strict !== "boolean") {
    fail(`tools[${index}].strict must be a boolean`);
  }
  const parameters = value.parameters ?? {};
  if (typeof parameters !== "object" || parameters === null || Array.isArray(parameters)) {
    fail(`tools[${index}].parameters must be a JSON object`);
  }
  return {
    name: requireString(value.name, `tools[${index}].name`),
    parameters: cloneJson(parameters, `tools[${index}].parameters`),
    ...(value.description === undefined
      ? {}
      : { description: requireString(value.description, `tools[${index}].description`, true) }),
    ...(value.strict === undefined ? {} : { strict: value.strict }),
  };
}

function normalizeToolChoice(value: ToolChoice | undefined): ToolChoice | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (value === "auto" || value === "none" || value === "required") {
    return value;
  }
  if (
    typeof value === "object" &&
    value !== null &&
    Object.keys(value).length === 1 &&
    Object.hasOwn(value, "tool")
  ) {
    return { tool: requireString(value.tool, "tool_choice.tool") };
  }
  return fail("tool_choice must be 'auto', 'none', 'required', or { tool: name }");
}

function normalizeReasoning(value: ReasoningOptions | undefined): ReasoningOptions | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("reasoning must be an object");
  }

  const mode = value.mode;
  if (mode !== undefined && (typeof mode !== "string" || !REASONING_MODES.has(mode))) {
    fail(`unknown reasoning mode '${String(mode)}'`);
  }
  const effort = optionalString(value.effort, "reasoning.effort");
  const summary = optionalString(value.summary, "reasoning.summary");
  const budgetTokens =
    value.budget_tokens === undefined
      ? undefined
      : safeInteger(value.budget_tokens, "reasoning.budget_tokens", 1);
  if (mode === undefined && effort === undefined && summary === undefined && budgetTokens === undefined) {
    fail("reasoning options cannot be empty");
  }
  if (mode === "disabled" && (effort !== undefined || summary !== undefined || budgetTokens !== undefined)) {
    fail("disabled reasoning cannot set effort, budget_tokens, or summary");
  }
  if (mode === "adaptive" && budgetTokens !== undefined) {
    fail("adaptive reasoning cannot set budget_tokens");
  }

  return {
    ...(mode === undefined ? {} : { mode }),
    ...(effort === undefined ? {} : { effort }),
    ...(budgetTokens === undefined ? {} : { budget_tokens: budgetTokens }),
    ...(summary === undefined ? {} : { summary }),
  };
}

export function normalizeRequestOptions(value: RequestOptions | undefined): RequestOptions | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("request options must be an object");
  }

  if (value.headers !== undefined && !Array.isArray(value.headers)) {
    fail("headers must be an array");
  }
  const headers = value.headers?.map((pair, index) => {
    if (!Array.isArray(pair) || pair.length !== 2) {
      fail(`headers[${index}] must contain exactly two strings`);
    }
    return [
      requireString(pair[0], `headers[${index}][0]`),
      requireString(pair[1], `headers[${index}][1]`, true),
    ] as const;
  });
  const normalized: RequestOptions = {
    ...(value.profile === undefined ? {} : { profile: requireString(value.profile, "profile") }),
    ...(value.request_id === undefined ? {} : { request_id: requireString(value.request_id, "request_id") }),
    ...(value.session_id === undefined ? {} : { session_id: requireString(value.session_id, "session_id") }),
    ...(value.project_id === undefined ? {} : { project_id: requireString(value.project_id, "project_id") }),
    ...(value.initiator === undefined ? {} : { initiator: requireString(value.initiator, "initiator") }),
    ...(headers === undefined || headers.length === 0 ? {} : { headers }),
  };
  return Object.keys(normalized).length === 0 ? undefined : normalized;
}

export function createRequest(input: GenerateInput): GenerateRequest {
  if (typeof input !== "object" || input === null) {
    fail("generation request must be an object");
  }

  const model = requireString(input.model, "model");
  if (input.messages !== undefined && !Array.isArray(input.messages)) {
    fail("messages must be an array");
  }
  const messages = (input.messages ?? []).map(normalizeMessage);
  if (input.system !== undefined) {
    messages.unshift(systemMessage(input.system));
  }
  if (input.prompt !== undefined) {
    messages.push(userMessage(input.prompt));
  }
  if (messages.length === 0) {
    fail("at least one message or prompt is required");
  }
  if (
    messages
      .filter((message) => message.role !== "system")
      .every(
        (message) =>
          message.content === "" && message.tool_call_id === undefined && (message.tool_calls?.length ?? 0) === 0,
      )
  ) {
    fail("at least one non-system message must contain content");
  }

  if (input.tools !== undefined && !Array.isArray(input.tools)) {
    fail("tools must be an array");
  }
  const tools = (input.tools ?? []).map(normalizeTool);
  const toolChoice = normalizeToolChoice(input.tool_choice);
  const reasoning = normalizeReasoning(input.reasoning);
  const options = normalizeRequestOptions(input.options);
  if (
    input.extras !== undefined &&
    (typeof input.extras !== "object" || input.extras === null || Array.isArray(input.extras))
  ) {
    fail("extras must be a JSON object");
  }
  const extras = input.extras === undefined ? undefined : cloneJson(input.extras, "extras");
  if (reasoning !== undefined && extras !== undefined) {
    const conflict = Object.keys(extras).find((key) => REASONING_EXTRAS.has(key));
    if (conflict !== undefined) {
      fail(`typed reasoning conflicts with extras['${conflict}']`);
    }
  }

  const temperature = input.temperature;
  if (temperature !== undefined && (typeof temperature !== "number" || !Number.isFinite(temperature))) {
    fail("temperature must be finite");
  }
  const topP = input.top_p;
  if (topP !== undefined && (typeof topP !== "number" || !Number.isFinite(topP) || topP < 0 || topP > 1)) {
    fail("top_p must be between 0 and 1");
  }
  const topK = input.top_k === undefined ? undefined : safeInteger(input.top_k, "top_k", 0);
  const maxOutputTokens =
    input.max_output_tokens === undefined
      ? undefined
      : safeInteger(input.max_output_tokens, "max_output_tokens", 1);

  const request: GenerateRequest = {
    model,
    messages,
    ...(tools.length === 0 ? {} : { tools }),
    ...(toolChoice === undefined ? {} : { tool_choice: toolChoice }),
    ...(temperature === undefined ? {} : { temperature }),
    ...(topP === undefined ? {} : { top_p: topP }),
    ...(topK === undefined ? {} : { top_k: topK }),
    ...(maxOutputTokens === undefined ? {} : { max_output_tokens: maxOutputTokens }),
    ...(reasoning === undefined ? {} : { reasoning }),
    ...(options === undefined ? {} : { options }),
    ...(extras === undefined || Object.keys(extras).length === 0 ? {} : { extras }),
  };
  return cloneJson(request, "generation request");
}

export function systemMessage(content: string): Message {
  return { role: "system", content: requireString(content, "content", true) };
}

export function userMessage(content: string): Message {
  return { role: "user", content: requireString(content, "content", true) };
}

export function assistantMessage(content: string, toolCalls: readonly ToolCall[] = []): Message {
  return {
    role: "assistant",
    content: requireString(content, "content", true),
    ...(toolCalls.length === 0
      ? {}
      : {
          tool_calls: toolCalls.map((call, index) => normalizeToolCall(call, `tool_calls[${index}]`)),
        }),
  };
}

export function toolMessage(toolCallId: string, content: string): Message {
  return {
    role: "tool",
    content: requireString(content, "content", true),
    tool_call_id: requireString(toolCallId, "tool_call_id"),
  };
}

interface MutableReasoningOptions {
  mode?: ReasoningMode;
  effort?: ReasoningEffort;
  budget_tokens?: number;
  summary?: ReasoningSummary;
}

export class RequestBuilder {
  protected readonly modelName: string;
  protected readonly messageList: Message[] = [];
  protected readonly toolList: Tool[] = [];
  protected selectedToolChoice: ToolChoice | undefined;
  protected temperatureValue?: number;
  protected topPValue?: number;
  protected topKValue?: number;
  protected maxOutputTokensValue?: number;
  protected reasoningValue?: MutableReasoningOptions;
  protected requestOptionsValue: RequestOptions = {};
  protected readonly extrasValue: Record<string, JsonValue> = {};

  constructor(model: string) {
    this.modelName = requireString(model, "model");
  }

  prompt(content: string): this {
    return this.user(content);
  }

  system(content: string): this {
    this.messageList.push(systemMessage(content));
    return this;
  }

  user(content: string): this {
    this.messageList.push(userMessage(content));
    return this;
  }

  assistant(content: string, toolCalls: readonly ToolCall[] = []): this {
    this.messageList.push(assistantMessage(content, toolCalls));
    return this;
  }

  toolResult(toolCallId: string, content: string): this {
    this.messageList.push(toolMessage(toolCallId, content));
    return this;
  }

  message(message: Message): this {
    this.messageList.push(normalizeMessage(message, this.messageList.length));
    return this;
  }

  messages(messages: Iterable<Message>): this {
    for (const message of messages) {
      this.message(message);
    }
    return this;
  }

  tool(tool: Tool): this {
    this.toolList.push(normalizeTool(tool, this.toolList.length));
    return this;
  }

  toolChoice(toolChoice: ToolChoice): this {
    this.selectedToolChoice = normalizeToolChoice(toolChoice);
    return this;
  }

  temperature(temperature: number): this {
    this.temperatureValue = temperature;
    return this;
  }

  topP(topP: number): this {
    this.topPValue = topP;
    return this;
  }

  topK(topK: number): this {
    this.topKValue = topK;
    return this;
  }

  maxOutputTokens(maxOutputTokens: number): this {
    this.maxOutputTokensValue = maxOutputTokens;
    return this;
  }

  maxTokens(maxTokens: number): this {
    return this.maxOutputTokens(maxTokens);
  }

  reasoning(reasoning: ReasoningOptions): this {
    const normalized = normalizeReasoning(reasoning);
    if (normalized === undefined) {
      fail("reasoning options cannot be empty");
    }
    this.reasoningValue = { ...normalized };
    return this;
  }

  reasoningMode(mode: ReasoningMode): this {
    this.reasoningOptions().mode = mode;
    return this;
  }

  reasoningEnabled(enabled: boolean): this {
    if (typeof enabled !== "boolean") {
      fail("reasoning enabled must be a boolean");
    }
    return this.reasoningMode(enabled ? "enabled" : "disabled");
  }

  reasoningEffort(effort: ReasoningEffort): this {
    this.reasoningOptions().effort = effort;
    return this;
  }

  reasoningBudgetTokens(budgetTokens: number): this {
    this.reasoningOptions().budget_tokens = budgetTokens;
    return this;
  }

  reasoningSummary(summary: ReasoningSummary): this {
    this.reasoningOptions().summary = summary;
    return this;
  }

  options(options: RequestOptions): this {
    this.requestOptionsValue = normalizeRequestOptions(options) ?? {};
    return this;
  }

  profile(profile: string): this {
    this.requestOptionsValue = { ...this.requestOptionsValue, profile };
    return this;
  }

  requestId(requestId: string): this {
    this.requestOptionsValue = { ...this.requestOptionsValue, request_id: requestId };
    return this;
  }

  sessionId(sessionId: string): this {
    this.requestOptionsValue = { ...this.requestOptionsValue, session_id: sessionId };
    return this;
  }

  projectId(projectId: string): this {
    this.requestOptionsValue = { ...this.requestOptionsValue, project_id: projectId };
    return this;
  }

  initiator(initiator: string): this {
    this.requestOptionsValue = { ...this.requestOptionsValue, initiator };
    return this;
  }

  header(name: string, value: string): this {
    this.requestOptionsValue = {
      ...this.requestOptionsValue,
      headers: [...(this.requestOptionsValue.headers ?? []), [name, value]],
    };
    return this;
  }

  extra(name: string, value: JsonValue): this {
    this.extrasValue[requireString(name, "extra name")] = cloneJson(value, `extras.${name}`);
    return this;
  }

  build(): GenerateRequest {
    return createRequest({
      model: this.modelName,
      messages: this.messageList,
      tools: this.toolList,
      ...(this.selectedToolChoice === undefined ? {} : { tool_choice: this.selectedToolChoice }),
      ...(this.temperatureValue === undefined ? {} : { temperature: this.temperatureValue }),
      ...(this.topPValue === undefined ? {} : { top_p: this.topPValue }),
      ...(this.topKValue === undefined ? {} : { top_k: this.topKValue }),
      ...(this.maxOutputTokensValue === undefined ? {} : { max_output_tokens: this.maxOutputTokensValue }),
      ...(this.reasoningValue === undefined ? {} : { reasoning: this.reasoningValue }),
      ...(Object.keys(this.requestOptionsValue).length === 0 ? {} : { options: this.requestOptionsValue }),
      ...(Object.keys(this.extrasValue).length === 0 ? {} : { extras: this.extrasValue }),
    });
  }

  private reasoningOptions(): MutableReasoningOptions {
    this.reasoningValue ??= {};
    return this.reasoningValue;
  }
}

export function request(model: string): RequestBuilder {
  return new RequestBuilder(model);
}

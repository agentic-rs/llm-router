from __future__ import annotations

import json
import math
from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import (
  TYPE_CHECKING,
  Any,
  ClassVar,
  Iterable,
  Literal,
  Mapping,
  Sequence,
  TypeVar,
  cast,
)

if TYPE_CHECKING:
  from ._client import Client, GenerateCall, GenerateRequestBuilder


JsonValue = bool | int | float | str | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]
HeaderValue = str | list[str]

_T = TypeVar("_T")


def _json_dumps(value: object) -> str:
  return json.dumps(value, allow_nan=False)


def _json_loads_object(value: str) -> Mapping[str, Any]:
  decoded = json.loads(value)
  if not isinstance(decoded, dict):
    raise ValueError("expected a JSON object")
  return decoded


def _mapping(value: object, name: str) -> Mapping[str, Any]:
  if not isinstance(value, Mapping):
    raise TypeError(f"{name} must be a mapping")
  if not all(isinstance(key, str) for key in value):
    raise TypeError(f"{name} keys must be strings")
  return cast(Mapping[str, Any], value)


def _required(data: Mapping[str, Any], name: str) -> Any:
  if name not in data:
    raise ValueError(f"missing required field '{name}'")
  return data[name]


def _optional_string(data: Mapping[str, Any], name: str) -> str | None:
  value = data.get(name)
  if value is not None and not isinstance(value, str):
    raise TypeError(f"{name} must be a string or None")
  return value


def _string(data: Mapping[str, Any], name: str) -> str:
  value = _required(data, name)
  if not isinstance(value, str):
    raise TypeError(f"{name} must be a string")
  return value


def _optional_int(data: Mapping[str, Any], name: str) -> int | None:
  value = data.get(name)
  if value is None:
    return None
  if isinstance(value, bool) or not isinstance(value, int):
    raise TypeError(f"{name} must be an integer or None")
  return int(value)


def _optional_float(data: Mapping[str, Any], name: str) -> float | None:
  value = data.get(name)
  if value is None:
    return None
  if isinstance(value, bool) or not isinstance(value, (int, float)):
    raise TypeError(f"{name} must be a number or None")
  return float(value)


def _sequence(value: object, name: str) -> Sequence[Any]:
  if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
    raise TypeError(f"{name} must be a sequence")
  return value


def _models(
  value: object,
  model: type[_T],
  name: str,
) -> list[_T]:
  items = _sequence(value, name)
  output: list[_T] = []
  for item in items:
    if isinstance(item, model):
      output.append(item)
    else:
      output.append(model.from_dict(_mapping(item, name)))  # type: ignore[attr-defined]
  return output


@dataclass(slots=True)
class RequestOptions:
  """Routing and request-correlation options shared by all SDK calls."""

  profile: str | None = None
  request_id: str | None = None
  session_id: str | None = None
  project_id: str | None = None
  initiator: str | None = None
  headers: list[tuple[str, str]] = field(default_factory=list)

  @property
  def is_empty(self) -> bool:
    return (
      self.profile is None
      and self.request_id is None
      and self.session_id is None
      and self.project_id is None
      and self.initiator is None
      and not self.headers
    )

  def to_dict(self) -> JsonObject:
    data: JsonObject = {}
    if self.profile is not None:
      data["profile"] = self.profile
    if self.request_id is not None:
      data["request_id"] = self.request_id
    if self.session_id is not None:
      data["session_id"] = self.session_id
    if self.project_id is not None:
      data["project_id"] = self.project_id
    if self.initiator is not None:
      data["initiator"] = self.initiator
    if self.headers:
      data["headers"] = [[name, value] for name, value in self.headers]
    return data

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> RequestOptions:
    headers: list[tuple[str, str]] = []
    for pair in _sequence(data.get("headers", []), "headers"):
      values = _sequence(pair, "header")
      if len(values) != 2 or not all(isinstance(value, str) for value in values):
        raise TypeError("each header must contain exactly two strings")
      headers.append((values[0], values[1]))
    return cls(
      profile=_optional_string(data, "profile"),
      request_id=_optional_string(data, "request_id"),
      session_id=_optional_string(data, "session_id"),
      project_id=_optional_string(data, "project_id"),
      initiator=_optional_string(data, "initiator"),
      headers=headers,
    )

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> RequestOptions:
    return cls.from_dict(_json_loads_object(value))


class Role(str, Enum):
  """Roles supported by the provider-neutral message API."""

  SYSTEM = "system"
  USER = "user"
  ASSISTANT = "assistant"
  TOOL = "tool"

  def to_dict(self) -> str:
    return self.value

  @classmethod
  def from_dict(cls, value: object) -> Role:
    if not isinstance(value, str):
      raise TypeError("role must be a string")
    try:
      return cls(value)
    except ValueError as error:
      raise ValueError(f"unknown role '{value}'") from error

  def to_json(self) -> str:
    return _json_dumps(self.value)

  @classmethod
  def from_json(cls, value: str) -> Role:
    return cls.from_dict(json.loads(value))


@dataclass(frozen=True, slots=True)
class ToolChoice:
  """A provider-neutral tool selection mode or a specific named tool."""

  kind: Literal["auto", "none", "required", "tool"]
  name: str | None = None

  AUTO: ClassVar[ToolChoice]
  NONE: ClassVar[ToolChoice]
  REQUIRED: ClassVar[ToolChoice]

  def __post_init__(self) -> None:
    if self.kind not in {"auto", "none", "required", "tool"}:
      raise ValueError(f"unknown tool choice '{self.kind}'")
    if self.kind == "tool":
      if self.name is None:
        raise ValueError("a named tool choice requires a name")
    elif self.name is not None:
      raise ValueError(f"tool choice '{self.kind}' cannot have a name")

  @classmethod
  def named(cls, name: str) -> ToolChoice:
    return cls("tool", name)

  def to_dict(self) -> str | JsonObject:
    if self.kind == "tool":
      assert self.name is not None
      data: JsonObject = {"tool": self.name}
      return data
    return self.kind

  @classmethod
  def from_dict(cls, value: object) -> ToolChoice:
    if isinstance(value, str):
      if value == "auto":
        return cls.AUTO
      if value == "none":
        return cls.NONE
      if value == "required":
        return cls.REQUIRED
      raise ValueError(f"unknown tool choice '{value}'")
    data = _mapping(value, "tool_choice")
    if set(data) != {"tool"} or not isinstance(data["tool"], str):
      raise ValueError("named tool choice must have the form {'tool': name}")
    return cls.named(data["tool"])

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> ToolChoice:
    return cls.from_dict(json.loads(value))


ToolChoice.AUTO = ToolChoice("auto")
ToolChoice.NONE = ToolChoice("none")
ToolChoice.REQUIRED = ToolChoice("required")


@dataclass(slots=True)
class Tool:
  """A provider-neutral function tool definition."""

  name: str
  parameters: JsonObject = field(default_factory=dict)
  description: str | None = None
  strict: bool | None = None

  @classmethod
  def function(
    cls,
    name: str,
    parameters: Mapping[str, JsonValue] | None = None,
    *,
    description: str | None = None,
    strict: bool | None = None,
  ) -> Tool:
    return cls(
      name=name,
      parameters=dict(parameters or {}),
      description=description,
      strict=strict,
    )

  def to_dict(self) -> JsonObject:
    data: JsonObject = {
      "name": self.name,
      "parameters": deepcopy(self.parameters),
    }
    if self.description is not None:
      data["description"] = self.description
    if self.strict is not None:
      data["strict"] = self.strict
    return data

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> Tool:
    parameters = data.get("parameters", {})
    if not isinstance(parameters, Mapping):
      raise TypeError("parameters must be a mapping")
    strict = data.get("strict")
    if strict is not None and not isinstance(strict, bool):
      raise TypeError("strict must be a bool or None")
    return cls(
      name=_string(data, "name"),
      parameters=deepcopy(dict(parameters)),
      description=_optional_string(data, "description"),
      strict=strict,
    )

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> Tool:
    return cls.from_dict(_json_loads_object(value))


@dataclass(slots=True)
class ToolCall:
  """A normalized tool invocation in a request or response."""

  name: str
  arguments: JsonValue
  id: str | None = None

  def to_dict(self) -> JsonObject:
    return {
      "id": self.id,
      "name": self.name,
      "arguments": deepcopy(self.arguments),
    }

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> ToolCall:
    return cls(
      id=_optional_string(data, "id"),
      name=_string(data, "name"),
      arguments=deepcopy(_required(data, "arguments")),
    )

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> ToolCall:
    return cls.from_dict(_json_loads_object(value))


@dataclass(slots=True)
class Message:
  """A simple provider-neutral conversation message."""

  role: Role
  content: str
  tool_call_id: str | None = None
  tool_calls: list[ToolCall] = field(default_factory=list)

  @classmethod
  def system(cls, content: str) -> Message:
    return cls(Role.SYSTEM, content)

  @classmethod
  def user(cls, content: str) -> Message:
    return cls(Role.USER, content)

  @classmethod
  def assistant(cls, content: str) -> Message:
    return cls(Role.ASSISTANT, content)

  @classmethod
  def tool(cls, call_id: str, content: str) -> Message:
    return cls(Role.TOOL, content, tool_call_id=call_id)

  @classmethod
  def assistant_with_tool_calls(
    cls,
    content: str,
    tool_calls: Iterable[ToolCall],
  ) -> Message:
    return cls(Role.ASSISTANT, content, tool_calls=list(tool_calls))

  def to_dict(self) -> JsonObject:
    data: JsonObject = {
      "role": self.role.value,
      "content": self.content,
    }
    if self.tool_call_id is not None:
      data["tool_call_id"] = self.tool_call_id
    if self.tool_calls:
      data["tool_calls"] = [tool_call.to_dict() for tool_call in self.tool_calls]
    return data

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> Message:
    return cls(
      role=Role.from_dict(_required(data, "role")),
      content=_string(data, "content"),
      tool_call_id=_optional_string(data, "tool_call_id"),
      tool_calls=_models(data.get("tool_calls", []), ToolCall, "tool_calls"),
    )

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> Message:
    return cls.from_dict(_json_loads_object(value))


@dataclass(slots=True)
class Usage:
  """Provider-neutral token usage."""

  input_tokens: int | None = None
  output_tokens: int | None = None
  total_tokens: int | None = None
  input_tokens_details: JsonValue = None
  output_tokens_details: JsonValue = None
  extras: JsonObject = field(default_factory=dict)

  def to_dict(self) -> JsonObject:
    data: JsonObject = {
      "input_tokens": self.input_tokens,
      "output_tokens": self.output_tokens,
      "total_tokens": self.total_tokens,
    }
    if self.input_tokens_details is not None:
      data["input_tokens_details"] = deepcopy(self.input_tokens_details)
    if self.output_tokens_details is not None:
      data["output_tokens_details"] = deepcopy(self.output_tokens_details)
    if self.extras:
      data["extras"] = deepcopy(self.extras)
    return data

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> Usage:
    extras = data.get("extras", {})
    if not isinstance(extras, Mapping):
      raise TypeError("extras must be a mapping")
    return cls(
      input_tokens=_optional_int(data, "input_tokens"),
      output_tokens=_optional_int(data, "output_tokens"),
      total_tokens=_optional_int(data, "total_tokens"),
      input_tokens_details=deepcopy(data.get("input_tokens_details")),
      output_tokens_details=deepcopy(data.get("output_tokens_details")),
      extras=deepcopy(dict(extras)),
    )

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> Usage:
    return cls.from_dict(_json_loads_object(value))


@dataclass(slots=True)
class GenerateRequest:
  """An owned, serializable, provider-neutral generation request."""

  model: str
  messages: list[Message] = field(default_factory=list)
  tools: list[Tool] = field(default_factory=list)
  tool_choice: ToolChoice | None = None
  temperature: float | None = None
  top_p: float | None = None
  max_output_tokens: int | None = None
  options: RequestOptions = field(default_factory=RequestOptions)
  extras: JsonObject = field(default_factory=dict)

  @classmethod
  def builder(cls, model: str) -> GenerateRequestBuilder:
    from ._client import GenerateRequestBuilder

    return GenerateRequestBuilder(model)

  def bind(self, client: Client) -> GenerateCall:
    from ._client import GenerateCall

    return GenerateCall(client, self)

  def with_changes(self, **changes: Any) -> GenerateRequest:
    """Return an independently transformed copy of this request."""

    return replace(deepcopy(self), **deepcopy(changes))

  def validate(self) -> None:
    """Validate the fields required by the friendly generation API."""

    if not isinstance(self.model, str) or not self.model.strip():
      raise ValueError("model cannot be empty")
    if not self.messages:
      raise ValueError("at least one message or prompt is required")
    if all(
      message.role == Role.SYSTEM
      or (
        not message.content
        and message.tool_call_id is None
        and not message.tool_calls
      )
      for message in self.messages
    ):
      raise ValueError("at least one non-system message must contain content")
    for message in self.messages:
      if message.role != Role.ASSISTANT and message.tool_calls:
        raise ValueError("tool calls are only valid on assistant messages")
      if message.role == Role.TOOL:
        if message.tool_call_id is None or not message.tool_call_id.strip():
          raise ValueError("tool results require a non-empty tool call id")
      elif message.tool_call_id is not None:
        raise ValueError("tool_call_id is only valid on tool messages")
      if any(
        tool_call.id is None
        or not tool_call.id.strip()
        or not tool_call.name.strip()
        for tool_call in message.tool_calls
      ):
        raise ValueError("assistant tool calls require non-empty ids and names")
    for name, value in (
      ("temperature", self.temperature),
      ("top_p", self.top_p),
    ):
      if value is not None and (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
      ):
        raise ValueError(f"{name} must be finite")
    if self.max_output_tokens is not None and (
      isinstance(self.max_output_tokens, bool)
      or not isinstance(self.max_output_tokens, int)
      or self.max_output_tokens <= 0
    ):
      raise ValueError("max_output_tokens must be greater than zero")
    if any(not tool.name.strip() for tool in self.tools):
      raise ValueError("tool names cannot be empty")
    if any(not isinstance(tool.parameters, Mapping) for tool in self.tools):
      raise ValueError("tool parameters must be a JSON object")
    if (
      self.tool_choice is not None
      and self.tool_choice.kind == "tool"
      and (self.tool_choice.name is None or not self.tool_choice.name.strip())
    ):
      raise ValueError("named tool choices require a non-empty name")

  def to_dict(self) -> JsonObject:
    data: JsonObject = {"model": self.model}
    if self.messages:
      data["messages"] = [message.to_dict() for message in self.messages]
    if self.tools:
      data["tools"] = [tool.to_dict() for tool in self.tools]
    if self.tool_choice is not None:
      data["tool_choice"] = self.tool_choice.to_dict()
    if self.temperature is not None:
      data["temperature"] = self.temperature
    if self.top_p is not None:
      data["top_p"] = self.top_p
    if self.max_output_tokens is not None:
      data["max_output_tokens"] = self.max_output_tokens
    if not self.options.is_empty:
      data["options"] = self.options.to_dict()
    if self.extras:
      data["extras"] = deepcopy(self.extras)
    return data

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> GenerateRequest:
    choice = data.get("tool_choice")
    options = data.get("options", {})
    extras = data.get("extras", {})
    if not isinstance(extras, Mapping):
      raise TypeError("extras must be a mapping")
    return cls(
      model=_string(data, "model"),
      messages=_models(data.get("messages", []), Message, "messages"),
      tools=_models(data.get("tools", []), Tool, "tools"),
      tool_choice=None if choice is None else ToolChoice.from_dict(choice),
      temperature=_optional_float(data, "temperature"),
      top_p=_optional_float(data, "top_p"),
      max_output_tokens=_optional_int(data, "max_output_tokens"),
      options=(
        RequestOptions.from_dict(options.to_dict())
        if isinstance(options, RequestOptions)
        else RequestOptions.from_dict(_mapping(options, "options"))
      ),
      extras=deepcopy(dict(extras)),
    )

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> GenerateRequest:
    return cls.from_dict(_json_loads_object(value))


@dataclass(slots=True)
class GenerateResponse:
  """Friendly buffered output from a provider-neutral generation."""

  http_status: int
  headers: dict[str, HeaderValue]
  text: str
  raw: JsonValue
  id: str | None = None
  model: str | None = None
  status: str | None = None
  finish_reason: str | None = None
  reasoning: str | None = None
  tool_calls: list[ToolCall] = field(default_factory=list)
  usage: Usage | None = None

  def to_dict(self) -> JsonObject:
    headers: JsonObject = {}
    for name, value in self.headers.items():
      headers[name] = value if isinstance(value, str) else list(value)
    return {
      "http_status": self.http_status,
      "headers": headers,
      "id": self.id,
      "model": self.model,
      "status": self.status,
      "finish_reason": self.finish_reason,
      "text": self.text,
      "reasoning": self.reasoning,
      "tool_calls": [tool_call.to_dict() for tool_call in self.tool_calls],
      "usage": None if self.usage is None else self.usage.to_dict(),
      "raw": deepcopy(self.raw),
    }

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> GenerateResponse:
    http_status = _required(data, "http_status")
    if isinstance(http_status, bool) or not isinstance(http_status, int):
      raise TypeError("http_status must be an integer")
    headers_data = _mapping(data.get("headers", {}), "headers")
    headers: dict[str, HeaderValue] = {}
    for name, value in headers_data.items():
      if isinstance(value, str):
        headers[str(name)] = value
      else:
        values = _sequence(value, f"header '{name}'")
        if not all(isinstance(item, str) for item in values):
          raise TypeError(f"header '{name}' values must be strings")
        headers[str(name)] = list(values)
    usage_data = data.get("usage")
    return cls(
      http_status=http_status,
      headers=headers,
      id=_optional_string(data, "id"),
      model=_optional_string(data, "model"),
      status=_optional_string(data, "status"),
      finish_reason=_optional_string(data, "finish_reason"),
      text=_string(data, "text"),
      reasoning=_optional_string(data, "reasoning"),
      tool_calls=_models(data.get("tool_calls", []), ToolCall, "tool_calls"),
      usage=None if usage_data is None else Usage.from_dict(_mapping(usage_data, "usage")),
      raw=deepcopy(_required(data, "raw")),
    )

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_json(cls, value: str) -> GenerateResponse:
    return cls.from_dict(_json_loads_object(value))


class GenerateEvent:
  """Base class for provider-neutral semantic streaming events."""

  def to_dict(self) -> JsonObject:
    raise NotImplementedError

  def to_json(self) -> str:
    return _json_dumps(self.to_dict())

  @classmethod
  def from_dict(cls, data: Mapping[str, Any]) -> GenerateEvent:
    return generate_event_from_dict(data)

  @classmethod
  def from_json(cls, value: str) -> GenerateEvent:
    return generate_event_from_dict(_json_loads_object(value))


@dataclass(frozen=True, slots=True)
class TextDelta(GenerateEvent):
  text: str

  def to_dict(self) -> JsonObject:
    return {"type": "text_delta", "text": self.text}


@dataclass(frozen=True, slots=True)
class ReasoningDelta(GenerateEvent):
  text: str

  def to_dict(self) -> JsonObject:
    return {"type": "reasoning_delta", "text": self.text}


@dataclass(frozen=True, slots=True)
class ToolCallDelta(GenerateEvent):
  index: int
  id: str | None
  name: str | None
  arguments_delta: str

  def to_dict(self) -> JsonObject:
    return {
      "type": "tool_call_delta",
      "index": self.index,
      "id": self.id,
      "name": self.name,
      "arguments_delta": self.arguments_delta,
    }


@dataclass(frozen=True, slots=True)
class UsageEvent(GenerateEvent):
  usage: Usage

  def to_dict(self) -> JsonObject:
    return {"type": "usage", "usage": self.usage.to_dict()}


@dataclass(frozen=True, slots=True)
class Completed(GenerateEvent):
  finish_reason: str | None

  def to_dict(self) -> JsonObject:
    return {"type": "completed", "finish_reason": self.finish_reason}


@dataclass(frozen=True, slots=True)
class OtherEvent(GenerateEvent):
  kind: str
  data: JsonValue

  def to_dict(self) -> JsonObject:
    return {
      "type": "other",
      "kind": self.kind,
      "data": deepcopy(self.data),
    }


def generate_event_from_dict(data: Mapping[str, Any]) -> GenerateEvent:
  """Parse one Rust SDK ``GenerateEvent`` JSON object."""

  kind = _string(data, "type")
  if kind == "text_delta":
    return TextDelta(text=_string(data, "text"))
  if kind == "reasoning_delta":
    return ReasoningDelta(text=_string(data, "text"))
  if kind == "tool_call_delta":
    index = _required(data, "index")
    if isinstance(index, bool) or not isinstance(index, int):
      raise TypeError("index must be an integer")
    return ToolCallDelta(
      index=index,
      id=_optional_string(data, "id"),
      name=_optional_string(data, "name"),
      arguments_delta=_string(data, "arguments_delta"),
    )
  if kind == "usage":
    return UsageEvent(usage=Usage.from_dict(_mapping(_required(data, "usage"), "usage")))
  if kind == "completed":
    return Completed(finish_reason=_optional_string(data, "finish_reason"))
  if kind == "other":
    return OtherEvent(
      kind=_string(data, "kind"),
      data=deepcopy(_required(data, "data")),
    )
  raise ValueError(f"unknown generation event type '{kind}'")


__all__ = [
  "Completed",
  "GenerateEvent",
  "GenerateRequest",
  "GenerateResponse",
  "JsonObject",
  "JsonValue",
  "Message",
  "OtherEvent",
  "ReasoningDelta",
  "RequestOptions",
  "Role",
  "TextDelta",
  "Tool",
  "ToolCall",
  "ToolCallDelta",
  "ToolChoice",
  "Usage",
  "UsageEvent",
  "generate_event_from_dict",
]

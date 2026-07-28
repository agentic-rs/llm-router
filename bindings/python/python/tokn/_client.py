from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import (
  Any,
  AsyncIterator,
  Generic,
  Iterable,
  Mapping,
  TypeVar,
  cast,
  overload,
)

from ._models import (
  GenerateEvent,
  GenerateRequest,
  GenerateResponse,
  Message,
  RequestOptions,
  Tool,
  ToolCall,
  ToolChoice,
  generate_event_from_dict,
)
from ._native import (
  NativeClient,
  NativeGenerateStream,
  NativeStream,
  NativeTextStream,
)

JsonObject = dict[str, Any]


@dataclass(slots=True)
class Response:
  """A raw endpoint response."""

  status: int
  headers: JsonObject
  data: Any


class StreamResponse(AsyncIterator[bytes]):
  """A raw byte stream returned by an endpoint escape hatch."""

  def __init__(self, native: NativeStream) -> None:
    self._native = native
    self.status = native.status
    self.headers: JsonObject = json.loads(native.headers_json)

  def __aiter__(self) -> StreamResponse:
    return self

  async def __anext__(self) -> bytes:
    return await self._native.next_chunk()

  async def aclose(self) -> None:
    await self._native.aclose()

  async def __aenter__(self) -> StreamResponse:
    return self

  async def __aexit__(self, *exc_info: object) -> None:
    del exc_info
    await self.aclose()


class GenerateStream(AsyncIterator[GenerateEvent]):
  """A stream of normalized, provider-neutral generation events."""

  def __init__(self, native: NativeGenerateStream) -> None:
    self._native = native

  def __aiter__(self) -> GenerateStream:
    return self

  async def __anext__(self) -> GenerateEvent:
    event_json = await self._native.next_event()
    return generate_event_from_dict(json.loads(event_json))

  async def aclose(self) -> None:
    await self._native.aclose()

  async def __aenter__(self) -> GenerateStream:
    return self

  async def __aexit__(self, *exc_info: object) -> None:
    del exc_info
    await self.aclose()


class TextStream(AsyncIterator[str]):
  """A generation stream containing only text deltas."""

  def __init__(self, native: NativeTextStream) -> None:
    self._native = native

  def __aiter__(self) -> TextStream:
    return self

  async def __anext__(self) -> str:
    return await self._native.next_text()

  async def aclose(self) -> None:
    await self._native.aclose()

  async def __aenter__(self) -> TextStream:
    return self

  async def __aexit__(self, *exc_info: object) -> None:
    del exc_info
    await self.aclose()


_BuilderT = TypeVar("_BuilderT", bound="_GenerateBuilder[Any]")


class _GenerateBuilder(Generic[_BuilderT]):
  def __init__(self, request: GenerateRequest) -> None:
    self._request = _copy_request(request)

  def _self(self) -> _BuilderT:
    return cast(_BuilderT, self)

  def prompt(self, prompt: str) -> _BuilderT:
    return self.user(prompt)

  def system(self, content: str) -> _BuilderT:
    self._request.messages.append(Message.system(content))
    return self._self()

  def user(self, content: str) -> _BuilderT:
    self._request.messages.append(Message.user(content))
    return self._self()

  def assistant(self, content: str) -> _BuilderT:
    self._request.messages.append(Message.assistant(content))
    return self._self()

  def assistant_with_tool_calls(
    self,
    content: str,
    tool_calls: Iterable[ToolCall],
  ) -> _BuilderT:
    self._request.messages.append(
      Message.assistant_with_tool_calls(content, tool_calls)
    )
    return self._self()

  def tool_result(self, call_id: str, content: str) -> _BuilderT:
    self._request.messages.append(Message.tool(call_id, content))
    return self._self()

  def message(self, message: Message) -> _BuilderT:
    self._request.messages.append(message)
    return self._self()

  def messages(self, messages: Iterable[Message]) -> _BuilderT:
    self._request.messages.extend(messages)
    return self._self()

  def tool(self, tool: Tool) -> _BuilderT:
    self._request.tools.append(tool)
    return self._self()

  def tool_choice(self, tool_choice: ToolChoice | str) -> _BuilderT:
    if isinstance(tool_choice, str):
      known_choice = {
        "auto": ToolChoice.AUTO,
        "none": ToolChoice.NONE,
        "required": ToolChoice.REQUIRED,
      }.get(tool_choice)
      tool_choice = known_choice or ToolChoice.named(tool_choice)
    self._request.tool_choice = tool_choice
    return self._self()

  def temperature(self, temperature: float) -> _BuilderT:
    self._request.temperature = temperature
    return self._self()

  def top_p(self, top_p: float) -> _BuilderT:
    self._request.top_p = top_p
    return self._self()

  def max_output_tokens(self, max_output_tokens: int) -> _BuilderT:
    self._request.max_output_tokens = max_output_tokens
    return self._self()

  def options(self, options: RequestOptions) -> _BuilderT:
    self._request.options = RequestOptions.from_dict(options.to_dict())
    return self._self()

  def profile(self, profile: str) -> _BuilderT:
    self._request.options.profile = profile
    return self._self()

  def request_id(self, request_id: str) -> _BuilderT:
    self._request.options.request_id = request_id
    return self._self()

  def session_id(self, session_id: str) -> _BuilderT:
    self._request.options.session_id = session_id
    return self._self()

  def project_id(self, project_id: str) -> _BuilderT:
    self._request.options.project_id = project_id
    return self._self()

  def initiator(self, initiator: str) -> _BuilderT:
    self._request.options.initiator = initiator
    return self._self()

  def header(self, name: str, value: str) -> _BuilderT:
    self._request.options.headers.append((name, value))
    return self._self()

  def extra(self, name: str, value: Any) -> _BuilderT:
    self._request.extras[name] = value
    return self._self()

  def build(self) -> GenerateRequest:
    self._request.validate()
    return _copy_request(self._request)


class GenerateRequestBuilder(_GenerateBuilder["GenerateRequestBuilder"]):
  """A client-independent fluent builder for an owned request."""

  def __init__(self, model: str) -> None:
    super().__init__(GenerateRequest(model=model))

  def bind(self, client: Client) -> GenerateCall:
    return GenerateCall(client, self._request)


class GenerateCall(_GenerateBuilder["GenerateCall"]):
  """A fluent generation builder bound to a client."""

  def __init__(self, client: Client, request: GenerateRequest) -> None:
    super().__init__(request)
    self._client = client

  async def send(self) -> GenerateResponse:
    return await self._client.send(self.build())

  async def stream(self) -> GenerateStream:
    return await self._client.stream(self.build())

  async def stream_text(self) -> TextStream:
    return await self._client.stream_text(self.build())


class _Endpoint:
  def __init__(self, client: Client, name: str) -> None:
    self._client = client
    self._name = name

  async def create(
    self,
    body: Mapping[str, Any],
    *,
    options: RequestOptions | None = None,
  ) -> Response:
    return await self._client.request(self._name, body, options=options)

  async def stream(
    self,
    body: Mapping[str, Any],
    *,
    options: RequestOptions | None = None,
  ) -> StreamResponse:
    return await self._client.stream(self._name, body, options=options)


class _Chat:
  def __init__(self, client: Client) -> None:
    self.completions = _Endpoint(client, "chat_completions")


class Client:
  """An in-process client using the gateway's configuration and credentials."""

  def __init__(
    self,
    *,
    config_path: str | Path | None = None,
    auth_path: str | Path | None = None,
    profile: str | None = None,
  ) -> None:
    self._native = NativeClient(
      str(config_path) if config_path is not None else None,
      str(auth_path) if auth_path is not None else None,
      profile,
    )
    self.responses = _Endpoint(self, "responses")
    self.chat = _Chat(self)
    self.messages = _Endpoint(self, "messages")

  @property
  def config_path(self) -> Path:
    return Path(self._native.config_path())

  @property
  def auth_path(self) -> Path:
    return Path(self._native.auth_path())

  def reload(self) -> None:
    self._native.reload()

  def generate(self, model: str) -> GenerateCall:
    """Start a client-bound, provider-neutral generation."""
    return GenerateCall(self, GenerateRequest(model=model))

  async def send(self, request: GenerateRequest) -> GenerateResponse:
    """Send a detached provider-neutral generation request."""
    request.validate()
    response_json = await self._native.send_generate(request.to_json())
    return GenerateResponse.from_dict(json.loads(response_json))

  async def request(
    self,
    endpoint: str,
    body: Mapping[str, Any],
    *,
    options: RequestOptions | None = None,
  ) -> Response:
    """Send a request through a raw endpoint escape hatch."""
    status, headers_json, body_json = await self._native.request(
      endpoint,
      json.dumps(dict(body)),
      options.to_json() if options is not None else None,
    )
    return Response(
      status=status,
      headers=json.loads(headers_json),
      data=json.loads(body_json),
    )

  @overload
  async def stream(
    self,
    endpoint: str,
    body: Mapping[str, Any],
    *,
    options: RequestOptions | None = None,
  ) -> StreamResponse: ...

  @overload
  async def stream(
    self,
    endpoint: GenerateRequest,
    body: None = None,
    *,
    options: None = None,
  ) -> GenerateStream: ...

  async def stream(
    self,
    endpoint: str | GenerateRequest,
    body: Mapping[str, Any] | None = None,
    *,
    options: RequestOptions | None = None,
  ) -> StreamResponse | GenerateStream:
    """Stream either a detached generation request or a raw endpoint."""
    if isinstance(endpoint, GenerateRequest):
      if body is not None or options is not None:
        raise TypeError("body and options are not accepted with GenerateRequest")
      endpoint.validate()
      generate_native = await self._native.stream_generate(endpoint.to_json())
      return GenerateStream(generate_native)

    if body is None:
      raise TypeError("body is required when streaming a raw endpoint")
    raw_native = await self._native.stream(
      endpoint,
      json.dumps(dict(body)),
      options.to_json() if options is not None else None,
    )
    return StreamResponse(raw_native)

  async def stream_text(self, request: GenerateRequest) -> TextStream:
    """Stream only generated text deltas from a detached request."""
    request.validate()
    native = await self._native.stream_generate_text(request.to_json())
    return TextStream(native)


def _copy_request(request: GenerateRequest) -> GenerateRequest:
  return GenerateRequest.from_dict(request.to_dict())

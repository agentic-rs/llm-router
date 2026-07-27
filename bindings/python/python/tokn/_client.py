from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

from ._native import NativeClient, NativeStream

JsonObject = dict[str, Any]


@dataclass(slots=True)
class RequestOptions:
  profile: str | None = None
  request_id: str | None = None
  session_id: str | None = None
  project_id: str | None = None
  initiator: str | None = None
  headers: list[tuple[str, str]] = field(default_factory=list)

  def to_json(self) -> str:
    return json.dumps(
      {
        "profile": self.profile,
        "request_id": self.request_id,
        "session_id": self.session_id,
        "project_id": self.project_id,
        "initiator": self.initiator,
        "headers": self.headers,
      }
    )


@dataclass(slots=True)
class Response:
  status: int
  headers: JsonObject
  data: Any


class StreamResponse(AsyncIterator[bytes]):
  def __init__(self, native: NativeStream) -> None:
    self._native = native
    self.status = native.status
    self.headers: JsonObject = json.loads(native.headers_json)

  def __aiter__(self) -> StreamResponse:
    return self

  async def __anext__(self) -> bytes:
    return await self._native.next_chunk()


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

  async def request(
    self,
    endpoint: str,
    body: Mapping[str, Any],
    *,
    options: RequestOptions | None = None,
  ) -> Response:
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

  async def stream(
    self,
    endpoint: str,
    body: Mapping[str, Any],
    *,
    options: RequestOptions | None = None,
  ) -> StreamResponse:
    native = await self._native.stream(
      endpoint,
      json.dumps(dict(body)),
      options.to_json() if options is not None else None,
    )
    return StreamResponse(native)

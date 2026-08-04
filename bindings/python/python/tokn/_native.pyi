class ToknError(RuntimeError): ...


class ConfigurationError(ToknError): ...


class AuthenticationError(ToknError): ...


class RequestError(ToknError): ...


class APIStatusError(ToknError):
  status: int
  body: str


class StreamError(ToknError): ...


class SerializationError(ToknError): ...


class NativeStream:
  status: int
  headers_json: str

  async def next_chunk(self) -> bytes: ...

  async def aclose(self) -> None: ...


class NativeGenerateStream:
  async def next_event(self) -> str: ...

  async def aclose(self) -> None: ...


class NativeTextStream:
  async def next_text(self) -> str: ...

  async def aclose(self) -> None: ...


class NativeClient:
  def __init__(
    self,
    config_path: str | None = None,
    auth_path: str | None = None,
    profile: str | None = None,
  ) -> None: ...

  def reload(self) -> None: ...

  def config_path(self) -> str: ...

  def auth_path(self) -> str: ...

  def profile(self) -> str: ...

  async def request(
    self,
    endpoint: str,
    body_json: str,
    options_json: str | None = None,
  ) -> tuple[int, str, str]: ...

  async def stream(
    self,
    endpoint: str,
    body_json: str,
    options_json: str | None = None,
  ) -> NativeStream: ...

  async def send_generate(self, request_json: str) -> str: ...

  async def stream_generate(
    self,
    request_json: str,
  ) -> NativeGenerateStream: ...

  async def stream_generate_text(
    self,
    request_json: str,
  ) -> NativeTextStream: ...

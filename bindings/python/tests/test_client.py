from __future__ import annotations

import asyncio
import json
import math
import pickle
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

from tokn import (
  APIStatusError,
  Client,
  Completed,
  GenerateRequest,
  Message,
  ReasoningDelta,
  RequestOptions,
  Role,
  StreamError,
  TextDelta,
  ToknError,
  Tool,
  ToolCall,
  ToolCallDelta,
  ToolChoice,
  Usage,
  UsageEvent,
)


class ProviderHandler(BaseHTTPRequestHandler):
  requests: ClassVar[list[dict[str, Any]]] = []
  idle_stream_started: ClassVar[threading.Event] = threading.Event()
  idle_stream_release: ClassVar[threading.Event] = threading.Event()

  def do_POST(self) -> None:
    length = int(self.headers.get("content-length", "0"))
    body = json.loads(self.rfile.read(length))
    type(self).requests.append(
      {
        "path": self.path,
        "headers": dict(self.headers),
        "body": body,
      }
    )

    if self.path == "/responses":
      self._handle_responses(body)
      return
    if self.path != "/chat/completions":
      self.send_error(404)
      return
    if body.get("stream"):
      self._handle_chat_stream(body)
      return
    if "api-error" in json.dumps(body):
      self._send_json(
        {"error": {"message": "mock rate limit"}},
        status=429,
      )
      return
    self._send_json(
      {
        "id": "chatcmpl-python",
        "model": "mock-model",
        "object": "chat.completion",
        "choices": [
          {
            "index": 0,
            "message": {
              "role": "assistant",
              "content": "mock answer",
              "reasoning_content": "mock reasoning",
              "tool_calls": [
                {
                  "id": "call_1",
                  "type": "function",
                  "function": {
                    "name": "lookup",
                    "arguments": '{"query":"rust"}',
                  },
                }
              ],
            },
            "finish_reason": "tool_calls",
          }
        ],
        "usage": {
          "prompt_tokens": 3,
          "completion_tokens": 5,
          "total_tokens": 8,
        },
      }
    )

  def _handle_responses(self, body: dict[str, Any]) -> None:
    if body.get("stream") and "stream-error" in json.dumps(body):
      self._send_sse(["not-json"])
      return
    self._send_json(
      {
        "id": "resp-python",
        "object": "response",
        "model": "mock-model",
        "status": "completed",
        "output": [
          {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": "mock answer"}],
          }
        ],
        "usage": {
          "input_tokens": 1,
          "output_tokens": 2,
          "total_tokens": 3,
        },
      }
    )

  def _handle_chat_stream(self, body: dict[str, Any]) -> None:
    serialized = json.dumps(body)
    if "cancel pending read" in serialized:
      self._send_delayed_sse(
        [
          self._chat_chunk({"content": "after cancel"}),
          self._chat_chunk({}, finish_reason="stop"),
          "[DONE]",
        ]
      )
      return
    if "idle stream" in serialized:
      self._send_idle_sse()
      return
    if "semantic stream" in serialized:
      self._send_sse(
        [
          self._chat_chunk(
            {
              "role": "assistant",
              "reasoning_content": "think",
            }
          ),
          self._chat_chunk({"content": "hello"}),
          self._chat_chunk(
            {
              "tool_calls": [
                {
                  "index": 0,
                  "id": "call_stream",
                  "type": "function",
                  "function": {
                    "name": "lookup",
                    "arguments": '{"query":',
                  },
                }
              ]
            }
          ),
          self._chat_chunk(
            {
              "tool_calls": [
                {
                  "index": 0,
                  "function": {"arguments": '"rust"}'},
                }
              ]
            }
          ),
          self._chat_chunk(
            {},
            finish_reason="tool_calls",
            usage={
              "prompt_tokens": 3,
              "completion_tokens": 5,
              "total_tokens": 8,
            },
          ),
          "[DONE]",
        ]
      )
      return

    self._send_sse(
      [
        self._chat_chunk({"role": "assistant", "content": "hel"}),
        self._chat_chunk({"content": "lo"}),
        self._chat_chunk({}, finish_reason="stop"),
        "[DONE]",
      ]
    )

  @staticmethod
  def _chat_chunk(
    delta: dict[str, Any],
    *,
    finish_reason: str | None = None,
    usage: dict[str, int] | None = None,
  ) -> str:
    payload: dict[str, Any] = {
      "id": "chatcmpl-stream",
      "model": "mock-model",
      "choices": [
        {
          "index": 0,
          "delta": delta,
          "finish_reason": finish_reason,
        }
      ],
    }
    if usage is not None:
      payload["usage"] = usage
    return json.dumps(payload)

  def _send_json(
    self,
    data: dict[str, Any],
    *,
    status: int = 200,
  ) -> None:
    payload = json.dumps(data).encode()
    self.send_response(status)
    self.send_header("content-type", "application/json")
    self.send_header("content-length", str(len(payload)))
    self.end_headers()
    self.wfile.write(payload)

  def _send_sse(self, values: list[str]) -> None:
    payload = "".join(f"data: {value}\n\n" for value in values).encode()
    self.send_response(200)
    self.send_header("content-type", "text/event-stream")
    self.send_header("content-length", str(len(payload)))
    self.end_headers()
    self.wfile.write(payload)

  def _send_idle_sse(self) -> None:
    self.send_response(200)
    self.send_header("content-type", "text/event-stream")
    self.end_headers()
    self.wfile.flush()
    type(self).idle_stream_started.set()
    type(self).idle_stream_release.wait(timeout=5)

  def _send_delayed_sse(self, values: list[str]) -> None:
    self.send_response(200)
    self.send_header("content-type", "text/event-stream")
    self.end_headers()
    self.wfile.flush()
    type(self).idle_stream_started.set()
    type(self).idle_stream_release.wait(timeout=5)
    payload = "".join(f"data: {value}\n\n" for value in values).encode()
    self.wfile.write(payload)
    self.wfile.flush()

  def log_message(self, format: str, *args: object) -> None:
    del format, args


class ModelTests(unittest.TestCase):
  def test_sdk_errors_preserve_runtime_error_compatibility(self) -> None:
    self.assertTrue(issubclass(ToknError, RuntimeError))
    self.assertTrue(issubclass(StreamError, ToknError))
    restored = pickle.loads(pickle.dumps(ToknError("round trip")))
    self.assertIsInstance(restored, ToknError)
    self.assertEqual(str(restored), "round trip")

  def test_owned_request_round_trips_and_transforms(self) -> None:
    call = ToolCall(
      name="lookup",
      arguments={"query": "rust"},
      id="call_1",
    )
    request = GenerateRequest(
      model="smart",
      messages=[
        Message.system("Answer briefly."),
        Message.user("Look up Rust."),
        Message.assistant_with_tool_calls("", [call]),
        Message.tool("call_1", "Rust is a systems language."),
      ],
      tools=[
        Tool.function(
          "lookup",
          {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
          },
          description="Look up a value",
          strict=True,
        )
      ],
      tool_choice=ToolChoice.named("lookup"),
      temperature=0.2,
      options=RequestOptions(
        profile="fast",
        request_id="python-detached",
        headers=[("x-sdk-test", "detached")],
      ),
    )

    restored = GenerateRequest.from_json(request.to_json())
    changed = restored.with_changes(max_output_tokens=64)

    self.assertEqual(restored.to_dict(), request.to_dict())
    self.assertIsNone(restored.max_output_tokens)
    self.assertEqual(changed.max_output_tokens, 64)
    self.assertEqual(changed.messages[2].role, Role.ASSISTANT)
    self.assertEqual(changed.messages[2].tool_calls[0], call)
    self.assertEqual(changed.tools[0].description, "Look up a value")
    self.assertEqual(changed.tool_choice, ToolChoice.named("lookup"))
    self.assertEqual(changed.options.request_id, "python-detached")
    changed.messages[0].content = "Changed copy."
    self.assertEqual(restored.messages[0].content, "Answer briefly.")

    caller_message = Message.user("Caller-owned message.")
    copied = GenerateRequest.from_dict(
      {
        "model": "smart",
        "messages": [caller_message],
      }
    )
    copied.messages[0].content = "Changed copied message."
    self.assertEqual(caller_message.content, "Caller-owned message.")

  def test_models_and_typed_events_round_trip(self) -> None:
    usage = Usage(
      input_tokens=3,
      output_tokens=5,
      total_tokens=8,
      extras={"cached_tokens": 1},
    )
    restored_usage = Usage.from_json(usage.to_json())
    self.assertEqual(restored_usage, usage)

    event = ToolCallDelta(
      index=0,
      id="call_1",
      name="lookup",
      arguments_delta='{"query":"rust"}',
    )
    restored_event = ToolCallDelta.from_json(event.to_json())
    self.assertEqual(restored_event, event)
    self.assertEqual(ToolChoice.from_json('"required"'), ToolChoice.REQUIRED)

  def test_detached_validation_fails_before_execution(self) -> None:
    with self.assertRaisesRegex(ValueError, "model cannot be empty"):
      GenerateRequest(model=" ", messages=[Message.user("hello")]).validate()
    with self.assertRaisesRegex(ValueError, "at least one message"):
      GenerateRequest(model="smart").validate()
    with self.assertRaisesRegex(ValueError, "temperature must be finite"):
      GenerateRequest(
        model="smart",
        messages=[Message.user("hello")],
        temperature=math.nan,
      ).validate()
    with self.assertRaisesRegex(ValueError, "non-empty ids and names"):
      GenerateRequest(
        model="smart",
        messages=[
          Message.user("hello"),
          Message.assistant_with_tool_calls(
            "",
            [ToolCall(name="lookup", arguments={})],
          ),
        ],
      ).validate()
    with self.assertRaisesRegex(ValueError, "unknown tool choice"):
      GenerateRequest.builder("smart").tool_choice("lookup")


class PythonSdkTests(unittest.IsolatedAsyncioTestCase):
  server: ClassVar[ThreadingHTTPServer]
  server_thread: ClassVar[threading.Thread]
  root: ClassVar[tempfile.TemporaryDirectory[str]]
  config_path: ClassVar[Path]
  auth_path: ClassVar[Path]

  @classmethod
  def setUpClass(cls) -> None:
    cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
    cls.server_thread = threading.Thread(
      target=cls.server.serve_forever,
      daemon=True,
    )
    cls.server_thread.start()
    cls.root = tempfile.TemporaryDirectory()
    root = Path(cls.root.name)
    cls.config_path = root / "config.toml"
    cls.auth_path = root / "auth.yaml"
    cls.config_path.write_text('[defaults]\nmode = "exact"\n')
    cls.auth_path.write_text(
      "\n".join(
        [
          "version: 1",
          "accounts:",
          "  - id: local-llama",
          "    provider: llama-cpp",
          f"    base_url: http://127.0.0.1:{cls.server.server_port}",
          "  - id: local-openai",
          "    provider: openai",
          f"    base_url: http://127.0.0.1:{cls.server.server_port}",
          "    api_key: test-key",
          "",
        ]
      )
    )

  @classmethod
  def tearDownClass(cls) -> None:
    ProviderHandler.idle_stream_release.set()
    cls.server.shutdown()
    cls.server.server_close()
    cls.server_thread.join()
    cls.root.cleanup()

  def setUp(self) -> None:
    ProviderHandler.requests.clear()
    ProviderHandler.idle_stream_started.clear()
    ProviderHandler.idle_stream_release.clear()

  def client(self) -> Client:
    return Client(
      config_path=self.config_path,
      auth_path=self.auth_path,
    )

  def last_request(self) -> dict[str, Any]:
    self.assertTrue(ProviderHandler.requests)
    return ProviderHandler.requests[-1]

  async def test_client_bound_generation_normalizes_response(self) -> None:
    response = await (
      self.client()
      .generate("llama-cpp/mock-model")
      .system("Answer briefly.")
      .prompt("Use a tool.")
      .tool(
        Tool.function(
          "lookup",
          {
            "type": "object",
            "properties": {"query": {"type": "string"}},
          },
          description="Look up a value",
          strict=True,
        )
      )
      .tool_choice(ToolChoice.named("lookup"))
      .temperature(0.2)
      .top_p(0.9)
      .max_output_tokens(64)
      .request_id("python-bound")
      .send()
    )

    self.assertEqual(response.http_status, 200)
    self.assertEqual(response.id, "chatcmpl-python")
    self.assertEqual(response.model, "mock-model")
    self.assertEqual(response.status, "completed")
    self.assertEqual(response.finish_reason, "tool_calls")
    self.assertEqual(response.text, "mock answer")
    self.assertEqual(response.reasoning, "mock reasoning")
    self.assertEqual(
      response.tool_calls,
      [
        ToolCall(
          name="lookup",
          arguments={"query": "rust"},
          id="call_1",
        )
      ],
    )
    self.assertEqual(
      response.usage,
      Usage(input_tokens=3, output_tokens=5, total_tokens=8),
    )
    self.assertIsInstance(response.raw, dict)
    assert isinstance(response.raw, dict)
    self.assertEqual(response.raw["status"], "completed")

    captured = self.last_request()
    self.assertEqual(captured["path"], "/chat/completions")
    body = captured["body"]
    self.assertEqual(body["model"], "mock-model")
    self.assertEqual(
      body["messages"],
      [
        {"role": "system", "content": "Answer briefly."},
        {"role": "user", "content": "Use a tool."},
      ],
    )
    self.assertEqual(body["tools"][0]["function"]["name"], "lookup")
    self.assertEqual(
      body["tool_choice"],
      {"type": "function", "function": {"name": "lookup"}},
    )
    self.assertEqual(body["temperature"], 0.2)
    self.assertEqual(body["top_p"], 0.9)
    self.assertEqual(body["max_tokens"], 64)
    self.assertFalse(body.get("stream", False))

  async def test_detached_request_can_send_or_bind(self) -> None:
    client = self.client()
    request = (
      GenerateRequest.builder("llama-cpp/mock-model")
      .prompt("Send a detached request.")
      .temperature(0.2)
      .request_id("python-detached")
      .build()
    )
    request = GenerateRequest.from_json(request.to_json()).with_changes(
      max_output_tokens=32
    )

    response = await client.send(request)
    bound_response = await request.bind(client).send()

    self.assertEqual(response.text, "mock answer")
    self.assertEqual(bound_response.text, "mock answer")
    self.assertEqual(request.max_output_tokens, 32)
    self.assertEqual(len(ProviderHandler.requests), 2)
    self.assertTrue(
      all(
        captured["body"]["max_tokens"] == 32
        for captured in ProviderHandler.requests
      )
    )

  async def test_semantic_stream_returns_typed_events(self) -> None:
    request = (
      GenerateRequest.builder("llama-cpp/mock-model")
      .prompt("semantic stream")
      .build()
    )
    stream = await self.client().stream(request)
    async with stream:
      events = [event async for event in stream]

    text = "".join(
      event.text for event in events if isinstance(event, TextDelta)
    )
    reasoning = "".join(
      event.text for event in events if isinstance(event, ReasoningDelta)
    )
    tool_events = [
      event for event in events if isinstance(event, ToolCallDelta)
    ]
    usage_events = [
      event for event in events if isinstance(event, UsageEvent)
    ]
    completed = [
      event for event in events if isinstance(event, Completed)
    ]

    self.assertEqual(text, "hello")
    self.assertEqual(reasoning, "think")
    self.assertTrue(tool_events)
    self.assertTrue(
      all(event.id == "call_stream" for event in tool_events)
    )
    self.assertTrue(all(event.name == "lookup" for event in tool_events))
    self.assertEqual(
      "".join(event.arguments_delta for event in tool_events),
      '{"query":"rust"}',
    )
    self.assertEqual(usage_events[-1].usage.total_tokens, 8)
    self.assertEqual(completed[-1].finish_reason, "tool_calls")
    self.assertTrue(self.last_request()["body"]["stream"])

  async def test_text_stream_and_early_close(self) -> None:
    client = self.client()
    request = (
      GenerateRequest.builder("llama-cpp/mock-model")
      .prompt("text stream")
      .build()
    )
    text_stream = await client.stream_text(request)
    async with text_stream:
      text = [part async for part in text_stream]
    self.assertEqual(text, ["hel", "lo"])

    semantic_stream = await client.stream(request)
    async with semantic_stream:
      await semantic_stream.__anext__()
    with self.assertRaises(StopAsyncIteration):
      await semantic_stream.__anext__()

  async def test_close_wakes_a_pending_stream_read(self) -> None:
    request = (
      GenerateRequest.builder("llama-cpp/mock-model")
      .prompt("idle stream")
      .build()
    )
    stream = await self.client().stream(request)
    pending = asyncio.create_task(stream.__anext__())

    try:
      started = await asyncio.to_thread(
        ProviderHandler.idle_stream_started.wait,
        1,
      )
      self.assertTrue(started)
      await asyncio.sleep(0.05)
      await asyncio.wait_for(stream.aclose(), timeout=0.5)
      with self.assertRaises(StopAsyncIteration):
        await asyncio.wait_for(pending, timeout=0.5)
    finally:
      ProviderHandler.idle_stream_release.set()
      if not pending.done():
        pending.cancel()
        try:
          await pending
        except asyncio.CancelledError:
          pass

  async def test_cancelled_pending_read_preserves_stream(self) -> None:
    request = (
      GenerateRequest.builder("llama-cpp/mock-model")
      .prompt("cancel pending read")
      .build()
    )
    stream = await self.client().stream(request)
    pending = asyncio.create_task(stream.__anext__())

    try:
      started = await asyncio.to_thread(
        ProviderHandler.idle_stream_started.wait,
        1,
      )
      self.assertTrue(started)
      await asyncio.sleep(0.05)
      pending.cancel()
      with self.assertRaises(asyncio.CancelledError):
        await pending

      ProviderHandler.idle_stream_release.set()

      async def next_text_delta() -> TextDelta:
        async for event in stream:
          if isinstance(event, TextDelta):
            return event
        raise AssertionError("stream ended before yielding text")

      event = await asyncio.wait_for(next_text_delta(), timeout=0.5)
      self.assertEqual(event.text, "after cancel")
    finally:
      ProviderHandler.idle_stream_release.set()
      await stream.aclose()

  async def test_stream_errors_are_typed_and_terminal(self) -> None:
    request = (
      GenerateRequest.builder("openai/gpt-5")
      .prompt("stream-error")
      .build()
    )
    stream = await self.client().stream(request)

    with self.assertRaises(StreamError):
      await stream.__anext__()
    with self.assertRaises(StopAsyncIteration):
      await stream.__anext__()

  async def test_api_status_errors_expose_status_and_body(self) -> None:
    request = (
      GenerateRequest.builder("llama-cpp/mock-model")
      .prompt("api-error")
      .build()
    )

    with self.assertRaises(APIStatusError) as raised:
      await self.client().send(request)

    self.assertEqual(raised.exception.status, 429)
    self.assertIn("mock rate limit", raised.exception.body)
    restored = pickle.loads(pickle.dumps(raised.exception))
    self.assertEqual(restored.status, 429)
    self.assertIn("mock rate limit", restored.body)

  async def test_raw_endpoint_apis_remain_compatible(self) -> None:
    client = self.client()
    direct_response = await client.request(
      "chat",
      {
        "model": "llama-cpp/mock-model",
        "messages": [{"role": "user", "content": "direct raw request"}],
      },
    )
    self.assertEqual(direct_response.data["id"], "chatcmpl-python")

    response = await client.chat.completions.create(
      {
        "model": "llama-cpp/mock-model",
        "messages": [{"role": "user", "content": "hello"}],
      },
      options=RequestOptions(
        request_id="python-raw",
        session_id="session-1",
      ),
    )

    self.assertEqual(response.status, 200)
    self.assertEqual(response.data["id"], "chatcmpl-python")
    captured = self.last_request()
    self.assertEqual(captured["path"], "/chat/completions")
    self.assertEqual(captured["body"]["model"], "mock-model")
    self.assertFalse(captured["body"].get("stream", False))

    raw_stream = await client.chat.completions.stream(
      {
        "model": "llama-cpp/mock-model",
        "messages": [{"role": "user", "content": "raw stream"}],
      }
    )
    async with raw_stream:
      chunks = [chunk async for chunk in raw_stream]
    payload = b"".join(chunks)
    self.assertIn(b'"content": "hel"', payload)
    self.assertIn(b"data: [DONE]", payload)


if __name__ == "__main__":
  unittest.main()

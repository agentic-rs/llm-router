from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tokn import Client, RequestOptions


class ProviderHandler(BaseHTTPRequestHandler):
  requests: list[dict[str, Any]] = []

  def do_POST(self) -> None:
    length = int(self.headers.get("content-length", "0"))
    body = json.loads(self.rfile.read(length))
    type(self).requests.append({"path": self.path, "headers": dict(self.headers), "body": body})

    if self.path != "/chat/completions":
      self.send_error(404)
      return

    if body.get("stream"):
      payload = (
        'data: {"id":"chatcmpl-stream","choices":[{"index":0,"delta":{"content":"hello"}}]}\n\n'
        "data: [DONE]\n\n"
      ).encode()
      self.send_response(200)
      self.send_header("content-type", "text/event-stream")
      self.send_header("content-length", str(len(payload)))
      self.end_headers()
      self.wfile.write(payload)
      return

    payload = json.dumps(
      {
        "id": "chatcmpl-python",
        "object": "chat.completion",
        "choices": [
          {
            "index": 0,
            "message": {"role": "assistant", "content": "hello"},
            "finish_reason": "stop",
          }
        ],
      }
    ).encode()
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.send_header("content-length", str(len(payload)))
    self.end_headers()
    self.wfile.write(payload)

  def log_message(self, format: str, *args: object) -> None:
    del format, args


class PythonSdkTests(unittest.IsolatedAsyncioTestCase):
  @classmethod
  def setUpClass(cls) -> None:
    ProviderHandler.requests.clear()
    cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
    cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
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
          "  - id: local",
          "    provider: llama-cpp",
          f"    base_url: http://127.0.0.1:{cls.server.server_port}",
          "",
        ]
      )
    )

  @classmethod
  def tearDownClass(cls) -> None:
    cls.server.shutdown()
    cls.server.server_close()
    cls.server_thread.join()
    cls.root.cleanup()

  def client(self) -> Client:
    return Client(config_path=self.config_path, auth_path=self.auth_path)

  async def test_buffered_endpoint_returns_python_response(self) -> None:
    response = await self.client().chat.completions.create(
      {
        "model": "llama-cpp/mock-model",
        "messages": [{"role": "user", "content": "hello"}],
      },
      options=RequestOptions(request_id="python-buffered", session_id="session-1"),
    )

    self.assertEqual(response.status, 200)
    self.assertEqual(response.data["id"], "chatcmpl-python")
    captured = ProviderHandler.requests[-1]
    self.assertEqual(captured["path"], "/chat/completions")
    self.assertEqual(captured["body"]["model"], "mock-model")
    self.assertFalse(captured["body"].get("stream", False))

  async def test_streaming_endpoint_is_an_async_iterator(self) -> None:
    response = await self.client().chat.completions.stream(
      {
        "model": "llama-cpp/mock-model",
        "messages": [{"role": "user", "content": "hello"}],
      }
    )
    chunks = [chunk async for chunk in response]

    self.assertEqual(response.status, 200)
    self.assertIn(b'"content":"hello"', b"".join(chunks))
    self.assertIn(b"data: [DONE]", b"".join(chunks))
    self.assertTrue(ProviderHandler.requests[-1]["body"]["stream"])

  async def test_raw_request_supports_all_endpoint_names(self) -> None:
    response = await self.client().request(
      "chat",
      {
        "model": "llama-cpp/mock-model",
        "messages": [{"role": "user", "content": "hello"}],
      },
    )
    self.assertEqual(response.data["id"], "chatcmpl-python")


if __name__ == "__main__":
  unittest.main()

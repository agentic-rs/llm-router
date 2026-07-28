# tokn Python SDK

The Python package embeds the same Rust routing engine as `tokn-sdk`. It uses
the existing `config.toml`, `config.d`, `auth.yaml`, and `auth.d` sources and
does not require a gateway process.

## Friendly generation API

For a one-off request, start with the client-bound builder:

```python
from tokn import Client

client = Client()

response = await (
  client.generate("smart")
  .system("You are a Python expert.")
  .prompt("Explain this function.")
  .temperature(0.2)
  .send()
)

print(response.text)
```

Responses normalize text, reasoning, tool calls, token usage, and finish
reasons across supported providers.

The snippets below continue using the `client` created above. Snippets after
the detached-request example also reuse its `request`.

Build an owned request when it needs to be serialized, transformed, queued, or
reused independently of a client:

```python
from tokn import GenerateRequest

request = (
  GenerateRequest.builder("smart")
  .prompt("Explain this function.")
  .temperature(0.2)
  .build()
)

serialized = request.to_json()
request = GenerateRequest.from_json(serialized)
request = request.with_changes(max_output_tokens=128)

response = await client.send(request)
```

As an alternative to `client.send(request)`, use
`await request.bind(client).send()` when fluent binding is more convenient.

Semantic streaming returns typed events:

```python
from tokn import Completed, TextDelta

stream = await client.generate("smart").prompt("Write a haiku.").stream()
async with stream:
  async for event in stream:
    if isinstance(event, TextDelta):
      print(event.text, end="")
    elif isinstance(event, Completed):
      print(f"\nfinish reason: {event.finish_reason}")
```

Use `stream_text()` when only generated text is needed:

```python
stream = await client.stream_text(request)
async with stream:
  async for text in stream:
    print(text, end="")
```

SDK failures derive from `ToknError` (and remain compatible with
`RuntimeError`). Catch a specific subtype when recovery depends on the cause:

```python
from tokn import APIStatusError, ToknError

try:
  response = await client.send(request)
except APIStatusError as error:
  print(error.status, error.body)
except ToknError as error:
  print(f"request failed: {error}")
```

## Raw endpoint escape hatches

Provider-compatible mappings remain available for endpoint-specific fields:

```python
raw = await client.responses.create({
  "model": "gpt-5",
  "input": "Explain this function.",
})

stream = await client.chat.completions.stream({
  "model": "claude-sonnet-4",
  "messages": [{"role": "user", "content": "Hello"}],
})
async with stream:
  payload = b"".join([chunk async for chunk in stream])
```

Raw stream chunks are transport bytes and do not necessarily align with SSE
event or UTF-8 boundaries.

Pass `config_path`, `auth_path`, or `profile` to `Client` to override the same
defaults used by the gateway.

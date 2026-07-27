# tokn Python SDK

The Python package embeds the same Rust routing engine as `tokn-sdk`. It loads
the existing `config.toml`, `config.d`, `auth.yaml`, and `auth.d` sources
without requiring a gateway process.

```python
from tokn import Client

client = Client()

response = await client.responses.create({
  "model": "gpt-5",
  "input": "Explain this function.",
})

stream = await client.chat.completions.stream({
  "model": "claude-sonnet-4",
  "messages": [{"role": "user", "content": "Hello"}],
})
async for chunk in stream:
  print(chunk.decode(), end="")
```

Use `config_path`, `auth_path`, or `profile` when constructing `Client` to
override the same defaults used by the gateway.

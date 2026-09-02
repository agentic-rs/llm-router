# tokn

Local, account-aware LLM gateway for OpenAI-compatible clients.

`tokn` runs a local HTTP API and optional MITM forward proxy, routes requests
across configured provider accounts, and records local usage/session/request
history. GitHub Copilot is still the default provider, but the gateway now also
supports OpenAI, ChatGPT Codex, DeepSeek, llama.cpp, Z.ai, and Zhipu BigModel.

The shipped Cargo package is `tokn-gateway-cli` and the binary is
`tokn-gateway`.

## Active Development

**This project is moving quickly.** Config shape, database schemas, API
behavior, provider routing, and proxy behavior are all expected to change as the
gateway settles.

## Features

- OpenAI-compatible local API on `127.0.0.1:4141`.
- Endpoints for `GET /v1/models`, `POST /v1/chat/completions`,
  `POST /v1/responses`, and `POST /v1/messages`.
- Profile-prefixed routes like `/{profile}/v1/chat/completions`.
- Client API keys with per-key provider allowlists.
- Multiple accounts per provider with active/fallback/disabled tiers.
- Route modes for passthrough, provider switching, exact routing, catalogue
  routing, and fuzzy model-family routing.
- Streaming support through the shared request pipeline.
- Local SQLite-backed usage, session, and request-body persistence.
- Optional HTTP CONNECT proxy with local CA generation for agent workflows.

Docker PR trial helpers live under [`scripts/`](/Users/clouds/.codex/worktrees/59e1/llm-router/scripts/README.md).
They load the CI image artifact, run a persistent gateway container, and launch
disposable Codex/opencode/pi agent containers through Bun.

## Install

From this workspace:

```sh
cargo install --path crates/gateway-cli
```

Or run directly during development:

```sh
cargo run -p tokn-gateway-cli -- --help
```

## Quick Start

Add an account, start the API server, then point any OpenAI-compatible client at
the local base URL.

```sh
# Interactive provider/account setup.
tokn-gateway account add

# GitHub Copilot device-flow login.
tokn-gateway account login --provider github-copilot

# Or import a static API key from the environment.
OPENAI_API_KEY=sk-... tokn-gateway account import --provider openai --from env --id openai

# Start the local API server.
tokn-gateway serve

# Send a chat-completions request.
curl http://127.0.0.1:4141/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "hi"}],
    "stream": true
  }'
```

For clients that expect `OPENAI_BASE_URL`, use:

```sh
export OPENAI_BASE_URL=http://127.0.0.1:4141/v1
```

## Client API Keys

Client authentication is controlled explicitly in `config.toml` and is disabled
by default:

```toml
[api_key]
enabled = true
```

Create a key with access to every current and future provider (the default):

```sh
tokn-gateway api-key create my-client
```

Restrict a key by repeating `--provider`:

```sh
tokn-gateway api-key create openai-client \
  --provider openai \
  --provider github-copilot
```

The secret is printed only when the key is created. Send it as a standard
Bearer token (or as `x-api-key`):

```sh
curl http://127.0.0.1:4141/v1/models \
  -H "authorization: Bearer $TOKN_API_KEY"
```

When `[api_key].enabled` is true, gateway-managed `/v1/*` and
profile-prefixed `/{profile}/v1/*` routes require a valid key. Intercepted proxy
requests also require a key whenever their effective route mode is `route`,
`exact`, `fuzzy`, or `switch`. `GET /v1/models` and `GET /v1/providers` expose
only permitted providers, and routing, retries, session affinity, and proxy
switching remain inside the key's provider allowlist. Provider permissions
default to `*`; an explicit `*` cannot be combined with specific provider ids.

List or revoke keys with:

```sh
tokn-gateway api-key list
tokn-gateway api-key revoke KEY_ID
```

Enabling authentication with no active keys fails closed. Gateway credentials
are removed before managed upstream dispatch. Effective `passthrough` mode is
the exception: it bypasses API-key authentication and the authentication layer
does not remove `Authorization` or `x-api-key`. Raw CONNECT tunnels and hosts in
`proxy_mode.passthrough_hosts` cannot be inspected, so they are also left
untouched and unauthenticated.

The projected v2 proxy created by legacy `serve --with-proxy` uses the v2
admission boundary instead: when `[api_key].enabled = true`, every proxy
request, including CONNECT, must provide exactly one
`Proxy-Authorization: Bearer <key>` header. For example:

```sh
curl --proxy http://127.0.0.1:4142 \
  --proxy-header "Proxy-Authorization: Bearer $TOKN_API_KEY" \
  https://api.openai.com/v1/models
```

This stronger behavior applies only to the v2 proxy path; standalone legacy
`proxy start` retains the legacy authentication behavior described above.

For authenticated managed requests, persistence records the key name as the
request `user` and its non-secret key id as `ctx_json.api_key_id` in request and
usage data. The token and its hash are never copied into those databases.

## Config And Data

Default files live under `~/.tokn/router/`:

- `config.toml`: runtime config.
- `config.d/`: non-secret, agent-owned binding and profile overlays.
- `auth.yaml`: user-managed and shared account credentials.
- `auth.d/`: credential-only fragments owned by linked agents.
- `access.db`: hashed client API keys and provider permissions.
- `usage.db`: usage summaries.
- `sessions.db`: semantic message trees captured from live sessions.
- `requests/`: archived request bodies.
- `ca/`: proxy CA material.
- `logs/`: file logs when enabled.

Print the config path with:

```sh
tokn-gateway config path
```

Minimal config:

```toml
[api_key]
enabled = false

[server]
host = "127.0.0.1"
port = 4141

[server.cors]
# Cross-origin browser access is disabled by default.
enabled = false
# Allows http(s) localhost, *.localhost, 127.0.0.1, and [::1] origins on any port.
allow_localhost = false
# Use exact origins for non-local websites.
allowed_origins = []

[defaults]
mode = "route"
# Required when mode is "passthrough" or "switch"; optional otherwise.
# default_provider_id = "github-copilot"
# Omit providers/accounts to allow every configured active account.
# providers = ["github-copilot", "openai"]
# accounts = ["personal", "openai"]

[pool]
strategy = "round_robin"
failure_cooldown_secs = 60
session_ttl_secs = 18000

[db]
enabled = true
record_sessions = true
record_request_bodies = true
body_max_bytes = 10485760

[proxy]
# url = "http://user:pass@proxy.example.com:8080"
# url = "socks5h://127.0.0.1:1080"
# system = false
# no_proxy = ["localhost", "127.0.0.1", ".internal"]
```

Profiles merge with `[defaults]` and are selected by prefixing the route:

```toml
[profiles.coding]
mode = "fuzzy"
agent_id = "codex-cli"
# Overrides [defaults].default_provider_id when present.
# default_provider_id = "github-copilot"
providers = ["github-copilot"]
accounts = ["personal"]

[[profiles.coding.model_families]]
name = "glm"
members = ["glm-4.6", "glm-4.7"]
```

Requests to `/v1/...` use `[defaults]`. Requests to `/coding/v1/...` use
`[defaults]` plus `[profiles.coding]`. Profile `providers` entries must be
canonical provider ids; if omitted, the profile inherits the default provider
set. Profile `accounts` entries must be configured account ids; if omitted, the
profile inherits the default account set. Profile `model_families`, when
present, replaces default model families for that profile. API `passthrough`
and `switch` policies require `default_provider_id` so the router can target a
deterministic provider while preserving request bytes.

## Database

When `[db].enabled` is true, the gateway writes local SQLite state under
`~/.tokn/router/` unless paths are overridden:

- `usage.db` stores aggregate request usage for `tokn-gateway usage`.
- `sessions.db` stores semantic message trees for successful live requests with a session id.
- `requests/` stores day-rotated request databases named like
  `2026-06-09.db`.

When a client supplies thread identifiers, session nodes reduce against the
previous request in the same thread. Root and subagent thread relationships
remain grouped under their shared session.

Set `record_sessions = false` to disable live semantic capture without disabling request or usage persistence.

The request DBs are not a single `requests.db` file. They record request and
response metadata, and can also persist request bodies when
`record_request_bodies = true`. Use `body_max_bytes` to cap stored body size.

### Inspect request history

Run the standalone local viewer without starting `serve`:

```sh
tokn-gateway inspect
```

It binds only to `127.0.0.1`, prints an available URL, and reads the existing
request-day databases and `sessions.db` without creating or migrating either.
The Sessions view reads its list, semantic node tree, and selected-node content
only from `sessions.db`; opening it does not scan request history. Session and
node metadata load first, while message content is fetched only when a node is
opened. Large node responses use explicit message, part, and byte bounds, and
the viewer reports anything omitted or truncated. Use
`--requests-dir PATH` or `--sessions-db PATH` to inspect different persisted
paths. The viewer can expose stored prompts and responses, so treat its URL and
screen contents as sensitive.

The Requests view opens on the most recent non-empty UTC day. It pages through
large days, supports provider, status, error, and text filters, and loads stored
headers or bodies only when their panel is opened. Empty or unreadable day files
remain visible in the day picker but cannot be selected.

The inspector never applies migrations. The writable gateway runtime migrates
databases when it opens them; to review or apply those migrations explicitly:

```sh
tokn-gateway migration
tokn-gateway migration --commit
```

## Accounts

Accounts are managed separately from `config.toml`.

```sh
tokn-gateway account add
tokn-gateway account list
tokn-gateway account status
tokn-gateway account show personal
tokn-gateway account refresh personal
tokn-gateway account switch --only personal
tokn-gateway account remove personal
```

Non-interactive imports support `env`, `string`, `file`, `stdin`, and
provider-specific sources:

```sh
tokn-gateway account import --provider openai --from env --id openai
tokn-gateway account import --provider deepseek --from env --id deepseek
tokn-gateway account import --provider github-copilot --from gh --id personal
tokn-gateway account import --provider github-copilot --from copilot-plugin --id personal
```

Default environment variable names are derived from the provider id and
credential kind, for example `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`,
`ZAI_API_KEY`, and `GITHUB_COPILOT_REFRESH_TOKEN`.

## Providers

| id | auth | primary endpoints |
| --- | --- | --- |
| `github-copilot` | GitHub OAuth refresh token | chat completions |
| `openai` | API key | chat completions, responses |
| `codex` | OpenAI refresh token or API key | responses |
| `deepseek` | API key | chat completions, messages |
| `llama-cpp` | API key | chat completions |
| `zai`, `zai-coding-plan` | API key | chat completions |
| `zhipuai`, `zhipuai-coding-plan` | API key | chat completions |

Provider ids are canonical config values. Z.ai and Zhipu coding-plan ids use
coding-plan upstream paths; the non-coding ids use the regular PAAS paths.

Per-account `base_url` can override the provider default. Manual account
commands write account records to `auth.yaml`; linked agents keep transferred
credentials in their own `auth.d/<agent>.yaml` fragment. The gateway loads both
locations as one account pool, while preserving the file that owns each account
when credentials are refreshed or removed.

```yaml
version: 1
accounts:
  - id: local
    provider: llama-cpp
    enabled: true
    tier: active
    auth_type: bearer
    api_key: unused
    base_url: http://127.0.0.1:8080/v1
```

## Commands

```text
tokn-gateway account add [--provider PROVIDER] [--id ID]
tokn-gateway account login [--provider PROVIDER] [--id ID] [--no-proxy]
tokn-gateway account import --provider PROVIDER --from env|string|file|stdin|gh|copilot-plugin [--id ID]
tokn-gateway account list [--no-quota]
tokn-gateway account status [ID]
tokn-gateway account switch --only ID
tokn-gateway headers [--account ID]
tokn-gateway serve [--host HOST] [--port PORT] [--with-proxy] [--proxy-route-mode MODE] [--insecure-allow-remote] [--no-proxy]
tokn-gateway proxy start [--host HOST] [--port PORT] [--route-mode MODE] [--passthrough] [--insecure-allow-remote]
tokn-gateway proxy env [--shell sh|bash|zsh|fish|pwsh]
tokn-gateway proxy shell [--shell /path/to/shell]
tokn-gateway proxy codex|opencode|pi [--npx] [ARGS...]
tokn-gateway proxy run [--npx] codex|opencode|pi [ARGS...]
tokn-gateway proxy exec COMMAND [ARGS...]
tokn-gateway proxy ca path|show|regenerate
tokn-gateway usage [--since 24h] [--account ID] [--provider PROVIDER]
tokn-gateway inspect [--port PORT] [--requests-dir PATH] [--sessions-db PATH]
tokn-gateway config get|set|unset KEY [--account ID] [--add]
tokn-gateway config list|edit|path|init
tokn-gateway config migrate-v2 [--expanded] [--with-proxy] [--proxy-route-mode MODE] [--insecure-allow-remote] [--allow-insecure-http]
tokn-gateway agent list
tokn-gateway agent show codex-cli|opencode
tokn-gateway agent import codex-cli|opencode [--yes]
tokn-gateway agent link codex-cli|opencode [--profile NAME] [--mode MODE] [--yes]
tokn-gateway agent link opencode --use-main-accounts [--mode passthrough|switch|exact|route|fuzzy] [--provider ID] [--provider-filter ID]... [--yes]
tokn-gateway agent sync codex-cli|opencode|--all [--yes]
tokn-gateway agent unlink codex-cli|opencode [--backup-id ID] [--legacy-root PATH] [--yes]
tokn-gateway migration [--commit|--rollback]
tokn-gateway update
tokn-gateway smoke provider|model|send ...
```

`config get`, `config set`, and `config unset` accept dotted paths through
both regular TOML tables and inline tables, including nested v2 policies:

```sh
tokn-gateway config get routes.default.retry.policy
tokn-gateway config set routes.default.retry.policy standard
tokn-gateway config set listeners.api.cors.allowed_origins https://app.example.com --add
```

Edits preserve surrounding comments and table layout. `set --add` appends to
an array (or creates a missing array). Set and unset validate the complete
result before writing; invalid values, missing references, and removal of
required fields leave the original file unchanged. `--account` remains a
legacy-only selector for inline account entries.

`smoke provider` and `smoke send` require a `schema_version = 2` config.
`smoke provider` accepts a configured provider name, and `smoke send` runs a
request through the selected `llm_api` listener in memory. Pass `--listener`
when the config contains more than one LLM API listener. `smoke model` remains
a catalogue-only lookup and does not load the gateway config.

`serve` always runs the v2 request runtime. A native `schema_version = 2`
config is compiled directly. An unversioned legacy config is merged with its
fragments, projected into v2 together with the current account store, and
compiled entirely in memory; neither config nor auth files are rewritten.
Projection warnings are logged at startup. Legacy `route`, `exact`, `fuzzy`,
and `switch` policies are supported when their referenced accounts and
providers can be represented. Legacy API `passthrough` is rejected instead of
falling back silently to the old server runtime. For legacy configs,
`--with-proxy` adds an in-memory v2 `forward_proxy` listener using
`[proxy_mode]`; `--proxy-route-mode` overrides only that listener's static
route mode. Native v2 configs continue to declare their listeners in config
and reject these compatibility flags.

`config migrate-v2` renders the same legacy-to-v2 projection as validated TOML
on stdout without changing `config.toml`, `config.d`, `auth.yaml`, or `auth.d`.
It merges legacy fragments and uses the current effective account store while
keeping credentials out of the generated config. Warnings are written to
stderr, so the preview can be redirected safely. `--with-proxy` materializes
the legacy `[proxy_mode]` listener, and `--proxy-route-mode` overrides only its
static route mode. Non-loopback listeners require `--insecure-allow-remote`;
non-loopback cleartext HTTP provider destinations require
`--allow-insecure-http`. The command rejects native v2 input and never applies
its output.

Migration output is compact by default: redundant defaults and empty
containers are omitted, and short selectors/actions use inline tables.
Custom TTL, logging, CORS, retry, and security settings are preserved;
long or nested policies stay expanded. Empty named resources such as
`[account_pools.default]` remain declared, and routing-rule order is unchanged.
Use `config migrate-v2 --expanded` for the full representation, including
default values. Both forms decode to the same config and are validated before
anything is written to stdout. This changes only migration presentation, not
the schema, runtime defaults, or `config list` output.

Native v2 uses `[service.logging]` for the same settings as legacy `[logging]`:
`level`, `format`, `target`, `dir`, `ansi`, and `include_spans`. Migration
preserves these settings. When omitted, logging defaults to compact stderr
and daily log files under the gateway logs directory; `RUST_LOG` still takes
precedence over the configured level.

Native v2 API listeners support opt-in CORS:

```toml
[listeners.api.cors]
enabled = true
allow_localhost = false
allowed_origins = ["https://app.example.com"]
```

Migration preserves legacy `[server.cors]` on the generated API listener.
CORS remains disabled when omitted or when `enabled = false`; enabling it
requires an exact HTTP(S) origin allowlist, `allow_localhost = true`, or both.
Localhost permission includes `localhost`, subdomains of `.localhost`,
`127.0.0.1`, and `[::1]` on any port. CORS does not apply to forward proxies.

Allowed origins can call the inference and discovery endpoints, including
profile-prefixed paths. Browser preflight does not require an API key, but
actual requests retain client authentication and routing policy. Cookie-based
CORS credentials are not enabled. Health and admin endpoints never receive
CORS permission. Origin permissions can reload without restarting the listener;
invalid edits leave the current permissions and generation unchanged.

Both schemas default session affinity to 18,000 seconds. Migration preserves
explicit `session_ttl_secs` values instead of replacing them with this default.
Legacy `session_tombstone_secs` is total retention from the last successful
touch; v2 `session_expired_retention_secs` is additional retention after the
affinity TTL. For example, legacy TTL `1800` and tombstone `7200` become v2 TTL
`1800` and extra retention `5400`, preserving the same two-hour total window.
Zero TTL disables v2 affinity and requires zero extra retention; legacy zero
TTL with a nonzero tombstone is rejected rather than silently losing retention.

Every loopback-bound v2 `llm_api` listener exposes the local control endpoint
`POST /admin/config/reload`. It is deliberately absent from non-loopback
listeners because ordinary client keys do not grant gateway-administration
capability. The endpoint re-reads the selected config plus `auth.yaml` and
`auth.d`; for an unversioned legacy config it also merges fragments and repeats
the in-memory v2 projection with the original `serve` flags. Listener
client authentication does not apply to this control endpoint: ordinary client
keys neither grant nor gate gateway administration. Every call must include
`x-tokn-admin: reload`; this explicit non-simple header prevents ambient browser
requests from triggering a reload on a loopback listener:

```sh
curl -X POST http://127.0.0.1:4141/admin/config/reload \
  -H "x-tokn-admin: reload"
```

A successful reload replaces routes, bindings, profiles, retry policies,
providers, account pools, accounts, discovery data, and forward-proxy routing
rules as one generation across every listener. Requests already admitted keep
their previous generation; later requests use the new generation. Invalid
configuration returns `422`, and a change that needs a restart returns `409`;
either failure leaves the active generation untouched.

Listener ids, kinds, bind addresses, client authentication, and proxy TLS/CA
settings require a restart. Service-level outbound transport, request limits,
persistence and logging settings, and switching between legacy and native-v2 config
schemas also require a restart. A forward-proxy listener's
`request_body_max_bytes` is request policy and can reload. A native config with
only `forward_proxy` listeners, or with no loopback `llm_api` listener, has no
HTTP admin endpoint and must be restarted to apply changes.

Native v2 retries are opt-in route policy. Define a bounded exponential
backoff policy once, then reference it from each route that may retry:

```toml
[retry_policies.standard]
max_retries = 2
initial_backoff_ms = 100

[routes.default]
kind = "managed"
account_pool = "default"
provider = { kind = "any" }
model = { kind = "capability" }
operation = "translate_compatible"
retry = { kind = "recoverable", policy = "standard" }
```

Only recoverable send failures consume the retry budget. Managed requests are
buffered and use `kind = "recoverable"`. Opaque relay routes must either use
`kind = "safe_methods"` (GET, HEAD, OPTIONS, and TRACE only) or explicitly
acknowledge body replay with `kind = "buffered"`; omitting `retry` means
`never`. Policies accept 1–10 retries and an initial backoff from 0–60000 ms.
The generated v2 config and in-memory legacy projection use two retries with a
100 ms initial backoff, preserving the former API retry behavior. Projected
legacy forward-proxy passthrough and switch routes remain non-retrying.

Every v2 `llm_api` listener serves `GET /v1/providers` and `GET /v1/models`
alongside the three inference endpoints. Discovery is derived from the
profiles and account pools reachable through that listener, filtered by the
authenticated key's provider allowlist. Model discovery queries eligible
upstream accounts and falls back to the local catalogue. When the selected
profiles use different routing policies, the response reports
`"route_mode": "mixed"` and lists the individual values in `route_modes`.
Projected legacy profile paths also expose the same discovery and inference
surface at `/{profile}/v1/*`; native v2 configs must create matching path
bindings before those profile-compatible paths are active.

The remaining legacy-to-v2 behavior differences are intentional and reported
at startup: per-request route-mode overrides, agent binding metadata,
selection-order details, proxy
authentication/override semantics, LAN bootstrap helpers, percent-decoded
profile aliases, and HTTP rejection behavior. Legacy listener,
outbound-proxy, CORS, logging, persistence, account-pool cooldown, and session-affinity
settings are projected; they do not fall back wholesale to v2 defaults.

Route modes are `passthrough`, `switch`, `exact`, `route`, and `fuzzy`. A
fresh link defaults to `route`; a relink or sync preserves the binding's
current mode when `--mode` is omitted. `exact` requires an agent that can
encode provider-qualified model IDs and is currently supported only by
OpenCode.

`agent link` writes its binding and generated profile to
`config.d/<agent>.toml`, so the primary config remains untouched. Tokn owns
that generated fragment and checks its planned preimage during link and sync;
do not edit it concurrently while either command is running. When a normal
agent-owned link transfers credentials, its matching `auth.d/<agent>.yaml`
fragment forms a separately backed up and restored credential bundle; the shared
root `auth.yaml` stays unchanged. An agent-owned link requires at least one
importable local credential and never falls back to the main account pool.
`--use-main-accounts` creates no auth fragment: OpenCode keeps its local
credentials unchanged and routes selected providers through the gateway's
existing account pool. `--provider-filter` is repeatable;
if it is omitted, the link discovers all enabled providers in the effective
main account pool. `agent sync` repeats that discovery and retains an explicit
filter when one was configured. Because the link does not edit OpenCode's local
auth, its direct providers remain available alongside the gateway-published
providers. Raw `passthrough` and `switch` links require a single target
`--provider` (or a configured default provider) that supports OpenCode's Chat
Completions endpoint. That choice is persisted as
`[agents.opencode].provider` and is the desired link state; the generated
profile's `default_provider_id` is only its runtime snapshot. This means sync
and status retain the raw target even when generated profile state drifts.
`provider` and `provider_filter` are mutually exclusive: `provider` is
valid only for main-account `switch`/`passthrough`, while `provider_filter` is
valid only for main-account `route`/`fuzzy`/`exact`. Older raw bindings without
`provider` recover it once from their generated profile (or gateway defaults)
on sync. Codex
CLI does not yet support main-account links because its credential bootstrap
would need to be changed. An existing link keeps its account source; unlink it
before linking again with a different source. To move a pre-`auth.d` imported
link, unlink it first so its local credentials are restored, then link it again.
Manifests written by older versions may contain paths relative to the directory
where the link command ran. Unlink refuses to guess that directory; pass the
original directory explicitly with `--legacy-root`. The directory itself no
longer needs to exist. A legacy chain containing more than one relative-path
manifest is refused because each link or sync invocation may have used a
different working directory and one root cannot resolve that chain safely.

OpenCode publication follows the route mode. `route` and `fuzzy` publish one
`tokn-router` provider with a deduplicated model list. `exact` uses the same
provider but publishes provider-qualified model IDs such as
`tokn-router/deepseek/deepseek-chat`. `switch` and `passthrough` publish pinned
providers such as `tokn-router-openai`, backed by provider-specific profiles.
The provider/profile layout is derived rather than configured independently:
normalized modes use one shared profile, raw main-account modes use one pinned
profile, and raw agent-owned modes use one profile per provider. The generated
profiles are the runtime materialization of `[agents.opencode].mode`; a
mismatch is configuration drift. Providers without a static model catalogue
remain usable with an existing custom selection, but cannot add discoverable
entries to OpenCode's model picker and produce a link warning.

Generated agent clients currently use a non-secret sentinel API key. Therefore
link and sync reject every mode when `[api_key].enabled = true`, including
`passthrough`, because it would bypass the requested client-authentication
boundary. Disable gateway API-key enforcement before linking until
agent-scoped client-key provisioning is supported.

Agent-owned links also check global OpenCode agent and command Markdown files
before transferring credentials. A `model` frontmatter entry that still names
a transferred provider blocks the link and reports its generated replacement.
Project-local `.opencode` Markdown files cannot be discovered by a global link,
so update those model references to the generated `tokn-router` namespace
manually; the link plan prints this reminder.

## Proxy Mode

The proxy runs a local HTTP CONNECT forward proxy. Requests for recognized LLM
API hosts are intercepted and routed through the same account pool; unrelated
hosts are tunneled through untouched.

```sh
tokn-gateway proxy start
tokn-gateway proxy ca show
eval "$(tokn-gateway proxy env)"
```

The generated environment includes:

- `HTTPS_PROXY` and `HTTP_PROXY`.
- `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and
  `GIT_SSL_CAINFO` pointing at a merged system-root plus tokn CA bundle.
- `NODE_EXTRA_CA_CERTS` pointing at the tokn CA certificate.
- `NO_PROXY` for local loopback addresses.

Useful wrappers:

```sh
tokn-gateway proxy shell
tokn-gateway proxy codex --help
tokn-gateway proxy exec curl https://api.openai.com/v1/models
```

Proxy config:

```toml
[proxy_mode]
host = "127.0.0.1"
port = 4142
route_mode = "route"

[proxy_mode.provider_modes]
# openai = "switch"
# github-copilot = "passthrough"

# Optional; defaults to ~/.tokn/router/ca
# ca_dir = "/some/path"

# Extend or trim the interception set.
# intercept_hosts = ["my-gateway.example.com"]
# passthrough_hosts = ["api.githubcopilot.com"]
```

Run the legacy-configured proxy as a separate process with `tokn-gateway proxy
start`, or serve it with the API through the v2 runtime:

```sh
tokn-gateway serve --with-proxy
tokn-gateway serve --with-proxy --proxy-route-mode exact
```

The projection preserves the proxy bind, CA directory, built-in/custom
interception hosts, passthrough hosts, static route mode, and resolvable
provider-specific `switch`/`passthrough` modes. Proxy `passthrough` preserves
the original destination and client credentials; proxy `switch` preserves the
destination and injects a matching account credential. Wildcard host entries
are rejected because the legacy proxy treated them as literal strings while
v2 treats them as patterns.

Per-request `x-route-mode` and Basic proxy-auth username mode overrides are not
projected. Native v2 configs can declare one or more `forward_proxy` listeners
and serve them together with API listeners without compatibility flags.

## LAN Bootstrap

By default, listeners must bind to loopback. To expose a trusted LAN gateway,
bind explicitly and opt into the risk:

```sh
tokn-gateway proxy start --host 0.0.0.0 --insecure-allow-remote
```

Standalone `proxy start` exposes helper routes through plain HTTP requests to
the proxy listener:

- `/-/lan/bootstrap.json`
- `/-/lan/ca.crt`
- `/-/lan/env?shell=sh|bash|zsh|fish|pwsh`

The projected v2 listener created by `serve --with-proxy` does not expose these
bootstrap helpers. Distribute and trust the configured CA separately when
using that listener from another machine.

The proxy prints the CA SHA-256 fingerprint at startup. Verify that fingerprint
before trusting a CA fetched over the LAN. The private CA key is never served.

## Development

This is a Rust workspace. The runtime entrypoint lives in
`crates/gateway-cli`; `crates/router` owns the HTTP API/router/proxy wiring.

```sh
cargo fmt --all
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

Schema snapshots track the active release line in `VERSION`. If `VERSION` is on
`v0.2.x`, keep snapshot updates on the existing `v0.2.0.sql` files.

## License

MIT.

## Inspiration

Inspired by [`sub2api`](https://github.com/Wei-Shaw/sub2api).

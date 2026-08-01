# Scripts

This directory contains repo-local helper tooling that should not make the Rust
workspace root a JavaScript package.

## Docker PR Trial

Download and load the `tokn-gateway-cli-image` artifact from CI, build the agent
runner image once, and start the gateway:

```sh
bun --cwd scripts docker load --pr 67
```

This tags the loaded gateway image as `tokn-gateway-cli:pr-67`.

To load the latest successful artifact from a branch:

```sh
bun --cwd scripts docker load --branch main
```

This tags the loaded gateway image as `tokn-gateway-cli:main`.

If you already downloaded the artifact tar manually:

```sh
bun --cwd scripts docker load --tag pr-67 ./tokn-gateway-cli-image.tar
```

Then:

```sh
bun --cwd scripts docker build-agent
bun --cwd scripts docker up --tag pr-67 --copy-local-config
```

The gateway image runs `tokn-gateway serve` without listener overrides. A fresh
tag-scoped volume must therefore be seeded with a schema-version 2
`config.toml`; subsequent `up` commands reuse that config and can omit
`--copy-local-config`.

To seed the tag-scoped gateway volume from local router state when the server is
created:

```sh
bun --cwd scripts docker up --tag pr-67 --copy-local-config
bun --cwd scripts docker up --tag pr-67 --copy-local-accounts
```

`--copy-local-config` copies `~/.tokn/router/config.toml` and `auth.yaml`.
`--copy-local-accounts` copies only `auth.yaml`. Existing target files are not
overwritten unless `--force-copy-local` is also passed. Runtime state such as
`ca/`, cache, DBs, logs, and request records is never copied by these options.

`up` does not expose host ports by default, so multiple PR gateways can run at
the same time. A v2 config can declare any number of listeners on arbitrary
ports, so host publication uses an explicit `HOST_PORT:LISTENER_PORT` mapping:

```sh
bun --cwd scripts docker up --tag pr-67 --publish 5141:4141 --publish 5152:4142
```

The listener must bind an address reachable through the container port mapping.
The v2 config compiler requires `client_auth = "local_keys"` and
`allow_insecure_public = true` for non-loopback binds.

Run disposable agent containers against that gateway:

```sh
bun --cwd scripts docker agent --tag pr-67 --agent opencode --transport api
bun --cwd scripts docker agent --tag pr-67 --agent codex --transport proxy
```

Agent containers share the gateway container's network namespace, so loopback
listeners remain loopback-only. API transport defaults to
`http://127.0.0.1:4141/v1`; set `TOKN_GATEWAY_API_URL` to select a different API
listener. Proxy transport resolves the configured listener through the
gateway's v2 proxy helper. If the config contains more than one forward proxy,
select one explicitly:

```sh
bun --cwd scripts docker agent --tag pr-67 --agent codex --transport proxy --listener work
```

When that listener has interception material, the runner copies only its public
CA certificate into the disposable agent container. It does not mount gateway
credentials or the private CA key.

Forward arguments to the selected agent after `--`:

```sh
bun --cwd scripts docker agent --tag pr-67 --agent codex --transport api -- --help
```

The CLI adds an interactive TTY only when stdin and stdout both look
interactive. If Podman still warns about a non-TTY input device in a scripted
run, disable TTY allocation explicitly:

```sh
bun --cwd scripts docker agent --tag pr-67 --no-tty --agent codex --transport api -- --help
```

Transports:

- `api`: point the agent at the configured LLM API listener.
- `proxy`: use the selected forward-proxy listener.

Routing behavior is not a runner mode. The v2 listener's bindings select
profiles, and profiles select managed, relay, or transparent routes.

Lifecycle:

```sh
bun --cwd scripts docker status --tag pr-67
bun --cwd scripts docker logs --tag pr-67
bun --cwd scripts docker down --tag pr-67
```

`down` keeps the persistent gateway state volume. To remove containers and
volumes, use the explicit reset guard:

```sh
bun --cwd scripts docker reset --tag pr-67 --yes
```

The CLI uses Podman by default. Set `TOKN_CONTAINER_ENGINE=docker` only if you
want the same lifecycle managed through Docker-compatible commands.

Omit `--tag` to use the default `ci` tag, or set `TOKN_TAG=pr-67` to make a tag
the default for one shell session.

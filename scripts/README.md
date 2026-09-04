# Scripts

This directory contains repo-local helper tooling that should not make the Rust
workspace root a JavaScript package.

## Docker PR Trial

For native v2 configurations, use [the standard Docker setup](../docs/docker.md).
The older Bun trial helper below still supplies legacy `serve --with-proxy`
flags and requires a compatible v1 config with client authentication enabled.
It stops containers with a 40-second grace period before removing them.

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
bun --cwd scripts docker up --tag pr-67
```

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
the same time. Expose ports only when you want to call the gateway from the host:

```sh
bun --cwd scripts docker up --tag pr-67 --port 5141 --proxy-port 5152
```

Run disposable agent containers against that gateway:

```sh
bun --cwd scripts docker agent --tag pr-67 --agent opencode --mode api-route
bun --cwd scripts docker agent --tag pr-67 --agent codex --mode proxy-switch
```

Forward arguments to the selected agent after `--`:

```sh
bun --cwd scripts docker agent --tag pr-67 --agent codex --mode api-route -- --help
```

The CLI adds an interactive TTY only when stdin and stdout both look
interactive. If Podman still warns about a non-TTY input device in a scripted
run, disable TTY allocation explicitly:

```sh
bun --cwd scripts docker agent --tag pr-67 --no-tty --agent codex --mode api-route -- --help
```

Modes:

- `api-route`: point the agent at `http://gateway:4141/v1`; gateway owns
  credentials and routing.
- `proxy-switch`: run through `http://gateway:4142`; gateway injects upstream
  credentials for recognized providers.
- `api-passthrough`: diagnostic API passthrough endpoint.
- `proxy-passthrough`: diagnostic transparent proxy passthrough; the concrete
  agent may need its own upstream login.

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

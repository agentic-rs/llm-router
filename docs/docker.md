# Running the gateway in Docker

The image runs `tokn-gateway serve`. It does not override listener addresses,
authentication, or the number of listeners. Mount a configured router state
directory; the image does not provision upstream accounts or an unauthenticated
public listener.

For a new, isolated state directory:

```sh
mkdir -p router-state
cp examples/docker/config.toml router-state/config.toml
docker run --rm -v "$(pwd)/router-state:/root/.tokn/router" \
  tokn-gateway-cli:local api-key create local-client
docker run --name tokn-gateway --stop-timeout 40 \
  -p 127.0.0.1:4141:4141 \
  -v "$(pwd)/router-state:/root/.tokn/router" tokn-gateway-cli:local
```

Use your actual image tag in place of `tokn-gateway-cli:local`. Save the generated
client key and send it in `Authorization: Bearer KEY`. The sample configuration
uses `client_auth = "local_keys"` and explicitly allows plaintext on the
container's non-loopback interface. Publish only on host loopback as above, or
terminate TLS on a trusted network. Upstream accounts are managed separately
with the account commands in the same mounted state directory.

## Shutdown

`serve` handles SIGINT and SIGTERM (Ctrl-C and Ctrl-Break on Windows). It stops
accepting connections, allows active API and decoded proxy HTTP requests up to
30 seconds to finish, then cancels and joins remaining connection tasks. Idle
HTTP keep-alive connections close immediately. Opaque CONNECT tunnels close
immediately because they have no HTTP request boundary to drain. The standalone
legacy `proxy start` also handles termination signals and bounds connection
draining to 30 seconds, but cannot distinguish idle from active legacy tunnels.

Request, usage, session, and archival handlers then get up to five seconds for
cleanup. A drain or cleanup timeout is logged and returns a nonzero exit status;
timed-out cleanup cannot guarantee that every queued record was written. The
async runtime gets a final one-second bounded wait for blocking background
tasks. Allow at least 40 seconds before a supervisor force-kills the process:

```sh
docker stop --time 40 tokn-gateway
```

A listener startup/runtime failure stops and drains sibling listeners before
the same cleanup path runs. Invalid configuration or a failed listener never
leaves a partially serving process running.

CI runs `bash scripts/docker/smoke.sh IMAGE` against the built image with
disposable state. It checks default-command startup, unauthenticated rejection,
authenticated discovery, and successful SIGTERM cleanup without upstream calls.

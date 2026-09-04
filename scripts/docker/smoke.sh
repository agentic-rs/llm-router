#!/usr/bin/env bash
# CI-only disposable state; no local config, credentials, or upstream calls.
set -euo pipefail

image=${1:?usage: bash scripts/docker/smoke.sh IMAGE}
smoke_volume=
smoke_container=
cleanup() {
  if [ -n "$smoke_container" ]; then
    docker logs "$smoke_container" 2>&1 || true
    docker rm -f "$smoke_container" >/dev/null 2>&1 || true
  fi
  if [ -n "$smoke_volume" ]; then
    docker volume rm "$smoke_volume" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
# An engine-owned volume also works with remote/rootless engines, where host
# temporary directories can have incompatible ownership or mount permissions.
smoke_volume=$(docker volume create)
smoke_container=$(docker create --stop-timeout 40 \
  -v "$smoke_volume:/root/.tokn/router" -p 127.0.0.1::4141 "$image")
docker cp examples/docker/config.toml "$smoke_container:/root/.tokn/router/config.toml"

token=$(docker run --rm -v "$smoke_volume:/root/.tokn/router" "$image" api-key create smoke | sed -n 's/^key: //p')
test -n "$token"
docker start "$smoke_container" >/dev/null
address=$(docker port "$smoke_container" 4141/tcp)
# Refuse to test a publicly published plaintext listener, even if a future
# command edit accidentally removes the explicit host address above.
if [[ ! "$address" =~ ^127\.0\.0\.1:[0-9]+$ ]]; then
  echo "unsafe Docker publication: $address (expected host loopback)" >&2
  exit 1
fi
status=000
for attempt in {1..30}; do
  status=$(curl --noproxy '*' --connect-timeout 1 --max-time 2 -s -o /dev/null -w '%{http_code}' "http://$address/v1/models") || true
  if [ "$status" = 401 ]; then break; fi
  sleep 1
done
test "$status" = 401
curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  -H "Authorization: Bearer $token" "http://$address/v1/models" >/dev/null
docker stop --time 40 "$smoke_container"
test "$(docker inspect --format '{{.State.ExitCode}}' "$smoke_container")" = 0
docker logs "$smoke_container" 2>&1 | grep -q 'shutdown persistence cleanup complete'
echo 'Docker startup, authentication, and SIGTERM cleanup passed'

#!/bin/sh
set -eu

agent="${TOKN_AGENT:-codex}"
transport="${TOKN_TRANSPORT:-api}"
api_url="${TOKN_GATEWAY_API_URL:-http://127.0.0.1:4141}"
proxy_url="${TOKN_GATEWAY_PROXY_URL:-http://127.0.0.1:4142}"
ca_dir="${TOKN_AGENT_CA_DIR:-/tmp/tokn-router/ca}"
ca_cert="$ca_dir/ca.crt"
ca_bundle="$ca_dir/ca-bundle.crt"

case "$agent" in
  codex)
    agent_cmd="${TOKN_CODEX_CMD:-codex}"
    ;;
  opencode)
    agent_cmd="${TOKN_OPENCODE_CMD:-opencode}"
    ;;
  pi)
    agent_cmd="${TOKN_PI_CMD:-pi}"
    ;;
  *)
    echo "tokn-agent: unsupported TOKN_AGENT '$agent' (expected codex, opencode, or pi)" >&2
    exit 64
    ;;
esac

install_ca() {
  source_cert="${TOKN_GATEWAY_CA_CERT:-}"
  if [ -z "$source_cert" ]; then
    return
  fi
  if [ ! -s "$source_cert" ]; then
    echo "tokn-agent: gateway CA is missing or empty: $source_cert" >&2
    exit 1
  fi
  mkdir -p "$ca_dir"
  if [ "$source_cert" != "$ca_cert" ]; then
    cp "$source_cert" "$ca_cert"
  fi
  if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cat /etc/ssl/certs/ca-certificates.crt "$ca_cert" > "$ca_bundle"
  else
    cp "$ca_cert" "$ca_bundle"
  fi
  export NODE_EXTRA_CA_CERTS="$ca_cert"
  export SSL_CERT_FILE="$ca_bundle"
  export CODEX_CA_CERTIFICATE="$ca_bundle"
  export REQUESTS_CA_BUNDLE="$ca_bundle"
  export CURL_CA_BUNDLE="$ca_bundle"
  export GIT_SSL_CAINFO="$ca_bundle"
}

case "$transport" in
  api)
    export OPENAI_BASE_URL="$api_url/v1"
    export OPENAI_API_KEY="${OPENAI_API_KEY:-tokn-local}"
    export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-tokn-local}"
    ;;
  proxy)
    install_ca
    export HTTPS_PROXY="${HTTPS_PROXY:-$proxy_url}"
    export HTTP_PROXY="${HTTP_PROXY:-$proxy_url}"
    export ALL_PROXY="${ALL_PROXY:-$HTTPS_PROXY}"
    export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1,::1}"
    ;;
  *)
    echo "tokn-agent: unsupported TOKN_TRANSPORT '$transport' (expected api or proxy)" >&2
    exit 64
    ;;
esac

echo "tokn-agent: agent=$agent transport=$transport command=$agent_cmd" >&2
exec "$agent_cmd" "$@"

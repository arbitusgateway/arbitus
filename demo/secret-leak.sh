#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${TMPDIR:-/tmp}/arbitus-secret-leak-demo"
GATEWAY_ADDR="${GATEWAY_ADDR:-127.0.0.1:4100}"
DUMMY_ADDR="${DUMMY_ADDR:-127.0.0.1:3100}"

GATEWAY_URL="http://${GATEWAY_ADDR}/mcp"
DUMMY_URL="http://${DUMMY_ADDR}/mcp"
CONFIG="${WORKDIR}/gateway.yml"
AUDIT_DB="${WORKDIR}/gateway-audit.db"
GATEWAY_LOG="${WORKDIR}/arbitus.log"
DUMMY_LOG="${WORKDIR}/dummy-server.log"

mkdir -p "$WORKDIR"
rm -f "$CONFIG" "$AUDIT_DB" "$GATEWAY_LOG" "$DUMMY_LOG"

cleanup() {
  if [[ -n "${GATEWAY_PID:-}" ]]; then
    kill "$GATEWAY_PID" >/dev/null 2>&1 || true
    wait "$GATEWAY_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${DUMMY_PID:-}" ]]; then
    kill "$DUMMY_PID" >/dev/null 2>&1 || true
    wait "$DUMMY_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_health() {
  local url="$1"
  for _ in $(seq 1 80); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "Timed out waiting for $url" >&2
  return 1
}

wait_for_mcp() {
  local url="$1"
  for _ in $(seq 1 80); do
    if curl -fsS -X POST "$url" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"demo"}}}' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "Timed out waiting for $url" >&2
  return 1
}

echo
echo "==> Building demo binaries"
cargo build --quiet --bin arbitus --bin dummy-server

echo
echo "==> Initializing a Claude Code starter policy"
target/debug/arbitus policy init claude-code --out "$CONFIG" --force
sed -i.bak \
  -e "s|addr: \"0.0.0.0:4000\"|addr: \"${GATEWAY_ADDR}\"|" \
  -e "s|upstream: \"http://localhost:3000/mcp\"|upstream: \"${DUMMY_URL}\"|" \
  -e "s|path: \"gateway-audit.db\"|path: \"${AUDIT_DB}\"|" \
  "$CONFIG"
rm -f "${CONFIG}.bak"
target/debug/arbitus validate "$CONFIG"

echo
echo "==> Starting dummy MCP server on ${DUMMY_ADDR}"
target/debug/dummy-server --addr "$DUMMY_ADDR" >"$DUMMY_LOG" 2>&1 &
DUMMY_PID=$!
wait_for_mcp "$DUMMY_URL"

echo "==> Starting Arbitus gateway on ${GATEWAY_ADDR}"
target/debug/arbitus "$CONFIG" >"$GATEWAY_LOG" 2>&1 &
GATEWAY_PID=$!
wait_for_health "http://${GATEWAY_ADDR}/health"

echo
echo "==> Initializing MCP session as claude-code"
INIT_RESPONSE="$(mktemp)"
curl -i -s "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": { "name": "claude-code", "version": "demo" }
    }
  }' | tee "$INIT_RESPONSE"

SESSION_ID="$(awk 'BEGIN{IGNORECASE=1} /^mcp-session-id:/ {gsub("\r","",$2); print $2}' "$INIT_RESPONSE")"
rm -f "$INIT_RESPONSE"

if [[ -z "$SESSION_ID" ]]; then
  echo "No Mcp-Session-Id returned by gateway" >&2
  exit 1
fi

echo
echo "==> Listing visible tools through Arbitus"
curl -s "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: ${SESSION_ID}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
echo

echo
echo "==> Attempting to exfiltrate a fake .env secret"
BLOCK_RESPONSE="$(curl -s "$GATEWAY_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: ${SESSION_ID}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "echo",
      "arguments": {
        "text": "OPENAI_API_KEY=sk-demo-secret"
      }
    }
  }')"
echo "$BLOCK_RESPONSE"

if [[ "$BLOCK_RESPONSE" != *"blocked: sensitive data detected"* ]]; then
  echo "Expected blocked secret response, got: $BLOCK_RESPONSE" >&2
  exit 1
fi

echo
echo "==> Audit log"
target/debug/arbitus audit "$AUDIT_DB" --agent claude-code --outcome blocked --limit 5

echo
echo "Demo complete. Logs and config are in $WORKDIR"

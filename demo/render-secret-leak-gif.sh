#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/docs/assets/secret-leak-demo.gif"
TMPDIR_RENDER="$(mktemp -d)"

cleanup() {
  rm -rf "$TMPDIR_RENDER"
}
trap cleanup EXIT

mkdir -p "$(dirname "$OUT")"

render_frame() {
  local index="$1"
  local text_file="$2"
  local frame="${TMPDIR_RENDER}/frame-${index}.png"

  magick -size 1200x760 xc:"#282a36" \
    -fill "#44475a" -draw "rectangle 0,0 1200,46" \
    -fill "#ff5555" -draw "circle 28,23 36,23" \
    -fill "#f1fa8c" -draw "circle 56,23 64,23" \
    -fill "#50fa7b" -draw "circle 84,23 92,23" \
    -font Liberation-Mono-Bold -pointsize 18 -fill "#f8f8f2" \
    -annotate +112+30 "Arbitus MCP firewall demo" \
    -font Liberation-Mono -pointsize 23 -fill "#f8f8f2" \
    -annotate +40+92 @"$text_file" \
    "$frame"
}

cat >"${TMPDIR_RENDER}/01.txt" <<'EOF'
$ cargo install arbitus
$ arbitus policy init claude-code --out gateway.yml

✓ wrote claude-code policy to gateway.yml

$ arbitus validate gateway.yml
✓ gateway.yml is valid

Policy:
  agent: claude-code
  allowed_tools: echo, read_file, list_directory, search_files
  denied_tools: write_file, delete_file, exec_*, shell_*, secret_dump
  block_patterns: api keys, bearer tokens, private keys, AWS keys
EOF

cat >"${TMPDIR_RENDER}/02.txt" <<'EOF'
$ ./demo/secret-leak.sh

==> Starting dummy MCP server on 127.0.0.1:3100
==> Starting Arbitus gateway on 127.0.0.1:4100

Agent (Claude Code)
        |
        v
      Arbitus  <--- auth, rate limit, payload filter, audit
        |
        v
  Dummy MCP server
EOF

cat >"${TMPDIR_RENDER}/03.txt" <<'EOF'
==> Initializing MCP session as claude-code

HTTP/1.1 200 OK
mcp-session-id: b875f4a4-516b-427e-98d5-17c90c6c92ab

==> Listing visible tools through Arbitus

{
  "result": {
    "tools": [
      { "name": "echo" }
    ]
  }
}

Hidden upstream tool: secret_dump
EOF

cat >"${TMPDIR_RENDER}/04.txt" <<'EOF'
==> Attempting to exfiltrate a fake .env secret

tools/call echo:
{
  "text": "OPENAI_API_KEY=sk-demo-secret"
}

Arbitus response:
{
  "error": {
    "code": -32603,
    "message": "blocked: sensitive data detected"
  }
}

The request never reaches the upstream MCP server.
EOF

cat >"${TMPDIR_RENDER}/05.txt" <<'EOF'
==> Audit log

AGE      AGENT        METHOD      TOOL  OUTCOME   REASON
---------------------------------------------------------------
0s ago   claude-code  tools/call  echo  blocked   sensitive data detected

What the demo proves:
  - agents connect through the gateway
  - tools/list is filtered
  - tools/call is enforced
  - secret-like payloads are blocked
  - every decision is auditable
EOF

render_frame 01 "${TMPDIR_RENDER}/01.txt"
render_frame 02 "${TMPDIR_RENDER}/02.txt"
render_frame 03 "${TMPDIR_RENDER}/03.txt"
render_frame 04 "${TMPDIR_RENDER}/04.txt"
render_frame 05 "${TMPDIR_RENDER}/05.txt"

magick -delay 180 "${TMPDIR_RENDER}/frame-01.png" \
  -delay 160 "${TMPDIR_RENDER}/frame-02.png" \
  -delay 190 "${TMPDIR_RENDER}/frame-03.png" \
  -delay 220 "${TMPDIR_RENDER}/frame-04.png" \
  -delay 220 "${TMPDIR_RENDER}/frame-05.png" \
  -loop 0 -layers Optimize "$OUT"

echo "✓ wrote $OUT"

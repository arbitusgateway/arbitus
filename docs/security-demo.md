# Security Demo: Block a Secret Leak

This demo shows the core Arbitus value proposition in a few commands: an agent tries to send a fake `.env` secret through an MCP tool call, and Arbitus blocks the request before it reaches the upstream server.

## 1. Start the dummy MCP server

In one terminal:

```sh
cargo run --bin dummy-server
```

The dummy server listens on `http://localhost:3000/mcp` and exposes an `echo` tool. The tool is intentionally harmless, which keeps the demo focused on gateway policy enforcement.

## 2. Start Arbitus with a starter policy

In another terminal:

```sh
cargo run --bin arbitus -- examples/policies/claude-code-readonly.yml
```

The policy allows Claude Code to call read-oriented tools, enables prompt-injection detection, and blocks common secret patterns such as API keys, bearer tokens, AWS keys, and private keys.

## 3. Initialize an MCP session

```sh
curl -i -s http://localhost:4000/mcp \
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
  }'
```

Copy the `Mcp-Session-Id` response header.

## 4. Confirm allowed tools are visible

Replace `<session-id>` with the value from the previous response:

```sh
curl -s http://localhost:4000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }'
```

Only tools allowed by the policy are returned to the agent. Hidden tools are still blocked if an agent tries to call them directly.

## 5. Try to exfiltrate a fake `.env` value

```sh
curl -s http://localhost:4000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session-id>" \
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
  }'
```

Expected result:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "error": {
    "code": -32603,
    "message": "blocked: sensitive data detected"
  }
}
```

The call is blocked and does not reach the dummy upstream.

## 6. Query the audit log

```sh
cargo run --bin arbitus -- audit gateway-audit.db --agent claude-code --outcome blocked --limit 5
```

The audit entry gives you the agent, method, tool, outcome, timestamp, and request ID. In production you can send the same events to SQLite, stdout, webhooks, CloudEvents, OpenLineage, Prometheus, and OpenTelemetry backends.

## What this proves

- Agents do not get direct, unrestricted access to MCP servers.
- `tools/list` can hide tools the agent should not know about.
- `tools/call` is enforced even if an agent guesses a hidden tool name.
- Secret-like payloads are blocked before reaching upstream.
- Every decision is auditable.

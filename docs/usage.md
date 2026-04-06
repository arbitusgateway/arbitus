# Usage

## HTTP mode

Start the gateway:

```sh
./arbitus gateway.yml
# or explicitly:
./arbitus start gateway.yml
```

Agents connect to `http://localhost:4000/mcp`. The gateway forwards allowed requests to the upstream MCP server.

Session management follows the MCP spec: the gateway assigns a `Mcp-Session-Id` on `initialize` and uses it to identify the agent on subsequent requests. Requests with a missing or expired session ID receive `404`.

To explicitly end a session, send `DELETE /mcp` with the session header:

```sh
curl -X DELETE http://localhost:4000/mcp -H "Mcp-Session-Id: <id>"
# 204 No Content on success, 404 if the session is already gone
```

## Rate-limit headers

Every `tools/call` response includes standard rate-limit headers:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 57
X-RateLimit-Reset: 42
```

When the limit is exceeded, the response also includes `Retry-After`:

```
HTTP/1.1 200 OK
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 38
Retry-After: 38
```

`X-RateLimit-Reset` and `Retry-After` are in seconds until the oldest request in the window ages out (max 60).

## Human-in-the-Loop (HITL)

Tools listed in `approval_required` are suspended until an operator takes action. The gateway holds the request open and waits up to `hitl_timeout_secs` (default: 60) before auto-rejecting.

List pending approvals:

```sh
curl http://localhost:4000/approvals \
  -H "Authorization: Bearer admin-secret"
```

```json
[
  {
    "id": "appr-abc-123",
    "agent_id": "cursor",
    "tool_name": "delete_file",
    "arguments": {"path": "/data/important.db"},
    "created_at": 1743375600
  }
]
```

Approve or reject:

```sh
# Approve
curl -X POST http://localhost:4000/approvals/appr-abc-123/approve \
  -H "Authorization: Bearer admin-secret"

# Reject with reason
curl -X POST http://localhost:4000/approvals/appr-abc-123/reject \
  -H "Authorization: Bearer admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"reason": "not authorized during off-hours"}'
```

Both endpoints return `204 No Content` on success, `404` if the approval ID is unknown or already resolved.

## Shadow mode

Tools listed in `shadow_tools` are intercepted after all middleware passes. The gateway logs them as `shadowed`, returns a mock success response to the agent, and does **not** forward the call to the upstream server.

This is useful for observing what a new agent would do with dangerous tools before granting real access.

```yaml
agents:
  new-agent:
    shadow_tools:
      - delete_file
      - "exec_*"
```

The agent receives:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "[shadow] call intercepted — not forwarded to upstream"}]
  }
}
```

Shadowed calls appear in the audit log with `outcome: shadowed`.

## Supply-chain security

When using stdio transport, verify the MCP server binary before spawning it:

```yaml
transport:
  type: stdio
  server: ["/usr/local/bin/mcp-server", "--data-dir", "/data"]
  verify:
    sha256: "e3b0c44298fc1c149afbf4c8996fb924..."  # hex SHA-256 of the binary
    cosign_bundle: "/etc/mcp/server.bundle"         # cosign bundle produced by `cosign sign-blob`
    cosign_identity: "ci@example.com"               # expected signer identity (keyless)
    cosign_issuer: "https://token.actions.githubusercontent.com"
```

Both `sha256` and `cosign_bundle` are optional and independent — configure one or both. If either check fails, the gateway aborts at startup before spawning the process.

To generate a `sha256` for your binary:

```sh
sha256sum /usr/local/bin/mcp-server
```

To sign a binary with cosign (keyless, via GitHub Actions OIDC):

```sh
cosign sign-blob --bundle server.bundle /usr/local/bin/mcp-server
```

## SSE streaming

Once a session is established, open a server-sent event stream to receive server-pushed notifications:

```sh
curl -N http://localhost:4000/mcp \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: <id>"
```

The gateway proxies the upstream SSE stream and applies `block_patterns` to each event before forwarding it to the client.

Without a session, `GET /mcp` returns an `endpoint` event (legacy HTTP+SSE transport):

```
event: endpoint
data: /mcp
```

## OpenAI Tools Bridge

`GET /openai/v1/tools` and `POST /openai/v1/execute` let OpenAI function-calling clients use arbitus without refactoring. All requests still pass through the full security pipeline (auth, rate limiting, payload filtering, audit).

## Tool Federation

Agents with `federate: true` aggregate tools from all named upstreams into a single merged view. Colliding tool names are prefixed with `<upstream>__`. `tools/call` is transparently routed to the correct upstream. Discovery has a 10-second global timeout to prevent slow upstreams from stalling the gateway.

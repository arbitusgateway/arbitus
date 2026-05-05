# Cursor Setup

Use this guide to put Arbitus between Cursor and your upstream MCP server.

Official Cursor MCP docs: <https://docs.cursor.com/context/model-context-protocol>

## 1. Start your upstream MCP server

For a local demo, use the included dummy server:

```sh
cargo run --bin dummy-server
```

For a real deployment, set `transport.upstream` in the policy to your MCP server URL.

## 2. Start Arbitus

Use the Cursor starter policy:

```sh
arbitus policy init cursor --out gateway.yml
arbitus gateway.yml
```

During local development from source:

```sh
cargo run --bin arbitus -- policy init cursor --out gateway.yml
cargo run --bin arbitus -- gateway.yml
```

This policy identifies Cursor by `clientInfo.name: cursor`, allows common read/search/edit tools, requires Human-in-the-Loop approval for edits, shadows command-like tools, redacts matching secrets, and logs every decision.

## 3. Add Arbitus to Cursor MCP config

Cursor supports project-scoped MCP configuration at `.cursor/mcp.json` and global configuration at `~/.cursor/mcp.json`.

Create `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "arbitus": {
      "url": "http://localhost:4000/mcp"
    }
  }
}
```

If your Cursor version requires an explicit transport type for HTTP servers, use:

```json
{
  "mcpServers": {
    "arbitus": {
      "type": "http",
      "url": "http://localhost:4000/mcp"
    }
  }
}
```

If Arbitus is protected by an API key, pass it as a header when your Cursor version supports headers for HTTP MCP servers:

```json
{
  "mcpServers": {
    "arbitus": {
      "type": "http",
      "url": "http://localhost:4000/mcp",
      "headers": {
        "X-Api-Key": "${ARBITUS_AGENT_API_KEY}"
      }
    }
  }
}
```

## 4. Verify Cursor sees the gateway

Open Cursor settings or the chat tool list and confirm the `arbitus` MCP server is connected. Cursor's Agent can use MCP tools from the available tools list when relevant.

Run a safe tool first. Then test a blocked path using the [Security demo](security-demo.md).

Query audit events:

```sh
arbitus audit gateway-audit.db --agent cursor --limit 20
```

## Production notes

- Keep `.cursor/mcp.json` project-specific when the MCP tools belong to a single repo.
- Use `~/.cursor/mcp.json` only for personal cross-project tools.
- Keep auto-run disabled for high-risk tools unless Arbitus policy requires approval or shadow mode.
- Use the Arbitus policy as the source of truth; Cursor's UI toggles are useful, but the gateway enforces policy even if an agent guesses a tool name directly.

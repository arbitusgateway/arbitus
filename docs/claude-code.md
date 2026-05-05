# Claude Code Setup

Use this guide to put Arbitus between Claude Code and your upstream MCP server.

Official Claude Code MCP docs: <https://code.claude.com/docs/en/mcp>

## 1. Start your upstream MCP server

For a local demo, use the included dummy server:

```sh
cargo run --bin dummy-server
```

For a real deployment, replace `transport.upstream` in the policy with your MCP server URL.

## 2. Start Arbitus

Use the read-only Claude Code starter policy:

```sh
arbitus policy init claude-code --out gateway.yml
arbitus gateway.yml
```

During local development from source:

```sh
cargo run --bin arbitus -- policy init claude-code --out gateway.yml
cargo run --bin arbitus -- gateway.yml
```

This policy identifies Claude Code by `clientInfo.name: claude-code`, exposes only read-oriented tools, blocks writes/deletes/command-like tools, rate-limits tool calls, and blocks common secret patterns.

## 3. Register Arbitus as Claude Code's MCP server

Claude Code supports remote HTTP MCP servers. Point Claude Code at Arbitus, not directly at the upstream MCP server:

```sh
claude mcp add --transport http arbitus http://localhost:4000/mcp
```

For a team-shared project config:

```sh
claude mcp add --transport http --scope project arbitus http://localhost:4000/mcp
```

For a user-wide config:

```sh
claude mcp add --transport http --scope user arbitus http://localhost:4000/mcp
```

If Arbitus is protected by an API key, add the header:

```sh
claude mcp add --transport http arbitus http://localhost:4000/mcp \
  --header "X-Api-Key: ${ARBITUS_AGENT_API_KEY}"
```

## 4. Verify Claude Code sees the gateway

List configured servers:

```sh
claude mcp list
```

Inside Claude Code, check MCP status:

```text
/mcp
```

Ask Claude Code to use a safe tool exposed by your upstream server. Arbitus should forward the allowed call and record it in the audit log.

## 5. Test the security path

Use the copy/paste walkthrough in [Security demo](security-demo.md), or ask Claude Code to summarize why it cannot send a fake `.env` value through the MCP tool.

Then query blocked events:

```sh
arbitus audit gateway-audit.db --agent claude-code --outcome blocked --limit 10
```

## Production notes

- Use `--scope project` for team-shared MCP configuration and keep secrets out of committed files.
- Prefer environment variables or secret managers for `api_key`, JWT secrets, and upstream credentials.
- Add `approval_required` for write, delete, deploy, database mutation, and command-like tools.
- Keep Claude Code connected to Arbitus instead of direct upstream MCP endpoints so audit and policy stay centralized.

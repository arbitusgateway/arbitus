# Discord Announcements

## MCP Discord (if applicable)

**Channel**: #announcements or #projects

---

🚀 **New MCP Security Project: Arbitus**

Hey everyone! I built a security proxy for MCP servers and wanted to share it here.

**The problem**: 
- 92% of MCP servers carry high security risk
- Tool poisoning, prompt injection, over-scoped auth are real attack vectors
- Official roadmap: security is "on the horizon"

**What it does**:
A proxy that sits between AI agents and MCP servers, enforcing policies before any tool call reaches upstream:

✅ Per-agent auth (API key, JWT/OIDC, mTLS)
✅ tools/list filtering
✅ Rate limiting (per-agent, per-tool, per-IP)
✅ Human-in-the-Loop approvals
✅ Payload + response filtering
✅ Prompt injection detection
✅ OPA/Rego policies
✅ Audit logging
✅ Circuit breaker

**Tech stack**:
- Written in Rust (sub-millisecond overhead)
- MIT licensed
- 446 unit tests, 22 e2e sections
- Works with Cursor, Claude, Windsurf, any MCP client

**Quick start**:
```bash
cargo install arbitus
```

GitHub: https://github.com/arbitusgateway/arbitus

Would love feedback from folks deploying MCP in production!

---

## Claude Discord

**Channel**: #general or #tools

---

**New Tool: Arbitus - Security Proxy for MCP**

For teams using Claude with MCP tools, I built a security proxy that sits between Claude and your MCP servers.

It adds:
- Per-agent authentication (API key, JWT)
- Tool allowlists/denylists
- Rate limiting
- Human-in-the-Loop approvals for sensitive operations
- Audit logging
- Prompt injection filtering

Example use case: You want Claude to read files but not delete them, and you want to approve any write operations before they happen.

Rust-based, sub-millisecond overhead, open source (MIT).

GitHub: https://github.com/arbitusgateway/arbitus

Happy to answer questions!

---

## Cursor Discord

**Channel**: #general or #tools

---

**New Tool: Arbitus - Security Gates for Cursor's MCP Tools**

If you're using Cursor with MCP servers, I built a security proxy that can:

- Control which tools Cursor can access
- Rate-limit tool calls
- Require approval before sensitive operations
- Log all tool calls for audit
- Block prompt injection attempts

It sits between Cursor and your MCP servers, enforcing policies before any tool call.

Rust-based, minimal overhead, MIT licensed.

GitHub: https://github.com/arbitusgateway/arbitus

Docs: https://github.com/arbitusgateway/arbitus#documentation

---

## Rust Discord

**Channel**: #showcase

---

**[Showcase] Arbitus - MCP Security Proxy**

Hi #showcase! I built a security proxy for MCP (Model Context Protocol) servers in Rust.

Architecture:
- Middleware pipeline with trait-based design
- Each middleware returns `Decision` (Allow/Block/Redact)
- Tokio async runtime
- Axum for HTTP
- GCRA rate limiting (lock-free, O(1))
- SQLite with hash-chain audit integrity

Key things I'm happy with:
- Sub-millisecond overhead
- Static binary, no runtime deps
- Memory-safe in a security-critical component
- Clean trait abstraction for extensibility

Test coverage: 446 unit tests, 22 e2e test sections

GitHub: https://github.com/arbitusgateway/arbitus

Feedback on async patterns and middleware design welcome!

---

## AI Agents Discord (if applicable)

**Channel**: #projects or #tools

---

🛡️ **Arbitus: Security Gateway for AI Agents**

If you're deploying AI agents with tool access (MCP), security should be a first-class concern.

I built Arbitus to be that security layer:

- **Authentication**: API key, JWT/OIDC, mTLS per-agent
- **Authorization**: Tool allowlists/denylists
- **Rate limiting**: Prevent runaway agents
- **HITL**: Require human approval for sensitive ops
- **Audit**: Log every tool call
- **Filtering**: Block sensitive patterns in payloads and responses

The gap is real: 92% of MCP servers have security issues, and the official roadmap doesn't prioritize this.

Rust-based, minimal overhead, open source.

GitHub: https://github.com/arbitusgateway/arbitus
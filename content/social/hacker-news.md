# Hacker News "Show HN" Post

---

## Recommended: Focus on Problem/Solution

**Title**: Show HN: Arbitus, a Rust security proxy for MCP tool calls

**Body**:

I built Arbitus because MCP adoption is moving faster than MCP governance.

MCP is how AI agents connect to tools such as filesystems, databases, internal APIs, browser automation, and deployment systems. That is useful, but it also means agents can now reach tools that need normal security controls: identity, least privilege, rate limits, approval workflows, payload filtering, and audit logs.

Arbitus is an open-source security proxy that sits between agents and MCP servers. It enforces policy before any tool call reaches upstream:

- Per-agent auth (API key, JWT/OIDC, mTLS)
- tools/list filtering (agents only see allowed tools)
- Rate limiting (per-agent, per-tool, per-IP)
- Human-in-the-Loop approval workflow
- Payload + response filtering (encoding-aware)
- Prompt injection detection
- OPA/Rego policy engine
- Schema validation
- Audit logging (SQLite, webhook, OpenLineage)
- Circuit breaker

The most useful demo is simple: point Claude Code or Cursor at Arbitus instead of directly at an MCP filesystem server, then try to send a fake `.env` value through a tool call. Arbitus blocks it before it reaches upstream and records the decision in the audit log.

Why Rust? This is latency-sensitive security infrastructure. The gateway is a static binary, has no Python/npm runtime in the hot path, and keeps policy enforcement cheap enough that developers should not feel tempted to bypass it.

Quick start:

```bash
cargo install arbitus
```

```yaml
agents:
  cursor:
    allowed_tools: [read_file]
    rate_limit: 30
rules:
  block_patterns: ["password", "api_key"]
  block_prompt_injection: true
```

There are also starter policies for Claude Code, Cursor, and OpenAI Agents SDK clients in `examples/policies/`.

GitHub: https://github.com/arbitusgateway/arbitus

I would like feedback from folks deploying MCP in production or reviewing it from a security/platform perspective. What controls are missing before you would let agents reach internal tools?

---

## Option 2: Focus on Numbers

**Title**: Show HN: I analyzed 1,808 MCP servers – 92% have security issues. So I built this

**Body**:

After analyzing the MCP ecosystem, I found:

- 92% of MCP servers carry high security risk [1]
- 66% had security findings across 1,808 servers [2]
- 30 CVEs in 60 days (2026) [3]
- Official roadmap: security is "on the horizon"

So I built Arbitus — a security proxy for MCP servers.

It sits between AI agents (Cursor, Claude, Windsurf) and MCP servers, enforcing policies before any tool call reaches upstream:

**Auth & Access**:
- Per-agent authentication (API key, JWT/OIDC, mTLS)
- Tool allowlists/denylists with glob wildcards
- tools/list filtering (agents only see what they're allowed)

**Rate Limiting**:
- Sliding window per-agent
- Per-tool limits
- Per-IP infrastructure protection

**Security**:
- Human-in-the-Loop approval workflow
- Payload filtering (encoding-aware: Base64, URL, Unicode)
- Response filtering (blocks sensitive data in tool responses)
- Prompt injection detection
- Schema validation against inputSchema
- OPA/Rego policy engine

**Operations**:
- Circuit breaker for upstream failures
- Audit logging (SQLite, webhook, OpenLineage, CloudEvents)
- Hot-reload config (SIGUSR1 or 30s poll)
- Both HTTP+SSE and stdio transports

Tech: Rust, sub-millisecond overhead, static binary, 446 tests.

Quick start:

```bash
cargo install arbitus
```

GitHub: https://github.com/arbitusgateway/arbitus

[1] https://ienable.ai/blog/mcp-security-enterprise-governance-guide
[2] https://www.reddit.com/r/netsec/comments/1rtxacu/analysis_of_1808_mcp_servers_66_had_security/
[3] https://news.ycombinator.com/item?id=47356600

---

## Option 3: Focus on Gap in Official Roadmap

**Title**: Show HN: MCP security is "on the horizon" in the roadmap. I didn't want to wait.

**Body**:

MCP (Model Context Protocol) is how AI agents connect to tools. The ecosystem is exploding — 132M npm downloads, 70× YoY growth.

But security is an afterthought:

- 92% of MCP servers carry high security risk
- Tool poisoning attacks are real
- Prompt injection in tool responses
- Over-scoped OAuth tokens
- The official roadmap lists security as "on the horizon"

So I built Arbitus — a security proxy that sits between agents and MCP servers.

What it does:

1. Per-agent auth (API key, JWT/OIDC, mTLS)
2. Tool allowlists/denylists
3. Rate limiting (agent + tool + IP)
4. Human-in-the-Loop approvals for risky operations
5. Payload + response filtering
6. Prompt injection detection
7. OPA/Rego policy engine
8. Audit logging
9. Circuit breaker

Why Rust? Security infrastructure should minimize its own attack surface. Static binary, no runtime dependencies, sub-millisecond overhead.

446 tests, MIT licensed, docs included.

```bash
cargo install arbitus
```

GitHub: https://github.com/arbitusgateway/arbitus

If you're deploying AI agents with MCP, you need governance. This fills the gap.

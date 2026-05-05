# LinkedIn Post

---

## Main Post (Longer, more professional tone)

I've been following the rapid adoption of Model Context Protocol (MCP) in enterprise AI deployments. The numbers are striking:

📈 132 million monthly npm downloads (70× year-over-year growth)
🏢 28% of Fortune 500 companies using MCP
⚠️ But here's the concern: 92% of MCP servers carry high security risk

The security research is clear: tool poisoning, prompt injection, over-scoped OAuth tokens, and output poisoning are real attack vectors. Yet the official MCP roadmap lists security as "on the horizon."

I believe enterprises deploying AI agents shouldn't wait.

So I built Arbitus.

Arbitus is a security proxy that sits between AI agents (Cursor, Claude, Windsurf) and MCP servers. It enforces policies BEFORE any tool call reaches upstream:

✅ Per-agent authentication (API key, JWT/OIDC, mTLS)
✅ Tool allowlists/denylists with pattern matching
✅ Rate limiting (per-agent, per-tool, per-IP)
✅ Human-in-the-Loop approval workflows
✅ Payload and response filtering
✅ Prompt injection detection
✅ Audit logging with integrity verification
✅ OPA/Rego policy engine

Built in Rust for minimal overhead — sub-millisecond latency, no GC pauses, static binary with minimal attack surface.

Open source (MIT), fully tested (446 unit tests, 22 e2e sections), and documented.

If your organization is deploying AI agents with tool access, security governance shouldn't be an afterthought.

GitHub: https://github.com/arbitusgateway/arbitus

#AI #Security #Rust #OpenSource #EnterpriseAI #MCP #AIInfrastructure

---

## Shorter Post

92% of MCP servers have security issues.

AI agents are increasingly connected to file systems, databases, and cloud infrastructure. But the standard MCP SDK doesn't include:
- Per-agent authentication
- Tool access controls
- Rate limiting
- Audit logging

I built Arbitus to fill this gap — a security proxy that governs agent-to-server communication with:
- Per-agent auth (API key, JWT, mTLS)
- Human-in-the-Loop approvals
- Payload + response filtering
- Prompt injection detection
- Full audit logging

Rust-based, sub-millisecond overhead, open source.

GitHub: https://github.com/arbitusgateway/arbitus

#AI #Security #MCP #Rust
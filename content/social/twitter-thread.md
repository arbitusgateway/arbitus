# Twitter/X Thread

## Launch Thread (10 tweets)

---

**Tweet 1/10**

🚨 92% of MCP servers have security issues.

30 CVEs in 60 days. Tool poisoning. Prompt injection. Over-scoped OAuth.

The official roadmap lists security as "on the horizon."

I built a fix. Introducing Arbitus:

https://github.com/arbitusgateway/arbitus

🧵👇

---

**Tweet 2/10**

Arbitus is a security proxy that sits between AI agents (Cursor, Claude, Windsurf) and MCP servers.

It enforces policies BEFORE any tool call reaches upstream:

✅ Per-agent auth (API key, JWT, mTLS)
✅ Rate limiting
✅ tools/list filtering
✅ Human-in-the-Loop approvals

---

**Tweet 3/10**

Key security features:

🛡️ Prompt injection detection (built-in heuristics)
🔒 Payload filtering (encoding-aware: Base64, URL, Unicode)
📋 Schema validation against inputSchema
👤 Human-in-the-Loop approval workflow
🔍 Audit logging (SQLite + webhook + OpenLineage)

---

**Tweet 4/10**

Every competitor is Go, Python, or TypeScript.

Arbitus is Rust-native:

⚡ Sub-millisecond overhead
📦 Static binary, no runtime deps
🔒 Memory-safe without GC pauses
🦀 Zero CVEs from supply chain

Security infrastructure should minimize its own attack surface.

---

**Tweet 5/10**

Quick example:

```yaml
agents:
  cursor:
    allowed_tools: [read_file]
    rate_limit: 30

rules:
  block_patterns: ["password"]
  block_prompt_injection: true
```

```bash
cargo install arbitus
./arbitus gateway.yml
```

That's it. Your agents are now gated.

---

**Tweet 6/10**

How does it compare?

| Feature | Arbitus | docker/mcp-gateway |
|---------|---------|-------------------|
| HITL approvals | ✅ | ❌ |
| Prompt injection | ✅ | ❌ |
| OPA/Rego | ✅ | ❌ |
| Response filtering | ✅ | ❌ |
| Supply chain verify | ✅ | Docker-only |

Full comparison in the README.

---

**Tweet 7/10**

Test coverage:

✅ 446 unit tests
✅ 22 e2e test sections
✅ Security coverage tests
✅ Attack scenarios

CI runs on every push. Zero warnings from clippy.

---

**Tweet 8/10**

The numbers:

📈 132M monthly npm downloads (70× YoY)
🏢 28% of Fortune 500 using MCP
⚠️ 92% of servers carry high risk
📅 Security on official roadmap: "on the horizon"

This gap needs filling. Now.

---

**Tweet 9/10**

Open source, MIT licensed:

- 6 comprehensive docs
- GOVERNANCE.md for contributions
- SECURITY.md for disclosure process
- CODE_OF_CONDUCT.md

Ready for community contributions:

https://github.com/arbitusgateway/arbitus

---

**Tweet 10/10**

If you're deploying AI agents with MCP, you need a gateway.

Security shouldn't be "on the horizon."

⭐ Star: https://github.com/arbitusgateway/arbitus
📖 Docs: https://github.com/arbitusgateway/arbitus#documentation
💬 Discuss: https://github.com/arbitusgateway/arbitus/discussions

🦀 Built with Rust. Ready for production.

---

## Alternative Short Thread (5 tweets)

**Tweet 1**

I analyzed 1,808 MCP servers.

66% had security findings. 92% carry high risk.

The official roadmap: security is "on the horizon."

So I built Arbitus — a Rust security proxy for MCP servers.

🦀 Open source
⚡ Sub-ms overhead
🔒 Full security stack

https://github.com/arbitusgateway/arbitus

---

**Tweet 2**

What arbitus does:

• Per-agent auth (API key, JWT, mTLS)
• Rate limiting (sliding window)
• Human-in-the-Loop approvals
• Prompt injection detection
• Payload + response filtering
• OPA/Rego policies
• Audit logging

All before any tool reaches upstream.

---

**Tweet 3**

Why Rust?

Every competitor is Go/Python/TS.

Rust:
- No GC pauses (latency-sensitive)
- Static binary (minimal attack surface)
- Memory-safe (critical for security infra)
- Sub-millisecond overhead

After the LiteLLM supply chain attack, this matters.

---

**Tweet 4**

Quick start:

```bash
cargo install arbitus
```

```yaml
agents:
  cursor:
    allowed_tools: [read_file]
rules:
  block_prompt_injection: true
```

Your agents are now gated.

446 tests. 22 e2e sections. MIT licensed.

---

**Tweet 5**

AI agents are powerful. They need governance.

Arbitus: security for MCP, not "on the horizon."

⭐ https://github.com/arbitusgateway/arbitus
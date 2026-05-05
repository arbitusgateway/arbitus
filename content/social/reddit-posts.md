# Reddit Posts

## r/MCP Post

**Title**: [Project] Arbitus: Open-source security proxy for MCP - auth, rate limiting, HITL, audit logging

**Body**:

Hey r/MCP,

I've been working on **[Arbitus](https://github.com/arbitusgateway/arbitus)**, a security proxy that sits between AI agents and MCP servers. I wanted to share it here since security is becoming a real concern as MCP adoption grows.

## The Problem

- 92% of MCP servers carry high security risk ([iEnable](https://ienable.ai/blog/mcp-security-enterprise-governance-guide))
- 30 CVEs in MCP ecosystem in 60 days
- Official roadmap lists security as "on the horizon"

## What Arbitus Does

It's a proxy that enforces policies *before* any tool call reaches the upstream MCP server:

- **Per-agent auth** (API key, JWT/OIDC, mTLS)
- **tools/list filtering** — agents only see allowed tools
- **Rate limiting** (per-agent, per-tool, per-IP)
- **Human-in-the-Loop** — suspend tool calls for approval
- **Payload filtering** — encoding-aware (Base64, URL, Unicode)
- **Prompt injection detection** — built-in heuristics
- **OPA/Rego policies** — custom policy evaluation
- **Audit logging** — SQLite, webhook, OpenLineage
- **Both HTTP+SSE and stdio transports**

## Quick Example

```yaml
# gateway.yml
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"

agents:
  cursor:
    allowed_tools: [read_file, list_directory]
    rate_limit: 30

rules:
  block_patterns: ["password", "api_key", "secret"]
  block_prompt_injection: true
```

```bash
cargo install arbitus
./arbitus gateway.yml
```

## Tech Stack

- Written in Rust (sub-millisecond overhead)
- MIT licensed
- 446 unit tests passing
- Works with Cursor, Claude, Windsurf, and any MCP client

Would love feedback from folks deploying MCP in production. What security concerns do you have?

**Links**:
- GitHub: https://github.com/arbitusgateway/arbitus
- Docs: https://github.com/arbitusgateway/arbitus#documentation

---

## r/cybersecurity Post

**Title**: 92% of MCP servers have security issues. I built a Rust proxy to fix the gap.

**Body**:

The MCP (Model Context Protocol) ecosystem has a security problem. A recent analysis found that **92% of MCP servers carry high security risk** — tool poisoning, prompt injection, over-scoped OAuth, and output poisoning are all real attack vectors.

The official roadmap lists security as "on the horizon" — but enterprises are deploying MCP agents *now*.

## The Attack Surface

MCP servers introduce several unique vulnerabilities:

1. **Tool poisoning / rug pull** — Malicious tool manifest changes after approval
2. **Indirect prompt injection** — Adversarial content in tool responses manipulates the agent
3. **Over-scoped OAuth tokens** — Write access granted to read-only workflows
4. **Output poisoning** — Sensitive data bleeding into model context via tool responses
5. **Cross-tool interference** — Recursive tool calls causing resource exhaustion

## What I Built

**[Arbitus](https://github.com/arbitusgateway/arbitus)** is a security proxy that sits between AI agents and MCP servers. It enforces policies at the gateway layer:

```
Agent → Arbitus (auth, rate limit, filter, audit) → MCP Server
```

Key security features:

| Feature | What it Does |
|---------|--------------|
| Per-agent auth | API key, JWT/OIDC, mTLS with tool allowlists |
| tools/list filtering | Agents only see tools they're allowed to call |
| Rate limiting | Per-agent, per-tool, per-IP sliding window |
| Human-in-the-Loop | Suspend tool calls until operator approves |
| Payload filtering | Block/redact sensitive patterns (encoding-aware) |
| Response filtering | Block sensitive data in tool responses |
| Prompt injection detection | Built-in heuristics for attack patterns |
| OPA/Rego policies | Custom policy evaluation with full context |
| Audit logging | SQLite, webhook, OpenLineage, CloudEvents |
| Circuit breaker | Isolate failing upstreams automatically |
| Supply chain verification | SHA-256 hash pinning for stdio MCP servers |

## Why This Matters

AI agents are increasingly connected to:
- File systems
- Databases
- APIs with write access
- Cloud infrastructure

A single compromised MCP server = full data breach. And the standard MCP SDK doesn't protect against:
- An agent calling a tool it shouldn't have access to
- Prompt injection in tool responses
- Exfiltration via seemingly innocent tool calls

## Why Rust?

Security infrastructure should have minimal attack surface. Rust provides:
- Memory safety without GC pauses
- Static binary — no runtime dependencies
- Sub-millisecond overhead (transparent to agents)

After the March 2026 LiteLLM supply chain attack, I believe security tools should minimize their own dependency footprint.

## Quick Start

```bash
cargo install arbitus
```

```yaml
# gateway.yml
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"

agents:
  cursor:
    allowed_tools: [read_file, list_directory]
    rate_limit: 30

rules:
  block_patterns: ["password", "api_key", "secret"]
  block_prompt_injection: true
```

GitHub: https://github.com/arbitusgateway/arbitus

MIT licensed, open source, 446 tests passing.

Curious to hear from security folks — what else should a proxy like this handle?

---

## r/rust Post

**Title**: [Show r/rust] Arbitus - MCP security proxy (sub-millisecond overhead, 446 tests, 22 e2e sections)

**Body**:

Hi r/rust,

I built **[Arbitus](https://github.com/arbitusgateway/arbitus)**, a security proxy for MCP (Model Context Protocol) servers. It sits between AI agents (Cursor, Claude, etc.) and MCP servers, enforcing policies before any tool call reaches upstream.

## Why Rust?

Every competitor is Go, Python, or TypeScript. I chose Rust for:

- **No GC pauses** — latency-sensitive gateway
- **Static binary** — no runtime dependencies, minimal attack surface
- **Memory safety** — no use-after-free in a security gateway
- **Sub-millisecond overhead** — transparent to agents

## Architecture

Middleware pipeline, trait-based:

```rust
pub trait Middleware: Send + Sync {
    async fn handle(
        &self,
        request: JsonRpcRequest,
        context: &mut RequestContext,
    ) -> Result<Decision, MiddlewareError>;
}

// Pipeline: RateLimit → Auth → HITL → Schema → PayloadFilter
```

Key modules:
- `src/middleware/` — Each implements `Middleware`, returns `Decision` (Allow/Block/Redact)
- `src/transport/` — `Transport` trait; HTTP (Axum + SSE) and stdio
- `src/upstream/` — `McpUpstream` trait with circuit breaker
- `src/audit/` — `AuditLog` trait; SQLite, webhook, OpenLineage
- `src/jwt.rs` — JWT/OIDC validation (HS256, RS256, JWKS)

## Tech Stack

- Axum for HTTP
- Tokio for async runtime
- GCRA algorithm for rate limiting (lock-free, O(1))
- SQLite with hash-chain audit integrity
- OPA/Rego for custom policies

## Test Coverage

- 446 unit tests (`cargo test --lib`)
- 22 end-to-end test sections (`tests/e2e.sh`)
- Integration tests for HTTP, stdio, security, attack scenarios

```
cargo test --lib              # Unit tests
cargo test --test http_gateway  # Integration
./tests/e2e.sh                # E2E (spins up real gateway + dummy MCP)
```

## Quick Start

```bash
cargo install arbitus
```

```yaml
# gateway.yml
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"

agents:
  cursor:
    allowed_tools: [read_file, list_directory]
    rate_limit: 30

rules:
  block_patterns: ["password", "api_key"]
  block_prompt_injection: true
```

```bash
./arbitus gateway.yml
```

## What It Does

| Feature | Implementation |
|---------|---------------|
| Per-agent auth | API key, JWT/OIDC, mTLS |
| Rate limiting | GCRA, lock-free, per-agent/tool/IP |
| HITL | Long-poll approval workflow |
| Payload filtering | Regex + encoding-aware (Base64, URL, Unicode) |
| Schema validation | JSON Schema from tools/list |
| OPA/Rego | WASM policy evaluation |
| Audit logging | SQLite + webhook + OpenLineage fan-out |
| Circuit breaker | Closed → Open → HalfOpen |

MIT licensed, docs in `docs/`, governance in `GOVERNANCE.md`.

GitHub: https://github.com/arbitusgateway/arbitus

Feedback welcome — especially on async patterns, middleware design, and test coverage.

---

## r/artificial Post (if relevant)

**Title**: AI agents need security too. I built a Rust proxy for MCP servers after discovering 92% have vulnerabilities.

**Body**:

(Shorter version of r/cybersecurity post focused on AI agent security)
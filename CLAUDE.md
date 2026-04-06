# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**arbitus** is a security proxy (gateway) that sits between AI agents (Cursor, Claude, etc.) and MCP (Model Context Protocol) servers. It enforces per-agent policies — authentication, rate limiting, payload filtering, schema validation, and audit logging — before any tool call reaches the upstream MCP server.

## Commands

### Build
```bash
cargo build            # Debug
cargo build --release  # Release (binaries: arbitus, arbitus-audit, dummy-server)
```

### Test
```bash
cargo test --all-features              # All tests
cargo test --test http_gateway         # Single integration test file
cargo test my_test_name -- --nocapture # Single test with output
cargo test --lib                       # Unit tests only (no stdio tests requiring npx)
```

### Lint & Format
```bash
cargo fmt                      # Apply formatting
cargo fmt --check              # Check without modifying
cargo clippy -- -D warnings    # Lint (CI fails on any warning)
```

## Architecture

```
Agent (Cursor, Claude, etc.)
       ↓ JSON-RPC
  arbitus (this gateway)
       ↓ Middleware pipeline:
         1. RateLimitMiddleware    — sliding-window per-agent/tool/IP
         2. AuthMiddleware         — tool allowlist/denylist (supports wildcards)
         3. PayloadFilterMiddleware — block/redact sensitive patterns + prompt injection
         4. SchemaValidationMiddleware — validate args against tools/list schema
       ↓
  McpUpstream (circuit breaker: Closed → Open → HalfOpen)
       ↓
  MCP Server (filesystem, database, APIs, etc.)
```

### Key Modules

- **`src/gateway.rs`** — `McpGateway`: intercepts requests, runs the middleware pipeline, routes to upstream
- **`src/config.rs`** — YAML config parsing (agents, rules, auth, transports, audit backends)
- **`src/live_config.rs`** — Hot-reloadable config via `tokio::sync::watch`; reloads on `SIGUSR1` or every 30s
- **`src/middleware/`** — Trait-based middleware pipeline; each impl returns `Decision` (Allow/Block/Redact)
- **`src/transport/`** — `Transport` trait; `http.rs` = Axum HTTP server with SSE + dashboard + metrics; `stdio.rs` = spawn MCP subprocess
- **`src/upstream/`** — `McpUpstream` trait; `http.rs` = reqwest client with circuit breaker
- **`src/audit/`** — `AuditLog` trait with SQLite, stdout, webhook backends; `fanout.rs` fans out to multiple
- **`src/jwt.rs`** — JWT/OIDC validation (HS256, RS256, JWKS, multi-provider)
- **`src/bin/arbitus.rs`** — Main binary entrypoint
- **`src/bin/audit.rs`** — CLI to query SQLite audit log
- **`src/bin/dummy_server.rs`** — Minimal MCP server used in integration tests

### Test Structure

```
tests/
  common/mod.rs          # Shared harness: spins up dummy server + gateway on free ports
  http_gateway.rs        # HTTP transport integration tests
  stdio_gateway.rs       # Stdio transport tests (marked #[ignore], require npx)
  security_coverage.rs   # Payload filtering and injection detection
  attack_scenarios.rs    # Real-world attack scenarios
  fixtures/
    gateway-test.yml     # Block patterns reference for security_coverage.rs
    gateway-stdio.yml    # Stdio transport config for stdio_gateway.rs
```

Integration tests spin up a real gateway binary + in-process dummy MCP server. The test harness is in `tests/common/mod.rs`.

## Configuration

The gateway is configured via YAML (`gateway.yml`). Key sections:

```yaml
transport:
  type: http              # or stdio
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"
  circuit_breaker:
    threshold: 5
    recovery_secs: 30

upstreams:                # Named upstreams for per-agent routing
  filesystem: "http://localhost:3001/mcp"

agents:
  cursor:
    upstream: filesystem
    allowed_tools: [read_file, "list_*"]   # supports wildcards
    rate_limit: 30         # req/min
    tool_rate_limits:
      write_file: 5
    api_key: "sk-cursor-secret"

rules:
  block_patterns: ["password", "(?i)private_key"]
  filter_mode: block       # or redact
  block_prompt_injection: true

audits:                    # Fan-out to multiple backends
  - type: sqlite
    path: "gateway-audit.db"
  - type: webhook
    url: "https://hooks.example.com/mcp"
```

## Running

```bash
# Start gateway
./target/release/arbitus gateway.yml

# Query audit log
./target/release/arbitus-audit gateway-audit.db --agent cursor --outcome blocked --since 1h

# Hot-reload config
kill -USR1 $(pidof arbitus)
```

Endpoints: `/health`, `/metrics` (Prometheus), `/dashboard` (audit UI). The admin endpoints require `Authorization: Bearer <admin_token>`.

## Development Rules

These rules apply to every change made in this repository.

### Workflow

1. **Issues first** — every new feature or bug fix must have a corresponding GitHub issue before work begins
2. **Feature branch** — create a branch named `feat/<topic>` or `fix/<topic>` from `master`
3. **Update docs** — update `README.md` and `CHANGELOG.md` for every feature or fix before committing
4. **Pull request to close** — all work lands via PR; the PR description must reference the issue (`Closes #N`)

### Code quality checklist (required before every push)

```bash
cargo fmt --check          # must pass — no formatting violations
cargo clippy -- -D warnings  # must pass — zero warnings
cargo test --lib           # all unit tests green
```

Integration tests (`cargo test --test`) should also pass unless they require external services (stdio tests need `npx`).

### Language

Everything that goes into the public repository must be written in **English**: code, comments, commit messages, PR titles and descriptions, issue content, and documentation. Conversations with the developer may be in any language.

### Design principles

- **Modularity** — new behaviour goes into its own module or middleware; avoid growing existing files beyond their scope
- **Trait-based abstraction** — use traits (`McpUpstream`, `AuditLog`, `Middleware`) for anything that may have multiple implementations or needs to be mocked in tests
- **Tests before merge** — every new public function or behaviour must have at least one unit test; security-sensitive paths require both a happy-path and an adversarial test
- **Security by default** — new inputs must be validated at the boundary; block patterns, rate limits, and auth checks apply to all agents unless explicitly relaxed
- **Performance** — prefer async-safe patterns; avoid blocking calls inside `async fn`; no unnecessary heap allocations in hot paths
- **Interoperability** — config changes must remain backward-compatible; new YAML fields must have `#[serde(default)]`
- **Scalability** — shared state must use `Arc` + lock-free structures where possible; avoid global mutable state

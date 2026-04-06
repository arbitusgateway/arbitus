# Arbitus

[![crates.io](https://img.shields.io/crates/v/arbitus.svg)](https://crates.io/crates/arbitus)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/nfvelten/arbitus/actions/workflows/ci.yml/badge.svg)](https://github.com/nfvelten/arbitus/actions/workflows/ci.yml)

A security proxy that sits between AI agents and MCP servers. It enforces per-agent policies before any tool call reaches the upstream server.

```
Agent (Cursor, Claude, etc.)
        │  JSON-RPC
        ▼
      arbitus     ← auth, rate limit, HITL, payload filter, audit
        │
        ▼
  MCP Server (filesystem, database, APIs...)
```

## What it does

- **Auth** — per-agent allowlist/denylist with glob wildcards; API key, JWT/OIDC, or mTLS
- **tools/list filtering** — agents only see the tools they are allowed to call
- **Resource & Prompt access control** — `allowed_resources`/`denied_resources` and `allowed_prompts`/`denied_prompts` with list filtering; full MCP protocol governance
- **Default policy** — fallback policy for unknown agents; avoids hard-blocking agents not listed in config
- **Rate limiting** — per-agent sliding window + per-tool limits + per-IP limit; standard `X-RateLimit-*` headers
- **Human-in-the-Loop (HITL)** — suspend tool calls until an operator approves or rejects via REST API
- **Shadow mode** — intercept and log tool calls without forwarding; dry-run risky operations
- **Payload filtering** — block or redact sensitive patterns; encoding-aware (Base64, percent-encoding, Unicode)
- **Response filtering** — block upstream responses containing sensitive patterns
- **Schema validation** — validate `tools/call` arguments against `inputSchema` from `tools/list`
- **OPA/Rego policy engine** — evaluate every `tools/call` against a Rego policy file; input exposes agent, tool, arguments, and client IP
- **Supply-chain security** — verify MCP server binaries via SHA-256 or cosign before spawning (stdio mode)
- **Audit log** — every request recorded with `X-Request-Id`; fan-out to SQLite, webhook, stdout, or OpenLineage
- **CloudEvents** — webhook audit can emit CNCF CloudEvents 1.0 for direct SIEM ingestion
- **Tool Federation** — aggregate tools from multiple upstreams into a single view
- **OpenAI Tools Bridge** — `/openai/v1/tools` and `/openai/v1/execute` for OpenAI function-calling clients
- **Multiple upstreams** — route different agents to different MCP servers
- **Circuit breaker** — automatic upstream failure isolation with half-open recovery
- **Config hot-reload** — reload on `SIGUSR1` or automatically every 30 seconds
- **Metrics** — Prometheus-compatible `/metrics` endpoint with cost/token estimation
- **OpenTelemetry** — export traces to any OTLP backend (Jaeger, Tempo, Honeycomb, Datadog)
- **Dashboard** — `/dashboard` audit viewer with per-agent filtering
- **TLS / mTLS** — optional HTTPS with mutual TLS agent authentication
- **Transport agnostic** — HTTP+SSE or stdio; same config, same policies
- **Secrets-safe config** — `${VAR}` interpolation in YAML + `ARBITUS_*` env var overrides; compatible with K8s Secrets, Vault, External Secrets Operator
- **Container-ready** — multi-arch Docker image, Helm chart with sidecar pattern, graceful shutdown

## Documentation

| Document | Contents |
|----------|----------|
| **[Configuration](docs/configuration.md)** | Full YAML reference — transport, auth (JWT/OIDC), agents, rules, secrets, upstreams, default policy, OPA, schema validation |
| **[Usage](docs/usage.md)** | HTTP mode, sessions, rate-limit headers, HITL approvals, shadow mode, supply-chain verification, SSE streaming, OpenAI bridge, tool federation |
| **[Deployment](docs/deployment.md)** | Docker, Helm chart (sidecar pattern, values reference), HTTPS, mTLS, stdio mode, graceful shutdown |
| **[Audit](docs/audit.md)** | Audit backends (SQLite, webhook, stdout), CloudEvents 1.0, OpenLineage, audit CLI |
| **[Observability](docs/observability.md)** | Prometheus metrics, cost/token estimation, health check, dashboard, config hot-reload, OpenTelemetry, logging, circuit breaker |
| **[Architecture](docs/architecture.md)** | Middleware pipeline, trait-based design, encoding-aware filtering, test structure |

## Quick start

### Install

```sh
cargo install arbitus
```

Or download a pre-built binary from the [releases page](https://github.com/nfvelten/arbitus/releases):

| Platform | Archive |
|---|---|
| Linux x64 (static) | `arbitus-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (static) | `arbitus-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS x64 | `arbitus-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `arbitus-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `arbitus-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

Or build from source:

```sh
git clone https://github.com/nfvelten/arbitus
cd arbitus
cargo build --release
```

Or use Docker:

```sh
docker pull ghcr.io/nfvelten/arbitus:latest
docker run --rm -p 4000:4000 -v $(pwd)/gateway.yml:/app/gateway.yml ghcr.io/nfvelten/arbitus:latest
```

### Configure

```sh
cp gateway.example.yml gateway.yml
```

```yaml
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"

agents:
  cursor:
    allowed_tools: [read_file, list_directory]
    rate_limit: 30

  claude-code:
    denied_tools: [write_file, delete_file]
    rate_limit: 60

rules:
  block_patterns: ["password", "api_key", "secret"]
```

### Run

```sh
./arbitus gateway.yml
```

Agents connect to `http://localhost:4000/mcp`. The gateway enforces policies and forwards allowed requests to the upstream MCP server.

### Validate config

```sh
./arbitus validate gateway.yml
```

### Query audit log

```sh
./arbitus audit gateway-audit.db --agent cursor --outcome blocked --since 1h
```

## Architecture

```
            ┌──────────────────────────────────────────┐
            │                 Arbitus                  │
            │                                          │
  request ──► Pipeline                                 │
            │   1. RateLimitMiddleware                 │
            │   2. AuthMiddleware                      │
            │   3. HitlMiddleware    ← suspend & wait  │
            │   4. SchemaValidationMiddleware          │
            │   5. PayloadFilterMiddleware             │
            │         │                                │
            │    Allow / Block                         │
            │         │                                │
            │   Shadow mode check  ← mock if matched   │
            │         │                                │
            │   AuditLog + Metrics                     │
            │         │                                │
            │    McpUpstream (per-agent)               │
            └──────────────────────────────────────────┘
```

## Tests

```sh
cargo test --all-features              # All tests
cargo test --lib                       # Unit tests only (no stdio/npx)
cargo test --test http_gateway         # Single integration test file
```

## License

[MIT](LICENSE)

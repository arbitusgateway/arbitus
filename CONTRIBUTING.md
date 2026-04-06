# Contributing to arbitus

Contributions are welcome — bug fixes, new features, tests, and documentation.

## Before you start

For anything beyond a small fix, open an issue first to discuss the approach. This avoids wasted work if the direction doesn't fit the project. See [CLAUDE.md](CLAUDE.md) for the full development workflow and design principles.

## Setup

```bash
# Prerequisites: Rust stable (1.85+)
git clone https://github.com/nfvelten/arbitus
cd arbitus
cargo build
```

Node.js is only needed for the stdio integration tests (`#[ignore]` by default).

## Running the tests

```bash
# All unit tests (fast, no external deps)
cargo test --lib

# All integration tests (spins up real gateway + dummy MCP server)
cargo test --test http_gateway
cargo test --test security_coverage
cargo test --test attack_scenarios

# stdio tests (requires npx — excluded from CI)
cargo test --test stdio_gateway -- --ignored

# Full suite
cargo test --all-features
```

## Code quality (required before every push)

```bash
cargo fmt --check        # must pass — no formatting violations
cargo clippy -- -D warnings  # must pass — zero warnings
cargo test --lib         # all unit tests green
```

## Project structure

```
src/
  bin/
    arbitus.rs            # Main binary — wires config, pipeline, transport
    audit.rs             # arbitus audit/verify-log CLI
    dummy_server.rs      # Minimal MCP server used in integration tests
  audit/                 # AuditLog trait + backends (sqlite, stdout, webhook, openlineage, fanout)
  middleware/            # Trait-based pipeline (auth, rate_limit, payload_filter, schema, hitl, opa)
  transport/             # Transport trait + HTTP (axum) and stdio implementations
  upstream/              # McpUpstream trait + HTTP upstream with circuit breaker
  secrets/               # SecretsProvider trait + OpenBao backend
  config.rs              # YAML config parsing and validation
  gateway.rs             # Core McpGateway — intercept, handle, filter, federate
  live_config.rs         # Hot-reloadable config via tokio::sync::watch
  jwt.rs                 # JWT/OIDC validation (HS256, RS256, JWKS, multi-provider)
  oauth.rs               # OAuth 2.1 + PKCE token management
  metrics.rs             # Prometheus metrics
  cost.rs                # Token estimation utilities
  decode.rs              # Encoding-aware payload normalisation (Base64, URL, Unicode)
  prompt_injection.rs    # Built-in prompt injection patterns
  schema_cache.rs        # LRU-bounded inputSchema cache per agent
  hitl.rs                # HitlStore — pending approval requests
tests/
  common/mod.rs          # Shared harness: gateway + dummy server on free ports
  http_gateway.rs        # HTTP integration tests
  security_coverage.rs   # Payload filter and injection detection
  attack_scenarios.rs    # Real-world attack scenarios
  stdio_gateway.rs       # Stdio tests (require npx, ignored in CI)
  fixtures/
    gateway-test.yml     # Block patterns reference for security_coverage.rs
    gateway-stdio.yml    # Stdio transport config for stdio_gateway.rs
```

## Design principles

- **Traits over structs** — `Transport`, `McpUpstream`, `AuditLog`, `Middleware` are traits; new implementations don't touch the core.
- **No blocking in async context** — SQLite and heavy I/O go through `spawn_blocking`; audit `record()` is fire-and-forget via bounded channels.
- **Hot-reload without restart** — `tokio::sync::watch` propagates a new `Arc<LiveConfig>` to all middleware. Middleware snapshots what it needs and drops the borrow before any `.await` to stay `Send`.
- **Security by default** — block patterns, rate limits, and auth checks apply to all agents unless explicitly relaxed. New inputs validated at the boundary.
- **Tests before merge** — every new public function or behaviour must have at least one unit test; security-sensitive paths require both a happy-path and an adversarial test.

## Workflow

1. Open or reference a GitHub issue
2. Create a branch: `feat/<topic>` or `fix/<topic>` from `master`
3. Make your changes with tests
4. Update `README.md` and `CHANGELOG.md` under `[Unreleased]`
5. Run the quality checklist above
6. Open a PR referencing the issue (`Closes #N`)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

# Architecture

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

Each middleware is a trait object — new checks can be added without touching the gateway core. Transport, upstream, and audit backend are also trait objects, swappable via config.

Payload filtering is encoding-aware: before applying `block_patterns`, the gateway decodes Base64 (standard and URL-safe), percent-encoding, double-encoding, and Unicode variants (NFC normalization, Bidi-control stripping). This prevents bypass attempts using encoded payloads.

## Tests

```sh
# All tests
cargo test --all-features

# Skip stdio tests (require npx)
cargo test --lib

# Single test file
cargo test --test http_gateway
```

Integration tests are written in Rust under `tests/`. They spin up a real gateway binary and an in-process dummy MCP server on free ports. Stdio tests are marked `#[ignore]` since they require `npx` at runtime.

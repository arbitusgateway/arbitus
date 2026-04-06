# Changelog

## [0.19.1] — 2026-04-06

### Fixed
- **Docker build**: install `git` in Alpine builder and include `.git` in the build context so `regorus` build script can run `git rev-parse HEAD` successfully.

---

## [0.19.0] — 2026-04-05

### Changed
- **Project renamed from `arbit` to `arbitus`**: binary names, crate name, Helm chart, Docker image, and all internal references updated. First release under the new name on crates.io, Docker Hub, and the Helm chart repository.

---

## [0.18.0] — 2026-04-02

### Added
- **mTLS agent authentication** (`transport/http.rs`, `config.rs`, `live_config.rs`): agents can now authenticate via mutual TLS instead of a static API key. Set `tls.client_ca` in `gateway.yml` to enable client certificate verification, and set `mtls_identity` on any `AgentPolicy` to the expected CN (Common Name) of the agent's certificate. The gateway maps the verified CN to an agent name at connection time. CN-to-agent mapping is hot-reloaded with the rest of the config. Closes #9.
- **Full-spec MCP governance — Resources & Prompts** (`gateway.rs`, `config.rs`, `middleware/auth.rs`): access control now covers the entire MCP protocol, not just `tools/call`. Agents enforce `allowed_resources`/`denied_resources` on `resources/read` and `resources/subscribe`, and `allowed_prompts`/`denied_prompts` on `prompts/get`. `resources/list` and `prompts/list` responses are filtered to only expose accessible items. All middleware stages (rate-limit, payload-filter, OPA) now apply to the new governed methods as well. Closes #11.
- **OPA/Rego policy engine** (`middleware/opa.rs`, `config.rs`): embedded Rego policy evaluation via `regorus`. Declare `rules.opa.policy_path` in `gateway.yml` to gate every `tools/call` against a Rego policy. Input exposes `agent_id`, `method`, `tool_name`, `arguments`, and `client_ip`. Defaults to `data.mcp.allow`; any falsy result or evaluation error blocks the request. Hot-reload picks up policy file changes automatically. Closes #8.
- **Observability Dashboard enhancements** (`transport/http.rs`): rebuilt `/dashboard` with filter bar (agent, outcome, tool, since), summary stats cards (total, allowed, blocked, block rate %), paginated audit table (100 entries/page), and operator **kill switch** — block/unblock individual tools from the UI without restarting the gateway. Blocked tools return a JSON-RPC error immediately, before the middleware pipeline. Closes #4.
- **Immutable audit log — hash chain integrity** (`audit/sqlite.rs`): every new entry stores a `prev_hash` and an `entry_hash` (SHA-256 of the previous hash + all fields). Existing databases are migrated transparently; legacy rows are skipped during verification. New `arbitus verify-log <db>` subcommand walks the chain and exits non-zero if any row is missing, tampered, or chain-broken. Closes #10.
- **OpenBao secret management** (`secrets/`, `config.rs`): native integration with OpenBao (Vault-compatible). Declare a `secrets:` block in `gateway.yml` to fetch secret values at startup and inject them into the config before the gateway starts. Supports `token`, `approle`, and `kubernetes` auth methods. The `SecretsProvider` trait enables mocking in tests. Closes #22.
- **OAuth 2.1 + PKCE for upstream authentication** (`oauth.rs`, `upstream/http.rs`, `transport/http.rs`): arbitus can now authenticate itself to upstream MCP servers using the authorization code flow with PKCE (RFC 7636). Configure `oauth:` under a named upstream, visit the printed authorization URL once, and arbitus refreshes tokens automatically. The `/oauth/callback` endpoint handles the provider redirect. Closes #3.

---

## [0.17.0] — 2026-04-01

### Security
- **SSRF guard on OIDC discovery** (`jwt.rs`): `validate_issuer_url` now rejects non-HTTPS schemes, `localhost`, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), private IPv4 (`10/8`, `172.16/12`, `192.168/16`), and unique-local IPv6 (`fc00::/7`) before making any outbound HTTP request. Closes #32.
- **Block errors no longer expose internal regex patterns** (`PayloadFilterMiddleware`): client-facing JSON-RPC error messages now return generic reasons (`"sensitive data detected"`, `"prompt injection detected"`) instead of the triggering pattern string. The matched pattern is still recorded in server logs (`tracing::debug!`) for operator visibility. Closes #30.
- **Agent enumeration via error messages fixed** (`AuthMiddleware`): unknown agent IDs previously produced a distinct `"unknown agent '...'"` error. The reason is now the uniform `"not authorized"` regardless of whether the agent exists. Closes #31.
- **`tool_matches` DoS fixed** (`config.rs`): replaced O(2^n) recursive backtracking glob matcher with an O(n·m) segment-anchoring scan. A crafted pattern like `*a*a*a*…*` no longer causes exponential blowup. Closes #29.

### Fixed
- **`SchemaCache` now LRU-bounded** (`schema_cache.rs`): replaced unbounded `HashMap` with `lru::LruCache` capped at 1024 `(agent_id, tool_name)` entries; least-recently-used schemas are evicted automatically. Closes #36.
- **Audit backends use bounded channels**: replaced `unbounded_channel` with `channel(4096)` in `SqliteAudit`, `WebhookAudit`, and `OpenLineageAudit`. Dropped entries increment the new `arbitus_audit_drops_total{backend}` Prometheus counter. Closes #28.
- **Federated `tools/list` has a 10-second global timeout** (`gateway.rs`): `join_all` over named upstreams was unbounded — a single slow upstream could stall the gateway indefinitely. Returns JSON-RPC `-32603` on timeout. Closes #33.
- **Hot-reload preserves running config on failure**: if `Config::from_file` returns any error the watch channel is not updated and the previous config stays active. The new `arbitus_config_reload_failures_total` Prometheus counter is incremented on each failure. Closes #35.
- **Blocked JSON-RPC notifications receive no response** (`McpGateway`): spec §4 requires silence when blocking a notification (request without `id`). Previously a `-32603` error was sent anyway. Closes #34.

---

## [0.16.0] — 2026-03-31

### Added
- **Helm chart published to GitHub Pages**: `helm repo add arbitus https://nfvelten.github.io/arbitus` — chart is automatically packaged and published on every `v*` tag via `.github/workflows/helm-release.yml` using `helm/chart-releaser-action`
- **Artifact Hub metadata**: `artifacthub-repo.yml` at repo root registers the repository with Artifact Hub for discoverability

---

## [0.15.0] — 2026-03-31

### Added
- **Helm chart** (`charts/arbitus/`): production-ready chart for Kubernetes deployment
  - `Deployment` with non-root security context, liveness/readiness probes, config checksum annotation (auto-restart on config change)
  - `ConfigMap` renders `gateway.yml` from `values.yaml`; supports `${VAR}` placeholders resolved from env vars
  - `Service` (ClusterIP), `ServiceAccount` (automount disabled)
  - Optional `HorizontalPodAutoscaler` (CPU/memory), `PodDisruptionBudget`, `NetworkPolicy` (restrict ingress to `arbitus-client: "true"` pods), `PersistentVolumeClaim` for SQLite audit log
  - Sidecar pattern: `extraContainers` in `values.yaml` adds agent containers to the same Pod (shared network — agent reaches arbitus at `localhost:4000`)
  - `existingSecret` mounts a Kubernetes Secret as env vars via `envFrom`
  - `terminationGracePeriodSeconds: 30` aligned with SIGTERM graceful shutdown

---

## [0.14.0] — 2026-03-31

### Added
- **Docker image published to GHCR**: `ghcr.io/nfvelten/arbitus:<version>` built and pushed automatically on every `v*` tag via `.github/workflows/docker.yml`; multi-arch (`linux/amd64` + `linux/arm64`); layer cache backed by GitHub Actions cache
- **`docker-compose.yml`**: healthcheck via `wget /health`, `LOG_FORMAT`/`LOG_LEVEL` env vars documented, commented example for `ARBITUS_ADMIN_TOKEN` secret injection

### Changed
- **Dockerfile**: fixed binary names (`gateway`/`audit` → `arbitus`); added non-root user `arbitus` (uid 10001); added `wget` for healthcheck; `ENTRYPOINT ["arbitus"] CMD ["start", "/app/gateway.yml"]`
- **`.dockerignore`**: extended to exclude test fixtures, strategy docs, and extra config files
## [0.13.0] — 2026-03-31

### Changed
- **Graceful shutdown for stdio transport**: the main read loop now uses `tokio::select!` to race `stdin.next_line()` against SIGTERM/CTRL-C; on signal the loop breaks cleanly, the child process is drained, and the audit log is flushed before exit — previously SIGTERM killed the process immediately without flushing
- **Shutdown log sequence**: `shutdown_signal()` (HTTP) now logs "draining active connections"; `arbitus.rs` logs "flushing audit backends" and "shutdown complete" after transport exits — the audit flush is no longer misleadingly attributed to the signal handler

---

## [0.12.0] — 2026-03-31

### Added
- **Env var interpolation in config** (`${VAR}` syntax): any value in `gateway.yml` can reference an environment variable; missing variables abort startup with a descriptive error identifying the missing name — enables Kubernetes Secret injection without embedding credentials in config files
- **`ARBITUS_*` env var overrides**: three top-level overrides applied after YAML parsing; precedence: env var > YAML value:
  - `ARBITUS_ADMIN_TOKEN` — overrides `admin_token`
  - `ARBITUS_UPSTREAM_URL` — overrides `transport.upstream`
  - `ARBITUS_LISTEN_ADDR` — overrides `transport.addr`
- `Config::set_upstream_url()` and `Config::set_listen_addr()` helper methods

### Changed
- `Config::from_file()` now runs interpolation and env overrides before `validate()` — fully backward compatible

---

## [0.11.0] — 2026-03-31

### Added
- **OpenLineage Integration**: new `openlineage` audit backend emits OpenLineage `RunEvent` (spec 2-0-2) on every `tools/call`:
  - `eventType` maps to `COMPLETE` (allowed/forwarded/shadowed) or `FAIL` (blocked)
  - `job.namespace` / `job.name` encode `<namespace>/<agent_id>/<tool_name>` for lineage graph navigation
  - `run.runId` is the existing `X-Request-Id` UUID — correlates lineage events with audit log entries
  - `run.facets` includes `arbitus:execution` (outcome, agent, input_tokens) and `arbitus:arguments` (captured tool arguments)
  - `inputs[]` dataset entry identifies the tool and agent as the lineage source
  - Configurable `namespace`, optional Bearer token auth; non-tools/call events skipped automatically
  - Enables LGPD/GDPR compliance tracing: "AI generated response X based on tool Y which queried Z"
- **`AuditConfig::OpenLineage`** variant: `url`, `token` (optional), `namespace` (default: `"arbitus"`) — fully backward compatible

---

## [0.10.0] — 2026-03-31

### Added
- **Cost Observability**: per-agent token estimation and chargeback tracking using the 4-chars-per-token heuristic:
  - `arbitus_tokens_total` Prometheus counter with `agent` and `direction` (`input`/`output`) labels — queryable via `/metrics` for cumulative per-agent spend
  - `input_tokens` column added to the SQLite audit log — per-request token estimate stored alongside every `tools/call` entry; existing databases are migrated automatically
  - `cost.rs` module with `estimate_tokens()` and `estimate_tokens_str()` utilities
  - `GatewayMetrics::record_tokens()` method called on every forwarded `tools/call` (both regular and federated paths)

---

## [0.9.0] — 2026-03-31

### Added
- **Tool Federation**: agents with `federate: true` query all named upstreams in parallel on `tools/list` and receive a single merged tool view; colliding tool names are prefixed with `<upstream>__name` (e.g. `filesystem__read_file`); `tools/call` transparently strips the prefix and routes to the correct upstream
- **OpenAI Tools Bridge**: two new endpoints translate between OpenAI function-calling format and MCP, allowing legacy OpenAI SDK clients to use arbitus's security infrastructure without refactoring:
  - `GET /openai/v1/tools` — returns available tools in OpenAI function format (`parameters` / `type: function`)
  - `POST /openai/v1/execute` — accepts `tool_calls` array, executes each via the MCP gateway, returns `tool_results`; all requests pass through the full middleware pipeline

### Changed
- `AgentPolicy` gains `federate: bool` field (default: `false`) — fully backward compatible

---

## [0.8.0] — 2026-03-31

### Added
- **Human-in-the-Loop (HITL)**: `HitlMiddleware` suspends `tools/call` requests matching `approval_required` patterns and waits for an operator decision via REST API (`GET /approvals`, `POST /approvals/{id}/approve`, `POST /approvals/{id}/reject`); auto-rejects after `hitl_timeout_secs` (default: 60)
- **Shadow mode**: tools matching `shadow_tools` are intercepted after the middleware pipeline passes — logged as `Outcome::Shadowed`, a mock success response is returned, and the call is never forwarded to the upstream; supports glob wildcards
- **Supply-chain security**: binary verification for the stdio transport before spawn; two independent checks: SHA-256 hash pinning (`verify.sha256`) and Sigstore cosign bundle (`verify.cosign_bundle` via `cosign verify-blob`); startup aborted on failure
- **CloudEvents 1.0**: webhook audit backend gains `cloudevents: true` option; emits CNCF CloudEvents 1.0 envelopes (`application/cloudevents+json`) with event type `dev.arbitus.audit.<outcome>`; configurable `source` attribute (default: `/arbitus`)
- **Unified CLI**: `arbitus start`, `arbitus validate`, and `arbitus audit` subcommands replace the separate `arbitus` and `arbitus-audit` binaries; legacy `arbitus gateway.yml` invocation still works
- **`Outcome::Shadowed`** audit variant: all backends (SQLite, stdout, webhook) handle the new outcome

### Changed
- `AuditConfig::Webhook` gains `cloudevents: bool` (default: `false`) and `source: String` (default: `"/arbitus"`) fields — fully backward compatible
- `TransportConfig::Stdio` gains optional `verify: BinaryVerifyConfig` field

---

## [0.7.0] — 2026-03-30

### Added
- **Schema validation middleware**: `SchemaValidationMiddleware` validates `tools/call` arguments against the `inputSchema` from `tools/list`; invalid args are blocked before reaching the upstream
- **Encoding-aware filtering**: `decode.rs` decodes Base64 (standard and URL-safe), percent-encoding, double-encoding, and Unicode (NFC + Bidi-control stripping) variants of every argument before applying block patterns — catches obfuscated bypass attempts
- **Schema cache**: `schema_cache.rs` caches per-agent `inputSchema` entries populated from `tools/list` responses; used by the validation middleware
- **Expanded `AuthMiddleware`**: full allowlist/denylist enforcement and API key / JWT validation moved into the middleware pipeline
- **Security test suite**: `attack_scenarios.rs` (SSRF, path traversal, credential leaks, SQL injection, prompt injection variants) and `security_coverage.rs` (payload filter and injection detection coverage)
- **`tests/fixtures/gateway-test.yml`** fixture for the integration test environment

### Changed
- Integration tests migrated from shell scripts (`test-http.sh`, `test-stdio.sh`) to Rust (`tests/http_gateway.rs`, `tests/stdio_gateway.rs`)
- Stdio tests marked `#[ignore]` — require `npx` at runtime, excluded from CI

---

## [0.6.0] — 2026-03-29

### Added
- **Wildcard tool matching**: glob patterns (`read_*`, `*_file`, `fs/*`) in `allowed_tools` / `denied_tools`
- **`/health` endpoint v2**: reports per-upstream circuit state (`{"status":"ok","upstreams":{"default":true,"filesystem":false}}`)
- **Per-agent upstream timeout**: `timeout_secs` field overrides the global 30s default
- **`default_policy`**: top-level fallback for agents not listed in config (rate limit, denied tools, timeout)
- **`X-Request-Id`** header on every response for end-to-end tracing
- **OAuth 2.1 / multi-provider auth**: list form of `auth:` accepts multiple providers; first valid token wins
- **OpenTelemetry tracing**: `telemetry.otlp_endpoint` exports spans per `tools/call`
- **Prompt injection detection**: `block_prompt_injection: true` in `rules` enables 7 built-in patterns
- **`filter_mode: redact`**: scrubs matching values to `[REDACTED]` and forwards the sanitised request instead of blocking
- **Rate-limit response headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After`
- **`/dashboard`** endpoint — HTML audit log viewer with per-agent filtering

---

## [0.5.0] — 2026-03-28

### Added
- **Response filtering** in stdio transport: block patterns now applied to all upstream responses, not just HTTP
- **Configurable circuit breaker**: `circuit_breaker.threshold` and `circuit_breaker.recovery_secs` in `gateway.yml`
- **Key-based agent identity**: `X-Api-Key` header maps directly to an agent (via reverse lookup in `LiveConfig`), overriding `clientInfo.name`
- **Audit log rotation**: `max_entries` and `max_age_days` options for `sqlite` audit backend
- **`/health` endpoint**: returns `{"status":"ok","version":"0.5.0"}`
- **Config validation at startup**: validates regexes, upstream references, TLS file existence, circuit breaker threshold
- **SIGUSR1 hot-reload**: immediate config reload on `SIGUSR1`; 30-second polling as fallback
- **Test coverage**: 42 HTTP integration tests, 16 stdio integration tests

### Changed
- `LiveConfig::new()` now precomputes the `api_key → agent_name` reverse map for O(1) key lookup
- `do_reload()` extracted as a helper to avoid duplication between signal and timer paths

---

## [0.4.0] — 2026-03-27

### Added
- **API key authentication**: `api_key` field per agent in config; middleware returns 401 on mismatch
- **Response filtering**: HTTP responses checked against `block_patterns`; replaced with error on match
- **Config hot-reload**: config file polled every 30 seconds; changes applied without restart via `watch::channel`
- **`FanoutAudit`**: fan-out audit backend that writes to multiple backends simultaneously
- **Circuit breaker** in `HttpUpstream`: opens after N consecutive failures, recovers after timeout
- **Per-tool rate limits**: `tool_rate_limits` map per agent (e.g., `echo: 2` — max 2 calls/min to that tool)
- **SSE proxy**: `GET /mcp` proxies upstream SSE stream with per-event response filtering
- **`DELETE /mcp`**: session invalidation endpoint; returns 204 on success, 404 if not found
- **Prometheus metrics endpoint** (`/metrics`): request counts, blocked counts, latency histograms
- **Named upstreams**: `upstreams:` map in config; agents can route to different upstream servers
- **TLS support**: optional `tls.cert` / `tls.key` in HTTP transport config

---

## [0.3.0] — 2026-03-26

### Added
- **`DELETE /mcp`** session invalidation
- **Webhook audit backend**: POSTs JSON audit entries to a configurable URL with optional Bearer token
- **`FanoutAudit` skeleton**: multiple audit backends wired together
- **Session TTL**: configurable `session_ttl_secs` in HTTP transport

---

## [0.2.0] — 2026-03-25

### Added
- **HTTP transport** (`axum`) with MCP session management (`Mcp-Session-Id` header)
- **SQLite audit log** with async worker task
- **Middleware pipeline**: auth, rate limit, payload filter — composable and ordered
- **`tools/list` filtering**: per-agent `allowed_tools` / `denied_tools` applied to upstream responses
- **Stdio transport**: wraps any MCP server process, intercepts JSON-RPC on stdin/stdout
- **`x-agent-id` fallback** for clients that skip session management

---

## [0.1.0] — 2026-03-24

### Added
- Initial implementation: JSON-RPC 2.0 proxy with basic allow/deny tool filtering
- YAML config (`gateway.yml`) with agents, rules, and transport sections
- Stdout audit backend
- HTTP upstream with `reqwest`

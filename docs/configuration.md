# Configuration

The gateway is configured via a YAML file. Pass the path as the first argument, or let it default to `gateway.yml`. Copy `gateway.example.yml` to get started:

```sh
cp gateway.example.yml gateway.yml
```

```yaml
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"
  session_ttl_secs: 3600   # optional, default: 3600
  # tls:                   # optional — enables HTTPS
  #   cert: "cert.pem"
  #   key:  "key.pem"

admin_token: "admin-secret"   # optional — protects /metrics and /dashboard

audit:
  type: sqlite
  path: "gateway-audit.db"

# Named upstreams — agents can reference these via `upstream:` in their policy.
# upstreams:
#   filesystem: "http://localhost:3001/mcp"
#   database:   "http://localhost:3002/mcp"

agents:
  cursor:
    allowed_tools:
      - read_file
      - list_directory
    rate_limit: 30

  claude-code:
    denied_tools:
      - write_file
      - delete_file
    rate_limit: 60
    # upstream: filesystem   # route this agent to a named upstream

rules:
  block_patterns:
    - "password"
    - "api_key"
    - "secret"
    - "Bearer "
    - "private_key"
  # ip_rate_limit: 100      # optional — max calls/min per client IP
```

Config changes to `agents` and `rules` are picked up automatically — no restart required. See [Observability — Config hot-reload](observability.md#config-hot-reload) for details.

## `transport`

| Field | Description |
|---|---|
| `type` | `http` or `stdio` |
| `addr` | (HTTP only) address to listen on |
| `upstream` | (HTTP only) default upstream MCP server URL, including path (e.g. `/mcp`) |
| `session_ttl_secs` | (HTTP only) session lifetime in seconds. Default: `3600` |
| `tls.cert` | (HTTP only) path to PEM certificate file. Enables HTTPS when set. |
| `tls.key` | (HTTP only) path to PEM private key file |
| `server` | (stdio only) command to spawn the MCP server, as a list |
| `verify` | (stdio only) optional binary verification before spawn — see [Usage — Supply-chain security](usage.md#supply-chain-security) |

## Secrets in config

Credentials should never be stored in plaintext. Two mechanisms are available:

### `${VAR}` interpolation

Reference any environment variable inside `gateway.yml`:

```yaml
admin_token: "${ARBITUS_ADMIN_TOKEN}"

agents:
  cursor:
    api_key: "${CURSOR_API_KEY}"

auth:
  - type: jwt
    secret: "${JWT_SECRET}"
```

If the variable is not set, arbitus aborts at startup:

```
config error: env var 'ARBITUS_ADMIN_TOKEN' is not set (referenced in gateway.yml)
```

### `ARBITUS_*` env var overrides

Override specific fields without modifying the YAML file — useful when deploying a shared base config with environment-specific secrets:

| Env var | Overrides |
|---------|-----------|
| `ARBITUS_ADMIN_TOKEN` | `admin_token` |
| `ARBITUS_UPSTREAM_URL` | `transport.upstream` |
| `ARBITUS_LISTEN_ADDR` | `transport.addr` |

These work with any secret manager that exposes secrets as env vars: Kubernetes Secrets (`envFrom`), Vault Agent, External Secrets Operator, OpenBao, Infisical, etc.

## `admin_token`

Optional top-level field. When set, `/metrics` and `/dashboard` require an `Authorization: Bearer <token>` header. Without the header the endpoints return `403`.

```yaml
admin_token: "${ARBITUS_ADMIN_TOKEN}"   # recommended: inject via env var
```

## `auth` (JWT / OIDC / OAuth 2.1)

Optional. When set, every `initialize` request must carry a valid JWT in the `Authorization: Bearer` header. The gateway rejects tokens without an `exp` claim.

Accepts a single provider or a list — the first to successfully validate the token wins:

```yaml
# HMAC (HS256) — shared secret
auth:
  secret: "your-signing-secret"
  issuer: "https://auth.example.com"   # optional — validated if set
  audience: "arbitus"               # optional — validated if set

# JWKS (RS256 / OIDC) — explicit endpoint
auth:
  jwks_url: "https://auth.example.com/.well-known/jwks.json"
  issuer: "https://auth.example.com"
  audience: "arbitus"

# Provider presets — OIDC discovery URL resolved automatically
auth:
  provider: google
  audience: "my-oauth-client-id"

# Multiple providers — any valid token is accepted
auth:
  - provider: google
    audience: "my-client-id"
  - provider: github-actions
    audience: "https://github.com/myorg"
  - provider: okta
    issuer: "https://dev-123.okta.com"
    audience: "api://default"
```

| Provider | Issuer (auto-set) | Notes |
|---|---|---|
| `google` | `https://accounts.google.com` | Google Cloud / Firebase ID tokens |
| `github-actions` | `https://token.actions.githubusercontent.com` | GitHub Actions OIDC tokens |
| `auth0` | user-specified `issuer` required | Auth0 tenants |
| `okta` | user-specified `issuer` required | Okta orgs |

JWKS keys are fetched lazily, cached for 5 minutes, and refreshed on expiry. OIDC discovery documents are cached for the process lifetime.

## `upstreams`

Named upstream servers. Agents can route to a specific upstream by setting `upstream: <name>` in their policy. Agents without a named upstream use the default `transport.upstream`.

```yaml
upstreams:
  filesystem: "http://localhost:3001/mcp"
  database:   "http://localhost:3002/mcp"

agents:
  cursor:
    upstream: filesystem
    allowed_tools: [read_file]
  claude-code:
    upstream: database
    denied_tools: [drop_table]
```

## `agents`

Each key is an agent name matched against the `clientInfo.name` field in the MCP `initialize` message.

| Field | Description |
|---|---|
| `allowed_tools` | Allowlist — only these tools are reachable. Omit to allow all. Supports glob wildcards (`read_*`, `*_file`, `fs/*`). |
| `denied_tools` | Denylist — these tools are always blocked, even if in the allowlist. Supports glob wildcards. |
| `allowed_resources` | Allowlist for `resources/read` and `resources/subscribe`. Entries are matched against the resource URI. Omit to allow all. Supports glob wildcards. |
| `denied_resources` | Resource URIs always denied. Takes priority over `allowed_resources`. Supports glob wildcards. |
| `allowed_prompts` | Allowlist for `prompts/get`. Entries are matched against the prompt name. Omit to allow all. Supports glob wildcards. |
| `denied_prompts` | Prompt names always denied. Takes priority over `allowed_prompts`. Supports glob wildcards. |
| `rate_limit` | Max `tools/call` requests per minute. Default: 60. |
| `tool_rate_limits` | Per-tool rate limits (calls/min). Checked in addition to `rate_limit`. |
| `upstream` | Named upstream to use for this agent. Falls back to the default. |
| `api_key` | Pre-shared API key. Agent must send `X-Api-Key: <key>` on `initialize`. Optional. |
| `timeout_secs` | Upstream timeout in seconds for this agent. Overrides the default 30s. Optional. |
| `approval_required` | List of tool patterns that require human approval before being forwarded. Supports glob wildcards. |
| `hitl_timeout_secs` | Seconds to wait for a human decision before auto-rejecting. Default: 60. |
| `shadow_tools` | List of tool patterns to intercept in shadow mode — logged but not forwarded to upstream. Supports glob wildcards. |

Agents not listed in the config are blocked entirely unless `default_policy` is set.

Example with `api_key`, `tool_rate_limits`, HITL, and shadow mode:

```yaml
agents:
  cursor:
    allowed_tools: [read_file, write_file, list_directory, delete_file]
    rate_limit: 60
    tool_rate_limits:
      write_file: 5       # max 5 write_file calls/min, within the global 60/min
    api_key: "sk-cursor-secret"
    approval_required:
      - delete_file       # human must approve every delete
    shadow_tools:
      - "exec_*"          # intercept all exec_* tools silently
```

## `default_policy`

Optional top-level fallback applied to any agent not listed in `agents`. Useful when you want to allow unknown agents with baseline restrictions rather than hard-blocking them.

```yaml
default_policy:
  denied_tools: [delete_file, drop_table]
  rate_limit: 10
  timeout_secs: 5
```

## `rules`

| Field | Description |
|---|---|
| `block_patterns` | List of regex patterns applied to `tools/call` arguments and upstream responses. Applied after decoding Base64, percent-encoding, double-encoding, and Unicode normalization — obfuscated payloads are not bypassed. |
| `filter_mode` | `block` (default) or `redact`. In `redact` mode, matching values in arguments are scrubbed to `[REDACTED]` and the sanitised request is forwarded instead of being rejected. Responses are always scrubbed regardless of this setting. |
| `block_prompt_injection` | `true` to enable built-in prompt injection detection (7 patterns). Matched requests are always blocked, even in `redact` mode. Default: `false`. |
| `ip_rate_limit` | Max `tools/call` requests per minute per client IP. Applied before per-agent limits. Optional. |
| `validate_schema` | `true` to enable JSON schema validation of `tools/call` arguments against the `inputSchema` from `tools/list`. Requests with invalid or unexpected fields are blocked. Default: `false`. |
| `opa.policy_path` | Path to a Rego policy file (`.rego`). When set, every `tools/call` is evaluated against the policy before reaching the upstream. Requests that do not satisfy the entrypoint are blocked. Optional. |
| `opa.entrypoint` | Rego query to evaluate. Must resolve to a boolean. Default: `data.mcp.allow`. |

```yaml
rules:
  block_patterns:
    - "password"
    - "api_key"
  filter_mode: redact          # scrub instead of block
  block_prompt_injection: true # detect "ignore previous instructions" etc.
  ip_rate_limit: 100
  opa:
    policy_path: policy.rego   # path to Rego policy file
    entrypoint: data.mcp.allow # boolean query (default)
```

**Example policy** (`policy.rego`):

```rego
package mcp
import future.keywords.if

default allow := false

# Only allow read-only tools during business hours
allow if {
    input.tool_name == "read_file"
}

# Trusted agents can call any tool
allow if {
    input.agent_id == "ops-agent"
}
```

The policy input object contains: `agent_id`, `method`, `tool_name`, `arguments`, `client_ip`. Policy file changes are picked up automatically on hot-reload.

## Config validation

Validate a config file without starting the gateway:

```sh
./arbitus validate gateway.yml
```

Checks performed: regex syntax in `block_patterns`, upstream name references, TLS file paths, circuit breaker threshold, and tool name format.

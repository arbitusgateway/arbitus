# Threat Model

This document describes what Arbitus is designed to protect, which trust boundaries it enforces, and which risks remain outside the gateway's control.

Arbitus is a policy enforcement point between AI agents and MCP servers. It should be treated as part of your security boundary when agents can reach filesystems, databases, internal APIs, deployment systems, or other tools with side effects.

## Assets Protected

| Asset | Why it matters | Arbitus controls |
|-------|----------------|------------------|
| Secrets | API keys, bearer tokens, private keys, `.env` values, cloud credentials | Encoding-aware payload filtering, response filtering, block/redact mode |
| Internal tools | Filesystem, database, browser, deployment, ticketing, and internal API tools | Tool allowlists/denylists, `tools/list` filtering, OPA/Rego |
| Production state | Files, databases, services, deploy targets, and mutable infrastructure | HITL approvals, shadow mode, denied tools, schema validation |
| Agent budget and infrastructure | Runaway tool loops can create cost or availability incidents | Per-agent, per-tool, and per-IP rate limits, upstream timeouts, circuit breaker |
| Audit evidence | Security teams need to reconstruct who called what and why | Request IDs, SQLite, webhook, CloudEvents, OpenLineage, stdout audit |
| MCP server supply chain | Stdio MCP servers may be local binaries or package-manager-installed tools | SHA-256 and cosign verification before spawning stdio servers |

## Trust Boundaries

```
AI Agent / MCP Client
        │
        │ initialize, tools/list, tools/call, resources/*, prompts/*
        ▼
Arbitus Gateway
        │
        │ policy-enforced upstream calls
        ▼
MCP Server / Tool Runtime
        │
        ▼
Files, databases, APIs, SaaS, production systems
```

Additional boundaries:

| Boundary | Assumption |
|----------|------------|
| Agent to Arbitus | Agents may be buggy, compromised, prompt-injected, or overly broad in tool use. |
| Arbitus to upstream MCP server | Upstream servers may expose more tools than each agent should see or call. |
| Arbitus to auth provider | JWT/OIDC providers and mTLS CA material are trusted to identify agents correctly. |
| Arbitus to audit backend | Audit backends are trusted to persist events and enforce their own access controls. |
| Operator to HITL API | Operators approving HITL requests are trusted for the actions they approve. |
| Config source to Arbitus | Config files, ConfigMaps, and secret providers are trusted inputs and must be protected. |

## Threats Mitigated

### Secret Exfiltration in Tool Arguments

An agent may accidentally send `.env` contents, API keys, tokens, or private keys through `tools/call` arguments.

Controls:

- `rules.block_patterns`
- `rules.filter_mode: block` or `redact`
- Base64, percent-encoding, double-encoding, and Unicode normalization before matching
- Audit entries for blocked calls

### Sensitive Data in Tool Responses

An upstream MCP server may return sensitive content that should not enter model context or be shown to the agent.

Controls:

- Response filtering using the same block patterns
- Redaction of matching response content
- Audit entries tied to request IDs

### Unauthorized Tool Discovery

An agent may discover tools that it should not know about, such as `delete_file`, `exec_shell`, or `drop_table`.

Controls:

- `tools/list` filtering
- `allowed_tools` and `denied_tools`
- Glob patterns for tool families

### Direct Calls to Hidden Tools

An agent may guess a hidden tool name and call it directly.

Controls:

- Policy enforcement on `tools/call`
- Denylists take priority over allowlists
- OPA/Rego checks for custom conditions

### Prompt Injection Payloads

Retrieved content or user-provided payloads may instruct the agent to ignore prior instructions, reveal secrets, or call another tool.

Controls:

- Built-in prompt injection detection patterns
- Payload and response filtering
- HITL approval for high-risk tools
- Audit logging for blocked attempts

### Runaway Tool Loops

An agent may repeatedly call tools because of a loop, bad planning, retry bug, or prompt injection.

Controls:

- Per-agent rate limits
- Per-tool rate limits
- Per-IP rate limits
- Upstream timeouts
- Circuit breaker for failing upstreams

### Risky Writes and Side Effects

Agents may attempt to write files, delete data, deploy code, mutate databases, or call shell-like tools.

Controls:

- `denied_tools`
- `approval_required` HITL workflow
- `shadow_tools` dry-run mode
- OPA/Rego policy
- JSON schema validation for tool arguments

### Missing Audit Trail

Without a gateway, tool calls may be scattered across agent logs, editor logs, upstream logs, and vendor traces.

Controls:

- Unified request IDs
- SQLite audit log
- Webhook fan-out
- CloudEvents 1.0 for SIEM ingestion
- OpenLineage for lineage-oriented environments
- Prometheus and OpenTelemetry for operations

## Threats Not Fully Mitigated

Arbitus reduces risk at the MCP gateway boundary. It does not remove the need to secure agents, upstream tools, networks, identities, or operators.

| Risk | Why it remains | Recommended control |
|------|----------------|---------------------|
| Direct gateway bypass | An agent can avoid Arbitus if it can reach the upstream MCP server directly | Network policy, localhost-only upstreams, sidecar pattern, firewall rules |
| Overly permissive config | `allowed_tools: ["*"]` or weak patterns can allow dangerous actions | Deny-by-default policies, reviews, `arbitus validate`, OPA for production |
| Compromised upstream MCP server | A malicious server can lie in descriptions, return bad data, or abuse its own credentials | Pin trusted servers, verify stdio binaries, isolate credentials, monitor audit |
| Malicious approved operator | HITL cannot protect against an operator intentionally approving a bad action | RBAC, separation of duties, approval audit, change-management process |
| Model hallucination | Arbitus cannot make a model reason correctly | Keep policies external to the model, require HITL for side effects |
| Unknown secret formats | Regex filters only match configured or built-in patterns | Add organization-specific patterns and DLP integrations via webhook/SIEM |
| Side channels | Data may leak through timing, tool names, aggregate counts, or allowed summaries | Minimize tool exposure, avoid broad read tools, review upstream server design |
| Auth provider compromise | Valid JWTs or certificates from a compromised provider may be accepted | Protect identity provider, rotate credentials, use short TTLs, monitor anomalies |
| Audit backend compromise | Events can be deleted or altered outside Arbitus if the backend allows it | Restrict backend access, use append-only storage, verify SQLite hash chain |
| Local machine compromise | A compromised developer workstation can tamper with local config or traffic | Endpoint security, config management, mTLS/TLS, central gateways for sensitive tools |

## Recommended Deployment Patterns

### Local Developer Gateway

Use for individual developers trying Claude Code, Cursor, or SDK agents against local MCP servers.

Recommended controls:

- `arbitus policy init claude-code` or another starter policy
- Secret blocking enabled
- Deny command-like tools by default
- HITL for writes
- Audit to SQLite

### Project Gateway

Use one gateway config per repository or team toolchain.

Recommended controls:

- Project-scoped MCP config pointing agents to Arbitus
- Deny-by-default `default_policy`
- Agent-specific policies for Claude Code, Cursor, and SDK clients
- Shared policy review in code review
- Audit fan-out to webhook or SIEM

### Kubernetes Sidecar

Run Arbitus in the same pod as an agent or MCP-facing service. The agent talks to `localhost:4000/mcp`; Arbitus talks to the upstream MCP server.

Recommended controls:

- Upstream reachable only from the pod or namespace
- Kubernetes Secret or External Secrets for credentials
- NetworkPolicy restricting ingress and egress
- ConfigMap watcher for hot reload
- Prometheus and OpenTelemetry enabled

### Central Gateway

Run Arbitus as a shared gateway for many agents and upstream MCP servers.

Recommended controls:

- TLS or mTLS
- JWT/OIDC auth
- Per-agent upstream routing
- OPA/Rego for environment-specific policy
- Admin token for `/dashboard` and `/metrics`
- Audit fan-out to append-only or SIEM-backed storage

## Hardening Checklist

- [ ] Agents connect to Arbitus, not directly to upstream MCP servers.
- [ ] Upstream MCP servers are not reachable from untrusted networks.
- [ ] `default_policy` is deny-by-default or tightly restricted.
- [ ] Each known agent has an explicit policy.
- [ ] Dangerous tools are denied, shadowed, or require HITL approval.
- [ ] Writes, deletes, deploys, database mutations, and command-like tools require explicit controls.
- [ ] `rules.block_prompt_injection` is enabled for agent-facing deployments.
- [ ] `block_patterns` include organization-specific secrets and token formats.
- [ ] `filter_mode` is chosen intentionally: `block` for strict environments, `redact` where continuity matters.
- [ ] `validate_schema` is enabled when upstream tool schemas are reliable.
- [ ] OPA/Rego is used for production-specific rules.
- [ ] API keys, JWT/OIDC, or mTLS identify agents instead of trusting only `clientInfo.name`.
- [ ] TLS is enabled for non-local traffic.
- [ ] `/dashboard` and `/metrics` are protected with `admin_token`.
- [ ] Audit logs are persisted and shipped to a backend with restricted access.
- [ ] SQLite audit hash-chain verification is run when using SQLite for compliance evidence.
- [ ] Stdio MCP server binaries are pinned with SHA-256 or verified with cosign where practical.
- [ ] Config files, ConfigMaps, and secret sources are protected from untrusted writes.
- [ ] Rate limits are set per agent and per high-cost or high-risk tool.
- [ ] Operators who approve HITL requests are authenticated and their approvals are audited.

## Design Principle

Policies should live outside the model. Agents can suggest actions, but Arbitus enforces which actions are visible, allowed, rate-limited, approved, redacted, blocked, and audited.

# Audit

Every request is recorded with a unique `X-Request-Id`. Audit backends use bounded channels (4096 entries) with `arbitus_audit_drops_total` Prometheus counter for backpressure alerting.

## Backends

Use `audit:` for a single backend or `audits:` to fan-out to multiple backends simultaneously:

```yaml
# Single backend (backward compatible)
audit:
  type: sqlite
  path: "gateway-audit.db"

# Multiple backends — all receive every event
audits:
  - type: sqlite
    path: "gateway-audit.db"
  - type: webhook
    url: "https://hooks.example.com/mcp"
    token: "secret"
```

| Value | Description |
|---|---|
| `type: stdout` | Print entries to stdout (default) |
| `type: sqlite` | Persist to a SQLite database at `path` |
| `type: webhook` | POST each entry as JSON to `url` |
| `type: openlineage` | POST OpenLineage `RunEvent` to `url` |

## Webhook — plain JSON

```yaml
audit:
  type: webhook
  url: "https://hooks.example.com/mcp-audit"
  token: "secret"   # optional — sent as Bearer token in Authorization header
```

Payload sent on each request:

```json
{
  "ts": 1711584000,
  "agent_id": "cursor",
  "method": "tools/call",
  "tool": "write_file",
  "outcome": "blocked",
  "reason": "tool 'write_file' not in allowlist"
}
```

## Webhook — CloudEvents 1.0

Set `cloudevents: true` to emit [CNCF CloudEvents 1.0](https://cloudevents.io/) envelopes. The `Content-Type` header becomes `application/cloudevents+json`, enabling direct ingestion by SIEMs and event brokers without custom parsers.

```yaml
audit:
  type: webhook
  url: "https://hooks.splunk.example.com/mcp"
  token: "splunk-hec-token"
  cloudevents: true
   source: "https://gateway.prod.example.com"  # optional, default: /arbitus
```

CloudEvents envelope:

```json
{
  "specversion": "1.0",
  "type": "dev.arbitus.audit.blocked",
  "source": "https://gateway.prod.example.com",
  "id": "req-abc-123",
  "time": "2026-03-31T00:54:00Z",
  "datacontenttype": "application/json",
  "data": {
    "agent_id": "cursor",
    "method": "tools/call",
    "tool": "write_file",
    "outcome": "blocked",
    "reason": "tool 'write_file' not in allowlist"
  }
}
```

Event types follow the reverse-DNS convention: `dev.arbitus.audit.<outcome>` where outcome is `allowed`, `blocked`, `forwarded`, or `shadowed`.

## OpenLineage

Emits an OpenLineage `RunEvent` (spec 2-0-2) for every `tools/call`. Enables data lineage tracing for LGPD/GDPR compliance: "agent X called tool Y which accessed Z".

```yaml
audit:
  type: openlineage
  url: "https://api.openlineage.io/api/v1/lineage"
  token: "my-api-key"   # optional — sent as Bearer token
   namespace: "arbitus"    # optional — OpenLineage job.namespace, default: "arbitus"
```

Or fan-out alongside other backends:

```yaml
audits:
  - type: sqlite
    path: "gateway-audit.db"
  - type: openlineage
    url: "https://marquez.internal/api/v1/lineage"
    namespace: "prod-gateway"
```

Payload sent per `tools/call`:

```json
{
  "eventType": "COMPLETE",
  "eventTime": "2026-03-31T00:54:00Z",
  "run": {
    "runId": "550e8400-e29b-41d4-a716-446655440000",
    "facets": {
      "arbitus:execution": { "outcome": "allowed", "agent": "cursor", "input_tokens": 12 },
      "arbitus:arguments": { "arguments": { "path": "/etc/hosts" } }
    }
  },
  "job": { "namespace": "arbitus", "name": "cursor/read_file", "facets": {} },
  "inputs": [{ "namespace": "cursor", "name": "read_file" }],
  "outputs": [],
  "producer": "https://github.com/arbitusgateway/arbitus",
  "schemaURL": "https://openlineage.io/spec/2-0-2/OpenLineage.json#/definitions/RunEvent"
}
```

`eventType` is `COMPLETE` for allowed/forwarded/shadowed and `FAIL` for blocked. The `run.runId` matches the `X-Request-Id` header so lineage events can be correlated with audit log entries.

## Audit CLI

Query the audit log without opening SQLite directly:

```sh
# Last 50 entries
./arbitus audit gateway-audit.db

# Only blocked requests in the last hour
./arbitus audit gateway-audit.db --outcome blocked --since 1h

# All activity from a specific agent
./arbitus audit gateway-audit.db --agent cursor

# Increase the row limit
./arbitus audit gateway-audit.db --limit 200
```

Output:

```
AGE            AGENT            METHOD             TOOL                   OUTCOME    REASON
──────────────────────────────────────────────────────────────────────────────────────────────
3s ago         cursor           tools/call         write_file             blocked    tool 'write_file' not in allowlist
5s ago         cursor           tools/call         read_file              allowed
7s ago         cursor           tools/call         delete_file            shadowed
9s ago         claude-code      tools/call         write_file             blocked    tool 'write_file' explicitly denied
──────────────────────────────────────────────────────────────────────────────────────────────
Showing 4 of 4 total record(s) — since=1m
```

### Flags

| Flag | Description |
|---|---|
| `--agent NAME` | Filter by agent name |
| `--since DURATION` | Relative time window: `30s`, `5m`, `2h`, `7d` |
| `--outcome VALUE` | `allowed`, `blocked`, `forwarded`, or `shadowed` |
| `--limit N` | Max rows (default: 50) |

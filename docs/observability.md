# Observability

## Metrics

The HTTP gateway exposes a Prometheus-compatible metrics endpoint:

```sh
curl http://localhost:4000/metrics
# With admin_token:
curl http://localhost:4000/metrics -H "Authorization: Bearer admin-secret"
```

```
# HELP arbitus_requests_total Total requests processed by the gateway
# TYPE arbitus_requests_total counter
arbitus_requests_total{agent="cursor",outcome="allowed"} 12
arbitus_requests_total{agent="cursor",outcome="blocked"} 3
arbitus_requests_total{agent="cursor",outcome="shadowed"} 2
arbitus_requests_total{agent="claude-code",outcome="forwarded"} 8

# HELP arbitus_tokens_total Estimated token count processed by arbitus (4-chars-per-token heuristic)
# TYPE arbitus_tokens_total counter
arbitus_tokens_total{agent="cursor",direction="input"} 1420
arbitus_tokens_total{agent="cursor",direction="output"} 3870
arbitus_tokens_total{agent="claude-code",direction="input"} 520
arbitus_tokens_total{agent="claude-code",direction="output"} 1340
```

### Cost observability

Use `arbitus_tokens_total` for per-agent chargeback dashboards in Grafana or Datadog. The `input` direction tracks tokens sent to upstream MCP servers; `output` tracks tokens returned in responses. Both use the 4-chars-per-token heuristic — actual billing by model providers may differ. `input_tokens` is also stored in the SQLite audit log per request.

## Health check

```sh
curl http://localhost:4000/health
```

```json
{
  "status": "ok",
  "version": "0.18.0",
  "upstreams": {
    "default": true,
    "filesystem": true,
    "database": false
  }
}
```

Returns `200 OK` when all upstreams are healthy, `503 Service Unavailable` when any are degraded (circuit open). The status reflects the circuit breaker state — no extra probing requests are made.

## Dashboard

The HTTP gateway exposes an audit dashboard at `/dashboard`:

```sh
open http://localhost:4000/dashboard
# With admin_token:
curl http://localhost:4000/dashboard -H "Authorization: Bearer admin-secret"
```

Supports filtering by agent via query parameter:

```sh
curl "http://localhost:4000/dashboard?agent=cursor"
```

## Config hot-reload

Agent policies and block patterns reload from disk every 30 seconds automatically, or immediately on `SIGUSR1`:

```sh
kill -USR1 $(pidof arbitus)
```

No restart required. In-flight requests are not affected. Failed reloads keep the previous config active and increment `arbitus_config_reload_failures_total`.

## OpenTelemetry

Export traces to any OTLP-compatible backend (Jaeger, Grafana Tempo, Honeycomb, Datadog, etc.):

```yaml
telemetry:
  otlp_endpoint: "http://localhost:4317"   # gRPC OTLP
  service_name: "arbitus"               # optional, default: "arbitus"
```

Every `tools/call` creates a span with `agent_id`, `method`, and `tool` attributes. Spans are exported in batches; any buffered spans are flushed on shutdown.

```sh
# Quick local test with Jaeger all-in-one
docker run -p 4317:4317 -p 16686:16686 jaegertracing/all-in-one
LOG_LEVEL=debug ./arbitus gateway.yml
open http://localhost:16686
```

## Logging

Control log format and level via environment variables:

```sh
# Structured JSON (production / log aggregators)
LOG_FORMAT=json ./arbitus gateway.yml

# Adjust log level (default: info)
LOG_LEVEL=debug ./arbitus gateway.yml
```

## Circuit breaker

Upstream failures open the circuit after a configurable threshold. Once open, requests receive `503` immediately without contacting the upstream. After the recovery timeout, the circuit enters half-open state and allows a single probe request — if it succeeds, the circuit closes; if it fails, it reopens.

```yaml
transport:
  circuit_breaker:
    threshold: 5
    recovery_secs: 30
```

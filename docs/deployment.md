# Deployment

## Docker

```sh
# Pull the latest image
docker pull ghcr.io/arbitusgateway/arbitus:latest

# Run with your config file
docker run --rm \
  -p 4000:4000 \
  -v $(pwd)/gateway.yml:/app/gateway.yml:ro \
  -e ARBITUS_ADMIN_TOKEN=your-secret \
  ghcr.io/arbitusgateway/arbitus:latest

# Or with docker-compose (includes healthcheck and audit log persistence)
docker compose up
```

Available tags: `latest`, `0.14`, `0.14.0`. Multi-arch: `linux/amd64` and `linux/arm64`.

## Helm

```sh
# Add the Helm repository
helm repo add arbitus https://nfvelten.github.io/arbitus
helm repo update

# Install from the repo
helm install arbitus arbitus/arbitus \
  --set env[0].name=ARBITUS_UPSTREAM_URL \
  --set env[0].value=http://mcp-server:3000/mcp
```

```sh
# Install with defaults (points upstream to $ARBITUS_UPSTREAM_URL) — local chart
helm install arbitus ./charts/arbitus \
  --set env[0].name=ARBITUS_UPSTREAM_URL \
  --set env[0].value=http://mcp-server:3000/mcp

# Install with an existing Kubernetes Secret
helm install arbitus ./charts/arbitus --set existingSecret=arbitus-secrets

# Upgrade
helm upgrade arbitus ./charts/arbitus -f my-values.yaml
```

### Sidecar pattern

```yaml
# my-values.yaml — sidecar example
config:
  gateway: |
    transport:
      type: http
      addr: "0.0.0.0:4000"
      upstream: "${ARBITUS_UPSTREAM_URL}"
    agents:
      my-agent:
        allowed_tools: [read_file, list_dir]
        rate_limit: 60
    rules:
      block_prompt_injection: true

existingSecret: arbitus-secrets   # must contain ARBITUS_UPSTREAM_URL

extraContainers:
  - name: my-agent
    image: my-org/my-agent:latest
    env:
      - name: MCP_GATEWAY_URL
        value: http://localhost:4000/mcp
```

```
┌─────────────────────────────────┐
│  Pod                            │
│  ┌──────────┐  ┌─────────────┐ │
│  │  agent   │→ │   arbitus   │ │
│  │(sidecar) │  │  :4000/mcp  │ │
│  └──────────┘  └──────┬──────┘ │
└─────────────────────────│───────┘
                          ↓
                   MCP Server
```

### Helm values reference

| Key | Default | Description |
|-----|---------|-------------|
| `image.tag` | `""` (appVersion) | Override image tag |
| `existingSecret` | `""` | K8s Secret loaded via `envFrom` |
| `env` | `[]` | Extra env vars injected into arbitus |
| `autoscaling.enabled` | `false` | Enable HPA |
| `podDisruptionBudget.enabled` | `false` | Enable PDB |
| `networkPolicy.enabled` | `false` | Restrict ingress to `arbitus-client: "true"` pods |
| `persistence.enabled` | `false` | PVC for SQLite audit log |
| `extraContainers` | `[]` | Sidecar containers sharing Pod network |

## HTTPS

Add `tls` to the transport config:

```yaml
transport:
  type: http
  addr: "0.0.0.0:4443"
  upstream: "http://localhost:3000/mcp"
  tls:
    cert: "cert.pem"
    key:  "key.pem"
```

## mTLS agent authentication

Set `tls.client_ca` to a PEM file containing the CA certificate used to sign agent client certs. The gateway will require and verify a client certificate on every connection. The verified CN is matched against `mtls_identity` in the agent policy — no API key is needed:

```yaml
transport:
  type: http
  addr: "0.0.0.0:4443"
  upstream: "http://localhost:3000/mcp"
  tls:
    cert: "server.pem"
    key:  "server-key.pem"
    client_ca: "agent-ca.pem"   # enables mTLS

agents:
  cursor:
    mtls_identity: "cursor.agents.internal"   # must match client cert CN
    allowed_tools: ["read_file", "list_dir"]
```

Authentication priority: JWT Bearer → mTLS cert CN → `X-Api-Key` → `clientInfo.name` (no auth).

## stdio mode

The gateway spawns the MCP server as a child process and mediates the stdio pipe:

```yaml
transport:
  type: stdio
  server: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
```

```sh
./arbitus my-config.yml
```

This is the mode used when configuring the gateway inside tools like Cursor or Claude Code — the editor talks to the gateway via stdio, and the gateway talks to the real server the same way.

## Graceful shutdown

SIGTERM and CTRL-C are handled in both HTTP and stdio transports. Active connections are drained, child processes closed, and all audit backends flushed before exit — safe for Kubernetes `terminationGracePeriodSeconds`.

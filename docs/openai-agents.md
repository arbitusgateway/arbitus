# OpenAI Agents SDK Setup

Use this guide to connect OpenAI Agents SDK applications to MCP servers through Arbitus.

Official OpenAI Agents SDK MCP docs: <https://openai.github.io/openai-agents-js/guides/mcp/>

## 1. Start your upstream MCP server

For a local demo, use the included dummy server:

```sh
cargo run --bin dummy-server
```

For a real deployment, set `transport.upstream` in the policy to your MCP server URL.

## 2. Start Arbitus

Use the OpenAI Agents SDK starter policy:

```sh
arbitus policy init openai-agents --out gateway.yml
arbitus gateway.yml
```

During local development from source:

```sh
cargo run --bin arbitus -- policy init openai-agents --out gateway.yml
cargo run --bin arbitus -- gateway.yml
```

This policy includes an `openai-agent` entry and a restrictive `default_policy`. The default is intentional: SDK versions and MCP client implementations can differ in the `clientInfo.name` they send during `initialize`. The fallback keeps first-run behavior safe while you confirm the exact agent ID from the audit log.

## 3. Connect with `MCPServerStreamableHttp`

The Agents SDK supports Streamable HTTP MCP servers via `MCPServerStreamableHttp`. Point the SDK at Arbitus:

```ts
import { Agent, MCPServerStreamableHttp, run } from '@openai/agents';

async function main() {
  const arbitus = new MCPServerStreamableHttp({
    url: 'http://localhost:4000/mcp',
    name: 'Arbitus MCP Gateway',
  });

  const agent = new Agent({
    name: 'openai-agent',
    instructions: 'Use MCP tools only when they are needed for the task.',
    mcpServers: [arbitus],
  });

  try {
    await arbitus.connect();
    const result = await run(agent, 'List the safe tools available through MCP.');
    console.log(result.finalOutput);
  } finally {
    await arbitus.close();
  }
}

main().catch(console.error);
```

After the first run, check which agent ID Arbitus recorded:

```sh
arbitus audit gateway-audit.db --limit 10
```

If the SDK reports a different agent ID, copy the `openai-agent` policy block in `gateway.yml` and rename it to the observed ID. You can then make `default_policy` stricter or empty.

## 4. Add an API key header

If the Arbitus policy sets `api_key` for `openai-agent`, pass the header through the SDK's request options:

```ts
const arbitus = new MCPServerStreamableHttp({
  url: 'http://localhost:4000/mcp',
  name: 'Arbitus MCP Gateway',
  requestInit: {
    headers: {
      'X-Api-Key': process.env.ARBITUS_AGENT_API_KEY!,
    },
  },
});
```

## 5. Test blocked events

Run the [Security demo](security-demo.md) or have your app call an MCP tool with a fake secret payload such as `OPENAI_API_KEY=sk-demo-secret`.

Then query the audit log:

```sh
arbitus audit gateway-audit.db --outcome blocked --limit 10
```

## Production notes

- Use Arbitus for policy that must be enforced outside application code.
- Keep SDK-level `toolFilter` useful for UX, but do not rely on it as the only security boundary.
- Use `cacheToolsList` only when your Arbitus policy and upstream tool list are stable enough for cached discovery.
- Add `approval_required` or OPA/Rego policy for write, delete, deploy, database mutation, and external side-effect tools.

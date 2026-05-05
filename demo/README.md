# Demo

## Secret Leak Block

Run the reproducible terminal demo:

```sh
./demo/secret-leak.sh
```

The script starts local servers on `127.0.0.1`, so run it in an environment where binding localhost ports is allowed.

The script:

1. Builds `arbitus` and `dummy-server`.
2. Runs `arbitus policy init claude-code`.
3. Starts the dummy MCP server.
4. Starts Arbitus on a local gateway port.
5. Initializes an MCP session as `claude-code`.
6. Shows filtered tools.
7. Attempts to send `OPENAI_API_KEY=sk-demo-secret` through `tools/call`.
8. Shows the blocked audit entry.

Default ports:

| Service | Address |
|---------|---------|
| Arbitus | `127.0.0.1:4100` |
| Dummy MCP server | `127.0.0.1:3100` |

Override ports if needed:

```sh
GATEWAY_ADDR=127.0.0.1:4200 DUMMY_ADDR=127.0.0.1:3200 ./demo/secret-leak.sh
```

Runtime files are written to `/tmp/arbitus-secret-leak-demo` unless `TMPDIR` is set.

## Recording

With VHS installed, record the demo from a terminal:

```sh
vhs demo/secret-leak.tape
```

The generated GIF is written to `docs/assets/secret-leak-demo.gif`.

If VHS is not installed, generate the checked-in GIF asset with ImageMagick:

```sh
./demo/render-secret-leak-gif.sh
```

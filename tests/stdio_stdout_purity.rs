//! In stdio mode, stdout is the JSON-RPC channel — nothing else may be written
//! there. Tracing output on stdout corrupts the protocol and every MCP client
//! fails to parse the stream.
//!
//! Regression test for that bug. Unlike the other stdio tests, this one needs no
//! npx: the upstream is a tiny `sh` loop, so it runs in CI on every commit.

mod common;

use common::GATEWAY_BIN;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Upstream stub: answers every line with one valid JSON-RPC response.
const FAKE_SERVER: &str =
    r#"while IFS= read -r _line; do printf '{"jsonrpc":"2.0","id":1,"result":{}}\n'; done"#;

fn config(audit_path: &str) -> String {
    format!(
        r#"
transport:
  type: stdio
  server: ["sh", "-c", {server:?}]

audit:
  type: sqlite
  path: {audit_path:?}

default_policy:
  rate_limit: 100
"#,
        server = FAKE_SERVER,
        audit_path = audit_path,
    )
}

#[tokio::test]
async fn stdio_stdout_carries_only_json_rpc() {
    let dir = std::env::temp_dir().join(format!("arbitus-purity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("gateway.yml");
    let audit_path = dir.join("audit.db");
    std::fs::write(&cfg_path, config(audit_path.to_str().unwrap())).unwrap();

    // RUST_LOG=info guarantees the gateway actually emits logs — without it the
    // test could pass simply because nothing was logged.
    let mut child = tokio::process::Command::new(GATEWAY_BIN)
        .arg(&cfg_path)
        .env("RUST_LOG", "info")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn gateway");

    {
        let stdin = child.stdin.as_mut().unwrap();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0"}}}"#;
        stdin
            .write_all(format!("{req}\n").as_bytes())
            .await
            .unwrap();
        stdin.shutdown().await.unwrap();
    }

    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Ok(Ok(Some(line))) =
        tokio::time::timeout_at(deadline, lines.next_line()).await
    {
        if !line.trim().is_empty() {
            seen.push(line);
        }
    }

    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !seen.is_empty(),
        "gateway produced no stdout at all — the exchange did not happen"
    );

    for line in &seen {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "non-JSON line on stdout in stdio mode — logs must go to stderr.\nOffending line: {line}"
        );
    }
}

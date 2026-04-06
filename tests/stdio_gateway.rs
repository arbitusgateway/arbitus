mod common;

use common::*;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn npx_available() -> bool {
    std::process::Command::new("npx")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn setup_test_files() {
    std::fs::create_dir_all("/tmp/mcp-test").unwrap();
    std::fs::write("/tmp/mcp-test/hello.txt", "conteudo do arquivo").unwrap();
}

/// Write a config, spawn the gateway in stdio mode, return the child.
async fn stdio_gateway(config: &str) -> tokio::process::Child {
    let port = free_port().await;
    let path = format!("/tmp/arbitus-stdio-test-{port}.yml");
    std::fs::write(&path, config).unwrap();

    tokio::process::Command::new(GATEWAY_BIN)
        .arg(&path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

/// Send newline-delimited JSON messages to the gateway and collect all
/// responses until the process exits or we reach a line count.
async fn exchange(child: &mut tokio::process::Child, messages: &[Value]) -> Vec<serde_json::Value> {
    let stdin = child.stdin.as_mut().unwrap();
    for msg in messages {
        let line = format!("{}\n", serde_json::to_string(msg).unwrap());
        stdin.write_all(line.as_bytes()).await.unwrap();
    }
    stdin.shutdown().await.unwrap();

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();
    let mut responses = Vec::new();

    // Collect lines with a 5-second timeout
    loop {
        match tokio::time::timeout(Duration::from_secs(5), reader.next_line()).await {
            Ok(Ok(Some(line))) if !line.trim().is_empty() => {
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    responses.push(v);
                }
            }
            _ => break,
        }
    }
    responses
}

fn stdio_config() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/gateway-stdio.yml"
    ))
    .expect("failed to read gateway-stdio.yml fixture")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires npx and @modelcontextprotocol/server-filesystem (run locally)"]
async fn stdio_initialize_and_tools_list() {
    if !npx_available() {
        eprintln!("skipping stdio tests: npx not available");
        return;
    }
    setup_test_files();

    let mut gw = stdio_gateway(&stdio_config()).await;
    let responses = exchange(
        &mut gw,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        ],
    )
    .await;

    let init_resp = responses.iter().find(|r| r["id"] == 1).unwrap();
    assert!(
        init_resp["result"]["serverInfo"].is_object(),
        "serverInfo missing"
    );

    let list_resp = responses.iter().find(|r| r["id"] == 2).unwrap();
    let empty = vec![];
    let tool_names: Vec<&str> = list_resp["result"]["tools"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|t| t["name"].as_str().unwrap_or(""))
        .collect();

    assert!(
        tool_names.contains(&"read_file"),
        "read_file should be visible"
    );
    assert!(
        !tool_names.contains(&"write_file"),
        "write_file should be hidden (not in cursor's allowlist)"
    );
}

#[tokio::test]
#[ignore = "requires npx and @modelcontextprotocol/server-filesystem (run locally)"]
async fn stdio_allowed_tool_returns_result() {
    if !npx_available() {
        eprintln!("skipping stdio tests: npx not available");
        return;
    }
    setup_test_files();

    let mut gw = stdio_gateway(&stdio_config()).await;
    let responses = exchange(
        &mut gw,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}),
        ],
    )
    .await;

    let resp = responses.iter().find(|r| r["id"] == 2).unwrap();
    let text = resp.to_string();
    assert!(
        text.contains("conteudo do arquivo"),
        "expected file contents in response, got: {resp}"
    );
}

#[tokio::test]
#[ignore = "requires npx and @modelcontextprotocol/server-filesystem (run locally)"]
async fn stdio_tool_not_in_allowlist_is_blocked() {
    if !npx_available() {
        eprintln!("skipping stdio tests: npx not available");
        return;
    }
    setup_test_files();

    let mut gw = stdio_gateway(&stdio_config()).await;
    let responses = exchange(
        &mut gw,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/mcp-test/pwned.txt","content":"hacked"}}}),
        ],
    )
    .await;

    let resp = responses.iter().find(|r| r["id"] == 2).unwrap();
    assert!(
        resp.to_string().to_lowercase().contains("blocked"),
        "write_file should be blocked for cursor, got: {resp}"
    );
    assert!(
        !std::path::Path::new("/tmp/mcp-test/pwned.txt").exists(),
        "file must not have been created"
    );
}

#[tokio::test]
#[ignore = "requires npx and @modelcontextprotocol/server-filesystem (run locally)"]
async fn stdio_unknown_agent_is_blocked() {
    if !npx_available() {
        eprintln!("skipping stdio tests: npx not available");
        return;
    }
    setup_test_files();

    let mut gw = stdio_gateway(&stdio_config()).await;
    let responses = exchange(
        &mut gw,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"malicious-agent","version":"1.0.0"}}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}),
        ],
    )
    .await;

    let resp = responses.iter().find(|r| r["id"] == 2).unwrap();
    assert!(
        resp.to_string().to_lowercase().contains("unknown"),
        "unknown agent should be blocked, got: {resp}"
    );
}

#[tokio::test]
#[ignore = "requires npx and @modelcontextprotocol/server-filesystem (run locally)"]
async fn stdio_sensitive_payload_is_blocked() {
    if !npx_available() {
        eprintln!("skipping stdio tests: npx not available");
        return;
    }
    setup_test_files();

    let mut gw = stdio_gateway(&stdio_config()).await;
    let responses = exchange(
        &mut gw,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/password=abc"}}}),
        ],
    )
    .await;

    let resp = responses.iter().find(|r| r["id"] == 2).unwrap();
    assert!(
        resp.to_string().to_lowercase().contains("blocked"),
        "sensitive payload should be blocked, got: {resp}"
    );
}

#[tokio::test]
#[ignore = "requires npx and @modelcontextprotocol/server-filesystem (run locally)"]
async fn stdio_rate_limit_blocks_after_threshold() {
    if !npx_available() {
        eprintln!("skipping stdio tests: npx not available");
        return;
    }
    setup_test_files();

    let mut gw = stdio_gateway(&stdio_config()).await;
    let responses = exchange(
        &mut gw,
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"rate-test","version":"1.0.0"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}),
        ],
    )
    .await;

    // First two calls should succeed
    let r2 = responses.iter().find(|r| r["id"] == 2).unwrap();
    assert!(r2["result"].is_object(), "first call should succeed");

    // Third call should be rate-limited
    let r4 = responses.iter().find(|r| r["id"] == 4).unwrap();
    assert!(
        r4.to_string().to_lowercase().contains("rate limit"),
        "third call should be rate-limited, got: {r4}"
    );
}

mod common;

use common::*;
use serde_json::json;

// ── Agent card discovery ──────────────────────────────────────────────────────

#[tokio::test]
async fn agent_card_is_served_at_well_known_path() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    let card = h.agent_card().await;
    assert_eq!(card["name"].as_str().unwrap(), "Test Agent");
    assert!(!card["supportedInterfaces"].as_array().unwrap().is_empty());
}

// ── message/send proxy ────────────────────────────────────────────────────────

#[tokio::test]
async fn message_send_proxied_to_upstream() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    let resp = h.send_message("cursor", "hello world", None).await;
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    // Result should contain the upstream's echo reply.
    assert!(
        body["result"]["message"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("echo: hello world"),
        "unexpected response: {body}"
    );
}

// ── Agent identity enforcement ────────────────────────────────────────────────

#[tokio::test]
async fn missing_agent_header_is_rejected() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    // Send without x-arbitus-agent header.
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "msg-1",
                "role": "ROLE_USER",
                "parts": [{ "text": "hello" }],
                "extensions": []
            }
        }
    });
    let resp = h
        .client
        .post(h.url("/a2a"))
        .json(&body)
        .send()
        .await
        .unwrap();
    // ra2a returns 200 with a JSON-RPC error for interceptor rejections.
    let resp_body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        resp_body["error"].is_object(),
        "expected error, got: {resp_body}"
    );
}

#[tokio::test]
async fn unknown_agent_is_rejected() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    let resp = h.send_message("ghost-agent", "hello", None).await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_object(),
        "expected error for unconfigured agent, got: {body}"
    );
}

// ── API key authentication ────────────────────────────────────────────────────

#[tokio::test]
async fn correct_api_key_allows_request() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    let resp = h
        .send_message("secured-agent", "hello", Some("test-key-123"))
        .await;
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["result"].is_object(), "expected result, got: {body}");
}

#[tokio::test]
async fn wrong_api_key_is_rejected() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    let resp = h
        .send_message("secured-agent", "hello", Some("wrong-key"))
        .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_object(),
        "expected error for wrong API key, got: {body}"
    );
}

#[tokio::test]
async fn missing_api_key_is_rejected() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    // secured-agent requires api_key but we send none.
    let resp = h.send_message("secured-agent", "hello", None).await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_object(),
        "expected error for missing API key, got: {body}"
    );
}

// ── Payload filtering ─────────────────────────────────────────────────────────

#[tokio::test]
async fn message_with_blocked_pattern_is_rejected() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    // DEFAULT_CONFIG has block_patterns: ["password=", "private_key"]
    let resp = h
        .send_message("cursor", "my private_key=AAABBBCCC", None)
        .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_object(),
        "expected block for sensitive pattern, got: {body}"
    );
}

#[tokio::test]
async fn clean_message_passes_payload_filter() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    let resp = h
        .send_message("cursor", "this is a harmless message", None)
        .await;
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["result"].is_object(),
        "expected result for clean message, got: {body}"
    );
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn rate_limit_blocks_after_limit_exceeded() {
    // rate-test agent has rate_limit: 3
    let h = harness_with_a2a(DEFAULT_CONFIG).await;

    for _ in 0..3 {
        let resp = h.send_message("rate-test", "hello", None).await;
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["result"].is_object(),
            "expected success within limit, got: {body}"
        );
    }

    // 4th request should be blocked.
    let resp = h.send_message("rate-test", "hello", None).await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_object(),
        "expected rate limit error on 4th request, got: {body}"
    );
}

// ── MCP endpoint unaffected ───────────────────────────────────────────────────

#[tokio::test]
async fn mcp_endpoint_still_works_when_a2a_is_configured() {
    let h = harness_with_a2a(DEFAULT_CONFIG).await;
    // MCP initialize should still work normally.
    let mcp_body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "cursor", "version": "1.0.0" }
        }
    });
    let resp = h
        .client
        .post(h.url("/mcp"))
        .json(&mcp_body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["result"]["serverInfo"].is_object(),
        "expected MCP initialize result, got: {body}"
    );
}

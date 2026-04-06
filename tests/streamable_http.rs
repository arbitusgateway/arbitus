mod common;

use common::*;
use serde_json::{Value, json};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse the first SSE `message` event from a raw SSE body and return its data
/// parsed as JSON. Panics if no `data:` line is found.
fn parse_sse_json(body: &str) -> Value {
    let data = body
        .lines()
        .find(|l| l.starts_with("data:"))
        .unwrap_or_else(|| panic!("no 'data:' line in SSE body:\n{body}"));
    let json_str = data.trim_start_matches("data:").trim();
    serde_json::from_str(json_str)
        .unwrap_or_else(|e| panic!("SSE data is not valid JSON: {e}\ndata: {json_str}"))
}

// ── Session lifecycle ─────────────────────────────────────────────────────────

#[tokio::test]
async fn streamable_initialize_returns_json_and_session_id() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    let (sid, body) = h.init("cursor").await;
    assert!(
        body["result"]["serverInfo"].is_object(),
        "serverInfo missing"
    );
    assert!(!sid.is_empty(), "session ID must be assigned");
}

#[tokio::test]
async fn streamable_initialize_always_returns_json_even_with_sse_accept() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    // Spec: initialize MUST return application/json
    let resp = h
        .post_accept(None, "text/event-stream", init_body("cursor"))
        .await;
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/json"),
        "initialize must return JSON regardless of Accept; got: {ct}"
    );
}

#[tokio::test]
async fn streamable_unknown_session_returns_404() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    let status = h.status(Some("no-such-session"), list_body()).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn streamable_delete_session_invalidates_it() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;

    let del = h
        .client
        .delete(h.url("/mcp"))
        .header("mcp-session-id", &sid)
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204);

    // Further requests must return 404
    let status = h.status(Some(&sid), list_body()).await;
    assert_eq!(status, 404);
}

// ── JSON vs SSE response mode ─────────────────────────────────────────────────

#[tokio::test]
async fn streamable_tools_list_returns_json_by_default() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;
    let resp = h.post(Some(&sid), list_body()).await;
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("application/json"), "expected JSON; got: {ct}");
    let body: Value = resp.json().await.unwrap();
    assert!(body["result"]["tools"].is_array());
}

#[tokio::test]
async fn streamable_tools_list_returns_sse_when_accept_event_stream() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;

    let resp = h
        .post_accept(Some(&sid), "text/event-stream", list_body())
        .await;

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/event-stream"),
        "expected SSE content-type; got: {ct}"
    );

    let raw = resp.text().await.unwrap();
    assert!(
        raw.contains("event: message"),
        "SSE body missing event type"
    );

    let body = parse_sse_json(&raw);
    assert!(
        body["result"]["tools"].is_array(),
        "tools array missing in SSE payload"
    );
}

#[tokio::test]
async fn streamable_tool_call_returns_sse_when_accept_event_stream() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    let (sid, _) = h.init("cursor").await;

    let resp = h
        .post_accept(
            Some(&sid),
            "text/event-stream",
            call_body("echo", json!({"text": "hello"})),
        )
        .await;

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/event-stream"), "expected SSE; got: {ct}");

    let raw = resp.text().await.unwrap();
    let body = parse_sse_json(&raw);
    let text = body["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert_eq!(text, "echo: hello");
}

#[tokio::test]
async fn streamable_blocked_tool_sse_error_has_correct_structure() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    // claude-code has delete_database in its denylist
    let (sid, _) = h.init("claude-code").await;

    let resp = h
        .post_accept(
            Some(&sid),
            "text/event-stream",
            call_body("delete_database", json!({})),
        )
        .await;

    // Blocked calls return a JSON-RPC error — still wrapped as SSE
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/event-stream"), "expected SSE; got: {ct}");

    let raw = resp.text().await.unwrap();
    let body = parse_sse_json(&raw);
    assert!(
        body["error"].is_object(),
        "expected JSON-RPC error in SSE payload; got: {body}"
    );
}

// ── Auth passthrough ──────────────────────────────────────────────────────────

#[tokio::test]
async fn streamable_api_key_auth_works() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    // secured-agent requires X-Api-Key: test-key-123
    let resp = h
        .client
        .post(h.url("/mcp"))
        .header("x-api-key", "test-key-123")
        .json(&init_body("secured-agent"))
        .send()
        .await
        .unwrap();
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(!sid.is_empty(), "should get a session with valid api_key");
}

#[tokio::test]
async fn streamable_missing_api_key_returns_401() {
    let h = harness_streamable(DEFAULT_CONFIG).await;
    let resp = h.post(None, init_body("secured-agent")).await;
    assert_eq!(resp.status().as_u16(), 401);
}

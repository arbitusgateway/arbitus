mod common;

use common::*;
use serde_json::json;

// ── OTLP pipeline resilience ──────────────────────────────────────────────────
//
// These tests verify that the gateway starts and operates correctly when OTLP
// is configured, even when the collector is unreachable.  The pipelines are
// asynchronous and batch-based, so a missing collector only causes background
// export errors — it must never crash the gateway or block request handling.

#[tokio::test]
async fn gateway_starts_with_export_metrics_and_unreachable_collector() {
    // Port 19999 is almost certainly not listening — collector unreachable.
    let h = harness_with_telemetry(DEFAULT_CONFIG, "http://127.0.0.1:19999", true, false).await;
    // Gateway must be healthy and serve requests normally.
    let (sid, body) = h.init("cursor").await;
    assert!(body["result"]["serverInfo"].is_object());
    assert!(!sid.is_empty());
}

#[tokio::test]
async fn gateway_starts_with_export_logs_and_unreachable_collector() {
    let h = harness_with_telemetry(DEFAULT_CONFIG, "http://127.0.0.1:19999", false, true).await;
    let (sid, _) = h.init("cursor").await;
    assert!(!sid.is_empty());
}

#[tokio::test]
async fn gateway_starts_with_all_otlp_pipelines_and_unreachable_collector() {
    let h = harness_with_telemetry(DEFAULT_CONFIG, "http://127.0.0.1:19999", true, true).await;
    let (sid, _) = h.init("cursor").await;
    assert!(!sid.is_empty());
}

// ── Prometheus /metrics unaffected ───────────────────────────────────────────

#[tokio::test]
async fn prometheus_metrics_still_work_when_otlp_is_configured() {
    let h = harness_with_telemetry(DEFAULT_CONFIG, "http://127.0.0.1:19999", true, true).await;

    // Generate some traffic so counters are non-zero.
    let (sid, _) = h.init("cursor").await;
    h.json(Some(&sid), list_body()).await;
    h.json(Some(&sid), call_body("echo", json!({"text": "otlp-test"})))
        .await;

    // /metrics must still respond with Prometheus text format.
    let metrics = h
        .client
        .get(h.url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        metrics.contains("arbitus_requests_total"),
        "Prometheus counter missing: {metrics}"
    );
}

// ── request handling unaffected by OTLP config ───────────────────────────────

#[tokio::test]
async fn tool_call_blocked_correctly_with_otlp_configured() {
    let h = harness_with_telemetry(DEFAULT_CONFIG, "http://127.0.0.1:19999", true, true).await;
    // cursor only has `echo` in allowed_tools
    let (sid, _) = h.init("cursor").await;
    let body = h
        .json(Some(&sid), call_body("delete_database", json!({})))
        .await;
    assert!(
        body["error"].is_object(),
        "expected blocked response; got: {body}"
    );
}

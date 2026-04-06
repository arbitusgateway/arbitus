use super::{AuditEntry, AuditLog, Outcome};
use crate::metrics::GatewayMetrics;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

const CHANNEL_CAPACITY: usize = 4096;

pub struct WebhookAudit {
    tx: Arc<Mutex<Option<mpsc::Sender<Arc<AuditEntry>>>>>,
    handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    metrics: Arc<GatewayMetrics>,
}

impl WebhookAudit {
    pub fn new(
        url: impl Into<String>,
        token: Option<String>,
        cloudevents: bool,
        source: String,
        metrics: Arc<GatewayMetrics>,
    ) -> Self {
        let url = url.into();
        let client = Client::new();
        let (tx, mut rx) = mpsc::channel::<Arc<AuditEntry>>(CHANNEL_CAPACITY);

        let handle = tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                let body = if cloudevents {
                    build_cloudevent(&entry, &source)
                } else {
                    build_plain(&entry)
                };

                let content_type = if cloudevents {
                    "application/cloudevents+json"
                } else {
                    "application/json"
                };

                let mut req = client
                    .post(&url)
                    .header("Content-Type", content_type)
                    .json(&body);
                if let Some(tok) = &token {
                    req = req.header("Authorization", format!("Bearer {tok}"));
                }

                if let Err(e) = req.send().await {
                    tracing::warn!(error = %e, "webhook delivery failed");
                }
            }
        });

        Self {
            tx: Arc::new(Mutex::new(Some(tx))),
            handle: Arc::new(Mutex::new(Some(handle))),
            metrics,
        }
    }
}

/// Plain JSON body — legacy format kept for backward compatibility.
fn build_plain(entry: &AuditEntry) -> Value {
    let ts = entry
        .ts
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (outcome_str, reason) = outcome_parts(&entry.outcome);
    json!({
        "ts": ts,
        "agent_id": entry.agent_id,
        "method": entry.method,
        "tool": entry.tool,
        "outcome": outcome_str,
        "reason": reason,
    })
}

/// CNCF CloudEvents 1.0 envelope.
/// Spec: https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md
fn build_cloudevent(entry: &AuditEntry, source: &str) -> Value {
    let (outcome_str, reason) = outcome_parts(&entry.outcome);

    // type follows reverse-DNS convention: dev.arbitus.audit.<outcome>
    let ce_type = format!("dev.arbitus.audit.{outcome_str}");

    // RFC 3339 timestamp
    let time: DateTime<Utc> = entry.ts.into();
    let time_str = time.to_rfc3339();

    json!({
        "specversion": "1.0",
        "type": ce_type,
        "source": source,
        "id": entry.request_id,
        "time": time_str,
        "datacontenttype": "application/json",
        "data": {
            "agent_id": entry.agent_id,
            "method": entry.method,
            "tool": entry.tool,
            "outcome": outcome_str,
            "reason": reason,
        }
    })
}

fn outcome_parts(outcome: &Outcome) -> (&'static str, Option<&str>) {
    match outcome {
        Outcome::Allowed => ("allowed", None),
        Outcome::Blocked(r) => ("blocked", Some(r.as_str())),
        Outcome::Forwarded => ("forwarded", None),
        Outcome::Shadowed => ("shadowed", None),
    }
}

#[async_trait]
impl AuditLog for WebhookAudit {
    fn record(&self, entry: Arc<AuditEntry>) {
        if let Ok(guard) = self.tx.lock()
            && let Some(tx) = guard.as_ref()
            && tx.try_send(entry).is_err()
        {
            tracing::warn!("webhook audit channel full — entry dropped");
            self.metrics.record_audit_drop("webhook");
        }
    }

    async fn flush(&self) {
        {
            let mut guard = self.tx.lock().unwrap();
            *guard = None;
        }
        let handle = {
            let mut guard = self.handle.lock().unwrap();
            guard.take()
        };
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Outcome;
    use std::time::{Duration, UNIX_EPOCH};

    fn entry(outcome: Outcome) -> Arc<AuditEntry> {
        Arc::new(AuditEntry {
            ts: UNIX_EPOCH + Duration::from_secs(1_743_375_600), // 2025-03-30T21:00:00Z
            agent_id: "cursor".to_string(),
            method: "tools/call".to_string(),
            tool: Some("read_file".to_string()),
            arguments: None,
            outcome,
            request_id: "req-abc-123".to_string(),
            input_tokens: 0,
        })
    }

    #[test]
    fn plain_body_has_expected_keys() {
        let body = build_plain(&entry(Outcome::Allowed));
        assert_eq!(body["agent_id"], "cursor");
        assert_eq!(body["outcome"], "allowed");
        assert_eq!(body["tool"], "read_file");
        assert!(
            body.get("specversion").is_none(),
            "plain should not have specversion"
        );
    }

    #[test]
    fn plain_blocked_has_reason() {
        let body = build_plain(&entry(Outcome::Blocked("rate limit".to_string())));
        assert_eq!(body["outcome"], "blocked");
        assert_eq!(body["reason"], "rate limit");
    }

    #[test]
    fn cloudevent_specversion_is_1_0() {
        let body = build_cloudevent(&entry(Outcome::Allowed), "/arbitus");
        assert_eq!(body["specversion"], "1.0");
    }

    #[test]
    fn cloudevent_type_encodes_outcome() {
        let cases = [
            (Outcome::Allowed, "dev.arbitus.audit.allowed"),
            (Outcome::Forwarded, "dev.arbitus.audit.forwarded"),
            (Outcome::Shadowed, "dev.arbitus.audit.shadowed"),
            (
                Outcome::Blocked("x".to_string()),
                "dev.arbitus.audit.blocked",
            ),
        ];
        for (outcome, expected_type) in cases {
            let body = build_cloudevent(&entry(outcome), "/arbitus");
            assert_eq!(body["type"], expected_type);
        }
    }

    #[test]
    fn cloudevent_source_propagated() {
        let body = build_cloudevent(&entry(Outcome::Allowed), "https://gateway.example.com");
        assert_eq!(body["source"], "https://gateway.example.com");
    }

    #[test]
    fn cloudevent_id_is_request_id() {
        let body = build_cloudevent(&entry(Outcome::Allowed), "/arbitus");
        assert_eq!(body["id"], "req-abc-123");
    }

    #[test]
    fn cloudevent_time_is_rfc3339() {
        let body = build_cloudevent(&entry(Outcome::Allowed), "/arbitus");
        let time_str = body["time"].as_str().unwrap();
        // RFC 3339 contains 'T' and 'Z' or offset
        assert!(
            time_str.contains('T'),
            "expected RFC 3339 timestamp, got: {time_str}"
        );
    }

    #[test]
    fn cloudevent_data_has_payload() {
        let body = build_cloudevent(&entry(Outcome::Blocked("denied".to_string())), "/arbitus");
        assert_eq!(body["datacontenttype"], "application/json");
        assert_eq!(body["data"]["agent_id"], "cursor");
        assert_eq!(body["data"]["outcome"], "blocked");
        assert_eq!(body["data"]["reason"], "denied");
    }

    #[test]
    fn cloudevent_blocked_reason_in_data() {
        let body = build_cloudevent(
            &entry(Outcome::Blocked("tool denied".to_string())),
            "/arbitus",
        );
        assert_eq!(body["data"]["reason"], "tool denied");
    }

    #[test]
    fn cloudevent_shadowed_no_reason() {
        let body = build_cloudevent(&entry(Outcome::Shadowed), "/arbitus");
        assert_eq!(body["type"], "dev.arbitus.audit.shadowed");
        assert!(body["data"]["reason"].is_null());
    }
}

use super::{AuditEntry, AuditLog, Outcome};
/// OpenLineage audit backend.
///
/// Emits an OpenLineage `RunEvent` (spec 2-0-2) for every `tools/call` audit entry.
/// Non-tool-call entries (method ≠ `tools/call`) are skipped — they carry no lineage data.
///
/// ## Event mapping
///
/// | OpenLineage field            | arbitus source                                   |
/// |------------------------------|--------------------------------------------------|
/// | `run.runId`                  | `entry.request_id` (UUID)                        |
/// | `job.namespace`              | configurable `namespace` (default: `"arbitus"`)  |
/// | `job.name`                   | `<agent_id>/<tool_name>`                         |
/// | `eventType`                  | `COMPLETE` (allowed/forwarded) / `FAIL` (blocked)|
/// | `eventTime`                  | `entry.ts` in RFC 3339 format                    |
/// | `run.facets.arbitus:execution` | outcome, reason, agent_id, input_tokens          |
/// | `inputs[0]`                  | `{namespace: agent_id, name: tool_name}`         |
/// | `producer`                   | `"https://github.com/nfvelten/arbitus"`          |
use crate::metrics::GatewayMetrics;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

const PRODUCER: &str = "https://github.com/nfvelten/arbitus";
const SCHEMA_URL: &str = "https://openlineage.io/spec/2-0-2/OpenLineage.json#/definitions/RunEvent";
const CHANNEL_CAPACITY: usize = 4096;

pub struct OpenLineageAudit {
    tx: Arc<Mutex<Option<mpsc::Sender<Arc<AuditEntry>>>>>,
    handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    metrics: Arc<GatewayMetrics>,
}

impl OpenLineageAudit {
    pub fn new(
        url: impl Into<String>,
        token: Option<String>,
        namespace: String,
        metrics: Arc<GatewayMetrics>,
    ) -> Self {
        let url = url.into();
        let client = Client::new();
        let (tx, mut rx) = mpsc::channel::<Arc<AuditEntry>>(CHANNEL_CAPACITY);

        let handle = tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                // Only tools/call carries actionable lineage data.
                if entry.method != "tools/call" {
                    continue;
                }

                let body = build_run_event(&entry, &namespace);

                let mut req = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&body);
                if let Some(tok) = &token {
                    req = req.header("Authorization", format!("Bearer {tok}"));
                }

                if let Err(e) = req.send().await {
                    tracing::warn!(error = %e, "openlineage delivery failed");
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

#[async_trait]
impl AuditLog for OpenLineageAudit {
    fn record(&self, entry: Arc<AuditEntry>) {
        if let Ok(guard) = self.tx.lock()
            && let Some(tx) = guard.as_ref()
            && tx.try_send(entry).is_err()
        {
            tracing::warn!("openlineage audit channel full — entry dropped");
            self.metrics.record_audit_drop("openlineage");
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

/// Build an OpenLineage `RunEvent` from an `AuditEntry`.
///
/// Exported for unit testing without requiring an HTTP server.
pub fn build_run_event(entry: &AuditEntry, namespace: &str) -> Value {
    let event_time = {
        let dt: DateTime<Utc> = entry
            .ts
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| {
                DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos()).unwrap_or_default()
            })
            .unwrap_or_default();
        dt.to_rfc3339()
    };

    let tool_name = entry.tool.as_deref().unwrap_or("unknown");
    let job_name = format!("{}/{}", entry.agent_id, tool_name);

    let (event_type, outcome_str, reason) = match &entry.outcome {
        Outcome::Allowed | Outcome::Forwarded | Outcome::Shadowed => {
            ("COMPLETE", outcome_label(&entry.outcome), None::<&str>)
        }
        Outcome::Blocked(r) => ("FAIL", "blocked", Some(r.as_str())),
    };

    // Execution facet — carries arbitus-specific metadata.
    let mut facet_data = json!({
        "_producer": PRODUCER,
        "_schemaURL": format!("{PRODUCER}/facets/execution"),
        "outcome": outcome_str,
        "agent": entry.agent_id,
        "input_tokens": entry.input_tokens,
    });
    if let Some(r) = reason {
        facet_data["reason"] = json!(r);
    }

    // Arguments facet — only present when arguments were captured.
    let run_facets = if let Some(args) = &entry.arguments {
        json!({
            "arbitus:execution": facet_data,
            "arbitus:arguments": {
                "_producer": PRODUCER,
                "_schemaURL": format!("{PRODUCER}/facets/arguments"),
                "arguments": args
            }
        })
    } else {
        json!({ "arbitus:execution": facet_data })
    };

    json!({
        "eventType": event_type,
        "eventTime": event_time,
        "run": {
            "runId": entry.request_id,
            "facets": run_facets
        },
        "job": {
            "namespace": namespace,
            "name": job_name,
            "facets": {}
        },
        "inputs": [{
            "namespace": entry.agent_id,
            "name": tool_name
        }],
        "outputs": [],
        "producer": PRODUCER,
        "schemaURL": SCHEMA_URL
    })
}

fn outcome_label(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Allowed => "allowed",
        Outcome::Forwarded => "forwarded",
        Outcome::Shadowed => "shadowed",
        Outcome::Blocked(_) => "blocked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Outcome;
    use std::time::{Duration, UNIX_EPOCH};

    fn entry(outcome: Outcome) -> Arc<AuditEntry> {
        Arc::new(AuditEntry {
            ts: UNIX_EPOCH + Duration::from_secs(1_743_375_600),
            agent_id: "cursor".to_string(),
            method: "tools/call".to_string(),
            tool: Some("read_file".to_string()),
            arguments: Some(serde_json::json!({"path": "/etc/hosts"})),
            outcome,
            request_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            input_tokens: 8,
        })
    }

    #[test]
    fn allowed_produces_complete_event() {
        let ev = build_run_event(&entry(Outcome::Allowed), "arbitus");
        assert_eq!(ev["eventType"], "COMPLETE");
        assert_eq!(ev["schemaURL"], SCHEMA_URL);
        assert_eq!(ev["producer"], PRODUCER);
    }

    #[test]
    fn blocked_produces_fail_event() {
        let ev = build_run_event(&entry(Outcome::Blocked("rate limit".into())), "arbitus");
        assert_eq!(ev["eventType"], "FAIL");
        assert_eq!(
            ev["run"]["facets"]["arbitus:execution"]["outcome"],
            "blocked"
        );
        assert_eq!(
            ev["run"]["facets"]["arbitus:execution"]["reason"],
            "rate limit"
        );
    }

    #[test]
    fn job_name_combines_agent_and_tool() {
        let ev = build_run_event(&entry(Outcome::Allowed), "arbitus");
        assert_eq!(ev["job"]["name"], "cursor/read_file");
        assert_eq!(ev["job"]["namespace"], "arbitus");
    }

    #[test]
    fn run_id_matches_request_id() {
        let ev = build_run_event(&entry(Outcome::Allowed), "arbitus");
        assert_eq!(ev["run"]["runId"], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn input_dataset_uses_agent_and_tool() {
        let ev = build_run_event(&entry(Outcome::Allowed), "arbitus");
        let inputs = ev["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["namespace"], "cursor");
        assert_eq!(inputs[0]["name"], "read_file");
    }

    #[test]
    fn arguments_facet_present_when_args_captured() {
        let ev = build_run_event(&entry(Outcome::Allowed), "arbitus");
        assert_eq!(
            ev["run"]["facets"]["arbitus:arguments"]["arguments"]["path"],
            "/etc/hosts"
        );
    }

    #[test]
    fn arguments_facet_absent_when_no_args() {
        let e = Arc::new(AuditEntry {
            ts: UNIX_EPOCH,
            agent_id: "cursor".to_string(),
            method: "tools/call".to_string(),
            tool: Some("ping".to_string()),
            arguments: None,
            outcome: Outcome::Allowed,
            request_id: "req-1".to_string(),
            input_tokens: 0,
        });
        let ev = build_run_event(&e, "arbitus");
        assert!(
            ev["run"]["facets"]["arbitus:arguments"].is_null(),
            "arguments facet should be absent"
        );
    }

    #[test]
    fn input_tokens_in_execution_facet() {
        let ev = build_run_event(&entry(Outcome::Allowed), "arbitus");
        assert_eq!(ev["run"]["facets"]["arbitus:execution"]["input_tokens"], 8);
    }

    #[test]
    fn custom_namespace_used() {
        let ev = build_run_event(&entry(Outcome::Allowed), "my-gateway");
        assert_eq!(ev["job"]["namespace"], "my-gateway");
    }

    #[test]
    fn event_time_is_rfc3339() {
        let ev = build_run_event(&entry(Outcome::Allowed), "arbitus");
        let t = ev["eventTime"].as_str().unwrap();
        // Should parse as a valid RFC 3339 timestamp
        assert!(t.contains('T'), "eventTime should be ISO 8601: {t}");
        assert!(
            t.ends_with('Z') || t.contains('+'),
            "should have timezone: {t}"
        );
    }
}

pub mod fanout;
pub mod openlineage;
pub mod sqlite;
pub mod stdout;
pub mod webhook;

use async_trait::async_trait;
use std::{sync::Arc, time::SystemTime};

#[derive(Clone)]
pub struct AuditEntry {
    pub ts: SystemTime,
    pub agent_id: String,
    pub method: String,
    pub tool: Option<String>,
    /// Tool arguments captured at intercept time — stored for replay.
    pub arguments: Option<serde_json::Value>,
    pub outcome: Outcome,
    /// Unique ID for this request — propagated as `X-Request-Id` response header.
    pub request_id: String,
    /// Estimated tokens in the request arguments (4-chars-per-token heuristic).
    /// Zero for non-tools/call methods.
    pub input_tokens: u32,
}

#[derive(Clone)]
pub enum Outcome {
    Allowed,
    Blocked(String),
    Forwarded,
    /// Tool was intercepted and a mock response was returned — not forwarded to upstream.
    Shadowed,
}

/// Pluggable audit log — swap SQLite, file, or external service
/// without changing anything in the gateway core.
///
/// `record` takes an `Arc<AuditEntry>` so fan-out to multiple backends
/// is a cheap pointer clone, not a deep copy per backend.
///
/// Implementations MUST be `Send + Sync` and safe to call from any async context.
#[async_trait]
pub trait AuditLog: Send + Sync {
    fn record(&self, entry: Arc<AuditEntry>);
    /// Flush all pending writes. Called on graceful shutdown.
    async fn flush(&self) {}
}

use super::{AuditEntry, AuditLog, Outcome};
use async_trait::async_trait;
use std::sync::Arc;

pub struct StdoutAudit;

#[async_trait]
impl AuditLog for StdoutAudit {
    fn record(&self, entry: Arc<AuditEntry>) {
        let tool = entry.tool.as_deref().unwrap_or("-");
        match &entry.outcome {
            Outcome::Allowed => tracing::info!(
                outcome = "allowed",
                agent = %entry.agent_id,
                method = %entry.method,
                tool,
            ),
            Outcome::Blocked(reason) => tracing::info!(
                outcome = "blocked",
                agent = %entry.agent_id,
                method = %entry.method,
                tool,
                reason = %reason,
            ),
            Outcome::Forwarded => tracing::info!(
                outcome = "forwarded",
                agent = %entry.agent_id,
                method = %entry.method,
            ),
            Outcome::Shadowed => tracing::info!(
                outcome = "shadowed",
                agent = %entry.agent_id,
                method = %entry.method,
                tool,
            ),
        }
    }
}

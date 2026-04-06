use super::{AuditEntry, AuditLog};
use async_trait::async_trait;
use std::sync::Arc;

/// Fans out every audit event to multiple backends simultaneously.
/// Uses `Arc<AuditEntry>` so all backends share the same allocation.
pub struct FanoutAudit {
    backends: Vec<Arc<dyn AuditLog>>,
}

impl FanoutAudit {
    pub fn new(backends: Vec<Arc<dyn AuditLog>>) -> Self {
        Self { backends }
    }
}

#[async_trait]
impl AuditLog for FanoutAudit {
    fn record(&self, entry: Arc<AuditEntry>) {
        for backend in &self.backends {
            backend.record(Arc::clone(&entry));
        }
    }

    async fn flush(&self) {
        for backend in &self.backends {
            backend.flush().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEntry, Outcome};
    use std::sync::Mutex;
    use std::time::SystemTime;

    /// An in-memory audit backend that records entries for assertion.
    struct RecordingAudit {
        entries: Arc<Mutex<Vec<Arc<AuditEntry>>>>,
        flushed: Arc<Mutex<bool>>,
    }

    impl RecordingAudit {
        fn new() -> (Self, Arc<Mutex<Vec<Arc<AuditEntry>>>>, Arc<Mutex<bool>>) {
            let entries = Arc::new(Mutex::new(vec![]));
            let flushed = Arc::new(Mutex::new(false));
            (
                Self {
                    entries: Arc::clone(&entries),
                    flushed: Arc::clone(&flushed),
                },
                entries,
                flushed,
            )
        }
    }

    #[async_trait::async_trait]
    impl AuditLog for RecordingAudit {
        fn record(&self, entry: Arc<AuditEntry>) {
            self.entries.lock().unwrap().push(entry);
        }
        async fn flush(&self) {
            *self.flushed.lock().unwrap() = true;
        }
    }

    fn make_entry(outcome: Outcome) -> Arc<AuditEntry> {
        Arc::new(AuditEntry {
            ts: SystemTime::UNIX_EPOCH,
            agent_id: "agent".to_string(),
            method: "tools/call".to_string(),
            tool: Some("do_thing".to_string()),
            arguments: None,
            outcome,
            request_id: "req-1".to_string(),
            input_tokens: 0,
        })
    }

    #[test]
    fn all_backends_receive_event() {
        let (b1, entries1, _) = RecordingAudit::new();
        let (b2, entries2, _) = RecordingAudit::new();
        let fanout = FanoutAudit::new(vec![Arc::new(b1), Arc::new(b2)]);
        fanout.record(make_entry(Outcome::Allowed));
        assert_eq!(entries1.lock().unwrap().len(), 1);
        assert_eq!(entries2.lock().unwrap().len(), 1);
    }

    #[test]
    fn multiple_events_all_delivered() {
        let (b1, entries1, _) = RecordingAudit::new();
        let fanout = FanoutAudit::new(vec![Arc::new(b1)]);
        fanout.record(make_entry(Outcome::Allowed));
        fanout.record(make_entry(Outcome::Forwarded));
        fanout.record(make_entry(Outcome::Blocked("rate limit".to_string())));
        assert_eq!(entries1.lock().unwrap().len(), 3);
    }

    #[test]
    fn empty_backend_list_does_not_panic() {
        let fanout = FanoutAudit::new(vec![]);
        // Should not panic
        fanout.record(make_entry(Outcome::Allowed));
    }

    #[tokio::test]
    async fn flush_called_on_all_backends() {
        let (b1, _, flushed1) = RecordingAudit::new();
        let (b2, _, flushed2) = RecordingAudit::new();
        let fanout = FanoutAudit::new(vec![Arc::new(b1), Arc::new(b2)]);
        fanout.flush().await;
        assert!(
            *flushed1.lock().unwrap(),
            "backend 1 should have been flushed"
        );
        assert!(
            *flushed2.lock().unwrap(),
            "backend 2 should have been flushed"
        );
    }

    #[tokio::test]
    async fn flush_empty_backends_does_not_panic() {
        let fanout = FanoutAudit::new(vec![]);
        fanout.flush().await; // should not panic
    }

    #[test]
    fn backends_share_same_arc_allocation() {
        // Verify that fanout does Arc::clone, not deep copy
        let (b1, entries1, _) = RecordingAudit::new();
        let (b2, entries2, _) = RecordingAudit::new();
        let fanout = FanoutAudit::new(vec![Arc::new(b1), Arc::new(b2)]);
        let entry = make_entry(Outcome::Shadowed);
        fanout.record(Arc::clone(&entry));
        let received1 = entries1.lock().unwrap();
        let received2 = entries2.lock().unwrap();
        // Both backends hold a pointer to the same AuditEntry
        assert!(Arc::ptr_eq(&received1[0], &received2[0]));
    }
}

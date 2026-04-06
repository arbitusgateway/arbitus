//! Human-in-the-Loop approval store.
//!
//! When a tool is marked `approval_required` in the agent policy, the
//! `HitlMiddleware` inserts a pending entry here, waits on a oneshot channel,
//! and only allows the request once an operator approves via `POST /approvals/:id/approve`.

use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;

/// The operator's decision.
#[derive(Debug, Clone)]
pub enum ApprovalDecision {
    Approved,
    Rejected { reason: Option<String> },
}

/// Snapshot of a pending approval — returned by `GET /approvals`.
#[derive(Debug, Clone, Serialize)]
pub struct PendingApproval {
    pub id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    /// Unix timestamp (seconds) of when the approval was created.
    pub created_at: u64,
}

struct Entry {
    approval: PendingApproval,
    tx: oneshot::Sender<ApprovalDecision>,
}

/// Thread-safe store of in-flight approval requests.
#[derive(Default)]
pub struct HitlStore {
    pending: Mutex<HashMap<String, Entry>>,
}

impl HitlStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a new pending approval.
    ///
    /// Returns the approval `id` and the receiver end of the decision channel.
    /// The middleware awaits the receiver; the HTTP handler sends on the transmitter.
    pub async fn insert(
        &self,
        agent_id: String,
        tool_name: String,
        arguments: serde_json::Value,
    ) -> (String, oneshot::Receiver<ApprovalDecision>) {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.pending.lock().await.insert(
            id.clone(),
            Entry {
                approval: PendingApproval {
                    id: id.clone(),
                    agent_id,
                    tool_name,
                    arguments,
                    created_at,
                },
                tx,
            },
        );
        (id, rx)
    }

    /// List all pending approvals (for the operator UI).
    pub async fn list(&self) -> Vec<PendingApproval> {
        self.pending
            .lock()
            .await
            .values()
            .map(|e| e.approval.clone())
            .collect()
    }

    /// Resolve an approval by id. Returns `false` if the id is unknown.
    ///
    /// If the middleware already timed out and dropped the receiver, the send
    /// will fail silently — that is fine.
    pub async fn resolve(&self, id: &str, decision: ApprovalDecision) -> bool {
        if let Some(entry) = self.pending.lock().await.remove(id) {
            let _ = entry.tx.send(decision);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_shows_up_in_list() {
        let store = HitlStore::new();
        let (id, _rx) = store
            .insert(
                "agent-a".to_string(),
                "do_thing".to_string(),
                serde_json::Value::Null,
            )
            .await;
        let list = store.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].agent_id, "agent-a");
        assert_eq!(list[0].tool_name, "do_thing");
    }

    #[tokio::test]
    async fn created_at_is_nonzero() {
        let store = HitlStore::new();
        let (_id, _rx) = store
            .insert("a".to_string(), "t".to_string(), serde_json::Value::Null)
            .await;
        let list = store.list().await;
        assert!(
            list[0].created_at > 0,
            "created_at should be a Unix timestamp"
        );
    }

    #[tokio::test]
    async fn resolve_returns_true_and_removes_entry() {
        let store = HitlStore::new();
        let (id, _rx) = store
            .insert("a".to_string(), "t".to_string(), serde_json::Value::Null)
            .await;
        assert_eq!(store.list().await.len(), 1);
        let ok = store.resolve(&id, ApprovalDecision::Approved).await;
        assert!(ok, "resolve should return true for a known id");
        assert!(
            store.list().await.is_empty(),
            "entry should be removed after resolve"
        );
    }

    #[tokio::test]
    async fn resolve_unknown_id_returns_false() {
        let store = HitlStore::new();
        let ok = store
            .resolve("nonexistent-id", ApprovalDecision::Approved)
            .await;
        assert!(!ok, "resolve of unknown id should return false");
    }

    #[tokio::test]
    async fn double_resolve_returns_false_second_time() {
        let store = HitlStore::new();
        let (id, _rx) = store
            .insert("a".to_string(), "t".to_string(), serde_json::Value::Null)
            .await;
        let first = store.resolve(&id, ApprovalDecision::Approved).await;
        let second = store.resolve(&id, ApprovalDecision::Approved).await;
        assert!(first);
        assert!(!second, "second resolve of same id should return false");
    }

    #[tokio::test]
    async fn resolve_with_dropped_receiver_succeeds_silently() {
        let store = HitlStore::new();
        let (id, rx) = store
            .insert("a".to_string(), "t".to_string(), serde_json::Value::Null)
            .await;
        drop(rx); // simulate middleware timeout dropping the receiver
        // resolve should not panic — the send fails silently
        let ok = store.resolve(&id, ApprovalDecision::Approved).await;
        assert!(
            ok,
            "resolve should return true even when receiver was dropped"
        );
    }

    #[tokio::test]
    async fn concurrent_inserts_all_appear_in_list() {
        let store = HitlStore::new();
        let s1 = Arc::clone(&store);
        let s2 = Arc::clone(&store);
        let (id1, _rx1) = s1
            .insert("a".to_string(), "t1".to_string(), serde_json::Value::Null)
            .await;
        let (id2, _rx2) = s2
            .insert("b".to_string(), "t2".to_string(), serde_json::Value::Null)
            .await;
        let list = store.list().await;
        assert_eq!(list.len(), 2);
        let ids: Vec<&str> = list.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&id1.as_str()));
        assert!(ids.contains(&id2.as_str()));
    }

    #[tokio::test]
    async fn arguments_are_stored() {
        let store = HitlStore::new();
        let args = serde_json::json!({"key": "value", "n": 42});
        let (_id, _rx) = store
            .insert("a".to_string(), "t".to_string(), args.clone())
            .await;
        let list = store.list().await;
        assert_eq!(list[0].arguments, args);
    }
}

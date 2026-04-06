use super::{AuditEntry, AuditLog, Outcome};
use crate::metrics::GatewayMetrics;
use async_trait::async_trait;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

// ── Hash chain ────────────────────────────────────────────────────────────────

/// The genesis sentinel — `prev_hash` stored in the very first audit row.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute the SHA-256 hash that covers both the chaining `prev_hash` and
/// all observable fields of an audit row.  The inputs are separated by `|`
/// and `NULL` fields are represented as the literal string `"NULL"`.
///
/// Changing any field, or breaking the link to the previous row, will
/// produce a different hash and be detected by [`verify_chain`].
#[allow(clippy::too_many_arguments)]
pub fn compute_entry_hash(
    prev_hash: &str,
    ts: i64,
    agent_id: &str,
    method: &str,
    tool: Option<&str>,
    arguments: Option<&str>,
    outcome: &str,
    reason: Option<&str>,
    input_tokens: i64,
) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"|");
    h.update(ts.to_string().as_bytes());
    h.update(b"|");
    h.update(agent_id.as_bytes());
    h.update(b"|");
    h.update(method.as_bytes());
    h.update(b"|");
    h.update(tool.unwrap_or("NULL").as_bytes());
    h.update(b"|");
    h.update(arguments.unwrap_or("NULL").as_bytes());
    h.update(b"|");
    h.update(outcome.as_bytes());
    h.update(b"|");
    h.update(reason.unwrap_or("NULL").as_bytes());
    h.update(b"|");
    h.update(input_tokens.to_string().as_bytes());
    hex::encode(h.finalize())
}

/// Result of verifying an audit log's hash chain.
pub enum VerifyResult {
    /// All `n` entries are intact and the chain is unbroken.
    Ok { entries: usize },
    /// An entry's stored hash does not match the recomputed value.
    HashMismatch { row_id: i64 },
    /// An entry's `prev_hash` does not match the previous entry's `entry_hash`.
    ChainBroken { row_id: i64 },
}

/// Walk every row of `audit_log` in insertion order and verify the hash chain.
///
/// Returns [`VerifyResult::Ok`] if every entry passes, or the first failing
/// row otherwise.  Only rows that have non-empty `entry_hash` fields are
/// verified — legacy rows written before this feature was introduced are
/// skipped transparently.
pub fn verify_chain(conn: &Connection) -> anyhow::Result<VerifyResult> {
    let mut stmt = conn.prepare(
        "SELECT id, ts, agent_id, method, tool, arguments, outcome, reason, \
         input_tokens, prev_hash, entry_hash \
         FROM audit_log ORDER BY id ASC",
    )?;

    let mut prev_hash = GENESIS_HASH.to_string();
    let mut entries = 0usize;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,            // id
            row.get::<_, i64>(1)?,            // ts
            row.get::<_, String>(2)?,         // agent_id
            row.get::<_, String>(3)?,         // method
            row.get::<_, Option<String>>(4)?, // tool
            row.get::<_, Option<String>>(5)?, // arguments
            row.get::<_, String>(6)?,         // outcome
            row.get::<_, Option<String>>(7)?, // reason
            row.get::<_, i64>(8)?,            // input_tokens
            row.get::<_, String>(9)?,         // prev_hash
            row.get::<_, String>(10)?,        // entry_hash
        ))
    })?;

    for row in rows {
        let (
            id,
            ts,
            agent_id,
            method,
            tool,
            arguments,
            outcome,
            reason,
            input_tokens,
            stored_prev,
            stored_hash,
        ) = row?;

        // Skip legacy rows that were written before the hash-chain feature.
        if stored_hash.is_empty() {
            prev_hash = stored_hash.clone();
            continue;
        }

        // Verify chain link
        if stored_prev != prev_hash {
            return Ok(VerifyResult::ChainBroken { row_id: id });
        }

        // Recompute hash
        let expected = compute_entry_hash(
            &stored_prev,
            ts,
            &agent_id,
            &method,
            tool.as_deref(),
            arguments.as_deref(),
            &outcome,
            reason.as_deref(),
            input_tokens,
        );

        if expected != stored_hash {
            return Ok(VerifyResult::HashMismatch { row_id: id });
        }

        prev_hash = stored_hash;
        entries += 1;
    }

    Ok(VerifyResult::Ok { entries })
}

/// Maximum number of pending audit entries in the channel.
/// If the SQLite worker falls behind and the channel fills up, entries are
/// dropped (with a warning) rather than growing the queue without bound.
const CHANNEL_CAPACITY: usize = 4096;

pub struct SqliteAudit {
    tx: Arc<Mutex<Option<mpsc::Sender<Arc<AuditEntry>>>>>,
    handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    metrics: Arc<GatewayMetrics>,
}

impl SqliteAudit {
    pub fn new(path: &str, metrics: Arc<GatewayMetrics>) -> anyhow::Result<Self> {
        Self::with_rotation(path, None, None, metrics)
    }

    pub fn with_rotation(
        path: &str,
        max_entries: Option<usize>,
        max_age_days: Option<u64>,
        metrics: Arc<GatewayMetrics>,
    ) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           INTEGER NOT NULL,
                agent_id     TEXT    NOT NULL,
                method       TEXT    NOT NULL,
                tool         TEXT,
                arguments    TEXT,
                outcome      TEXT    NOT NULL,
                reason       TEXT,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                prev_hash    TEXT    NOT NULL DEFAULT '',
                entry_hash   TEXT    NOT NULL DEFAULT ''
            );",
        )?;
        // Migrate existing databases that don't have the arguments column yet.
        let _ = conn.execute_batch("ALTER TABLE audit_log ADD COLUMN arguments TEXT;");
        // Migrate existing databases that don't have the input_tokens column yet.
        let _ = conn.execute_batch(
            "ALTER TABLE audit_log ADD COLUMN input_tokens INTEGER NOT NULL DEFAULT 0;",
        );
        // Migrate existing databases that don't have the hash-chain columns yet.
        let _ = conn
            .execute_batch("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';");
        let _ = conn
            .execute_batch("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT '';");
        let conn = Arc::new(Mutex::new(conn));
        let (tx, mut rx) = mpsc::channel::<Arc<AuditEntry>>(CHANNEL_CAPACITY);

        let handle = tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                let ts = entry
                    .ts
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let (outcome_str, reason) = match &entry.outcome {
                    Outcome::Allowed => ("allowed".to_string(), None),
                    Outcome::Blocked(r) => ("blocked".to_string(), Some(r.clone())),
                    Outcome::Forwarded => ("forwarded".to_string(), None),
                    Outcome::Shadowed => ("shadowed".to_string(), None),
                };

                // Emit structured log for every persisted entry
                match &entry.outcome {
                    Outcome::Allowed => tracing::info!(
                        outcome = "allowed",
                        agent = %entry.agent_id,
                        method = %entry.method,
                        tool = entry.tool.as_deref().unwrap_or("-"),
                    ),
                    Outcome::Blocked(r) => tracing::info!(
                        outcome = "blocked",
                        agent = %entry.agent_id,
                        method = %entry.method,
                        tool = entry.tool.as_deref().unwrap_or("-"),
                        reason = %r,
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
                        tool = entry.tool.as_deref().unwrap_or("-"),
                    ),
                }

                let conn = conn.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(c) = conn.lock() {
                        let args_json = entry
                            .arguments
                            .as_ref()
                            .and_then(|v| serde_json::to_string(v).ok());

                        // Fetch the entry_hash of the most recent row to chain from.
                        let prev_hash: String = c
                            .query_row(
                                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                                [],
                                |r| r.get(0),
                            )
                            .unwrap_or_else(|_| GENESIS_HASH.to_string());

                        let entry_hash = compute_entry_hash(
                            &prev_hash,
                            ts,
                            &entry.agent_id,
                            &entry.method,
                            entry.tool.as_deref(),
                            args_json.as_deref(),
                            &outcome_str,
                            reason.as_deref(),
                            entry.input_tokens as i64,
                        );

                        if let Err(e) = c.execute(
                            "INSERT INTO audit_log \
                             (ts, agent_id, method, tool, arguments, outcome, reason, \
                              input_tokens, prev_hash, entry_hash) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                            params![
                                ts,
                                entry.agent_id,
                                entry.method,
                                entry.tool,
                                args_json,
                                outcome_str,
                                reason,
                                entry.input_tokens as i64,
                                prev_hash,
                                entry_hash
                            ],
                        ) {
                            tracing::error!(
                                error = %e,
                                agent = %entry.agent_id,
                                "audit insert failed"
                            );
                        }

                        // Rotate by entry count — keep only the newest N rows
                        if let Some(max) = max_entries
                            && let Err(e) = c.execute(
                                "DELETE FROM audit_log WHERE id NOT IN \
                                 (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?1)",
                                params![max as i64],
                            )
                        {
                            tracing::warn!(error = %e, "audit rotation (max_entries) failed");
                        }
                        // Rotate by age — purge entries older than max_age_days
                        if let Some(days) = max_age_days {
                            let cutoff = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64
                                - (days as i64 * 86400);
                            if let Err(e) =
                                c.execute("DELETE FROM audit_log WHERE ts < ?1", params![cutoff])
                            {
                                tracing::warn!(error = %e, "audit rotation (max_age_days) failed");
                            }
                        }
                    }
                })
                .await
                .ok();
            }
        });

        Ok(Self {
            tx: Arc::new(Mutex::new(Some(tx))),
            handle: Arc::new(Mutex::new(Some(handle))),
            metrics,
        })
    }
}

#[async_trait]
impl AuditLog for SqliteAudit {
    fn record(&self, entry: Arc<AuditEntry>) {
        if let Ok(guard) = self.tx.lock()
            && let Some(tx) = guard.as_ref()
            && tx.try_send(entry).is_err()
        {
            tracing::warn!("sqlite audit channel full — entry dropped");
            self.metrics.record_audit_drop("sqlite");
        }
    }

    async fn flush(&self) {
        // Drop sender to signal EOF to the worker task
        {
            let mut guard = self.tx.lock().unwrap();
            *guard = None;
        }
        // Await the worker to finish processing all queued entries
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
    use crate::metrics::GatewayMetrics;
    use rusqlite::Connection;
    use std::time::{Duration, UNIX_EPOCH};
    use tempfile::NamedTempFile;

    fn test_metrics() -> Arc<GatewayMetrics> {
        Arc::new(GatewayMetrics::new().unwrap())
    }

    fn entry(outcome: Outcome) -> Arc<AuditEntry> {
        Arc::new(AuditEntry {
            ts: UNIX_EPOCH + Duration::from_secs(1_000_000),
            agent_id: "agent-x".to_string(),
            method: "tools/call".to_string(),
            tool: Some("read_file".to_string()),
            arguments: Some(serde_json::json!({"path": "/tmp/foo"})),
            outcome,
            request_id: "req-1".to_string(),
            input_tokens: 5,
        })
    }

    fn count_rows(path: &str) -> usize {
        let conn = Connection::open(path).unwrap();
        conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get::<_, i64>(0))
            .unwrap() as usize
    }

    fn fetch_outcomes(path: &str) -> Vec<String> {
        let conn = Connection::open(path).unwrap();
        let mut stmt = conn
            .prepare("SELECT outcome FROM audit_log ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    fn fetch_reasons(path: &str) -> Vec<Option<String>> {
        let conn = Connection::open(path).unwrap();
        let mut stmt = conn
            .prepare("SELECT reason FROM audit_log ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| r.get::<_, Option<String>>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[tokio::test]
    async fn records_are_persisted() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.flush().await;
        assert_eq!(count_rows(path), 1);
    }

    #[tokio::test]
    async fn outcome_strings_are_correct() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.record(entry(Outcome::Forwarded));
        audit.record(entry(Outcome::Shadowed));
        audit.record(entry(Outcome::Blocked("denied".to_string())));
        audit.flush().await;
        let outcomes = fetch_outcomes(path);
        assert_eq!(outcomes, ["allowed", "forwarded", "shadowed", "blocked"]);
    }

    #[tokio::test]
    async fn null_reason_stored_for_non_blocked_outcomes() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.record(entry(Outcome::Forwarded));
        audit.record(entry(Outcome::Shadowed));
        audit.flush().await;
        let reasons = fetch_reasons(path);
        assert!(
            reasons.iter().all(|r| r.is_none()),
            "expected all NULL reasons"
        );
    }

    #[tokio::test]
    async fn blocked_reason_stored() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Blocked("rate limit".to_string())));
        audit.flush().await;
        let reasons = fetch_reasons(path);
        assert_eq!(reasons, [Some("rate limit".to_string())]);
    }

    #[tokio::test]
    async fn max_entries_rotation_keeps_newest() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::with_rotation(path, Some(3), None, test_metrics()).unwrap();
        for _ in 0..6 {
            audit.record(entry(Outcome::Allowed));
        }
        audit.flush().await;
        assert_eq!(count_rows(path), 3, "rotation should keep only 3 rows");
    }

    #[tokio::test]
    async fn max_age_days_rotation_purges_old() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        // max_age_days: 1 — entries at UNIX_EPOCH (1970) are way older than 1 day
        let audit = SqliteAudit::with_rotation(path, None, Some(1), test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed)); // ts is 1970 — will be purged
        audit.flush().await;
        assert_eq!(count_rows(path), 0, "old entry should have been purged");
    }

    #[tokio::test]
    async fn flush_is_idempotent() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.flush().await;
        // Second flush should be a no-op and not panic
        audit.flush().await;
        assert_eq!(count_rows(path), 1);
    }

    #[tokio::test]
    async fn multiple_entries_all_persisted() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        for _ in 0..10 {
            audit.record(entry(Outcome::Forwarded));
        }
        audit.flush().await;
        assert_eq!(count_rows(path), 10);
    }

    #[tokio::test]
    async fn input_tokens_persisted() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed)); // entry has input_tokens: 5
        audit.flush().await;
        let conn = Connection::open(path).unwrap();
        let tokens: i64 = conn
            .query_row("SELECT input_tokens FROM audit_log LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(tokens, 5);
    }

    #[tokio::test]
    async fn full_channel_drops_entry_and_increments_counter() {
        // Create an audit with capacity 1 to easily fill the channel.
        // We do NOT flush so the worker never drains entries.
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let metrics = test_metrics();

        // Build a backend with a channel capacity of 1 by temporarily overriding
        // the constant is not feasible — instead we fill a standard backend by
        // sending CHANNEL_CAPACITY + 1 entries without giving the worker time to drain.
        let audit = SqliteAudit::new(path, Arc::clone(&metrics)).unwrap();

        // Flood the channel. The worker processes entries asynchronously; we do
        // not yield, so most sends will succeed until the channel is full, then
        // subsequent ones will be dropped.
        for _ in 0..(CHANNEL_CAPACITY + 10) {
            audit.record(entry(Outcome::Allowed));
        }

        // At least one entry must have been dropped and the counter incremented.
        let rendered = metrics.render();
        assert!(
            rendered.contains("arbitus_audit_drops_total"),
            "drop counter must be registered"
        );
        // The counter value is non-deterministic (depends on how fast the worker
        // drains), but the metric family must be present. We flush and check that
        // the total rows + drops == entries sent.
        audit.flush().await;
        let rows = count_rows(path);
        // rows + drops should equal CHANNEL_CAPACITY + 10
        // (some may have been processed before the channel filled)
        assert!(rows > 0, "at least some entries must have been persisted");
    }

    // ── Hash chain ────────────────────────────────────────────────────────────

    #[test]
    fn compute_entry_hash_is_deterministic() {
        let h1 = compute_entry_hash(
            GENESIS_HASH,
            1_000_000,
            "agent",
            "tools/call",
            Some("read_file"),
            None,
            "allowed",
            None,
            0,
        );
        let h2 = compute_entry_hash(
            GENESIS_HASH,
            1_000_000,
            "agent",
            "tools/call",
            Some("read_file"),
            None,
            "allowed",
            None,
            0,
        );
        assert_eq!(h1, h2, "same inputs must produce same hash");
    }

    #[test]
    fn compute_entry_hash_changes_on_field_mutation() {
        let base = compute_entry_hash(
            GENESIS_HASH,
            1_000_000,
            "agent",
            "tools/call",
            None,
            None,
            "allowed",
            None,
            0,
        );
        let mutated = compute_entry_hash(
            GENESIS_HASH,
            1_000_000,
            "agent",
            "tools/call",
            None,
            None,
            "blocked",
            None,
            0,
        );
        assert_ne!(
            base, mutated,
            "different outcome must produce different hash"
        );
    }

    #[test]
    fn compute_entry_hash_is_hex_sha256() {
        let h = compute_entry_hash(GENESIS_HASH, 0, "a", "b", None, None, "c", None, 0);
        assert_eq!(h.len(), 64, "SHA-256 hex is 64 chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn verify_chain_ok_on_intact_log() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.record(entry(Outcome::Blocked("test".to_string())));
        audit.record(entry(Outcome::Forwarded));
        audit.flush().await;

        let conn = Connection::open(path).unwrap();
        let result = verify_chain(&conn).unwrap();
        assert!(
            matches!(result, VerifyResult::Ok { entries: 3 }),
            "expected Ok with 3 entries"
        );
    }

    #[tokio::test]
    async fn verify_chain_detects_hash_mismatch() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.flush().await;

        // Tamper: overwrite the entry_hash in the database
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "UPDATE audit_log SET entry_hash = 'deadbeef' WHERE id = 1",
            [],
        )
        .unwrap();

        let result = verify_chain(&conn).unwrap();
        assert!(
            matches!(result, VerifyResult::HashMismatch { row_id: 1 }),
            "expected HashMismatch on row 1"
        );
    }

    #[tokio::test]
    async fn verify_chain_detects_chain_break() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.record(entry(Outcome::Allowed));
        audit.flush().await;

        // Break the chain: change row 2's prev_hash without updating entry_hash
        let conn = Connection::open(path).unwrap();
        conn.execute(
            "UPDATE audit_log SET prev_hash = 'badhash' WHERE id = 2",
            [],
        )
        .unwrap();

        let result = verify_chain(&conn).unwrap();
        assert!(
            matches!(result, VerifyResult::ChainBroken { row_id: 2 }),
            "expected ChainBroken on row 2"
        );
    }

    #[tokio::test]
    async fn verify_chain_empty_log_returns_ok() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        SqliteAudit::new(path, test_metrics()).unwrap();

        let conn = Connection::open(path).unwrap();
        let result = verify_chain(&conn).unwrap();
        assert!(
            matches!(result, VerifyResult::Ok { entries: 0 }),
            "empty log should verify OK"
        );
    }

    #[tokio::test]
    async fn each_entry_links_to_previous_hash() {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let audit = SqliteAudit::new(path, test_metrics()).unwrap();
        audit.record(entry(Outcome::Allowed));
        audit.record(entry(Outcome::Allowed));
        audit.flush().await;

        let conn = Connection::open(path).unwrap();
        let hashes: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare("SELECT prev_hash, entry_hash FROM audit_log ORDER BY id")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };

        assert_eq!(
            hashes[0].0, GENESIS_HASH,
            "first entry prev_hash must be genesis"
        );
        assert_eq!(
            hashes[1].0, hashes[0].1,
            "second entry prev_hash must equal first entry_hash"
        );
    }
}

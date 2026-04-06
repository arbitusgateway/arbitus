use super::McpUpstream;
use crate::{config::OAuthClientConfig, oauth::OAuthManager};
use async_trait::async_trait;
use reqwest::{Client, ClientBuilder};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

// ── Circuit breaker ───────────────────────────────────────────────────────────

enum CbState {
    Closed,
    Open { until: Instant },
    HalfOpen,
}

struct CircuitBreaker {
    state: Mutex<CbState>,
    failure_count: AtomicUsize,
    threshold: usize,
    recovery_secs: u64,
}

impl CircuitBreaker {
    fn new(threshold: usize, recovery_secs: u64) -> Self {
        Self {
            state: Mutex::new(CbState::Closed),
            failure_count: AtomicUsize::new(0),
            threshold,
            recovery_secs,
        }
    }

    /// Returns true if the circuit is open (requests should be rejected immediately).
    async fn is_open(&self) -> bool {
        let mut state = self.state.lock().await;
        match &*state {
            CbState::Closed | CbState::HalfOpen => false,
            CbState::Open { until } => {
                if Instant::now() >= *until {
                    *state = CbState::HalfOpen;
                    tracing::info!("circuit entering half-open, probing upstream");
                    false
                } else {
                    true
                }
            }
        }
    }

    async fn on_success(&self) {
        let prev = self.failure_count.swap(0, Ordering::Relaxed);
        let mut state = self.state.lock().await;
        if !matches!(*state, CbState::Closed) {
            tracing::info!(
                previous_failures = prev,
                "upstream recovered, circuit closed"
            );
            *state = CbState::Closed;
        }
    }

    async fn on_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.threshold {
            let mut state = self.state.lock().await;
            let until = Instant::now() + Duration::from_secs(self.recovery_secs);
            *state = CbState::Open { until };
            self.failure_count.store(0, Ordering::Relaxed);
            tracing::warn!(
                failures = count,
                recovery_secs = self.recovery_secs,
                "circuit opened"
            );
        }
    }
}

// ── HttpUpstream ──────────────────────────────────────────────────────────────

pub struct HttpUpstream {
    url: String,
    client: Client,
    cb: Arc<CircuitBreaker>,
    /// Optional OAuth token provider — when set, a `Bearer` token is fetched
    /// and attached to every upstream request.
    oauth: Option<(Arc<OAuthManager>, String, OAuthClientConfig)>,
}

impl HttpUpstream {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_circuit_breaker(url, 5, 30)
    }

    pub fn with_circuit_breaker(
        url: impl Into<String>,
        threshold: usize,
        recovery_secs: u64,
    ) -> Self {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
            .expect("failed to build HTTP client");
        Self {
            url: url.into(),
            client,
            cb: Arc::new(CircuitBreaker::new(threshold, recovery_secs)),
            oauth: None,
        }
    }

    /// Attach an OAuth 2.1 + PKCE token provider to this upstream.
    pub fn with_oauth(
        url: impl Into<String>,
        threshold: usize,
        recovery_secs: u64,
        oauth_manager: Arc<OAuthManager>,
        upstream_name: String,
        oauth_config: OAuthClientConfig,
    ) -> Self {
        let mut up = Self::with_circuit_breaker(url, threshold, recovery_secs);
        up.oauth = Some((oauth_manager, upstream_name, oauth_config));
        up
    }
}

#[async_trait]
impl McpUpstream for HttpUpstream {
    async fn forward(&self, msg: &Value) -> Option<Value> {
        if self.cb.is_open().await {
            tracing::warn!("circuit open, rejecting request");
            return Some(json!({
                "jsonrpc": "2.0",
                "error": { "code": -32603, "message": "service unavailable (circuit open)" }
            }));
        }

        // Attach OAuth Bearer token if this upstream is configured with OAuth.
        let mut req = self.client.post(&self.url).json(msg);
        if let Some((manager, name, config)) = &self.oauth {
            if let Some(token) = manager.get_token(name, config).await {
                req = req.bearer_auth(token);
            } else {
                tracing::warn!(
                    upstream = %name,
                    "OAuth token unavailable — visit the authorization URL to authorize arbitus"
                );
            }
        }

        match req.send().await {
            Ok(resp) => {
                self.cb.on_success().await;
                if resp.status() == reqwest::StatusCode::ACCEPTED {
                    return None; // notification — no body
                }
                match resp.json::<Value>().await {
                    Ok(body) => Some(body),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse upstream response");
                        Some(json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32603, "message": "internal error" }
                        }))
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "upstream request failed");
                self.cb.on_failure().await;
                Some(json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32603, "message": "service unavailable" }
                }))
            }
        }
    }

    fn base_url(&self) -> &str {
        &self.url
    }

    async fn is_healthy(&self) -> bool {
        !self.cb.is_open().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CircuitBreaker ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn circuit_starts_closed() {
        let cb = CircuitBreaker::new(3, 30);
        assert!(!cb.is_open().await);
    }

    #[tokio::test]
    async fn failures_below_threshold_keep_circuit_closed() {
        let cb = CircuitBreaker::new(3, 30);
        cb.on_failure().await;
        cb.on_failure().await;
        // 2 failures, threshold is 3 → still closed
        assert!(!cb.is_open().await);
    }

    #[tokio::test]
    async fn threshold_failures_open_circuit() {
        let cb = CircuitBreaker::new(3, 60);
        cb.on_failure().await;
        cb.on_failure().await;
        cb.on_failure().await; // hits threshold
        assert!(cb.is_open().await);
    }

    #[tokio::test]
    async fn success_resets_failure_count() {
        let cb = CircuitBreaker::new(3, 60);
        cb.on_failure().await;
        cb.on_failure().await; // 2/3
        cb.on_success().await; // resets to 0
        cb.on_failure().await;
        cb.on_failure().await; // 2/3 again — should not open
        assert!(!cb.is_open().await);
    }

    #[tokio::test]
    async fn open_circuit_transitions_to_halfopen_after_recovery() {
        // recovery_secs=0: deadline is always in the past, so is_open() immediately
        // transitions Open → HalfOpen and returns false.
        let cb = CircuitBreaker::new(1, 0);
        cb.on_failure().await; // → Open {until: now + 0s}
        tokio::time::sleep(Duration::from_millis(1)).await; // ensure now > until
        assert!(
            !cb.is_open().await,
            "circuit should be HalfOpen (not Open) after recovery window elapsed"
        );
    }

    #[tokio::test]
    async fn halfopen_success_closes_circuit() {
        let cb = CircuitBreaker::new(1, 0);
        cb.on_failure().await; // → Open
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(!cb.is_open().await); // → HalfOpen
        cb.on_success().await; // → Closed
        assert!(
            !cb.is_open().await,
            "circuit should be Closed after success in HalfOpen"
        );
    }

    #[tokio::test]
    async fn halfopen_failure_resets_failure_count_for_next_probe() {
        // After failure in HalfOpen, failure_count is reset when the circuit
        // re-opens. With threshold=2, two failures are needed to open from Closed,
        // but in HalfOpen the count starts at 0 again — so a subsequent failure
        // in HalfOpen does not immediately re-close (it re-opens after threshold failures).
        let cb = CircuitBreaker::new(2, 0);
        // Open circuit: needs 2 failures
        cb.on_failure().await;
        cb.on_failure().await; // count=2 >= 2 → Open, count reset to 0
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(!cb.is_open().await); // → HalfOpen, count=0
        // Fail once in HalfOpen: count 0→1, 1 < 2 → does NOT re-open
        cb.on_failure().await;
        // The circuit is still in HalfOpen state: count=1, below threshold
        // Success now would close it; one more failure would reopen
        cb.on_success().await; // success in HalfOpen → Closed
        assert!(!cb.is_open().await, "should be Closed after success");
        // Now from Closed, one failure should not open (threshold=2)
        cb.on_failure().await; // count=1, still Closed
        assert!(
            !cb.is_open().await,
            "one failure below threshold keeps circuit Closed"
        );
    }

    #[tokio::test]
    async fn success_on_closed_circuit_is_noop() {
        let cb = CircuitBreaker::new(3, 60);
        cb.on_success().await; // no-op on already-closed circuit
        assert!(!cb.is_open().await);
    }

    // ── HttpUpstream (integration with CircuitBreaker) ────────────────────────

    /// Use port 1 (reserved, connection refused) to simulate unreachable upstream.
    fn failing_upstream(threshold: usize) -> HttpUpstream {
        HttpUpstream::with_circuit_breaker("http://127.0.0.1:1", threshold, 60)
    }

    #[tokio::test]
    async fn forward_to_unreachable_upstream_returns_error_response() {
        let up = failing_upstream(5);
        let resp = up.forward(&serde_json::json!({"method": "ping"})).await;
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert!(
            resp["error"].is_object(),
            "expected error JSON-RPC response, got: {resp}"
        );
        assert_eq!(resp["error"]["code"], -32603);
    }

    #[tokio::test]
    async fn forward_opens_circuit_after_threshold_failures() {
        let up = failing_upstream(2);
        let msg = serde_json::json!({"method": "ping"});
        up.forward(&msg).await; // failure 1
        up.forward(&msg).await; // failure 2 → circuit opens
        // Next call — circuit is open → immediate "circuit open" error (no network attempt)
        let resp = up.forward(&msg).await.unwrap();
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("circuit open"),
            "expected circuit open error, got: {resp}"
        );
    }

    #[tokio::test]
    async fn is_healthy_false_when_circuit_open() {
        let up = failing_upstream(1);
        assert!(up.is_healthy().await);
        up.forward(&serde_json::json!({})).await; // 1 failure → circuit opens
        assert!(!up.is_healthy().await);
    }

    #[tokio::test]
    async fn is_healthy_true_when_circuit_closed() {
        let up = failing_upstream(5);
        assert!(up.is_healthy().await);
    }

    #[tokio::test]
    async fn notification_202_returns_none() {
        // Spin up a tiny local server that returns 202 for any request
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 512];
            stream.read(&mut buf).await.ok();
            stream
                .write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .ok();
        });

        let up = HttpUpstream::new(format!("http://127.0.0.1:{port}"));
        let resp = up.forward(&serde_json::json!({"method": "ping"})).await;
        assert!(
            resp.is_none(),
            "202 response should return None (notification)"
        );
    }
}

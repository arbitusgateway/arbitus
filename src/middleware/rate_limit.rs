use super::{Decision, McpContext, Middleware, RateLimitInfo};
use crate::live_config::LiveConfig;
use async_trait::async_trait;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{
        Arc, RwLock,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

// ── Per-key limiter entry ─────────────────────────────────────────────────────

/// One rate-limiter entry per (agent | tool | IP) key.
///
/// `governor` handles enforcement via lock-free atomics (GCRA).
/// The separate `remaining` / `window_start_ms` atomics give us an O(1)
/// approximation of burst-capacity remaining for `X-RateLimit-Remaining`
/// response headers — no Vec, no Mutex.
struct LimiterEntry {
    limiter: DefaultDirectRateLimiter,
    /// Configured quota (requests / min).
    limit: usize,
    /// Approximate remaining capacity in the current 60-second window.
    remaining: AtomicI64,
    /// Unix-epoch milliseconds when the current window started.
    window_start_ms: AtomicU64,
}

impl LimiterEntry {
    fn new(limit: usize, burst: usize) -> Self {
        let nz_limit = NonZeroU32::new(limit.max(1) as u32).expect("rate_limit > 0");
        let nz_burst = NonZeroU32::new(burst.max(1) as u32).expect("burst > 0");
        let quota = Quota::per_minute(nz_limit).allow_burst(nz_burst);
        Self {
            limiter: RateLimiter::direct(quota),
            limit,
            remaining: AtomicI64::new(burst as i64),
            window_start_ms: AtomicU64::new(now_ms()),
        }
    }

    /// Check whether a cell is available.
    /// Returns `(allowed, remaining, reset_after_secs)`.
    fn check(&self) -> (bool, usize, u64) {
        // Reset the remaining counter once per 60-second window.
        let ws = self.window_start_ms.load(Ordering::Relaxed);
        let now = now_ms();
        if now.saturating_sub(ws) >= 60_000 {
            // CAS prevents two threads from both resetting at once.
            if self
                .window_start_ms
                .compare_exchange(ws, now, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                self.remaining.store(self.limit as i64, Ordering::Relaxed);
            }
        }

        let elapsed_secs = now.saturating_sub(self.window_start_ms.load(Ordering::Relaxed)) / 1000;
        let reset_after = 60u64.saturating_sub(elapsed_secs);

        match self.limiter.check() {
            Ok(_) => {
                let r = (self.remaining.fetch_sub(1, Ordering::Relaxed) - 1).max(0) as usize;
                (true, r, reset_after)
            }
            Err(_) => (false, 0, reset_after),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Limiter store ─────────────────────────────────────────────────────────────

type EntryMap<K> = Arc<RwLock<HashMap<K, Arc<LimiterEntry>>>>;

/// Look up an existing entry or create a new one with the given `limit`/`burst`.
/// If the stored entry's limit differs from the current config (after a hot-reload),
/// replace it so the new rate takes effect immediately.
fn get_or_create<K>(map: &EntryMap<K>, key: K, limit: usize, burst: usize) -> Arc<LimiterEntry>
where
    K: std::hash::Hash + Eq + Clone,
{
    // Fast path: entry exists and has the right limit.
    {
        let m = map.read().unwrap();
        if let Some(e) = m.get(&key)
            && e.limit == limit
        {
            return Arc::clone(e);
        }
    }
    // Slow path: create (or replace) the entry.
    let mut m = map.write().unwrap();
    let entry = Arc::new(LimiterEntry::new(limit, burst));
    m.insert(key, Arc::clone(&entry));
    entry
}

// ── Middleware ─────────────────────────────────────────────────────────────────

pub struct RateLimitMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
    /// One entry per agent_id.
    agent_limiters: EntryMap<String>,
    /// One entry per (agent_id, tool_name) pair.
    tool_limiters: EntryMap<(String, String)>,
    /// One entry per client IP string.
    ip_limiters: EntryMap<String>,
}

impl RateLimitMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self {
            config,
            agent_limiters: Arc::new(RwLock::new(HashMap::new())),
            tool_limiters: Arc::new(RwLock::new(HashMap::new())),
            ip_limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if !matches!(
            ctx.method.as_str(),
            "tools/call" | "resources/read" | "resources/subscribe" | "prompts/get"
        ) {
            return Decision::Allow { rl: None };
        }

        let (global_limit, global_burst, tool_limit, ip_limit) = {
            let cfg = self.config.borrow();
            let Some(policy) = cfg.agents.get(&ctx.agent_id) else {
                return Decision::Allow { rl: None }; // unknown agents blocked by AuthMiddleware
            };
            let burst = policy.rate_limit_burst.unwrap_or(policy.rate_limit);
            let tool_limit = ctx
                .tool_name
                .as_ref()
                .and_then(|t| policy.tool_rate_limits.get(t).copied());
            (policy.rate_limit, burst, tool_limit, cfg.ip_rate_limit)
        };

        // ── IP rate limit (cheapest rejection — checked first) ────────────────
        if let (Some(limit), Some(ip)) = (ip_limit, ctx.client_ip.as_ref()) {
            let entry = get_or_create(&self.ip_limiters, ip.clone(), limit, limit);
            let (allowed, remaining, reset_after) = entry.check();
            if !allowed {
                return Decision::Block {
                    reason: format!("IP rate limit exceeded ({limit}/min)"),
                    rl: Some(RateLimitInfo {
                        limit,
                        remaining,
                        reset_after_secs: reset_after,
                    }),
                };
            }
        }

        // ── Global agent rate limit ───────────────────────────────────────────
        let agent_entry = get_or_create(
            &self.agent_limiters,
            ctx.agent_id.clone(),
            global_limit,
            global_burst,
        );
        let (allowed, remaining, reset_after) = agent_entry.check();
        if !allowed {
            return Decision::Block {
                reason: format!("rate limit exceeded ({global_limit}/min)"),
                rl: Some(RateLimitInfo {
                    limit: global_limit,
                    remaining: 0,
                    reset_after_secs: reset_after,
                }),
            };
        }
        let agent_rl = RateLimitInfo {
            limit: global_limit,
            remaining,
            reset_after_secs: reset_after,
        };

        // ── Per-tool rate limit ───────────────────────────────────────────────
        if let (Some(limit), Some(tool)) = (tool_limit, ctx.tool_name.as_ref()) {
            let key = (ctx.agent_id.clone(), tool.clone());
            let entry = get_or_create(&self.tool_limiters, key, limit, limit);
            let (allowed, _, reset_after) = entry.check();
            if !allowed {
                return Decision::Block {
                    reason: format!("tool '{tool}' rate limit exceeded ({limit}/min)"),
                    rl: Some(RateLimitInfo {
                        limit,
                        remaining: 0,
                        reset_after_secs: reset_after,
                    }),
                };
            }
        }

        Decision::Allow { rl: Some(agent_rl) }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentPolicy, FilterMode};

    fn policy(rate_limit: usize) -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit,
            rate_limit_burst: None,
            tool_rate_limits: HashMap::new(),
            upstream: None,
            api_key: None,
            timeout_secs: None,
            approval_required: vec![],
            hitl_timeout_secs: 60,
            shadow_tools: vec![],
            federate: false,
            allowed_resources: None,
            denied_resources: vec![],
            allowed_prompts: None,
            denied_prompts: vec![],
            mtls_identity: None,
        }
    }

    fn make_mw(
        agents: HashMap<String, AgentPolicy>,
        ip_limit: Option<usize>,
    ) -> RateLimitMiddleware {
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            ip_limit,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        RateLimitMiddleware::new(rx)
    }

    fn ctx(agent: &str, tool: &str, ip: Option<&str>) -> McpContext {
        McpContext {
            agent_id: agent.to_string(),
            method: "tools/call".to_string(),
            tool_name: Some(tool.to_string()),
            arguments: None,
            client_ip: ip.map(String::from),
        }
    }

    #[tokio::test]
    async fn non_tools_call_always_allowed() {
        let mw = make_mw(HashMap::new(), None);
        let ctx = McpContext {
            agent_id: "a".to_string(),
            method: "initialize".to_string(),
            tool_name: None,
            arguments: None,
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn unknown_agent_passes_to_auth_middleware() {
        let mw = make_mw(HashMap::new(), None);
        assert!(matches!(
            mw.check(&ctx("ghost", "echo", None)).await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn within_global_limit_allowed() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(3));
        let mw = make_mw(agents, None);
        for _ in 0..3 {
            assert!(matches!(
                mw.check(&ctx("a", "echo", None)).await,
                Decision::Allow { .. }
            ));
        }
    }

    #[tokio::test]
    async fn exceeds_global_limit_blocked() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(2));
        let mw = make_mw(agents, None);
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn per_tool_rate_limit_enforced() {
        let mut tool_limits = HashMap::new();
        tool_limits.insert("search".to_string(), 1usize);
        let mut agents = HashMap::new();
        agents.insert(
            "a".to_string(),
            AgentPolicy {
                allowed_tools: None,
                denied_tools: vec![],
                rate_limit: 100,
                rate_limit_burst: None,
                tool_rate_limits: tool_limits,
                upstream: None,
                api_key: None,
                timeout_secs: None,
                approval_required: vec![],
                hitl_timeout_secs: 60,
                shadow_tools: vec![],
                federate: false,
                allowed_resources: None,
                denied_resources: vec![],
                allowed_prompts: None,
                denied_prompts: vec![],
                mtls_identity: None,
            },
        );
        let mw = make_mw(agents, None);
        assert!(matches!(
            mw.check(&ctx("a", "search", None)).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "search", None)).await,
            Decision::Block { .. }
        ));
        // Other tools not affected
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn ip_rate_limit_enforced() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(100));
        let mw = make_mw(agents, Some(2));
        assert!(matches!(
            mw.check(&ctx("a", "echo", Some("1.2.3.4"))).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "echo", Some("1.2.3.4"))).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "echo", Some("1.2.3.4"))).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn different_ips_have_separate_limits() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(100));
        let mw = make_mw(agents, Some(1));
        assert!(matches!(
            mw.check(&ctx("a", "echo", Some("1.1.1.1"))).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "echo", Some("2.2.2.2"))).await,
            Decision::Allow { .. }
        ));
        // Second call from first IP blocked
        assert!(matches!(
            mw.check(&ctx("a", "echo", Some("1.1.1.1"))).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn allow_carries_rate_limit_info() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(10));
        let mw = make_mw(agents, None);
        if let Decision::Allow { rl: Some(info) } = mw.check(&ctx("a", "echo", None)).await {
            assert_eq!(info.limit, 10);
            assert_eq!(info.remaining, 9); // 1 used
            assert!(info.reset_after_secs <= 60);
        } else {
            panic!("expected Allow with RateLimitInfo");
        }
    }

    #[tokio::test]
    async fn block_carries_rate_limit_info_with_zero_remaining() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(1));
        let mw = make_mw(agents, None);
        let _ = mw.check(&ctx("a", "echo", None)).await; // consume the 1 allowed
        if let Decision::Block { rl: Some(info), .. } = mw.check(&ctx("a", "echo", None)).await {
            assert_eq!(info.limit, 1);
            assert_eq!(info.remaining, 0);
        } else {
            panic!("expected Block with RateLimitInfo");
        }
    }

    #[tokio::test]
    async fn no_client_ip_skips_ip_limit() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(100));
        let mw = make_mw(agents, Some(1));
        for _ in 0..5 {
            assert!(matches!(
                mw.check(&ctx("a", "echo", None)).await,
                Decision::Allow { .. }
            ));
        }
    }

    #[tokio::test]
    async fn remaining_count_decrements() {
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(5));
        let mw = make_mw(agents, None);
        for expected_remaining in (0..5).rev() {
            if let Decision::Allow { rl: Some(info) } = mw.check(&ctx("a", "echo", None)).await {
                assert_eq!(info.remaining, expected_remaining);
            } else {
                panic!("expected Allow");
            }
        }
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn burst_config_respected() {
        let mut agents = HashMap::new();
        agents.insert(
            "a".to_string(),
            AgentPolicy {
                rate_limit: 60,
                rate_limit_burst: Some(2), // only 2 rapid requests allowed
                ..policy(60)
            },
        );
        let mw = make_mw(agents, None);
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("a", "echo", None)).await,
            Decision::Block { .. }
        ));
    }
}

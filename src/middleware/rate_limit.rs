use super::{Decision, McpContext, Middleware};
use crate::live_config::LiveConfig;
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, watch};

type ToolCounts = Arc<Mutex<HashMap<(String, String), Vec<Instant>>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentPolicy, FilterMode};

    fn policy(rate_limit: usize) -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit,
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
        // Rate limit doesn't block unknown agents — that's auth's job
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
}

pub struct RateLimitMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
    /// Per-agent sliding window counters — keyed by agent_id.
    counts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    /// Per-(agent, tool) sliding window counters for tool_rate_limits.
    tool_counts: ToolCounts,
    /// Per-IP sliding window counters (HTTP mode). Keyed by client IP string.
    ip_counts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimitMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let tool_counts = Arc::new(Mutex::new(HashMap::new()));
        let ip_counts = Arc::new(Mutex::new(HashMap::new()));

        // Background task: purge inactive entries every 5 minutes to prevent
        // unbounded HashMap growth when many distinct agents/IPs are seen.
        {
            let counts = Arc::clone(&counts);
            let tool_counts = Arc::clone(&tool_counts);
            let ip_counts = Arc::clone(&ip_counts);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                interval.tick().await; // skip immediate tick
                loop {
                    interval.tick().await;
                    let window = Duration::from_secs(60);
                    let now = Instant::now();
                    {
                        let mut m = counts.lock().await;
                        m.retain(|_, ts: &mut Vec<Instant>| {
                            ts.retain(|t| now.duration_since(*t) < window);
                            !ts.is_empty()
                        });
                    }
                    {
                        let mut m = tool_counts.lock().await;
                        m.retain(|_, ts: &mut Vec<Instant>| {
                            ts.retain(|t| now.duration_since(*t) < window);
                            !ts.is_empty()
                        });
                    }
                    {
                        let mut m = ip_counts.lock().await;
                        m.retain(|_, ts: &mut Vec<Instant>| {
                            ts.retain(|t| now.duration_since(*t) < window);
                            !ts.is_empty()
                        });
                    }
                }
            });
        }

        Self {
            config,
            counts,
            tool_counts,
            ip_counts,
        }
    }
}

/// Seconds until the oldest timestamp in `ts` ages out of the 60s window.
fn window_reset_secs(ts: &[Instant], now: Instant) -> u64 {
    ts.first()
        .map(|oldest| {
            let elapsed = now.duration_since(*oldest).as_secs();
            60u64.saturating_sub(elapsed)
        })
        .unwrap_or(60)
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        use super::RateLimitInfo;

        if !matches!(
            ctx.method.as_str(),
            "tools/call" | "resources/read" | "resources/subscribe" | "prompts/get"
        ) {
            return Decision::Allow { rl: None };
        }

        let (global_limit, tool_limit, ip_limit) = {
            let cfg = self.config.borrow();
            let Some(policy) = cfg.agents.get(&ctx.agent_id) else {
                return Decision::Allow { rl: None }; // unknown agents are blocked by AuthMiddleware
            };
            let tool_limit = ctx
                .tool_name
                .as_ref()
                .and_then(|t| policy.tool_rate_limits.get(t).copied());
            (policy.rate_limit, tool_limit, cfg.ip_rate_limit)
        };

        let now = Instant::now();
        let window = Duration::from_secs(60);

        // ── IP rate limit (checked first — cheapest rejection) ─────────────────
        if let (Some(limit), Some(ip)) = (ip_limit, ctx.client_ip.as_ref()) {
            let mut ip_counts = self.ip_counts.lock().await;
            let ts = ip_counts.entry(ip.clone()).or_default();
            ts.retain(|t| now.duration_since(*t) < window);
            if ts.len() >= limit {
                return Decision::Block {
                    reason: format!("IP rate limit exceeded ({limit}/min)"),
                    rl: Some(RateLimitInfo {
                        limit,
                        remaining: 0,
                        reset_after_secs: window_reset_secs(ts, now),
                    }),
                };
            }
            ts.push(now);
        }

        // ── Global agent rate limit ────────────────────────────────────────────
        let agent_rl = {
            let mut counts = self.counts.lock().await;
            let ts = counts.entry(ctx.agent_id.clone()).or_default();
            ts.retain(|t| now.duration_since(*t) < window);

            if ts.len() >= global_limit {
                return Decision::Block {
                    reason: format!("rate limit exceeded ({global_limit}/min)"),
                    rl: Some(RateLimitInfo {
                        limit: global_limit,
                        remaining: 0,
                        reset_after_secs: window_reset_secs(ts, now),
                    }),
                };
            }
            ts.push(now);
            RateLimitInfo {
                limit: global_limit,
                remaining: global_limit.saturating_sub(ts.len()),
                reset_after_secs: window_reset_secs(ts, now),
            }
        };

        // ── Per-tool rate limit ────────────────────────────────────────────────
        if let (Some(limit), Some(tool)) = (tool_limit, ctx.tool_name.as_ref()) {
            let key = (ctx.agent_id.clone(), tool.clone());
            let mut tool_counts = self.tool_counts.lock().await;
            let ts = tool_counts.entry(key.clone()).or_default();
            ts.retain(|t| now.duration_since(*t) < window);

            if ts.len() >= limit {
                return Decision::Block {
                    reason: format!("tool '{tool}' rate limit exceeded ({limit}/min)"),
                    rl: Some(RateLimitInfo {
                        limit,
                        remaining: 0,
                        reset_after_secs: window_reset_secs(ts, now),
                    }),
                };
            }
            ts.push(now);
        }

        Decision::Allow { rl: Some(agent_rl) }
    }
}

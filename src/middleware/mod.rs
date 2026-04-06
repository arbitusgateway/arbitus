pub mod auth;
pub mod hitl;
pub mod opa;
pub mod payload_filter;
pub mod rate_limit;
pub mod schema_validation;

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// Immutable context for an MCP request, passed through the entire pipeline.
pub struct McpContext {
    pub agent_id: String,
    pub method: String,
    pub tool_name: Option<String>,
    pub arguments: Option<Value>,
    /// Client IP address — present in HTTP mode, None in stdio mode.
    pub client_ip: Option<String>,
}

/// Rate-limit metadata attached to every tools/call decision.
/// The HTTP transport uses this to populate `X-RateLimit-*` response headers.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Configured limit (requests / 60-second window).
    pub limit: usize,
    /// Requests remaining in the current window after this one.
    pub remaining: usize,
    /// Seconds until the oldest in-window request ages out (≤ 60).
    pub reset_after_secs: u64,
}

/// Middleware decision: continue or block with a reason.
pub enum Decision {
    Allow {
        rl: Option<RateLimitInfo>,
    },
    Block {
        reason: String,
        rl: Option<RateLimitInfo>,
    },
}

/// Core trait — each middleware implements `check`.
/// Returning `Allow` means "no objection, pass it along".
/// Returning `Block` stops the pipeline immediately.
#[async_trait]
pub trait Middleware: Send + Sync {
    fn name(&self) -> &'static str;
    async fn check(&self, ctx: &McpContext) -> Decision;
}

/// Composable pipeline — middlewares are executed in insertion order.
#[allow(dead_code)]
#[derive(Default)]
pub struct Pipeline {
    middlewares: Vec<Arc<dyn Middleware>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, mw: Arc<dyn Middleware>) -> Self {
        self.middlewares.push(mw);
        self
    }

    /// Run all middlewares. Stops at the first `Block`.
    /// The last `Allow`'s `RateLimitInfo` (if any) is forwarded to the caller.
    pub async fn run(&self, ctx: &McpContext) -> Decision {
        let mut last_rl: Option<RateLimitInfo> = None;
        for mw in &self.middlewares {
            match mw.check(ctx).await {
                Decision::Allow { rl } => {
                    if rl.is_some() {
                        last_rl = rl;
                    }
                }
                block => return block,
            }
        }
        Decision::Allow { rl: last_rl }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct AlwaysAllow;
    #[async_trait]
    impl Middleware for AlwaysAllow {
        fn name(&self) -> &'static str {
            "allow"
        }
        async fn check(&self, _: &McpContext) -> Decision {
            Decision::Allow { rl: None }
        }
    }

    struct AlwaysBlock;
    #[async_trait]
    impl Middleware for AlwaysBlock {
        fn name(&self) -> &'static str {
            "block"
        }
        async fn check(&self, _: &McpContext) -> Decision {
            Decision::Block {
                reason: "blocked".to_string(),
                rl: None,
            }
        }
    }

    struct Counter(Arc<AtomicUsize>);
    #[async_trait]
    impl Middleware for Counter {
        fn name(&self) -> &'static str {
            "counter"
        }
        async fn check(&self, _: &McpContext) -> Decision {
            self.0.fetch_add(1, Ordering::SeqCst);
            Decision::Allow { rl: None }
        }
    }

    fn ctx() -> McpContext {
        McpContext {
            agent_id: "test".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("echo".to_string()),
            arguments: None,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn empty_pipeline_allows() {
        let p = Pipeline::new();
        assert!(matches!(p.run(&ctx()).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn all_allow_middlewares_passes() {
        let p = Pipeline::new()
            .add(Arc::new(AlwaysAllow))
            .add(Arc::new(AlwaysAllow));
        assert!(matches!(p.run(&ctx()).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn first_block_short_circuits() {
        let counter = Arc::new(AtomicUsize::new(0));
        let p = Pipeline::new()
            .add(Arc::new(AlwaysBlock))
            .add(Arc::new(Counter(Arc::clone(&counter))));
        assert!(matches!(p.run(&ctx()).await, Decision::Block { .. }));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn middle_block_stops_rest() {
        let counter = Arc::new(AtomicUsize::new(0));
        let p = Pipeline::new()
            .add(Arc::new(AlwaysAllow))
            .add(Arc::new(AlwaysBlock))
            .add(Arc::new(Counter(Arc::clone(&counter))));
        assert!(matches!(p.run(&ctx()).await, Decision::Block { .. }));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn block_reason_preserved() {
        let p = Pipeline::new().add(Arc::new(AlwaysBlock));
        if let Decision::Block { reason, .. } = p.run(&ctx()).await {
            assert_eq!(reason, "blocked");
        } else {
            panic!("expected Block");
        }
    }
}

//! A2A policy interceptor — enforces Arbitus agent policies on A2A requests.
//!
//! This interceptor runs before every A2A handler method and applies:
//! 1. Agent identity extraction from the `x-arbitus-agent` header
//! 2. API key authentication if the agent has `api_key` configured
//! 3. Per-agent sliding-window rate limiting
//! 4. Payload filtering for blocked patterns on message text parts

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ra2a::{
    error::{A2AError, Result},
    server::{AuthenticatedUser, CallContext, CallInterceptor, Request, Response},
    types::SendMessageRequest,
};
use tokio::sync::{Mutex, watch};

use crate::live_config::LiveConfig;

/// Header used by callers to declare their agent identity.
pub const AGENT_ID_HEADER: &str = "x-arbitus-agent";
/// Header used for API key authentication.
pub const API_KEY_HEADER: &str = "x-api-key";

/// Per-agent request timestamp store for sliding-window rate limiting.
type RateCounts = Arc<Mutex<HashMap<String, Vec<Instant>>>>;

/// Enforces Arbitus agent policies on incoming A2A requests.
pub struct A2aPolicyInterceptor {
    config: watch::Receiver<Arc<LiveConfig>>,
    counts: RateCounts,
}

impl A2aPolicyInterceptor {
    /// Creates a new interceptor backed by the given live config receiver.
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        let counts: RateCounts = Arc::new(Mutex::new(HashMap::new()));

        // Background task: prune stale entries every 5 minutes to prevent unbounded growth.
        {
            let counts = Arc::clone(&counts);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let window = Duration::from_secs(60);
                    let now = Instant::now();
                    let mut m = counts.lock().await;
                    m.retain(|_, ts: &mut Vec<Instant>| {
                        ts.retain(|t| now.duration_since(*t) < window);
                        !ts.is_empty()
                    });
                }
            });
        }

        Self { config, counts }
    }

    /// Returns `true` if the agent has consumed fewer than `limit` requests in the last 60s.
    /// Appends the current timestamp to the window when returning `true`.
    async fn check_rate_limit(&self, agent_id: &str, limit: usize) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let mut m = self.counts.lock().await;
        let ts = m.entry(agent_id.to_string()).or_default();
        ts.retain(|t| now.duration_since(*t) < window);
        if ts.len() >= limit {
            return false;
        }
        ts.push(now);
        true
    }
}

impl CallInterceptor for A2aPolicyInterceptor {
    fn before<'a>(
        &'a self,
        ctx: &'a mut CallContext,
        req: &'a mut Request,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // ── 1. Agent identity ─────────────────────────────────────────────
            let agent_id = ctx
                .request_meta()
                .get(AGENT_ID_HEADER)
                .and_then(|v| v.first())
                .cloned()
                .ok_or_else(|| {
                    A2AError::Other(format!(
                        "missing '{AGENT_ID_HEADER}' header — agent identity required"
                    ))
                })?;

            // Reject suspiciously long agent IDs to prevent log injection.
            if agent_id.len() > 128 {
                return Err(A2AError::Other("agent ID exceeds maximum length".into()));
            }

            // Clone the Arc<LiveConfig> immediately so we don't hold the
            // watch::Ref (RwLockReadGuard) across any .await points.
            let cfg: Arc<LiveConfig> = Arc::clone(&*self.config.borrow());

            let (rate_limit, expected_api_key, patterns) = {
                let policy = match cfg.agents.get(&agent_id) {
                    Some(p) => p,
                    None => match cfg.default_policy.as_ref() {
                        Some(p) => p,
                        None => {
                            return Err(A2AError::Other(format!(
                                "agent '{agent_id}' is not configured"
                            )));
                        }
                    },
                };
                (
                    policy.rate_limit,
                    policy.api_key.clone(),
                    Arc::clone(&cfg.block_patterns),
                )
            };
            drop(cfg); // release Arc before any await

            // ── 2. API key authentication ─────────────────────────────────────
            if let Some(expected_key) = &expected_api_key {
                let provided = ctx
                    .request_meta()
                    .get(API_KEY_HEADER)
                    .and_then(|v| v.first())
                    .map(String::as_str)
                    .unwrap_or("");

                // Constant-time comparison to prevent timing attacks.
                use subtle::ConstantTimeEq;
                let ok: bool = expected_key.as_bytes().ct_eq(provided.as_bytes()).into();
                if !ok {
                    return Err(A2AError::Other("invalid or missing API key".into()));
                }
            }

            // ── 3. Rate limiting ──────────────────────────────────────────────
            if !self.check_rate_limit(&agent_id, rate_limit).await {
                return Err(A2AError::Other(format!(
                    "rate limit exceeded for agent '{agent_id}'"
                )));
            }

            // ── 4. Payload filtering ──────────────────────────────────────────
            // Only `message/send` and `message/stream` carry a message payload.
            if let Some(send_req) = req.downcast_ref::<SendMessageRequest>()
                && !patterns.is_empty()
            {
                // Collect all text content from the message parts.
                let text_content: String = send_req
                    .message
                    .parts
                    .iter()
                    .filter_map(|p| p.as_text())
                    .collect::<Vec<_>>()
                    .join(" ");

                for pattern in patterns.iter() {
                    if pattern.is_match(&text_content) {
                        return Err(A2AError::Other(
                            "request blocked: sensitive data detected".into(),
                        ));
                    }
                }
            }

            // ── 5. Mark request as authenticated ─────────────────────────────
            ctx.user = Arc::new(AuthenticatedUser::new(agent_id));

            Ok(())
        })
    }

    fn after<'a>(
        &'a self,
        _ctx: &'a CallContext,
        _resp: &'a mut Response,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentPolicy, FilterMode};
    use std::collections::HashMap;
    use tokio::sync::watch;

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

    fn policy_with_key(rate_limit: usize, key: &str) -> AgentPolicy {
        AgentPolicy {
            api_key: Some(key.to_string()),
            ..policy(rate_limit)
        }
    }

    fn make_interceptor(agents: HashMap<String, AgentPolicy>) -> A2aPolicyInterceptor {
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        A2aPolicyInterceptor::new(rx)
    }

    fn make_call_ctx(agent: Option<&str>, api_key: Option<&str>) -> CallContext {
        use ra2a::server::RequestMeta;
        use std::collections::HashMap;
        let mut meta: HashMap<String, Vec<String>> = HashMap::new();
        if let Some(a) = agent {
            meta.insert(AGENT_ID_HEADER.to_string(), vec![a.to_string()]);
        }
        if let Some(k) = api_key {
            meta.insert(API_KEY_HEADER.to_string(), vec![k.to_string()]);
        }
        CallContext::new("message/send", RequestMeta::new(meta))
    }

    fn send_req(text: &str) -> ra2a::types::SendMessageRequest {
        use ra2a::types::{Message, MessageId, Part, Role};
        let msg = Message {
            message_id: MessageId::from("msg-1"),
            role: Role::User, // serialized as "ROLE_USER" by ra2a
            parts: vec![Part::text(text)],
            task_id: None,
            context_id: None,
            reference_task_ids: vec![],
            metadata: None,
            extensions: vec![],
        };
        ra2a::types::SendMessageRequest::new(msg)
    }

    #[tokio::test]
    async fn missing_agent_header_is_rejected() {
        let interceptor = make_interceptor(HashMap::new());
        let mut ctx = make_call_ctx(None, None);
        let mut req = Request::new(send_req("hello"));
        let result = interceptor.before(&mut ctx, &mut req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing"));
    }

    #[tokio::test]
    async fn unknown_agent_is_rejected() {
        let interceptor = make_interceptor(HashMap::new());
        let mut ctx = make_call_ctx(Some("ghost"), None);
        let mut req = Request::new(send_req("hello"));
        let result = interceptor.before(&mut ctx, &mut req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not configured"));
    }

    #[tokio::test]
    async fn known_agent_without_key_passes() {
        let mut agents = HashMap::new();
        agents.insert("cursor".to_string(), policy(60));
        let interceptor = make_interceptor(agents);
        let mut ctx = make_call_ctx(Some("cursor"), None);
        let mut req = Request::new(send_req("hello"));
        assert!(interceptor.before(&mut ctx, &mut req).await.is_ok());
    }

    #[tokio::test]
    async fn wrong_api_key_is_rejected() {
        let mut agents = HashMap::new();
        agents.insert("secured".to_string(), policy_with_key(60, "secret-key"));
        let interceptor = make_interceptor(agents);
        let mut ctx = make_call_ctx(Some("secured"), Some("wrong-key"));
        let mut req = Request::new(send_req("hello"));
        let result = interceptor.before(&mut ctx, &mut req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("API key"));
    }

    #[tokio::test]
    async fn correct_api_key_passes() {
        let mut agents = HashMap::new();
        agents.insert("secured".to_string(), policy_with_key(60, "secret-key"));
        let interceptor = make_interceptor(agents);
        let mut ctx = make_call_ctx(Some("secured"), Some("secret-key"));
        let mut req = Request::new(send_req("hello"));
        assert!(interceptor.before(&mut ctx, &mut req).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limit_blocks_when_exceeded() {
        let mut agents = HashMap::new();
        agents.insert("limited".to_string(), policy(2));
        let interceptor = make_interceptor(agents);

        for _ in 0..2 {
            let mut ctx = make_call_ctx(Some("limited"), None);
            let mut req = Request::new(send_req("hello"));
            assert!(interceptor.before(&mut ctx, &mut req).await.is_ok());
        }

        let mut ctx = make_call_ctx(Some("limited"), None);
        let mut req = Request::new(send_req("hello"));
        let result = interceptor.before(&mut ctx, &mut req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rate limit"));
    }

    #[tokio::test]
    async fn blocked_pattern_in_message_is_rejected() {
        use crate::live_config::LiveConfig;
        use regex::Regex;

        let mut agents = HashMap::new();
        agents.insert("cursor".to_string(), policy(60));
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![Regex::new("private_key").unwrap()],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        let interceptor = A2aPolicyInterceptor::new(rx);

        let mut ctx = make_call_ctx(Some("cursor"), None);
        let mut req = Request::new(send_req("my private_key=AAABBB"));
        let result = interceptor.before(&mut ctx, &mut req).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sensitive data"));
    }

    #[tokio::test]
    async fn clean_message_passes_filter() {
        use crate::live_config::LiveConfig;
        use regex::Regex;

        let mut agents = HashMap::new();
        agents.insert("cursor".to_string(), policy(60));
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![Regex::new("private_key").unwrap()],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        let interceptor = A2aPolicyInterceptor::new(rx);

        let mut ctx = make_call_ctx(Some("cursor"), None);
        let mut req = Request::new(send_req("hello world, no secrets here"));
        assert!(interceptor.before(&mut ctx, &mut req).await.is_ok());
    }
}

use super::{Decision, McpContext, Middleware};
use crate::{
    config::tool_matches,
    hitl::{ApprovalDecision, HitlStore},
    live_config::LiveConfig,
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentPolicy, FilterMode};
    use std::collections::HashMap;

    fn policy(approval_required: Vec<&str>, timeout_secs: u64) -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit: 60,
            tool_rate_limits: HashMap::new(),
            upstream: None,
            api_key: None,
            timeout_secs: None,
            approval_required: approval_required.into_iter().map(String::from).collect(),
            hitl_timeout_secs: timeout_secs,
            shadow_tools: vec![],
            federate: false,
            allowed_resources: None,
            denied_resources: vec![],
            allowed_prompts: None,
            denied_prompts: vec![],
            mtls_identity: None,
        }
    }

    fn make_mw(store: Arc<HitlStore>, agents: HashMap<String, AgentPolicy>) -> HitlMiddleware {
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        HitlMiddleware::new(store, rx)
    }

    fn ctx(agent: &str, tool: &str) -> McpContext {
        McpContext {
            agent_id: agent.to_string(),
            method: "tools/call".to_string(),
            tool_name: Some(tool.to_string()),
            arguments: None,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn non_tools_call_always_allowed() {
        let store = HitlStore::new();
        let mw = make_mw(Arc::clone(&store), HashMap::new());
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
    async fn tool_not_requiring_approval_passes() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(vec!["dangerous_op"], 60));
        let mw = make_mw(Arc::clone(&store), agents);
        // "echo" is not in approval_required
        assert!(matches!(
            mw.check(&ctx("a", "echo")).await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn unknown_agent_passes() {
        // Unknown agents are blocked by AuthMiddleware, not HITL
        let store = HitlStore::new();
        let mw = make_mw(Arc::clone(&store), HashMap::new());
        assert!(matches!(
            mw.check(&ctx("ghost", "echo")).await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn approved_call_returns_allow() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(vec!["critical_op"], 10));
        let mw = Arc::new(make_mw(Arc::clone(&store), agents));

        let mw2 = Arc::clone(&mw);
        let check = tokio::spawn(async move { mw2.check(&ctx("a", "critical_op")).await });

        // Wait for the approval entry to appear
        for _ in 0..50 {
            if !store.list().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pending = store.list().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_name, "critical_op");
        store
            .resolve(&pending[0].id, ApprovalDecision::Approved)
            .await;

        let decision = check.await.unwrap();
        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn rejected_call_returns_block() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(vec!["critical_op"], 10));
        let mw = Arc::new(make_mw(Arc::clone(&store), agents));

        let mw2 = Arc::clone(&mw);
        let check = tokio::spawn(async move { mw2.check(&ctx("a", "critical_op")).await });

        for _ in 0..50 {
            if !store.list().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let id = store.list().await[0].id.clone();
        store
            .resolve(
                &id,
                ApprovalDecision::Rejected {
                    reason: Some("denied by policy".to_string()),
                },
            )
            .await;

        let decision = check.await.unwrap();
        if let Decision::Block { reason, .. } = decision {
            assert!(reason.contains("rejected by operator"));
            assert!(reason.contains("denied by policy"));
        } else {
            panic!("expected Block");
        }
    }

    #[tokio::test]
    async fn timeout_auto_rejects() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        // hitl_timeout_secs: 0 → immediate timeout
        agents.insert("a".to_string(), policy(vec!["critical_op"], 0));
        let mw = make_mw(Arc::clone(&store), agents);

        let decision = mw.check(&ctx("a", "critical_op")).await;
        assert!(matches!(decision, Decision::Block { .. }));
        if let Decision::Block { reason, .. } = decision {
            assert!(reason.contains("timed out"));
        }
    }

    #[tokio::test]
    async fn glob_pattern_matches_approval() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(vec!["delete_*"], 10));
        let mw = Arc::new(make_mw(Arc::clone(&store), agents));

        let mw2 = Arc::clone(&mw);
        let check = tokio::spawn(async move { mw2.check(&ctx("a", "delete_database")).await });

        for _ in 0..50 {
            if !store.list().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let id = store.list().await[0].id.clone();
        store.resolve(&id, ApprovalDecision::Approved).await;

        assert!(matches!(check.await.unwrap(), Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn arguments_stored_in_pending_approval() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(vec!["risky"], 10));
        let mw = Arc::new(make_mw(Arc::clone(&store), agents));

        let args = serde_json::json!({"path": "/etc/passwd"});
        let check_ctx = McpContext {
            agent_id: "a".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("risky".to_string()),
            arguments: Some(args.clone()),
            client_ip: None,
        };

        let mw2 = Arc::clone(&mw);
        let check = tokio::spawn(async move { mw2.check(&check_ctx).await });

        for _ in 0..50 {
            if !store.list().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pending = store.list().await;
        assert_eq!(pending[0].arguments, args);

        store
            .resolve(&pending[0].id, ApprovalDecision::Approved)
            .await;
        check.await.unwrap();
    }

    #[tokio::test]
    async fn none_arguments_stored_as_null() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(vec!["risky"], 10));
        let mw = Arc::new(make_mw(Arc::clone(&store), agents));

        // arguments: None → should be stored as JSON null
        let check_ctx = McpContext {
            agent_id: "a".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("risky".to_string()),
            arguments: None,
            client_ip: None,
        };

        let mw2 = Arc::clone(&mw);
        let check = tokio::spawn(async move { mw2.check(&check_ctx).await });

        for _ in 0..50 {
            if !store.list().await.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pending = store.list().await;
        assert_eq!(pending[0].arguments, serde_json::Value::Null);

        store
            .resolve(&pending[0].id, ApprovalDecision::Approved)
            .await;
        check.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_approvals_for_same_agent() {
        let store = HitlStore::new();
        let mut agents = HashMap::new();
        agents.insert("a".to_string(), policy(vec!["op1", "op2"], 10));
        let mw = Arc::new(make_mw(Arc::clone(&store), agents));

        let mw2 = Arc::clone(&mw);
        let mw3 = Arc::clone(&mw);
        let check1 = tokio::spawn(async move { mw2.check(&ctx("a", "op1")).await });
        let check2 = tokio::spawn(async move { mw3.check(&ctx("a", "op2")).await });

        // Wait for both to appear as pending
        for _ in 0..100 {
            if store.list().await.len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pending = store.list().await;
        assert_eq!(pending.len(), 2, "both calls should be pending");

        for p in &pending {
            store.resolve(&p.id, ApprovalDecision::Approved).await;
        }

        assert!(matches!(check1.await.unwrap(), Decision::Allow { .. }));
        assert!(matches!(check2.await.unwrap(), Decision::Allow { .. }));
    }
}

pub struct HitlMiddleware {
    store: Arc<HitlStore>,
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl HitlMiddleware {
    pub fn new(store: Arc<HitlStore>, config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { store, config }
    }
}

#[async_trait]
impl Middleware for HitlMiddleware {
    fn name(&self) -> &'static str {
        "hitl"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow { rl: None };
        }

        let tool = match ctx.tool_name.as_deref() {
            Some(t) => t,
            None => return Decision::Allow { rl: None },
        };

        let (needs_approval, timeout_secs) = {
            let cfg = self.config.borrow();
            let policy = cfg
                .agents
                .get(&ctx.agent_id)
                .or(cfg.default_policy.as_ref());
            match policy {
                Some(p) => {
                    let matched = p
                        .approval_required
                        .iter()
                        .any(|pat| tool_matches(pat, tool));
                    (matched, p.hitl_timeout_secs)
                }
                None => (false, 60),
            }
        };

        if !needs_approval {
            return Decision::Allow { rl: None };
        }

        let args = ctx.arguments.clone().unwrap_or(serde_json::Value::Null);
        let (id, rx) = self
            .store
            .insert(ctx.agent_id.clone(), tool.to_string(), args)
            .await;

        tracing::info!(
            approval_id = %id,
            agent = %ctx.agent_id,
            tool = %tool,
            timeout_secs,
            "awaiting human approval"
        );

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(ApprovalDecision::Approved)) => {
                tracing::info!(approval_id = %id, "approved");
                Decision::Allow { rl: None }
            }
            Ok(Ok(ApprovalDecision::Rejected { reason })) => {
                tracing::info!(approval_id = %id, ?reason, "rejected by operator");
                Decision::Block {
                    reason: format!(
                        "tool '{}' rejected by operator{}",
                        tool,
                        reason
                            .as_deref()
                            .map(|r| format!(": {r}"))
                            .unwrap_or_default()
                    ),
                    rl: None,
                }
            }
            // Sender dropped (race with timeout cleanup) or timeout elapsed
            Ok(Err(_)) | Err(_) => {
                // Clean up the entry if the timeout fired before the operator acted
                self.store
                    .resolve(
                        &id,
                        ApprovalDecision::Rejected {
                            reason: Some("timeout".into()),
                        },
                    )
                    .await;
                tracing::warn!(approval_id = %id, "approval timed out, auto-rejecting");
                Decision::Block {
                    reason: format!("tool '{}' approval timed out", tool),
                    rl: None,
                }
            }
        }
    }
}

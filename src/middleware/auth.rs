use super::{Decision, McpContext, Middleware};
use crate::{config::tool_matches, live_config::LiveConfig};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilterMode, make_agent};
    use std::collections::HashMap;

    fn make_mw(agents: HashMap<String, crate::config::AgentPolicy>) -> AuthMiddleware {
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        ));
        let (_, rx) = watch::channel(live);
        AuthMiddleware::new(rx)
    }

    fn ctx(agent: &str, method: &str, tool: Option<&str>) -> McpContext {
        McpContext {
            agent_id: agent.to_string(),
            method: method.to_string(),
            tool_name: tool.map(String::from),
            arguments: None,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn non_tools_call_always_allowed() {
        let mw = make_mw(HashMap::new()); // unknown agent but method != tools/call
        assert!(matches!(
            mw.check(&ctx("nobody", "initialize", None)).await,
            Decision::Allow { rl: None }
        ));
        assert!(matches!(
            mw.check(&ctx("nobody", "notifications/initialized", None))
                .await,
            Decision::Allow { rl: None }
        ));
    }

    #[tokio::test]
    async fn unknown_agent_blocked_on_tools_call() {
        let mw = make_mw(HashMap::new());
        assert!(matches!(
            mw.check(&ctx("ghost", "tools/call", Some("echo"))).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn denied_tool_blocked() {
        let mut agents = HashMap::new();
        agents.insert(
            "cursor".to_string(),
            make_agent(None, vec!["write_file"], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("cursor", "tools/call", Some("write_file")))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn non_denied_tool_allowed_without_allowlist() {
        let mut agents = HashMap::new();
        agents.insert(
            "cursor".to_string(),
            make_agent(None, vec!["write_file"], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("cursor", "tools/call", Some("read_file")))
                .await,
            Decision::Allow { rl: None }
        ));
    }

    #[tokio::test]
    async fn allowlist_permits_listed_tool() {
        let mut agents = HashMap::new();
        agents.insert(
            "claude".to_string(),
            make_agent(Some(vec!["read_file"]), vec![], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("claude", "tools/call", Some("read_file")))
                .await,
            Decision::Allow { rl: None }
        ));
    }

    #[tokio::test]
    async fn allowlist_blocks_unlisted_tool() {
        let mut agents = HashMap::new();
        agents.insert(
            "claude".to_string(),
            make_agent(Some(vec!["read_file"]), vec![], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("claude", "tools/call", Some("delete_file")))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn denied_takes_priority_over_allowlist() {
        let mut agents = HashMap::new();
        agents.insert(
            "cursor".to_string(),
            make_agent(
                Some(vec!["read_file", "write_file"]),
                vec!["write_file"],
                60,
            ),
        );
        let mw = make_mw(agents);
        // Even though write_file is in allowed_tools, denied_tools wins
        assert!(matches!(
            mw.check(&ctx("cursor", "tools/call", Some("write_file")))
                .await,
            Decision::Block { .. }
        ));
    }

    // ── Glob wildcards — denylist ─────────────────────────────────────────────

    #[tokio::test]
    async fn glob_denylist_blocks_matching_tools() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(None, vec!["write_*"], 60));
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("write_file")))
                .await,
            Decision::Block { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("write_dir")))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn glob_denylist_allows_non_matching_tools() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(None, vec!["write_*"], 60));
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("read_file")))
                .await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn glob_denylist_star_blocks_all_tools() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(None, vec!["*"], 60));
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("any_tool")))
                .await,
            Decision::Block { .. }
        ));
    }

    // ── Glob wildcards — allowlist ────────────────────────────────────────────

    #[tokio::test]
    async fn glob_allowlist_permits_matching_tools() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent(Some(vec!["read_*", "list_*"]), vec![], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("read_file")))
                .await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("list_dir")))
                .await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn glob_allowlist_blocks_non_matching_tools() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent(Some(vec!["read_*"]), vec![], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("write_file")))
                .await,
            Decision::Block { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("delete_file")))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn glob_allowlist_star_permits_all_tools() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(Some(vec!["*"]), vec![], 60));
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("anything")))
                .await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn glob_deny_overrides_glob_allowlist() {
        // read_file is in allowlist via read_*, but also denied via read_file explicitly
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent(Some(vec!["read_*"]), vec!["read_file"], 60),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("read_file")))
                .await,
            Decision::Block { .. }
        ));
        // read_dir still allowed (not denied)
        assert!(matches!(
            mw.check(&ctx("agent", "tools/call", Some("read_dir")))
                .await,
            Decision::Allow { .. }
        ));
    }

    // ── default_policy fallback ───────────────────────────────────────────────

    fn make_mw_with_default(
        agents: HashMap<String, crate::config::AgentPolicy>,
        default: crate::config::AgentPolicy,
    ) -> AuthMiddleware {
        use crate::config::FilterMode;
        let live = Arc::new(LiveConfig::new(
            agents,
            vec![],
            vec![],
            None,
            FilterMode::Block,
            Some(default),
        ));
        let (_, rx) = watch::channel(live);
        AuthMiddleware::new(rx)
    }

    #[tokio::test]
    async fn unknown_agent_falls_back_to_default_policy() {
        // default_policy with a denylist — unknown agent should use it instead of being blocked
        let default = make_agent(None, vec!["delete_*"], 60);
        let mw = make_mw_with_default(HashMap::new(), default);

        // allowed by default policy (not in denylist)
        assert!(matches!(
            mw.check(&ctx("unknown-agent", "tools/call", Some("read_file")))
                .await,
            Decision::Allow { .. }
        ));
        // blocked by default policy denylist
        assert!(matches!(
            mw.check(&ctx("unknown-agent", "tools/call", Some("delete_db")))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn named_agent_takes_precedence_over_default_policy() {
        let mut agents = HashMap::new();
        // named agent only allows read_file
        agents.insert(
            "strict-agent".to_string(),
            make_agent(Some(vec!["read_file"]), vec![], 60),
        );
        // default policy allows everything
        let default = make_agent(Some(vec!["*"]), vec![], 60);
        let mw = make_mw_with_default(agents, default);

        // strict-agent is blocked by its own allowlist, not the permissive default
        assert!(matches!(
            mw.check(&ctx("strict-agent", "tools/call", Some("write_file")))
                .await,
            Decision::Block { .. }
        ));
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tools_call_without_tool_name_blocked() {
        // tools/call with no tool name — unknown agent, should block
        let mw = make_mw(HashMap::new());
        let ctx = McpContext {
            agent_id: "ghost".to_string(),
            method: "tools/call".to_string(),
            tool_name: None,
            arguments: None,
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn block_reason_contains_tool_name() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(None, vec!["delete_db"], 60));
        let mw = make_mw(agents);
        if let Decision::Block { reason, .. } = mw
            .check(&ctx("agent", "tools/call", Some("delete_db")))
            .await
        {
            assert!(reason.contains("delete_db"));
        } else {
            panic!("expected Block");
        }
    }

    // ── Resources ────────────────────────────────────────────────────────────

    fn make_agent_with_resources(
        allowed_resources: Option<Vec<&str>>,
        denied_resources: Vec<&str>,
    ) -> crate::config::AgentPolicy {
        let mut p = make_agent(None, vec![], 60);
        p.allowed_resources = allowed_resources.map(|v| v.into_iter().map(String::from).collect());
        p.denied_resources = denied_resources.into_iter().map(String::from).collect();
        p
    }

    fn make_agent_with_prompts(
        allowed_prompts: Option<Vec<&str>>,
        denied_prompts: Vec<&str>,
    ) -> crate::config::AgentPolicy {
        let mut p = make_agent(None, vec![], 60);
        p.allowed_prompts = allowed_prompts.map(|v| v.into_iter().map(String::from).collect());
        p.denied_prompts = denied_prompts.into_iter().map(String::from).collect();
        p
    }

    fn resource_ctx(agent: &str, method: &str, uri: &str) -> McpContext {
        McpContext {
            agent_id: agent.to_string(),
            method: method.to_string(),
            tool_name: Some(uri.to_string()),
            arguments: None,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn resources_read_allowed_when_no_policy() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(None, vec![], 60));
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&resource_ctx("agent", "resources/read", "file:///data.txt"))
                .await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn resources_read_blocked_by_denylist() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent_with_resources(None, vec!["file:///secret*"]),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&resource_ctx(
                "agent",
                "resources/read",
                "file:///secret.txt"
            ))
            .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn resources_read_blocked_when_not_in_allowlist() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent_with_resources(Some(vec!["file:///public/*"]), vec![]),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&resource_ctx(
                "agent",
                "resources/read",
                "file:///private.txt"
            ))
            .await,
            Decision::Block { .. }
        ));
        assert!(matches!(
            mw.check(&resource_ctx(
                "agent",
                "resources/read",
                "file:///public/readme.txt"
            ))
            .await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn resources_subscribe_uses_same_policy_as_read() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent_with_resources(None, vec!["file:///forbidden"]),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&resource_ctx(
                "agent",
                "resources/subscribe",
                "file:///forbidden"
            ))
            .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn resources_list_always_allowed_by_auth() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent_with_resources(Some(vec!["file:///allowed"]), vec![]),
        );
        let mw = make_mw(agents);
        let ctx = McpContext {
            agent_id: "agent".to_string(),
            method: "resources/list".to_string(),
            tool_name: None,
            arguments: None,
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Allow { .. }));
    }

    // ── Prompts ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn prompts_get_allowed_when_no_policy() {
        let mut agents = HashMap::new();
        agents.insert("agent".to_string(), make_agent(None, vec![], 60));
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&resource_ctx("agent", "prompts/get", "summarize"))
                .await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn prompts_get_blocked_by_denylist() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent_with_prompts(None, vec!["admin_*"]),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&resource_ctx("agent", "prompts/get", "admin_report"))
                .await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn prompts_get_blocked_when_not_in_allowlist() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent_with_prompts(Some(vec!["summarize", "translate"]), vec![]),
        );
        let mw = make_mw(agents);
        assert!(matches!(
            mw.check(&resource_ctx("agent", "prompts/get", "generate_code"))
                .await,
            Decision::Block { .. }
        ));
        assert!(matches!(
            mw.check(&resource_ctx("agent", "prompts/get", "summarize"))
                .await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn prompts_list_always_allowed_by_auth() {
        let mut agents = HashMap::new();
        agents.insert(
            "agent".to_string(),
            make_agent_with_prompts(Some(vec!["only_this"]), vec![]),
        );
        let mw = make_mw(agents);
        let ctx = McpContext {
            agent_id: "agent".to_string(),
            method: "prompts/list".to_string(),
            tool_name: None,
            arguments: None,
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn block_reason_for_unknown_agent_is_generic() {
        // The client-facing reason must not reveal whether the agent exists,
        // preventing enumeration of valid agent IDs via error messages.
        let mw = make_mw(HashMap::new());
        if let Decision::Block { reason, .. } = mw
            .check(&ctx("mystery-agent", "tools/call", Some("echo")))
            .await
        {
            assert!(
                !reason.contains("mystery-agent"),
                "reason leaked agent name: {reason}"
            );
            assert_eq!(reason, "not authorized");
        } else {
            panic!("expected Block");
        }
    }
}

pub struct AuthMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl AuthMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    fn name(&self) -> &'static str {
        "auth"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        let method = ctx.method.as_str();
        if !matches!(
            method,
            "tools/call" | "resources/read" | "resources/subscribe" | "prompts/get"
        ) {
            return Decision::Allow { rl: None };
        }

        let cfg = self.config.borrow();
        let Some(policy) = cfg
            .agents
            .get(&ctx.agent_id)
            .or(cfg.default_policy.as_ref())
        else {
            tracing::debug!(agent = %ctx.agent_id, "agent not found in configuration");
            return Decision::Block {
                reason: "not authorized".to_string(),
                rl: None,
            };
        };

        match method {
            "tools/call" => {
                let tool = ctx.tool_name.as_deref().unwrap_or("");
                if policy.denied_tools.iter().any(|t| tool_matches(t, tool)) {
                    return Decision::Block {
                        reason: format!("tool '{tool}' explicitly denied"),
                        rl: None,
                    };
                }
                if let Some(allowed) = &policy.allowed_tools
                    && !allowed.iter().any(|t| tool_matches(t, tool))
                {
                    return Decision::Block {
                        reason: format!("tool '{tool}' not in allowlist"),
                        rl: None,
                    };
                }
            }
            "resources/read" | "resources/subscribe" => {
                let uri = ctx.tool_name.as_deref().unwrap_or("");
                if policy.denied_resources.iter().any(|t| tool_matches(t, uri)) {
                    return Decision::Block {
                        reason: format!("resource '{uri}' explicitly denied"),
                        rl: None,
                    };
                }
                if let Some(allowed) = &policy.allowed_resources
                    && !allowed.iter().any(|t| tool_matches(t, uri))
                {
                    return Decision::Block {
                        reason: format!("resource '{uri}' not in allowlist"),
                        rl: None,
                    };
                }
            }
            "prompts/get" => {
                let name = ctx.tool_name.as_deref().unwrap_or("");
                if policy.denied_prompts.iter().any(|t| tool_matches(t, name)) {
                    return Decision::Block {
                        reason: format!("prompt '{name}' explicitly denied"),
                        rl: None,
                    };
                }
                if let Some(allowed) = &policy.allowed_prompts
                    && !allowed.iter().any(|t| tool_matches(t, name))
                {
                    return Decision::Block {
                        reason: format!("prompt '{name}' not in allowlist"),
                        rl: None,
                    };
                }
            }
            _ => {}
        }

        Decision::Allow { rl: None }
    }
}

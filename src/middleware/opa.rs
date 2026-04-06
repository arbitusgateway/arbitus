use super::{Decision, McpContext, Middleware};
use crate::live_config::LiveConfig;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;

/// Middleware that evaluates every `tools/call` against an embedded Rego policy.
///
/// When `rules.opa` is configured in `gateway.yml`, the policy file is loaded at
/// startup and on every hot-reload. Each request receives a JSON input object:
///
/// ```json
/// {
///   "agent_id": "cursor",
///   "method": "tools/call",
///   "tool_name": "read_file",
///   "arguments": { ... },
///   "client_ip": "1.2.3.4"
/// }
/// ```
///
/// The middleware evaluates the configured entrypoint (default: `data.mcp.allow`).
/// A `true` result allows the request; `false` or an evaluation error blocks it.
pub struct OpaMiddleware {
    config: watch::Receiver<Arc<LiveConfig>>,
}

impl OpaMiddleware {
    pub fn new(config: watch::Receiver<Arc<LiveConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Middleware for OpaMiddleware {
    fn name(&self) -> &'static str {
        "opa"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if !matches!(
            ctx.method.as_str(),
            "tools/call" | "resources/read" | "resources/subscribe" | "prompts/get"
        ) {
            return Decision::Allow { rl: None };
        }

        let policy = {
            let cfg = self.config.borrow();
            cfg.opa_policy.clone()
        };

        let Some(policy) = policy else {
            return Decision::Allow { rl: None };
        };

        let input = serde_json::json!({
            "agent_id": ctx.agent_id,
            "method": ctx.method,
            "tool_name": ctx.tool_name,
            "arguments": ctx.arguments,
            "client_ip": ctx.client_ip,
        });

        match evaluate_policy(&policy.content, &policy.entrypoint, &input) {
            Ok(true) => Decision::Allow { rl: None },
            Ok(false) => Decision::Block {
                reason: "denied by policy".to_string(),
                rl: None,
            },
            Err(e) => {
                tracing::warn!(
                    agent = %ctx.agent_id,
                    tool = ?ctx.tool_name,
                    error = %e,
                    "OPA policy evaluation failed — denying by default"
                );
                Decision::Block {
                    reason: "policy evaluation error".to_string(),
                    rl: None,
                }
            }
        }
    }
}

fn evaluate_policy(
    content: &str,
    entrypoint: &str,
    input: &serde_json::Value,
) -> anyhow::Result<bool> {
    let input_json = serde_json::to_string(input)?;
    let input_val = regorus::Value::from_json_str(&input_json)?;

    let mut engine = regorus::Engine::new();
    engine.add_policy("policy.rego".to_string(), content.to_string())?;
    engine.set_input(input_val);

    engine.eval_bool_query(entrypoint.to_string(), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::FilterMode,
        live_config::{LiveConfig, OpaPolicy},
    };
    use std::collections::HashMap;

    const ALLOW_ALL_POLICY: &str = r#"
package mcp
default allow := true
"#;

    const DENY_ALL_POLICY: &str = r#"
package mcp
default allow := false
"#;

    const ALLOW_TRUSTED_POLICY: &str = r#"
package mcp
import future.keywords.if
default allow := false
allow if input.agent_id == "trusted"
"#;

    const ALLOW_BY_TOOL_POLICY: &str = r#"
package mcp
import future.keywords.if
default allow := false
allow if input.tool_name == "safe_tool"
"#;

    fn make_mw(policy_content: Option<&str>) -> OpaMiddleware {
        let opa = policy_content.map(|content| {
            Arc::new(OpaPolicy {
                entrypoint: "data.mcp.allow".to_string(),
                content: content.to_string(),
            })
        });
        let live = Arc::new(
            LiveConfig::new(
                HashMap::new(),
                vec![],
                vec![],
                None,
                FilterMode::Block,
                None,
            )
            .with_opa_policy(opa),
        );
        let (_, rx) = watch::channel(live);
        OpaMiddleware::new(rx)
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
    async fn no_policy_configured_allows_all() {
        let mw = make_mw(None);
        assert!(matches!(
            mw.check(&ctx("any", "any_tool")).await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn non_tools_call_bypasses_opa() {
        let mw = make_mw(Some(DENY_ALL_POLICY));
        let ctx = McpContext {
            agent_id: "agent".to_string(),
            method: "initialize".to_string(),
            tool_name: None,
            arguments: None,
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn allow_all_policy_allows() {
        let mw = make_mw(Some(ALLOW_ALL_POLICY));
        assert!(matches!(
            mw.check(&ctx("any", "any_tool")).await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn deny_all_policy_blocks() {
        let mw = make_mw(Some(DENY_ALL_POLICY));
        assert!(matches!(
            mw.check(&ctx("any", "any_tool")).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn policy_allows_trusted_agent() {
        let mw = make_mw(Some(ALLOW_TRUSTED_POLICY));
        assert!(matches!(
            mw.check(&ctx("trusted", "any_tool")).await,
            Decision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn policy_blocks_untrusted_agent() {
        let mw = make_mw(Some(ALLOW_TRUSTED_POLICY));
        assert!(matches!(
            mw.check(&ctx("untrusted", "any_tool")).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn policy_gates_by_tool_name() {
        let mw = make_mw(Some(ALLOW_BY_TOOL_POLICY));
        assert!(matches!(
            mw.check(&ctx("agent", "safe_tool")).await,
            Decision::Allow { .. }
        ));
        assert!(matches!(
            mw.check(&ctx("agent", "dangerous_tool")).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn invalid_policy_blocks_with_error_reason() {
        let mw = make_mw(Some("this is not valid rego !!!"));
        if let Decision::Block { reason, .. } = mw.check(&ctx("agent", "tool")).await {
            assert!(
                reason.contains("policy") || reason.contains("error"),
                "unexpected block reason: {reason}"
            );
        } else {
            panic!("expected Block for invalid policy");
        }
    }

    #[tokio::test]
    async fn block_reason_does_not_leak_policy_details() {
        let mw = make_mw(Some(DENY_ALL_POLICY));
        if let Decision::Block { reason, .. } = mw.check(&ctx("agent", "tool")).await {
            assert!(
                !reason.contains("mcp") && !reason.contains("package"),
                "reason leaked policy internals: {reason}"
            );
        } else {
            panic!("expected Block");
        }
    }
}

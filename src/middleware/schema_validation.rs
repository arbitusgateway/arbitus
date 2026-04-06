use super::{Decision, McpContext, Middleware};
use crate::schema_cache::SchemaCache;
use async_trait::async_trait;
use jsonschema::JSONSchema;

/// Validates `tools/call` arguments against the `inputSchema` cached from `tools/list`.
///
/// Fixes benchmark property P2 (Parameter Constraint Enforcement).
/// If no schema is cached for the tool (e.g. `tools/list` hasn't been called yet,
/// or the server doesn't advertise a schema), the request is allowed through.
pub struct SchemaValidationMiddleware {
    cache: SchemaCache,
}

impl SchemaValidationMiddleware {
    pub fn new(cache: SchemaCache) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl Middleware for SchemaValidationMiddleware {
    fn name(&self) -> &'static str {
        "schema_validation"
    }

    async fn check(&self, ctx: &McpContext) -> Decision {
        if ctx.method != "tools/call" {
            return Decision::Allow { rl: None };
        }
        let Some(tool_name) = &ctx.tool_name else {
            return Decision::Allow { rl: None };
        };
        let Some(schema) = self.cache.get(&ctx.agent_id, tool_name) else {
            // No schema cached yet — allow and let the upstream validate
            return Decision::Allow { rl: None };
        };

        let compiled = match JSONSchema::compile(&schema) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(tool = tool_name.as_str(), error = %e, "invalid tool schema, skipping validation");
                return Decision::Allow { rl: None };
            }
        };

        let args = ctx.arguments.as_ref().unwrap_or(&serde_json::Value::Null);

        match compiled.validate(args) {
            Ok(_) => Decision::Allow { rl: None },
            Err(errors) => {
                let msgs: Vec<String> = errors.take(3).map(|e| e.to_string()).collect();
                Decision::Block {
                    reason: format!("argument schema violation: {}", msgs.join("; ")),
                    rl: None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_cache::SchemaCache;
    use serde_json::json;

    fn ctx(tool: &str, args: serde_json::Value) -> McpContext {
        McpContext {
            agent_id: "agent".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some(tool.to_string()),
            arguments: Some(args),
            client_ip: None,
        }
    }

    fn cache_with(agent: &str, tool: &str, schema: serde_json::Value) -> SchemaCache {
        let cache = SchemaCache::new();
        let resp = json!({
            "result": {
                "tools": [{"name": tool, "inputSchema": schema}]
            }
        });
        cache.populate(agent, &resp);
        cache
    }

    #[tokio::test]
    async fn no_schema_cached_allows() {
        let mw = SchemaValidationMiddleware::new(SchemaCache::new());
        let result = mw.check(&ctx("search", json!({"q": 42}))).await;
        assert!(matches!(result, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn valid_args_allowed() {
        let schema = json!({
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "search", schema));
        let result = mw.check(&ctx("search", json!({"q": "hello"}))).await;
        assert!(matches!(result, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn wrong_type_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "search", schema));
        let result = mw.check(&ctx("search", json!({"q": 42}))).await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn missing_required_field_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "search", schema));
        let result = mw.check(&ctx("search", json!({}))).await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn non_tools_call_skipped() {
        let schema = json!({"type": "object"});
        let cache = cache_with("agent", "search", schema);
        let mw = SchemaValidationMiddleware::new(cache);
        let ctx = McpContext {
            agent_id: "agent".to_string(),
            method: "initialize".to_string(),
            tool_name: None,
            arguments: Some(json!({"bad": 123})),
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn block_reason_mentions_violation() {
        let schema = json!({
            "type": "object",
            "properties": {"limit": {"type": "integer", "maximum": 100}}
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "list", schema));
        if let Decision::Block { reason, .. } = mw.check(&ctx("list", json!({"limit": 999}))).await
        {
            assert!(reason.contains("schema violation"));
        } else {
            panic!("expected Block");
        }
    }

    // ── additionalProperties ──────────────────────────────────────────────────

    #[tokio::test]
    async fn additional_properties_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": false
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "read_file", schema));
        // extra field "__proto__" should be rejected
        let result = mw
            .check(&ctx(
                "read_file",
                json!({"path": "/tmp/f", "__proto__": "injected"}),
            ))
            .await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn additional_properties_allowed_when_schema_permits() {
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string"}}
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "read_file", schema));
        let result = mw
            .check(&ctx("read_file", json!({"path": "/tmp/f", "extra": "ok"})))
            .await;
        assert!(matches!(result, Decision::Allow { .. }));
    }

    // ── enum constraint ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn enum_violation_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {
                "mode": {"type": "string", "enum": ["read", "write"]}
            },
            "required": ["mode"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "open", schema));
        let result = mw.check(&ctx("open", json!({"mode": "execute"}))).await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn enum_valid_value_allowed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "mode": {"type": "string", "enum": ["read", "write"]}
            },
            "required": ["mode"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "open", schema));
        let result = mw.check(&ctx("open", json!({"mode": "read"}))).await;
        assert!(matches!(result, Decision::Allow { .. }));
    }

    // ── pattern constraint ────────────────────────────────────────────────────

    #[tokio::test]
    async fn pattern_constraint_violation_blocked() {
        // Only allow safe filenames — no path traversal components
        let schema = json!({
            "type": "object",
            "properties": {
                "filename": {"type": "string", "pattern": "^[a-zA-Z0-9_.-]+$"}
            },
            "required": ["filename"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "read_file", schema));
        let result = mw
            .check(&ctx("read_file", json!({"filename": "../../etc/passwd"})))
            .await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn pattern_constraint_valid_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {
                "filename": {"type": "string", "pattern": "^[a-zA-Z0-9_.-]+$"}
            },
            "required": ["filename"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "read_file", schema));
        let result = mw
            .check(&ctx("read_file", json!({"filename": "report.txt"})))
            .await;
        assert!(matches!(result, Decision::Allow { .. }));
    }

    // ── minimum / maximum ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn minimum_violation_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {"count": {"type": "integer", "minimum": 1}}
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "list", schema));
        let result = mw.check(&ctx("list", json!({"count": 0}))).await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    // ── nested object ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn nested_property_violation_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {
                "options": {
                    "type": "object",
                    "properties": {"timeout": {"type": "integer"}},
                    "required": ["timeout"]
                }
            },
            "required": ["options"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "run", schema));
        // timeout should be integer, not a shell injection string
        let result = mw
            .check(&ctx(
                "run",
                json!({"options": {"timeout": "999; rm -rf /"}}),
            ))
            .await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    // ── array items ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn array_item_type_violation_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "integer"}}
            },
            "required": ["ids"]
        });
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "batch_get", schema));
        let result = mw
            .check(&ctx(
                "batch_get",
                json!({"ids": [1, "drop table users", 3]}),
            ))
            .await;
        assert!(matches!(result, Decision::Block { .. }));
    }

    // ── null / missing args ───────────────────────────────────────────────────

    #[tokio::test]
    async fn null_args_with_required_fields_blocked() {
        let schema = json!({
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
        });
        let cache = cache_with("agent", "read_file", schema);
        let mw = SchemaValidationMiddleware::new(cache);
        let ctx = McpContext {
            agent_id: "agent".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("read_file".to_string()),
            arguments: None, // no arguments provided
            client_ip: None,
        };
        // Null fails required field check
        assert!(matches!(mw.check(&ctx).await, Decision::Block { .. }));
    }

    // ── agent isolation ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn schema_is_agent_scoped() {
        // Cache schema only for agent1
        let schema = json!({
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"]
        });
        let cache = cache_with("agent1", "search", schema);
        let mw = SchemaValidationMiddleware::new(cache);

        // agent1 with wrong type → blocked
        let ctx1 = McpContext {
            agent_id: "agent1".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("search".to_string()),
            arguments: Some(json!({"q": 123})),
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx1).await, Decision::Block { .. }));

        // agent2 has no cached schema → allowed through
        let ctx2 = McpContext {
            agent_id: "agent2".to_string(),
            method: "tools/call".to_string(),
            tool_name: Some("search".to_string()),
            arguments: Some(json!({"q": 123})),
            client_ip: None,
        };
        assert!(matches!(mw.check(&ctx2).await, Decision::Allow { .. }));
    }

    #[tokio::test]
    async fn different_tool_no_schema_allows() {
        // Schema cached for "search" — a call to "delete" (no schema) should pass through
        let schema = json!({"type": "object", "properties": {"q": {"type": "string"}}});
        let mw = SchemaValidationMiddleware::new(cache_with("agent", "search", schema));
        let result = mw.check(&ctx("delete", json!({"id": "anything"}))).await;
        assert!(matches!(result, Decision::Allow { .. }));
    }

    // ── invalid schema robustness ─────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_schema_gracefully_allows() {
        // `{"type": null}` fails JSONSchema::compile — middleware should warn and allow
        let cache = SchemaCache::new();
        let resp = json!({
            "result": {
                "tools": [{"name": "broken", "inputSchema": {"type": null}}]
            }
        });
        cache.populate("agent", &resp);
        let mw = SchemaValidationMiddleware::new(cache);
        let result = mw.check(&ctx("broken", json!({"any": "args"}))).await;
        assert!(matches!(result, Decision::Allow { .. }));
    }
}

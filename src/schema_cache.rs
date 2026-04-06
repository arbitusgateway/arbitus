/// Per-agent tool schema cache with LRU eviction.
///
/// Populated when a `tools/list` response passes through the gateway.
/// Read by `SchemaValidationMiddleware` to validate `tools/call` arguments
/// against the `inputSchema` advertised by the upstream server.
///
/// Bounded to [`SCHEMA_CACHE_CAPACITY`] entries to prevent unbounded memory
/// growth in deployments with many agents or frequently-changing tool sets.
use lru::LruCache;
use serde_json::Value;
use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

/// Maximum number of `(agent_id, tool_name)` entries held in memory.
/// LRU eviction removes the least-recently-used entry when this is exceeded.
const SCHEMA_CACHE_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct SchemaCache(Arc<Mutex<LruCache<(String, String), Value>>>);

impl Default for SchemaCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaCache {
    pub fn new() -> Self {
        let cap = NonZeroUsize::new(SCHEMA_CACHE_CAPACITY).expect("capacity is non-zero");
        Self(Arc::new(Mutex::new(LruCache::new(cap))))
    }

    /// Populate the cache from a `tools/list` response (already filtered by agent policy).
    /// Only tools that include an `inputSchema` field are cached.
    pub fn populate(&self, agent_id: &str, response: &Value) {
        let Some(tools) = response.pointer("/result/tools").and_then(|t| t.as_array()) else {
            return;
        };
        let mut map = self.0.lock().expect("schema cache lock poisoned");
        for tool in tools {
            let Some(name) = tool["name"].as_str() else {
                continue;
            };
            if let Some(schema) = tool.get("inputSchema") {
                map.put((agent_id.to_string(), name.to_string()), schema.clone());
            }
        }
    }

    /// Look up the cached input schema for a tool. Returns `None` if not yet cached.
    pub fn get(&self, agent_id: &str, tool_name: &str) -> Option<Value> {
        self.0
            .lock()
            .expect("schema cache lock poisoned")
            .get(&(agent_id.to_string(), tool_name.to_string()))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tools_list(tools: &[(&str, Option<Value>)]) -> Value {
        let arr: Vec<Value> = tools
            .iter()
            .map(|(name, schema)| {
                let mut t = json!({"name": name});
                if let Some(s) = schema {
                    t["inputSchema"] = s.clone();
                }
                t
            })
            .collect();
        json!({"result": {"tools": arr}})
    }

    #[test]
    fn populates_schema_from_tools_list() {
        let cache = SchemaCache::new();
        let schema = json!({"type": "object", "properties": {"q": {"type": "string"}}});
        let resp = tools_list(&[("search", Some(schema.clone())), ("noop", None)]);
        cache.populate("agent1", &resp);

        assert_eq!(cache.get("agent1", "search"), Some(schema));
        assert_eq!(cache.get("agent1", "noop"), None);
    }

    #[test]
    fn returns_none_for_unknown_tool() {
        let cache = SchemaCache::new();
        assert!(cache.get("agent1", "nonexistent").is_none());
    }

    #[test]
    fn schemas_are_agent_scoped() {
        let cache = SchemaCache::new();
        let schema = json!({"type": "object"});
        let resp = tools_list(&[("tool", Some(schema.clone()))]);
        cache.populate("agent1", &resp);

        assert!(cache.get("agent1", "tool").is_some());
        assert!(cache.get("agent2", "tool").is_none());
    }

    #[test]
    fn populate_overwrites_stale_schema() {
        let cache = SchemaCache::new();
        let s1 = json!({"type": "string"});
        let s2 = json!({"type": "object"});
        cache.populate("a", &tools_list(&[("t", Some(s1))]));
        cache.populate("a", &tools_list(&[("t", Some(s2.clone()))]));
        assert_eq!(cache.get("a", "t"), Some(s2));
    }

    #[test]
    fn populate_multiple_tools_in_one_response() {
        let cache = SchemaCache::new();
        let s1 = json!({"type": "object", "properties": {"q": {"type": "string"}}});
        let s2 = json!({"type": "object", "properties": {"id": {"type": "integer"}}});
        let resp = tools_list(&[("search", Some(s1.clone())), ("get", Some(s2.clone()))]);
        cache.populate("agent", &resp);
        assert_eq!(cache.get("agent", "search"), Some(s1));
        assert_eq!(cache.get("agent", "get"), Some(s2));
    }

    #[test]
    fn populate_skips_tool_without_name() {
        let cache = SchemaCache::new();
        let resp = json!({
            "result": {
                "tools": [
                    {"inputSchema": {"type": "object"}},
                    {"name": "valid", "inputSchema": {"type": "string"}}
                ]
            }
        });
        cache.populate("agent", &resp);
        assert!(cache.get("agent", "valid").is_some());
    }

    #[test]
    fn populate_handles_missing_result_key() {
        let cache = SchemaCache::new();
        cache.populate("agent", &json!({}));
        cache.populate("agent", &json!({"result": {}}));
        cache.populate("agent", &json!({"result": {"tools": null}}));
        assert!(cache.get("agent", "anything").is_none());
    }

    #[test]
    fn populate_handles_non_array_tools() {
        let cache = SchemaCache::new();
        cache.populate("agent", &json!({"result": {"tools": "not-an-array"}}));
        assert!(cache.get("agent", "anything").is_none());
    }

    #[test]
    fn lru_evicts_oldest_entry_when_capacity_exceeded() {
        // Build a cache with capacity 2 to exercise eviction without inserting 1024 entries.
        let cap = NonZeroUsize::new(2).unwrap();
        let cache = SchemaCache(Arc::new(Mutex::new(LruCache::new(cap))));

        let schema = json!({"type": "object"});
        cache.populate("a", &tools_list(&[("t1", Some(schema.clone()))]));
        cache.populate("a", &tools_list(&[("t2", Some(schema.clone()))]));
        // Access t1 so it becomes the most-recently-used entry
        assert!(cache.get("a", "t1").is_some());
        // Inserting t3 should evict t2 (least-recently-used)
        cache.populate("a", &tools_list(&[("t3", Some(schema.clone()))]));

        assert!(
            cache.get("a", "t1").is_some(),
            "t1 was recently used — must survive"
        );
        assert!(
            cache.get("a", "t3").is_some(),
            "t3 was just inserted — must be present"
        );
        assert!(
            cache.get("a", "t2").is_none(),
            "t2 was least-recently-used — must be evicted"
        );
    }
}

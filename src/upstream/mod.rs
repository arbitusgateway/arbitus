pub mod http;

use async_trait::async_trait;
use serde_json::Value;

/// Trait for the MCP upstream — any server that receives JSON-RPC.
/// `None` = no response body (202 for notifications).
#[async_trait]
pub trait McpUpstream: Send + Sync {
    async fn forward(&self, msg: &Value) -> Option<Value>;
    /// Base URL of the upstream (e.g. `http://localhost:3000/mcp`).
    /// Used by the SSE proxy to construct the GET endpoint.
    fn base_url(&self) -> &str {
        ""
    }
    /// Returns `true` if the upstream is believed to be reachable.
    /// For HTTP upstreams this reflects the circuit breaker state.
    async fn is_healthy(&self) -> bool {
        true
    }
}

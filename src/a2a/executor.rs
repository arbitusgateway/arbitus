//! A2A proxy executor — forwards A2A messages to an upstream agent.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ra2a::{
    error::{A2AError, Result},
    server::{AgentExecutor, EventQueue, RequestContext},
    types::{SendMessageRequest, SendMessageResponse, StreamResponse, Task, TaskState, TaskStatus},
};
use reqwest::Client;
use serde_json::json;

/// Proxies incoming A2A `message/send` requests to an upstream A2A agent.
///
/// The `A2aPolicyInterceptor` runs before this executor and enforces rate limits,
/// API key authentication, and payload filtering. This executor only handles the
/// mechanical proxy step: forward the message to the upstream and write the
/// response to the event queue.
pub struct A2aProxyExecutor {
    upstream_url: String,
    client: Arc<Client>,
}

impl A2aProxyExecutor {
    /// Creates a new proxy executor pointing at the given upstream A2A JSON-RPC endpoint.
    ///
    /// `upstream_url` should be the base URL without trailing slash
    /// (e.g., `"http://localhost:4001"`). The executor will POST to this URL.
    pub fn new(upstream_url: impl Into<String>) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build A2A proxy client: {e}"))?;

        Ok(Self {
            upstream_url: upstream_url.into(),
            client: Arc::new(client),
        })
    }
}

impl AgentExecutor for A2aProxyExecutor {
    fn execute<'a>(
        &'a self,
        ctx: &'a RequestContext,
        queue: &'a EventQueue,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let message = ctx
                .message
                .clone()
                .ok_or_else(|| A2AError::InvalidParams("no message in request context".into()))?;

            let send_req = SendMessageRequest::new(message);

            // Build the JSON-RPC 2.0 request envelope.
            let rpc_body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": send_req,
            });

            let resp = self
                .client
                .post(&self.upstream_url)
                .json(&rpc_body)
                .send()
                .await
                .map_err(|e| A2AError::Other(format!("upstream A2A request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                return Err(A2AError::Other(format!(
                    "upstream A2A agent returned HTTP {status}"
                )));
            }

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| A2AError::Other(format!("failed to parse upstream response: {e}")))?;

            // Propagate JSON-RPC errors from the upstream agent.
            if let Some(error) = body.get("error") {
                let code = error["code"].as_i64().unwrap_or(-32603) as i32;
                let message_str = error["message"]
                    .as_str()
                    .unwrap_or("upstream agent error")
                    .to_string();
                return Err(A2AError::JsonRpc(ra2a::error::JsonRpcError {
                    code,
                    message: message_str,
                    data: None,
                }));
            }

            let result = body
                .get("result")
                .ok_or_else(|| A2AError::Other("upstream response missing 'result'".into()))?;

            let upstream_response: SendMessageResponse = serde_json::from_value(result.clone())
                .map_err(|e| {
                    A2AError::Other(format!("failed to parse upstream SendMessageResponse: {e}"))
                })?;

            let event = match upstream_response {
                SendMessageResponse::Message(m) => StreamResponse::Message(m),
                SendMessageResponse::Task(t) => StreamResponse::Task(t),
            };

            queue.send(event)?;

            Ok(())
        })
    }

    fn cancel<'a>(
        &'a self,
        ctx: &'a RequestContext,
        queue: &'a EventQueue,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut task = Task::new(&ctx.task_id, &ctx.context_id);
            task.status = TaskStatus::new(TaskState::Canceled);
            queue.send(StreamResponse::Task(task))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_constructs_without_error() {
        let result = A2aProxyExecutor::new("http://localhost:4001");
        assert!(result.is_ok());
    }
}

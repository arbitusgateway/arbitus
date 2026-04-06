pub mod http;
pub mod stdio;

use crate::gateway::McpGateway;
use async_trait::async_trait;
use std::sync::Arc;

/// Trait para o transport — HTTP hoje, stdio depois.
/// O gateway não sabe nada sobre como as mensagens chegam.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()>;
}

use super::Transport;
use crate::{config::BinaryVerifyConfig, gateway::McpGateway, verify};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::Mutex,
};

/// Wait for SIGTERM (Unix) or CTRL-C (all platforms).
/// Used by the stdio transport to break its read loop cleanly.
async fn shutdown_signal_stdio() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}

pub struct StdioTransport {
    server_cmd: Vec<String>,
    verify: Option<BinaryVerifyConfig>,
}

impl StdioTransport {
    pub fn new(server_cmd: Vec<String>, verify: Option<BinaryVerifyConfig>) -> Self {
        Self { server_cmd, verify }
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()> {
        let (cmd, args) = self
            .server_cmd
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty server_cmd"))?;

        // Supply-chain check: verify binary before spawning it.
        if let Some(cfg) = &self.verify {
            verify::verify_binary(cmd, cfg).await?;
        }

        let mut child = Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;

        // Wrapped in Arc<Mutex> to allow explicit close after the main loop
        let child_stdin = Arc::new(Mutex::new(
            child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("child stdin unavailable"))?,
        ));
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("child stdout unavailable"))?;

        let our_stdout = Arc::new(Mutex::new(tokio::io::stdout()));
        let agent_id: Arc<Mutex<String>> = Arc::new(Mutex::new("unknown".to_string()));

        // Task A: child stdout → our stdout
        // Intercepts tools/list responses to filter tools per agent.
        let stdout_a = our_stdout.clone();
        let agent_id_a = agent_id.clone();
        let gateway_a = gateway.clone();
        let passthrough = tokio::spawn(async move {
            let mut lines = BufReader::new(child_stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let output = filter_if_tools_list(&gateway_a, &agent_id_a, &line).await;
                write_line(&stdout_a, &output).await;
            }
        });

        // Task B (main loop): our stdin → gateway intercept → child stdin or our stdout.
        // Exits cleanly on EOF *or* on SIGTERM/CTRL-C so the audit log is flushed before exit.
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut shutdown = std::pin::pin!(shutdown_signal_stdio());

        loop {
            let line = tokio::select! {
                result = lines.next_line() => {
                    match result {
                        Ok(Some(l)) => l,
                        // EOF or read error — upstream process closed stdin
                        _ => break,
                    }
                }
                _ = &mut shutdown => {
                    tracing::info!("shutdown signal received (stdio), draining child process");
                    break;
                }
            };

            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            let msg: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "invalid message ignored");
                    continue;
                }
            };

            if msg["method"].as_str() == Some("initialize")
                && let Some(name) = msg["params"]["clientInfo"]["name"].as_str()
            {
                tracing::info!(agent = name, "agent identified");
                *agent_id.lock().await = name.to_string();
            }

            let current_agent = agent_id.lock().await.clone();

            match gateway.intercept(&current_agent, &msg).await {
                Some(block_response) => {
                    let json_str = serde_json::to_string(&block_response).unwrap_or_default();
                    write_line(&our_stdout, &json_str).await;
                }
                None => {
                    let mut child_in = child_stdin.lock().await;
                    let _ = child_in.write_all(line.as_bytes()).await;
                    let _ = child_in.write_all(b"\n").await;
                    let _ = child_in.flush().await;
                }
            }
        }

        // Close child stdin — signals EOF so the child knows to finish.
        // The passthrough task will keep reading until the child closes its stdout.
        drop(child_stdin);

        // Wait for passthrough to drain all pending responses before exiting.
        let _ = passthrough.await;
        child.wait().await?;
        Ok(())
    }
}

async fn filter_if_tools_list(
    gateway: &McpGateway,
    agent_id: &Mutex<String>,
    line: &str,
) -> String {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return line.to_string();
    };

    let agent = agent_id.lock().await.clone();

    // tools/list: filter visible tools per policy
    let msg = if msg["result"]["tools"].is_array() {
        gateway.filter_tools_response(&agent, msg)
    } else {
        msg
    };

    // All responses: apply block_patterns to the upstream response body
    let msg = gateway.filter_response(msg);

    serde_json::to_string(&msg).unwrap_or_else(|_| line.to_string())
}

async fn write_line(stdout: &Arc<Mutex<tokio::io::Stdout>>, line: &str) {
    let mut out = stdout.lock().await;
    let _ = out.write_all(line.as_bytes()).await;
    let _ = out.write_all(b"\n").await;
    let _ = out.flush().await;
}

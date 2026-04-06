//! Config reload helpers shared by the file-based hot-reload loop and the
//! Kubernetes ConfigMap watcher.

use crate::{
    config::{Config, OpaConfig},
    live_config::{LiveConfig, OpaPolicy},
    metrics::GatewayMetrics,
    prompt_injection,
};
use regex::Regex;
use std::{sync::Arc, time::Instant};
use tokio::sync::watch;

fn load_opa_policy(cfg: Option<&OpaConfig>) -> Option<Arc<OpaPolicy>> {
    let cfg = cfg?;
    match std::fs::read_to_string(&cfg.policy_path) {
        Ok(content) => {
            tracing::info!(
                path = %cfg.policy_path,
                entrypoint = %cfg.entrypoint,
                "OPA policy loaded"
            );
            Some(Arc::new(OpaPolicy {
                entrypoint: cfg.entrypoint.clone(),
                content,
            }))
        }
        Err(e) => {
            tracing::warn!(
                path = %cfg.policy_path,
                error = %e,
                "failed to load OPA policy — OPA disabled"
            );
            None
        }
    }
}

/// Build a `LiveConfig` from a parsed `Config`.  Compiles block-patterns and
/// injection-patterns, loads the OPA policy if configured, and wraps everything
/// in an `Arc` ready to broadcast on the watch channel.
pub fn build_live_config(cfg: Config) -> Arc<LiveConfig> {
    let block_patterns: Vec<Regex> = cfg
        .rules
        .block_patterns
        .iter()
        .filter_map(|p| {
            Regex::new(p)
                .map_err(
                    |e| tracing::warn!(pattern = p, error = %e, "invalid regex in reloaded config"),
                )
                .ok()
        })
        .collect();

    let injection_patterns: Vec<Regex> = if cfg.rules.block_prompt_injection {
        prompt_injection::PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect()
    } else {
        vec![]
    };

    let opa = load_opa_policy(cfg.rules.opa.as_ref());

    Arc::new(
        LiveConfig::new(
            cfg.agents,
            block_patterns,
            injection_patterns,
            cfg.rules.ip_rate_limit,
            cfg.rules.filter_mode,
            cfg.default_policy,
        )
        .with_opa_policy(opa),
    )
}

/// Parse `yaml`, build a `LiveConfig`, and broadcast it on `tx`.
/// Records a reload-failure metric and rate-limits error logs on parse errors.
/// `source` is a human-readable label used in log messages (e.g. a file path or
/// `"ConfigMap <name>"`).
pub fn reload_from_yaml(
    yaml: &str,
    tx: &watch::Sender<Arc<LiveConfig>>,
    metrics: &GatewayMetrics,
    last_error: &mut Option<Instant>,
    source: &str,
) {
    match Config::from_yaml_str(yaml) {
        Ok(cfg) => {
            *last_error = None;
            let new_live = build_live_config(cfg);
            if tx.send(new_live).is_ok() {
                tracing::info!(source, "config reloaded");
            }
        }
        Err(e) => {
            metrics.record_config_reload_failure();
            let now = Instant::now();
            let should_log = last_error
                .map(|t| now.duration_since(t).as_secs() >= 5)
                .unwrap_or(true);
            if should_log {
                tracing::error!(source, error = %e, "config reload failed — keeping previous config");
                *last_error = Some(now);
            }
        }
    }
}

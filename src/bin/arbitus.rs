use arbitus::live_config::OpaPolicy;
use arbitus::{
    audit::{
        AuditLog,
        fanout::FanoutAudit,
        openlineage::OpenLineageAudit,
        sqlite::{SqliteAudit, VerifyResult, verify_chain},
        stdout::StdoutAudit,
        webhook::WebhookAudit,
    },
    config::{AuditConfig, Config, SecretsConfig, TelemetryConfig, TransportConfig},
    env_config,
    gateway::McpGateway,
    hitl::HitlStore,
    jwt::MultiJwtValidator,
    live_config::LiveConfig,
    metrics::GatewayMetrics,
    middleware::{
        Pipeline, auth::AuthMiddleware, hitl::HitlMiddleware, opa::OpaMiddleware,
        payload_filter::PayloadFilterMiddleware, rate_limit::RateLimitMiddleware,
        schema_validation::SchemaValidationMiddleware,
    },
    oauth::OAuthManager,
    prompt_injection,
    schema_cache::SchemaCache,
    secrets::{self, openbao::OpenBaoProvider},
    transport::{
        Transport,
        http::{HttpTransport, StreamableHttpTransport},
        stdio::StdioTransport,
    },
    upstream::{McpUpstream, http::HttpUpstream},
};
use clap::{Parser, Subcommand};
use regex::Regex;

use rusqlite::{Connection, types::Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "arbitus",
    about = "Security proxy for MCP servers — auth, rate limiting, payload filtering, and audit",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Config file path (shorthand for `arbitus start <config>`)
    #[arg(global = false)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the gateway (default when no subcommand is given)
    Start {
        /// Path to the gateway config file
        #[arg(default_value = "gateway.yml")]
        config: String,
    },
    /// Validate a config file without starting the gateway
    Validate {
        /// Path to the gateway config file
        #[arg(default_value = "gateway.yml")]
        config: String,
    },
    /// Verify the integrity of the SQLite audit log hash chain
    VerifyLog {
        /// Path to the SQLite audit database
        #[arg(default_value = "gateway-audit.db")]
        db: String,
    },
    /// Query the SQLite audit log
    Audit {
        /// Path to the SQLite audit database
        #[arg(default_value = "gateway-audit.db")]
        db: String,

        /// Filter by agent name
        #[arg(long)]
        agent: Option<String>,

        /// Show entries from the last duration (e.g. 30s, 5m, 2h, 7d)
        #[arg(long)]
        since: Option<String>,

        /// Filter by outcome: allowed | blocked | forwarded
        #[arg(long)]
        outcome: Option<String>,

        /// Max rows to show
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Replay tool calls from the audit log against an upstream (time-travel debugging)
    Replay {
        /// Path to the SQLite audit database
        #[arg(default_value = "gateway-audit.db")]
        db: String,

        /// Agent ID whose calls to replay
        #[arg(long)]
        agent: Option<String>,

        /// Only replay calls from the last duration (e.g. 1h, 30m, 7d)
        #[arg(long)]
        since: Option<String>,

        /// Target upstream URL to replay against (e.g. http://localhost:3000/mcp)
        #[arg(long)]
        upstream: Option<String>,

        /// Print what would be sent without actually sending
        #[arg(long)]
        dry_run: bool,

        /// Max entries to replay
        #[arg(long, default_value = "100")]
        limit: usize,
    },
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Support legacy invocation `arbitus gateway.yml` (no subcommand)
    let args: Vec<String> = std::env::args().collect();
    let has_subcommand = args
        .get(1)
        .map(|a| {
            matches!(
                a.as_str(),
                "start"
                    | "validate"
                    | "audit"
                    | "replay"
                    | "verify-log"
                    | "--help"
                    | "-h"
                    | "--version"
                    | "-V"
            )
        })
        .unwrap_or(false);

    let config_path = if !has_subcommand && args.len() > 1 && !args[1].starts_with('-') {
        // Legacy: `arbitus gateway.yml`
        args[1].clone()
    } else {
        let cli = Cli::parse();
        return match cli.command.unwrap_or(Command::Start {
            config: "gateway.yml".into(),
        }) {
            Command::Start { config } => cmd_start(config).await,
            Command::Validate { config } => cmd_validate(config),
            Command::VerifyLog { db } => cmd_verify_log(db),
            Command::Audit {
                db,
                agent,
                since,
                outcome,
                limit,
            } => cmd_audit(db, agent, since, outcome, limit),
            Command::Replay {
                db,
                agent,
                since,
                upstream,
                dry_run,
                limit,
            } => cmd_replay(db, agent, since, upstream, dry_run, limit).await,
        };
    };

    cmd_start(config_path).await
}

// ── start ──────────────────────────────────────────────────────────────────────

async fn cmd_start(config_path: String) -> anyhow::Result<()> {
    let config = load_config(&config_path).await?;

    let _otel_guard = init_tracing(config.telemetry.as_ref());

    // Metrics is created first so audit backends can report drop events.
    let metrics = Arc::new(GatewayMetrics::new()?);

    // ── Audit backends ────────────────────────────────────────────────────────
    let mut audit_backends: Vec<Arc<dyn AuditLog>> = Vec::new();
    let mut sqlite_db_path: Option<String> = None;

    for backend_cfg in &config.audits {
        if let AuditConfig::Sqlite { path, .. } = backend_cfg
            && sqlite_db_path.is_none()
        {
            sqlite_db_path = Some(path.clone());
        }
        audit_backends.push(build_audit_backend(backend_cfg, Arc::clone(&metrics))?);
    }
    if let Some(backend_cfg) = &config.audit {
        if let AuditConfig::Sqlite { path, .. } = backend_cfg
            && sqlite_db_path.is_none()
        {
            sqlite_db_path = Some(path.clone());
        }
        audit_backends.push(build_audit_backend(backend_cfg, Arc::clone(&metrics))?);
    }
    if audit_backends.is_empty() {
        audit_backends.push(Arc::new(StdoutAudit));
    }

    let audit: Arc<dyn AuditLog> = if audit_backends.len() == 1 {
        audit_backends.remove(0)
    } else {
        Arc::new(FanoutAudit::new(audit_backends))
    };

    // ── Live config ───────────────────────────────────────────────────────────
    let block_patterns: Vec<Regex> = config
        .rules
        .block_patterns
        .iter()
        .map(|p| Regex::new(p).unwrap_or_else(|_| panic!("invalid regex: {p}")))
        .collect();

    let injection_patterns: Vec<Regex> = if config.rules.block_prompt_injection {
        tracing::info!(
            "prompt injection detection enabled ({} patterns)",
            prompt_injection::PATTERNS.len()
        );
        prompt_injection::PATTERNS
            .iter()
            .map(|p| Regex::new(p).unwrap_or_else(|_| panic!("invalid injection regex: {p}")))
            .collect()
    } else {
        vec![]
    };

    let opa_policy = load_opa_policy(config.rules.opa.as_ref());
    let live = Arc::new(
        LiveConfig::new(
            config.agents,
            block_patterns,
            injection_patterns,
            config.rules.ip_rate_limit,
            config.rules.filter_mode,
            config.default_policy,
        )
        .with_opa_policy(opa_policy),
    );
    let (config_tx, config_rx) = watch::channel(live);

    // ── Hot-reload ────────────────────────────────────────────────────────────
    {
        let reload_path = config_path.clone();
        let tx = config_tx;
        let reload_metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            #[cfg(unix)]
            let mut sigusr1 = {
                use tokio::signal::unix::{SignalKind, signal};
                signal(SignalKind::user_defined1()).expect("failed to install SIGUSR1 handler")
            };

            let mut last_modified = tokio::fs::metadata(&reload_path)
                .await
                .ok()
                .and_then(|m| m.modified().ok());
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await;
            let mut last_error: Option<std::time::Instant> = None;

            loop {
                #[cfg(unix)]
                {
                    enum Trigger {
                        Timer,
                        Signal,
                    }
                    let trigger = tokio::select! {
                        _ = interval.tick() => Trigger::Timer,
                        _ = sigusr1.recv() => Trigger::Signal,
                    };
                    if matches!(trigger, Trigger::Signal) {
                        tracing::info!("SIGUSR1 received, reloading config");
                        do_reload(&reload_path, &tx, &reload_metrics, &mut last_error);
                        last_modified = tokio::fs::metadata(&reload_path)
                            .await
                            .ok()
                            .and_then(|m| m.modified().ok());
                        continue;
                    }
                }
                #[cfg(not(unix))]
                interval.tick().await;

                let modified = tokio::fs::metadata(&reload_path)
                    .await
                    .ok()
                    .and_then(|m| m.modified().ok());
                if modified.is_some() && modified != last_modified {
                    last_modified = modified;
                    do_reload(&reload_path, &tx, &reload_metrics, &mut last_error);
                }
            }
        });
    }

    // ── Pipeline ──────────────────────────────────────────────────────────────
    let schema_cache = SchemaCache::new();
    let hitl_store = HitlStore::new();
    let pipeline = Pipeline::new()
        .add(Arc::new(RateLimitMiddleware::new(config_rx.clone())))
        .add(Arc::new(AuthMiddleware::new(config_rx.clone())))
        .add(Arc::new(HitlMiddleware::new(
            Arc::clone(&hitl_store),
            config_rx.clone(),
        )))
        .add(Arc::new(SchemaValidationMiddleware::new(
            schema_cache.clone(),
        )))
        .add(Arc::new(PayloadFilterMiddleware::new(config_rx.clone())))
        .add(Arc::new(OpaMiddleware::new(config_rx.clone())));

    // ── OAuth manager (shared between transport callback + HttpUpstream) ───────
    let oauth_manager = Arc::new(OAuthManager::new());

    // ── Named upstreams ───────────────────────────────────────────────────────
    let named_upstreams: HashMap<String, Arc<dyn McpUpstream>> = config
        .upstreams
        .iter()
        .map(|(name, def)| {
            let upstream: Arc<dyn McpUpstream> = if let Some(oauth_cfg) = def.oauth() {
                let auth_url = oauth_manager.authorization_url(name, oauth_cfg);
                tracing::info!(
                    upstream = %name,
                    url = %auth_url,
                    "OAuth authorization required — visit the URL to authorize arbitus"
                );
                Arc::new(HttpUpstream::with_oauth(
                    def.url(),
                    5,
                    30,
                    Arc::clone(&oauth_manager),
                    name.clone(),
                    oauth_cfg.clone(),
                ))
            } else {
                Arc::new(HttpUpstream::new(def.url()))
            };
            (name.clone(), upstream)
        })
        .collect();

    let jwt = config.auth.map(|auth_cfg| {
        let configs = auth_cfg.into_configs().expect("invalid auth config");
        tracing::info!(providers = configs.len(), "auth configured");
        Arc::new(MultiJwtValidator::new(configs))
    });

    match config.transport {
        TransportConfig::Http {
            addr,
            upstream,
            session_ttl_secs,
            tls,
            circuit_breaker,
        } => {
            tracing::info!(upstream, addr, "HTTP mode");
            let default_upstream = Arc::new(HttpUpstream::with_circuit_breaker(
                &upstream,
                circuit_breaker.threshold,
                circuit_breaker.recovery_secs,
            ));
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                default_upstream,
                named_upstreams,
                audit.clone(),
                Arc::clone(&metrics),
                config_rx.clone(),
                schema_cache,
            ));
            HttpTransport::new(
                addr,
                session_ttl_secs,
                tls,
                metrics,
                config_rx,
                jwt,
                sqlite_db_path,
                config.admin_token,
                hitl_store,
                oauth_manager,
            )
            .serve(gateway)
            .await?;
        }
        TransportConfig::StreamableHttp {
            addr,
            upstream,
            session_ttl_secs,
            tls,
            circuit_breaker,
        } => {
            tracing::info!(upstream, addr, "streamable-HTTP mode");
            let default_upstream = Arc::new(HttpUpstream::with_circuit_breaker(
                &upstream,
                circuit_breaker.threshold,
                circuit_breaker.recovery_secs,
            ));
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                default_upstream,
                named_upstreams,
                audit.clone(),
                Arc::clone(&metrics),
                config_rx.clone(),
                schema_cache,
            ));
            StreamableHttpTransport::new(
                addr,
                session_ttl_secs,
                tls,
                metrics,
                config_rx,
                jwt,
                sqlite_db_path,
                config.admin_token,
                hitl_store,
                oauth_manager,
            )
            .serve(gateway)
            .await?;
        }
        TransportConfig::Stdio { server, verify } => {
            tracing::info!(server = %server.join(" "), "stdio mode");
            let gateway = Arc::new(McpGateway::new(
                pipeline,
                Arc::new(HttpUpstream::new("")),
                named_upstreams,
                audit.clone(),
                Arc::clone(&metrics),
                config_rx,
                schema_cache,
            ));
            StdioTransport::new(server, verify).serve(gateway).await?;
        }
    }

    tracing::info!("flushing audit backends");
    audit.flush().await;
    tracing::info!("shutdown complete");
    Ok(())
}

// ── Config loading with optional secrets injection ────────────────────────────

/// Two-stage config loader:
/// 1. Parse YAML (with env-var interpolation) into a `serde_json::Value`.
/// 2. If a `secrets:` block is present, authenticate to the provider, resolve
///    all declared paths, and inject the values before final deserialization.
/// 3. Apply env-var overrides and validate as usual.
async fn load_config(path: &str) -> anyhow::Result<Config> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not read '{}': {}", path, e))?;
    let interpolated = env_config::interpolate_env_vars(&raw)?;

    // Parse YAML into a generic JSON value so we can inject secrets.
    let mut value: serde_json::Value = serde_yaml::from_str(&interpolated)
        .map_err(|e| anyhow::anyhow!("invalid config: {}", e))?;

    // Resolve secrets if configured.
    if let Some(secrets_val) = value.get("secrets").cloned() {
        let secrets_cfg: SecretsConfig = serde_json::from_value(secrets_val)
            .map_err(|e| anyhow::anyhow!("invalid secrets config: {}", e))?;

        if secrets_cfg.provider != "openbao" {
            anyhow::bail!("unknown secrets provider: '{}'", secrets_cfg.provider);
        }

        tracing::info!(
            paths = secrets_cfg.paths.len(),
            "resolving secrets from OpenBao"
        );
        let provider = OpenBaoProvider::new(&secrets_cfg.address, &secrets_cfg.auth.method).await?;
        let resolved = secrets::resolve_all(&provider, &secrets_cfg.paths).await;

        let missing = secrets_cfg.paths.len().saturating_sub(resolved.len());
        if missing > 0 {
            anyhow::bail!(
                "{missing} secret(s) could not be resolved — check OpenBao connectivity and policies"
            );
        }

        secrets::inject_into_value(&mut value, &resolved);
        tracing::info!(injected = resolved.len(), "secrets injected into config");
    }

    let mut config: Config = serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("invalid config after secret injection: {}", e))?;
    env_config::apply_env_overrides(&mut config);
    config.validate()?;
    Ok(config)
}

// ── validate ───────────────────────────────────────────────────────────────────

fn cmd_validate(config_path: String) -> anyhow::Result<()> {
    let config =
        Config::from_file(&config_path).map_err(|e| anyhow::anyhow!("config parse error: {e}"))?;

    let mut errors: Vec<String> = Vec::new();

    // Validate block_patterns compile
    for pattern in &config.rules.block_patterns {
        if let Err(e) = Regex::new(pattern) {
            errors.push(format!("invalid block_pattern '{pattern}': {e}"));
        }
    }

    // Validate agent upstream references resolve
    for (agent, policy) in &config.agents {
        if let Some(upstream_name) = &policy.upstream
            && !config.upstreams.contains_key(upstream_name)
        {
            errors.push(format!(
                "agent '{agent}' references unknown upstream '{upstream_name}'"
            ));
        }
    }

    // Validate TLS files exist and circuit breaker threshold
    if let TransportConfig::Http {
        tls,
        circuit_breaker,
        ..
    } = &config.transport
    {
        if let Some(tls) = tls {
            if !std::path::Path::new(&tls.cert).exists() {
                errors.push(format!("TLS cert not found: {}", tls.cert));
            }
            if !std::path::Path::new(&tls.key).exists() {
                errors.push(format!("TLS key not found: {}", tls.key));
            }
        }
        if circuit_breaker.threshold == 0 {
            errors.push("circuit_breaker.threshold must be > 0".to_string());
        }
    }

    if errors.is_empty() {
        println!("✓ {config_path} is valid");
        Ok(())
    } else {
        for e in &errors {
            eprintln!("error: {e}");
        }
        anyhow::bail!("{} error(s) found in {config_path}", errors.len())
    }
}

// ── verify-log ─────────────────────────────────────────────────────────────────

fn cmd_verify_log(db_path: String) -> anyhow::Result<()> {
    let conn = Connection::open(&db_path)?;
    match verify_chain(&conn)? {
        VerifyResult::Ok { entries } => {
            println!("OK: {entries} entries verified — audit log integrity confirmed");
            Ok(())
        }
        VerifyResult::HashMismatch { row_id } => {
            anyhow::bail!("TAMPERED: row {row_id} — stored hash does not match recomputed value")
        }
        VerifyResult::ChainBroken { row_id } => {
            anyhow::bail!(
                "TAMPERED: row {row_id} — prev_hash does not match the previous entry's hash"
            )
        }
    }
}

// ── audit ──────────────────────────────────────────────────────────────────────

fn cmd_audit(
    db_path: String,
    agent: Option<String>,
    since: Option<String>,
    outcome: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    let since_secs = since.as_deref().map(parse_duration).transpose()?;

    if let Some(ref o) = outcome
        && !matches!(o.as_str(), "allowed" | "blocked" | "forwarded")
    {
        anyhow::bail!("unknown outcome '{o}'; use allowed, blocked, or forwarded");
    }

    let conn = Connection::open(&db_path)?;

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut conditions: Vec<String> = Vec::new();
    let mut binds: Vec<Value> = Vec::new();

    if let Some(ref a) = agent {
        conditions.push("agent_id = ?".to_string());
        binds.push(Value::Text(a.clone()));
    }
    if let Some(since) = since_secs {
        conditions.push("ts >= ?".to_string());
        binds.push(Value::Integer(now_ts - since as i64));
    }
    if let Some(ref o) = outcome {
        conditions.push("outcome = ?".to_string());
        binds.push(Value::Text(o.clone()));
    }

    let where_sql = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT ts, agent_id, method, tool, outcome, reason \
         FROM audit_log {where_sql} ORDER BY ts DESC LIMIT {limit}"
    );

    let refs: Vec<&dyn rusqlite::types::ToSql> = binds.iter().map(|v| v as _).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<_> = stmt
        .query_map(refs.as_slice(), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let total: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM audit_log {where_sql}"),
        refs.as_slice(),
        |r| r.get(0),
    )?;

    println!(
        "\n{:<14} {:<16} {:<18} {:<22} {:<10} REASON",
        "AGE", "AGENT", "METHOD", "TOOL", "OUTCOME"
    );
    println!("{}", "─".repeat(110));

    for (ts, agent_id, method, tool, outcome_val, reason) in &rows {
        let age = format_age(*ts, now_ts);
        let outcome_display = match outcome_val.as_str() {
            "blocked" => format!("\x1b[31m{outcome_val:<10}\x1b[0m"),
            "allowed" => format!("\x1b[32m{outcome_val:<10}\x1b[0m"),
            _ => format!("{outcome_val:<10}"),
        };
        println!(
            "{:<14} {:<16} {:<18} {:<22} {} {}",
            age,
            trunc(agent_id, 15),
            trunc(method, 17),
            trunc(tool.as_deref().unwrap_or("-"), 21),
            outcome_display,
            reason.as_deref().unwrap_or(""),
        );
    }

    println!("{}", "─".repeat(110));

    let mut filter_parts = Vec::new();
    if let Some(a) = &agent {
        filter_parts.push(format!("agent={a}"));
    }
    if let Some(s) = since_secs {
        filter_parts.push(format!("since={}", format_duration(s)));
    }
    if let Some(o) = &outcome {
        filter_parts.push(format!("outcome={o}"));
    }
    let filter_str = if filter_parts.is_empty() {
        "no filters".to_string()
    } else {
        filter_parts.join(", ")
    };

    println!(
        "Showing {} of {} total record(s) — {filter_str}",
        rows.len(),
        total
    );
    Ok(())
}

// ── replay ─────────────────────────────────────────────────────────────────────

async fn cmd_replay(
    db_path: String,
    agent: Option<String>,
    since: Option<String>,
    upstream: Option<String>,
    dry_run: bool,
    limit: usize,
) -> anyhow::Result<()> {
    let since_secs = since.as_deref().map(parse_duration).transpose()?;

    let conn = Connection::open(&db_path)?;
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut conditions = vec![
        "method = 'tools/call'".to_string(),
        "arguments IS NOT NULL".to_string(),
    ];
    let mut binds: Vec<Value> = Vec::new();

    if let Some(ref a) = agent {
        conditions.push("agent_id = ?".to_string());
        binds.push(Value::Text(a.clone()));
    }
    if let Some(since) = since_secs {
        conditions.push("ts >= ?".to_string());
        binds.push(Value::Integer(now_ts - since as i64));
    }

    let where_sql = format!("WHERE {}", conditions.join(" AND "));
    let sql = format!(
        "SELECT ts, agent_id, tool, arguments FROM audit_log {where_sql} ORDER BY ts ASC LIMIT {limit}"
    );
    let refs: Vec<&dyn rusqlite::types::ToSql> = binds.iter().map(|v| v as _).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<(i64, String, Option<String>, String)> = stmt
        .query_map(refs.as_slice(), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    if rows.is_empty() {
        println!("No tool calls found to replay.");
        return Ok(());
    }

    let client = if !dry_run {
        if upstream.is_none() {
            anyhow::bail!("--upstream <url> is required unless --dry-run is specified");
        }
        Some(
            reqwest::ClientBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        )
    } else {
        None
    };

    let upstream_url = upstream.as_deref().unwrap_or("<dry-run>");

    println!(
        "\nReplaying {} tool call(s) → {}\n",
        rows.len(),
        upstream_url
    );

    for (i, (ts, agent_id, tool, args_json)) in rows.iter().enumerate() {
        let tool_name = tool.as_deref().unwrap_or("<unknown>");
        let arguments: serde_json::Value =
            serde_json::from_str(args_json).unwrap_or(serde_json::Value::Null);

        let age = format_age(*ts, now_ts);
        println!(
            "[{:>3}] {} | agent={} | tool={} | args={}",
            i + 1,
            age,
            agent_id,
            tool_name,
            args_json
        );

        if dry_run {
            continue;
        }

        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": i + 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        });

        match client
            .as_ref()
            .unwrap()
            .post(upstream.as_ref().unwrap())
            .json(&msg)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
                if body.get("error").is_some() {
                    println!(
                        "      → ERROR {}: {}",
                        status,
                        body["error"]["message"].as_str().unwrap_or("?")
                    );
                } else {
                    println!("      → OK {}", status);
                }
            }
            Err(e) => {
                println!("      → FAILED: {e}");
            }
        }
    }

    if dry_run {
        println!("\n(dry-run: no requests sent)");
    } else {
        println!("\nDone.");
    }

    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn parse_duration(s: &str) -> anyhow::Result<u64> {
    let i = s
        .find(|c: char| c.is_alphabetic())
        .ok_or_else(|| anyhow::anyhow!("invalid duration '{s}'; expected e.g. 30s, 5m, 2h, 7d"))?;
    let (num, unit) = s.split_at(i);
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{s}'"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => anyhow::bail!("unknown unit '{other}'; use s, m, h, or d"),
    };
    Ok(n * mult)
}

fn format_age(ts: i64, now: i64) -> String {
    let diff = now - ts;
    if diff < 0 {
        "just now".to_string()
    } else if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

fn format_duration(secs: u64) -> String {
    if secs.is_multiple_of(86400) {
        format!("{}d", secs / 86400)
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        format!("{s:<max$}")
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn build_audit_backend(
    cfg: &AuditConfig,
    metrics: Arc<GatewayMetrics>,
) -> anyhow::Result<Arc<dyn AuditLog>> {
    match cfg {
        AuditConfig::Stdout => Ok(Arc::new(StdoutAudit)),
        AuditConfig::Sqlite {
            path,
            max_entries,
            max_age_days,
        } => {
            tracing::info!(path, "SQLite audit");
            Ok(Arc::new(SqliteAudit::with_rotation(
                path,
                *max_entries,
                *max_age_days,
                metrics,
            )?))
        }
        AuditConfig::Webhook {
            url,
            token,
            cloudevents,
            source,
        } => {
            tracing::info!(url, cloudevents, "webhook audit");
            Ok(Arc::new(WebhookAudit::new(
                url,
                token.clone(),
                *cloudevents,
                source.clone(),
                metrics,
            )))
        }
        AuditConfig::OpenLineage {
            url,
            token,
            namespace,
        } => {
            tracing::info!(url, namespace, "openlineage audit");
            Ok(Arc::new(OpenLineageAudit::new(
                url,
                token.clone(),
                namespace.clone(),
                metrics,
            )))
        }
    }
}

fn load_opa_policy(cfg: Option<&arbitus::config::OpaConfig>) -> Option<Arc<OpaPolicy>> {
    let cfg = cfg?;
    match std::fs::read_to_string(&cfg.policy_path) {
        Ok(content) => {
            tracing::info!(path = %cfg.policy_path, entrypoint = %cfg.entrypoint, "OPA policy loaded");
            Some(Arc::new(OpaPolicy {
                entrypoint: cfg.entrypoint.clone(),
                content,
            }))
        }
        Err(e) => {
            tracing::warn!(path = %cfg.policy_path, error = %e, "failed to load OPA policy — OPA disabled");
            None
        }
    }
}

fn do_reload(
    reload_path: &str,
    tx: &tokio::sync::watch::Sender<Arc<LiveConfig>>,
    metrics: &GatewayMetrics,
    last_error: &mut Option<std::time::Instant>,
) {
    match Config::from_file(reload_path) {
        Ok(new_cfg) => {
            *last_error = None;
            let new_patterns: Vec<Regex> = new_cfg
                .rules
                .block_patterns
                .iter()
                .filter_map(|p| {
                    Regex::new(p)
                        .map_err(|e| {
                            tracing::warn!(pattern = p, error = %e, "invalid regex in reloaded config")
                        })
                        .ok()
                })
                .collect();
            let new_injection: Vec<Regex> = if new_cfg.rules.block_prompt_injection {
                prompt_injection::PATTERNS
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect()
            } else {
                vec![]
            };
            let new_opa = load_opa_policy(new_cfg.rules.opa.as_ref());
            let new_live = Arc::new(
                LiveConfig::new(
                    new_cfg.agents,
                    new_patterns,
                    new_injection,
                    new_cfg.rules.ip_rate_limit,
                    new_cfg.rules.filter_mode,
                    new_cfg.default_policy,
                )
                .with_opa_policy(new_opa),
            );
            if tx.send(new_live).is_ok() {
                tracing::info!(path = reload_path, "config reloaded");
            }
        }
        Err(e) => {
            metrics.record_config_reload_failure();
            let now = std::time::Instant::now();
            let should_log = last_error
                .map(|t| now.duration_since(t).as_secs() >= 5)
                .unwrap_or(true);
            if should_log {
                tracing::error!(error = %e, "config reload failed — keeping previous config");
                *last_error = Some(now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_valid_config_file() -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"
agents: {{}}
rules:
  block_patterns: []
audits: []
"#
        )
        .unwrap();
        f
    }

    fn make_invalid_config_file() -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "this: is: not: valid: yaml: [[[").unwrap();
        f
    }

    fn initial_live() -> Arc<LiveConfig> {
        Arc::new(LiveConfig::new(
            {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "sentinel".to_string(),
                    arbitus::config::AgentPolicy {
                        allowed_tools: None,
                        denied_tools: vec![],
                        rate_limit: 60,
                        tool_rate_limits: std::collections::HashMap::new(),
                        upstream: None,
                        api_key: None,
                        timeout_secs: None,
                        approval_required: vec![],
                        hitl_timeout_secs: 60,
                        shadow_tools: vec![],
                        federate: false,
                        allowed_resources: None,
                        denied_resources: vec![],
                        allowed_prompts: None,
                        denied_prompts: vec![],
                        mtls_identity: None,
                    },
                );
                m
            },
            vec![],
            vec![],
            None,
            arbitus::config::FilterMode::Block,
            None,
        ))
    }

    #[test]
    fn reload_valid_config_updates_channel() {
        let file = make_valid_config_file();
        let live = initial_live();
        let (tx, rx) = tokio::sync::watch::channel(Arc::clone(&live));
        let metrics = GatewayMetrics::new().unwrap();
        let mut last_error = None;

        do_reload(
            file.path().to_str().unwrap(),
            &tx,
            &metrics,
            &mut last_error,
        );

        // Config was updated — "sentinel" agent is gone (valid config has empty agents).
        let current = rx.borrow();
        assert!(
            !current.agents.contains_key("sentinel"),
            "valid reload should replace config"
        );
        assert_eq!(
            metrics
                .render()
                .contains("arbitus_config_reload_failures_total"),
            true
        );
        // Counter should be zero (no failure occurred)
        assert!(
            !metrics
                .render()
                .contains("arbitus_config_reload_failures_total 1"),
            "no failure should be recorded on successful reload"
        );
    }

    #[test]
    fn reload_invalid_yaml_preserves_previous_config() {
        let file = make_invalid_config_file();
        let live = initial_live();
        let (tx, rx) = tokio::sync::watch::channel(Arc::clone(&live));
        let metrics = GatewayMetrics::new().unwrap();
        let mut last_error = None;

        do_reload(
            file.path().to_str().unwrap(),
            &tx,
            &metrics,
            &mut last_error,
        );

        // Config must be unchanged — "sentinel" agent still present.
        let current = rx.borrow();
        assert!(
            current.agents.contains_key("sentinel"),
            "invalid config must not replace the running config"
        );
        // Failure counter incremented.
        assert!(
            metrics
                .render()
                .contains("arbitus_config_reload_failures_total 1"),
            "failure counter must be incremented on bad reload"
        );
    }

    #[test]
    fn reload_missing_file_preserves_previous_config() {
        let live = initial_live();
        let (tx, rx) = tokio::sync::watch::channel(Arc::clone(&live));
        let metrics = GatewayMetrics::new().unwrap();
        let mut last_error = None;

        do_reload(
            "/nonexistent/path/gateway.yml",
            &tx,
            &metrics,
            &mut last_error,
        );

        let current = rx.borrow();
        assert!(
            current.agents.contains_key("sentinel"),
            "missing file must not replace the running config"
        );
        assert!(
            metrics
                .render()
                .contains("arbitus_config_reload_failures_total 1"),
            "failure counter must be incremented on missing file"
        );
    }
}

// ── OpenTelemetry ──────────────────────────────────────────────────────────────

struct OtelGuard;

impl Drop for OtelGuard {
    fn drop(&mut self) {
        opentelemetry::global::shutdown_tracer_provider();
    }
}

fn init_tracing(telemetry: Option<&TelemetryConfig>) -> Option<OtelGuard> {
    let filter = EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("LOG_FORMAT").as_deref() == Ok("json");

    let tracer = telemetry.and_then(|tel| match build_otel_tracer(tel) {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("warn: OTel init failed: {e}");
            None
        }
    });

    let has_otel = tracer.is_some();

    match (json, tracer) {
        (true, Some(t)) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .with(tracing_opentelemetry::layer().with_tracer(t))
            .init(),
        (true, None) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init(),
        (false, Some(t)) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(t))
            .init(),
        (false, None) => tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init(),
    }

    if has_otel { Some(OtelGuard) } else { None }
}

fn build_otel_tracer(tel: &TelemetryConfig) -> anyhow::Result<opentelemetry_sdk::trace::Tracer> {
    use opentelemetry::KeyValue;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{Resource, runtime::Tokio, trace::Config};

    let resource = Resource::new(vec![KeyValue::new(
        "service.name",
        tel.service_name.clone(),
    )]);

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&tel.otlp_endpoint),
        )
        .with_trace_config(Config::default().with_resource(resource))
        .install_batch(Tokio)
        .map_err(|e| anyhow::anyhow!("OTLP pipeline: {e}"))?;

    Ok(provider.tracer("arbitus"))
}

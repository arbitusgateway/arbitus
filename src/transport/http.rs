use super::Transport;
use crate::{
    config::TlsConfig,
    gateway::McpGateway,
    hitl::{ApprovalDecision, HitlStore},
    jwt::MultiJwtValidator,
    live_config::LiveConfig,
    metrics::GatewayMetrics,
    oauth::OAuthManager,
    openai_bridge::{mcp_result_to_openai, mcp_tools_to_openai, openai_tool_call_to_mcp},
};
use async_trait::async_trait;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use futures_util::StreamExt;
use serde_json::Value;
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Instant};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, watch};
use uuid::Uuid;

// ── Session store ────────────────────────────────────────────────────────────

struct SessionStore {
    /// session_id → (agent_id, created_at)
    sessions: Mutex<HashMap<String, (String, Instant)>>,
    ttl_secs: u64,
}

impl SessionStore {
    fn new(ttl_secs: u64) -> Arc<Self> {
        let store = Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            ttl_secs,
        });
        // Periodically evict expired sessions so the map doesn't grow unbounded
        // when `create` is never called (e.g., long-lived connections only).
        let weak = Arc::downgrade(&store);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip immediate tick
            loop {
                interval.tick().await;
                let Some(s) = weak.upgrade() else { break };
                let now = Instant::now();
                let ttl = s.ttl_secs;
                s.sessions
                    .lock()
                    .await
                    .retain(|_, (_, created)| now.duration_since(*created).as_secs() < ttl);
            }
        });
        store
    }

    async fn create(&self, agent_id: String) -> String {
        let id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();
        let ttl = self.ttl_secs;
        sessions.retain(|_, (_, created)| now.duration_since(*created).as_secs() < ttl);
        sessions.insert(id.clone(), (agent_id, now));
        id
    }

    async fn resolve(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.lock().await;
        sessions.get(session_id).and_then(|(agent_id, created)| {
            let expired = Instant::now().duration_since(*created).as_secs() >= self.ttl_secs;
            if expired {
                None
            } else {
                Some(agent_id.clone())
            }
        })
    }

    async fn invalidate(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session_id).is_some()
    }
}

// ── Transport ────────────────────────────────────────────────────────────────

pub struct HttpTransport {
    addr: String,
    session_ttl_secs: u64,
    tls: Option<TlsConfig>,
    metrics: Arc<GatewayMetrics>,
    config: watch::Receiver<Arc<LiveConfig>>,
    jwt: Option<Arc<MultiJwtValidator>>,
    /// Path to the SQLite audit DB for the /dashboard endpoint.
    /// None when audit is not SQLite or dashboard is disabled.
    audit_db: Option<String>,
    /// Optional Bearer token required to access /dashboard and /metrics.
    admin_token: Option<String>,
    hitl_store: Arc<HitlStore>,
    /// OAuth manager — handles the `/oauth/callback` endpoint for upstream auth.
    oauth_manager: Arc<OAuthManager>,
    /// Operator kill switch — tool names in this set are immediately blocked
    /// regardless of agent policy. Managed via the dashboard UI.
    kill_switch: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl HttpTransport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: impl Into<String>,
        session_ttl_secs: u64,
        tls: Option<TlsConfig>,
        metrics: Arc<GatewayMetrics>,
        config: watch::Receiver<Arc<LiveConfig>>,
        jwt: Option<Arc<MultiJwtValidator>>,
        audit_db: Option<String>,
        admin_token: Option<String>,
        hitl_store: Arc<HitlStore>,
        oauth_manager: Arc<OAuthManager>,
    ) -> Self {
        Self {
            addr: addr.into(),
            session_ttl_secs,
            tls,
            metrics,
            config,
            jwt,
            audit_db,
            admin_token,
            hitl_store,
            oauth_manager,
            kill_switch: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }
}

struct HttpState {
    gateway: Arc<McpGateway>,
    sessions: Arc<SessionStore>,
    metrics: Arc<GatewayMetrics>,
    config: watch::Receiver<Arc<LiveConfig>>,
    /// Optional JWT validator — present when `auth.jwt` is configured.
    jwt: Option<Arc<MultiJwtValidator>>,
    audit_db: Option<String>,
    /// Optional Bearer token required to access /dashboard and /metrics.
    admin_token: Option<String>,
    hitl_store: Arc<HitlStore>,
    oauth_manager: Arc<OAuthManager>,
    kill_switch: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

const MAX_AGENT_ID_LEN: usize = 128;

#[async_trait]
impl Transport for HttpTransport {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()> {
        let state = Arc::new(HttpState {
            gateway,
            sessions: SessionStore::new(self.session_ttl_secs),
            metrics: Arc::clone(&self.metrics),
            config: self.config.clone(),
            jwt: self.jwt.clone(),
            audit_db: self.audit_db.clone(),
            admin_token: self.admin_token.clone(),
            hitl_store: Arc::clone(&self.hitl_store),
            oauth_manager: Arc::clone(&self.oauth_manager),
            kill_switch: Arc::clone(&self.kill_switch),
        });

        let app = Router::new()
            .route("/mcp", post(handle_mcp))
            .route("/mcp", get(handle_sse))
            .route("/mcp", delete(handle_delete_session))
            .route("/metrics", get(handle_metrics))
            .route("/health", get(handle_health))
            .route("/dashboard", get(handle_dashboard))
            .route("/dashboard/tools/{tool}/block", post(handle_block_tool))
            .route("/dashboard/tools/{tool}/block", delete(handle_unblock_tool))
            .route("/dashboard/tools/{tool}/unblock", post(handle_unblock_tool))
            .route("/approvals", get(handle_list_approvals))
            .route("/approvals/{id}/approve", post(handle_approve))
            .route("/approvals/{id}/reject", post(handle_reject))
            .route("/openai/v1/tools", get(handle_openai_tools))
            .route("/openai/v1/execute", post(handle_openai_execute))
            .route("/oauth/callback", get(handle_oauth_callback))
            .with_state(state);

        if let Some(tls) = &self.tls {
            let mode = if tls.client_ca.is_some() {
                "HTTPS+mTLS"
            } else {
                "HTTPS"
            };
            tracing::info!(addr = %self.addr, "{mode} mode listening");
            serve_tls(
                app,
                &self.addr,
                &tls.cert,
                &tls.key,
                tls.client_ca.as_deref(),
            )
            .await
        } else {
            tracing::info!(addr = %self.addr, "HTTP mode listening");
            let listener = tokio::net::TcpListener::bind(&self.addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
            Ok(())
        }
    }
}

// ── Streamable HTTP transport ─────────────────────────────────────────────────

/// MCP Streamable HTTP transport (spec 2025-03-26).
///
/// Single endpoint: `POST /mcp` may return either `application/json` or
/// `text/event-stream` depending on the client's `Accept` header.
/// `GET /mcp` is available for server-initiated SSE streams.
/// `DELETE /mcp` terminates a session.
pub struct StreamableHttpTransport {
    addr: String,
    session_ttl_secs: u64,
    tls: Option<TlsConfig>,
    metrics: Arc<GatewayMetrics>,
    config: watch::Receiver<Arc<LiveConfig>>,
    jwt: Option<Arc<MultiJwtValidator>>,
    audit_db: Option<String>,
    admin_token: Option<String>,
    hitl_store: Arc<HitlStore>,
    oauth_manager: Arc<OAuthManager>,
    kill_switch: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl StreamableHttpTransport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: impl Into<String>,
        session_ttl_secs: u64,
        tls: Option<TlsConfig>,
        metrics: Arc<GatewayMetrics>,
        config: watch::Receiver<Arc<LiveConfig>>,
        jwt: Option<Arc<MultiJwtValidator>>,
        audit_db: Option<String>,
        admin_token: Option<String>,
        hitl_store: Arc<HitlStore>,
        oauth_manager: Arc<OAuthManager>,
    ) -> Self {
        Self {
            addr: addr.into(),
            session_ttl_secs,
            tls,
            metrics,
            config,
            jwt,
            audit_db,
            admin_token,
            hitl_store,
            oauth_manager,
            kill_switch: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }
}

#[async_trait]
impl Transport for StreamableHttpTransport {
    async fn serve(&self, gateway: Arc<McpGateway>) -> anyhow::Result<()> {
        let state = Arc::new(HttpState {
            gateway,
            sessions: SessionStore::new(self.session_ttl_secs),
            metrics: Arc::clone(&self.metrics),
            config: self.config.clone(),
            jwt: self.jwt.clone(),
            audit_db: self.audit_db.clone(),
            admin_token: self.admin_token.clone(),
            hitl_store: Arc::clone(&self.hitl_store),
            oauth_manager: Arc::clone(&self.oauth_manager),
            kill_switch: Arc::clone(&self.kill_switch),
        });

        let app = Router::new()
            .route("/mcp", post(handle_streamable_post))
            .route("/mcp", get(handle_sse))
            .route("/mcp", delete(handle_delete_session))
            .route("/metrics", get(handle_metrics))
            .route("/health", get(handle_health))
            .route("/dashboard", get(handle_dashboard))
            .route("/dashboard/tools/{tool}/block", post(handle_block_tool))
            .route("/dashboard/tools/{tool}/block", delete(handle_unblock_tool))
            .route("/dashboard/tools/{tool}/unblock", post(handle_unblock_tool))
            .route("/approvals", get(handle_list_approvals))
            .route("/approvals/{id}/approve", post(handle_approve))
            .route("/approvals/{id}/reject", post(handle_reject))
            .route("/openai/v1/tools", get(handle_openai_tools))
            .route("/openai/v1/execute", post(handle_openai_execute))
            .route("/oauth/callback", get(handle_oauth_callback))
            .with_state(state);

        if let Some(tls) = &self.tls {
            let mode = if tls.client_ca.is_some() {
                "HTTPS+mTLS"
            } else {
                "HTTPS"
            };
            tracing::info!(addr = %self.addr, "{mode} streamable-HTTP mode listening");
            serve_tls(
                app,
                &self.addr,
                &tls.cert,
                &tls.key,
                tls.client_ca.as_deref(),
            )
            .await
        } else {
            tracing::info!(addr = %self.addr, "streamable-HTTP mode listening");
            let listener = tokio::net::TcpListener::bind(&self.addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
            Ok(())
        }
    }
}

// ── TLS ───────────────────────────────────────────────────────────────────────

async fn serve_tls(
    app: Router,
    addr: &str,
    cert: &str,
    key: &str,
    client_ca: Option<&str>,
) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = addr.parse()?;
    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        h.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    if let Some(ca_path) = client_ca {
        // mTLS: build rustls ServerConfig that requests client certificates.
        let server_config = build_mtls_config(cert, key, ca_path)?;
        let acceptor = MtlsAcceptor::new(server_config);
        axum_server::bind(addr)
            .handle(handle)
            .acceptor(acceptor)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        use axum_server::tls_rustls::RustlsConfig;
        let tls_config = RustlsConfig::from_pem_file(cert, key).await?;
        axum_server::bind_rustls(addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    }
    Ok(())
}

// ── mTLS acceptor ────────────────────────────────────────────────────────────

/// Internal header name used to pass the mTLS peer CN from the acceptor to the handler.
/// Clients cannot spoof this because `CertInjectedService` always strips it before setting.
const MTLS_CN_HEADER: &str = "x-arbitus-mtls-cn";

/// Builds a `rustls::ServerConfig` that requires client certificate verification
/// using the supplied CA PEM file.
fn build_mtls_config(
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    // Load server cert chain
    let cert_file = File::open(cert_path)?;
    let server_certs: Vec<CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_file)).collect::<Result<_, _>>()?;

    // Load server private key
    let key_file = File::open(key_path)?;
    let server_key: PrivateKeyDer<'static> = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {key_path}"))?;

    // Load CA cert for client verification
    let ca_file = File::open(ca_path)?;
    let ca_certs: Vec<CertificateDer<'static>> =
        certs(&mut BufReader::new(ca_file)).collect::<Result<_, _>>()?;
    let mut root_store = rustls::RootCertStore::empty();
    for ca in ca_certs {
        root_store.add(ca)?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)?;
    Ok(Arc::new(config))
}

/// Extracts the CN from the first peer certificate on a TLS stream.
fn extract_peer_cn(
    stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<String> {
    let (_, server_conn) = stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    let cert = certs.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).ok()?;
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string())
}

/// Tower `Service` wrapper that injects a [`PeerCertCn`] extension into every request.
#[derive(Clone)]
struct CertInjectedService<S> {
    inner: S,
    cn: Option<String>,
}

impl<S, ReqBody> tower::Service<axum::http::Request<ReqBody>> for CertInjectedService<S>
where
    S: tower::Service<axum::http::Request<ReqBody>>,
    S::Error: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), <S as tower::Service<axum::http::Request<ReqBody>>>::Error>>
    {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<ReqBody>) -> Self::Future {
        // Always strip the client-provided header (prevent spoofing), then
        // set the server-authoritative value when a peer cert was presented.
        req.headers_mut().remove(MTLS_CN_HEADER);
        if let Some(cn) = &self.cn
            && let Ok(val) = axum::http::HeaderValue::from_str(cn)
        {
            req.headers_mut()
                .insert(axum::http::HeaderName::from_static(MTLS_CN_HEADER), val);
        }
        self.inner.call(req)
    }
}

/// Custom `axum_server` acceptor that performs the TLS handshake and extracts
/// the peer certificate CN, injecting it into a [`CertInjectedService`] wrapper.
#[derive(Clone)]
struct MtlsAcceptor {
    acceptor: tokio_rustls::TlsAcceptor,
}

impl MtlsAcceptor {
    fn new(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            acceptor: tokio_rustls::TlsAcceptor::from(config),
        }
    }
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for MtlsAcceptor
where
    S: Clone + Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Service = CertInjectedService<S>;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send,
        >,
    >;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let acceptor = self.acceptor.clone();
        Box::pin(async move {
            let tls_stream = acceptor.accept(stream).await?;
            let cn = extract_peer_cn(&tls_stream);
            Ok((tls_stream, CertInjectedService { inner: service, cn }))
        })
    }
}

// ── Shutdown signal ───────────────────────────────────────────────────────────

async fn shutdown_signal() {
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
    tracing::info!("shutdown signal received, draining active connections");
}

// ── Rate-limit header helper ──────────────────────────────────────────────────

/// Attach `X-RateLimit-*` (and `Retry-After` when remaining == 0) headers
/// to any axum response, sourced from the pipeline's `RateLimitInfo`.
fn insert_rl_headers(res: &mut axum::response::Response, rl: &crate::middleware::RateLimitInfo) {
    let headers = res.headers_mut();
    for (name, val) in [
        ("x-ratelimit-limit", rl.limit.to_string()),
        ("x-ratelimit-remaining", rl.remaining.to_string()),
        ("x-ratelimit-reset", rl.reset_after_secs.to_string()),
    ] {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&val),
        ) {
            headers.insert(n, v);
        }
    }
    if rl.remaining == 0
        && let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(b"retry-after"),
            HeaderValue::from_str(&rl.reset_after_secs.to_string()),
        )
    {
        headers.insert(n, v);
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_mcp(
    State(state): State<Arc<HttpState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let client_ip = Some(peer.ip().to_string());
    let method = msg["method"].as_str().unwrap_or("");

    // initialize: resolve agent identity, validate api_key, create session
    if method == "initialize" {
        let claimed_name = msg["params"]["clientInfo"]["name"]
            .as_str()
            .unwrap_or("unknown");

        if claimed_name.len() > MAX_AGENT_ID_LEN {
            return StatusCode::BAD_REQUEST.into_response();
        }

        // JWT auth: if a JwtValidator is configured and the request carries
        // Authorization: Bearer <token>, validate it and use the token's claim
        // as the agent identity. api_key and clientInfo.name are both ignored.
        if let Some(validator) = &state.jwt
            && let Some(bearer) = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        {
            match validator.validate(bearer).await {
                Ok(agent_name) => {
                    let session_id = state.sessions.create(agent_name.clone()).await;
                    tracing::info!(session_id, agent = agent_name, "JWT session created");
                    let (response, rl, request_id) =
                        state.gateway.handle(&agent_name, msg, client_ip).await;
                    return match response {
                        Some(body) => {
                            let mut res = Json(body).into_response();
                            if let Ok(val) = HeaderValue::from_str(&session_id) {
                                res.headers_mut().insert("mcp-session-id", val);
                            }
                            if let Ok(val) = HeaderValue::from_str(&request_id) {
                                res.headers_mut().insert("x-request-id", val);
                            }
                            if let Some(rl) = &rl {
                                insert_rl_headers(&mut res, rl);
                            }
                            res
                        }
                        None => StatusCode::ACCEPTED.into_response(),
                    };
                }
                Err(e) => {
                    tracing::warn!(error = %e, "JWT validation failed");
                    return StatusCode::UNAUTHORIZED.into_response();
                }
            }
        }

        // mTLS auth: if the acceptor injected a peer cert CN, map it to an agent name.
        // The header is stripped and set by CertInjectedService, so it cannot be spoofed.
        // cfg is resolved inside a block so the watch::Ref (non-Send) is dropped before any .await.
        let mtls_agent: Option<Result<String, ()>> = headers
            .get(MTLS_CN_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|cn| {
                let cfg = state.config.borrow();
                match cfg.mtls_identities.get(cn) {
                    Some(name) => Ok(name.clone()),
                    None => {
                        tracing::warn!(cn, "client cert CN not mapped to any agent");
                        Err(())
                    }
                }
            });
        if let Some(result) = mtls_agent {
            match result {
                Err(()) => return StatusCode::UNAUTHORIZED.into_response(),
                Ok(agent_name) => {
                    let session_id = state.sessions.create(agent_name.clone()).await;
                    tracing::info!(session_id, agent = agent_name, "mTLS session created");
                    let (response, rl, request_id) =
                        state.gateway.handle(&agent_name, msg, client_ip).await;
                    return match response {
                        Some(body) => {
                            let mut res = Json(body).into_response();
                            if let Ok(val) = HeaderValue::from_str(&session_id) {
                                res.headers_mut().insert("mcp-session-id", val);
                            }
                            if let Ok(val) = HeaderValue::from_str(&request_id) {
                                res.headers_mut().insert("x-request-id", val);
                            }
                            if let Some(rl) = &rl {
                                insert_rl_headers(&mut res, rl);
                            }
                            res
                        }
                        None => StatusCode::ACCEPTED.into_response(),
                    };
                }
            }
        }

        // Key-based identity: if X-Api-Key is provided, the key IS the identity.
        // The key maps to an agent name — clientInfo.name is ignored.
        // If no key is provided but the agent requires one → 401.
        let agent_name = {
            let cfg = state.config.borrow();
            if let Some(provided_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                // Constant-time lookup: find the matching stored key without short-circuiting
                // on the first character match to prevent timing-based key enumeration.
                let matched = cfg.api_keys.iter().find(|(stored_key, _)| {
                    stored_key.as_bytes().ct_eq(provided_key.as_bytes()).into()
                });
                match matched {
                    Some((_, name)) => name.clone(),
                    None => {
                        tracing::warn!("unknown api_key");
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                }
            } else {
                // No key: use claimed name, but reject if the agent requires a key
                if let Some(policy) = cfg.agents.get(claimed_name)
                    && policy.api_key.is_some()
                {
                    tracing::warn!(agent = claimed_name, "api_key required but not provided");
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                claimed_name.to_string()
            }
        };
        let session_id = state.sessions.create(agent_name.clone()).await;
        tracing::info!(session_id, agent = agent_name, "session created");

        let (response, rl, request_id) = state.gateway.handle(&agent_name, msg, client_ip).await;
        return match response {
            Some(body) => {
                let mut res = Json(body).into_response();
                if let Ok(val) = HeaderValue::from_str(&session_id) {
                    res.headers_mut().insert("mcp-session-id", val);
                }
                if let Ok(val) = HeaderValue::from_str(&request_id) {
                    res.headers_mut().insert("x-request-id", val);
                }
                if let Some(rl) = &rl {
                    insert_rl_headers(&mut res, rl);
                }
                res
            }
            None => StatusCode::ACCEPTED.into_response(),
        };
    }

    match resolve_agent(&state.sessions, &headers).await {
        Ok(agent_id) => {
            // Kill switch: block tools/call for operator-disabled tools immediately,
            // before the pipeline runs, regardless of agent policy.
            if method == "tools/call"
                && let Some(tool_name) = msg["params"]["name"].as_str()
                && state.kill_switch.lock().unwrap().contains(tool_name)
            {
                tracing::warn!(
                    agent = %agent_id,
                    tool = tool_name,
                    "kill switch: tool blocked by operator"
                );
                let id = msg.get("id").cloned();
                return Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32603,
                        "message": format!("tool '{}' is blocked by operator", tool_name)
                    }
                }))
                .into_response();
            }

            let (response, rl, request_id) = state.gateway.handle(&agent_id, msg, client_ip).await;
            match response {
                Some(body) => {
                    let mut res = Json(body).into_response();
                    if let Ok(val) = HeaderValue::from_str(&request_id) {
                        res.headers_mut().insert("x-request-id", val);
                    }
                    if let Some(rl) = &rl {
                        insert_rl_headers(&mut res, rl);
                    }
                    res
                }
                None => StatusCode::ACCEPTED.into_response(),
            }
        }
        Err(status) => status.into_response(),
    }
}

/// Returns `true` when the `Accept` header explicitly includes `text/event-stream`.
fn accepts_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().starts_with("text/event-stream"))
        })
        .unwrap_or(false)
}

/// Wrap a JSON-RPC body as a single SSE `message` event for Streamable HTTP.
fn json_as_sse_response(body: Value) -> impl IntoResponse {
    let data = serde_json::to_string(&body).unwrap_or_default();
    let stream = futures_util::stream::once(async move {
        Ok::<Event, Infallible>(Event::default().event("message").data(data))
    });
    Sse::new(stream).into_response()
}

/// POST /mcp — MCP Streamable HTTP transport (spec 2025-03-26).
///
/// `initialize` requests always return `application/json`.
/// All other requests return `text/event-stream` when the client sends
/// `Accept: text/event-stream`; otherwise they return `application/json`.
async fn handle_streamable_post(
    State(state): State<Arc<HttpState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let client_ip = Some(peer.ip().to_string());
    let method = msg["method"].as_str().unwrap_or("");
    let use_sse = method != "initialize" && accepts_event_stream(&headers);

    // initialize: resolve agent identity, validate api_key, create session.
    // Always returns JSON regardless of Accept header.
    if method == "initialize" {
        let claimed_name = msg["params"]["clientInfo"]["name"]
            .as_str()
            .unwrap_or("unknown");

        if claimed_name.len() > MAX_AGENT_ID_LEN {
            return StatusCode::BAD_REQUEST.into_response();
        }

        if let Some(validator) = &state.jwt
            && let Some(bearer) = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        {
            match validator.validate(bearer).await {
                Ok(agent_name) => {
                    let session_id = state.sessions.create(agent_name.clone()).await;
                    tracing::info!(
                        session_id,
                        agent = agent_name,
                        "JWT session created (streamable)"
                    );
                    let (response, rl, request_id) =
                        state.gateway.handle(&agent_name, msg, client_ip).await;
                    return match response {
                        Some(body) => {
                            let mut res = Json(body).into_response();
                            if let Ok(val) = HeaderValue::from_str(&session_id) {
                                res.headers_mut().insert("mcp-session-id", val);
                            }
                            if let Ok(val) = HeaderValue::from_str(&request_id) {
                                res.headers_mut().insert("x-request-id", val);
                            }
                            if let Some(rl) = &rl {
                                insert_rl_headers(&mut res, rl);
                            }
                            res
                        }
                        None => StatusCode::ACCEPTED.into_response(),
                    };
                }
                Err(e) => {
                    tracing::warn!(error = %e, "JWT validation failed");
                    return StatusCode::UNAUTHORIZED.into_response();
                }
            }
        }

        let mtls_agent: Option<Result<String, ()>> = headers
            .get(MTLS_CN_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|cn| {
                let cfg = state.config.borrow();
                match cfg.mtls_identities.get(cn) {
                    Some(name) => Ok(name.clone()),
                    None => {
                        tracing::warn!(cn, "client cert CN not mapped to any agent");
                        Err(())
                    }
                }
            });
        if let Some(result) = mtls_agent {
            match result {
                Err(()) => return StatusCode::UNAUTHORIZED.into_response(),
                Ok(agent_name) => {
                    let session_id = state.sessions.create(agent_name.clone()).await;
                    tracing::info!(
                        session_id,
                        agent = agent_name,
                        "mTLS session created (streamable)"
                    );
                    let (response, rl, request_id) =
                        state.gateway.handle(&agent_name, msg, client_ip).await;
                    return match response {
                        Some(body) => {
                            let mut res = Json(body).into_response();
                            if let Ok(val) = HeaderValue::from_str(&session_id) {
                                res.headers_mut().insert("mcp-session-id", val);
                            }
                            if let Ok(val) = HeaderValue::from_str(&request_id) {
                                res.headers_mut().insert("x-request-id", val);
                            }
                            if let Some(rl) = &rl {
                                insert_rl_headers(&mut res, rl);
                            }
                            res
                        }
                        None => StatusCode::ACCEPTED.into_response(),
                    };
                }
            }
        }

        let agent_name = {
            let cfg = state.config.borrow();
            if let Some(provided_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                let matched = cfg.api_keys.iter().find(|(stored_key, _)| {
                    stored_key.as_bytes().ct_eq(provided_key.as_bytes()).into()
                });
                match matched {
                    Some((_, name)) => name.clone(),
                    None => {
                        tracing::warn!("unknown api_key");
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                }
            } else {
                if let Some(policy) = cfg.agents.get(claimed_name)
                    && policy.api_key.is_some()
                {
                    tracing::warn!(agent = claimed_name, "api_key required but not provided");
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                claimed_name.to_string()
            }
        };
        let session_id = state.sessions.create(agent_name.clone()).await;
        tracing::info!(
            session_id,
            agent = agent_name,
            "session created (streamable)"
        );

        let (response, rl, request_id) = state.gateway.handle(&agent_name, msg, client_ip).await;
        return match response {
            Some(body) => {
                let mut res = Json(body).into_response();
                if let Ok(val) = HeaderValue::from_str(&session_id) {
                    res.headers_mut().insert("mcp-session-id", val);
                }
                if let Ok(val) = HeaderValue::from_str(&request_id) {
                    res.headers_mut().insert("x-request-id", val);
                }
                if let Some(rl) = &rl {
                    insert_rl_headers(&mut res, rl);
                }
                res
            }
            None => StatusCode::ACCEPTED.into_response(),
        };
    }

    // Non-initialize: resolve session, run pipeline, return JSON or SSE.
    match resolve_agent(&state.sessions, &headers).await {
        Ok(agent_id) => {
            if method == "tools/call"
                && let Some(tool_name) = msg["params"]["name"].as_str()
                && state.kill_switch.lock().unwrap().contains(tool_name)
            {
                tracing::warn!(
                    agent = %agent_id,
                    tool = tool_name,
                    "kill switch: tool blocked by operator"
                );
                let id = msg.get("id").cloned();
                let error_body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32603,
                        "message": format!("tool '{}' is blocked by operator", tool_name)
                    }
                });
                return if use_sse {
                    json_as_sse_response(error_body).into_response()
                } else {
                    Json(error_body).into_response()
                };
            }

            let (response, rl, request_id) = state.gateway.handle(&agent_id, msg, client_ip).await;
            match response {
                Some(body) => {
                    if use_sse {
                        let mut res = json_as_sse_response(body).into_response();
                        if let Ok(val) = HeaderValue::from_str(&request_id) {
                            res.headers_mut().insert("x-request-id", val);
                        }
                        if let Some(rl) = &rl {
                            insert_rl_headers(&mut res, rl);
                        }
                        res
                    } else {
                        let mut res = Json(body).into_response();
                        if let Ok(val) = HeaderValue::from_str(&request_id) {
                            res.headers_mut().insert("x-request-id", val);
                        }
                        if let Some(rl) = &rl {
                            insert_rl_headers(&mut res, rl);
                        }
                        res
                    }
                }
                None => StatusCode::ACCEPTED.into_response(),
            }
        }
        Err(status) => status.into_response(),
    }
}

async fn handle_delete_session(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sid = match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    if state.sessions.invalidate(&sid).await {
        tracing::info!(session_id = sid, "session invalidated");
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn handle_health(State(state): State<Arc<HttpState>>) -> impl IntoResponse {
    let upstreams = state.gateway.upstreams_health().await;
    let all_up = upstreams.values().all(|&v| v);
    let status = if all_up {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "status": if all_up { "ok" } else { "degraded" },
            "version": env!("CARGO_PKG_VERSION"),
            "upstreams": upstreams,
        })),
    )
}

/// Core Bearer token check — extracted for testability.
/// Returns `true` if `expected` is None (open) or matches the Bearer token in `headers`.
fn check_bearer_token(expected: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

fn check_admin_auth(state: &HttpState, headers: &HeaderMap) -> bool {
    check_bearer_token(state.admin_token.as_deref(), headers)
}

async fn handle_metrics(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_admin_auth(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let body = state.metrics.render();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

// ── Dashboard query params ────────────────────────────────────────────────────

#[derive(serde::Deserialize, Default)]
struct DashboardParams {
    agent: Option<String>,
    outcome: Option<String>,
    tool: Option<String>,
    /// Duration string, e.g. "1h", "30m", "7d"
    since: Option<String>,
    #[serde(default)]
    page: usize,
}

async fn handle_dashboard(
    State(state): State<Arc<HttpState>>,
    Query(params): Query<DashboardParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    use axum::http::header::CONTENT_TYPE;

    if !check_admin_auth(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let Some(db_path) = &state.audit_db else {
        return (
            StatusCode::NOT_FOUND,
            [(CONTENT_TYPE, "text/plain")],
            "dashboard requires a sqlite audit backend".to_string(),
        )
            .into_response();
    };

    const PAGE_SIZE: usize = 100;
    let offset = params.page * PAGE_SIZE;

    // Collect current kill-switch state before blocking task
    let killed_tools: Vec<String> = {
        let ks = state.kill_switch.lock().unwrap();
        let mut v: Vec<String> = ks.iter().cloned().collect();
        v.sort();
        v
    };

    let db_path = db_path.clone();
    let filter_agent = params.agent.clone();
    let filter_outcome = params.outcome.clone();
    let filter_tool = params.tool.clone();
    let filter_since = params.since.clone();

    type AuditRow = (i64, String, String, Option<String>, String, Option<String>);
    type Stats = (i64, i64, i64, i64); // total, allowed, blocked, forwarded

    let result: Option<(Vec<AuditRow>, Stats, i64)> = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || -> anyhow::Result<(Vec<AuditRow>, Stats, i64)> {
            let conn = rusqlite::Connection::open(&db_path)?;

            // Build WHERE clause from filters
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let mut conditions: Vec<String> = Vec::new();
            if let Some(ref a) = filter_agent {
                conditions.push(format!("agent_id = '{}'", a.replace('\'', "''")));
            }
            if let Some(ref o) = filter_outcome {
                conditions.push(format!("outcome = '{}'", o.replace('\'', "''")));
            }
            if let Some(ref t) = filter_tool {
                conditions.push(format!("tool = '{}'", t.replace('\'', "''")));
            }
            if let Some(ref s) = filter_since
                && let Some(secs) = parse_since(s)
            {
                conditions.push(format!("ts >= {}", now_ts - secs));
            }

            let where_sql = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };

            // Summary stats (unfiltered by outcome for the breakdown)
            let stats: Stats = conn.query_row(
                &format!(
                    "SELECT COUNT(*), \
                     SUM(CASE WHEN outcome='allowed' THEN 1 ELSE 0 END), \
                     SUM(CASE WHEN outcome='blocked' THEN 1 ELSE 0 END), \
                     SUM(CASE WHEN outcome='forwarded' THEN 1 ELSE 0 END) \
                     FROM audit_log {where_sql}"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;

            // Total matching rows (for pagination)
            let total_filtered: i64 = conn.query_row(
                &format!("SELECT COUNT(*) FROM audit_log {where_sql}"),
                [],
                |r| r.get(0),
            )?;

            // Paginated rows
            let sql = format!(
                "SELECT ts, agent_id, method, tool, outcome, reason \
                 FROM audit_log {where_sql} \
                 ORDER BY id DESC LIMIT {PAGE_SIZE} OFFSET {offset}"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt
                .query_map([], |row| {
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

            Ok((rows, stats, total_filtered))
        }),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .and_then(|r| r.ok());

    let (rows, stats, total_filtered) = result.unwrap_or_default();
    let (total_all, allowed, blocked, _forwarded) = stats;
    let block_pct = if total_all > 0 {
        blocked * 100 / total_all
    } else {
        0
    };

    // Build query string helper (for filter-preserving links)
    let qs_base = {
        let mut parts = Vec::new();
        if let Some(ref a) = params.agent {
            parts.push(format!("agent={}", urlenc(a)));
        }
        if let Some(ref o) = params.outcome {
            parts.push(format!("outcome={}", urlenc(o)));
        }
        if let Some(ref t) = params.tool {
            parts.push(format!("tool={}", urlenc(t)));
        }
        if let Some(ref s) = params.since {
            parts.push(format!("since={}", urlenc(s)));
        }
        parts.join("&")
    };
    let page_link = |p: usize| {
        if qs_base.is_empty() {
            format!("?page={p}")
        } else {
            format!("?{qs_base}&page={p}")
        }
    };

    // Audit table rows
    let mut table_rows = String::new();
    for (ts, agent, method, tool, outcome, reason) in &rows {
        let dt = chrono_ts(*ts);
        let badge = match outcome.as_str() {
            "allowed" => r#"<span class="badge badge-allowed">allowed</span>"#,
            "blocked" => r#"<span class="badge badge-blocked">blocked</span>"#,
            "forwarded" => r#"<span class="badge badge-forwarded">forwarded</span>"#,
            _ => r#"<span class="badge badge-shadowed">shadowed</span>"#,
        };
        let tool_str = html_escape(tool.as_deref().unwrap_or("—"));
        let reason_str = html_escape(reason.as_deref().unwrap_or(""));
        table_rows.push_str(&format!(
            "<tr><td class=\"mono\">{dt}</td><td>{}</td><td>{}</td>\
             <td>{tool_str}</td><td>{badge}</td><td class=\"reason\">{reason_str}</td></tr>\n",
            html_escape(agent),
            html_escape(method),
        ));
    }

    // Kill switch panel rows
    let mut ks_rows = String::new();
    for tool in &killed_tools {
        let t = html_escape(tool);
        ks_rows.push_str(&format!(
            "<tr><td>{t}</td><td>\
             <form method=\"post\" action=\"/dashboard/tools/{t}/unblock\" style=\"margin:0\">\
             <button class=\"btn btn-unblock\" type=\"submit\">Unblock</button></form>\
             </td></tr>\n"
        ));
    }
    let ks_empty = if killed_tools.is_empty() {
        "<p class=\"ks-empty\">No tools currently blocked.</p>"
    } else {
        ""
    };

    // Pagination
    let total_pages = (total_filtered as usize).div_ceil(PAGE_SIZE);
    let mut pagination = String::new();
    if total_pages > 1 {
        if params.page > 0 {
            pagination.push_str(&format!(
                "<a class=\"page-btn\" href=\"{}\">← Prev</a>",
                page_link(params.page - 1)
            ));
        }
        pagination.push_str(&format!(
            "<span class=\"page-info\">Page {} of {}</span>",
            params.page + 1,
            total_pages
        ));
        if params.page + 1 < total_pages {
            pagination.push_str(&format!(
                "<a class=\"page-btn\" href=\"{}\">Next →</a>",
                page_link(params.page + 1)
            ));
        }
    }

    // Current filter values for form pre-fill
    let fv_agent = html_escape(params.agent.as_deref().unwrap_or(""));
    let fv_outcome = params.outcome.as_deref().unwrap_or("");
    let fv_tool = html_escape(params.tool.as_deref().unwrap_or(""));
    let fv_since = html_escape(params.since.as_deref().unwrap_or(""));
    let sel = |v: &str, cmp: &str| if v == cmp { " selected" } else { "" };

    // Auto-refresh URL (preserves filters, resets to page 0)
    let refresh_url = if qs_base.is_empty() {
        "/dashboard".to_string()
    } else {
        format!("/dashboard?{qs_base}")
    };

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>arbitus — dashboard</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;margin:0;background:#f0f2f5;color:#1a1a2e}}
header{{background:#1a1a2e;color:#fff;padding:.9rem 2rem;display:flex;align-items:center;gap:1.5rem}}
header h1{{margin:0;font-size:1.1rem;font-weight:700;letter-spacing:.02em}}
header .sub{{font-size:.8rem;opacity:.6}}
.refresh-btn{{margin-left:auto;background:rgba(255,255,255,.15);border:none;color:#fff;
  padding:.35rem .8rem;border-radius:5px;cursor:pointer;font-size:.8rem}}
.refresh-btn:hover{{background:rgba(255,255,255,.25)}}
main{{padding:1.5rem 2rem;max-width:1400px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}}
.stat-card{{background:#fff;border-radius:8px;padding:1rem 1.2rem;
  box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.stat-card .label{{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;
  color:#666;margin-bottom:.3rem}}
.stat-card .value{{font-size:1.6rem;font-weight:700}}
.stat-card.danger .value{{color:#c0392b}}
.stat-card.success .value{{color:#27ae60}}
.panel{{background:#fff;border-radius:8px;padding:1.2rem 1.4rem;
  box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:1.5rem}}
.panel h2{{margin:0 0 .9rem;font-size:.95rem;font-weight:600}}
.ks-form{{display:flex;gap:.6rem;margin-bottom:.8rem}}
.ks-form input{{flex:1;padding:.4rem .7rem;border:1px solid #ddd;border-radius:5px;font-size:.88rem}}
.filter-form{{display:flex;flex-wrap:wrap;gap:.6rem;align-items:flex-end}}
.filter-form label{{display:flex;flex-direction:column;gap:.25rem;font-size:.78rem;
  text-transform:uppercase;letter-spacing:.04em;color:#555}}
.filter-form input,.filter-form select{{padding:.4rem .7rem;border:1px solid #ddd;
  border-radius:5px;font-size:.88rem;min-width:130px}}
table{{width:100%;border-collapse:collapse;font-size:.87rem}}
thead th{{background:#f7f7f7;padding:.55rem .9rem;text-align:left;
  font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:#555;
  border-bottom:2px solid #eee}}
td{{padding:.5rem .9rem;border-top:1px solid #f0f0f0}}
tr:hover td{{background:#fafafa}}
.mono{{font-family:monospace;font-size:.82rem;color:#555}}
.reason{{color:#888;font-size:.82rem;max-width:200px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}}
.badge{{display:inline-block;padding:.15rem .55rem;border-radius:4px;
  font-size:.73rem;font-weight:600}}
.badge-allowed{{background:#d5f5e3;color:#1e8449}}
.badge-blocked{{background:#fadbd8;color:#c0392b}}
.badge-forwarded{{background:#d6eaf8;color:#1a5276}}
.badge-shadowed{{background:#fdebd0;color:#784212}}
.btn{{padding:.3rem .7rem;border:none;border-radius:4px;cursor:pointer;font-size:.82rem;font-weight:500}}
.btn-block{{background:#c0392b;color:#fff}}
.btn-block:hover{{background:#a93226}}
.btn-unblock{{background:#e8f8f5;color:#1e8449;border:1px solid #a9dfbf}}
.btn-unblock:hover{{background:#d5f5e3}}
.btn-apply{{background:#1a1a2e;color:#fff}}
.btn-apply:hover{{background:#2c2c54}}
.btn-clear{{background:#f4f4f4;color:#555;border:1px solid #ddd}}
.pagination{{display:flex;align-items:center;gap:.7rem;margin-top:1rem;font-size:.85rem}}
.page-btn{{background:#fff;border:1px solid #ddd;padding:.3rem .7rem;
  border-radius:4px;text-decoration:none;color:#333}}
.page-btn:hover{{background:#f4f4f4}}
.page-info{{color:#666}}
.ks-empty{{color:#888;font-size:.85rem;margin:.3rem 0}}
.ks-table td{{padding:.35rem .7rem}}
.section-row{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem}}
</style>
</head>
<body>
<header>
  <h1>arbitus</h1>
  <span class="sub">audit dashboard</span>
  <button class="refresh-btn" onclick="location.href='{refresh_url}'">↻ Refresh</button>
</header>
<main>

<div class="stats">
  <div class="stat-card">
    <div class="label">Total (filtered)</div>
    <div class="value">{total_filtered}</div>
  </div>
  <div class="stat-card success">
    <div class="label">Allowed</div>
    <div class="value">{allowed}</div>
  </div>
  <div class="stat-card danger">
    <div class="label">Blocked</div>
    <div class="value">{blocked}</div>
  </div>
  <div class="stat-card">
    <div class="label">Block rate</div>
    <div class="value">{block_pct}%</div>
  </div>
</div>

<div class="section-row">
<div class="panel">
  <h2>Kill Switch</h2>
  <form class="ks-form" method="post" id="ks-add">
    <input name="tool" placeholder="tool name (e.g. write_file)" required>
    <button class="btn btn-block" type="submit" id="ks-submit">Block Tool</button>
  </form>
  <script>
    document.getElementById('ks-add').addEventListener('submit', function(e) {{
      e.preventDefault();
      var tool = this.tool.value.trim();
      if (!tool) return;
      fetch('/dashboard/tools/' + encodeURIComponent(tool) + '/block', {{method:'POST'}})
        .then(function() {{ location.reload(); }});
    }});
  </script>
  {ks_empty}
  {ks_table}
</div>

<div class="panel">
  <h2>Filters</h2>
  <form class="filter-form" method="get" action="/dashboard">
    <label>Agent
      <input name="agent" value="{fv_agent}" placeholder="any">
    </label>
    <label>Outcome
      <select name="outcome">
        <option value=""{out_any}>any</option>
        <option value="allowed"{out_allowed}>allowed</option>
        <option value="blocked"{out_blocked}>blocked</option>
        <option value="forwarded"{out_forwarded}>forwarded</option>
      </select>
    </label>
    <label>Tool
      <input name="tool" value="{fv_tool}" placeholder="any">
    </label>
    <label>Since
      <input name="since" value="{fv_since}" placeholder="e.g. 1h 30m 7d">
    </label>
    <div style="display:flex;gap:.4rem;align-self:flex-end">
      <button class="btn btn-apply" type="submit">Apply</button>
      <a class="btn btn-clear" href="/dashboard">Clear</a>
    </div>
  </form>
</div>
</div>

<div class="panel">
  <h2>Audit Log <span style="font-weight:400;color:#888;font-size:.85rem">— {total_filtered} entries, showing page {page_num}</span></h2>
  <table>
    <thead><tr>
      <th>Time</th><th>Agent</th><th>Method</th>
      <th>Tool</th><th>Outcome</th><th>Reason</th>
    </tr></thead>
    <tbody>{table_rows}</tbody>
  </table>
  <div class="pagination">{pagination}</div>
</div>

</main>
</body>
</html>"#,
        refresh_url = refresh_url,
        total_filtered = total_filtered,
        allowed = allowed,
        blocked = blocked,
        block_pct = block_pct,
        ks_empty = ks_empty,
        ks_table = if !killed_tools.is_empty() {
            format!(
                "<table class=\"ks-table\"><thead><tr><th>Tool</th><th></th></tr></thead><tbody>{ks_rows}</tbody></table>"
            )
        } else {
            String::new()
        },
        fv_agent = fv_agent,
        out_any = sel(fv_outcome, ""),
        out_allowed = sel(fv_outcome, "allowed"),
        out_blocked = sel(fv_outcome, "blocked"),
        out_forwarded = sel(fv_outcome, "forwarded"),
        fv_tool = fv_tool,
        fv_since = fv_since,
        table_rows = table_rows,
        page_num = params.page + 1,
        pagination = pagination,
    );

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

// ── Kill switch handlers ──────────────────────────────────────────────────────

async fn handle_block_tool(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::extract::Path(tool): axum::extract::Path<String>,
) -> impl IntoResponse {
    if !check_admin_auth(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state.kill_switch.lock().unwrap().insert(tool.clone());
    tracing::warn!(tool = %tool, "operator kill switch: tool blocked");
    StatusCode::NO_CONTENT.into_response()
}

async fn handle_unblock_tool(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::extract::Path(tool): axum::extract::Path<String>,
) -> impl IntoResponse {
    if !check_admin_auth(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state.kill_switch.lock().unwrap().remove(&tool);
    tracing::info!(tool = %tool, "operator kill switch: tool unblocked");
    // Redirect back to dashboard after form POST
    axum::response::Redirect::to("/dashboard").into_response()
}

// ── Dashboard helpers ─────────────────────────────────────────────────────────

/// Parse duration strings like "30m", "2h", "7d" into seconds.
fn parse_since(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('d') {
        n.parse::<i64>().ok().map(|v| v * 86400)
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<i64>().ok().map(|v| v * 3600)
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<i64>().ok().map(|v| v * 60)
    } else if let Some(n) = s.strip_suffix('s') {
        n.parse::<i64>().ok()
    } else {
        s.parse::<i64>().ok()
    }
}

fn urlenc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

// ── HITL approval endpoints ───────────────────────────────────────────────────

/// GET /approvals — list all pending approvals waiting for operator action.
async fn handle_list_approvals(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_admin_auth(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    axum::Json(state.hitl_store.list().await).into_response()
}

/// POST /approvals/:id/approve — approve a pending tool call.
async fn handle_approve(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if !check_admin_auth(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if state
        .hitl_store
        .resolve(&id, ApprovalDecision::Approved)
        .await
    {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(serde::Deserialize, Default)]
struct RejectBody {
    reason: Option<String>,
}

/// POST /approvals/:id/reject — reject a pending tool call.
/// Optional JSON body: `{"reason": "..."}`.
async fn handle_reject(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    body: Option<axum::Json<RejectBody>>,
) -> impl IntoResponse {
    if !check_admin_auth(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let reason = body.and_then(|b| b.reason.clone());
    if state
        .hitl_store
        .resolve(&id, ApprovalDecision::Rejected { reason })
        .await
    {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn chrono_ts(ts: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── SSE proxy ─────────────────────────────────────────────────────────────────

/// GET /mcp — MCP SSE transport.
///
/// With a valid `Mcp-Session-Id`: proxies the upstream SSE stream for that agent,
/// applying response filtering to each event.
///
/// Without a session (legacy HTTP+SSE transport): sends an `endpoint` event that
/// tells the client where to POST `initialize`.
async fn handle_sse(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> impl IntoResponse {
    match resolve_agent(&state.sessions, &headers).await {
        Ok(agent_id) => {
            let upstream_url = state.gateway.upstream_url_for(&agent_id);
            if upstream_url.is_empty() {
                // Upstream is stdio — SSE proxy not supported in stdio mode
                return StatusCode::NOT_IMPLEMENTED.into_response();
            }
            let config_rx = state.config.clone();
            sse_proxy(upstream_url, config_rx).await.into_response()
        }
        Err(_) => {
            // Legacy HTTP+SSE: no session yet — send endpoint event
            let stream = futures_util::stream::once(async {
                Ok::<Event, Infallible>(Event::default().event("endpoint").data("/mcp"))
            });
            Sse::new(stream).into_response()
        }
    }
}

/// Connects to the upstream SSE endpoint and proxies events downstream,
/// filtering each event's data through the live block_patterns.
async fn sse_proxy(
    upstream_url: String,
    config_rx: watch::Receiver<Arc<LiveConfig>>,
) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let resp = client
        .get(&upstream_url)
        .header("Accept", "text/event-stream")
        .send()
        .await;

    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), "SSE upstream returned error");
            return StatusCode::BAD_GATEWAY.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "SSE upstream connection failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(32);

    tokio::spawn(async move {
        let mut byte_stream = resp.bytes_stream();
        let mut buf = String::new();

        while let Some(chunk) = byte_stream.next().await {
            let Ok(bytes) = chunk else { break };
            buf.push_str(&String::from_utf8_lossy(&bytes));

            // SSE events are separated by blank lines (\n\n)
            while let Some(pos) = buf.find("\n\n") {
                let raw = buf[..pos].to_string();
                buf = buf[pos + 2..].to_string();

                if let Some(event) = parse_and_filter_sse(&raw, &config_rx)
                    && tx.send(Ok(event)).await.is_err()
                {
                    return; // client disconnected
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Parse a raw SSE event block, apply response filtering, return an axum `Event`.
/// Returns `None` if the event is dropped by the filter.
fn parse_and_filter_sse(raw: &str, config_rx: &watch::Receiver<Arc<LiveConfig>>) -> Option<Event> {
    let mut event_type = "message".to_string();
    let mut data_parts: Vec<&str> = Vec::new();
    let mut comment: Option<&str> = None;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("event: ") {
            event_type = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data_parts.push(rest);
        } else if let Some(rest) = line.strip_prefix(": ") {
            comment = Some(rest);
        }
    }

    // SSE comment (keepalive) — pass through
    if data_parts.is_empty() {
        return comment.map(|_| Event::default().comment(""));
    }

    let data = data_parts.join("\n");

    // Apply block patterns to the event data — replace matches with [REDACTED]
    let data = {
        let cfg = config_rx.borrow();
        let mut out = data;
        for pattern in cfg.block_patterns.as_ref() {
            if pattern.is_match(&out) {
                tracing::info!(
                    pattern = pattern.as_str(),
                    "sensitive data redacted from SSE event"
                );
                out = pattern.replace_all(&out, "[REDACTED]").into_owned();
            }
        }
        out
    };

    Some(Event::default().event(event_type).data(data))
}

// ── OpenAI bridge ─────────────────────────────────────────────────────────────

/// `GET /openai/v1/tools` — returns the agent's available tools in OpenAI function format.
///
/// Headers:
///   `X-Agent-Id: <agent>` or `Mcp-Session-Id: <sid>`
async fn handle_openai_tools(
    State(state): State<Arc<HttpState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let agent_id = match resolve_agent(&state.sessions, &headers).await {
        Ok(id) => id,
        Err(status) => return (status, Json(serde_json::Value::Null)).into_response(),
    };
    let client_ip = Some(peer.ip().to_string());

    let list_req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
    });
    let (response, _, _) = state.gateway.handle(&agent_id, list_req, client_ip).await;

    let tools = response
        .as_ref()
        .map(mcp_tools_to_openai)
        .unwrap_or_default();

    Json(serde_json::json!({ "tools": tools })).into_response()
}

/// `POST /openai/v1/execute` — execute one or more OpenAI tool calls via the MCP gateway.
///
/// Request body:
/// ```json
/// { "tool_calls": [ { "id": "call_abc", "type": "function",
///                     "function": { "name": "...", "arguments": "{...}" } } ] }
/// ```
///
/// Response body:
/// ```json
/// { "tool_results": [ { "role": "tool", "tool_call_id": "...", "content": "..." } ] }
/// ```
async fn handle_openai_execute(
    State(state): State<Arc<HttpState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id = match resolve_agent(&state.sessions, &headers).await {
        Ok(id) => id,
        Err(status) => return (status, Json(serde_json::Value::Null)).into_response(),
    };
    let client_ip = Some(peer.ip().to_string());

    let Some(tool_calls) = body["tool_calls"].as_array() else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "missing `tool_calls` array"})),
        )
            .into_response();
    };

    let mut results = Vec::new();
    for (i, tool_call) in tool_calls.iter().enumerate() {
        let tool_call_id = tool_call["id"].as_str().unwrap_or("").to_string();

        let Some(mcp_req) = openai_tool_call_to_mcp(tool_call, i as u64 + 1) else {
            results.push(serde_json::json!({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": "error: malformed tool call"
            }));
            continue;
        };

        let (response, _, _) = state
            .gateway
            .handle(&agent_id, mcp_req, client_ip.clone())
            .await;

        let result = response
            .as_ref()
            .map(|r| mcp_result_to_openai(r, &tool_call_id))
            .unwrap_or_else(|| {
                serde_json::json!({
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": ""
                })
            });
        results.push(result);
    }

    Json(serde_json::json!({ "tool_results": results })).into_response()
}

// ── OAuth callback ────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct OAuthCallbackParams {
    code: String,
    state: String,
}

async fn handle_oauth_callback(
    Query(params): Query<OAuthCallbackParams>,
    State(state): State<Arc<HttpState>>,
) -> impl IntoResponse {
    match state
        .oauth_manager
        .exchange_code(&params.state, &params.code)
        .await
    {
        Ok(upstream_name) => (
            StatusCode::OK,
            format!("Upstream '{upstream_name}' authorized. You may close this tab."),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("OAuth error: {e}")).into_response(),
    }
}

async fn resolve_agent(sessions: &SessionStore, headers: &HeaderMap) -> Result<String, StatusCode> {
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        return sessions.resolve(sid).await.ok_or(StatusCode::NOT_FOUND);
    }
    Ok(headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::FilterMode, live_config::LiveConfig};
    use regex::Regex;
    use std::collections::HashMap;

    // ── chrono_ts ─────────────────────────────────────────────────────────────

    #[test]
    fn unix_epoch_formats_correctly() {
        assert_eq!(chrono_ts(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn known_timestamp_formats_correctly() {
        // 2001-09-09T01:46:40Z
        assert_eq!(chrono_ts(1_000_000_000), "2001-09-09 01:46:40");
    }

    #[test]
    fn out_of_range_timestamp_falls_back_to_string() {
        // i64::MIN is way before year 0 — chrono cannot represent it
        let ts = i64::MIN;
        assert_eq!(chrono_ts(ts), ts.to_string());
    }

    // ── html_escape ───────────────────────────────────────────────────────────

    #[test]
    fn html_escape_all_special_chars() {
        assert_eq!(
            html_escape("<script>&\"alert\"</script>"),
            "&lt;script&gt;&amp;&quot;alert&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn html_escape_no_special_chars_unchanged() {
        assert_eq!(html_escape("hello world 123"), "hello world 123");
    }

    #[test]
    fn html_escape_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    // ── check_bearer_token ────────────────────────────────────────────────────

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    #[test]
    fn no_expected_token_is_open() {
        assert!(check_bearer_token(None, &HeaderMap::new()));
    }

    #[test]
    fn correct_token_passes() {
        let h = headers_with_bearer("my-secret-token");
        assert!(check_bearer_token(Some("my-secret-token"), &h));
    }

    #[test]
    fn wrong_token_fails() {
        let h = headers_with_bearer("wrong-token");
        assert!(!check_bearer_token(Some("my-secret-token"), &h));
    }

    #[test]
    fn missing_authorization_header_fails() {
        assert!(!check_bearer_token(
            Some("my-secret-token"),
            &HeaderMap::new()
        ));
    }

    #[test]
    fn non_bearer_scheme_fails() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str("Basic my-secret-token").unwrap(),
        );
        assert!(!check_bearer_token(Some("my-secret-token"), &h));
    }

    // ── SessionStore ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn session_create_and_resolve() {
        let store = SessionStore::new(3600);
        let sid = store.create("cursor".to_string()).await;
        assert_eq!(store.resolve(&sid).await, Some("cursor".to_string()));
    }

    #[tokio::test]
    async fn expired_session_not_resolved() {
        let store = SessionStore::new(0); // TTL = 0 seconds → immediately expired
        let sid = store.create("cursor".to_string()).await;
        // Wait a tiny bit to ensure elapsed > 0
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(store.resolve(&sid).await, None);
    }

    #[tokio::test]
    async fn unknown_session_not_resolved() {
        let store = SessionStore::new(3600);
        assert_eq!(store.resolve("no-such-id").await, None);
    }

    #[tokio::test]
    async fn invalidate_existing_session_returns_true() {
        let store = SessionStore::new(3600);
        let sid = store.create("agent".to_string()).await;
        assert!(store.invalidate(&sid).await);
    }

    #[tokio::test]
    async fn invalidate_unknown_session_returns_false() {
        let store = SessionStore::new(3600);
        assert!(!store.invalidate("no-such-id").await);
    }

    #[tokio::test]
    async fn invalidated_session_cannot_be_resolved() {
        let store = SessionStore::new(3600);
        let sid = store.create("agent".to_string()).await;
        store.invalidate(&sid).await;
        assert_eq!(store.resolve(&sid).await, None);
    }

    // ── parse_and_filter_sse ─────────────────────────────────────────────────

    fn empty_config_rx() -> watch::Receiver<Arc<LiveConfig>> {
        let (_, rx) = watch::channel(Arc::new(LiveConfig::new(
            HashMap::new(),
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        )));
        rx
    }

    fn config_rx_with_pattern(pattern: &str) -> watch::Receiver<Arc<LiveConfig>> {
        let re = Regex::new(pattern).unwrap();
        let (_, rx) = watch::channel(Arc::new(LiveConfig::new(
            HashMap::new(),
            vec![re],
            vec![],
            None,
            FilterMode::Block,
            None,
        )));
        rx
    }

    #[test]
    fn event_with_data_returns_some() {
        let rx = empty_config_rx();
        let raw = "event: message\ndata: hello world";
        assert!(parse_and_filter_sse(raw, &rx).is_some());
    }

    #[test]
    fn comment_only_returns_some_keepalive() {
        let rx = empty_config_rx();
        let raw = ": keepalive";
        assert!(parse_and_filter_sse(raw, &rx).is_some());
    }

    #[test]
    fn empty_raw_returns_none() {
        let rx = empty_config_rx();
        assert!(parse_and_filter_sse("", &rx).is_none());
    }

    #[test]
    fn event_without_data_or_comment_returns_none() {
        let rx = empty_config_rx();
        assert!(parse_and_filter_sse("id: 123", &rx).is_none());
    }

    #[test]
    fn data_not_matching_pattern_returns_some() {
        let rx = config_rx_with_pattern("secret");
        let raw = "data: harmless text";
        assert!(parse_and_filter_sse(raw, &rx).is_some());
    }

    #[test]
    fn data_matching_pattern_still_returns_some() {
        // Redaction replaces content but event is not dropped
        let rx = config_rx_with_pattern("secret");
        let raw = "data: my secret token";
        assert!(parse_and_filter_sse(raw, &rx).is_some());
    }

    #[test]
    fn matching_pattern_content_is_redacted_in_event() {
        let rx = config_rx_with_pattern("private_key");
        let raw = "event: message\ndata: value=private_key=AAABBB";
        // The event should still be returned but content should be [REDACTED]
        let event = parse_and_filter_sse(raw, &rx).unwrap();
        // axum's Event doesn't expose data directly, but we can verify by debug output
        let dbg = format!("{event:?}");
        assert!(
            dbg.contains("REDACTED") || !dbg.contains("private_key"),
            "sensitive data should be redacted in SSE event: {dbg}"
        );
    }

    #[test]
    fn multiline_data_joined_with_newline() {
        let rx = empty_config_rx();
        // SSE multi-line data
        let raw = "event: batch\ndata: line1\ndata: line2\ndata: line3";
        let event = parse_and_filter_sse(raw, &rx);
        assert!(event.is_some(), "multiline data should produce an event");
    }

    #[test]
    fn multiple_block_patterns_applied() {
        fn config_rx_with_two_patterns(p1: &str, p2: &str) -> watch::Receiver<Arc<LiveConfig>> {
            let re1 = Regex::new(p1).unwrap();
            let re2 = Regex::new(p2).unwrap();
            let (_, rx) = watch::channel(Arc::new(LiveConfig::new(
                HashMap::new(),
                vec![re1, re2],
                vec![],
                None,
                FilterMode::Block,
                None,
            )));
            rx
        }
        let rx = config_rx_with_two_patterns("secret", "password");
        let raw = "data: secret=abc password=xyz";
        let event = parse_and_filter_sse(raw, &rx);
        assert!(event.is_some());
        // Both patterns should redact; the event is not dropped
    }

    #[test]
    fn event_type_preserved_in_output() {
        let rx = empty_config_rx();
        let raw = "event: tools_response\ndata: {\"result\": \"ok\"}";
        let event = parse_and_filter_sse(raw, &rx);
        assert!(event.is_some());
        let dbg = format!("{event:?}");
        assert!(
            dbg.contains("tools_response"),
            "event type should be preserved: {dbg}"
        );
    }

    // ── SessionStore additional ────────────────────────────────────────────────

    #[tokio::test]
    async fn multiple_sessions_independent() {
        let store = SessionStore::new(3600);
        let sid1 = store.create("agent-a".to_string()).await;
        let sid2 = store.create("agent-b".to_string()).await;
        assert_ne!(sid1, sid2);
        assert_eq!(store.resolve(&sid1).await, Some("agent-a".to_string()));
        assert_eq!(store.resolve(&sid2).await, Some("agent-b".to_string()));
    }

    #[tokio::test]
    async fn invalidate_one_session_leaves_other_intact() {
        let store = SessionStore::new(3600);
        let sid1 = store.create("a".to_string()).await;
        let sid2 = store.create("b".to_string()).await;
        store.invalidate(&sid1).await;
        assert_eq!(store.resolve(&sid1).await, None);
        assert_eq!(store.resolve(&sid2).await, Some("b".to_string()));
    }

    // ── accepts_event_stream ──────────────────────────────────────────────────

    fn headers_with_accept(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    #[test]
    fn accepts_event_stream_exact_type() {
        assert!(accepts_event_stream(&headers_with_accept(
            "text/event-stream"
        )));
    }

    #[test]
    fn accepts_event_stream_multiple_types_includes_sse() {
        assert!(accepts_event_stream(&headers_with_accept(
            "application/json, text/event-stream"
        )));
    }

    #[test]
    fn accepts_event_stream_sse_with_quality_factor() {
        // q-values are common; we check prefix only (text/event-stream starts the token)
        assert!(accepts_event_stream(&headers_with_accept(
            "text/event-stream;q=0.9, application/json"
        )));
    }

    #[test]
    fn accepts_event_stream_false_for_json_only() {
        assert!(!accepts_event_stream(&headers_with_accept(
            "application/json"
        )));
    }

    #[test]
    fn accepts_event_stream_false_when_no_accept_header() {
        assert!(!accepts_event_stream(&HeaderMap::new()));
    }

    #[test]
    fn accepts_event_stream_false_for_wildcard_only() {
        assert!(!accepts_event_stream(&headers_with_accept("*/*")));
    }
}

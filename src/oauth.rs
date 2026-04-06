/// OAuth 2.1 + PKCE client for authenticating arbitus to upstream MCP servers.
///
/// # Flow
///
/// 1. For each named upstream with an `oauth:` block, arbitus calls
///    [`OAuthManager::authorization_url`] at startup and logs the URL.
/// 2. The operator visits the URL in a browser, authorizes arbitus, and the
///    provider redirects to `GET /oauth/callback?code=…&state=…`.
/// 3. The callback handler calls [`OAuthManager::exchange_code`], which
///    exchanges the authorization code + PKCE verifier for tokens.
/// 4. [`OAuthManager::get_token`] is called before every upstream request.
///    If the access token is close to expiry it is refreshed automatically
///    using the stored refresh token.  If refresh fails the operator must
///    re-authorize (the URL is logged again at that point).
use crate::config::OAuthClientConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

// ── PKCE ─────────────────────────────────────────────────────────────────────

/// A PKCE (RFC 7636) code-verifier / code-challenge pair.
pub struct PkceChallenge {
    /// The raw verifier — sent in the token request as `code_verifier`.
    pub verifier: String,
    /// S256 challenge — sent in the authorization request as `code_challenge`.
    pub challenge: String,
}

impl Default for PkceChallenge {
    fn default() -> Self {
        Self::new()
    }
}

impl PkceChallenge {
    /// Generate a fresh PKCE pair using two UUID v4 values as random material
    /// (32 bytes total, well within the RFC 7636 range of 32–96 bytes).
    pub fn new() -> Self {
        let bytes: Vec<u8> = Uuid::new_v4()
            .as_bytes()
            .iter()
            .chain(Uuid::new_v4().as_bytes().iter())
            .copied()
            .collect();
        let verifier = URL_SAFE_NO_PAD.encode(&bytes);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

// ── Internal state ────────────────────────────────────────────────────────────

struct PendingAuth {
    upstream_name: String,
    verifier: String,
    config: OAuthClientConfig,
}

struct TokenSet {
    access_token: String,
    refresh_token: Option<String>,
    /// When the access token expires; refresh is triggered 60 s early.
    expires_at: Instant,
}

// ── OAuthManager ─────────────────────────────────────────────────────────────

/// Thread-safe OAuth 2.1 + PKCE token manager.
///
/// Shared between the HTTP transport (callback handler) and each `HttpUpstream`
/// instance that has an OAuth configuration.
pub struct OAuthManager {
    /// In-flight authorization requests: `state` → `PendingAuth`.
    pending: Mutex<HashMap<String, PendingAuth>>,
    /// Stored token sets: `upstream_name` → `TokenSet`.
    tokens: Mutex<HashMap<String, TokenSet>>,
    client: Client,
}

impl Default for OAuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthManager {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            client: Client::new(),
        }
    }

    /// Build an OAuth 2.1 + PKCE authorization URL for the given upstream.
    ///
    /// The generated `state` is stored internally and must be presented back
    /// by the callback via [`exchange_code`].  The URL must be visited by the
    /// operator in a browser to authorize arbitus.
    pub fn authorization_url(&self, upstream_name: &str, config: &OAuthClientConfig) -> String {
        let pkce = PkceChallenge::new();
        let state = Uuid::new_v4().to_string();

        self.pending.lock().unwrap().insert(
            state.clone(),
            PendingAuth {
                upstream_name: upstream_name.to_string(),
                verifier: pkce.verifier,
                config: config.clone(),
            },
        );

        let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();

        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
            config.authorization_url,
            enc(&config.client_id),
            enc(&config.redirect_uri),
            pkce.challenge,
            state,
        );
        if !config.scopes.is_empty() {
            url.push_str(&format!("&scope={}", enc(&config.scopes.join(" "))));
        }
        url
    }

    /// Exchange an authorization code + state for tokens.
    ///
    /// Called by the `/oauth/callback` HTTP handler.
    /// Returns the upstream name that was authorized.
    pub async fn exchange_code(&self, state: &str, code: &str) -> anyhow::Result<String> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .remove(state)
            .ok_or_else(|| anyhow::anyhow!("unknown or expired OAuth state"))?;

        let verifier = pending.verifier.clone();
        let redirect_uri = pending.config.redirect_uri.clone();
        let client_id = pending.config.client_id.clone();

        let resp = self
            .token_request(
                &pending.config,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", &redirect_uri),
                    ("code_verifier", &verifier),
                    ("client_id", &client_id),
                ],
            )
            .await?;

        let upstream_name = pending.upstream_name.clone();
        self.store_token(&upstream_name, resp);
        tracing::info!(upstream = %upstream_name, "OAuth token obtained");
        Ok(upstream_name)
    }

    /// Return a valid access token for `upstream_name`.
    ///
    /// Refreshes the token automatically if it is within 60 seconds of expiry.
    /// Returns `None` if the upstream has not been authorized yet or if refresh
    /// fails (in which case the operator must re-authorize).
    pub async fn get_token(
        &self,
        upstream_name: &str,
        config: &OAuthClientConfig,
    ) -> Option<String> {
        let (access_token, refresh_token, expired) = {
            let tokens = self.tokens.lock().unwrap();
            let t = tokens.get(upstream_name)?;
            let expired = t.expires_at <= Instant::now() + Duration::from_secs(60);
            (t.access_token.clone(), t.refresh_token.clone(), expired)
        };

        if !expired {
            return Some(access_token);
        }

        if let Some(rt) = refresh_token {
            let client_id = config.client_id.clone();
            match self
                .token_request(
                    config,
                    &[
                        ("grant_type", "refresh_token"),
                        ("refresh_token", &rt),
                        ("client_id", &client_id),
                    ],
                )
                .await
            {
                Ok(resp) => {
                    let token = resp.access_token.clone();
                    self.store_token(upstream_name, resp);
                    tracing::info!(upstream = %upstream_name, "OAuth token refreshed");
                    return Some(token);
                }
                Err(e) => {
                    tracing::warn!(
                        upstream = %upstream_name,
                        error = %e,
                        "OAuth token refresh failed — re-authorization required"
                    );
                }
            }
        }

        None
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn store_token(&self, upstream_name: &str, resp: TokenResponse) {
        let expires_at = Instant::now() + Duration::from_secs(resp.expires_in.unwrap_or(3600));
        self.tokens.lock().unwrap().insert(
            upstream_name.to_string(),
            TokenSet {
                access_token: resp.access_token,
                refresh_token: resp.refresh_token,
                expires_at,
            },
        );
    }

    async fn token_request(
        &self,
        config: &OAuthClientConfig,
        params: &[(&str, &str)],
    ) -> anyhow::Result<TokenResponse> {
        let mut req = self.client.post(&config.token_url).form(params);
        if let Some(secret) = &config.client_secret {
            req = req.basic_auth(&config.client_id, Some(secret));
        }
        let resp = req.send().await?.json::<TokenResponse>().await?;
        Ok(resp)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OAuthClientConfig {
        OAuthClientConfig {
            client_id: "test-client".to_string(),
            client_secret: None,
            authorization_url: "https://auth.example.com/authorize".to_string(),
            token_url: "https://auth.example.com/token".to_string(),
            scopes: vec!["mcp:tools".to_string()],
            redirect_uri: "http://localhost:4000/oauth/callback".to_string(),
        }
    }

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let pkce = PkceChallenge::new();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.as_bytes()));
        assert_eq!(pkce.challenge, expected);
    }

    #[test]
    fn pkce_verifier_uses_url_safe_chars() {
        let pkce = PkceChallenge::new();
        assert!(
            pkce.verifier
                .chars()
                .all(|c| c.is_alphanumeric() || "-_".contains(c)),
            "verifier must use URL-safe base64 chars only"
        );
    }

    #[test]
    fn pkce_verifier_meets_rfc7636_length() {
        let pkce = PkceChallenge::new();
        assert!(
            (43..=128).contains(&pkce.verifier.len()),
            "verifier length must be 43-128 chars per RFC 7636, got {}",
            pkce.verifier.len()
        );
    }

    #[test]
    fn authorization_url_contains_required_params() {
        let mgr = OAuthManager::new();
        let config = test_config();
        let url = mgr.authorization_url("filesystem", &config);
        assert!(
            url.contains("response_type=code"),
            "must have response_type=code"
        );
        assert!(url.contains("code_challenge_method=S256"), "must use S256");
        assert!(url.contains("code_challenge="), "must include challenge");
        assert!(url.contains("state="), "must include state");
        assert!(
            url.starts_with("https://auth.example.com/authorize"),
            "must use configured authorization_url"
        );
    }

    #[test]
    fn authorization_url_includes_scope() {
        let mgr = OAuthManager::new();
        let url = mgr.authorization_url("fs", &test_config());
        assert!(url.contains("scope="), "must include scope when configured");
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let mgr = OAuthManager::new();
        let mut config = test_config();
        config.scopes.clear();
        let url = mgr.authorization_url("fs", &config);
        assert!(!url.contains("scope="), "must not include scope when empty");
    }

    #[test]
    fn each_authorization_url_has_unique_state() {
        let mgr = OAuthManager::new();
        let config = test_config();
        let url1 = mgr.authorization_url("fs", &config);
        let url2 = mgr.authorization_url("fs", &config);
        let state1 = url1.split("state=").nth(1).unwrap_or("");
        let state2 = url2.split("state=").nth(1).unwrap_or("");
        assert_ne!(state1, state2, "each call must produce a unique state");
    }

    #[tokio::test]
    async fn exchange_code_with_unknown_state_returns_error() {
        let mgr = OAuthManager::new();
        assert!(mgr.exchange_code("unknown-state", "code").await.is_err());
    }

    #[tokio::test]
    async fn get_token_returns_none_for_unknown_upstream() {
        let mgr = OAuthManager::new();
        assert!(mgr.get_token("unknown", &test_config()).await.is_none());
    }
}

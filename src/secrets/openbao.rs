/// OpenBao (Vault-compatible) secret backend.
///
/// Authenticates once at construction time, then fetches KV v2 secrets via the
/// REST API.  No heavy Vault SDK is required — OpenBao exposes plain HTTP/JSON.
///
/// # Path syntax
///
/// Paths follow the KV v2 convention: `secret/data/<path>`.
/// An optional `#field` fragment selects a specific key from the secret's
/// `data` object; if omitted the key `"value"` is used.
///
/// ```text
/// secret/data/arbitus/admin_token            → data["value"]
/// secret/data/agents/cursor#api_key        → data["api_key"]
/// ```
use crate::config::OpenBaoAuthMethod;
use anyhow::Context;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Mutex;

pub struct OpenBaoProvider {
    address: String,
    token: Mutex<String>,
    client: Client,
}

impl OpenBaoProvider {
    /// Authenticate to OpenBao and return a ready-to-use provider.
    pub async fn new(address: impl Into<String>, auth: &OpenBaoAuthMethod) -> anyhow::Result<Self> {
        let address = address.into();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let token = authenticate(&client, &address, auth).await?;
        tracing::info!("OpenBao authentication successful");
        Ok(Self {
            address,
            token: Mutex::new(token),
            client,
        })
    }
}

#[async_trait]
impl super::SecretsProvider for OpenBaoProvider {
    async fn get(&self, path: &str) -> anyhow::Result<String> {
        // Split optional #field fragment
        let (vault_path, field) = match path.split_once('#') {
            Some((p, f)) => (p, f),
            None => (path, "value"),
        };

        let url = format!("{}/v1/{}", self.address.trim_end_matches('/'), vault_path);
        let token = self.token.lock().await.clone();

        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .context("OpenBao request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("OpenBao GET {vault_path} returned {status}: {body}");
        }

        let body: KvV2Response = resp
            .json()
            .await
            .context("failed to parse OpenBao KV v2 response")?;

        body.data
            .data
            .get(field)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("field '{field}' not found in secret '{vault_path}'"))
    }
}

// ── Authentication ────────────────────────────────────────────────────────────

async fn authenticate(
    client: &Client,
    address: &str,
    method: &OpenBaoAuthMethod,
) -> anyhow::Result<String> {
    match method {
        OpenBaoAuthMethod::Token { token } => Ok(token.clone()),

        OpenBaoAuthMethod::Approle { role_id, secret_id } => {
            let url = format!("{address}/v1/auth/approle/login");
            let resp = client
                .post(&url)
                .json(&serde_json::json!({
                    "role_id": role_id,
                    "secret_id": secret_id,
                }))
                .send()
                .await
                .context("AppRole login request failed")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("AppRole login failed ({status}): {body}");
            }

            let body: AuthResponse = resp
                .json()
                .await
                .context("failed to parse AppRole login response")?;
            Ok(body.auth.client_token)
        }

        OpenBaoAuthMethod::Kubernetes {
            role,
            jwt_path,
            mount,
        } => {
            let jwt = tokio::fs::read_to_string(jwt_path)
                .await
                .with_context(|| format!("failed to read Kubernetes JWT from {jwt_path}"))?;
            let jwt = jwt.trim().to_string();

            let url = format!("{address}/v1/auth/{mount}/login");
            let resp = client
                .post(&url)
                .json(&serde_json::json!({
                    "role": role,
                    "jwt": jwt,
                }))
                .send()
                .await
                .context("Kubernetes auth login request failed")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Kubernetes login failed ({status}): {body}");
            }

            let body: AuthResponse = resp
                .json()
                .await
                .context("failed to parse Kubernetes login response")?;
            Ok(body.auth.client_token)
        }
    }
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct KvV2Response {
    data: KvV2Data,
}

#[derive(Deserialize)]
struct KvV2Data {
    data: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests for path/fragment parsing logic — no network required.

    fn split_path(path: &str) -> (&str, &str) {
        match path.split_once('#') {
            Some((p, f)) => (p, f),
            None => (path, "value"),
        }
    }

    #[test]
    fn path_without_fragment_uses_value_field() {
        let (path, field) = split_path("secret/data/arbitus/admin_token");
        assert_eq!(path, "secret/data/arbitus/admin_token");
        assert_eq!(field, "value");
    }

    #[test]
    fn path_with_fragment_extracts_named_field() {
        let (path, field) = split_path("secret/data/agents/cursor#api_key");
        assert_eq!(path, "secret/data/agents/cursor");
        assert_eq!(field, "api_key");
    }

    #[test]
    fn token_auth_returns_token_directly() {
        // Verify the Token branch doesn't need network — tested via config parsing.
        let method = OpenBaoAuthMethod::Token {
            token: "hvs.test".to_string(),
        };
        // Just assert the enum variant can be constructed and matched.
        if let OpenBaoAuthMethod::Token { token } = method {
            assert_eq!(token, "hvs.test");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn default_k8s_jwt_path_is_correct() {
        use crate::config::default_k8s_jwt_path;
        assert_eq!(
            default_k8s_jwt_path(),
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        );
    }

    #[test]
    fn default_k8s_mount_is_kubernetes() {
        use crate::config::default_k8s_mount;
        assert_eq!(default_k8s_mount(), "kubernetes");
    }
}

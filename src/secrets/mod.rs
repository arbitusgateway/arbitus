/// Secret management backends for arbitus.
///
/// The `SecretsProvider` trait abstracts over different backends (OpenBao,
/// mock). At startup the active provider resolves all paths declared in
/// `secrets.paths` and the values are injected into the gateway config.
pub mod openbao;

use async_trait::async_trait;

/// Minimal interface for a secret backend.
#[async_trait]
pub trait SecretsProvider: Send + Sync {
    /// Fetch the secret at `path`.
    ///
    /// The path uses the same syntax as `secrets.paths` values:
    /// `"secret/data/foo"` or `"secret/data/foo#field"`.
    async fn get(&self, path: &str) -> anyhow::Result<String>;
}

/// Resolve every `(config_key, vault_path)` pair and return a flat map of
/// `config_key → secret_value`. Errors for individual paths are logged as
/// warnings but do not abort — the caller decides how to handle missing values.
pub async fn resolve_all(
    provider: &dyn SecretsProvider,
    paths: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for (key, path) in paths {
        match provider.get(path).await {
            Ok(val) => {
                out.insert(key.clone(), val);
            }
            Err(e) => {
                tracing::warn!(config_key = %key, path = %path, error = %e, "secret resolution failed");
            }
        }
    }
    out
}

/// Apply a flat map of `dot.notation.key → value` overrides onto a
/// `serde_json::Value` that represents the parsed config.
///
/// Intermediate objects are created as needed. Existing scalar values are
/// replaced; if a parent key holds a non-object value the override is skipped
/// with a warning.
pub fn inject_into_value(
    config: &mut serde_json::Value,
    overrides: &std::collections::HashMap<String, String>,
) {
    for (key, value) in overrides {
        set_dotted(config, key, value);
    }
}

fn set_dotted(root: &mut serde_json::Value, key: &str, value: &str) {
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    match parts.as_slice() {
        [leaf] => {
            if let Some(obj) = root.as_object_mut() {
                obj.insert(
                    (*leaf).to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            } else {
                tracing::warn!(key = %key, "cannot inject secret: parent is not an object");
            }
        }
        [head, tail] => {
            if let Some(obj) = root.as_object_mut() {
                let child = obj
                    .entry((*head).to_string())
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                set_dotted(child, tail, value);
            } else {
                tracing::warn!(key = %key, "cannot inject secret: parent is not an object");
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_config() -> serde_json::Value {
        serde_json::json!({
            "admin_token": "old",
            "agents": {
                "cursor": {
                    "api_key": "old-key"
                }
            }
        })
    }

    #[test]
    fn inject_top_level_scalar() {
        let mut cfg = make_config();
        let mut overrides = HashMap::new();
        overrides.insert("admin_token".to_string(), "new-secret".to_string());
        inject_into_value(&mut cfg, &overrides);
        assert_eq!(cfg["admin_token"], "new-secret");
    }

    #[test]
    fn inject_nested_key() {
        let mut cfg = make_config();
        let mut overrides = HashMap::new();
        overrides.insert(
            "agents.cursor.api_key".to_string(),
            "rotated-key".to_string(),
        );
        inject_into_value(&mut cfg, &overrides);
        assert_eq!(cfg["agents"]["cursor"]["api_key"], "rotated-key");
    }

    #[test]
    fn inject_creates_missing_intermediate_objects() {
        let mut cfg = serde_json::json!({});
        let mut overrides = HashMap::new();
        overrides.insert("a.b.c".to_string(), "deep".to_string());
        inject_into_value(&mut cfg, &overrides);
        assert_eq!(cfg["a"]["b"]["c"], "deep");
    }

    #[test]
    fn inject_does_not_touch_other_keys() {
        let mut cfg = make_config();
        let mut overrides = HashMap::new();
        overrides.insert("admin_token".to_string(), "x".to_string());
        inject_into_value(&mut cfg, &overrides);
        // agents.cursor.api_key must be unchanged
        assert_eq!(cfg["agents"]["cursor"]["api_key"], "old-key");
    }
}

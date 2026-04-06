/// Environment variable support for `gateway.yml`.
///
/// # Interpolation (`${VAR}` syntax) — Issue #20
///
/// Any value in the YAML file written as `"${VAR_NAME}"` is replaced with the
/// corresponding environment variable before the file is parsed by serde.
/// If the variable is not set, startup fails with a descriptive error.
///
/// ```yaml
/// admin_token: "${ARBITUS_ADMIN_TOKEN}"
/// agents:
///   cursor:
///     api_key: "${CURSOR_API_KEY}"
/// ```
///
/// # Top-level overrides (`ARBITUS_` prefix) — Issue #21
///
/// A small set of high-value fields can be overridden via dedicated env vars
/// without touching the YAML file.  This follows the 12-factor app convention
/// and works with any secret manager that injects secrets as env vars
/// (Kubernetes Secrets, Vault Agent, External Secrets Operator, etc.).
///
/// | Env var              | Config field          |
/// |----------------------|-----------------------|
/// | `ARBITUS_ADMIN_TOKEN`  | `admin_token`         |
/// | `ARBITUS_UPSTREAM_URL` | `transport.upstream`  |
/// | `ARBITUS_LISTEN_ADDR`  | `transport.addr`      |
use crate::config::Config;

/// Replace every `${VAR_NAME}` placeholder in `raw` with the value of the
/// corresponding environment variable.
///
/// Returns an error if any placeholder references an unset variable.
pub fn interpolate_env_vars(raw: &str) -> anyhow::Result<String> {
    let mut result = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let var_name: String = chars.by_ref().take_while(|&c| c != '}').collect();
            if var_name.is_empty() {
                anyhow::bail!("config error: empty placeholder '${{}}' in gateway.yml");
            }
            let value = std::env::var(&var_name).map_err(|_| {
                anyhow::anyhow!(
                    "config error: env var '{}' is not set (referenced in gateway.yml)",
                    var_name
                )
            })?;
            result.push_str(&value);
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

/// Apply `ARBITUS_*` env var overrides to a parsed `Config`.
///
/// Each recognised variable silently overrides the corresponding field when set.
/// Unset variables are ignored — the YAML value is kept.
pub fn apply_env_overrides(config: &mut Config) {
    if let Ok(token) = std::env::var("ARBITUS_ADMIN_TOKEN") {
        config.admin_token = Some(token);
    }

    if let Ok(url) = std::env::var("ARBITUS_UPSTREAM_URL") {
        config.set_upstream_url(url);
    }

    if let Ok(addr) = std::env::var("ARBITUS_LISTEN_ADDR") {
        config.set_listen_addr(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── interpolate_env_vars ──────────────────────────────────────────────────

    #[test]
    fn resolves_single_placeholder() {
        // SAFETY: single-threaded test binary; no other thread reads this var concurrently.
        unsafe { std::env::set_var("_ARBITUS_TEST_TOKEN", "supersecret") };
        let raw = "admin_token: \"${_ARBITUS_TEST_TOKEN}\"";
        let out = interpolate_env_vars(raw).unwrap();
        assert_eq!(out, "admin_token: \"supersecret\"");
        unsafe { std::env::remove_var("_ARBITUS_TEST_TOKEN") };
    }

    #[test]
    fn resolves_multiple_placeholders() {
        unsafe {
            std::env::set_var("_ARBITUS_A", "val_a");
            std::env::set_var("_ARBITUS_B", "val_b");
        }
        let raw = "x: \"${_ARBITUS_A}\"\ny: \"${_ARBITUS_B}\"";
        let out = interpolate_env_vars(raw).unwrap();
        assert_eq!(out, "x: \"val_a\"\ny: \"val_b\"");
        unsafe {
            std::env::remove_var("_ARBITUS_A");
            std::env::remove_var("_ARBITUS_B");
        }
    }

    #[test]
    fn passthrough_when_no_placeholders() {
        let raw = "admin_token: hardcoded";
        let out = interpolate_env_vars(raw).unwrap();
        assert_eq!(out, "admin_token: hardcoded");
    }

    #[test]
    fn error_on_unset_variable() {
        unsafe { std::env::remove_var("_ARBITUS_DEFINITELY_NOT_SET") };
        let raw = "admin_token: \"${_ARBITUS_DEFINITELY_NOT_SET}\"";
        let err = interpolate_env_vars(raw).unwrap_err();
        assert!(
            err.to_string().contains("_ARBITUS_DEFINITELY_NOT_SET"),
            "error should name the missing variable"
        );
        assert!(
            err.to_string().contains("not set"),
            "error should say 'not set'"
        );
    }

    #[test]
    fn error_on_empty_placeholder() {
        let raw = "admin_token: \"${}\"";
        let err = interpolate_env_vars(raw).unwrap_err();
        assert!(err.to_string().contains("empty placeholder"));
    }

    #[test]
    fn dollar_without_brace_is_literal() {
        let raw = "cost: $100";
        let out = interpolate_env_vars(raw).unwrap();
        assert_eq!(out, "cost: $100");
    }

    #[test]
    fn partial_placeholder_not_consumed() {
        // "${VAR" without closing brace — take_while exhausts the string, var_name = "VAR"
        // and std::env::var("VAR") is unset → error
        unsafe { std::env::remove_var("_ARBITUS_UNCLOSED") };
        let raw = "${_ARBITUS_UNCLOSED";
        let err = interpolate_env_vars(raw).unwrap_err();
        assert!(err.to_string().contains("_ARBITUS_UNCLOSED"));
    }
}

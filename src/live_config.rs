use crate::config::{AgentPolicy, FilterMode};
use regex::Regex;
use std::{collections::HashMap, sync::Arc};

/// Loaded OPA policy — policy file content and the Rego query to evaluate.
pub struct OpaPolicy {
    pub entrypoint: String,
    pub content: String,
}

/// Hot-reloadable configuration snapshot.
/// Wrapped in `Arc` and broadcast via `tokio::sync::watch`.
/// All consumers (`borrow()`) always see the latest reloaded version.
pub struct LiveConfig {
    pub agents: HashMap<String, AgentPolicy>,
    /// Block patterns shared via `Arc` — cheap to snapshot in middleware without cloning
    /// each `Regex`. The inner `Vec` is immutable once constructed.
    pub block_patterns: Arc<Vec<Regex>>,
    /// Built-in prompt injection patterns. Non-empty when `rules.block_prompt_injection: true`.
    pub injection_patterns: Arc<Vec<Regex>>,
    /// Reverse map: api_key → agent_name.
    /// Used for key-based agent identity on `initialize`.
    pub api_keys: HashMap<String, String>,
    /// Max requests per minute per IP (HTTP mode). None = unlimited.
    pub ip_rate_limit: Option<usize>,
    /// How to handle block_pattern matches on requests (block vs redact).
    pub filter_mode: FilterMode,
    /// Fallback policy for agents not listed in `agents`. None = block unknown agents.
    pub default_policy: Option<AgentPolicy>,
    /// Pre-loaded OPA policy for contextual access control. None = OPA disabled.
    pub opa_policy: Option<Arc<OpaPolicy>>,
    /// Reverse map: client cert CN → agent_name.
    /// Built from agents whose policy has `mtls_identity` set.
    pub mtls_identities: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentPolicy;
    use std::collections::HashMap;

    fn policy_with_key(key: &str) -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit: 60,
            tool_rate_limits: HashMap::new(),
            upstream: None,
            api_key: Some(key.to_string()),
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
        }
    }

    fn policy_no_key() -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit: 60,
            tool_rate_limits: HashMap::new(),
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
        }
    }

    #[test]
    fn api_keys_reverse_map_built_correctly() {
        let mut agents = HashMap::new();
        agents.insert("cursor".to_string(), policy_with_key("key-cursor"));
        agents.insert("claude".to_string(), policy_with_key("key-claude"));
        let live = LiveConfig::new(agents, vec![], vec![], None, FilterMode::Block, None);
        assert_eq!(
            live.api_keys.get("key-cursor").map(String::as_str),
            Some("cursor")
        );
        assert_eq!(
            live.api_keys.get("key-claude").map(String::as_str),
            Some("claude")
        );
        assert_eq!(live.api_keys.len(), 2);
    }

    #[test]
    fn agent_without_api_key_not_in_map() {
        let mut agents = HashMap::new();
        agents.insert("anon".to_string(), policy_no_key());
        let live = LiveConfig::new(agents, vec![], vec![], None, FilterMode::Block, None);
        assert!(live.api_keys.is_empty());
    }

    #[test]
    fn mixed_agents_only_keyed_ones_in_map() {
        let mut agents = HashMap::new();
        agents.insert("keyed".to_string(), policy_with_key("k1"));
        agents.insert("open".to_string(), policy_no_key());
        let live = LiveConfig::new(agents, vec![], vec![], None, FilterMode::Block, None);
        assert_eq!(live.api_keys.len(), 1);
        assert!(live.api_keys.contains_key("k1"));
    }

    #[test]
    fn block_patterns_stored_in_arc() {
        let re = regex::Regex::new("secret").unwrap();
        let live = LiveConfig::new(
            HashMap::new(),
            vec![re],
            vec![],
            None,
            FilterMode::Block,
            None,
        );
        assert_eq!(live.block_patterns.len(), 1);
        // Arc::strong_count confirms it's wrapped
        assert_eq!(Arc::strong_count(&live.block_patterns), 1);
    }

    #[test]
    fn ip_rate_limit_preserved() {
        let live = LiveConfig::new(
            HashMap::new(),
            vec![],
            vec![],
            Some(100),
            FilterMode::Block,
            None,
        );
        assert_eq!(live.ip_rate_limit, Some(100));
        let live2 = LiveConfig::new(
            HashMap::new(),
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        );
        assert_eq!(live2.ip_rate_limit, None);
    }

    #[test]
    fn injection_patterns_stored_in_arc() {
        let re = regex::Regex::new("ignore.*instructions").unwrap();
        let live = LiveConfig::new(
            HashMap::new(),
            vec![],
            vec![re],
            None,
            FilterMode::Block,
            None,
        );
        assert_eq!(live.injection_patterns.len(), 1);
        assert_eq!(Arc::strong_count(&live.injection_patterns), 1);
    }

    #[test]
    fn filter_mode_preserved() {
        let live = LiveConfig::new(
            HashMap::new(),
            vec![],
            vec![],
            None,
            FilterMode::Redact,
            None,
        );
        assert_eq!(live.filter_mode, FilterMode::Redact);
        let live2 = LiveConfig::new(
            HashMap::new(),
            vec![],
            vec![],
            None,
            FilterMode::Block,
            None,
        );
        assert_eq!(live2.filter_mode, FilterMode::Block);
    }

    fn policy_with_mtls(cn: &str) -> AgentPolicy {
        AgentPolicy {
            allowed_tools: None,
            denied_tools: vec![],
            rate_limit: 60,
            tool_rate_limits: HashMap::new(),
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
            mtls_identity: Some(cn.to_string()),
        }
    }

    #[test]
    fn mtls_identities_reverse_map_built_correctly() {
        let mut agents = HashMap::new();
        agents.insert(
            "cursor".to_string(),
            policy_with_mtls("cursor.agents.internal"),
        );
        agents.insert(
            "claude".to_string(),
            policy_with_mtls("claude.agents.internal"),
        );
        let live = LiveConfig::new(agents, vec![], vec![], None, FilterMode::Block, None);
        assert_eq!(
            live.mtls_identities
                .get("cursor.agents.internal")
                .map(String::as_str),
            Some("cursor")
        );
        assert_eq!(
            live.mtls_identities
                .get("claude.agents.internal")
                .map(String::as_str),
            Some("claude")
        );
        assert_eq!(live.mtls_identities.len(), 2);
    }

    #[test]
    fn agent_without_mtls_identity_not_in_map() {
        let mut agents = HashMap::new();
        agents.insert("anon".to_string(), policy_no_key());
        let live = LiveConfig::new(agents, vec![], vec![], None, FilterMode::Block, None);
        assert!(live.mtls_identities.is_empty());
    }

    #[test]
    fn mixed_mtls_and_key_agents_only_mtls_in_mtls_map() {
        let mut agents = HashMap::new();
        agents.insert("mtls_agent".to_string(), policy_with_mtls("agent.cn"));
        agents.insert("key_agent".to_string(), policy_with_key("k1"));
        let live = LiveConfig::new(agents, vec![], vec![], None, FilterMode::Block, None);
        assert_eq!(live.mtls_identities.len(), 1);
        assert!(live.mtls_identities.contains_key("agent.cn"));
        assert_eq!(live.api_keys.len(), 1);
        assert!(live.api_keys.contains_key("k1"));
    }
}

impl LiveConfig {
    pub fn new(
        agents: HashMap<String, AgentPolicy>,
        block_patterns: Vec<Regex>,
        injection_patterns: Vec<Regex>,
        ip_rate_limit: Option<usize>,
        filter_mode: FilterMode,
        default_policy: Option<AgentPolicy>,
    ) -> Self {
        let api_keys = agents
            .iter()
            .filter_map(|(name, p)| p.api_key.as_ref().map(|k| (k.clone(), name.clone())))
            .collect();
        let mtls_identities = agents
            .iter()
            .filter_map(|(name, p)| {
                p.mtls_identity
                    .as_ref()
                    .map(|cn| (cn.clone(), name.clone()))
            })
            .collect();
        Self {
            agents,
            block_patterns: Arc::new(block_patterns),
            injection_patterns: Arc::new(injection_patterns),
            api_keys,
            ip_rate_limit,
            filter_mode,
            default_policy,
            opa_policy: None,
            mtls_identities,
        }
    }

    /// Builder method to attach an OPA policy after construction.
    pub fn with_opa_policy(mut self, policy: Option<Arc<OpaPolicy>>) -> Self {
        self.opa_policy = policy;
        self
    }
}

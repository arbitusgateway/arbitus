//! A2A (Agent-to-Agent) protocol support.
//!
//! Implements a security proxy that enforces Arbitus policies on A2A protocol
//! requests before forwarding them to an upstream A2A agent.
//!
//! ## Protocol
//! The A2A protocol is a JSON-RPC 2.0 interface for agent-to-agent communication.
//! Arbitus sits between the caller and the upstream agent, enforcing:
//! - Per-agent rate limits (using the `rate_limit` field from agent policy)
//! - API key authentication (using the `api_key` field from agent policy)
//! - Payload filtering for blocked patterns (using `rules.block_patterns`)
//!
//! ## Agent Identity
//! Callers identify themselves via the `x-arbitus-agent` HTTP header.
//! The value must match an agent name in the Arbitus config.
//!
//! ## Configuration
//! ```yaml
//! a2a:
//!   upstream: "http://localhost:4001"
//!   mount: "/a2a"
//!   agent_card:
//!     name: "My Agent"
//!     description: "Proxied via Arbitus"
//!     url: "http://localhost:4000/a2a"
//!     version: "1.0.0"
//! ```

pub mod executor;
pub mod interceptor;

pub use executor::A2aProxyExecutor;
pub use interceptor::A2aPolicyInterceptor;

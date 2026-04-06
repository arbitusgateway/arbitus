use opentelemetry::{KeyValue, global};
use prometheus::{Counter, CounterVec, Encoder, Opts, Registry, TextEncoder};

pub struct GatewayMetrics {
    registry: Registry,
    requests: CounterVec,
    /// Per-agent token counter. Labels: `agent`, `direction` ("input" | "output").
    tokens: CounterVec,
    /// Incremented each time a config reload attempt fails (parse or I/O error).
    config_reload_failures: Counter,
    /// Audit entries dropped because the backend channel was full.
    /// Labels: `backend` ("sqlite" | "webhook" | "openlineage").
    audit_drops: CounterVec,
}

impl GatewayMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let requests = CounterVec::new(
            Opts::new(
                "arbitus_requests_total",
                "Total requests processed by arbitus",
            ),
            &["agent", "outcome"],
        )?;
        registry.register(Box::new(requests.clone()))?;

        let tokens = CounterVec::new(
            Opts::new(
                "arbitus_tokens_total",
                "Estimated token count processed by arbitus (4-chars-per-token heuristic)",
            ),
            &["agent", "direction"],
        )?;
        registry.register(Box::new(tokens.clone()))?;

        let config_reload_failures = Counter::new(
            "arbitus_config_reload_failures_total",
            "Number of times a config reload attempt failed (parse or I/O error)",
        )?;
        registry.register(Box::new(config_reload_failures.clone()))?;

        let audit_drops = CounterVec::new(
            Opts::new(
                "arbitus_audit_drops_total",
                "Audit entries dropped because the backend channel was full",
            ),
            &["backend"],
        )?;
        registry.register(Box::new(audit_drops.clone()))?;

        Ok(Self {
            registry,
            requests,
            tokens,
            config_reload_failures,
            audit_drops,
        })
    }

    pub fn record(&self, agent: &str, outcome: &str) {
        self.requests.with_label_values(&[agent, outcome]).inc();
        // Mirror to OTLP when a global meter provider is installed (no-op otherwise).
        global::meter("arbitus")
            .u64_counter("arbitus.requests.total")
            .with_description("Total requests processed by arbitus")
            .init()
            .add(
                1,
                &[
                    KeyValue::new("agent", agent.to_string()),
                    KeyValue::new("outcome", outcome.to_string()),
                ],
            );
    }

    /// Record estimated token usage for a single request.
    ///
    /// - `input_tokens`: tokens estimated from the request arguments
    /// - `output_tokens`: tokens estimated from the upstream response
    pub fn record_tokens(&self, agent: &str, input_tokens: u32, output_tokens: u32) {
        if input_tokens > 0 {
            self.tokens
                .with_label_values(&[agent, "input"])
                .inc_by(f64::from(input_tokens));
            global::meter("arbitus")
                .f64_counter("arbitus.tokens.total")
                .with_description("Estimated tokens processed by arbitus")
                .init()
                .add(
                    f64::from(input_tokens),
                    &[
                        KeyValue::new("agent", agent.to_string()),
                        KeyValue::new("direction", "input"),
                    ],
                );
        }
        if output_tokens > 0 {
            self.tokens
                .with_label_values(&[agent, "output"])
                .inc_by(f64::from(output_tokens));
            global::meter("arbitus")
                .f64_counter("arbitus.tokens.total")
                .with_description("Estimated tokens processed by arbitus")
                .init()
                .add(
                    f64::from(output_tokens),
                    &[
                        KeyValue::new("agent", agent.to_string()),
                        KeyValue::new("direction", "output"),
                    ],
                );
        }
    }

    /// Increment the config reload failure counter.
    /// Called by the hot-reload task whenever `Config::from_file` returns an error.
    pub fn record_config_reload_failure(&self) {
        self.config_reload_failures.inc();
    }

    /// Increment the audit drop counter for a specific backend.
    /// Called when `try_send` fails because the channel is full.
    pub fn record_audit_drop(&self, backend: &str) {
        self.audit_drops.with_label_values(&[backend]).inc();
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = Vec::new();
        let _ = encoder.encode(&families, &mut buf);
        String::from_utf8(buf).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_tokens_updates_counter() {
        let m = GatewayMetrics::new().unwrap();
        m.record_tokens("agent-a", 10, 25);
        let rendered = m.render();
        assert!(rendered.contains("arbitus_tokens_total"));
        assert!(rendered.contains(r#"direction="input""#));
        assert!(rendered.contains(r#"direction="output""#));
    }

    #[test]
    fn zero_tokens_not_recorded() {
        let m = GatewayMetrics::new().unwrap();
        m.record_tokens("agent-a", 0, 0);
        let rendered = m.render();
        // Counter family is registered but no samples emitted for this agent
        assert!(!rendered.contains(r#"agent="agent-a""#));
    }

    #[test]
    fn multiple_agents_tracked_independently() {
        let m = GatewayMetrics::new().unwrap();
        m.record_tokens("cursor", 5, 10);
        m.record_tokens("claude", 20, 40);
        let rendered = m.render();
        assert!(rendered.contains(r#"agent="cursor""#));
        assert!(rendered.contains(r#"agent="claude""#));
    }

    // ── OTel dual-export (no-op without provider) ─────────────────────────────

    #[test]
    fn record_does_not_panic_without_otel_provider() {
        // No global OTel meter provider installed — calls must be silent no-ops.
        let m = GatewayMetrics::new().unwrap();
        m.record("cursor", "allowed");
        m.record("cursor", "blocked");
        // Prometheus counter still incremented
        let rendered = m.render();
        assert!(rendered.contains("arbitus_requests_total"));
    }

    #[test]
    fn record_tokens_does_not_panic_without_otel_provider() {
        let m = GatewayMetrics::new().unwrap();
        m.record_tokens("cursor", 100, 200);
        let rendered = m.render();
        assert!(rendered.contains("arbitus_tokens_total"));
    }

    #[test]
    fn prometheus_metrics_unaffected_by_otel_calls() {
        let m = GatewayMetrics::new().unwrap();
        m.record("agent-a", "allowed");
        m.record("agent-a", "allowed");
        m.record("agent-a", "blocked");
        let rendered = m.render();
        // Two allowed + one blocked — Prometheus counters must reflect this.
        assert!(rendered.contains(r#"outcome="allowed""#));
        assert!(rendered.contains(r#"outcome="blocked""#));
    }
}

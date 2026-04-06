//! Kubernetes ConfigMap watcher.
//!
//! When Arbitus is deployed in-cluster and `kubernetes.configmap_name` is set,
//! this module subscribes to the named ConfigMap via the K8s API and triggers a
//! live config reload on every `Apply` event — replacing the 30-second file
//! polling loop with an event-driven reload.
//!
//! Requires the `kubernetes` Cargo feature and a Kubernetes RBAC Role that
//! grants `get`, `list`, and `watch` on the target ConfigMap.

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{Api, Client, runtime::watcher};
use std::sync::Arc;
use tokio::sync::watch;

use crate::{config::KubernetesConfig, live_config::LiveConfig, metrics::GatewayMetrics, reload};

/// Returns the pod's namespace from the projected service-account token.
/// Falls back to `"default"` when running outside a cluster.
fn pod_namespace() -> String {
    std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "default".to_string())
}

/// Watches a Kubernetes ConfigMap and pushes config reloads through `tx`
/// whenever the ConfigMap data changes.
///
/// Runs indefinitely; spawn with `tokio::spawn`.
pub async fn watch_configmap(
    cfg: KubernetesConfig,
    tx: watch::Sender<Arc<LiveConfig>>,
    metrics: Arc<GatewayMetrics>,
) {
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                error = %e,
                "kubernetes: failed to build in-cluster client — ConfigMap watcher disabled"
            );
            return;
        }
    };

    let namespace = cfg.namespace.clone().unwrap_or_else(pod_namespace);
    let cms: Api<ConfigMap> = Api::namespaced(client, &namespace);
    let watcher_config =
        watcher::Config::default().fields(&format!("metadata.name={}", cfg.configmap_name));

    let source = format!("ConfigMap {}/{}", namespace, cfg.configmap_name);
    let mut stream = watcher(cms, watcher_config).boxed();
    let mut last_error: Option<std::time::Instant> = None;

    tracing::info!(
        configmap = %cfg.configmap_name,
        namespace = %namespace,
        key = %cfg.key,
        "kubernetes: ConfigMap watcher started"
    );

    while let Some(event) = stream.next().await {
        match event {
            Ok(watcher::Event::Apply(cm)) | Ok(watcher::Event::InitApply(cm)) => {
                if let Some(data) = cm.data
                    && let Some(yaml) = data.get(&cfg.key)
                {
                    reload::reload_from_yaml(yaml, &tx, &metrics, &mut last_error, &source);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "kubernetes: watcher error — will retry");
            }
            _ => {}
        }
    }
}

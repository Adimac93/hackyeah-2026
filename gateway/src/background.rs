//! Asynchronous semantic analysis: clean traffic is answered at deterministic
//! speed, and the semantic controls it skipped run afterwards. A hit is
//! recorded against the same trace and feeds the identity's risk score.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::json;
use uuid::Uuid;

use crate::audit::{self, EventRecord};
use crate::engine::{self, Evaluation, Verdict};
use crate::policy::{EscalateWhen, Hook, Policy};
use crate::state::AppState;

pub struct Job {
    pub policy: Arc<Policy>,
    pub hook: Hook,
    pub channel: &'static str,
    pub text: String,
    pub trace_id: Uuid,
    pub principal_id: Uuid,
    pub model: Option<String>,
    pub tool: Option<String>,
}

/// Queue the deferred controls for a request that did not escalate. Nothing
/// is spawned when the synchronous pass already ran them.
pub fn analyse(state: &AppState, evaluation: &Evaluation, job: Job) {
    let pending = !evaluation.suspicious
        && job.policy.semantic.iter().any(|c| {
            c.hooks.contains(&job.hook) && c.escalate_when == EscalateWhen::Suspicious
        });
    if !pending {
        return;
    }

    let state = state.clone();
    state.telemetry.queue_depth.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        let mut result = engine::deferred(&job.policy, job.hook, &job.text, &state.detectors).await;
        state.telemetry.queue_depth.fetch_sub(1, Ordering::Relaxed);
        state.telemetry.observe("semantic_async", result.semantic_us);

        // An outage is reported, not held against the caller: the request was
        // never refused for it, so it must not raise their risk either.
        let outages = result
            .detections
            .iter()
            .filter(|d| d.control_id.ends_with(".unavailable"))
            .count();
        for _ in 0..outages {
            state.telemetry.dependency("llm_judge", false);
        }
        result
            .detections
            .retain(|d| !d.control_id.ends_with(".unavailable"));
        if result.detections.is_empty() {
            return;
        }

        tracing::warn!(
            trace_id = %job.trace_id,
            controls = ?result.detections.iter().map(|d| &d.control_id).collect::<Vec<_>>(),
            "async semantic analysis found what the request path skipped",
        );
        state
            .auditor
            .record(EventRecord {
                trace_id: job.trace_id,
                hook: job.hook,
                channel: job.channel,
                principal_id: Some(job.principal_id),
                model: job.model.as_deref(),
                tool: job.tool.as_deref(),
                // The request was already answered; the verdict records what
                // happened to it, the detections what was found afterwards.
                verdict: Verdict::Allow,
                policy_version_id: job.policy.version_id,
                latency: json!({ "semantic_us": result.semantic_us, "async": true }),
                payload_sha256: audit::sha256_hex(job.text.as_bytes()),
                detections: &result.detections,
            })
            .await;
    });
}

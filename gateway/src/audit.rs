//! Tamper-evident audit log (task.md §4.5).
//!
//! Every intercepted interaction becomes one row in `events`, chained to the
//! one before it: `hash = sha256(prev_hash || canonical fields)`. Deleting or
//! editing a row breaks every hash after it, so the log can be shown to be
//! intact rather than asserted to be.
//!
//! Writes go through a mutex because a hash chain is inherently serial. At
//! hackathon traffic that costs nothing; a production version would shard the
//! chain per principal.

use std::fmt::Write as _;

use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::engine::{Detection, Evaluation, Verdict};
use crate::policy::Hook;

pub struct Auditor {
    db: PgPool,
    chain: Mutex<Vec<u8>>,
}

/// A registered caller: an agent, an application or a person.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: Uuid,
    pub slug: String,
    /// Deny-by-default: an empty list grants no model.
    pub allowed_models: Vec<String>,
    /// Deny-by-default: an empty list grants no tool.
    pub allowed_tools: Vec<String>,
}

impl Principal {
    pub fn may_use_model(&self, model: &str) -> bool {
        self.allowed_models.iter().any(|m| m == model)
    }

    pub fn may_call_tool(&self, tool: &str) -> bool {
        self.allowed_tools.iter().any(|t| t == tool)
    }
}

/// One interception, ready to be written.
pub struct EventRecord<'a> {
    pub trace_id: Uuid,
    pub hook: Hook,
    pub channel: &'static str,
    pub principal_id: Option<Uuid>,
    pub model: Option<&'a str>,
    pub tool: Option<&'a str>,
    pub verdict: Verdict,
    pub policy_version_id: Option<i64>,
    pub latency: serde_json::Value,
    pub payload_sha256: String,
    pub detections: &'a [Detection],
}

impl Auditor {
    /// Reads the tail of the existing chain so a restart continues it rather
    /// than starting a second, unverifiable one.
    pub async fn new(db: PgPool) -> Self {
        let tail = sqlx::query_scalar::<_, Vec<u8>>("select hash from events order by id desc limit 1")
            .fetch_optional(&db)
            .await
            .unwrap_or_else(|error| {
                tracing::error!(%error, "could not read the audit chain tail");
                None
            })
            .unwrap_or_default();
        if !tail.is_empty() {
            tracing::info!(tail = %hex(&tail)[..12].to_owned(), "continuing the audit chain");
        }
        Self {
            db,
            chain: Mutex::new(tail),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.db
    }

    /// Resolve an enabled principal from an API key. The registry stores only
    /// the digest, never a bearer secret. HTTP handlers must use this method,
    /// not a caller-supplied principal slug.
    pub async fn principal_for_api_key(&self, api_key: &str) -> Option<Principal> {
        let row = sqlx::query_as::<_, (Uuid, String, Vec<String>, Vec<String>)>(
            "select id, slug, allowed_models, allowed_tools
             from principals where api_key_hash = $1 and enabled",
        )
        .bind(sha256_hex(api_key.as_bytes()))
        .fetch_optional(&self.db)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, "API-key principal lookup failed");
            None
        })?;

        Some(Principal {
            id: row.0,
            slug: row.1,
            allowed_models: row.2,
            allowed_tools: row.3,
        })
    }

    pub async fn record_usage(
        &self,
        event_id: Option<i64>,
        principal: Option<Uuid>,
        model: &str,
        prompt_tokens: i32,
        completion_tokens: i32,
        cost_usd: f64,
    ) {
        let result = sqlx::query(
            "insert into usage
               (event_id, principal_id, model, prompt_tokens, completion_tokens, cost_usd)
             values ($1, $2, $3, $4, $5, $6)",
        )
        .bind(event_id)
        .bind(principal)
        .bind(model)
        .bind(prompt_tokens)
        .bind(completion_tokens)
        .bind(cost_usd)
        .execute(&self.db)
        .await;

        if let Err(error) = result {
            tracing::error!(%error, "could not record usage");
        }
    }

    /// Append one event and its detections. Returns the event id.
    pub async fn record(&self, record: EventRecord<'_>) -> Option<i64> {
        let pool = &self.db;

        // The chain is held across the insert so two concurrent requests cannot
        // compute their hashes from the same predecessor.
        let mut chain = self.chain.lock().await;
        let hash = next_hash(&chain, &record);

        let mut tx = match pool.begin().await {
            Ok(tx) => tx,
            Err(error) => {
                tracing::error!(%error, "could not open the audit transaction");
                return None;
            }
        };

        let event_id = sqlx::query_scalar::<_, i64>(
            "insert into events
               (trace_id, hook, channel, principal_id, model, tool, verdict,
                policy_version_id, latency, payload_sha256, prev_hash, hash)
             values ($1, $2::text::hook, $3::text::channel, $4, $5, $6,
                     $7::text::verdict, $8, $9, $10, $11, $12)
             returning id",
        )
        .bind(record.trace_id)
        .bind(hook_name(record.hook))
        .bind(record.channel)
        .bind(record.principal_id)
        .bind(record.model)
        .bind(record.tool)
        .bind(verdict_name(record.verdict))
        .bind(record.policy_version_id)
        .bind(&record.latency)
        .bind(&record.payload_sha256)
        .bind(if chain.is_empty() {
            None
        } else {
            Some(chain.clone())
        })
        .bind(&hash)
        .fetch_one(&mut *tx)
        .await;

        let event_id = match event_id {
            Ok(id) => id,
            Err(error) => {
                tracing::error!(%error, "could not write the audit event");
                return None;
            }
        };

        for detection in record.detections {
            let evidence = serde_json::to_value(&detection.evidence).unwrap_or_default();
            let result = sqlx::query(
                "insert into detections (event_id, control_id, kind, severity, score, action, evidence)
                 values ($1, $2, $3::text::control_kind, $4::text::severity, $5,
                         $6::text::control_action, $7)",
            )
            .bind(event_id)
            .bind(&detection.control_id)
            .bind(kind_name(detection.kind))
            .bind(severity_name(detection.severity))
            .bind(detection.score)
            .bind(action_name(detection.action))
            .bind(evidence)
            .execute(&mut *tx)
            .await;

            if let Err(error) = result {
                tracing::error!(%error, control = %detection.control_id, "could not write a detection");
            }

            // Keep only non-sensitive behavioral metadata for repeated-attack
            // scoring. The prompt itself remains represented by its hash.
            if counts_as_attack(detection) {
                let result = sqlx::query(
                    "insert into attack_history (principal_id, trace_id, control_id, action, risk_score)
                     values ($1, $2, $3, $4::text::control_action, $5)",
                )
                .bind(record.principal_id)
                .bind(record.trace_id)
                .bind(&detection.control_id)
                .bind(action_name(detection.action))
                .bind(risk_for(detection.severity))
                .execute(&mut *tx)
                .await;
                if let Err(error) = result {
                    tracing::error!(%error, "could not write attack history");
                }
            }
        }

        if let Err(error) = tx.commit().await {
            tracing::error!(%error, "could not commit the audit transaction");
            return None;
        }

        *chain = hash;
        Some(event_id)
    }
}

/// Blocked and flagged content feeds the risk score. Refusals on spend or on
/// the score itself do not: an exhausted budget is not an attack, and a
/// history refusal that raised the history would never expire.
fn counts_as_attack(detection: &Detection) -> bool {
    matches!(
        detection.action,
        crate::policy::Action::Block | crate::policy::Action::Flag
    ) && !detection.control_id.starts_with(crate::budget::BUDGET_PREFIX)
        && detection.control_id != crate::risk::RISK_CONTROL
}

const fn risk_for(severity: crate::policy::Severity) -> f32 {
    match severity {
        crate::policy::Severity::Info => 0.05,
        crate::policy::Severity::Low => 0.15,
        crate::policy::Severity::Medium => 0.35,
        crate::policy::Severity::High => 0.65,
        crate::policy::Severity::Critical => 1.0,
    }
}

/// `sha256(prev_hash || the fields a tamperer would want to change)`.
fn next_hash(prev: &[u8], record: &EventRecord<'_>) -> Vec<u8> {
    let detections: Vec<_> = record
        .detections
        .iter()
        .map(|d| (d.control_id.as_str(), action_name(d.action)))
        .collect();
    chain_hash(
        prev,
        record.trace_id,
        hook_name(record.hook),
        verdict_name(record.verdict),
        &record.payload_sha256,
        &detections,
    )
}

/// The chain function, expressed over plain values so the verifier can
/// recompute a hash from database rows alone. Changing this invalidates every
/// existing chain, which is the point.
pub fn chain_hash(
    prev: &[u8],
    trace_id: Uuid,
    hook: &str,
    verdict: &str,
    payload_sha256: &str,
    detections: &[(&str, &str)],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(trace_id.as_bytes());
    hasher.update(hook.as_bytes());
    hasher.update(verdict.as_bytes());
    hasher.update(payload_sha256.as_bytes());
    for (control_id, action) in detections {
        hasher.update(control_id.as_bytes());
        hasher.update(action.as_bytes());
    }
    hasher.finalize().to_vec()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

const fn hook_name(hook: Hook) -> &'static str {
    match hook {
        Hook::PromptIn => "prompt_in",
        Hook::ResponseOut => "response_out",
        Hook::ToolCall => "tool_call",
        Hook::ToolResult => "tool_result",
    }
}

const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Redact => "redact",
        Verdict::Block => "block",
    }
}

const fn kind_name(kind: crate::engine::ControlKind) -> &'static str {
    match kind {
        crate::engine::ControlKind::Deterministic => "deterministic",
        crate::engine::ControlKind::Semantic => "semantic",
    }
}

const fn severity_name(severity: crate::policy::Severity) -> &'static str {
    use crate::policy::Severity::{Critical, High, Info, Low, Medium};
    match severity {
        Info => "info",
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    }
}

const fn action_name(action: crate::policy::Action) -> &'static str {
    use crate::policy::Action::{Allow, Block, Flag, Redact};
    match action {
        Allow => "allow",
        Flag => "flag",
        Redact => "redact",
        Block => "block",
    }
}

/// Convenience for the proxy: build a record from an evaluation.
pub fn record_for<'a>(
    trace_id: Uuid,
    hook: Hook,
    evaluation: &'a Evaluation,
    model: Option<&'a str>,
    principal_id: Option<Uuid>,
    policy_version_id: Option<i64>,
    payload: &str,
) -> EventRecord<'a> {
    EventRecord {
        trace_id,
        hook,
        channel: "llm",
        principal_id,
        model,
        tool: None,
        verdict: evaluation.verdict,
        policy_version_id,
        latency: serde_json::json!({
            "deterministic_us": evaluation.deterministic_us,
            "semantic_us": evaluation.semantic_us,
        }),
        payload_sha256: sha256_hex(payload.as_bytes()),
        detections: &evaluation.detections,
    }
}

/// Walk the chain and report which events, if any, no longer reproduce their
/// stored hash. Shared by the verifier and the report so the two can never
/// disagree about whether the log is intact.
pub async fn verify_chain(pool: &PgPool) -> sqlx::Result<(i64, Vec<i64>)> {
    let events = sqlx::query_as::<
        _,
        (
            i64,
            Uuid,
            String,
            String,
            Option<String>,
            Option<Vec<u8>>,
            Vec<u8>,
        ),
    >(
        "select id, trace_id, hook::text, verdict::text, payload_sha256, prev_hash, hash
         from events order by id",
    )
    .fetch_all(pool)
    .await?;

    let mut previous: Vec<u8> = Vec::new();
    let mut broken = Vec::new();

    for (id, trace_id, hook, verdict, payload, prev_hash, stored) in &events {
        let detections = sqlx::query_as::<_, (String, String)>(
            "select control_id, action::text from detections where event_id = $1 order by id",
        )
        .bind(id)
        .fetch_all(pool)
        .await?;

        let borrowed: Vec<(&str, &str)> = detections
            .iter()
            .map(|(c, a)| (c.as_str(), a.as_str()))
            .collect();

        let recomputed = chain_hash(
            &previous,
            *trace_id,
            hook,
            verdict,
            payload.as_deref().unwrap_or_default(),
            &borrowed,
        );

        if &recomputed != stored || prev_hash.clone().unwrap_or_default() != previous {
            broken.push(*id);
        }
        previous.clone_from(stored);
    }

    Ok((i64::try_from(events.len()).unwrap_or(i64::MAX), broken))
}

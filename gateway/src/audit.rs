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
    /// Identities by key digest, used instead of `principals` by the
    /// self-test suite, which runs without a database. Always `None` in the
    /// service.
    fixed: Option<std::collections::HashMap<String, Principal>>,
}

/// A registered caller: an agent, an application or a person.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: Uuid,
    pub slug: String,
    /// `security_admin` may call the approvals admin routes with its API key.
    pub role: String,
    /// Deny-by-default: an empty list grants no model.
    pub allowed_models: Vec<String>,
    /// Deny-by-default: an empty list grants no tool.
    pub allowed_tools: Vec<String>,
    /// May name the end user it acts for in `X-On-Behalf-Of`.
    pub delegates_users: bool,
    /// Who budgets, risk and activity are attributed to: the delegated end
    /// user, or this principal's own slug.
    pub user: String,
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
    pub end_user: Option<&'a str>,
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
            fixed: None,
        }
    }

    /// An auditor whose identities are `(api key, principal)` pairs held in
    /// memory. Writes still go to `db`, so a pool that reaches nothing makes
    /// every write a logged no-op.
    #[cfg(test)]
    pub(crate) fn with_principals(db: PgPool, principals: Vec<(&str, Principal)>) -> Self {
        Self {
            db,
            chain: Mutex::default(),
            fixed: Some(
                principals
                    .into_iter()
                    .map(|(key, principal)| (sha256_hex(key.as_bytes()), principal))
                    .collect(),
            ),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.db
    }

    /// Resolve an enabled principal from an API key. The registry stores only
    /// the digest, never a bearer secret. HTTP handlers must use this method,
    /// not a caller-supplied principal slug.
    pub async fn principal_for_api_key(&self, api_key: &str) -> Option<Principal> {
        if let Some(fixed) = &self.fixed {
            return fixed.get(&sha256_hex(api_key.as_bytes())).cloned();
        }
        let row = sqlx::query_as::<_, (Uuid, String, String, Vec<String>, Vec<String>, bool)>(
            "select id, slug, role, allowed_models, allowed_tools, delegates_users
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
            user: row.1.clone(),
            slug: row.1,
            role: row.2,
            allowed_models: row.3,
            allowed_tools: row.4,
            delegates_users: row.5,
        })
    }

    pub async fn record_usage(
        &self,
        event_id: Option<i64>,
        principal: &Principal,
        model: &str,
        prompt_tokens: i32,
        completion_tokens: i32,
        cost_usd: f64,
    ) {
        let result = sqlx::query(
            "insert into usage
               (event_id, principal_id, end_user, model, prompt_tokens, completion_tokens, cost_usd)
             values ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event_id)
        .bind(principal.id)
        .bind(&principal.user)
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
               (trace_id, hook, channel, principal_id, end_user, model, tool, verdict,
                policy_version_id, latency, payload_sha256, prev_hash, hash)
             values ($1, $2::text::hook, $3::text::channel, $4, $5, $6, $7,
                     $8::text::verdict, $9, $10, $11, $12, $13)
             returning id",
        )
        .bind(record.trace_id)
        .bind(hook_name(record.hook))
        .bind(record.channel)
        .bind(record.principal_id)
        .bind(record.end_user)
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
                return abandon(tx).await;
            }

            // Keep only non-sensitive behavioral metadata for repeated-attack
            // scoring. The prompt itself remains represented by its hash.
            if crate::risk::counts(detection) {
                let result = sqlx::query(
                    "insert into attack_history
                       (principal_id, end_user, trace_id, control_id, action, risk_score)
                     values ($1, $2, $3, $4, $5::text::control_action, $6)",
                )
                .bind(record.principal_id)
                .bind(record.end_user)
                .bind(record.trace_id)
                .bind(&detection.control_id)
                .bind(action_name(detection.action))
                .bind(crate::risk::weight(detection.severity))
                .execute(&mut *tx)
                .await;
                if let Err(error) = result {
                    tracing::error!(%error, "could not write attack history");
                    return abandon(tx).await;
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

/// A failed statement aborts a Postgres transaction, and `COMMIT` on an
/// aborted transaction is a silent `ROLLBACK` that the driver reports as
/// success. Committing anyway would advance the in-memory chain past an event
/// that was never stored — a permanent gap. Roll back and leave the chain alone.
async fn abandon(tx: sqlx::Transaction<'_, sqlx::Postgres>) -> Option<i64> {
    if let Err(error) = tx.rollback().await {
        tracing::error!(%error, "could not roll back the audit transaction");
    }
    None
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
    principal: &'a Principal,
    policy_version_id: Option<i64>,
    payload: &str,
) -> EventRecord<'a> {
    EventRecord {
        trace_id,
        hook,
        channel: "llm",
        principal_id: Some(principal.id),
        end_user: Some(&principal.user),
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

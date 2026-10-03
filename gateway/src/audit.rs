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
    /// Absent when `DATABASE_URL` is unset: the gateway still enforces, it just
    /// cannot persist. Enforcement must not depend on the logger being up.
    db: Option<PgPool>,
    chain: Mutex<Vec<u8>>,
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
    pub async fn new(db: Option<PgPool>) -> Self {
        let tail = match &db {
            None => Vec::new(),
            Some(pool) => {
                sqlx::query_scalar::<_, Vec<u8>>("select hash from events order by id desc limit 1")
                    .fetch_optional(pool)
                    .await
                    .unwrap_or_else(|error| {
                        tracing::error!(%error, "could not read the audit chain tail");
                        None
                    })
                    .unwrap_or_default()
            }
        };
        if !tail.is_empty() {
            tracing::info!(tail = %hex(&tail)[..12].to_owned(), "continuing the audit chain");
        }
        Self {
            db,
            chain: Mutex::new(tail),
        }
    }

    pub fn enabled(&self) -> bool {
        self.db.is_some()
    }

    /// Record the policy the gateway is running under, returning its row id so
    /// each decision can point at the exact catalog text that produced it.
    pub async fn register_policy(&self, sha256: &str, source: &str) -> Option<i64> {
        let pool = self.db.as_ref()?;
        let result = sqlx::query_scalar::<_, i64>(
            "insert into policy_versions (sha256, source) values ($1, $2)
             on conflict (sha256) do update set loaded_at = now(), active = true
             returning id",
        )
        .bind(sha256)
        .bind(source)
        .fetch_one(pool)
        .await;

        match result {
            Ok(id) => Some(id),
            Err(error) => {
                tracing::error!(%error, "could not register the policy version");
                None
            }
        }
    }

    /// Resolve a principal slug to its id. Unknown slugs return `None`; the
    /// gateway records the event without an owner rather than inventing one.
    pub async fn principal_id(&self, slug: &str) -> Option<Uuid> {
        let pool = self.db.as_ref()?;
        sqlx::query_scalar::<_, Uuid>("select id from principals where slug = $1 and enabled")
            .bind(slug)
            .fetch_optional(pool)
            .await
            .unwrap_or_default()
    }

    /// Tokens spent by a principal inside the trailing window.
    pub async fn tokens_used(&self, principal: Option<Uuid>, window_secs: i32) -> i64 {
        let Some(pool) = self.db.as_ref() else {
            return 0;
        };
        let used = sqlx::query_scalar::<_, Option<i64>>(
            "select sum(prompt_tokens + completion_tokens)::bigint from usage
             where ts > now() - make_interval(secs => $1::int)
               and ($2::uuid is null or principal_id = $2::uuid)",
        )
        .bind(window_secs)
        .bind(principal)
        .fetch_one(pool)
        .await;

        match used {
            Ok(total) => total.unwrap_or(0),
            Err(error) => {
                tracing::error!(%error, "budget lookup failed");
                0
            }
        }
    }

    pub async fn record_usage(
        &self,
        event_id: Option<i64>,
        principal: Option<Uuid>,
        model: &str,
        prompt_tokens: i32,
        completion_tokens: i32,
    ) {
        let Some(pool) = self.db.as_ref() else {
            return;
        };
        let result = sqlx::query(
            "insert into usage (event_id, principal_id, model, prompt_tokens, completion_tokens)
             values ($1, $2, $3, $4, $5)",
        )
        .bind(event_id)
        .bind(principal)
        .bind(model)
        .bind(prompt_tokens)
        .bind(completion_tokens)
        .execute(pool)
        .await;

        if let Err(error) = result {
            tracing::error!(%error, "could not record usage");
        }
    }

    /// Append one event and its detections. Returns the event id.
    pub async fn record(&self, record: EventRecord<'_>) -> Option<i64> {
        let pool = self.db.as_ref()?;

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
        }

        if let Err(error) = tx.commit().await {
            tracing::error!(%error, "could not commit the audit transaction");
            return None;
        }

        *chain = hash;
        Some(event_id)
    }
}

/// `sha256(prev_hash || the fields a tamperer would want to change)`.
fn next_hash(prev: &[u8], record: &EventRecord<'_>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(record.trace_id.as_bytes());
    hasher.update(hook_name(record.hook).as_bytes());
    hasher.update(verdict_name(record.verdict).as_bytes());
    hasher.update(record.payload_sha256.as_bytes());
    for detection in record.detections {
        hasher.update(detection.control_id.as_bytes());
        hasher.update(action_name(detection.action).as_bytes());
    }
    hasher.finalize().to_vec()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
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
        latency: serde_json::json!({ "deterministic_us": evaluation.deterministic_us }),
        payload_sha256: sha256_hex(payload.as_bytes()),
        detections: &evaluation.detections,
    }
}

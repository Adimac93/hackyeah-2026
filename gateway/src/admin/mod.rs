//! The admin API the SecOps console calls for live state and for every write
//! to gateway state (docs/BACKEND.md, "Admin dashboard backend API"). The
//! console reads persisted data through the Data API; it changes gateway state
//! only here, and every change — accepted or rejected — lands in
//! `admin_actions`.

pub mod auth;
pub mod budgets;
pub mod export;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::policy::{self, Policy, store};
use crate::state::AppState;
use auth::{Access, Admin, refusal};

/// Record one state-changing admin call. Best effort: the change itself has
/// already been decided, and a lost audit row is logged, not hidden.
pub async fn record_action(
    pool: &PgPool,
    admin: &Admin,
    action: &str,
    target: Option<&str>,
    accepted: bool,
    detail: Value,
) {
    let result = sqlx::query(
        "insert into admin_actions (actor_user_id, actor_email, action, target, outcome, detail)
         values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(admin.user_id)
    .bind(&admin.email)
    .bind(action)
    .bind(target)
    .bind(if accepted { "accepted" } else { "rejected" })
    .bind(detail)
    .execute(pool)
    .await;
    if let Err(error) = result {
        tracing::error!(%error, action, "could not record the admin action");
    }
}

/// What the gateway is enforcing right now: the version every new decision
/// will point at, and each active control.
pub async fn active_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = state.admins.require(state.db(), &headers, Access::Read).await {
        return response;
    }
    Json(describe(&state.policy.load())).into_response()
}

pub fn describe(policy: &Policy) -> Value {
    let deterministic: Vec<Value> = policy
        .deterministic
        .iter()
        .chain(&policy.signature_controls)
        .map(|c| {
            json!({
                "id": c.id, "kind": "deterministic", "action": c.action,
                "severity": c.severity, "hooks": sorted_hooks(&c.hooks), "feed": c.feed,
            })
        })
        .collect();
    let semantic: Vec<Value> = policy
        .semantic
        .iter()
        .map(|c| {
            json!({
                "id": c.id, "kind": "semantic", "action": c.action, "severity": c.severity,
                "hooks": sorted_hooks(&c.hooks), "detector": c.detector,
                "threshold": c.threshold, "escalate_when": c.escalate_when,
                "fail_mode": c.fail_mode,
            })
        })
        .collect();
    json!({
        "version": policy.sha256,
        "version_id": policy.version_id,
        "source": policy.source,
        "profile": policy.profile,
        "on_detect": policy.on_detect,
        "fail_mode": policy.fail_mode,
        "models": policy.models,
        "signature_feed": policy.feed.as_ref().map(|f| json!({
            "source": f.source, "version": f.version, "signatures": f.entries.len(),
        })),
        "risk": policy.risk,
        "runaway": policy.runaway,
        "mcp_servers": policy.mcp.servers.iter().map(|s| json!({
            "name": s.name, "enabled": s.enabled, "pinned_tools": s.pinned.len(),
        })).collect::<Vec<_>>(),
        "controls": deterministic.into_iter().chain(semantic).collect::<Vec<_>>(),
    })
}

fn sorted_hooks(hooks: &std::collections::HashSet<policy::Hook>) -> Vec<policy::Hook> {
    let mut hooks: Vec<_> = hooks.iter().copied().collect();
    hooks.sort_by_key(|h| *h as u8);
    hooks
}

/// Version history with the diff each upload produced.
pub async fn policy_versions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = state.admins.require(state.db(), &headers, Access::Read).await {
        return response;
    }
    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            String,
            bool,
            Option<String>,
            Option<uuid::Uuid>,
            bool,
        ),
    >(
        "select id, sha256, source, to_char(loaded_at at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                active, diff_summary, uploaded_by_user, signatures_toml is not null
         from policy_versions where catalog_toml is not null
         order by loaded_at desc limit 100",
    )
    .fetch_all(state.db())
    .await;
    match rows {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| {
                    json!({
                        "id": r.0, "version": r.1, "source": r.2, "loaded_at": r.3,
                        "active": r.4, "diff": r.5, "uploaded_by": r.6, "has_signatures": r.7,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            tracing::error!(%error, "policy history query failed");
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "policy history is temporarily unavailable",
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpload {
    catalog_toml: String,
    /// Absent keeps the active feed; an empty string removes it.
    #[serde(default)]
    signatures_toml: Option<String>,
}

/// Validate, store and activate a catalog. An invalid upload never touches the
/// active policy.
pub async fn upload_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(upload): Json<PolicyUpload>,
) -> Response {
    let admin = match state.admins.require(state.db(), &headers, Access::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let pool = state.db();

    if upload.catalog_toml.trim().is_empty() {
        record_action(pool, &admin, "policy.upload", None, false, json!({ "error": "empty catalog" })).await;
        return refusal(
            StatusCode::BAD_REQUEST,
            "invalid_policy",
            "catalog_toml must not be empty",
        );
    }

    let current = state.policy.load_full();
    let signatures = match upload.signatures_toml {
        Some(text) => Some(text).filter(|t| !t.trim().is_empty()),
        None => current.feed.as_ref().map(|f| f.text.clone()),
    };
    let origin = format!(
        "upload by {}",
        admin.email.as_deref().unwrap_or("unknown user")
    );
    let mut next = match Policy::compile(&upload.catalog_toml, signatures.as_deref(), &origin) {
        Ok(policy) => policy,
        Err(error) => {
            let message = error.to_string();
            record_action(pool, &admin, "policy.upload", None, false, json!({ "error": message })).await;
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": { "type": "invalid_policy", "message": message } })),
            )
                .into_response();
        }
    };

    let lines = policy::diff(&current, &next);
    let summary = if lines.is_empty() {
        "no changes to enforcement".to_owned()
    } else {
        lines.join("\n")
    };

    let id = match store::activate(
        pool,
        &next,
        &upload.catalog_toml,
        signatures.as_deref(),
        Some(admin.user_id),
        &summary,
        false,
    )
    .await
    {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => {
            record_action(pool, &admin, "policy.upload", None, false, json!({ "error": "storage unavailable" })).await;
            return refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "policy storage is unavailable; the active policy is unchanged",
            );
        }
    };
    next.version_id = Some(id);
    let version = next.sha256.clone();
    let changed = state.policy.replace(next);
    store::mirror_signatures(pool, &state.policy.load()).await;

    record_action(
        pool,
        &admin,
        "policy.upload",
        Some(&version),
        true,
        json!({ "version_id": id, "diff": lines }),
    )
    .await;

    Json(json!({
        "accepted": true,
        "changed": changed,
        "version": version,
        "version_id": id,
        "diff": lines,
    }))
    .into_response()
}

/// The 24-hour management and security report, live.
pub async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = state.admins.require(state.db(), &headers, Access::Read).await {
        return response;
    }
    match crate::metrics::collect(state.db(), 24).await {
        Ok(report) => Json(json!(report)).into_response(),
        Err(error) => {
            tracing::error!(%error, "metrics query failed");
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "metrics temporarily unavailable",
            )
        }
    }
}

//! Per-user risk scores for the console, judged by the thresholds of the
//! policy the gateway enforces right now. The score is the same sum
//! `risk::apply` gates on, so the console shows what the next request faces.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth::{Access, refusal};
use crate::risk::{self, Outcome};
use crate::state::AppState;

const MAX_USERS: i64 = 500;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    /// Case-insensitive substring of the user.
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserRisk {
    pub user: String,
    pub score: f64,
    /// `normal`, `escalate` (every request runs the semantic tier) or `block`.
    pub status: &'static str,
    /// Blocked or flagged detections inside the window.
    pub violations: i64,
    pub last_violation: Option<String>,
    pub last_seen: String,
    /// Principals that carried this user's traffic.
    pub principals: Vec<String>,
}

pub const fn status_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Normal => "normal",
        Outcome::Escalate => "escalate",
        Outcome::Block => "block",
    }
}

/// Every user the gateway has seen, highest score first.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filters): Query<Filters>,
) -> Response {
    if let Err(response) = state.admins.require(state.db(), &headers, Access::Read).await {
        return response;
    }
    let policy = state.policy.load();
    let query = filters.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    let rows = sqlx::query_as::<_, (String, f64, i64, Option<String>, String, Vec<String>)>(
        "with seen as (
           select e.end_user, max(e.ts) as last_seen,
                  array_agg(distinct p.slug) filter (where p.slug is not null) as principals
           from events e left join principals p on p.id = e.principal_id
           where e.end_user is not null
             and ($1::text is null or strpos(lower(e.end_user), lower($1)) > 0)
           group by e.end_user
         ), risk as (
           select end_user, sum(risk_score)::float8 as score, count(*) as violations,
                  max(created_at) as last_violation
           from attack_history
           where end_user is not null
             and created_at > now() - make_interval(secs => $2::int)
           group by end_user
         )
         select s.end_user, coalesce(r.score, 0), coalesce(r.violations, 0),
                to_char(r.last_violation at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                to_char(s.last_seen at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                coalesce(s.principals, '{}')
         from seen s left join risk r on r.end_user = s.end_user
         order by 2 desc, s.last_seen desc
         limit $3",
    )
    .bind(query)
    .bind(policy.risk.window_secs)
    .bind(filters.limit.unwrap_or(MAX_USERS).clamp(1, MAX_USERS))
    .fetch_all(state.db())
    .await;

    match rows {
        Ok(rows) => {
            let users: Vec<UserRisk> = rows
                .into_iter()
                .map(|r| UserRisk {
                    #[expect(clippy::cast_possible_truncation, reason = "the gate compares an f32")]
                    status: status_name(risk::assess(&policy.risk, r.1 as f32)),
                    user: r.0,
                    score: r.1,
                    violations: r.2,
                    last_violation: r.3,
                    last_seen: r.4,
                    principals: r.5,
                })
                .collect();
            Json(json!({
                "window_secs": policy.risk.window_secs,
                "escalate_at": policy.risk.escalate_at,
                "block_at": policy.risk.block_at,
                "users": users,
            }))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "risk query failed");
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "risk scores are temporarily unavailable",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Risk;

    #[test]
    fn status_follows_the_active_thresholds() {
        let risk = Risk {
            window_secs: 3_600,
            escalate_at: Some(1.0),
            block_at: Some(3.0),
        };
        assert_eq!(status_name(risk::assess(&risk, 0.5)), "normal");
        assert_eq!(status_name(risk::assess(&risk, 1.0)), "escalate");
        assert_eq!(status_name(risk::assess(&risk, 3.5)), "block");
    }
}

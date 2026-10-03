//! Budget and resource governance (task.md §4.3).
//!
//! Budgets are rows in `budgets`, edited only through the admin API. Each row
//! scopes a trailing window to everyone (`global`), one user (`user`: the
//! delegated end user, or a principal acting for no one under its slug) or one
//! model (`model`), and may limit tokens, USD, request count and in-flight
//! concurrency. A hard budget blocks; a soft one is
//! recorded and lets the request through.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::audit::Principal;
use crate::engine::Evaluation;
use crate::policy::{Action, Severity};

/// Budget detections are `budget.global`, `budget.user.<user>` and
/// `budget.model.<name>`, mirroring the row's scope.
pub const BUDGET_PREFIX: &str = "budget.";

/// Edits through the admin API invalidate the cache at once on this instance;
/// other instances see them within this long.
const CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize)]
pub struct BudgetRow {
    pub id: i64,
    pub scope: String,
    pub scope_id: Option<String>,
    pub window_secs: i32,
    pub limit_tokens: Option<i64>,
    pub limit_usd: Option<f64>,
    pub limit_requests: Option<i64>,
    pub limit_concurrency: Option<i32>,
    pub hard: bool,
}

impl BudgetRow {
    fn key(&self) -> String {
        match &self.scope_id {
            Some(id) => format!("{}.{id}", self.scope),
            None => self.scope.clone(),
        }
    }

    fn applies(&self, principal: &Principal, model: Option<&str>) -> bool {
        match self.scope.as_str() {
            "global" => true,
            "user" => self.scope_id.as_deref() == Some(principal.user.as_str()),
            "model" => model.is_some() && self.scope_id.as_deref() == model,
            _ => false,
        }
    }
}

/// What has been spent against one budget row inside its window.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Used {
    pub tokens: i64,
    pub usd: f64,
    pub requests: i64,
    pub inflight: i64,
}

/// The first limit this usage reaches, as a reason a human can read.
pub fn exceeded(row: &BudgetRow, used: &Used) -> Option<String> {
    let spent = if let Some(limit) = row.limit_tokens.filter(|l| used.tokens >= *l) {
        format!("{}/{limit} tokens", used.tokens)
    } else if let Some(limit) = row.limit_usd.filter(|l| used.usd >= *l) {
        format!("${:.4}/${limit:.2}", used.usd)
    } else if let Some(limit) = row.limit_requests.filter(|l| used.requests >= *l) {
        format!("{}/{limit} requests", used.requests)
    } else if let Some(limit) = row
        .limit_concurrency
        .filter(|l| used.inflight >= i64::from(*l))
    {
        return Some(format!(
            "{} budget exhausted: {}/{limit} requests in flight",
            row.key(),
            used.inflight
        ));
    } else {
        return None;
    };
    Some(format!(
        "{} budget exhausted: {spent} in the last {}s",
        row.key(),
        row.window_secs
    ))
}

pub struct Budgets {
    pool: PgPool,
    cache: Mutex<Option<(Instant, Arc<Vec<BudgetRow>>)>>,
    /// Per-instance in-flight counters, keyed like detections. Concurrency is
    /// enforced per gateway instance.
    inflight: Mutex<HashMap<String, i64>>,
}

/// Holds a request's in-flight slots; releases them when dropped.
pub struct Inflight<'a> {
    budgets: &'a Budgets,
    keys: Vec<String>,
}

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        if let Ok(mut inflight) = self.budgets.inflight.lock() {
            for key in &self.keys {
                if let Some(count) = inflight.get_mut(key) {
                    *count -= 1;
                }
            }
        }
    }
}

impl Budgets {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Mutex::default(),
            inflight: Mutex::default(),
        }
    }

    pub fn invalidate(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            *cache = None;
        }
    }

    pub async fn rows(&self) -> Arc<Vec<BudgetRow>> {
        if let Ok(cache) = self.cache.lock()
            && let Some((at, rows)) = cache.as_ref()
            && at.elapsed() < CACHE_TTL
        {
            return Arc::clone(rows);
        }
        let rows = Arc::new(self.load().await.unwrap_or_else(|error| {
            tracing::error!(%error, "could not read budgets — enforcing none until it recovers");
            Vec::new()
        }));
        if let Ok(mut cache) = self.cache.lock() {
            *cache = Some((Instant::now(), Arc::clone(&rows)));
        }
        rows
    }

    async fn load(&self) -> sqlx::Result<Vec<BudgetRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                i32,
                Option<i64>,
                Option<f64>,
                Option<i64>,
                Option<i32>,
                bool,
            ),
        >(
            "select id, scope::text, scope_id, window_secs, limit_tokens, limit_usd::float8,
                    limit_requests, limit_concurrency, hard
             from budgets where enabled order by scope, scope_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| BudgetRow {
                id: r.0,
                scope: r.1,
                scope_id: r.2,
                window_secs: r.3,
                limit_tokens: r.4,
                limit_usd: r.5,
                limit_requests: r.6,
                limit_concurrency: r.7,
                hard: r.8,
            })
            .collect())
    }

    /// Gate the evaluation on every budget that applies, then take this
    /// request's in-flight slots. Keep the returned guard alive until the
    /// request is finished.
    pub async fn check(
        &self,
        principal: &Principal,
        model: Option<&str>,
        evaluation: &mut Evaluation,
    ) -> Inflight<'_> {
        let rows = self.rows().await;
        let applicable: Vec<&BudgetRow> = rows
            .iter()
            .filter(|row| row.applies(principal, model))
            .collect();

        let mut spent = Vec::with_capacity(applicable.len());
        for row in &applicable {
            let owner = (row.scope == "user").then_some(principal.user.as_str());
            let model = (row.scope == "model").then_some(model).flatten();
            spent.push(self.used(row, owner, model).await);
        }

        let mut keys = Vec::new();
        if let Ok(mut inflight) = self.inflight.lock() {
            for (row, used) in applicable.iter().zip(spent.iter_mut()) {
                used.inflight = inflight.get(&row.key()).copied().unwrap_or(0);
            }
            for row in &applicable {
                *inflight.entry(row.key()).or_default() += 1;
                keys.push(row.key());
            }
        }

        for (row, used) in applicable.iter().zip(&spent) {
            let Some(reason) = exceeded(row, used) else {
                continue;
            };
            let (severity, action) = if row.hard {
                (Severity::High, Action::Block)
            } else {
                tracing::warn!(budget = %row.key(), %reason, "soft budget exceeded");
                (Severity::Low, Action::Allow)
            };
            evaluation.gate(
                format!("{BUDGET_PREFIX}{}", row.key()),
                severity,
                action,
                reason,
            );
        }

        Inflight { budgets: self, keys }
    }

    /// The budgets that bind this user whatever the model, with what has
    /// been spent against each: what an agent is told about its own limits.
    pub async fn standing(&self, principal: &Principal) -> Vec<(BudgetRow, Used)> {
        let rows = self.rows().await;
        let mut standing = Vec::new();
        for row in rows.iter().filter(|row| row.applies(principal, None)) {
            let owner = (row.scope == "user").then_some(principal.user.as_str());
            standing.push((row.clone(), self.used(row, owner, None).await));
        }
        standing
    }

    async fn used(&self, row: &BudgetRow, owner: Option<&str>, model: Option<&str>) -> Used {
        let mut used = Used::default();
        if row.limit_tokens.is_some() || row.limit_usd.is_some() {
            let spent = sqlx::query_as::<_, (i64, f64)>(
                "select coalesce(sum(prompt_tokens + completion_tokens), 0)::bigint,
                        coalesce(sum(cost_usd), 0)::float8
                 from usage
                 where ts > now() - make_interval(secs => $1::int)
                   and ($2::text is null or end_user = $2::text)
                   and ($3::text is null or model = $3::text)",
            )
            .bind(row.window_secs)
            .bind(owner)
            .bind(model)
            .fetch_one(&self.pool)
            .await;
            match spent {
                Ok((tokens, usd)) => (used.tokens, used.usd) = (tokens, usd),
                Err(error) => tracing::error!(%error, "budget usage lookup failed"),
            }
        }
        if row.limit_requests.is_some() {
            let requests = sqlx::query_scalar::<_, i64>(
                "select count(*) from events
                 where ts > now() - make_interval(secs => $1::int)
                   and hook in ('prompt_in', 'tool_call')
                   and ($2::text is null or end_user = $2::text)
                   and ($3::text is null or model = $3::text)",
            )
            .bind(row.window_secs)
            .bind(owner)
            .bind(model)
            .fetch_one(&self.pool)
            .await;
            match requests {
                Ok(count) => used.requests = count,
                Err(error) => tracing::error!(%error, "budget request count failed"),
            }
        }
        used
    }

    /// Create or replace the budget for a scope. Returns its id.
    pub async fn upsert(&self, input: &BudgetInput) -> sqlx::Result<i64> {
        let id = sqlx::query_scalar::<_, i64>(
            "insert into budgets
               (scope, scope_id, window_secs, limit_tokens, limit_usd, limit_requests,
                limit_concurrency, hard, enabled)
             values ($1::text::budget_scope, $2, $3, $4, $5, $6, $7, $8, $9)
             on conflict (scope, coalesce(scope_id, '')) do update set
               window_secs = excluded.window_secs, limit_tokens = excluded.limit_tokens,
               limit_usd = excluded.limit_usd, limit_requests = excluded.limit_requests,
               limit_concurrency = excluded.limit_concurrency, hard = excluded.hard,
               enabled = excluded.enabled
             returning id",
        )
        .bind(&input.scope)
        .bind(&input.scope_id)
        .bind(input.window_secs)
        .bind(input.limit_tokens)
        .bind(input.limit_usd)
        .bind(input.limit_requests)
        .bind(input.limit_concurrency)
        .bind(input.hard)
        .bind(input.enabled)
        .fetch_one(&self.pool)
        .await?;
        self.invalidate();
        Ok(id)
    }

    /// Returns whether a row was deleted.
    pub async fn delete(&self, id: i64) -> sqlx::Result<bool> {
        let deleted = sqlx::query("delete from budgets where id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        self.invalidate();
        Ok(deleted > 0)
    }
}

/// Body of `PUT /admin/budgets`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetInput {
    pub scope: String,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default = "default_window")]
    pub window_secs: i32,
    #[serde(default)]
    pub limit_tokens: Option<i64>,
    #[serde(default)]
    pub limit_usd: Option<f64>,
    #[serde(default)]
    pub limit_requests: Option<i64>,
    #[serde(default)]
    pub limit_concurrency: Option<i32>,
    #[serde(default = "default_true")]
    pub hard: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_window() -> i32 {
    86_400
}

const fn default_true() -> bool {
    true
}

impl BudgetInput {
    /// The same rules the table's constraints enforce, checked first so the
    /// caller gets a reason instead of a database error.
    pub fn validate(&self) -> Result<(), String> {
        match self.scope.as_str() {
            "global" if self.scope_id.is_some() => {
                return Err("a global budget takes no scope_id".into());
            }
            "global" => {}
            "user" | "model" if self.scope_id.as_deref().is_none_or(str::is_empty) => {
                return Err(format!("a {} budget needs a scope_id", self.scope));
            }
            "user" | "model" => {}
            other => return Err(format!("unknown scope {other:?}: global | user | model")),
        }
        if self.window_secs <= 0 {
            return Err("window_secs must be positive".into());
        }
        if self.limit_tokens.is_none()
            && self.limit_usd.is_none()
            && self.limit_requests.is_none()
            && self.limit_concurrency.is_none()
        {
            return Err("set at least one limit".into());
        }
        let negative = self.limit_tokens.is_some_and(|l| l < 0)
            || self.limit_usd.is_some_and(|l| l < 0.0)
            || self.limit_requests.is_some_and(|l| l < 0)
            || self.limit_concurrency.is_some_and(|l| l < 0);
        if negative {
            return Err("limits must not be negative".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

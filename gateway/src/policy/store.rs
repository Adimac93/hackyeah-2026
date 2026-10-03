//! Where the policy lives: `policy_versions`, exactly one row active.
//!
//! The gateway never reads a catalog from disk. It loads the active row at
//! startup (seeding the built-in sample into an empty database), activates
//! uploads in one transaction, and polls so every instance converges on the
//! same version without a restart.

use std::time::Duration;

use anyhow::Context as _;
use sqlx::PgPool;
use uuid::Uuid;

use super::{BUILTIN_CATALOG, BUILTIN_SIGNATURES, Policy, PolicyHandle};

/// Serialises activations across instances, so two uploads (or two first
/// starts seeding at once) cannot both deactivate and insert.
const ACTIVATION_LOCK: i64 = 0x0070_6f6c_6963_79;

/// How often an instance checks for a version activated elsewhere.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(5);

struct Row {
    id: i64,
    source: String,
    catalog: String,
    signatures: Option<String>,
}

async fn active(pool: &PgPool) -> sqlx::Result<Option<Row>> {
    let row = sqlx::query_as::<_, (i64, String, String, Option<String>)>(
        "select id, source, catalog_toml, signatures_toml from policy_versions
         where active and catalog_toml is not null",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, source, catalog, signatures)| Row {
        id,
        source,
        catalog,
        signatures,
    }))
}

fn compile(row: &Row) -> anyhow::Result<Policy> {
    let mut policy = Policy::compile(&row.catalog, row.signatures.as_deref(), &row.source)
        .with_context(|| format!("compiling active policy version {}", row.id))?;
    policy.version_id = Some(row.id);
    Ok(policy)
}

/// The active policy, seeding the built-in sample when the database has none.
pub async fn load_or_seed(pool: &PgPool) -> anyhow::Result<Policy> {
    if let Some(row) = active(pool).await.context("reading the active policy")? {
        return compile(&row);
    }

    let mut policy = Policy::builtin().context("compiling the built-in policy")?;
    let id = activate(
        pool,
        &policy,
        BUILTIN_CATALOG,
        Some(BUILTIN_SIGNATURES),
        None,
        "seeded from the built-in sample",
        true,
    )
    .await
    .context("seeding the built-in policy")?;

    // Another instance may have seeded or uploaded while we waited on the
    // lock; whatever is active now is what we serve.
    match id {
        Some(id) => {
            tracing::info!(version_id = id, "seeded the built-in policy");
            policy.version_id = Some(id);
            mirror_signatures(pool, &policy).await;
            Ok(policy)
        }
        None => {
            let row = active(pool)
                .await?
                .context("no active policy after seeding")?;
            compile(&row)
        }
    }
}

/// Store a validated policy and make it the only active version. With
/// `only_if_empty`, nothing happens (and `None` is returned) when another
/// version is already active — the seeding path.
pub async fn activate(
    pool: &PgPool,
    policy: &Policy,
    catalog: &str,
    signatures: Option<&str>,
    uploaded_by: Option<Uuid>,
    diff_summary: &str,
    only_if_empty: bool,
) -> sqlx::Result<Option<i64>> {
    let mut tx = pool.begin().await?;
    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(ACTIVATION_LOCK)
        .execute(&mut *tx)
        .await?;

    if only_if_empty {
        let exists: bool = sqlx::query_scalar(
            "select exists (select 1 from policy_versions where active and catalog_toml is not null)",
        )
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            return Ok(None);
        }
    }

    sqlx::query("update policy_versions set active = false where active")
        .execute(&mut *tx)
        .await?;
    let id = sqlx::query_scalar::<_, i64>(
        "insert into policy_versions
           (sha256, source, catalog_toml, signatures_toml, diff_summary, uploaded_by_user, active)
         values ($1, $2, $3, $4, $5, $6, true)
         on conflict (sha256) do update set
           source = excluded.source, catalog_toml = excluded.catalog_toml,
           signatures_toml = excluded.signatures_toml, diff_summary = excluded.diff_summary,
           uploaded_by_user = excluded.uploaded_by_user, loaded_at = now(), active = true
         returning id",
    )
    .bind(&policy.sha256)
    .bind(&policy.source)
    .bind(catalog)
    .bind(signatures)
    .bind(diff_summary)
    .bind(uploaded_by)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(id))
}

/// Poll for a version activated by another instance and swap to it.
pub fn spawn_sync(pool: PgPool, handle: PolicyHandle) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SYNC_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let current = handle.load().version_id;
            let row = match active(&pool).await {
                Ok(Some(row)) if Some(row.id) != current => row,
                Ok(_) => continue,
                Err(error) => {
                    tracing::warn!(%error, "policy sync failed — keeping the current version");
                    continue;
                }
            };
            match compile(&row) {
                Ok(policy) => {
                    handle.replace(policy);
                }
                // Uploads are validated before they are stored, so this means
                // a row was edited by hand. Keep enforcing the last good one.
                Err(error) => {
                    tracing::error!(%error, "active policy does not compile — keeping the current version");
                }
            }
        }
    })
}

/// Mirror the active feed into `attack_signatures` so the dashboard can show
/// feed status (§4.4). Best effort: the feed is enforced from memory either way.
pub async fn mirror_signatures(pool: &PgPool, policy: &Policy) {
    if let Err(error) = try_mirror(pool, policy).await {
        tracing::error!(%error, "could not mirror the signature feed");
    }
}

async fn try_mirror(pool: &PgPool, policy: &Policy) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    let mut keep: Vec<String> = Vec::new();
    let source = policy.feed.as_ref().map(|f| f.source.clone());
    for entry in policy.feed.iter().flat_map(|f| &f.entries) {
        let severity = serde_json::to_value(entry.severity)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "high".to_owned());
        sqlx::query(
            "insert into attack_signatures
               (external_id, source, kind, severity, title, pattern, enabled, synced_at)
             values ($1, $2,
                     (case when $3 = 'semantic' then 'semantic' else 'deterministic' end)::control_kind,
                     $4::text::severity, $5, $6, true, now())
             on conflict (source, external_id) do update set
               kind = excluded.kind, severity = excluded.severity, title = excluded.title,
               pattern = excluded.pattern, enabled = true, synced_at = now()",
        )
        .bind(&entry.external_id)
        .bind(source.as_deref().unwrap_or_default())
        .bind(&entry.kind)
        .bind(severity)
        .bind(&entry.title)
        .bind(&entry.pattern)
        .execute(&mut *tx)
        .await?;
        keep.push(entry.external_id.clone());
    }
    sqlx::query(
        "update attack_signatures set enabled = false
         where enabled and (source is distinct from $1 or not (external_id = any($2)))",
    )
    .bind(source)
    .bind(&keep)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

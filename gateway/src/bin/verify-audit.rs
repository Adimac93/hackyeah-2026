//! Audit chain verifier.
//!
//! Walks `events` in order and recomputes each hash from the row's own fields
//! plus its predecessor's hash. A row that was edited, inserted or deleted after
//! the fact no longer reproduces its stored hash, and every row after it is
//! orphaned.
//!
//! This is what makes the audit log evidence rather than a claim: a security
//! team can prove the record is intact instead of trusting that it is.
//!
//! Exit code is 0 for an intact chain, 1 for a broken one, so CI and a demo can
//! both depend on it.

use anyhow::Context as _;
use gateway::audit::{chain_hash, hex};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("connecting to the database")?;

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
    .fetch_all(&pool)
    .await
    .context("reading events")?;

    if events.is_empty() {
        println!("no events recorded yet");
        return Ok(());
    }

    let mut previous: Vec<u8> = Vec::new();
    let mut broken = Vec::new();

    for (id, trace_id, hook, verdict, payload, prev_hash, stored) in &events {
        let detections = sqlx::query_as::<_, (String, String)>(
            "select control_id, action::text from detections where event_id = $1 order by id",
        )
        .bind(id)
        .fetch_all(&pool)
        .await
        .with_context(|| format!("reading detections for event {id}"))?;

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

        let linked = prev_hash.clone().unwrap_or_default() == previous;
        let matches = &recomputed == stored;

        if linked && matches {
            println!("  event {id:>5}  ok        {}…", &hex(stored)[..16]);
        } else {
            let why = if matches {
                "broken link to the previous event"
            } else {
                "row does not match its own hash"
            };
            println!("  event {id:>5}  TAMPERED  {why}");
            broken.push(*id);
        }

        previous.clone_from(stored);
    }

    println!();
    if broken.is_empty() {
        println!("chain intact: {} events verified", events.len());
        Ok(())
    } else {
        println!("CHAIN BROKEN at event(s): {broken:?}");
        std::process::exit(1);
    }
}

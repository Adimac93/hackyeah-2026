//! Audit chain verifier.
//!
//! Walks `events` in order and recomputes each hash from the row's own fields
//! plus its predecessor's. A row that was edited, inserted or deleted after the
//! fact no longer reproduces its stored hash, and every row after it is
//! orphaned.
//!
//! This is what makes the audit log evidence rather than a claim: a security
//! team can prove the record is intact instead of trusting that it is.
//!
//! Exit code is 0 for an intact chain, 1 for a broken one, so CI and a demo can
//! both depend on it.

use anyhow::Context as _;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("connecting to the database")?;

    let (checked, broken) = gateway::audit::verify_chain(&pool)
        .await
        .context("verifying the chain")?;

    if checked == 0 {
        println!("no events recorded yet");
        return Ok(());
    }

    if broken.is_empty() {
        println!("chain intact: {checked} events verified");
        Ok(())
    } else {
        println!("CHAIN BROKEN at event(s): {broken:?}");
        println!("{} of {checked} events no longer verify", broken.len());
        std::process::exit(1);
    }
}

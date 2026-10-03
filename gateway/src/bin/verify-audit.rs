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
//!
//! `verify-audit --file export.json` checks a JSON export from
//! `GET /admin/audit/export` instead, with no database: every row must
//! reproduce its own hash. An auditor holding only the file can run it.

use anyhow::Context as _;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {}
        [flag, path] if flag == "--file" => return verify_file(path),
        _ => anyhow::bail!("usage: verify-audit [--file export.json]"),
    }

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

fn verify_file(path: &str) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let rows: Vec<gateway::admin::export::Row> = serde_json::from_str(&text)
        .with_context(|| format!("{path} is not a JSON export from /admin/audit/export"))?;
    let report = gateway::admin::export::verify_export(&rows);

    if report.rows == 0 {
        println!("{path}: no events in the export");
        return Ok(());
    }
    // A complete export is one segment; filters and the row limit leave gaps,
    // which are not tampering, so say so rather than failing on them.
    let gaps = match report.segments {
        1 => "contiguous".to_owned(),
        n => format!("{n} segments: filtered or truncated export"),
    };
    if report.broken.is_empty() {
        println!("export intact: {} events verified ({gaps})", report.rows);
        Ok(())
    } else {
        println!("EXPORT TAMPERED at event(s): {:?}", report.broken);
        println!(
            "{} of {} events no longer verify ({gaps})",
            report.broken.len(),
            report.rows
        );
        std::process::exit(1);
    }
}

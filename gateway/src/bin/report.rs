//! Security report generator.
//!
//! §4.5 names two audiences with different needs: management wants posture and
//! spend, a security team wants the incidents and proof the record is intact.
//! A dashboard serves the first well and the second badly — nobody takes a web
//! page into a steering meeting. This produces a dated PDF that carries both,
//! including an attestation that the audit chain verifies.
//!
//! Typst renders it. The data is written as JSON and the template reads it, so
//! the layout can be changed without touching Rust.

use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, bail};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let window: i32 = std::env::var("REPORT_WINDOW_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);

    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?;
    let pool = gateway::db::connect(&url, 2).await?;

    let mut report = gateway::metrics::collect(&pool, window)
        .await
        .context("collecting metrics")?;

    // A report that does not say whether its own evidence is intact is worth
    // less than no report.
    let (checked, broken) = gateway::audit::verify_chain(&pool)
        .await
        .context("verifying the audit chain")?;
    report.chain = gateway::metrics::ChainStatus {
        events_checked: checked,
        intact: broken.is_empty(),
        first_broken: broken.first().copied(),
    };

    let out_dir = Path::new("report");
    let data_path = out_dir.join("data.json");
    std::fs::write(&data_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("writing {}", data_path.display()))?;

    let pdf_path = out_dir.join("security-report.pdf");
    let status = Command::new("typst")
        .arg("compile")
        .arg(out_dir.join("report.typ"))
        .arg(&pdf_path)
        .arg("--root")
        .arg(".")
        .status()
        .context("running typst — is it installed? `brew install typst`")?;

    if !status.success() {
        bail!("typst failed to compile the report");
    }

    println!();
    println!("  window      last {window}h");
    println!(
        "  events      {} ({} blocked, {:.1}%)",
        report.totals.events,
        report.totals.blocked,
        report.totals.block_rate()
    );
    println!(
        "  chain       {}",
        if report.chain.intact {
            format!("intact, {checked} events verified")
        } else {
            format!("BROKEN at event {:?}", report.chain.first_broken)
        }
    );
    println!("  written     {}", pdf_path.display());

    Ok(())
}

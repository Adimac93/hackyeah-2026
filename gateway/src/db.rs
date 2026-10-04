//! The database connection every binary opens.
//!
//! Supabase offers two poolers on one host: session mode (port 5432) and
//! transaction mode (port 6543). sqlx names its prepared statements per
//! connection, and transaction mode hands each transaction a different server
//! connection, so queries fail at random with `prepared statement "sqlx_s_3"
//! already exists`. Nothing fails at connect time, so it is refused here
//! rather than discovered as spurious 401s and lost audit writes.

use anyhow::{Context as _, bail};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

const TRANSACTION_POOLER_PORT: u16 = 6543;

pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
    if transaction_pooler(url) {
        bail!(
            "DATABASE_URL uses Supabase's transaction pooler (port 6543), which breaks \
             sqlx's prepared statements — use the session pooler (port 5432), see docs/DEPLOY.md"
        );
    }
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
        .context("connecting to DATABASE_URL")
}

fn transaction_pooler(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|url| {
        url.host_str()
            .is_some_and(|host| host.ends_with(".pooler.supabase.com"))
            && url.port() == Some(TRANSACTION_POOLER_PORT)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_supabase_transaction_pooler_is_refused() {
        let pooler = "postgresql://postgres.ref:pw@aws-1-eu-central-1.pooler.supabase.com";
        assert!(transaction_pooler(&format!("{pooler}:6543/postgres")));
        assert!(!transaction_pooler(&format!("{pooler}:5432/postgres")));
        assert!(!transaction_pooler("postgresql://postgres:pw@db.ref.supabase.co:5432/postgres"));
        assert!(!transaction_pooler("postgres://localhost:6543/dev"));
        assert!(!transaction_pooler("not a url"));
    }
}

//! AI Control Layer — gateway.
//!
//! Scaffold only: process bootstrap, health endpoint, optional database pool.
//! The enforcement hooks (prompt_in, response_out, tool_call, tool_result) and
//! the policy engine land on top of this.

use std::net::SocketAddr;

use anyhow::Context as _;
use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{EnvFilter, fmt};

use gateway::policy::{self, Policy, PolicyHandle};

const DEFAULT_POLICY_PATH: &str = "policy/control-catalog.toml";

#[derive(Clone)]
struct AppState {
    /// Absent when `DATABASE_URL` is unset, so the process still starts for
    /// local work before anyone has filled in `.env`.
    db: Option<sqlx::PgPool>,
    policy: PolicyHandle,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let db = match std::env::var("DATABASE_URL") {
        Ok(url) => {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .connect(&url)
                .await
                .context("connecting to DATABASE_URL")?;
            tracing::info!("database connected");
            Some(pool)
        }
        Err(_) => {
            tracing::warn!("DATABASE_URL unset — starting without persistence");
            None
        }
    };

    let policy_path =
        std::env::var("POLICY_PATH").unwrap_or_else(|_| DEFAULT_POLICY_PATH.to_owned());
    let loaded =
        Policy::load(&policy_path).with_context(|| format!("loading policy from {policy_path}"))?;
    tracing::info!(
        version = %loaded.sha256[..12].to_owned(),
        deterministic = loaded.deterministic.len(),
        semantic = loaded.semantic.len(),
        "policy loaded",
    );
    let policy = PolicyHandle::new(loaded, &policy_path);

    // Held for the lifetime of the process: dropping the watcher stops the watch.
    let _watcher = policy::spawn_watcher(policy.clone()).context("watching the policy file")?;

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = Router::new()
        .route("/health", get(health))
        .route("/policy", get(active_policy))
        .with_state(AppState { db, policy });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!("gateway listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .context("serving")?;

    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    let database = match &state.db {
        None => "not_configured",
        Some(pool) => match sqlx::query("select 1").execute(pool).await {
            Ok(_) => "connected",
            Err(error) => {
                tracing::error!(%error, "health check query failed");
                "error"
            }
        },
    };

    Json(json!({ "status": "ok", "database": database }))
}

/// What the gateway is currently enforcing. The dashboard polls this to show
/// which catalog version produced a given decision, and it is the fastest way
/// to see a hot-reload land.
async fn active_policy(State(state): State<AppState>) -> Json<Value> {
    let policy = state.policy.load();
    Json(json!({
        "version": policy.sha256,
        "source": policy.source,
        "fail_mode": policy.fail_mode,
        "on_detect": policy.on_detect,
        "controls": {
            "deterministic": policy.deterministic.len(),
            "semantic": policy.semantic.len(),
        },
        "models": policy.models,
        "signatures": policy.signatures,
    }))
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

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

#[derive(Clone)]
struct AppState {
    /// Absent when `DATABASE_URL` is unset, so the process still starts for
    /// local work before anyone has filled in `.env`.
    db: Option<sqlx::PgPool>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

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

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = Router::new()
        .route("/health", get(health))
        .with_state(AppState { db });

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

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

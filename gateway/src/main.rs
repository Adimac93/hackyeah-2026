//! AI Control Layer — gateway.
//!
//! Scaffold only: process bootstrap, health endpoint, optional database pool.
//! The enforcement hooks (prompt_in, response_out, tool_call, tool_result) and
//! the policy engine land on top of this.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method},
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{EnvFilter, fmt};

use gateway::audit::Auditor;
use gateway::mcp::{self, McpState};
use gateway::policy::{self, Policy, PolicyHandle};
use gateway::proxy::{self, ProxyState};
use gateway::semantic::Registry;

const DEFAULT_POLICY_PATH: &str = "policy/control-catalog.toml";

const DEFAULT_UPSTREAM: &str = "http://localhost:11434";

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

    // docs/BACKEND.md: the service runs locally (dev) or on Google Cloud (prod)
    // depending on ENVIRONMENT. It changes how we log and who may call us, never
    // what we enforce — the controls are identical in both.
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "dev".to_owned());
    let production = environment == "prod";

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if production {
        // Cloud Logging parses JSON lines and reads `severity` from them. A flat
        // text log arrives as an untyped string with every level and field lost.
        fmt()
            .json()
            .with_current_span(false)
            .with_env_filter(filter)
            .init();
    } else {
        fmt().with_env_filter(filter).init();
    }
    tracing::info!(environment = %environment, "starting");

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
    //
    // Hot-reload is a convenience; enforcement is not. If the platform will not
    // give us a file watch — a read-only layer, an inotify limit — the gateway
    // still serves under the policy it loaded rather than refusing to start.
    let _watcher = match policy::spawn_watcher(policy.clone()) {
        Ok(watcher) => Some(watcher),
        Err(error) => {
            tracing::warn!(%error, "policy hot-reload unavailable — edits need a restart");
            None
        }
    };

    // A malformed PORT is a configuration error, not a reason to pick another
    // one. Platforms that inject PORT health-check that exact port, so binding
    // a different one silently is a failure with no symptom.
    let port: u16 = match std::env::var("PORT") {
        Ok(value) => value
            .parse()
            .with_context(|| format!("PORT is set to {value:?}, which is not a port number"))?,
        Err(_) => 8080,
    };
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let auditor = Arc::new(Auditor::new(db.clone()).await);
    let policy_version_id = {
        let active = policy.load();
        auditor
            .register_policy(&active.sha256, &active.source)
            .await
    };
    if !auditor.enabled() {
        tracing::warn!("audit log disabled — enforcement still runs, nothing is persisted");
    }

    let upstream = std::env::var("UPSTREAM_URL").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    tracing::info!(%upstream, "forwarding model traffic upstream");

    let http = reqwest::Client::new();
    let detectors = Arc::new(Registry::from_env(http.clone()));

    let proxy_state = ProxyState {
        policy: policy.clone(),
        auditor: Arc::clone(&auditor),
        http: http.clone(),
        upstream,
        policy_version_id,
        detectors: Arc::clone(&detectors),
    };

    let mcp_state = McpState {
        policy: policy.clone(),
        auditor,
        http,
        policy_version_id,
        detectors,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/policy", get(active_policy))
        .with_state(AppState { db, policy })
        .merge(
            Router::new()
                .route("/v1/chat/completions", post(proxy::chat_completions))
                .with_state(proxy_state),
        )
        .merge(
            Router::new()
                .route("/mcp", post(mcp::endpoint))
                .with_state(mcp_state),
        )
        .layer(cors(&environment));

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

/// The dashboard is served from a different origin, so the browser will not
/// read a response without these.
///
/// `CORS_ORIGINS=*` opts into any origin. Note what that does and does not
/// cost: CORS constrains browsers only, and this gateway has no authentication,
/// so anything a wildcard would expose is already reachable with curl. The
/// control that actually matters here is authenticating callers, not this.
fn cors(environment: &str) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    match std::env::var("CORS_ORIGINS") {
        Ok(list) if list.trim() == "*" => {
            tracing::warn!("CORS_ORIGINS=* — any origin may call this gateway");
            layer.allow_origin(Any)
        }
        Ok(list) => {
            let origins: Vec<HeaderValue> = list
                .split(',')
                .filter_map(|origin| origin.trim().parse().ok())
                .collect();
            tracing::info!(
                count = origins.len(),
                "CORS restricted to configured origins"
            );
            layer.allow_origin(origins)
        }
        Err(_) if environment == "prod" => {
            tracing::warn!(
                "CORS_ORIGINS is unset in production — no cross-origin caller is allowed"
            );
            layer
        }
        Err(_) => {
            tracing::info!("dev: any origin may call this gateway");
            layer.allow_origin(Any)
        }
    }
}

/// Cloud Run sends SIGTERM and waits before killing the container. Without
/// handling it the process dies mid-request on every revision change.
async fn shutdown() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => tracing::error!(%error, "cannot listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!("interrupted — shutting down"),
        () = terminate => tracing::info!("SIGTERM — draining"),
    }
}

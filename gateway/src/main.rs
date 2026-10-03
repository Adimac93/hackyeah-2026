//! AI Control Layer — gateway.
//!
//! Process bootstrap: environment, logging, database, policy and its watcher,
//! then the routes. Enforcement lives in the library crate.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, Method},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
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

const DEFAULT_UPSTREAM: &str = gateway::mock::MOCK;

#[derive(Clone)]
struct AppState {
    /// Absent when `DATABASE_URL` is unset, so the process still starts for
    /// local work before anyone has filled in `.env`.
    db: Option<sqlx::PgPool>,
    policy: PolicyHandle,
    auditor: Arc<Auditor>,
}

#[derive(Deserialize)]
struct PolicyUpload {
    catalog_toml: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // docs/BACKEND.md: the service runs locally (dev) or on Google Cloud (prod)
    // depending on ENVIRONMENT. It changes how strict startup is, how we log and
    // who may call us, never what we enforce — the controls are identical.
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
        // A production control layer that cannot audit is not one.
        Err(_) if production => anyhow::bail!("DATABASE_URL is required when ENVIRONMENT=prod"),
        Err(_) => {
            tracing::warn!("DATABASE_URL unset — starting without persistence");
            None
        }
    };

    let policy_path =
        std::env::var("POLICY_PATH").unwrap_or_else(|_| DEFAULT_POLICY_PATH.to_owned());
    let mut loaded =
        Policy::load(&policy_path).with_context(|| format!("loading policy from {policy_path}"))?;
    // An accepted upload is portable across instances/restarts.  Prefer it
    // only when it is at least as new as the on-disk catalog; saving the file
    // later deliberately takes control back through the normal watcher.
    if let Some(pool) = &db {
        let file_modified_secs = std::fs::metadata(&policy_path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0.0, |duration| duration.as_secs_f64());
        let uploaded = sqlx::query_scalar::<_, String>(
            "select catalog_toml from policy_versions
             where active and catalog_toml is not null
               and loaded_at >= to_timestamp($1)
             order by loaded_at desc limit 1",
        )
        .bind(file_modified_secs)
        .fetch_optional(pool)
        .await;
        if let Ok(Some(catalog)) = uploaded {
            loaded = Policy::from_uploaded(&catalog, "database-upload", &policy_path)
                .context("loading active uploaded policy")?;
            tracing::info!(version = %loaded.sha256[..12], "using active uploaded policy");
        }
    }
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
    {
        let active = policy.load();
        auditor
            .policy_version_id(&active.sha256, &active.source)
            .await;
    }
    if !auditor.enabled() {
        tracing::warn!("audit log disabled — enforcement still runs, nothing is persisted");
    }

    let upstream = std::env::var("UPSTREAM_URL").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    tracing::info!(%upstream, "forwarding model traffic upstream");

    let http = reqwest::Client::new();
    let detectors = Arc::new(Registry::from_env(http.clone()));

    // A mock fabricates answers and verdicts; fine for a laptop, never for prod.
    if production && (upstream == gateway::mock::MOCK || detectors.mocked()) {
        anyhow::bail!("ENVIRONMENT=prod refuses a mock: set UPSTREAM_URL and OLLAMA_URL");
    }

    let proxy_state = ProxyState {
        policy: policy.clone(),
        auditor: Arc::clone(&auditor),
        http: http.clone(),
        upstream,
        detectors: Arc::clone(&detectors),
    };

    let mcp_state = McpState {
        policy: policy.clone(),
        auditor: Arc::clone(&auditor),
        http,
        detectors,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/openapi.json", get(openapi))
        .route("/admin/docs", get(swagger_ui))
        .route("/policy", get(active_policy))
        .route("/metrics", get(metrics))
        .route("/admin/policy", post(upload_policy))
        .with_state(AppState {
            db,
            policy,
            auditor,
        })
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

/// Service index. Anyone who opens the base URL — a judge, a teammate wiring up
/// the dashboard — should see what this is and what it serves, not a blank 404.
///
/// A browser gets a page; everything else gets the same facts as JSON. One
/// endpoint, two audiences, no second route to keep in step.
async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"));

    let facts = index_json(&state);
    if wants_html {
        Html(index_html(&facts)).into_response()
    } else {
        Json(facts).into_response()
    }
}

fn index_json(state: &AppState) -> Value {
    let policy = state.policy.load();
    json!({
        "service": "ai-control-layer",
        "description": "Security gateway for agent, LLM and MCP traffic. \
                        Every interception is policed at one of four hooks and \
                        written to a hash-chained audit log.",
        "version": env!("CARGO_PKG_VERSION"),
        "policy": {
            "version": policy.sha256,
            "deterministic_controls": policy.deterministic.len() + policy.signature_controls.len(),
            "semantic_controls": policy.semantic.len(),
            "fail_mode": policy.fail_mode,
        },
        "endpoints": {
            "GET  /health": "liveness, and whether the audit database is reachable",
            "GET  /admin/docs": "Swagger UI for the security-admin API",
            "GET  /openapi.json": "OpenAPI 3.1 document for integration tooling",
            "GET  /policy": "the catalog currently being enforced",
            "POST /v1/chat/completions": "OpenAI-compatible. Hooks: prompt_in, response_out",
            "POST /mcp": "MCP 2026-07-28. Hooks: tool_call, tool_result",
        },
    })
}

/// Rendered from the same values the JSON carries, so the page cannot drift
/// from the API. Deliberately one file with no assets: a landing page that
/// needs a CDN to render is a landing page that fails on conference wifi.
fn index_html(facts: &Value) -> String {
    let policy = &facts["policy"];
    let version = policy["version"].as_str().unwrap_or_default();
    let short = version.get(..12).unwrap_or(version);

    let endpoints = facts["endpoints"]
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(route, note)| {
                    format!(
                        "<tr><td><code>{route}</code></td><td>{}</td></tr>",
                        note.as_str().unwrap_or_default()
                    )
                })
                .collect::<String>()
        })
        .unwrap_or_default();

    format!(
        r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Control Layer</title>
<style>
  :root {{ color-scheme: light dark; --fg:#111; --muted:#666; --line:#e2e2e2; --bg:#fff; --accent:#b3261e; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --fg:#e8e8e8; --muted:#9a9a9a; --line:#2c2c2c; --bg:#131313; --accent:#ff6b5e; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif; }}
  main {{ max-width:46rem; margin:0 auto; padding:3rem 16px 4rem; }}
  h1 {{ font-size:1.6rem; margin:0 0 .2rem; letter-spacing:-.01em; }}
  .sub {{ color:var(--muted); margin:0 0 2rem; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(8rem,1fr)); gap:.75rem; margin-bottom:2.5rem; }}
  .stat {{ border:1px solid var(--line); border-radius:6px; padding:.8rem .9rem; }}
  .stat b {{ display:block; font-size:1.5rem; font-weight:650; }}
  .stat span {{ color:var(--muted); font-size:.72rem; text-transform:uppercase; letter-spacing:.06em; }}
  h2 {{ font-size:.78rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:0 0 .6rem; }}
  table {{ width:100%; border-collapse:collapse; }}
  td {{ padding:.55rem .5rem; border-bottom:1px solid var(--line); vertical-align:top; }}
  td:first-child {{ white-space:nowrap; width:1%; padding-right:1.25rem; }}
  td:last-child {{ color:var(--muted); font-size:.9rem; }}
  code {{ font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  footer {{ margin-top:2.5rem; color:var(--muted); font-size:.8rem; }}
  .chip {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:.1rem .5rem; font-size:.75rem; }}
</style>
</head><body><main>
  <h1>AI Control Layer</h1>
  <p class="sub">{}</p>

  <div class="grid">
    <div class="stat"><b>{}</b><span>deterministic</span></div>
    <div class="stat"><b>{}</b><span>semantic</span></div>
    <div class="stat"><b>{}</b><span>fail mode</span></div>
    <div class="stat"><b><code>{short}</code></b><span>policy</span></div>
  </div>

  <h2>Endpoints</h2>
  <table>{endpoints}</table>

  <footer>
    v{} · <span class="chip">this page is also JSON — request it with <code>Accept: application/json</code></span>
  </footer>
</main></body></html>"##,
        facts["description"].as_str().unwrap_or_default(),
        policy["deterministic_controls"],
        policy["semantic_controls"],
        policy["fail_mode"].as_str().unwrap_or_default(),
        facts["version"].as_str().unwrap_or_default(),
    )
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

/// Public documentation carries no live state or credentials. Every operation
/// it describes is still protected by the Bearer security scheme below.
async fn openapi() -> Json<Value> {
    Json(openapi_document())
}

/// Swagger UI is intentionally a thin viewer. Operators enter a security-admin
/// bearer key through its built-in Authorize dialog; no API key is embedded in
/// the page, URL, server log, or OpenAPI document.
async fn swagger_ui() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Control Layer — Security Admin API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head><body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/openapi.json",dom_id:"#swagger-ui",persistAuthorization:false});</script>
</body></html>"##,
    )
}

fn openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "AI Control Layer — Security Admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Live policy state, security telemetry, and validated policy uploads. All admin operations require a security_admin principal Bearer API key."
        },
        "paths": {
            "/policy": {
                "get": {
                    "summary": "Get the active policy",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {"description": "Current policy metadata"},
                        "401": {"$ref": "#/components/responses/AuthenticationRequired"},
                        "403": {"$ref": "#/components/responses/AdminRequired"}
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Get 24-hour management and security metrics",
                    "security": [{"bearerAuth": []}],
                    "responses": {
                        "200": {"description": "Aggregated events, detections, budgets, incidents, audit-chain status and percentiles"},
                        "401": {"$ref": "#/components/responses/AuthenticationRequired"},
                        "403": {"$ref": "#/components/responses/AdminRequired"},
                        "503": {"description": "Metrics persistence is unavailable"}
                    }
                }
            },
            "/admin/policy": {
                "post": {
                    "summary": "Validate, persist, and activate a policy catalog",
                    "description": "Invalid TOML leaves the active policy unchanged. Accepted uploads are retained with a version, administrator, and human-readable diff.",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PolicyUpload"}}}
                    },
                    "responses": {
                        "200": {"description": "Policy accepted and activated"},
                        "400": {"description": "Empty catalog"},
                        "401": {"$ref": "#/components/responses/AuthenticationRequired"},
                        "403": {"$ref": "#/components/responses/AdminRequired"},
                        "422": {"description": "Invalid TOML or policy schema; prior policy remains active"},
                        "503": {"description": "Policy database unavailable; policy remains unchanged"}
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "API key", "description": "Per-principal gateway API key; only its SHA-256 hash is stored."}},
            "schemas": {"PolicyUpload": {"type": "object", "additionalProperties": false, "required": ["catalog_toml"], "properties": {"catalog_toml": {"type": "string", "description": "Complete TOML control catalog", "example": "schema_version = 1\\n[defaults]\\non_detect = \\\"block\\\"\\nfail_mode = \\\"closed\\\""}}}},
            "responses": {
                "AuthenticationRequired": {"description": "Missing, malformed, invalid, or disabled Bearer API key"},
                "AdminRequired": {"description": "Authenticated principal lacks the security_admin role"}
            }
        }
    })
}

/// What the gateway is currently enforcing. The dashboard polls this to show
/// which catalog version produced a given decision, and it is the fastest way
/// to see a hot-reload land.
async fn active_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = security_admin(&state, &headers).await {
        return response;
    }
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
    .into_response()
}

/// Prometheus-style dashboards can use the richer persisted report while the
/// live endpoint stays deliberately small and requires a security-team key.
async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = security_admin(&state, &headers).await {
        return response;
    }
    let Some(pool) = &state.db else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "metrics persistence is not configured" })),
        )
            .into_response();
    };
    match gateway::metrics::collect(pool, 24).await {
        Ok(report) => Json(json!(report)).into_response(),
        Err(error) => {
            tracing::error!(%error, "metrics query failed");
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "metrics temporarily unavailable" })),
            )
                .into_response()
        }
    }
}

async fn upload_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(upload): Json<PolicyUpload>,
) -> Response {
    let admin = match security_admin(&state, &headers).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    if upload.catalog_toml.trim().is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": "catalog_toml must not be empty" })),
        )
            .into_response();
    }

    let current = state.policy.load();
    let origin = format!("uploaded:{}", &current.sha256[..12]);
    let next = match Policy::from_uploaded(&upload.catalog_toml, &origin, state.policy.path()) {
        Ok(policy) => policy,
        Err(error) => {
            // The old Arc remains active: invalid uploads never create a gap
            // in enforcement.
            return (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "invalid_policy", "message": error.to_string() })),
            )
                .into_response();
        }
    };
    let diff = format!(
        "policy {} -> {}; deterministic controls {} -> {}, semantic controls {} -> {}",
        &current.sha256[..12],
        &next.sha256[..12],
        current.deterministic.len(),
        next.deterministic.len(),
        current.semantic.len(),
        next.semantic.len(),
    );
    drop(current);

    if state
        .auditor
        .store_policy_upload(
            &next.sha256,
            &next.source,
            &upload.catalog_toml,
            admin.id,
            &diff,
        )
        .await
        .is_none()
    {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "policy persistence is unavailable; active policy unchanged" })),
        )
            .into_response();
    }

    let changed = state.policy.replace(next);
    Json(json!({ "accepted": true, "changed": changed, "diff": diff })).into_response()
}

async fn security_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<gateway::audit::Principal, Response> {
    let principal = proxy::bearer_principal(&state.auditor, headers).await?;
    if principal.role == "security_admin" {
        Ok(principal)
    } else {
        Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(json!({ "error": { "type": "admin_required", "message": "security administrator role required" } })),
        )
            .into_response())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_openapi_document_declares_bearer_auth_for_every_operation() {
        let document = openapi_document();
        assert_eq!(document["openapi"], "3.1.0");
        assert_eq!(
            document["components"]["securitySchemes"]["bearerAuth"]["scheme"],
            "bearer"
        );
        for (path, method) in [
            ("/policy", "get"),
            ("/metrics", "get"),
            ("/admin/policy", "post"),
        ] {
            assert!(
                document["paths"][path][method]["security"].is_array(),
                "{method} {path} must be protected in the contract"
            );
        }
    }
}

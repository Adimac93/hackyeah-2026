//! AI Control Layer — gateway.
//!
//! Process bootstrap: environment, logging, database, the active policy and
//! its sync, then the routes. Enforcement lives in the library crate.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{EnvFilter, fmt};

use gateway::admin::{self, auth::AdminAuth};
use gateway::approvals::Approvals;
use gateway::audit::Auditor;
use gateway::budget::Budgets;
use gateway::policy::{PolicyHandle, store};
use gateway::semantic::Registry;
use gateway::state::AppState;
use gateway::telemetry::Telemetry;

const DEFAULT_UPSTREAM: &str = gateway::mock::MOCK;

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

    // The policy, identities, grants and budgets all live in the database:
    // without it there is nothing to enforce, in any environment.
    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let db = gateway::db::connect(&url, 10).await?;
    tracing::info!("database connected");

    let loaded = store::load_or_seed(&db).await?;
    tracing::info!(
        version = %loaded.sha256[..12].to_owned(),
        version_id = ?loaded.version_id,
        deterministic = loaded.deterministic.len() + loaded.signature_controls.len(),
        semantic = loaded.semantic.len(),
        "policy loaded",
    );
    store::mirror_signatures(&db, &loaded).await;
    let policy = PolicyHandle::new(loaded);
    // Every instance converges on the active version without a restart.
    let _sync = store::spawn_sync(db.clone(), policy.clone());

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

    let upstream = std::env::var("UPSTREAM_URL").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_owned());
    tracing::info!(%upstream, "forwarding model traffic upstream");

    let http = reqwest::Client::new();
    let detectors = Arc::new(Registry::from_env(http.clone()));
    let admins = Arc::new(AdminAuth::from_env(http.clone()));

    // A mock fabricates answers and verdicts; fine for a laptop, never for prod.
    if production && (upstream == gateway::mock::MOCK || detectors.mocked()) {
        anyhow::bail!("ENVIRONMENT=prod refuses a mock: set UPSTREAM_URL and OLLAMA_URL");
    }
    // Enforcement does not depend on the admin API, so its absence is not a
    // reason to stop serving: every admin route then refuses (503).
    if !admins.configured() {
        tracing::warn!("admin API disabled — set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY");
    }

    // The resource tools share the main pool; each query switches to the
    // read-only `resources_reader` role for its own transaction.
    let resources = Some(db.clone());

    // Pending approvals live in this process: run one instance (docs/DEPLOY.md).
    let approvals = Arc::new(Approvals::new(Some(db.clone())));
    approvals.boot().await;

    let state = AppState {
        policy,
        auditor: Arc::new(Auditor::new(db.clone()).await),
        budgets: Arc::new(Budgets::new(db)),
        detectors,
        http,
        upstream,
        admins,
        resources,
        telemetry: Arc::new(Telemetry::default()),
        metrics_token: std::env::var("METRICS_TOKEN")
            .ok()
            .filter(|t| !t.is_empty()),
        approvals,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/openapi.json", get(openapi))
        .route("/admin/docs", get(swagger_ui))
        .route("/metrics/prometheus", get(prometheus))
        .merge(gateway::app::routes())
        .with_state(state)
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
        // Which models stand behind the gateway, without saying where they are.
        "semantic_judge": if state.detectors.mocked() { "mock" } else { "llm_judge" },
        "chat_upstream": if state.upstream == gateway::mock::MOCK { "mock" } else { "model" },
        "endpoints": {
            "GET  /health": "liveness, and whether the audit database is reachable",
            "GET  /admin/docs": "Swagger UI for the whole API",
            "GET  /openapi.json": "OpenAPI 3.1 document for integration tooling",
            "POST /v1/chat/completions": "OpenAI-compatible. Hooks: prompt_in, response_out",
            "POST /mcp": "MCP 2026-07-28. Hooks: tool_call, tool_result",
            "GET  /v1/results/{id}": "rows of a resources__query, for the identity that ran it",
            "GET  /policy": "admin: the catalog currently being enforced",
            "POST /admin/policy": "admin: upload and activate a catalog",
            "GET  /admin/risk": "admin: per-user risk scores, searchable with ?q=",
            "GET  /admin/approvals/stream": "SSE of pending access requests (security_admin)",
            "POST /admin/approvals/{id}": "approve or deny an access request (security_admin)",
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
    let database = match sqlx::query("select 1").execute(state.db()).await {
        Ok(_) => "connected",
        Err(error) => {
            tracing::error!(%error, "health check query failed");
            "error"
        }
    };
    Json(json!({ "status": "ok", "database": database }))
}

async fn openapi() -> Json<Value> {
    Json(gateway::openapi::document())
}

/// Swagger UI is intentionally a thin viewer. Operators paste a token into its
/// Authorize dialog; no credential is embedded in the page, URL or document.
async fn swagger_ui() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Control Layer — Gateway API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head><body><div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/openapi.json",dom_id:"#swagger-ui",persistAuthorization:false});</script>
</body></html>"##,
    )
}

/// Live telemetry for a scraper, which holds `METRICS_TOKEN` rather than a
/// user session.
async fn prometheus(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(expected) = &state.metrics_token else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let presented = admin::auth::bearer(&headers).unwrap_or_default();
    // Compare digests so the comparison time does not depend on the token.
    if gateway::audit::sha256_hex(presented.as_bytes())
        != gateway::audit::sha256_hex(expected.as_bytes())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.telemetry.render(),
    )
        .into_response()
}

/// The dashboard is served from a different origin, so the browser will not
/// read a response without these.
///
/// `CORS_ORIGINS=*` opts into any origin. CORS constrains browsers only; every
/// endpoint that matters authenticates its caller regardless.
fn cors(environment: &str) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
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

//! Everything a request handler needs. Cloned per request, so each field is
//! cheap to clone.

use std::sync::Arc;

use sqlx::PgPool;

use crate::admin::auth::AdminAuth;
use crate::approvals::Approvals;
use crate::audit::Auditor;
use crate::budget::Budgets;
use crate::policy::PolicyHandle;
use crate::semantic::Registry;
use crate::telemetry::Telemetry;
use crate::upstream::Upstreams;

#[derive(Clone)]
pub struct AppState {
    pub policy: PolicyHandle,
    pub auditor: Arc<Auditor>,
    pub budgets: Arc<Budgets>,
    pub detectors: Arc<Registry>,
    pub http: reqwest::Client,
    /// Where model traffic goes by default (`UPSTREAM_URL`), or `mock`.
    pub upstream: String,
    /// Per-model routing to the console's LLM connections; falls back to `upstream`.
    pub upstreams: Arc<Upstreams>,
    pub admins: Arc<AdminAuth>,
    /// The pool the MCP resource tools query through (each query runs as the
    /// read-only `resources_reader` role). `None` disables those tools.
    pub resources: Option<PgPool>,
    pub telemetry: Arc<Telemetry>,
    /// Bearer token for the Prometheus endpoint. `None` disables it.
    pub metrics_token: Option<String>,
    /// Human-approved access requests and the grants they produce.
    pub approvals: Arc<Approvals>,
}

impl AppState {
    pub fn db(&self) -> &PgPool {
        self.auditor.pool()
    }
}

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

#[derive(Clone)]
pub struct AppState {
    pub policy: PolicyHandle,
    pub auditor: Arc<Auditor>,
    pub budgets: Arc<Budgets>,
    pub detectors: Arc<Registry>,
    pub http: reqwest::Client,
    /// Where model traffic goes, or `mock`.
    pub upstream: String,
    pub admins: Arc<AdminAuth>,
    /// Read-only connection to the protected resources the MCP resource tools
    /// query. `None` disables those tools.
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

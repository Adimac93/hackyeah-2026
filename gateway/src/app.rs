//! The gateway's enforcement and admin routes. `main.rs` serves them next to
//! its landing pages, and the self-test suite serves exactly the same table
//! on a local port, so the suite tests what is deployed.

use axum::Router;
use axum::routing::{delete, get, post};

use crate::state::AppState;
use crate::{admin, approvals, mcp, proxy};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/results/{id}", get(mcp::resources::result))
        .route("/mcp", post(mcp::endpoint))
        .route("/policy", get(admin::active_policy))
        .route("/metrics", get(admin::metrics))
        .route("/admin/policy", post(admin::upload_policy))
        .route("/admin/policy/versions", get(admin::policy_versions))
        .route(
            "/admin/budgets",
            get(admin::budgets::list).put(admin::budgets::put),
        )
        .route("/admin/budgets/{id}", delete(admin::budgets::delete))
        .route("/admin/audit/export", get(admin::export::export))
        .route("/admin/risk", get(admin::risk::list))
        .route("/admin/approvals/stream", get(approvals::http::stream))
        .route("/admin/approvals/{id}", post(approvals::http::decide))
}

#[cfg(test)]
mod tests;

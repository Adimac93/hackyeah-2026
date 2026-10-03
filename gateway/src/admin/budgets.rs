//! Budget administration. Budgets live in `budgets`; the console reads them
//! through the Data API and changes them only here.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::auth::{Access, refusal};
use super::record_action;
use crate::budget::BudgetInput;
use crate::state::AppState;

/// Every enabled budget, as the gateway currently enforces it.
pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = state.admins.require(state.db(), &headers, Access::Read).await {
        return response;
    }
    Json(json!(*state.budgets.rows().await)).into_response()
}

/// Create or replace the budget for one scope.
pub async fn put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BudgetInput>,
) -> Response {
    let admin = match state.admins.require(state.db(), &headers, Access::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let detail = json!(input);
    if let Err(message) = input.validate() {
        record_action(state.db(), &admin, "budget.put", None, false, json!({ "input": detail, "error": message })).await;
        return refusal(StatusCode::UNPROCESSABLE_ENTITY, "invalid_budget", &message);
    }
    match state.budgets.upsert(&input).await {
        Ok(id) => {
            let target = id.to_string();
            record_action(state.db(), &admin, "budget.put", Some(&target), true, detail).await;
            Json(json!({ "id": id })).into_response()
        }
        Err(error) => {
            tracing::error!(%error, "budget upsert failed");
            record_action(state.db(), &admin, "budget.put", None, false, json!({ "input": detail, "error": "storage error" })).await;
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "budget storage is unavailable",
            )
        }
    }
}

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let admin = match state.admins.require(state.db(), &headers, Access::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let target = id.to_string();
    match state.budgets.delete(id).await {
        Ok(true) => {
            record_action(state.db(), &admin, "budget.delete", Some(&target), true, json!({})).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => refusal(StatusCode::NOT_FOUND, "not_found", "no budget with that id"),
        Err(error) => {
            tracing::error!(%error, "budget delete failed");
            record_action(state.db(), &admin, "budget.delete", Some(&target), false, json!({ "error": "storage error" })).await;
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "budget storage is unavailable",
            )
        }
    }
}

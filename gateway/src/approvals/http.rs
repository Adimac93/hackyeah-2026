//! The console's side of access requests: a live feed of pending requests and
//! the decision endpoint. Both take the `secops-console` principal's API key
//! (`GATEWAY_ADMIN_KEY`), which the console holds server-side.

use std::convert::Infallible;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::{Stream, StreamExt as _};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::{ApprovalEvent, DecideError, Decision, clamp_ttl};
use crate::admin::auth::refusal;
use crate::audit::Principal;
use crate::proxy::bearer_principal;
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    decision: String,
    ttl_minutes: Option<u32>,
    note: Option<String>,
    decided_by: String,
}

/// The console's live feed. Subscribe before the snapshot so nothing falls in
/// between; the console dedupes by id.
pub async fn stream(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(refusal) = security_admin(&state, &headers).await {
        return refusal;
    }
    let live = state.approvals.subscribe();
    let backlog = state
        .approvals
        .snapshot()
        .into_iter()
        .map(ApprovalEvent::Request);

    let live = futures_util::stream::unfold(live, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(event) => return Some((event, receiver)),
                // A slow console missed some events; a reconnect replays the
                // pending set, so carry on with what is current.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    let events: std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> = Box::pin(
        futures_util::stream::iter(backlog)
            .chain(live)
            .map(|event| {
                Ok(Event::default()
                    .json_data(&event)
                    .unwrap_or_else(|_| Event::default().comment("unserialisable event")))
            }),
    );

    Sse::new(events)
        .keep_alive(KeepAlive::default())
        .into_response()
}

pub async fn decide(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<DecisionBody>,
) -> Response {
    if let Err(refusal) = security_admin(&state, &headers).await {
        return refusal;
    }
    let approve = match body.decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "decision must be approve or deny" })),
            )
                .into_response();
        }
    };
    let decision = Decision {
        approve,
        ttl_minutes: clamp_ttl(body.ttl_minutes),
        note: body.note.filter(|n| !n.trim().is_empty()),
        decided_by: body.decided_by,
    };
    match state.approvals.decide(id, decision).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(error @ DecideError::NotPending) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
        Err(error @ DecideError::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn security_admin(state: &AppState, headers: &HeaderMap) -> Result<Principal, Response> {
    let principal = bearer_principal(&state.auditor, headers).await?;
    if principal.role == "security_admin" {
        Ok(principal)
    } else {
        Err(refusal(
            StatusCode::FORBIDDEN,
            "admin_required",
            "security administrator role required",
        ))
    }
}

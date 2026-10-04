//! `POST /admin/selftest`: run the full-system self-test against this gateway
//! and stream its log as plain text, one line at a time, while it runs.

use std::convert::Infallible;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::auth::Access;
use super::record_action;
use crate::selftest::suite::{self, Run};
use crate::state::AppState;

pub async fn run(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // The suite writes audit rows and raises its own users' risk scores, so it
    // takes the role that may change gateway state.
    let admin = match state.admins.require(state.db(), &headers, Access::Write).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let run = Run::from_env();
    record_action(state.db(), &admin, "selftest.run", Some(&run.id), true, json!({})).await;

    let (log, lines) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(suite::run(state, run, log));
    let body = futures_util::stream::unfold(lines, |mut lines| async move {
        lines.recv().await.map(|line| (Ok::<_, Infallible>(line), lines))
    });
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-transform"),
            (header::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        Body::from_stream(body),
    )
        .into_response()
}

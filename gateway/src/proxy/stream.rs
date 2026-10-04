//! Streamed answers (`"stream": true`).
//!
//! The upstream streams; the caller gets only text the deterministic
//! `response_out` controls have already seen, with [`HOLDBACK`] bytes of
//! margin behind it, so a pattern still being written (an email, a key) is
//! redacted or blocked before any of it leaves. When the answer is complete it
//! is policed exactly like a buffered one — both tiers, audit, usage — and that
//! verdict is the last event: a final chunk carrying `x_control_layer`, or the
//! same `error` object a buffered refusal has, which tells the client to
//! retract what it showed.

use std::convert::Infallible;
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::{Exchange, control_layer, micros, police_answer, refusal, refusal_body};
use crate::budget::Inflight;
use crate::engine::{self, Detection, Evaluation};
use crate::mock;
use crate::policy::{Hook, Policy};
use crate::state::AppState;

/// Text this close to the newest token is not released yet: it may still turn
/// out to be the start of a match.
pub const HOLDBACK: usize = 256;

/// Re-run the controls once this many new bytes arrived, not on every token.
const STEP: usize = 32;

/// Pace of the mock upstream's words, so `dev` visibly streams.
const MOCK_DELAY: Duration = Duration::from_millis(30);

/// One thing an OpenAI-style upstream stream said.
#[derive(Debug, PartialEq, Eq)]
pub enum Upstream {
    Delta(String),
    Usage(i32, i32),
    Done,
}

/// Turns the upstream's SSE bytes into [`Upstream`] events. Bytes arrive in
/// arbitrary pieces; only complete lines are decoded, and a newline byte never
/// occurs inside a UTF-8 character, so no character is ever split.
#[derive(Default)]
pub struct UpstreamParser {
    buffer: Vec<u8>,
}

impl UpstreamParser {
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Upstream> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        while let Some(end) = self.buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            let Some(data) = line.trim().strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data == "[DONE]" {
                events.push(Upstream::Done);
                continue;
            }
            let Ok(chunk) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if let Some(text) = chunk
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
            {
                events.push(Upstream::Delta(text.to_owned()));
            }
            if let Some(usage) = chunk.get("usage").filter(|usage| usage.is_object()) {
                let field = |name: &str| {
                    usage
                        .get(name)
                        .and_then(Value::as_i64)
                        .and_then(|v| i32::try_from(v).ok())
                        .unwrap_or_default()
                };
                events.push(Upstream::Usage(field("prompt_tokens"), field("completion_tokens")));
            }
        }
        events
    }
}

/// What the caller may be sent now.
#[derive(Debug)]
pub enum Step {
    /// Checked text to send; empty when nothing new is safe yet.
    Release(String),
    /// A control refused the answer.
    Block(Detection),
    /// A redaction reached into text already sent. It cannot be unsent, so the
    /// answer is retracted.
    Diverged,
}

/// The rolling window: what arrived, and what of its redacted form was sent.
#[derive(Default)]
pub struct Releaser {
    raw: String,
    sent: String,
    checked: usize,
}

impl Releaser {
    /// Take one delta; release whatever is now far enough behind the newest token.
    pub fn push(&mut self, policy: &Policy, delta: &str) -> Step {
        self.raw.push_str(delta);
        if self.raw.len() < self.checked + STEP {
            return Step::Release(String::new());
        }
        self.checked = self.raw.len();
        let evaluation = engine::evaluate(policy, Hook::ResponseOut, &self.raw);
        self.release_from(&evaluation, HOLDBACK)
    }

    /// Release from an evaluation of everything so far, keeping `holdback`
    /// bytes back. The final evaluation is released with no holdback.
    pub fn release_from(&mut self, evaluation: &Evaluation, holdback: usize) -> Step {
        if let Some(blocker) = evaluation.blocked_by() {
            return Step::Block(blocker.clone());
        }
        let text = &evaluation.text;
        if !text.starts_with(&self.sent) {
            return Step::Diverged;
        }
        // `sent.len()` is a character boundary of `text`, so this stops there at the latest.
        let mut cut = text.len().saturating_sub(holdback).max(self.sent.len());
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        let released = text[self.sent.len()..cut].to_owned();
        self.sent.push_str(&released);
        Step::Release(released)
    }

    /// Everything the upstream said, unredacted: what gets policed and audited.
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

enum Source {
    Mock { words: Vec<String>, usage: (i32, i32) },
    Upstream(reqwest::Response),
}

/// Start the upstream stream and answer with an SSE stream of checked chunks.
/// Failures before the first byte are ordinary JSON responses, as buffered.
pub async fn respond(
    state: AppState,
    exchange: Exchange,
    mut body: Value,
    inflight: Inflight,
) -> Response {
    let trace_id = exchange.trace_id;
    let started = Instant::now();
    let source = if state.upstream == mock::MOCK {
        mock_source(&body)
    } else {
        body["stream"] = json!(true);
        body["stream_options"] = json!({ "include_usage": true });
        let sent = state
            .http
            .post(format!("{}/v1/chat/completions", state.upstream))
            .json(&body)
            .send()
            .await;
        state.telemetry.dependency("upstream", sent.is_ok());
        let upstream = match sent {
            Ok(upstream) => upstream,
            Err(error) => {
                tracing::error!(%error, "upstream request failed");
                return refusal(
                    trace_id,
                    StatusCode::BAD_GATEWAY,
                    json!({ "type": "upstream_unavailable", "message": "the upstream model is unreachable" }),
                );
            }
        };
        let status = upstream.status();
        if !status.is_success() {
            let body = upstream.json::<Value>().await.unwrap_or_else(|_| {
                json!({ "error": { "type": "upstream_unreadable", "message": "the upstream response was not JSON" } })
            });
            return (status, Json(body)).into_response();
        }
        Source::Upstream(upstream)
    };

    let (sender, receiver) = mpsc::channel(64);
    tokio::spawn(relay(state, exchange, source, sender, started, inflight));
    let events = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|event| (Ok::<Event, Infallible>(event), receiver))
    });
    Sse::new(events).keep_alive(KeepAlive::default()).into_response()
}

fn mock_source(body: &Value) -> Source {
    let completion = mock::completion(body);
    let content = completion
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let field = |name: &str| {
        completion["usage"][name]
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or_default()
    };
    Source::Mock {
        words: content.split_inclusive(' ').map(str::to_owned).collect(),
        usage: (field("prompt_tokens"), field("completion_tokens")),
    }
}

/// OpenAI `chat.completion.chunk` events for one answer.
struct Chunks {
    id: String,
    model: String,
    sender: mpsc::Sender<Event>,
}

impl Chunks {
    /// A caller that went away is ignored: the answer is still finished,
    /// policed and audited.
    async fn send(&self, data: String) {
        let _ = self.sender.send(Event::default().data(data)).await;
    }

    async fn delta(&self, text: &str) {
        if text.is_empty() {
            return;
        }
        let chunk = json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "model": self.model,
            "choices": [{ "index": 0, "delta": { "content": text }, "finish_reason": null }],
        });
        self.send(chunk.to_string()).await;
    }

    /// Release what a step allows; false once the answer was stopped.
    async fn step(&self, step: Step) -> bool {
        match step {
            Step::Release(text) => {
                self.delta(&text).await;
                true
            }
            Step::Block(_) | Step::Diverged => false,
        }
    }
}

/// Read the upstream, release checked text, then police the whole answer and
/// send its verdict. Holds the budget's in-flight slots until the end.
async fn relay(
    state: AppState,
    exchange: Exchange,
    source: Source,
    sender: mpsc::Sender<Event>,
    started: Instant,
    _inflight: Inflight,
) {
    let chunks = Chunks {
        id: format!("chatcmpl-{}", exchange.trace_id),
        model: exchange.model.clone(),
        sender,
    };
    let policy = exchange.policy.clone();
    let mut releaser = Releaser::default();
    let mut usage = (0, 0);
    let mut broke_off = false;

    match source {
        Source::Mock { words, usage: counted } => {
            usage = counted;
            for word in words {
                tokio::time::sleep(MOCK_DELAY).await;
                if !chunks.step(releaser.push(&policy, &word)).await {
                    break;
                }
            }
        }
        Source::Upstream(mut upstream) => {
            let mut parser = UpstreamParser::default();
            'read: loop {
                let bytes = match upstream.chunk().await {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => break,
                    Err(error) => {
                        tracing::error!(%error, "upstream stream broke off");
                        broke_off = true;
                        break;
                    }
                };
                for event in parser.feed(&bytes) {
                    match event {
                        Upstream::Delta(text) => {
                            if !chunks.step(releaser.push(&policy, &text)).await {
                                break 'read;
                            }
                        }
                        Upstream::Usage(prompt, completion) => usage = (prompt, completion),
                        Upstream::Done => break 'read,
                    }
                }
            }
            state.telemetry.dependency("upstream", !broke_off);
        }
    }

    let upstream_us = micros(started);
    state.telemetry.observe("upstream", upstream_us);
    let answer = releaser.raw().to_owned();
    let outbound = police_answer(&state, &exchange, answer, usage, upstream_us).await;

    let error = if broke_off {
        Some(json!({ "type": "upstream_unavailable", "message": "the upstream model broke off the answer" }))
    } else {
        match releaser.release_from(&outbound, 0) {
            Step::Release(rest) => {
                chunks.delta(&rest).await;
                None
            }
            Step::Block(blocker) => Some(refusal_body(Hook::ResponseOut, &blocker, None).1),
            Step::Diverged => Some(json!({
                "type": "blocked_by_control",
                "message": "response retracted: a redaction reached text already sent",
                "stage": "deterministic",
                "hook": Hook::ResponseOut,
            })),
        }
    };

    let last = match error {
        Some(error) => {
            tracing::info!(trace_id = %exchange.trace_id, code = %error["type"], message = %error["message"], "refused");
            json!({ "error": error, "trace_id": exchange.trace_id })
        }
        None => json!({
            "id": chunks.id,
            "object": "chat.completion.chunk",
            "model": chunks.model,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
            "usage": {
                "prompt_tokens": usage.0,
                "completion_tokens": usage.1,
                "total_tokens": usage.0 + usage.1,
            },
            "x_control_layer": control_layer(&exchange, &outbound),
        }),
    };
    chunks.send(last.to_string()).await;
    chunks.send("[DONE]".to_owned()).await;
}

#[cfg(test)]
mod tests;

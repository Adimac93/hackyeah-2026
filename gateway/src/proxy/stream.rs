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

use std::collections::VecDeque;
use std::convert::Infallible;
use std::time::{Duration, Instant};

use axum::Json;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::agent::{self, ToolCall};
use super::{Exchange, control_layer, micros, police_answer, refusal, refusal_body};
use crate::budget::Inflight;
use crate::engine::{self, Detection, Evaluation};
use crate::{mcp, mock};
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
    /// A piece of a tool call. OpenAI streams one call across many chunks,
    /// keyed by `index`; Ollama sends it whole.
    ToolCall {
        index: usize,
        id: Option<String>,
        name: Option<String>,
        arguments: String,
    },
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
            for (position, call) in chunk
                .pointer("/choices/0/delta/tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let text = |pointer: &str| call.pointer(pointer).and_then(Value::as_str).map(str::to_owned);
                let arguments = match call.pointer("/function/arguments") {
                    Some(Value::String(text)) => text.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(object) => object.to_string(),
                };
                events.push(Upstream::ToolCall {
                    index: call
                        .get("index")
                        .and_then(Value::as_u64)
                        .and_then(|i| usize::try_from(i).ok())
                        .unwrap_or(position),
                    id: text("/id"),
                    name: text("/function/name"),
                    arguments,
                });
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

/// The model's tool calls in one turn, assembled from their streamed pieces.
#[derive(Default)]
pub struct PendingCalls {
    calls: Vec<(Option<String>, String, String)>,
}

impl PendingCalls {
    pub fn add(&mut self, index: usize, id: Option<String>, name: Option<String>, arguments: &str) {
        if self.calls.len() <= index {
            self.calls.resize_with(index + 1, Default::default);
        }
        let call = &mut self.calls[index];
        if id.is_some() {
            call.0 = id;
        }
        if let Some(name) = name {
            call.1.push_str(&name);
        }
        call.2.push_str(arguments);
    }

    pub fn is_empty(&self) -> bool {
        self.calls.iter().all(|(_, name, _)| name.is_empty())
    }

    /// The finished calls, and the assistant message that asked for them.
    pub fn finish(self) -> (Vec<ToolCall>, Value) {
        let mut calls = Vec::new();
        let mut asked = Vec::new();
        for (index, (id, name, arguments)) in self.calls.into_iter().enumerate() {
            if name.is_empty() {
                continue;
            }
            let id = id.unwrap_or_else(|| format!("call_{index}"));
            let raw = if arguments.is_empty() { "{}".to_owned() } else { arguments };
            asked.push(json!({
                "id": id,
                "type": "function",
                "function": { "name": name, "arguments": raw },
            }));
            calls.push(ToolCall {
                id,
                name,
                arguments: agent::parse_arguments(Some(&Value::String(raw))),
            });
        }
        (calls, json!({ "role": "assistant", "content": null, "tool_calls": asked }))
    }
}

/// One model turn's streamed body: the upstream's, or the mock rendered as the
/// same SSE so both take one path.
enum Turn {
    Http(reqwest::Response),
    Mock(VecDeque<Vec<u8>>),
}

impl Turn {
    async fn chunk(&mut self) -> Result<Option<Vec<u8>>, reqwest::Error> {
        match self {
            Self::Http(response) => Ok(response.chunk().await?.map(|bytes| bytes.to_vec())),
            Self::Mock(lines) => {
                tokio::time::sleep(MOCK_DELAY).await;
                Ok(lines.pop_front())
            }
        }
    }
}

/// The mock's answer to `body` as OpenAI SSE: a tool call, or its words.
fn mock_turn(body: &Value) -> Turn {
    let completion = mock::completion(body);
    let line = |chunk: Value| format!("data: {chunk}\n\n").into_bytes();
    let mut lines = VecDeque::new();
    if let Some(calls) = completion.pointer("/choices/0/message/tool_calls").and_then(Value::as_array) {
        let calls: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(index, call)| {
                let mut call = call.clone();
                call["index"] = json!(index);
                call
            })
            .collect();
        lines.push_back(line(json!({ "choices": [{ "index": 0, "delta": { "tool_calls": calls } }] })));
    } else {
        let content = completion
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        for word in content.split_inclusive(' ') {
            lines.push_back(line(json!({ "choices": [{ "index": 0, "delta": { "content": word } }] })));
        }
    }
    lines.push_back(line(json!({ "choices": [], "usage": completion["usage"] })));
    lines.push_back(b"data: [DONE]\n\n".to_vec());
    Turn::Mock(lines)
}

/// Why a turn could not start.
enum NoTurn {
    /// The upstream could not be reached or read: our `error` object.
    Unavailable(Value),
    /// The upstream answered with an error of its own, passed on as it is.
    Upstream(StatusCode, Value),
}

impl NoTurn {
    /// The `error` object for an answer already streaming.
    fn error(self) -> Value {
        match self {
            Self::Unavailable(error) => error,
            Self::Upstream(status, body) => body.get("error").cloned().unwrap_or_else(|| {
                json!({ "type": "upstream_error", "message": format!("the upstream model answered {status}") })
            }),
        }
    }
}

/// Start one model turn.
async fn open_turn(state: &AppState, body: &Value) -> Result<Turn, NoTurn> {
    if state.upstream == mock::MOCK {
        return Ok(mock_turn(body));
    }
    let mut body = body.clone();
    body["stream"] = json!(true);
    body["stream_options"] = json!({ "include_usage": true });
    let sent = state
        .http
        .post(format!("{}/v1/chat/completions", state.upstream))
        .json(&body)
        .send()
        .await;
    state.telemetry.dependency("upstream", sent.is_ok());
    let upstream = sent.map_err(|error| {
        tracing::error!(%error, "upstream request failed");
        NoTurn::Unavailable(
            json!({ "type": "upstream_unavailable", "message": "the upstream model is unreachable" }),
        )
    })?;
    let status = upstream.status();
    if !status.is_success() {
        return Err(match upstream.json::<Value>().await {
            Ok(body) => NoTurn::Upstream(status, body),
            Err(_) => NoTurn::Unavailable(
                json!({ "type": "upstream_unreadable", "message": "the upstream response was not JSON" }),
            ),
        });
    }
    Ok(Turn::Http(upstream))
}

/// Start the upstream stream and answer with an SSE stream of checked chunks.
/// Failures before the first byte are ordinary JSON responses, as buffered.
/// With `"mcp": true` the model is offered the caller's MCP tools, and each
/// turn that calls them runs them through the access layer and streams on.
pub async fn respond(
    state: AppState,
    exchange: Exchange,
    mut body: Value,
    inflight: Inflight,
) -> Response {
    let with_tools = body.as_object_mut().and_then(|b| b.remove("mcp")) == Some(Value::Bool(true));
    if with_tools {
        let tools = mcp::visible_tools(&state, &exchange.policy, &exchange.principal).await;
        body["tools"] = Value::Array(agent::openai_tools(&tools));
    }
    let first = match open_turn(&state, &body).await {
        Ok(turn) => turn,
        Err(NoTurn::Unavailable(error)) => {
            return refusal(exchange.trace_id, StatusCode::BAD_GATEWAY, error);
        }
        Err(NoTurn::Upstream(status, body)) => return (status, Json(body)).into_response(),
    };

    let (sender, receiver) = mpsc::channel(64);
    tokio::spawn(relay(state, exchange, body, first, sender, inflight));
    let events = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|event| (Ok::<Event, Infallible>(event), receiver))
    });
    Sse::new(events).keep_alive(KeepAlive::default()).into_response()
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

/// How a turn ended.
enum TurnEnd {
    /// The model answered (or the upstream finished without tool calls).
    Answered,
    /// A control stopped the answer.
    Stopped,
    /// The model asked for tools.
    Calls(PendingCalls),
    /// The upstream broke off mid-turn.
    BrokeOff,
}

/// Read one turn: text goes through the release window, tool-call pieces are
/// collected, usage is added up.
async fn read_turn(
    turn: &mut Turn,
    policy: &Policy,
    releaser: &mut Releaser,
    chunks: &Chunks,
    usage: &mut (i32, i32),
) -> TurnEnd {
    let mut parser = UpstreamParser::default();
    let mut pending = PendingCalls::default();
    loop {
        let bytes = match turn.chunk().await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break,
            Err(error) => {
                tracing::error!(%error, "upstream stream broke off");
                return TurnEnd::BrokeOff;
            }
        };
        for event in parser.feed(&bytes) {
            match event {
                Upstream::Delta(text) => {
                    if !chunks.step(releaser.push(policy, &text)).await {
                        return TurnEnd::Stopped;
                    }
                }
                Upstream::ToolCall { index, id, name, arguments } => {
                    pending.add(index, id, name, &arguments);
                }
                Upstream::Usage(prompt, completion) => {
                    usage.0 += prompt;
                    usage.1 += completion;
                }
                Upstream::Done => return finished(pending),
            }
        }
    }
    finished(pending)
}

fn finished(pending: PendingCalls) -> TurnEnd {
    if pending.is_empty() { TurnEnd::Answered } else { TurnEnd::Calls(pending) }
}

/// Read the upstream turn by turn, release checked text, run the tools the
/// model asks for, then police the whole answer and send its verdict. Holds
/// the budget's in-flight slots until the end.
async fn relay(
    state: AppState,
    exchange: Exchange,
    mut body: Value,
    first: Turn,
    sender: mpsc::Sender<Event>,
    _inflight: Inflight,
) {
    let started = Instant::now();
    let chunks = Chunks {
        id: format!("chatcmpl-{}", exchange.trace_id),
        model: exchange.model.clone(),
        sender,
    };
    let policy = exchange.policy.clone();
    let mut releaser = Releaser::default();
    let mut usage = (0, 0);
    let mut tool_calls = Vec::new();
    let mut failure: Option<Value> = None;

    let mut turn = first;
    for number in 1..=agent::MAX_TURNS {
        match read_turn(&mut turn, &policy, &mut releaser, &chunks, &mut usage).await {
            TurnEnd::Answered | TurnEnd::Stopped => break,
            TurnEnd::BrokeOff => {
                failure = Some(json!({ "type": "upstream_unavailable", "message": "the upstream model broke off the answer" }));
                break;
            }
            TurnEnd::Calls(pending) => {
                if number == agent::MAX_TURNS {
                    failure = Some(json!({
                        "type": "tool_loop_exceeded",
                        "message": format!("the model did not answer within {} turns", agent::MAX_TURNS),
                    }));
                    break;
                }
                let (calls, asked) = pending.finish();
                let (replies, reported) =
                    agent::run_calls(&state, &policy, &exchange.principal, &calls).await;
                tool_calls.extend(reported);
                if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
                    messages.push(asked);
                    messages.extend(replies);
                }
                turn = match open_turn(&state, &body).await {
                    Ok(turn) => turn,
                    Err(refused) => {
                        failure = Some(refused.error());
                        break;
                    }
                };
            }
        }
    }

    let upstream_us = micros(started);
    state.telemetry.observe("upstream", upstream_us);
    let answer = releaser.raw().to_owned();
    let outbound = police_answer(&state, &exchange, answer, usage, upstream_us).await;

    let error = match failure {
        Some(failure) => Some(failure),
        None => match releaser.release_from(&outbound, 0) {
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
        },
    };

    let last = match error {
        Some(error) => {
            tracing::info!(trace_id = %exchange.trace_id, code = %error["type"], message = %error["message"], "refused");
            json!({ "error": error, "trace_id": exchange.trace_id })
        }
        None => {
            let mut layer = control_layer(&exchange, &outbound);
            if !tool_calls.is_empty() {
                layer["tool_calls"] = json!(tool_calls);
            }
            json!({
                "id": chunks.id,
                "object": "chat.completion.chunk",
                "model": chunks.model,
                "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
                "usage": {
                    "prompt_tokens": usage.0,
                    "completion_tokens": usage.1,
                    "total_tokens": usage.0 + usage.1,
                },
                "x_control_layer": layer,
            })
        }
    };
    chunks.send(last.to_string()).await;
    chunks.send("[DONE]".to_owned()).await;
}

#[cfg(test)]
mod tests;

//! OpenAI-compatible chat endpoint.
//!
//! This is the integration surface: point any OpenAI client at the gateway and
//! every call is policed. Two of the four enforcement points are wired here —
//! `prompt_in` on the way out and `response_out` on the way back. `tool_call`
//! and `tool_result` are the same engine at the MCP boundary, which the model
//! reaches from here through [`agent`] when a request asks for tools.

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::admin::auth::bearer;
use crate::audit::{self, Auditor, Principal};
use crate::background::{self, Job};
use crate::budget::BUDGET_PREFIX;
use crate::engine::{self, ControlKind, Detection, Evaluation, Verdict};
use crate::helper::{self, Help};
use crate::policy::{Action, Hook, Policy, Severity};
use crate::risk::{self, RISK_CONTROL};
use crate::state::AppState;
use crate::telemetry::Telemetry;

/// Detection id for a model outside the allow lists.
pub const MODEL_NOT_ALLOWED: &str = "model.not-allowed";

/// Header a delegating principal names its end user in.
pub const ON_BEHALF_OF: &str = "x-on-behalf-of";

/// Authenticate the gateway's integration endpoints. Identity arrives only
/// from a per-principal Bearer key, and the database maps its hash to the
/// principal. A principal allowed to delegate may name the end user it acts
/// for; that name is trusted because the key is, never on its own.
pub async fn bearer_principal(
    auditor: &Auditor,
    headers: &HeaderMap,
) -> Result<Principal, Response> {
    let Some(key) = bearer(headers) else {
        return Err(authentication_refusal(
            "missing or malformed Bearer API key",
        ));
    };
    let mut principal = auditor
        .principal_for_api_key(key)
        .await
        .ok_or_else(|| authentication_refusal("invalid or disabled API key"))?;
    // A header that is not visible ASCII reads as empty, which is refused.
    let asserted = headers
        .get(ON_BEHALF_OF)
        .map(|value| value.to_str().unwrap_or_default());
    principal.user = delegated_user(&principal, asserted).map_err(|message| {
        (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "type": "delegation_refused", "message": message } })),
        )
            .into_response()
    })?;
    Ok(principal)
}

/// The user a request is attributed to: the named end user when the principal
/// may delegate, otherwise the principal itself.
pub fn delegated_user(principal: &Principal, asserted: Option<&str>) -> Result<String, &'static str> {
    let Some(asserted) = asserted else {
        return Ok(principal.slug.clone());
    };
    if !principal.delegates_users {
        return Err("this identity may not act on behalf of users");
    }
    let user = asserted.trim();
    if user.is_empty() || user.len() > 254 || user.chars().any(char::is_control) {
        return Err("X-On-Behalf-Of must be a printable user id of at most 254 bytes");
    }
    Ok(user.to_owned())
}

fn authentication_refusal(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": { "type": "authentication_required", "message": message } })),
    )
        .into_response()
}

/// The global deny list wins, then the global allow list, then the identity's
/// own grant narrows it. Grants are deny-by-default.
pub fn gate_model(policy: &Policy, principal: &Principal, model: &str, evaluation: &mut Evaluation) {
    let reason = if !policy.model_allowed(model) {
        format!("model {model} is not in the allow list")
    } else if !principal.may_use_model(model) {
        format!("model {model} is not granted to this identity")
    } else {
        return;
    };
    evaluation.gate(MODEL_NOT_ALLOWED.to_owned(), Severity::High, Action::Block, reason);
}

pub async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let started = Instant::now();
    let trace_id = Uuid::new_v4();
    let policy = state.policy.load_full();

    let principal = match bearer_principal(&state.auditor, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    // --- hook 1: prompt_in ------------------------------------------------
    let prompt = extract_prompt(&body);
    let mut inbound = engine::evaluate(&policy, Hook::PromptIn, &prompt);
    state.telemetry.observe("deterministic", inbound.deterministic_us);

    // Model grants (§4.1), budgets (§4.3) and history (§4.4) gate the same
    // evaluation, so a refusal is audited like any control.
    gate_model(&policy, &principal, &model, &mut inbound);
    let inflight = state
        .budgets
        .check(&principal, Some(&model), &mut inbound)
        .await;
    risk::apply(state.db(), &policy.risk, &principal.user, &mut inbound).await;

    // A request already refused should not also pay for the semantic tier.
    if inbound.verdict != Verdict::Block {
        engine::escalate(&policy, Hook::PromptIn, &mut inbound, &state.detectors).await;
        observe_semantic(&state.telemetry, &inbound);
    }

    let help = match inbound.blocked_by() {
        Some(blocker) if is_content_control(&blocker.control_id) => {
            helper::help(&policy, &state.detectors, &prompt, &inbound).await
        }
        _ => None,
    };
    if let Some(help) = &help {
        inbound.gate(
            "helper.suggestion".to_owned(),
            Severity::Info,
            Action::Allow,
            format!(
                "{}; rewrite {}",
                help.violated_policy,
                if help.suggestion.is_some() { "offered" } else { "unavailable" }
            ),
        );
    }

    let event_id = state
        .auditor
        .record(audit::record_for(
            trace_id,
            Hook::PromptIn,
            &inbound,
            Some(&model),
            &principal,
            policy.version_id,
            &prompt,
        ))
        .await;
    state.telemetry.verdict("prompt_in", verdict_name(inbound.verdict));

    if let Some(blocker) = inbound.blocked_by() {
        return refusal_for(trace_id, Hook::PromptIn, blocker, help, risk::of(&inbound));
    }
    background::analyse(
        &state,
        &inbound,
        Job {
            policy: policy.clone(),
            hook: Hook::PromptIn,
            channel: "llm",
            text: prompt.clone(),
            trace_id,
            principal: principal.clone(),
            model: Some(model.clone()),
            tool: None,
        },
    );

    // Forward the redacted conversation, never the original.
    let mut upstream_body = body.clone();
    if inbound.verdict == Verdict::Redact {
        redact_messages(&policy, &mut upstream_body);
    }

    let exchange = Exchange {
        trace_id,
        started,
        policy,
        principal,
        model,
        inbound,
        event_id,
    };
    // The tool loop needs each turn whole, so an `"mcp": true` request is
    // answered buffered even when it asks to stream.
    let with_tools = body.get("mcp").and_then(Value::as_bool) == Some(true);
    if !with_tools && body.get("stream").and_then(Value::as_bool) == Some(true) {
        return stream::respond(state, exchange, upstream_body, inflight).await;
    }
    upstream_body["stream"] = json!(false);

    // --- upstream, and the MCP tools the model calls on the way -------------
    let upstream_started = Instant::now();
    let agent::Reply { status, mut completion, tool_calls } =
        match agent::complete(&state, &exchange.policy, &exchange.principal, trace_id, upstream_body).await {
            Ok(reply) => reply,
            Err(refused) => return refused,
        };
    let upstream_us = micros(upstream_started);
    state.telemetry.observe("upstream", upstream_us);

    if !status.is_success() {
        return (status, Json(completion)).into_response();
    }

    // --- hook 2: response_out --------------------------------------------
    let answer = extract_answer(&completion);
    let outbound =
        police_answer(&state, &exchange, answer, usage(&completion), upstream_us).await;
    drop(inflight);

    if let Some(blocker) = outbound.blocked_by() {
        let risk_score = risk::of(&exchange.inbound) + risk::of(&outbound);
        return refusal_for(trace_id, Hook::ResponseOut, blocker, None, risk_score);
    }
    if outbound.verdict == Verdict::Redact {
        replace_answer(&mut completion, &outbound.text);
    }

    // Make the layer's work visible to the caller rather than silently
    // rewriting their data.
    completion["x_control_layer"] = control_layer(&exchange, &outbound);
    completion["x_control_layer"]["tool_calls"] = json!(tool_calls);

    (StatusCode::OK, Json(completion)).into_response()
}

/// What a request carries past `prompt_in`, for policing its answer.
pub(crate) struct Exchange {
    pub trace_id: Uuid,
    pub started: Instant,
    pub policy: Arc<Policy>,
    pub principal: Principal,
    pub model: String,
    pub inbound: Evaluation,
    /// The `prompt_in` audit event, for usage when `response_out` was not recorded.
    pub event_id: Option<i64>,
}

/// Hook 2, `response_out`, over a complete answer: both tiers, the audit
/// record and the usage. Shared by the plain and the streamed response, so a
/// streamed answer is judged and audited exactly like a buffered one.
pub(crate) async fn police_answer(
    state: &AppState,
    exchange: &Exchange,
    answer: String,
    (prompt_tokens, completion_tokens): (i32, i32),
    upstream_us: u64,
) -> Evaluation {
    let policy = &exchange.policy;
    let mut outbound = engine::evaluate(policy, Hook::ResponseOut, &answer);
    state.telemetry.observe("deterministic", outbound.deterministic_us);
    engine::escalate(policy, Hook::ResponseOut, &mut outbound, &state.detectors).await;
    observe_semantic(&state.telemetry, &outbound);

    let mut outbound_record = audit::record_for(
        exchange.trace_id,
        Hook::ResponseOut,
        &outbound,
        Some(&exchange.model),
        &exchange.principal,
        policy.version_id,
        &answer,
    );
    outbound_record.latency = json!({
        "deterministic_us": outbound.deterministic_us,
        "semantic_us": outbound.semantic_us,
        "upstream_us": upstream_us,
    });
    let outbound_event = state.auditor.record(outbound_record).await;
    state.telemetry.verdict("response_out", verdict_name(outbound.verdict));

    // Usage is recorded even when the answer is blocked: the tokens were spent.
    state
        .auditor
        .record_usage(
            outbound_event.or(exchange.event_id),
            &exchange.principal,
            &exchange.model,
            prompt_tokens,
            completion_tokens,
            policy.cost_usd(&exchange.model, prompt_tokens, completion_tokens),
        )
        .await;
    state
        .telemetry
        .observe("total", micros(exchange.started).saturating_sub(upstream_us));

    if outbound.blocked_by().is_none() {
        background::analyse(
            state,
            &outbound,
            Job {
                policy: policy.clone(),
                hook: Hook::ResponseOut,
                channel: "llm",
                text: answer,
                trace_id: exchange.trace_id,
                principal: exchange.principal.clone(),
                model: Some(exchange.model.clone()),
                tool: None,
            },
        );
    }
    outbound
}

/// The `x_control_layer` block a successful answer carries.
pub(crate) fn control_layer(exchange: &Exchange, outbound: &Evaluation) -> Value {
    json!({
        "trace_id": exchange.trace_id,
        "policy_version": exchange.policy.sha256,
        "prompt_in": summarise(&exchange.inbound),
        "response_out": summarise(outbound),
    })
}

/// Content controls get the prompt helper; refusals about who is asking (model
/// grant, budget, history) have no compliant rewrite to offer.
fn is_content_control(control_id: &str) -> bool {
    control_id != MODEL_NOT_ALLOWED
        && control_id != RISK_CONTROL
        && !control_id.starts_with(BUDGET_PREFIX)
}

/// Which check refused: `deterministic` or `semantic` for a content control,
/// `access` for who is asking (model grant, budget, history). Lets a client
/// tell "this prompt breaks a pattern rule" from everything else.
pub const fn stage_of(blocker: &Detection) -> &'static str {
    match blocker.kind {
        ControlKind::Semantic => "semantic",
        ControlKind::Deterministic => "deterministic",
    }
}

/// `risk_score` is what the request added to its user's attack history, so
/// a caller can see how the refusal counts against them.
fn refusal_for(
    trace_id: Uuid,
    hook: Hook,
    blocker: &Detection,
    help: Option<Help>,
    risk_score: f32,
) -> Response {
    let (status, mut error) = refusal_body(hook, blocker, help);
    error["risk_score"] = json!(risk_score);
    refusal(trace_id, status, error)
}

/// The status and `error` object a refusal carries. A streamed answer sends
/// the same object as its last event.
pub(crate) fn refusal_body(hook: Hook, blocker: &Detection, help: Option<Help>) -> (StatusCode, Value) {
    let control = blocker.control_id.as_str();
    let reason = &blocker.evidence.excerpt;
    let (status, code, message, stage) = if control == MODEL_NOT_ALLOWED {
        (StatusCode::FORBIDDEN, "model_not_allowed", reason.clone(), "access")
    } else if control.starts_with(BUDGET_PREFIX) {
        (StatusCode::TOO_MANY_REQUESTS, "budget_exceeded", reason.clone(), "access")
    } else if control == RISK_CONTROL {
        (
            StatusCode::FORBIDDEN,
            "risk_blocked",
            "too many recent policy violations; try again later".to_owned(),
            "access",
        )
    } else {
        let subject = if hook == Hook::PromptIn { "request" } else { "response" };
        (
            StatusCode::FORBIDDEN,
            "blocked_by_control",
            format!("{subject} blocked by {control}"),
            stage_of(blocker),
        )
    };
    let mut error = json!({ "type": code, "message": message, "stage": stage, "hook": hook });
    if let Some(help) = help {
        error["helper"] = json!(help);
    }
    (status, error)
}

fn observe_semantic(telemetry: &Telemetry, evaluation: &Evaluation) {
    if evaluation.semantic_us > 0 {
        telemetry.observe("semantic", evaluation.semantic_us);
    }
}

pub(crate) fn micros(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_micros()).unwrap_or(u64::MAX)
}

pub const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Redact => "redact",
        Verdict::Block => "block",
    }
}

pub fn summarise(evaluation: &Evaluation) -> Value {
    json!({
        "verdict": evaluation.verdict,
        "controls_fired": evaluation.detections.iter().map(|d| &d.control_id).collect::<Vec<_>>(),
        "risk_score": risk::of(evaluation),
        "deterministic_us": evaluation.deterministic_us,
        "semantic_us": evaluation.semantic_us,
    })
}

pub(crate) fn refusal(trace_id: Uuid, status: StatusCode, error: Value) -> Response {
    tracing::info!(%trace_id, code = %error["type"], message = %error["message"], "refused");
    (status, Json(json!({ "error": error, "trace_id": trace_id }))).into_response()
}

// ---------------------------------------------------------------- payloads

/// The text of one message's `content`: a plain string, or the text parts of
/// an array of content parts. Anything the model would read must be seen.
fn content_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Everything the model will read, concatenated. Controls run over the whole
/// conversation, not just the newest turn — an injection planted three
/// messages ago is still an injection.
pub fn extract_prompt(body: &Value) -> String {
    body.get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .filter_map(|m| m.get("content"))
                .map(content_text)
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Redact every message in place, each on its own, so the conversation keeps
/// its shape and every turn its own content.
pub fn redact_messages(policy: &Policy, body: &mut Value) {
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for content in messages.iter_mut().filter_map(|m| m.get_mut("content")) {
        match content {
            Value::String(text) => *text = engine::redact(policy, Hook::PromptIn, text),
            Value::Array(parts) => {
                for text in parts.iter_mut().filter_map(|p| p.get_mut("text")) {
                    if let Value::String(inner) = text {
                        *inner = engine::redact(policy, Hook::PromptIn, inner);
                    }
                }
            }
            _ => {}
        }
    }
}

fn extract_answer(completion: &Value) -> String {
    completion
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .map(content_text)
        .unwrap_or_default()
}

fn replace_answer(completion: &mut Value, text: &str) {
    if let Some(content) = completion
        .get_mut("choices")
        .and_then(Value::as_array_mut)
        .and_then(|choices| choices.first_mut())
        .and_then(|choice| choice.get_mut("message"))
        .and_then(|message| message.get_mut("content"))
    {
        *content = Value::String(text.to_owned());
    }
}

fn usage(completion: &Value) -> (i32, i32) {
    let usage = completion.get("usage");
    let field = |name: &str| {
        usage
            .and_then(|u| u.get(name))
            .and_then(Value::as_i64)
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or_default()
    };
    (field("prompt_tokens"), field("completion_tokens"))
}

mod agent;
mod stream;
#[cfg(test)]
mod tests;

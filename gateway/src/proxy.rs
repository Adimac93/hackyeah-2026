//! OpenAI-compatible chat endpoint.
//!
//! This is the integration surface: point any OpenAI client at the gateway and
//! every call is policed. Two of the four enforcement points are wired here —
//! `prompt_in` on the way out and `response_out` on the way back. `tool_call`
//! and `tool_result` are the same engine at the MCP boundary.

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
use crate::engine::{self, Evaluation, Verdict};
use crate::helper::{self, Help};
use crate::policy::{Action, Hook, Policy, Severity};
use crate::risk::{self, RISK_CONTROL};
use crate::state::AppState;
use crate::{mock, telemetry::Telemetry};

/// Detection id for a model outside the allow lists.
pub const MODEL_NOT_ALLOWED: &str = "model.not-allowed";

/// Authenticate the gateway's integration endpoints. There is no
/// `X-Principal` escape hatch: identity arrives only from a per-principal
/// Bearer key, and the database maps its hash to the principal.
pub async fn bearer_principal(
    auditor: &Auditor,
    headers: &HeaderMap,
) -> Result<Principal, Response> {
    let Some(key) = bearer(headers) else {
        return Err(authentication_refusal(
            "missing or malformed Bearer API key",
        ));
    };
    auditor
        .principal_for_api_key(key)
        .await
        .ok_or_else(|| authentication_refusal("invalid or disabled API key"))
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
    let _inflight = state
        .budgets
        .check(&principal, Some(&model), &mut inbound)
        .await;
    risk::apply(state.db(), &policy.risk, principal.id, &mut inbound).await;

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
            Some(principal.id),
            policy.version_id,
            &prompt,
        ))
        .await;
    state.telemetry.verdict("prompt_in", verdict_name(inbound.verdict));

    if let Some(blocker) = inbound.blocked_by() {
        return refusal_for(trace_id, &blocker.control_id, &blocker.evidence.excerpt, help);
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
            principal_id: principal.id,
            model: Some(model.clone()),
            tool: None,
        },
    );

    // Forward the redacted conversation, never the original.
    let mut upstream_body = body.clone();
    if inbound.verdict == Verdict::Redact {
        redact_messages(&policy, &mut upstream_body);
    }

    // --- upstream ---------------------------------------------------------
    let upstream_started = Instant::now();
    let (status, mut completion) = if state.upstream == mock::MOCK {
        (StatusCode::OK, mock::completion(&upstream_body))
    } else {
        let reply = forward(&state, trace_id, &upstream_body).await;
        state.telemetry.dependency("upstream", reply.is_ok());
        match reply {
            Ok(reply) => reply,
            Err(refused) => return refused,
        }
    };
    let upstream_us = micros(upstream_started);
    state.telemetry.observe("upstream", upstream_us);

    if !status.is_success() {
        return (status, Json(completion)).into_response();
    }

    // --- hook 2: response_out --------------------------------------------
    let answer = extract_answer(&completion);
    let mut outbound = engine::evaluate(&policy, Hook::ResponseOut, &answer);
    state.telemetry.observe("deterministic", outbound.deterministic_us);
    engine::escalate(&policy, Hook::ResponseOut, &mut outbound, &state.detectors).await;
    observe_semantic(&state.telemetry, &outbound);

    let mut outbound_record = audit::record_for(
        trace_id,
        Hook::ResponseOut,
        &outbound,
        Some(&model),
        Some(principal.id),
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
    let (prompt_tokens, completion_tokens) = usage(&completion);
    state
        .auditor
        .record_usage(
            outbound_event.or(event_id),
            Some(principal.id),
            &model,
            prompt_tokens,
            completion_tokens,
            policy.cost_usd(&model, prompt_tokens, completion_tokens),
        )
        .await;
    state
        .telemetry
        .observe("total", micros(started).saturating_sub(upstream_us));

    if outbound.verdict == Verdict::Block {
        let control = outbound
            .blocked_by()
            .map_or("policy", |d| d.control_id.as_str());
        return refusal(
            trace_id,
            StatusCode::FORBIDDEN,
            "blocked_by_control",
            &format!("response blocked by {control}"),
            None,
        );
    }
    background::analyse(
        &state,
        &outbound,
        Job {
            policy: policy.clone(),
            hook: Hook::ResponseOut,
            channel: "llm",
            text: answer,
            trace_id,
            principal_id: principal.id,
            model: Some(model),
            tool: None,
        },
    );

    if outbound.verdict == Verdict::Redact {
        replace_answer(&mut completion, &outbound.text);
    }

    // Make the layer's work visible to the caller rather than silently
    // rewriting their data.
    completion["x_control_layer"] = json!({
        "trace_id": trace_id,
        "policy_version": policy.sha256,
        "prompt_in": summarise(&inbound),
        "response_out": summarise(&outbound),
    });

    (StatusCode::OK, Json(completion)).into_response()
}

/// Content controls get the prompt helper; refusals about who is asking (model
/// grant, budget, history) have no compliant rewrite to offer.
fn is_content_control(control_id: &str) -> bool {
    control_id != MODEL_NOT_ALLOWED
        && control_id != RISK_CONTROL
        && !control_id.starts_with(BUDGET_PREFIX)
}

fn refusal_for(trace_id: Uuid, control: &str, reason: &str, help: Option<Help>) -> Response {
    if control == MODEL_NOT_ALLOWED {
        refusal(trace_id, StatusCode::FORBIDDEN, "model_not_allowed", reason, None)
    } else if control.starts_with(BUDGET_PREFIX) {
        refusal(trace_id, StatusCode::TOO_MANY_REQUESTS, "budget_exceeded", reason, None)
    } else if control == RISK_CONTROL {
        refusal(
            trace_id,
            StatusCode::FORBIDDEN,
            "risk_blocked",
            "too many recent policy violations; try again later",
            None,
        )
    } else {
        refusal(
            trace_id,
            StatusCode::FORBIDDEN,
            "blocked_by_control",
            &format!("request blocked by {control}"),
            help,
        )
    }
}

fn observe_semantic(telemetry: &Telemetry, evaluation: &Evaluation) {
    if evaluation.semantic_us > 0 {
        telemetry.observe("semantic", evaluation.semantic_us);
    }
}

fn micros(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_micros()).unwrap_or(u64::MAX)
}

pub const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Redact => "redact",
        Verdict::Block => "block",
    }
}

async fn forward(
    state: &AppState,
    trace_id: Uuid,
    body: &Value,
) -> Result<(StatusCode, Value), Response> {
    let upstream = state
        .http
        .post(format!("{}/v1/chat/completions", state.upstream))
        .json(body)
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, "upstream request failed");
            refusal(
                trace_id,
                StatusCode::BAD_GATEWAY,
                "upstream_unavailable",
                "the upstream model is unreachable",
                None,
            )
        })?;

    let status = upstream.status();
    let completion = upstream.json::<Value>().await.map_err(|_| {
        refusal(
            trace_id,
            StatusCode::BAD_GATEWAY,
            "upstream_unreadable",
            "the upstream response was not JSON",
            None,
        )
    })?;
    Ok((status, completion))
}

pub fn summarise(evaluation: &Evaluation) -> Value {
    json!({
        "verdict": evaluation.verdict,
        "controls_fired": evaluation.detections.iter().map(|d| &d.control_id).collect::<Vec<_>>(),
        "deterministic_us": evaluation.deterministic_us,
        "semantic_us": evaluation.semantic_us,
    })
}

fn refusal(
    trace_id: Uuid,
    status: StatusCode,
    code: &str,
    message: &str,
    help: Option<Help>,
) -> Response {
    tracing::info!(%trace_id, code, message, "refused");
    let mut error = json!({ "type": code, "message": message });
    if let Some(help) = help {
        error["helper"] = json!(help);
    }
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

#[cfg(test)]
mod tests;

//! OpenAI-compatible chat endpoint.
//!
//! This is the integration surface: point any OpenAI client at the gateway and
//! every call is policed. Two of the four enforcement points are wired here —
//! `prompt_in` on the way out and `response_out` on the way back. `tool_call`
//! and `tool_result` are the same engine at the MCP boundary, which lands with
//! the MCP proxy.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::audit::{self, Auditor};
use crate::engine::{self, Verdict};
use crate::policy::{Budget, Hook, Policy, PolicyHandle};
use crate::semantic::Registry;

/// Everything a request needs. Cloned per request, so each field is cheap.
#[derive(Clone)]
pub struct ProxyState {
    pub policy: PolicyHandle,
    pub auditor: std::sync::Arc<Auditor>,
    pub http: reqwest::Client,
    pub upstream: String,
    pub detectors: std::sync::Arc<Registry>,
}

pub async fn chat_completions(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let trace_id = Uuid::new_v4();
    let policy = state.policy.load();
    let policy_version_id = state
        .auditor
        .policy_version_id(&policy.sha256, &policy.source)
        .await;

    let slug = headers
        .get("x-principal")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous")
        .to_owned();
    let principal_id = state.auditor.principal_id(&slug).await;

    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    // --- model allow list (§4.1) -----------------------------------------
    if !policy.model_allowed(&model) {
        return refusal(
            trace_id,
            StatusCode::FORBIDDEN,
            "model_not_allowed",
            &format!("model {model} is not in the allow list"),
        );
    }

    // --- budget (§4.3) ----------------------------------------------------
    if let Some(reason) = over_budget(&policy, &state.auditor, principal_id, &slug, &model).await {
        return refusal(
            trace_id,
            StatusCode::TOO_MANY_REQUESTS,
            "budget_exceeded",
            &reason,
        );
    }

    // --- hook 1: prompt_in ------------------------------------------------
    let prompt = extract_prompt(&body);
    let mut inbound = engine::evaluate(&policy, Hook::PromptIn, &prompt);
    engine::escalate(&policy, Hook::PromptIn, &mut inbound, &state.detectors).await;

    let event_id = state
        .auditor
        .record(audit::record_for(
            trace_id,
            Hook::PromptIn,
            &inbound,
            Some(&model),
            principal_id,
            policy_version_id,
            &prompt,
        ))
        .await;

    if inbound.verdict == Verdict::Block {
        let control = inbound
            .blocked_by()
            .map_or("policy", |d| d.control_id.as_str());
        return refusal(
            trace_id,
            StatusCode::FORBIDDEN,
            "blocked_by_control",
            &format!("request blocked by {control}"),
        );
    }

    // Forward the redacted text, never the original.
    let mut upstream_body = body.clone();
    if inbound.verdict == Verdict::Redact {
        replace_prompt(&mut upstream_body, &inbound.text);
    }

    // --- upstream ---------------------------------------------------------
    let started = std::time::Instant::now();
    let upstream = state
        .http
        .post(format!("{}/v1/chat/completions", state.upstream))
        .json(&upstream_body)
        .send()
        .await;

    let upstream = match upstream {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "upstream request failed");
            return refusal(
                trace_id,
                StatusCode::BAD_GATEWAY,
                "upstream_unavailable",
                "the upstream model is unreachable",
            );
        }
    };

    let status = upstream.status();
    let Ok(mut completion) = upstream.json::<Value>().await else {
        return refusal(
            trace_id,
            StatusCode::BAD_GATEWAY,
            "upstream_unreadable",
            "the upstream response was not JSON",
        );
    };
    let upstream_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);

    if !status.is_success() {
        return (status, Json(completion)).into_response();
    }

    // --- hook 2: response_out --------------------------------------------
    let answer = extract_answer(&completion);
    let mut outbound = engine::evaluate(&policy, Hook::ResponseOut, &answer);
    engine::escalate(&policy, Hook::ResponseOut, &mut outbound, &state.detectors).await;

    let mut outbound_record = audit::record_for(
        trace_id,
        Hook::ResponseOut,
        &outbound,
        Some(&model),
        principal_id,
        policy_version_id,
        &answer,
    );
    outbound_record.latency = json!({
        "deterministic_us": outbound.deterministic_us,
        "semantic_us": outbound.semantic_us,
        "upstream_us": upstream_us,
    });
    let outbound_event = state.auditor.record(outbound_record).await;

    // Usage is recorded even when the answer is blocked: the tokens were spent.
    let (prompt_tokens, completion_tokens) = usage(&completion);
    state
        .auditor
        .record_usage(
            outbound_event.or(event_id),
            principal_id,
            &model,
            prompt_tokens,
            completion_tokens,
            policy.cost_usd(&model, prompt_tokens, completion_tokens),
        )
        .await;

    if outbound.verdict == Verdict::Block {
        let control = outbound
            .blocked_by()
            .map_or("policy", |d| d.control_id.as_str());
        return refusal(
            trace_id,
            StatusCode::FORBIDDEN,
            "blocked_by_control",
            &format!("response blocked by {control}"),
        );
    }

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

fn summarise(evaluation: &engine::Evaluation) -> Value {
    json!({
        "verdict": evaluation.verdict,
        "controls_fired": evaluation.detections.iter().map(|d| &d.control_id).collect::<Vec<_>>(),
        "deterministic_us": evaluation.deterministic_us,
        "semantic_us": evaluation.semantic_us,
    })
}

fn refusal(trace_id: Uuid, status: StatusCode, code: &str, message: &str) -> Response {
    tracing::info!(%trace_id, code, message, "refused");
    (
        status,
        Json(json!({
            "error": { "type": code, "message": message },
            "trace_id": trace_id,
        })),
    )
        .into_response()
}

/// Budget check. The global budget applies to everyone, a model budget to all
/// traffic on that model, a principal budget to that caller. A soft budget
/// warns instead of refusing.
async fn over_budget(
    policy: &Policy,
    auditor: &Auditor,
    principal_id: Option<Uuid>,
    slug: &str,
    model: &str,
) -> Option<String> {
    if !auditor.enabled() {
        return None;
    }

    let mut checks: Vec<(&str, Option<Uuid>, Option<&str>, &Budget)> = Vec::new();
    if let Some(budget) = policy.budgets.global.as_ref() {
        checks.push(("global", None, None, budget));
    }
    // Without a resolved principal the usage cannot be attributed, and summing
    // everyone's would charge this caller for the whole organisation.
    if let (Some(budget), Some(id)) = (policy.budgets.principal.get(slug), principal_id) {
        checks.push((slug, Some(id), None, budget));
    }
    if let Some(budget) = policy.budgets.model.get(model) {
        checks.push((model, None, Some(model), budget));
    }

    for (scope, owner, model, budget) in checks {
        let (tokens, usd) = auditor
            .usage_in_window(owner, model, budget.window_secs)
            .await;
        let spent = match (budget.limit_tokens, budget.limit_usd) {
            (Some(limit), _) if tokens >= limit => format!("{tokens}/{limit} tokens"),
            (_, Some(limit)) if usd >= limit => format!("${usd:.4}/${limit:.2}"),
            _ => continue,
        };
        if budget.hard {
            return Some(format!(
                "{scope} budget exhausted: {spent} in the last {}s",
                budget.window_secs
            ));
        }
        tracing::warn!(scope, %spent, "soft budget exceeded");
    }
    None
}

// ---------------------------------------------------------------- payloads

/// Everything the model will read, concatenated. Controls run over the whole
/// conversation, not just the newest turn — an injection planted three
/// messages ago is still an injection.
fn extract_prompt(body: &Value) -> String {
    body.get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .filter_map(|m| m.get("content").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Redaction rewrites the last user message, which is where the finding
/// realistically sits in a single-turn demo.
fn replace_prompt(body: &mut Value, text: &str) {
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut)
        && let Some(last) = messages.last_mut()
        && let Some(content) = last.get_mut("content")
    {
        *content = Value::String(text.to_owned());
    }
}

fn extract_answer(completion: &Value) -> String {
    completion
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
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

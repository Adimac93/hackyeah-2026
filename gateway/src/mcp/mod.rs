//! The MCP enforcement point.
//!
//! The gateway is the only MCP server any agent talks to; real servers sit
//! behind it. Two of the four hooks live here:
//!
//! - `tool_call`   — what the agent is about to ask a tool to do
//! - `tool_result` — what comes back, before it reaches the model's context
//!
//! The second one matters most. A user typing "ignore previous instructions" is
//! the attack everyone demonstrates; a poisoned document returned by a tool is
//! the attack that works.
//!
//! Protocol revision 2026-07-28, which is stateless: no handshake, no session.
//! Every request is self-contained, so enforcement is per-request.

pub mod federation;

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::audit::{self, Auditor};
use crate::engine::{self, Verdict};
use crate::policy::{Hook, Policy, PolicyHandle, UnknownPrincipal};

use federation::PROTOCOL_VERSION;

/// Reserved by the spec for transport-level header/body disagreement.
const HEADER_MISMATCH: i64 = -32020;
const METHOD_NOT_FOUND: i64 = -32601;
/// -32000..-32019 is the implementation-defined range. Policy outcomes are
/// ours, not the protocol's.
const POLICY_DENIED: i64 = -32000;
const PRINCIPAL_DENIED: i64 = -32001;
const UPSTREAM_ERROR: i64 = -32002;

#[derive(Clone)]
pub struct McpState {
    pub policy: PolicyHandle,
    pub auditor: Arc<Auditor>,
    pub http: reqwest::Client,
    pub policy_version_id: Option<i64>,
}

pub async fn endpoint(
    State(state): State<McpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let params = body.get("params").cloned().unwrap_or(Value::Null);
    let policy = state.policy.load();

    // The body is the source of truth. A request that says one thing in its
    // headers and another in its body is trying to be routed as one method and
    // executed as another, so it is refused rather than reconciled.
    if let Some(problem) = header_mismatch(&headers, &method, &params) {
        tracing::warn!(%problem, "refusing a header/body mismatch");
        return error(&id, HEADER_MISMATCH, &problem);
    }

    let slug = headers
        .get("x-principal")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous")
        .to_owned();
    let principal = state.auditor.principal(&slug).await;

    if principal.is_none() && policy.mcp.unknown_principal == UnknownPrincipal::Deny {
        return error(
            &id,
            PRINCIPAL_DENIED,
            &format!("principal {slug} is not registered"),
        );
    }

    match method.as_str() {
        "server/discover" => discover(&id),
        "tools/list" => tools_list(&state, &policy, principal.as_ref(), &id).await,
        "tools/call" => tools_call(&state, &policy, principal.as_ref(), &slug, &id, &params).await,
        // Deny by default: an unlisted method is not proxied to upstreams that
        // might implement it.
        other => error(
            &id,
            METHOD_NOT_FOUND,
            &format!("method {other} is not served"),
        ),
    }
}

/// Spec 2026-07-28 requires servers to implement `server/discover`.
fn discover(id: &Value) -> Response {
    result(
        id,
        json!({
            "resultType": "complete",
            "protocolVersions": [PROTOCOL_VERSION],
            "serverInfo": { "name": "ai-control-layer", "version": env!("CARGO_PKG_VERSION") },
            "capabilities": { "tools": {} },
        }),
    )
}

async fn tools_list(
    state: &McpState,
    policy: &Policy,
    principal: Option<&crate::audit::Principal>,
    id: &Value,
) -> Response {
    let mut tools = Vec::new();

    for server in policy.mcp.enabled_servers() {
        match federation::call(&state.http, server, "tools/list", None, json!({})).await {
            Ok(listing) => {
                let upstream = listing
                    .get("tools")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for mut tool in upstream {
                    if let Some(name) = tool.get("name").and_then(Value::as_str) {
                        tool["name"] = Value::String(federation::qualify(&server.name, name));
                    }
                    tools.push(tool);
                }
            }
            Err(problem) => tracing::warn!(%problem, "an upstream could not be listed"),
        }
    }

    // A tool the caller may not invoke is a tool they should not be shown.
    if let Some(principal) = principal
        && !principal.allowed_tools.is_empty()
    {
        tools.retain(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| principal.allowed_tools.iter().any(|t| t == name))
        });
    }

    result(
        id,
        json!({
            "resultType": "complete",
            "tools": tools,
            "ttlMs": 30_000,
            // The listing is filtered per principal, so a shared intermediary
            // must never serve one caller's list to another.
            "cacheScope": "private",
        }),
    )
}

async fn tools_call(
    state: &McpState,
    policy: &Policy,
    principal: Option<&crate::audit::Principal>,
    slug: &str,
    id: &Value,
    params: &Value,
) -> Response {
    let trace_id = Uuid::new_v4();
    let principal_id = principal.map(|p| p.id);

    let Some(qualified) = params.get("name").and_then(Value::as_str) else {
        return error(id, POLICY_DENIED, "tools/call requires a tool name");
    };

    // Checked again here, not only at list time: a client can call a tool it
    // was never shown.
    if let Some(principal) = principal
        && !principal.allowed_tools.is_empty()
        && !principal.allowed_tools.iter().any(|t| t == qualified)
    {
        tracing::warn!(%slug, tool = %qualified, "tool not permitted for this principal");
        return error(
            id,
            PRINCIPAL_DENIED,
            &format!("{slug} may not call {qualified}"),
        );
    }

    let Some((server_name, tool)) = federation::split(qualified) else {
        return error(
            id,
            POLICY_DENIED,
            &format!("{qualified} is not a federated tool name (expected server__tool)"),
        );
    };
    let Some(server) = policy.mcp.server(server_name) else {
        return error(
            id,
            POLICY_DENIED,
            &format!("no enabled server named {server_name}"),
        );
    };

    // --- hook 3: tool_call ------------------------------------------------
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
    let rendered = arguments.to_string();
    let outbound = engine::evaluate(policy, Hook::ToolCall, &rendered);

    record(
        state,
        trace_id,
        Hook::ToolCall,
        &outbound,
        qualified,
        principal_id,
        &rendered,
    )
    .await;

    if outbound.verdict == Verdict::Block {
        let control = outbound
            .blocked_by()
            .map_or("policy", |d| d.control_id.as_str());
        return error(
            id,
            POLICY_DENIED,
            &format!("tool call blocked by {control}"),
        );
    }

    let forwarded = if outbound.verdict == Verdict::Redact {
        // Redaction rewrote a JSON document as text. If it no longer parses we
        // refuse rather than forward something we cannot reason about.
        match serde_json::from_str::<Value>(&outbound.text) {
            Ok(value) => value,
            Err(error_) => {
                tracing::error!(%error_, "redaction produced invalid JSON arguments");
                return error(
                    id,
                    POLICY_DENIED,
                    "redaction could not be applied safely to the tool arguments",
                );
            }
        }
    } else {
        arguments
    };

    // --- upstream ---------------------------------------------------------
    let started = std::time::Instant::now();
    let upstream = federation::call(
        &state.http,
        server,
        "tools/call",
        Some(tool),
        json!({ "name": tool, "arguments": forwarded }),
    )
    .await;
    let upstream_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);

    let mut payload = match upstream {
        Ok(value) => value,
        Err(problem) => {
            tracing::error!(%problem, "upstream tool call failed");
            return error(id, UPSTREAM_ERROR, &problem);
        }
    };

    // --- hook 4: tool_result ---------------------------------------------
    // Nothing reaches the model's context unevaluated.
    let text = federation::result_text(&payload);
    let inbound = engine::evaluate(policy, Hook::ToolResult, &text);

    let mut inbound_record = audit::record_for(
        trace_id,
        Hook::ToolResult,
        &inbound,
        None,
        principal_id,
        state.policy_version_id,
        &text,
    );
    inbound_record.channel = "mcp";
    inbound_record.tool = Some(qualified);
    inbound_record.latency = json!({
        "deterministic_us": inbound.deterministic_us,
        "upstream_us": upstream_us,
    });
    state.auditor.record(inbound_record).await;

    if inbound.verdict == Verdict::Block {
        let control = inbound
            .blocked_by()
            .map_or("policy", |d| d.control_id.as_str());
        tracing::warn!(tool = %qualified, control, "tool result blocked");
        return error(
            id,
            POLICY_DENIED,
            &format!("tool result blocked by {control}"),
        );
    }

    if inbound.verdict == Verdict::Redact {
        federation::replace_result_text(&mut payload, &inbound.text);
    }

    payload["resultType"] = json!("complete");
    payload["_meta"] = json!({
        "io.modelcontextprotocol/serverInfo": { "name": "ai-control-layer" },
        "x-control-layer": {
            "trace_id": trace_id,
            "policy_version": policy.sha256,
            "tool_call": summarise(&outbound),
            "tool_result": summarise(&inbound),
        },
    });

    result(id, payload)
}

async fn record(
    state: &McpState,
    trace_id: Uuid,
    hook: Hook,
    evaluation: &engine::Evaluation,
    tool: &str,
    principal_id: Option<Uuid>,
    payload: &str,
) {
    let mut entry = audit::record_for(
        trace_id,
        hook,
        evaluation,
        None,
        principal_id,
        state.policy_version_id,
        payload,
    );
    entry.channel = "mcp";
    entry.tool = Some(tool);
    state.auditor.record(entry).await;
}

fn summarise(evaluation: &engine::Evaluation) -> Value {
    json!({
        "verdict": evaluation.verdict,
        "controls_fired": evaluation.detections.iter().map(|d| &d.control_id).collect::<Vec<_>>(),
        "deterministic_us": evaluation.deterministic_us,
    })
}

/// `Mcp-Method` and `Mcp-Name` mirror the body so intermediaries can route
/// without parsing it. A mismatch means the two readers would disagree about
/// what this request is, which is the whole attack.
fn header_mismatch(headers: &HeaderMap, method: &str, params: &Value) -> Option<String> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };

    if let Some(declared) = header("mcp-method")
        && declared != method
    {
        return Some(format!(
            "Mcp-Method header says {declared}, body says {method}"
        ));
    }

    if let Some(declared) = header("mcp-name")
        && method == "tools/call"
        && let Some(actual) = params.get("name").and_then(Value::as_str)
        && declared != actual
    {
        return Some(format!(
            "Mcp-Name header says {declared}, body says {actual}"
        ));
    }

    None
}

fn result(id: &Value, result: Value) -> Response {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

fn error(id: &Value, code: i64, message: &str) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    }))
    .into_response()
}

#[cfg(test)]
mod tests;

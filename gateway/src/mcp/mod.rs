//! The MCP enforcement point.
//!
//! The gateway is the only MCP server any agent talks to; real servers sit
//! behind it, next to the gateway's own `resources` and `control` tools. Two of the four
//! hooks live here:
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
pub mod guard;
mod listing;
pub mod native;
pub mod resources;

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::audit::{self, Principal};
use crate::background::{self, Job};
use crate::engine::{self, Evaluation, Verdict};
use crate::policy::{Action, Hook, Policy, Severity};
use crate::proxy::{bearer_principal, summarise, verdict_name};
use crate::risk;
use crate::state::AppState;

use federation::PROTOCOL_VERSION;

/// Reserved by the spec for transport-level header/body disagreement.
const HEADER_MISMATCH: i64 = -32020;
const METHOD_NOT_FOUND: i64 = -32601;
/// -32000..-32019 is the implementation-defined range. Policy outcomes are
/// ours, not the protocol's.
const POLICY_DENIED: i64 = -32000;
const PRINCIPAL_DENIED: i64 = -32001;
const UPSTREAM_ERROR: i64 = -32002;

const TOOL_NOT_GRANTED: &str = "mcp.tool-not-granted";

pub async fn endpoint(
    State(state): State<AppState>,
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
    let policy = state.policy.load_full();

    // The body is the source of truth. A request that says one thing in its
    // headers and another in its body is trying to be routed as one method and
    // executed as another, so it is refused rather than reconciled.
    if let Some(problem) = header_mismatch(&headers, &method, &params) {
        tracing::warn!(%problem, "refusing a header/body mismatch");
        return error(&id, HEADER_MISMATCH, &problem);
    }

    let principal = match bearer_principal(&state.auditor, &headers).await {
        Ok(principal) => principal,
        // Chat uses HTTP status for auth failure; JSON-RPC clients expect a
        // JSON-RPC error envelope even for the same gateway rule.
        Err(_) => {
            return error(
                &id,
                PRINCIPAL_DENIED,
                "missing, invalid or disabled API key",
            );
        }
    };

    match method.as_str() {
        "server/discover" => discover(&id),
        "tools/list" => listing::tools_list(&state, &policy, &principal, &id).await,
        "tools/call" => tools_call(&state, &policy, &principal, &id, &params).await,
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

/// A listing with nothing on it, for gating decisions that are not about text.
pub(crate) fn blank() -> Evaluation {
    Evaluation {
        verdict: Verdict::Allow,
        text: String::new(),
        detections: Vec::new(),
        suspicious: false,
        deterministic_us: 0,
        semantic_us: 0,
    }
}

/// Tool calls by this identity inside the runaway window: all of them, and
/// those identical to this one.
async fn runaway_counts(
    state: &AppState,
    policy: &Policy,
    principal: &Principal,
    tool: &str,
    payload_sha256: &str,
) -> (i64, i64) {
    let limits = &policy.runaway;
    if limits.max_tool_calls.is_none() && limits.max_identical_calls.is_none() {
        return (0, 0);
    }
    sqlx::query_as::<_, (i64, i64)>(
        "select count(*), count(*) filter (where tool = $3 and payload_sha256 = $4)
         from events
         where principal_id = $1 and hook = 'tool_call'
           and ts > now() - make_interval(secs => $2::int)",
    )
    .bind(principal.id)
    .bind(limits.window_secs)
    .bind(tool)
    .bind(payload_sha256)
    .fetch_one(state.db())
    .await
    .unwrap_or_else(|error| {
        tracing::error!(%error, "runaway count failed");
        (0, 0)
    })
}

#[expect(clippy::too_many_lines, reason = "one hook after another, in order")]
async fn tools_call(
    state: &AppState,
    policy: &Arc<Policy>,
    principal: &Principal,
    id: &Value,
    params: &Value,
) -> Response {
    let trace_id = Uuid::new_v4();
    let Some(qualified) = params.get("name").and_then(Value::as_str) else {
        return error(id, POLICY_DENIED, "tools/call requires a tool name");
    };

    if native::is_native(qualified) {
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
        return match native::call(state, policy, principal, qualified, &arguments).await {
            Ok(payload) => result(id, payload),
            Err(message) => error(id, POLICY_DENIED, &message),
        };
    }

    // --- hook 3: tool_call ------------------------------------------------
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
    let rendered = arguments.to_string();
    let mut outbound = engine::evaluate(policy, Hook::ToolCall, &rendered);
    state.telemetry.observe("deterministic", outbound.deterministic_us);

    // Checked here, not only at list time: a client can call a tool it was
    // never shown. A live human-approved grant counts as permission. Every
    // refusal below is audited with the call.
    let resource_tool = qualified == resources::DESCRIBE || qualified == resources::QUERY;
    let server = federation::split(qualified).and_then(|(server, _)| policy.mcp.server(server));
    let gate = |evaluation: &mut Evaluation, control: &str, reason: String| {
        evaluation.gate(control.to_owned(), Severity::High, Action::Block, reason);
    };
    if !principal.may_call_tool(qualified)
        && !state.approvals.has_grant(principal.id, qualified)
    {
        gate(&mut outbound, TOOL_NOT_GRANTED, format!("{} may not call {qualified}", principal.slug));
    } else if !resource_tool && server.is_none() {
        gate(&mut outbound, "mcp.unknown-server", format!("{qualified} is not served by an enabled server"));
    } else if let (Some(server), Some((_, tool))) = (server, federation::split(qualified))
        && !guard::callable(server, tool)
    {
        gate(&mut outbound, "mcp.tool-unapproved", format!("{qualified} is not on the approved list"));
    }
    let digest = audit::sha256_hex(rendered.as_bytes());
    let (calls, identical) = runaway_counts(state, policy, principal, qualified, &digest).await;
    let depth = params.pointer("/_meta/depth").and_then(Value::as_u64);
    if let Some(reason) = guard::runaway(&policy.runaway, calls, identical, depth) {
        gate(&mut outbound, "mcp.runaway", reason);
    }
    let _inflight = state.budgets.check(principal, None, &mut outbound).await;
    risk::apply(state.db(), &policy.risk, principal.id, &mut outbound).await;
    if outbound.verdict != Verdict::Block {
        engine::escalate(policy, Hook::ToolCall, &mut outbound, &state.detectors).await;
    }

    let mut outbound_record = audit::record_for(
        trace_id,
        Hook::ToolCall,
        &outbound,
        None,
        Some(principal.id),
        policy.version_id,
        &rendered,
    );
    outbound_record.channel = "mcp";
    outbound_record.tool = Some(qualified);
    state.auditor.record(outbound_record).await;
    state.telemetry.verdict("tool_call", verdict_name(outbound.verdict));

    if let Some(blocker) = outbound.blocked_by() {
        let code = if blocker.control_id == TOOL_NOT_GRANTED {
            PRINCIPAL_DENIED
        } else {
            POLICY_DENIED
        };
        return error(id, code, &format!("tool call blocked by {}", blocker.control_id));
    }
    background::analyse(state, &outbound, job(policy, Hook::ToolCall, &rendered, trace_id, principal, qualified));

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
    let started = Instant::now();
    let upstream = if resource_tool {
        resource_call(state, policy, principal, trace_id, qualified, &forwarded).await
    } else {
        let (server, tool) = server
            .zip(federation::split(qualified).map(|(_, tool)| tool))
            .expect("checked above");
        let reply = federation::call(
            &state.http,
            server,
            "tools/call",
            Some(tool),
            json!({ "name": tool, "arguments": forwarded }),
        )
        .await;
        state.telemetry.dependency(&format!("mcp:{}", server.name), reply.is_ok());
        reply
    };
    let upstream_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    state.telemetry.observe("mcp_upstream", upstream_us);

    let mut payload = match upstream {
        Ok(value) => value,
        Err(problem) => {
            tracing::error!(%problem, "tool call failed");
            return error(id, UPSTREAM_ERROR, &problem);
        }
    };

    // --- hook 4: tool_result ---------------------------------------------
    // Nothing reaches the model's context unevaluated.
    let text = federation::result_text(&payload);
    let mut inbound = engine::evaluate(policy, Hook::ToolResult, &text);
    engine::escalate(policy, Hook::ToolResult, &mut inbound, &state.detectors).await;

    let mut inbound_record = audit::record_for(
        trace_id,
        Hook::ToolResult,
        &inbound,
        None,
        Some(principal.id),
        policy.version_id,
        &text,
    );
    inbound_record.channel = "mcp";
    inbound_record.tool = Some(qualified);
    inbound_record.latency = json!({
        "deterministic_us": inbound.deterministic_us,
        "semantic_us": inbound.semantic_us,
        "upstream_us": upstream_us,
    });
    state.auditor.record(inbound_record).await;
    state.telemetry.verdict("tool_result", verdict_name(inbound.verdict));

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
    background::analyse(state, &inbound, job(policy, Hook::ToolResult, &text, trace_id, principal, qualified));

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

fn job(
    policy: &Arc<Policy>,
    hook: Hook,
    text: &str,
    trace_id: Uuid,
    principal: &Principal,
    tool: &str,
) -> Job {
    Job {
        policy: Arc::clone(policy),
        hook,
        channel: "mcp",
        text: text.to_owned(),
        trace_id,
        principal_id: principal.id,
        model: None,
        tool: Some(tool.to_owned()),
    }
}

/// The gateway's own `resources` tools. Structure goes to the model; rows go
/// to the identity that asked, and the model gets an acknowledgement.
async fn resource_call(
    state: &AppState,
    policy: &Policy,
    principal: &Principal,
    trace_id: Uuid,
    tool: &str,
    arguments: &Value,
) -> Result<Value, String> {
    let pool = state
        .resources
        .as_ref()
        .ok_or("resource tools are not configured on this gateway")?;
    let tables = policy.resources.tables_for(&principal.slug);

    if tool == resources::DESCRIBE {
        return resources::describe(pool, tables)
            .await
            .map(resources::as_tool_result);
    }

    let sql = arguments
        .get("sql")
        .and_then(Value::as_str)
        .ok_or("resources__query requires a `sql` argument")?;
    let mut result = resources::run(pool, policy, tables, sql).await?;

    // The rows leave through the output guardrails and are audited as data
    // delivered to the user.
    let delivered = resources::guard_rows(policy, &mut result.rows);
    let mut record = audit::record_for(
        trace_id,
        Hook::ResponseOut,
        &delivered,
        None,
        Some(principal.id),
        policy.version_id,
        &Value::Array(result.rows.clone()).to_string(),
    );
    record.channel = "mcp";
    record.tool = Some(resources::QUERY);
    state.auditor.record(record).await;

    let ack = resources::deliver(state.db(), principal, trace_id, &result).await?;
    Ok(resources::as_tool_result(ack.to_string()))
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

pub(crate) fn result(id: &Value, result: Value) -> Response {
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

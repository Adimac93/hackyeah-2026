//! Tools the gateway serves itself, under the reserved `control__` prefix.
//!
//! They let an agent see the rules it runs under and ask for more access
//! instead of hitting a wall. Always listed and always callable — an agent
//! that cannot see its own policy cannot ask for an exception to it.
//!
//! What they never expose: patterns, thresholds and mock keywords. Telling a
//! model the exact regex it must avoid is handing it the evasion.

use serde_json::{Value, json};
use uuid::Uuid;

use crate::approvals::{self, Access, Outcome, Target};
use crate::audit::{self, EventRecord, Principal};
use crate::engine::{self, Verdict};
use crate::policy::{Hook, Policy};
use crate::state::AppState;

use super::listing;

pub const LIST_CONTROLS: &str = "control__list_controls";
pub const MY_ACCESS: &str = "control__my_access";
pub const REQUEST_ACCESS: &str = "control__request_access";

pub fn descriptors() -> Vec<Value> {
    vec![
        json!({
            "name": LIST_CONTROLS,
            "description": "List the security controls this gateway enforces: id, kind, \
                            hooks, severity and the action taken when one fires.",
            "inputSchema": { "type": "object", "properties": {} },
        }),
        json!({
            "name": MY_ACCESS,
            "description": "Show what you may use: allowed tools and models, budgets and \
                            usage, active temporary grants, and the tools and tables you \
                            could request.",
            "inputSchema": { "type": "object", "properties": {} },
        }),
        json!({
            "name": REQUEST_ACCESS,
            "description": "Ask the security team for temporary access to a tool you are \
                            not allowed to call, or to a table resources__describe says needs \
                            approval. Pass exactly one of `tool` and `table`. Blocks for up to \
                            two minutes while a human decides. Returns granted (with expiry), \
                            denied, or expired.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool": { "type": "string", "description": "Qualified tool name, e.g. docs__read" },
                    "table": { "type": "string", "description": "Table name, e.g. customers" },
                    "reason": { "type": "string", "description": "Why you need it. Shown to the approver." },
                    "ttl_minutes": { "type": "integer", "minimum": 1, "maximum": approvals::MAX_TTL_MINUTES },
                },
                "required": ["reason"],
            },
        }),
    ]
}

pub fn is_native(name: &str) -> bool {
    name.starts_with(approvals::NATIVE_PREFIX)
}

/// The public face of the catalog.
pub fn public_controls(policy: &Policy) -> Value {
    fn sorted_hooks(hooks: &std::collections::HashSet<Hook>) -> Vec<Hook> {
        let mut list: Vec<Hook> = hooks.iter().copied().collect();
        list.sort_by_key(|h| format!("{h:?}"));
        list
    }

    let mut controls = Vec::new();
    for control in policy
        .deterministic
        .iter()
        .chain(&policy.signature_controls)
    {
        controls.push(json!({
            "id": control.id,
            "kind": "deterministic",
            "hooks": sorted_hooks(&control.hooks),
            "severity": control.severity,
            "action": control.action,
        }));
    }
    for control in &policy.semantic {
        controls.push(json!({
            "id": control.id,
            "kind": "semantic",
            "hooks": sorted_hooks(&control.hooks),
            "severity": control.severity,
            "action": control.action,
            "describes": control.describes,
        }));
    }
    json!({ "policy_version": policy.sha256, "controls": controls })
}

/// Returns the MCP `tools/call` result (or an error string for the caller to
/// wrap in a JSON-RPC error).
pub async fn call(
    state: &AppState,
    policy: &Policy,
    principal: &Principal,
    name: &str,
    arguments: &Value,
) -> Result<Value, String> {
    match name {
        LIST_CONTROLS => Ok(text(&public_controls(policy))),
        MY_ACCESS => Ok(text(&my_access(state, policy, principal).await)),
        REQUEST_ACCESS => request_access(state, policy, principal, arguments)
            .await
            .map(|outcome| text(&json!(outcome))),
        other => Err(format!("no gateway tool called {other}")),
    }
}

async fn my_access(state: &AppState, policy: &Policy, principal: &Principal) -> Value {
    let budgets: Vec<Value> = state
        .budgets
        .standing(principal)
        .await
        .into_iter()
        .map(|(row, used)| json!({ "limit": row, "used": used }))
        .collect();

    let grants = state.approvals.active_grants(principal.id, &principal.user);
    let (tools, _) = listing::catalog(state, policy).await;
    let requestable: Vec<String> = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .filter(|name| {
            approvals::validate_target(
                policy,
                principal,
                grants.iter().any(|g| g.access.tool() == Some(*name)),
                name,
            ) == Target::Requestable
        })
        .map(str::to_owned)
        .collect();
    let temporary: Vec<Value> = grants
        .iter()
        .filter_map(|g| {
            g.access
                .table()
                .map(|table| json!({ "table": table, "expires_at_ms": g.expires_at_ms }))
        })
        .collect();
    let requestable_tables: Vec<&String> = policy
        .resources
        .requestable_for(&principal.slug)
        .iter()
        .filter(|table| {
            !grants
                .iter()
                .any(|g| g.access.table() == Some(table.as_str()))
        })
        .collect();

    json!({
        "principal": principal.slug,
        "allowed_tools": principal.allowed_tools,
        "allowed_models": principal.allowed_models,
        "budgets": budgets,
        "grants": grants,
        "requestable_tools": requestable,
        "tables": {
            "granted": policy.resources.tables_for(&principal.slug),
            "requestable": requestable_tables,
            "temporary": temporary,
        },
    })
}

async fn request_access(
    state: &AppState,
    policy: &Policy,
    principal: &Principal,
    arguments: &Value,
) -> Result<Outcome, String> {
    let access = requested(arguments)?;
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if reason.is_empty() {
        return Err("request_access requires a reason".to_owned());
    }
    let ttl = approvals::clamp_ttl(
        arguments
            .get("ttl_minutes")
            .and_then(Value::as_u64)
            .map(|t| u32::try_from(t).unwrap_or(u32::MAX)),
    );

    let has_grant = state
        .approvals
        .has_grant(principal.id, &principal.user, &access);
    let target = match &access {
        Access::Tool(tool) => approvals::validate_target(policy, principal, has_grant, tool),
        Access::Table(table) => approvals::validate_table(policy, principal, has_grant, table),
    };
    match target {
        Target::Requestable => {}
        Target::AlreadyPermitted => return Ok(Outcome::AlreadyPermitted),
        Target::Refused(message) => return Ok(Outcome::Refused { message }),
    }

    // The reason is model-written text that a human will read: it gets the
    // same tool_call controls as any other argument, so an injected reason
    // cannot phish the approver.
    let trace_id = Uuid::new_v4();
    let policy_version_id = policy.version_id;
    let mut evaluation = engine::evaluate(policy, Hook::ToolCall, reason);
    engine::escalate(policy, Hook::ToolCall, &mut evaluation, &state.detectors).await;

    let mut record = audit::record_for(
        trace_id,
        Hook::ToolCall,
        &evaluation,
        None,
        principal,
        policy_version_id,
        reason,
    );
    record.channel = "mcp";
    record.tool = Some(REQUEST_ACCESS);
    state.auditor.record(record).await;

    if evaluation.verdict == Verdict::Block {
        let control = evaluation
            .blocked_by()
            .map_or("policy", |d| d.control_id.as_str());
        return Ok(Outcome::Refused {
            message: format!("the reason was blocked by {control}"),
        });
    }

    let outcome = state
        .approvals
        .request(principal, &access, &evaluation.text, ttl)
        .await;

    // The human's answer is a decision too; it goes in the chain.
    let rendered = json!(outcome).to_string();
    state
        .auditor
        .record(EventRecord {
            trace_id,
            hook: Hook::ToolCall,
            channel: "mcp",
            principal_id: Some(principal.id),
            end_user: Some(&principal.user),
            model: None,
            tool: Some(REQUEST_ACCESS),
            verdict: if matches!(outcome, Outcome::Granted { .. }) {
                Verdict::Allow
            } else {
                Verdict::Block
            },
            policy_version_id,
            latency: json!({}),
            payload_sha256: audit::sha256_hex(rendered.as_bytes()),
            detections: &[],
        })
        .await;

    Ok(outcome)
}

/// The one thing a request is for: a `tool` or a `table`, never both.
pub(crate) fn requested(arguments: &Value) -> Result<Access, String> {
    let field = |name: &str| {
        arguments
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    match (field("tool"), field("table")) {
        (Some(tool), None) => Ok(Access::Tool(tool)),
        (None, Some(table)) => Ok(Access::Table(table)),
        _ => Err("request_access takes exactly one of tool or table".to_owned()),
    }
}

fn text(value: &Value) -> Value {
    json!({
        "resultType": "complete",
        "content": [{ "type": "text", "text": value.to_string() }],
        "structuredContent": value,
        "isError": false,
    })
}

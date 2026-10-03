//! `tools/list`: what the caller is shown. Only tools whose definitions pass
//! the pin and poisoning checks, and only those the caller is granted.

use axum::response::Response;
use serde_json::{Value, json};
use uuid::Uuid;

use super::guard::{self, Pin};
use super::{blank, federation, resources, result};
use crate::audit::{self, Principal};
use crate::engine;
use crate::policy::{Action, Hook, Policy, Severity};
use crate::state::AppState;

pub(super) async fn tools_list(
    state: &AppState,
    policy: &Policy,
    principal: &Principal,
    id: &Value,
) -> Response {
    let mut tools = Vec::new();
    // Tools hidden for what their definitions say, recorded like any control.
    let mut hidden = blank();

    if state.resources.is_some() {
        tools.extend(resources::tools());
    }
    for server in policy.mcp.enabled_servers() {
        let listing = federation::call(&state.http, server, "tools/list", None, json!({})).await;
        state.telemetry.dependency(&format!("mcp:{}", server.name), listing.is_ok());
        let listing = match listing {
            Ok(listing) => listing,
            Err(problem) => {
                tracing::warn!(%problem, "an upstream could not be listed");
                continue;
            }
        };
        let upstream = listing
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for mut tool in upstream {
            let Some(name) = tool.get("name").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            let qualified = federation::qualify(&server.name, &name);
            if let Some((control, reason)) = definition_problem(policy, server, &tool) {
                tracing::warn!(tool = %qualified, %control, %reason, "tool hidden");
                hidden.gate(control, Severity::High, Action::Redact, format!("{qualified}: {reason}"));
                continue;
            }
            tool["name"] = Value::String(qualified);
            tools.push(tool);
        }
    }

    if !hidden.detections.is_empty() {
        let listing = json!(tools).to_string();
        let mut record = audit::record_for(
            Uuid::new_v4(),
            Hook::ToolResult,
            &hidden,
            None,
            Some(principal.id),
            policy.version_id,
            &listing,
        );
        record.channel = "mcp";
        state.auditor.record(record).await;
    }

    // A tool the caller may not invoke is a tool they should not be shown.
    // Grants are deny-by-default.
    tools.retain(|tool| {
        tool.get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| principal.may_call_tool(name))
    });

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

/// Why a listed tool must not reach the model: not the definition the security
/// team approved, or a description that carries an attack (tool poisoning).
fn definition_problem(
    policy: &Policy,
    server: &crate::policy::McpServer,
    tool: &Value,
) -> Option<(String, String)> {
    match guard::pin_status(server, tool) {
        Pin::Changed => {
            return Some((
                "mcp.tool-changed".into(),
                "definition differs from the approved version".into(),
            ));
        }
        Pin::Unknown => {
            return Some((
                "mcp.tool-unapproved".into(),
                "not on the server's approved list".into(),
            ));
        }
        Pin::Approved | Pin::Unpinned => {}
    }
    // The description and schema are read by the model like a tool result.
    let definition = tool.to_string();
    let evaluation = engine::evaluate(policy, Hook::ToolResult, &definition);
    let poisoned = evaluation
        .detections
        .iter()
        .find(|d| matches!(d.action, Action::Block | Action::Flag))?;
    Some((
        "mcp.tool-poisoned".into(),
        format!("definition matched {}", poisoned.control_id),
    ))
}

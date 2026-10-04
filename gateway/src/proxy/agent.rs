//! The chat endpoint's side of the LLM ↔ MCP interaction (docs/BACKEND.md).
//!
//! A request with `"mcp": true` offers the model the caller's MCP tools. Every
//! tool call the model makes runs through the same `tools/call` gate an MCP
//! client goes through, and what comes back is fed to the model until it
//! answers. For the protected SQL database that is: the columns of the tables
//! it names (`resources__describe`), one SELECT (`resources__query`), then an
//! answer. The rows go to the user; the model only ever sees structure and an
//! acknowledgement.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};
use uuid::Uuid;

use super::refusal;
use crate::audit::Principal;
use crate::engine;
use crate::mcp::{self, federation};
use crate::mock;
use crate::policy::{Hook, Policy};
use crate::state::AppState;
use crate::upstream::Upstream;

/// Model turns one request may take before the loop is cut off.
pub const MAX_TURNS: usize = 8;

pub struct Reply {
    pub status: StatusCode,
    pub completion: Value,
    /// What each tool call did, for the caller. `result_id` points at rows
    /// waiting for them at `GET /v1/results/{id}`.
    pub tool_calls: Vec<Value>,
}

/// A tool call the model asked for, in OpenAI's shape.
#[derive(Debug, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// Run the conversation to an answer: one upstream call, or, with `"mcp": true`,
/// as many as the model needs to finish its tool calls.
pub async fn complete(
    state: &AppState,
    policy: &Arc<Policy>,
    principal: &Principal,
    trace_id: Uuid,
    mut body: Value,
) -> Result<Reply, Response> {
    let with_tools = body.as_object_mut().and_then(|b| b.remove("mcp")) == Some(Value::Bool(true));
    if with_tools {
        let tools = mcp::visible_tools(state, policy, principal).await;
        body["tools"] = Value::Array(openai_tools(&tools));
    }

    let mut tool_calls = Vec::new();
    let (mut prompt_tokens, mut completion_tokens) = (0, 0);
    for _ in 0..MAX_TURNS {
        let (status, mut completion) = upstream(state, trace_id, &body).await?;
        if !status.is_success() {
            return Ok(Reply {
                status,
                completion,
                tool_calls,
            });
        }
        let calls = if with_tools {
            requested_calls(&completion)
        } else {
            Vec::new()
        };
        if calls.is_empty() && tool_calls.is_empty() {
            return Ok(Reply {
                status,
                completion,
                tool_calls,
            });
        }
        let (prompt, answer) = super::usage(&completion);
        prompt_tokens += prompt;
        completion_tokens += answer;
        if calls.is_empty() {
            completion["usage"] = json!({
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            });
            return Ok(Reply {
                status,
                completion,
                tool_calls,
            });
        }

        let turn = completion
            .pointer("/choices/0/message")
            .cloned()
            .unwrap_or_default();
        let (results, reported) = run_calls(state, policy, principal, &calls).await;
        tool_calls.extend(reported);
        let mut replies = vec![turn];
        replies.extend(results);
        if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
            messages.extend(replies);
        }
    }

    Err(refusal(
        trace_id,
        StatusCode::BAD_GATEWAY,
        json!({
            "type": "tool_loop_exceeded",
            "message": format!("the model did not answer within {MAX_TURNS} turns"),
        }),
    ))
}

/// Run the model's tool calls through the same gate an MCP client's
/// `tools/call` goes through. Returns the `tool` messages to feed back to the
/// model, and what each call did, for the caller. Shared by the buffered loop
/// above and the streamed one (`stream.rs`).
pub async fn run_calls(
    state: &AppState,
    policy: &Arc<Policy>,
    principal: &Principal,
    calls: &[ToolCall],
) -> (Vec<Value>, Vec<Value>) {
    let mut replies = Vec::with_capacity(calls.len());
    let mut reported = Vec::with_capacity(calls.len());
    for call in calls {
        let params = json!({ "name": call.name, "arguments": call.arguments });
        let outcome = mcp::call_tool(state, policy, principal, &params).await;
        let content = match &outcome {
            Ok(payload) => federation::result_text(payload),
            Err(refused) => format!("refused: {}", refused.message),
        };
        reported.push(json!({
            "tool": call.name,
            "arguments": reported_arguments(policy, &call.arguments),
            "status": if outcome.is_ok() { "ok" } else { "refused" },
            "trace_id": outcome.as_ref().ok().and_then(|p| p.pointer("/_meta/x-control-layer/trace_id")),
            "result_id": outcome.as_ref().ok().and_then(result_id),
            "content": content,
        }));
        replies.push(json!({ "role": "tool", "tool_call_id": call.id, "content": content }));
    }
    (replies, reported)
}

/// A tool call's arguments. OpenAI sends them as a JSON string, Ollama at
/// times as an object. Unparseable text is passed on as-is: the tool_call
/// controls still scan it and the tool refuses it.
pub fn parse_arguments(arguments: Option<&Value>) -> Value {
    match arguments {
        Some(Value::String(text)) => {
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.clone()))
        }
        Some(value) => value.clone(),
        None => json!({}),
    }
}

/// MCP tool definitions as OpenAI function tools.
pub fn openai_tools(tools: &[Value]) -> Vec<Value> {
    tools
        .iter()
        .filter_map(|tool| {
            Some(json!({
                "type": "function",
                "function": {
                    "name": tool.get("name")?.as_str()?,
                    "description": tool.get("description").and_then(Value::as_str).unwrap_or_default(),
                    "parameters": tool.get("inputSchema").cloned()
                        .unwrap_or_else(|| json!({ "type": "object", "properties": {} })),
                },
            }))
        })
        .collect()
}

/// Where a `resources__query` call left its rows: the ack's structured copy,
/// which the tool_result redactions do not touch.
pub fn result_id(payload: &Value) -> Option<Value> {
    payload
        .pointer("/structuredContent/result_id")
        .filter(|id| id.is_string())
        .cloned()
}

/// A call's arguments as the caller is shown them (the SQL of a query, say):
/// model-written, so through the `tool_call` redactions first.
pub fn reported_arguments(policy: &Policy, arguments: &Value) -> Value {
    let redacted = engine::redact(policy, Hook::ToolCall, &arguments.to_string());
    serde_json::from_str(&redacted).unwrap_or(Value::String(redacted))
}

/// The tool calls in a completion's first choice.
pub fn requested_calls(completion: &Value) -> Vec<ToolCall> {
    let Some(calls) = completion
        .pointer("/choices/0/message/tool_calls")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    calls
        .iter()
        .enumerate()
        .filter_map(|(index, call)| {
            let function = call.get("function")?;
            let arguments = parse_arguments(function.get("arguments"));
            Some(ToolCall {
                id: call
                    .get("id")
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("call_{index}"), str::to_owned),
                name: function.get("name")?.as_str()?.to_owned(),
                arguments,
            })
        })
        .collect()
}

async fn upstream(
    state: &AppState,
    trace_id: Uuid,
    body: &Value,
) -> Result<(StatusCode, Value), Response> {
    let model = body.get("model").and_then(Value::as_str).unwrap_or_default();
    let target = state.upstreams.resolve(model).await;
    if target.mock {
        return Ok((StatusCode::OK, mock::completion(body)));
    }
    tracing::info!(%trace_id, upstream = %target.name, "forwarding");
    let reply = forward(state, trace_id, &target, body).await;
    state.telemetry.dependency("upstream", reply.is_ok());
    reply
}

async fn forward(
    state: &AppState,
    trace_id: Uuid,
    target: &Upstream,
    body: &Value,
) -> Result<(StatusCode, Value), Response> {
    let mut request = state.http.post(&target.endpoint).json(body);
    if let Some(key) = &target.key {
        request = request.bearer_auth(key);
    }
    let upstream = request
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, "upstream request failed");
            refusal(
                trace_id,
                StatusCode::BAD_GATEWAY,
                json!({ "type": "upstream_unavailable", "message": "the upstream model is unreachable" }),
            )
        })?;

    let status = upstream.status();
    let completion = upstream.json::<Value>().await.map_err(|_| {
        refusal(
            trace_id,
            StatusCode::BAD_GATEWAY,
            json!({ "type": "upstream_unreadable", "message": "the upstream response was not JSON" }),
        )
    })?;
    Ok((status, completion))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_result_id_comes_from_the_structured_ack() {
        let payload = json!({
            "content": [{ "type": "text", "text": "{\"result_id\":\"7e9b[REDACTED:pii.phone]-a58c\"}" }],
            "structuredContent": { "result_id": "7e9b1234-5678-4a58c-0dc98a1f86bc", "row_count": 5 },
        });
        assert_eq!(
            result_id(&payload),
            Some(json!("7e9b1234-5678-4a58c-0dc98a1f86bc"))
        );
        assert_eq!(result_id(&json!({ "content": [] })), None);
    }

    #[test]
    fn reported_arguments_keep_their_shape_and_lose_their_pii() {
        let policy = Policy::builtin().unwrap();
        let sql = json!({ "sql": "select * from invoices where status = 'overdue'" });
        assert_eq!(reported_arguments(&policy, &sql), sql);
        let leaky =
            json!({ "sql": "select * from customers where email = 'anna.nowak@example.com'" });
        let shown = reported_arguments(&policy, &leaky);
        let shown = shown["sql"].as_str().unwrap();
        assert!(!shown.contains("anna.nowak@example.com"), "{shown}");
        assert!(shown.contains("[REDACTED:pii.email]"), "{shown}");
    }

    #[test]
    fn mcp_tools_become_function_tools() {
        let tools = openai_tools(&[
            json!({
                "name": "resources__query",
                "description": "Run one SELECT.",
                "inputSchema": { "type": "object", "properties": { "sql": { "type": "string" } } },
            }),
            json!({ "name": "control__my_access" }),
            json!({ "description": "nameless, dropped" }),
        ]);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["type"], "function");
        assert_eq!(tools[0]["function"]["name"], "resources__query");
        assert_eq!(
            tools[0]["function"]["parameters"]["properties"]["sql"]["type"],
            "string"
        );
        assert_eq!(tools[1]["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn tool_calls_are_read_from_string_or_object_arguments() {
        let completion = json!({ "choices": [{ "message": { "tool_calls": [
            { "id": "a", "function": { "name": "resources__query", "arguments": "{\"sql\":\"select 1\"}" } },
            { "function": { "name": "resources__describe", "arguments": { "tables": ["customers"] } } },
            { "id": "c", "function": { "name": "x", "arguments": "not json" } },
            { "id": "d" },
        ]}}]});
        assert_eq!(
            requested_calls(&completion),
            [
                ToolCall {
                    id: "a".into(),
                    name: "resources__query".into(),
                    arguments: json!({ "sql": "select 1" })
                },
                ToolCall {
                    id: "call_1".into(),
                    name: "resources__describe".into(),
                    arguments: json!({ "tables": ["customers"] }),
                },
                ToolCall {
                    id: "c".into(),
                    name: "x".into(),
                    arguments: json!("not json")
                },
            ]
        );
    }

    #[test]
    fn a_plain_answer_has_no_tool_calls() {
        let completion =
            json!({ "choices": [{ "message": { "role": "assistant", "content": "hi" } }] });
        assert!(requested_calls(&completion).is_empty());
    }
}

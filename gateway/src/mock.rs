//! Stand-ins for the models in `dev` (docs/BACKEND.md): a chat upstream and a
//! semantic judge that need no Ollama. `prod` refuses to start with either.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::mcp::native::REQUEST_ACCESS;
use crate::mcp::resources::{DESCRIBE, QUERY};

/// The value of `UPSTREAM_URL` or `OLLAMA_URL` that selects a mock.
pub const MOCK: &str = "mock";

/// An OpenAI-shaped completion that echoes the last message. The request has
/// already passed `prompt_in`, so the echo shows exactly what a model would
/// have been sent — redactions included.
///
/// Offered the resource tools and asked a SELECT, it plays the LLM ↔ MCP flow
/// instead: the columns of the tables the query names, then the query, then
/// an answer that repeats what the last tool said. A table that needs
/// approval is requested once with `control__request_access`; on `granted`
/// the walk starts over.
pub fn completion(body: &Value) -> Value {
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let offered = |name: &str| {
        body.get("tools")
            .and_then(Value::as_array)
            .is_some_and(|tools| {
                tools
                    .iter()
                    .any(|t| t.pointer("/function/name").and_then(Value::as_str) == Some(name))
            })
    };

    let (message, finish_reason) = match script(messages, offered) {
        Step::Call(name, arguments) => (
            json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": format!("call_{}", messages.len()),
                    "type": "function",
                    "function": { "name": name, "arguments": arguments.to_string() },
                }],
            }),
            "tool_calls",
        ),
        Step::Say(content) => (json!({ "role": "assistant", "content": content }), "stop"),
    };
    let prompt_tokens: usize = messages
        .iter()
        .map(|m| text(m).split_whitespace().count())
        .sum();
    let completion_tokens = message.to_string().split_whitespace().count();

    json!({
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "model": body.get("model").and_then(Value::as_str).unwrap_or(MOCK),
        "choices": [{ "index": 0, "message": message, "finish_reason": finish_reason }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    })
}

#[derive(Debug, PartialEq)]
enum Step {
    Call(&'static str, Value),
    Say(String),
}

fn text(message: &Value) -> String {
    message
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn script(messages: &[Value], offered: impl Fn(&str) -> bool) -> Step {
    let role = |message: &Value| {
        message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let question = messages
        .iter()
        .rfind(|m| role(m) == "user")
        .map(text)
        .unwrap_or_default();
    let sql = SELECT.find(&question).map(|m| m.as_str().trim().to_owned());
    let resources = offered(DESCRIBE) && offered(QUERY);

    let Some(last) = messages.last() else {
        return Step::Say("[mock] You said: ".to_owned());
    };
    if role(last) != "tool" {
        return match sql {
            Some(sql) if resources => Step::Call(DESCRIBE, json!({ "tables": tables_in(&sql) })),
            _ => Step::Say(format!("[mock] You said: {}", text(last))),
        };
    }
    let called = messages
        .iter()
        .rfind(|m| m.get("tool_calls").is_some())
        .and_then(|m| m.pointer("/tool_calls/0/function/name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let result = text(last);
    let asked_before = messages.iter().any(|m| {
        m.get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|calls| {
                calls.iter().any(|c| {
                    c.pointer("/function/name").and_then(Value::as_str) == Some(REQUEST_ACCESS)
                })
            })
    });
    match sql {
        Some(sql) if called == DESCRIBE && resources && !result.starts_with("refused") => {
            Step::Call(QUERY, json!({ "sql": sql }))
        }
        // The gateway said how to get the table: ask a human, once.
        Some(_)
            if (called == DESCRIBE || called == QUERY)
                && offered(REQUEST_ACCESS)
                && !asked_before =>
        {
            match NEEDS_APPROVAL.captures(&result) {
                Some(found) => Step::Call(
                    REQUEST_ACCESS,
                    json!({
                        "table": &found[1],
                        "reason": format!(
                            "The user asked: {}",
                            question.chars().take(120).collect::<String>()
                        ),
                    }),
                ),
                None => Step::Say(format!("[mock] {called} said: {result}")),
            }
        }
        Some(sql)
            if called == REQUEST_ACCESS
                && resources
                && result.contains(r#""status":"granted""#) =>
        {
            Step::Call(DESCRIBE, json!({ "tables": tables_in(&sql) }))
        }
        _ => Step::Say(format!("[mock] {called} said: {result}")),
    }
}

static NEEDS_APPROVAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"needs approval: call control__request_access with \{"table": "([A-Za-z0-9_]+)""#)
        .expect("static regex")
});

static SELECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)\bselect\b.+?\bfrom\b.+").expect("static regex"));
static TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_.]*)").expect("static regex")
});

/// The tables a query reads, without their schema.
fn tables_in(sql: &str) -> Vec<String> {
    let mut tables = Vec::new();
    for found in TABLE.captures_iter(sql) {
        let table = found[1].rsplit('.').next().unwrap_or_default().to_owned();
        if !tables.contains(&table) {
            tables.push(table);
        }
    }
    tables
}

/// 1.0 when the text contains any of the control's `mock_keywords`, ignoring
/// case, 0.0 otherwise. Deterministic, so a demo behaves the same on every
/// machine.
pub fn score(keywords: &[String], text: &str) -> f32 {
    let text = text.to_lowercase();
    if keywords.iter().any(|k| text.contains(&k.to_lowercase())) {
        1.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_judge_matches_keywords_ignoring_case() {
        let keywords = vec!["Ignore previous instructions".to_owned()];
        assert!(
            (score(&keywords, "please IGNORE previous instructions") - 1.0).abs() < f32::EPSILON
        );
        assert!(score(&keywords, "what is the weather").abs() < f32::EPSILON);
        assert!(score(&[], "anything").abs() < f32::EPSILON);
    }

    #[test]
    fn the_upstream_echoes_the_last_message_and_reports_usage() {
        let body = json!({
            "model": "llama3.1:8b",
            "messages": [
                { "role": "system", "content": "be brief" },
                { "role": "user", "content": "mail [REDACTED:pii.email] now" },
            ],
        });
        let reply = completion(&body);
        assert_eq!(
            reply["choices"][0]["message"]["content"],
            "[mock] You said: mail [REDACTED:pii.email] now"
        );
        assert_eq!(reply["usage"]["prompt_tokens"], 5);
        assert_eq!(reply["model"], "llama3.1:8b");
    }

    fn tools() -> Value {
        json!([
            { "type": "function", "function": { "name": DESCRIBE } },
            { "type": "function", "function": { "name": QUERY } },
        ])
    }

    fn next_call(body: &Value) -> (String, Value) {
        let call = &completion(body)["choices"][0]["message"]["tool_calls"][0]["function"];
        let arguments = serde_json::from_str(call["arguments"].as_str().unwrap()).unwrap();
        (call["name"].as_str().unwrap().to_owned(), arguments)
    }

    #[test]
    fn a_select_walks_describe_then_query_then_answers() {
        let sql =
            "select c.full_name from resources.customers c join invoices i on i.customer_id = c.id";
        let mut messages = vec![json!({ "role": "user", "content": format!("Run: {sql}") })];
        let mut body = json!({ "messages": messages, "tools": tools() });

        let (name, arguments) = next_call(&body);
        assert_eq!(name, DESCRIBE);
        assert_eq!(arguments, json!({ "tables": ["customers", "invoices"] }));

        messages.push(completion(&body)["choices"][0]["message"].clone());
        messages.push(
            json!({ "role": "tool", "tool_call_id": "call_1", "content": "customers(id uuid)" }),
        );
        body["messages"] = json!(messages);
        let (name, arguments) = next_call(&body);
        assert_eq!(name, QUERY);
        assert_eq!(arguments, json!({ "sql": sql }));

        messages.push(completion(&body)["choices"][0]["message"].clone());
        messages.push(
            json!({ "role": "tool", "tool_call_id": "call_3", "content": "{\"row_count\":2}" }),
        );
        body["messages"] = json!(messages);
        let reply = completion(&body);
        assert_eq!(reply["choices"][0]["finish_reason"], "stop");
        assert_eq!(
            reply["choices"][0]["message"]["content"],
            format!("[mock] {QUERY} said: {{\"row_count\":2}}")
        );
    }

    #[test]
    fn a_refused_describe_is_not_followed_by_a_query() {
        let body = json!({ "tools": tools(), "messages": [
            { "role": "user", "content": "select * from payroll" },
            { "role": "assistant", "content": null, "tool_calls": [{ "function": { "name": DESCRIBE } }] },
            { "role": "tool", "content": "refused: table payroll is not granted to this identity" },
        ]});
        let reply = completion(&body);
        assert_eq!(
            reply["choices"][0]["message"]["content"],
            format!(
                "[mock] {DESCRIBE} said: refused: table payroll is not granted to this identity"
            )
        );
    }

    fn with_requests() -> Value {
        json!([
            { "type": "function", "function": { "name": DESCRIBE } },
            { "type": "function", "function": { "name": QUERY } },
            { "type": "function", "function": { "name": REQUEST_ACCESS } },
        ])
    }

    fn turn(name: &str, result: &str) -> [Value; 2] {
        [
            json!({ "role": "assistant", "content": null,
                    "tool_calls": [{ "function": { "name": name } }] }),
            json!({ "role": "tool", "content": result }),
        ]
    }

    const NEEDS: &str = r#"refused: table customers needs approval: call control__request_access with {"table": "customers", "reason": "<why the user needs it>"}, then retry"#;

    #[test]
    fn a_table_that_needs_approval_is_requested_then_described_again() {
        let question = json!({ "role": "user", "content": "select email from customers" });
        let mut messages = vec![question];
        messages.extend(turn(DESCRIBE, NEEDS));
        let mut body = json!({ "tools": with_requests(), "messages": messages });
        let (name, arguments) = next_call(&body);
        assert_eq!(name, REQUEST_ACCESS);
        assert_eq!(arguments["table"], "customers");
        assert!(
            arguments["reason"]
                .as_str()
                .unwrap()
                .contains("select email from customers")
        );

        messages.extend(turn(
            REQUEST_ACCESS,
            r#"{"status":"granted","expires_at_ms":1}"#,
        ));
        body["messages"] = json!(messages);
        let (name, arguments) = next_call(&body);
        assert_eq!(name, DESCRIBE);
        assert_eq!(arguments, json!({ "tables": ["customers"] }));

        // A second refusal is reported, not requested again.
        messages.extend(turn(DESCRIBE, NEEDS));
        body["messages"] = json!(messages);
        assert_eq!(completion(&body)["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn a_denied_request_is_the_answer() {
        let mut messages =
            vec![json!({ "role": "user", "content": "select email from customers" })];
        messages.extend(turn(DESCRIBE, NEEDS));
        messages.extend(turn(REQUEST_ACCESS, r#"{"status":"denied","note":null}"#));
        let body = json!({ "tools": with_requests(), "messages": messages });
        let reply = completion(&body);
        assert_eq!(reply["choices"][0]["finish_reason"], "stop");
        assert!(
            reply["choices"][0]["message"]["content"]
                .as_str()
                .unwrap()
                .contains("denied")
        );
    }

    #[test]
    fn without_the_resource_tools_a_select_is_echoed() {
        let body = json!({ "messages": [{ "role": "user", "content": "select 1 from x" }] });
        assert_eq!(
            completion(&body)["choices"][0]["message"]["content"],
            "[mock] You said: select 1 from x"
        );
    }
}

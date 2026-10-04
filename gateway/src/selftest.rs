//! The self-test harness: send a prompt or a tool call to a gateway over
//! HTTP, read back what the control layer did with it, and say whether that
//! is what the case expected.
//!
//! Two drivers use it. The `selftest` binary runs it against the full running
//! system (`just test system`) and prints every case; the cargo tests in
//! `app/tests.rs` run it against the routes served in-process.

use std::fmt::{self, Write as _};
use std::time::Instant;

use serde_json::{Value, json};

/// Who sends a call: a label for the report, the API key (`None` sends none)
/// and the end user named in `X-On-Behalf-Of`.
#[derive(Clone)]
pub struct Caller {
    pub label: String,
    pub key: Option<String>,
    pub user: Option<String>,
}

pub enum Call {
    Chat {
        caller: Caller,
        model: String,
        prompt: String,
    },
    Tool {
        caller: Caller,
        name: String,
        arguments: Value,
        /// The agent's nesting depth, sent in `_meta.depth`.
        depth: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum Expect {
    /// Answered, nothing redacted or refused.
    Allow,
    /// Answered with this control's redaction marker in place of the match.
    Redact(&'static str),
    /// Refused, naming this control or error type.
    Block(&'static str),
}

impl fmt::Display for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Redact(control) => write!(f, "redact by {control}"),
            Self::Block(reason) => write!(f, "block by {reason}"),
        }
    }
}

pub struct Case {
    pub name: String,
    pub call: Call,
    pub expect: Expect,
}

pub fn case(name: impl Into<String>, call: Call, expect: Expect) -> Case {
    Case { name: name.into(), call, expect }
}

/// What the gateway did with one call, as the caller sees it.
pub struct Seen {
    pub status: u16,
    pub refused: bool,
    /// The refusal, or each hook's verdict and the controls that fired.
    pub result: String,
    /// The answer that reached the caller.
    pub text: String,
    /// What the call added to its user's risk score. `None` when it never
    /// reached the controls (no identity).
    pub risk: Option<f64>,
    pub round_trip_ms: u128,
    /// Time spent in each tier, when the gateway reports it.
    pub tiers: Option<(f64, f64)>,
}

impl Seen {
    pub fn passed(&self, expect: Expect) -> bool {
        let redacted = self.text.contains("[REDACTED:");
        match expect {
            Expect::Allow => self.status == 200 && !self.refused && !redacted,
            Expect::Redact(control) => {
                self.status == 200
                    && !self.refused
                    && self.text.contains(&format!("[REDACTED:{control}]"))
            }
            Expect::Block(reason) => self.refused && self.result.contains(reason),
        }
    }
}

/// Send one call to the gateway at `base`. The error is a transport failure,
/// which says nothing about the controls.
pub async fn send(http: &reqwest::Client, base: &str, call: &Call) -> Result<Seen, String> {
    let (caller, path, body, hooks): (_, _, _, &[&str]) = match call {
        Call::Chat { caller, model, prompt } => (
            caller,
            "/v1/chat/completions",
            json!({ "model": model, "messages": [{ "role": "user", "content": prompt }] }),
            &["prompt_in", "response_out"],
        ),
        Call::Tool { caller, name, arguments, depth } => {
            let mut params = json!({ "name": name, "arguments": arguments });
            if let Some(depth) = depth {
                params["_meta"] = json!({ "depth": depth });
            }
            (
                caller,
                "/mcp",
                json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params }),
                &["tool_call", "tool_result"],
            )
        }
    };
    let mut request = http.post(format!("{base}{path}")).json(&body);
    if let Some(key) = &caller.key {
        request = request.bearer_auth(key);
    }
    if let Some(user) = &caller.user {
        request = request.header("x-on-behalf-of", user);
    }
    let started = Instant::now();
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    let body: Value = response.json().await.map_err(|error| error.to_string())?;
    let round_trip_ms = started.elapsed().as_millis();

    let mut seen = match call {
        Call::Chat { .. } => seen_chat(&body, hooks),
        Call::Tool { .. } => seen_tool(&body, hooks),
    };
    seen.status = status;
    seen.round_trip_ms = round_trip_ms;
    Ok(seen)
}

fn seen_chat(body: &Value, hooks: &[&str]) -> Seen {
    if let Some(error) = body.get("error") {
        let mut result = format!("{}: {}", text(&error["type"]), text(&error["message"]));
        if let (Some(stage), Some(hook)) = (error["stage"].as_str(), error["hook"].as_str()) {
            let _ = write!(result, " (stage {stage}, hook {hook})");
        }
        return refusal(result, error["risk_score"].as_f64());
    }
    let answer = body.pointer("/choices/0/message/content");
    answered(&body["x_control_layer"], hooks, answer.map(text).unwrap_or_default())
}

fn seen_tool(body: &Value, hooks: &[&str]) -> Seen {
    if let Some(error) = body.get("error") {
        let result = format!("JSON-RPC error {}: {}", error["code"], text(&error["message"]));
        return refusal(result, error.pointer("/data/risk_score").and_then(Value::as_f64));
    }
    let result = &body["result"];
    let answer = result["content"]
        .as_array()
        .map(|blocks| blocks.iter().map(|b| text(&b["text"])).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
    answered(&result["_meta"]["x-control-layer"], hooks, answer)
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("?").to_owned()
}

fn refusal(result: String, risk: Option<f64>) -> Seen {
    Seen { status: 0, refused: true, result, text: String::new(), risk, round_trip_ms: 0, tiers: None }
}

fn answered(layer: &Value, hooks: &[&str], answer: String) -> Seen {
    let (mut risk, mut deterministic_us, mut semantic_us) = (0.0, 0.0, 0.0);
    let mut parts = Vec::new();
    for name in hooks {
        let hook = &layer[name];
        risk += hook["risk_score"].as_f64().unwrap_or_default();
        deterministic_us += hook["deterministic_us"].as_f64().unwrap_or_default();
        semantic_us += hook["semantic_us"].as_f64().unwrap_or_default();
        parts.push(format!("{name}={} {}", text(&hook["verdict"]), hook["controls_fired"]));
    }
    Seen {
        status: 0,
        refused: false,
        result: parts.join(" · "),
        text: answer,
        risk: Some(risk),
        round_trip_ms: 0,
        tiers: Some((deterministic_us / 1000.0, semantic_us / 1000.0)),
    }
}

/// One case as a report entry: what went in, what came back, the verdict.
pub fn render(number: usize, case: &Case, outcome: &Result<Seen, String>) -> String {
    let passed = outcome.as_ref().is_ok_and(|seen| seen.passed(case.expect));
    let mut out = format!(
        "[{}] #{number:02} {}\n",
        if passed { "PASS" } else { "FAIL" },
        case.name
    );
    match &case.call {
        Call::Chat { caller, model, prompt } => {
            let _ = writeln!(out, "  → POST /v1/chat/completions  as {}  model {model}", who(caller));
            let _ = writeln!(out, "    prompt    {prompt:?}");
        }
        Call::Tool { caller, name, arguments, depth } => {
            let depth = depth.map(|d| format!("  depth {d}")).unwrap_or_default();
            let _ = writeln!(out, "  → POST /mcp tools/call {name}  as {}{depth}", who(caller));
            let _ = writeln!(out, "    arguments {arguments}");
        }
    }
    let _ = writeln!(out, "    expected  {}", case.expect);
    match outcome {
        Err(error) => {
            let _ = writeln!(out, "  ← no answer: {error}");
        }
        Ok(seen) => {
            let _ = writeln!(out, "  ← {} {}", seen.status, seen.result);
            if !seen.text.is_empty() {
                let _ = writeln!(out, "    answer    {:?}", seen.text);
            }
            let risk = seen.risk.map_or_else(|| "n/a (never reached the controls)".to_owned(), |r| format!("{r:.2}"));
            let _ = writeln!(out, "    risk      {risk}");
            let mut timing = format!("{} ms round trip", seen.round_trip_ms);
            if let Some((deterministic, semantic)) = seen.tiers {
                let _ = write!(timing, " · deterministic {deterministic:.2} ms · semantic {semantic:.2} ms");
            }
            let _ = writeln!(out, "    timing    {timing}");
        }
    }
    out
}

fn who(caller: &Caller) -> String {
    match &caller.user {
        Some(user) => format!("{} for {user}", caller.label),
        None => caller.label.clone(),
    }
}

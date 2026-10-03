//! Talking to upstream MCP servers, and the naming scheme that lets several of
//! them live behind one endpoint.

use serde_json::{Value, json};

use crate::policy::McpServer;

/// Separates the server from the tool in a federated name. Two underscores
/// because single ones are common inside tool names.
const SEPARATOR: &str = "__";

/// `docs` + `read` -> `docs__read`
pub fn qualify(server: &str, tool: &str) -> String {
    format!("{server}{SEPARATOR}{tool}")
}

/// `docs__read` -> `("docs", "read")`. Returns `None` for an unqualified name:
/// the gateway refuses to guess which server a bare tool name meant.
pub fn split(qualified: &str) -> Option<(&str, &str)> {
    qualified.split_once(SEPARATOR)
}

/// Current protocol revision. Sent upstream and advertised downstream.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// One JSON-RPC call to an upstream server.
///
/// The `Mcp-Method` and `Mcp-Name` headers mirror the body because the spec
/// requires them on Streamable HTTP, and because the next intermediary in the
/// chain deserves the same ability to route without parsing that we rely on.
pub async fn call(
    http: &reqwest::Client,
    server: &McpServer,
    method: &str,
    name: Option<&str>,
    params: Value,
) -> Result<Value, String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
        "_meta": { "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION },
    });

    let mut request = http
        .post(&server.url)
        .header("Mcp-Method", method)
        .json(&body);
    if let Some(name) = name {
        request = request.header("Mcp-Name", name);
    }

    let response = request
        .send()
        .await
        .map_err(|error| format!("{} unreachable: {error}", server.name))?;

    let envelope: Value = response
        .json()
        .await
        .map_err(|error| format!("{} returned invalid JSON: {error}", server.name))?;

    if let Some(error) = envelope.get("error") {
        return Err(format!("{} returned an error: {error}", server.name));
    }

    Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
}

/// Every text block in an MCP result, concatenated. This is exactly what would
/// land in the model's context, which is what the `tool_result` hook must see.
pub fn result_text(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Replace the text blocks with redacted content, preserving everything else.
pub fn replace_result_text(result: &mut Value, text: &str) {
    let Some(blocks) = result.get_mut("content").and_then(Value::as_array_mut) else {
        return;
    };
    let mut written = false;
    for block in blocks.iter_mut() {
        if block.get("text").is_some() {
            if written {
                // The redacted text is the whole joined body, so later blocks
                // would duplicate it.
                block["text"] = Value::String(String::new());
            } else {
                block["text"] = Value::String(text.to_owned());
                written = true;
            }
        }
    }
}

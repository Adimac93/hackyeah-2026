//! The OpenAPI document served at `/openapi.json` and rendered by Swagger UI
//! at `/admin/docs`. Public documentation: it carries no live state or
//! credentials, and every operation it describes is still protected.

use serde_json::{Value, json};

fn refusal(description: &str) -> Value {
    json!({
        "description": description,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
    })
}

fn ok(description: &str, schema: Value) -> Value {
    json!({ "description": description, "content": {"application/json": {"schema": schema}} })
}

fn admin_errors() -> Value {
    json!({
        "401": {"$ref": "#/components/responses/AuthenticationRequired"},
        "403": {"$ref": "#/components/responses/AdminRequired"},
        "503": refusal("Admin authentication or storage unavailable")
    })
}

fn with(mut base: Value, extra: Value) -> Value {
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            base.insert(k.clone(), v.clone());
        }
    }
    base
}

#[expect(clippy::too_many_lines, reason = "one literal document")]
pub fn document() -> Value {
    let admin = json!([{"supabaseSession": []}]);
    let key = json!([{"apiKey": []}]);
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "AI Control Layer — Gateway API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Integration endpoints (OpenAI-compatible chat, MCP, resource results) authenticate with a per-principal API key. Admin endpoints authenticate the console user with their Supabase access token; viewer and analyst read, admin writes. Every admin write is recorded in admin_actions."
        },
        "tags": [
            {"name": "integration", "description": "Traffic the gateway polices"},
            {"name": "admin", "description": "Live state and state changes for the SecOps console"},
            {"name": "service", "description": "Unauthenticated service metadata"}
        ],
        "paths": {
            "/health": {"get": {"tags": ["service"], "summary": "Liveness and database reachability",
                "responses": {"200": ok("Status", json!({"type": "object", "properties": {
                    "status": {"type": "string"}, "database": {"type": "string", "enum": ["connected", "error"]}}}))}}},
            "/v1/chat/completions": {"post": {
                "tags": ["integration"], "summary": "OpenAI-compatible chat completion, policed at prompt_in and response_out",
                "security": key,
                "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ChatRequest"}}}},
                "responses": {
                    "200": ok("The upstream completion, redacted where policy requires, plus x_control_layer", json!({"$ref": "#/components/schemas/ChatResponse"})),
                    "401": refusal("authentication_required"),
                    "403": refusal("model_not_allowed | blocked_by_control (with error.helper) | risk_blocked"),
                    "429": refusal("budget_exceeded"),
                    "502": refusal("upstream_unavailable | upstream_unreadable")
                }}},
            "/mcp": {"post": {
                "tags": ["integration"], "summary": "MCP 2026-07-28 JSON-RPC endpoint (server/discover, tools/list, tools/call), policed at tool_call and tool_result",
                "description": "Policy outcomes are JSON-RPC errors: -32000 policy denied, -32001 principal denied (auth or tool grant), -32002 upstream error, -32020 header/body mismatch, -32601 method not served. The gateway's own tools resources__describe and resources__query return structure and an acknowledgement only; rows go to GET /v1/results/{id}.",
                "security": key,
                "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": ok("JSON-RPC result or error envelope", json!({"type": "object"}))}}},
            "/v1/results/{id}": {"get": {
                "tags": ["integration"], "summary": "Rows of a resources__query, for the identity that ran it",
                "security": key,
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}}],
                "responses": {
                    "200": ok("Redacted rows", json!({"$ref": "#/components/schemas/ResourceResult"})),
                    "401": refusal("authentication_required"),
                    "404": refusal("No such result for this identity, or expired")
                }}},
            "/policy": {"get": {
                "tags": ["admin"], "summary": "The active policy: version, settings and every active control",
                "security": admin,
                "responses": with(json!({"200": ok("Active policy", json!({"$ref": "#/components/schemas/ActivePolicy"}))}), admin_errors())}},
            "/admin/policy": {"post": {
                "tags": ["admin"], "summary": "Validate, store and activate a policy catalog (admin)",
                "description": "Invalid TOML leaves the active policy unchanged and is recorded as a rejected admin action. Every instance activates the new version within 5 s.",
                "security": admin,
                "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PolicyUpload"}}}},
                "responses": with(json!({
                    "200": ok("Activated", json!({"$ref": "#/components/schemas/PolicyUploadResult"})),
                    "400": refusal("Empty catalog"),
                    "422": refusal("invalid_policy: the TOML or the policy schema is invalid")
                }), admin_errors())}},
            "/admin/policy/versions": {"get": {
                "tags": ["admin"], "summary": "Policy version history with diffs",
                "security": admin,
                "responses": with(json!({"200": ok("Newest first, at most 100", json!({"type": "array", "items": {"$ref": "#/components/schemas/PolicyVersion"}}))}), admin_errors())}},
            "/admin/budgets": {
                "get": {"tags": ["admin"], "summary": "Enabled budgets as enforced", "security": admin,
                    "responses": with(json!({"200": ok("Budgets", json!({"type": "array", "items": {"$ref": "#/components/schemas/Budget"}}))}), admin_errors())},
                "put": {"tags": ["admin"], "summary": "Create or replace the budget for one scope (admin)", "security": admin,
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BudgetInput"}}}},
                    "responses": with(json!({"200": ok("Stored", json!({"type": "object", "properties": {"id": {"type": "integer"}}})),
                        "422": refusal("invalid_budget")}), admin_errors())}},
            "/admin/budgets/{id}": {"delete": {
                "tags": ["admin"], "summary": "Delete a budget (admin)", "security": admin,
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
                "responses": with(json!({"204": {"description": "Deleted"}, "404": refusal("not_found")}), admin_errors())}},
            "/metrics": {"get": {
                "tags": ["admin"], "summary": "24-hour management and security report",
                "security": admin,
                "responses": with(json!({"200": ok("Totals, top controls, identities, latency percentiles, budgets, incidents", json!({"type": "object"}))}), admin_errors())}},
            "/admin/audit/export": {"get": {
                "tags": ["admin"], "summary": "Export the audit log as JSON or CSV",
                "security": admin,
                "parameters": [
                    {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["json", "csv"], "default": "json"}},
                    {"name": "from", "in": "query", "description": "RFC 3339, inclusive", "schema": {"type": "string", "format": "date-time"}},
                    {"name": "to", "in": "query", "description": "RFC 3339, exclusive", "schema": {"type": "string", "format": "date-time"}},
                    {"name": "principal", "in": "query", "description": "Principal slug", "schema": {"type": "string"}},
                    {"name": "control", "in": "query", "description": "Control id that fired", "schema": {"type": "string"}},
                    {"name": "action", "in": "query", "schema": {"type": "string", "enum": ["allow", "flag", "redact", "block"]}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 10000}}
                ],
                "responses": with(json!({"200": {"description": "Events, oldest first", "content": {
                    "application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/AuditRow"}}},
                    "text/csv": {"schema": {"type": "string"}}}},
                    "400": refusal("invalid_format | invalid_filter")}), admin_errors())}},
            "/metrics/prometheus": {"get": {
                "tags": ["service"], "summary": "Live telemetry in the Prometheus text format",
                "security": [{"metricsToken": []}],
                "responses": {"200": {"description": "Prometheus exposition", "content": {"text/plain": {"schema": {"type": "string"}}}},
                    "401": refusal("Missing or wrong METRICS_TOKEN"), "404": refusal("METRICS_TOKEN not configured")}}}
        },
        "components": {
            "securitySchemes": {
                "apiKey": {"type": "http", "scheme": "bearer", "bearerFormat": "API key", "description": "Per-principal gateway API key; only its SHA-256 hash is stored."},
                "supabaseSession": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": "The console user's Supabase access token. Role from team_members: viewer/analyst read, admin writes."},
                "metricsToken": {"type": "http", "scheme": "bearer", "description": "METRICS_TOKEN, for scrapers."}
            },
            "responses": {
                "AuthenticationRequired": refusal("Missing, malformed, invalid or expired Bearer token"),
                "AdminRequired": refusal("The user's team role does not allow this operation")
            },
            "schemas": {
                "Error": {"type": "object", "properties": {
                    "error": {"type": "object", "properties": {
                        "type": {"type": "string"}, "message": {"type": "string"},
                        "helper": {"$ref": "#/components/schemas/Helper"}}},
                    "trace_id": {"type": "string", "format": "uuid"}}},
                "Helper": {"type": "object", "description": "Prompt helper: the violated policy and a compliant rewrite to resubmit explicitly. Never sent to the model automatically.",
                    "properties": {"violated_policy": {"type": "string"}, "suggestion": {"type": ["string", "null"]}}},
                "ChatRequest": {"type": "object", "required": ["model", "messages"], "properties": {
                    "model": {"type": "string"},
                    "messages": {"type": "array", "items": {"type": "object", "properties": {
                        "role": {"type": "string"},
                        "content": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "object"}}]}}}}}},
                "ChatResponse": {"type": "object", "description": "OpenAI chat.completion plus x_control_layer", "properties": {
                    "choices": {"type": "array", "items": {"type": "object"}},
                    "usage": {"type": "object"},
                    "x_control_layer": {"type": "object", "properties": {
                        "trace_id": {"type": "string", "format": "uuid"},
                        "policy_version": {"type": "string"},
                        "prompt_in": {"$ref": "#/components/schemas/HookSummary"},
                        "response_out": {"$ref": "#/components/schemas/HookSummary"}}}}},
                "HookSummary": {"type": "object", "properties": {
                    "verdict": {"type": "string", "enum": ["allow", "redact", "block"]},
                    "controls_fired": {"type": "array", "items": {"type": "string"}},
                    "deterministic_us": {"type": "integer"}, "semantic_us": {"type": "integer"}}},
                "ResourceResult": {"type": "object", "properties": {
                    "id": {"type": "string", "format": "uuid"}, "columns": {"type": "array", "items": {"type": "string"}},
                    "row_count": {"type": "integer"}, "rows": {"type": "array", "items": {"type": "object"}},
                    "created_at": {"type": "string", "format": "date-time"}}},
                "ActivePolicy": {"type": "object", "properties": {
                    "version": {"type": "string"}, "version_id": {"type": "integer"}, "source": {"type": "string"},
                    "profile": {"type": ["string", "null"]}, "on_detect": {"type": "string"}, "fail_mode": {"type": "string"},
                    "models": {"type": "object"}, "signature_feed": {"type": ["object", "null"]},
                    "risk": {"type": "object"}, "runaway": {"type": "object"}, "mcp_servers": {"type": "array", "items": {"type": "object"}},
                    "controls": {"type": "array", "items": {"type": "object"}}}},
                "PolicyUpload": {"type": "object", "additionalProperties": false, "required": ["catalog_toml"], "properties": {
                    "catalog_toml": {"type": "string", "description": "Complete TOML control catalog"},
                    "signatures_toml": {"type": "string", "description": "Attack-signature feed. Omit to keep the active feed; empty string removes it."}}},
                "PolicyUploadResult": {"type": "object", "properties": {
                    "accepted": {"type": "boolean"}, "changed": {"type": "boolean"},
                    "version": {"type": "string"}, "version_id": {"type": "integer"},
                    "diff": {"type": "array", "items": {"type": "string"}, "description": "+ added, - removed or disabled, ~ changed"}}},
                "PolicyVersion": {"type": "object", "properties": {
                    "id": {"type": "integer"}, "version": {"type": "string"}, "source": {"type": "string"},
                    "loaded_at": {"type": "string", "format": "date-time"}, "active": {"type": "boolean"},
                    "diff": {"type": ["string", "null"]}, "uploaded_by": {"type": ["string", "null"], "format": "uuid"},
                    "has_signatures": {"type": "boolean"}}},
                "Budget": {"type": "object", "properties": {
                    "id": {"type": "integer"}, "scope": {"type": "string"}, "scope_id": {"type": ["string", "null"]},
                    "window_secs": {"type": "integer"}, "limit_tokens": {"type": ["integer", "null"]},
                    "limit_usd": {"type": ["number", "null"]}, "limit_requests": {"type": ["integer", "null"]},
                    "limit_concurrency": {"type": ["integer", "null"]}, "hard": {"type": "boolean"}}},
                "BudgetInput": {"type": "object", "additionalProperties": false, "required": ["scope"], "properties": {
                    "scope": {"type": "string", "enum": ["global", "principal", "model"]},
                    "scope_id": {"type": "string", "description": "Principal slug or model name; absent for global"},
                    "window_secs": {"type": "integer", "default": 86400},
                    "limit_tokens": {"type": "integer"}, "limit_usd": {"type": "number"},
                    "limit_requests": {"type": "integer"}, "limit_concurrency": {"type": "integer"},
                    "hard": {"type": "boolean", "default": true}, "enabled": {"type": "boolean", "default": true}}},
                "AuditRow": {"type": "object", "properties": {
                    "id": {"type": "integer"}, "ts": {"type": "string"}, "trace_id": {"type": "string"},
                    "hook": {"type": "string"}, "channel": {"type": "string"}, "principal": {"type": ["string", "null"]},
                    "model": {"type": ["string", "null"]}, "tool": {"type": ["string", "null"]}, "verdict": {"type": "string"},
                    "policy_version": {"type": ["string", "null"]}, "controls": {"type": "string", "description": "control_id:action, space separated"},
                    "tokens": {"type": "integer"}, "cost_usd": {"type": "number"}, "latency": {"type": "string"}}}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_but_health_declares_security() {
        let document = document();
        assert_eq!(document["openapi"], "3.1.0");
        let paths = document["paths"].as_object().unwrap();
        for (path, operations) in paths {
            for (method, operation) in operations.as_object().unwrap() {
                if path == "/health" {
                    continue;
                }
                assert!(
                    operation["security"].is_array(),
                    "{method} {path} must declare its security"
                );
            }
        }
        assert!(paths.contains_key("/v1/chat/completions"));
        assert!(paths.contains_key("/admin/audit/export"));
    }

    #[test]
    fn every_schema_reference_resolves() {
        let document = document();
        let text = document.to_string();
        for reference in text.split("\"$ref\":\"#/components/").skip(1) {
            let path: Vec<&str> = reference.split('"').next().unwrap().split('/').collect();
            assert!(
                !document["components"][path[0]][path[1]].is_null(),
                "dangling $ref {path:?}"
            );
        }
    }
}

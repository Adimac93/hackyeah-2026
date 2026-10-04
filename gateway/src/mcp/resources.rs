//! The resource processing engine behind the gateway-native `resources` MCP
//! server (docs/BACKEND.md, "MCP integration" and "Resource processing
//! engine").
//!
//! The model may learn the structure of the protected data and ask questions
//! of it, but never sees a value: `resources__query` runs the query, pushes the
//! redacted rows to the identity that asked (`GET /v1/results/{id}`), and
//! hands the model only a reference, the column names and a row count.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use regex::Regex;
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use std::sync::LazyLock;
use uuid::Uuid;

use crate::admin::auth::refusal;
use crate::audit::Principal;
use crate::engine::{self, Evaluation};
use crate::policy::{Hook, Policy};
use crate::proxy::bearer_principal;
use crate::state::AppState;

/// The federated server name of the gateway's own tools.
pub const SERVER: &str = "resources";
pub const DESCRIBE: &str = "resources__describe";
pub const QUERY: &str = "resources__query";

pub fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": DESCRIBE,
            "description": "Structure of the protected SQL database, never data. With no arguments, \
                            lists the tables you may query. With `tables`, returns their columns \
                            from information_schema.columns. Call it before resources__query.",
            "inputSchema": {
                "type": "object",
                "properties": { "tables": { "type": "array", "items": { "type": "string" } } },
            },
        }),
        json!({
            "name": QUERY,
            "description": "Run one read-only SELECT over the tables listed by resources__describe. \
                            The rows go to the user who asked, not to you: you receive a result \
                            reference, the column names and the row count.",
            "inputSchema": {
                "type": "object",
                "properties": { "sql": { "type": "string" } },
                "required": ["sql"],
            },
        }),
    ]
}

/// The tables this identity may query, or the columns of the ones it asked
/// for. Asking for a table outside the grant is refused, whether or not it
/// exists.
pub async fn describe(pool: &PgPool, granted: &[String], wanted: &[String]) -> Result<String, String> {
    if wanted.is_empty() {
        return Ok(if granted.is_empty() {
            "no tables are available to this identity\n".to_owned()
        } else {
            format!("tables: {}\n", granted.join(", "))
        });
    }
    if let Some(table) = wanted.iter().find(|table| !granted.contains(table)) {
        return Err(format!("table {table} is not granted to this identity"));
    }
    let columns = sqlx::query_as::<_, (String, String, String)>(
        "select table_name::text, column_name::text, data_type::text
         from information_schema.columns
         where table_schema = 'resources' and table_name = any($1)
         order by table_name, ordinal_position",
    )
    .bind(wanted)
    .fetch_all(pool)
    .await
    .map_err(|error| format!("could not read the resource schema: {error}"))?;

    let mut out = String::new();
    let mut current = "";
    for (table, column, kind) in &columns {
        if table != current {
            if !current.is_empty() {
                out.push_str(")\n");
            }
            out.push_str(&format!("{table}("));
            current = table;
        } else {
            out.push_str(", ");
        }
        out.push_str(&format!("{column} {kind}"));
    }
    if !current.is_empty() {
        out.push_str(")\n");
    }
    if out.is_empty() {
        out.push_str("none of these tables exist\n");
    }
    Ok(out)
}

static FORBIDDEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(insert|update|delete|merge|drop|alter|create|grant|revoke|truncate|copy|call|do|execute|prepare|lock|vacuum|listen|notify|set|reset|into|pg_[a-z_]*|dblink[a-z_]*|lo_[a-z_]*|current_setting|set_config|pg_catalog|information_schema|public|auth|storage|vault|extensions)\b",
    )
    .expect("static regex")
});

/// Cheap first pass over the query text. The plan check in [`query`] is what
/// decides which tables are touched; this rejects what should never be parsed.
pub fn validate_sql(sql: &str) -> Result<String, String> {
    let sql = sql.trim().trim_end_matches(';').trim();
    if sql.is_empty() {
        return Err("empty query".into());
    }
    if sql.contains(';') {
        return Err("exactly one statement is allowed".into());
    }
    if sql.contains("--") || sql.contains("/*") {
        return Err("comments are not allowed".into());
    }
    let lower = sql.to_ascii_lowercase();
    if !(lower.starts_with("select") || lower.starts_with("with")) {
        return Err("only SELECT queries are allowed".into());
    }
    if let Some(word) = FORBIDDEN.find(sql) {
        return Err(format!("{:?} is not allowed in a resource query", word.as_str()));
    }
    Ok(sql.to_owned())
}

/// Every `(schema, relation)` a plan reads.
pub fn relations(plan: &Value, out: &mut Vec<(String, String)>) {
    match plan {
        Value::Object(map) => {
            if let Some(name) = map.get("Relation Name").and_then(Value::as_str) {
                let schema = map.get("Schema").and_then(Value::as_str).unwrap_or_default();
                out.push((schema.to_owned(), name.to_owned()));
            }
            map.values().for_each(|v| relations(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| relations(v, out)),
        _ => {}
    }
}

pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Value>,
    pub truncated: bool,
}

/// Run one query read-only, against granted tables only.
pub async fn run(
    pool: &PgPool,
    policy: &Policy,
    tables: &[String],
    sql: &str,
) -> Result<QueryResult, String> {
    let sql = validate_sql(sql)?;
    let limits = &policy.resources;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    for statement in [
        "set transaction read only".to_owned(),
        format!("set local statement_timeout = {}", limits.statement_timeout_ms),
        "set local search_path = resources".to_owned(),
    ] {
        sqlx::query(&statement)
            .persistent(false)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    }

    // The planner, not a regex, says which tables the query reads.
    let plan = sqlx::query_scalar::<_, Value>(&format!("explain (format json, verbose) {sql}"))
        .persistent(false)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("the query does not plan: {e}"))?;
    let mut touched = Vec::new();
    relations(&plan, &mut touched);
    for (schema, table) in &touched {
        if schema != "resources" || !tables.contains(table) {
            return Err(format!("table {schema}.{table} is not granted to this identity"));
        }
    }

    let wrapped = format!(
        "select coalesce(json_agg(q), '[]'::json) from (select * from ({sql}) inner_q limit {}) q",
        limits.max_rows + 1
    );
    let rows = sqlx::query_scalar::<_, Value>(&wrapped)
        .persistent(false)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("the query failed: {e}"))?;
    tx.rollback().await.map_err(|e| e.to_string())?;

    let mut rows = match rows {
        Value::Array(rows) => rows,
        _ => Vec::new(),
    };
    let truncated = rows.len() > usize::try_from(limits.max_rows).unwrap_or(usize::MAX);
    rows.truncate(usize::try_from(limits.max_rows).unwrap_or(usize::MAX));
    let columns = rows
        .first()
        .and_then(Value::as_object)
        .map(|row| row.keys().cloned().collect())
        .unwrap_or_default();
    Ok(QueryResult {
        columns,
        rows,
        truncated,
    })
}

/// Output guardrails before the rows reach anyone (§ resource engine): the
/// whole result is evaluated for the audit log, then every string value is
/// redacted on its own so the rows keep their shape.
pub fn guard_rows(policy: &Policy, rows: &mut [Value]) -> Evaluation {
    let text = Value::Array(rows.to_vec()).to_string();
    let evaluation = engine::evaluate(policy, Hook::ResponseOut, &text);
    for row in rows.iter_mut() {
        if let Value::Object(fields) = row {
            for value in fields.values_mut() {
                if let Value::String(inner) = value {
                    *inner = engine::redact(policy, Hook::ResponseOut, inner);
                }
            }
        }
    }
    evaluation
}

/// Store the rows for their owner and build the acknowledgement the model gets.
pub async fn deliver(
    pool: &PgPool,
    principal: &Principal,
    trace_id: Uuid,
    result: &QueryResult,
) -> Result<Value, String> {
    let row_count = i32::try_from(result.rows.len()).unwrap_or(i32::MAX);
    let id = sqlx::query_scalar::<_, Uuid>(
        "insert into resource_results (principal_id, trace_id, tool, columns, row_count, rows)
         values ($1, $2, $3, $4, $5, $6) returning id",
    )
    .bind(principal.id)
    .bind(trace_id)
    .bind(QUERY)
    .bind(&result.columns)
    .bind(row_count)
    .bind(Value::Array(result.rows.clone()))
    .fetch_one(pool)
    .await
    .map_err(|e| format!("could not store the result: {e}"))?;

    Ok(json!({
        "result_id": id,
        "columns": result.columns,
        "row_count": row_count,
        "truncated": result.truncated,
        "delivered_to": "the requesting user",
        "note": "The rows were delivered to the user. They are intentionally not included here.",
    }))
}

/// `GET /v1/results/{id}`: the rows of a query, to the identity that ran it.
pub async fn result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let principal = match bearer_principal(&state.auditor, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let row = sqlx::query_as::<_, (Vec<String>, i32, Value, String)>(
        "select columns, row_count, rows,
                to_char(created_at at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
         from resource_results
         where id = $1 and principal_id = $2 and expires_at > now()",
    )
    .bind(id)
    .bind(principal.id)
    .fetch_optional(state.db())
    .await;
    match row {
        Ok(Some((columns, row_count, rows, created_at))) => Json(json!({
            "id": id,
            "columns": columns,
            "row_count": row_count,
            "rows": rows,
            "created_at": created_at,
        }))
        .into_response(),
        // Someone else's result is indistinguishable from a missing one.
        Ok(None) => refusal(StatusCode::NOT_FOUND, "not_found", "no such result"),
        Err(error) => {
            tracing::error!(%error, "result lookup failed");
            refusal(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "results are unavailable")
        }
    }
}

/// The text the tool-result hook sees for a gateway-native result.
pub fn as_tool_result(text: String) -> Value {
    let mut result = Map::new();
    result.insert(
        "content".into(),
        json!([{ "type": "text", "text": text }]),
    );
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_single_select_passes() {
        assert!(validate_sql("select full_name from customers;").is_ok());
        assert!(validate_sql("with x as (select 1) select * from x").is_ok());
        assert!(validate_sql("delete from customers").is_err());
        assert!(validate_sql("select 1; drop table customers").is_err());
        assert!(validate_sql("select * from customers -- hidden").is_err());
        assert!(validate_sql("select pg_read_file('/etc/passwd')").is_err());
        assert!(validate_sql("select * from auth.users").is_err());
        assert!(validate_sql("select * into stolen from customers").is_err());
        assert!(validate_sql("").is_err());
    }

    #[tokio::test]
    async fn describe_lists_the_grant_and_refuses_tables_outside_it() {
        // Neither answer needs the database, so the pool never connects.
        let pool = PgPool::connect_lazy("postgres://localhost/unused").unwrap();
        let granted = vec!["customers".to_owned(), "invoices".to_owned()];
        assert_eq!(
            describe(&pool, &granted, &[]).await.unwrap(),
            "tables: customers, invoices\n"
        );
        assert_eq!(
            describe(&pool, &[], &[]).await.unwrap(),
            "no tables are available to this identity\n"
        );
        let refused = describe(&pool, &granted, &["customers".to_owned(), "payroll".to_owned()])
            .await
            .unwrap_err();
        assert_eq!(refused, "table payroll is not granted to this identity");
    }

    #[test]
    fn plan_relations_are_collected_at_any_depth() {
        let plan = json!([{ "Plan": {
            "Node Type": "Hash Join",
            "Plans": [
                { "Node Type": "Seq Scan", "Relation Name": "customers", "Schema": "resources" },
                { "Node Type": "Hash", "Plans": [
                    { "Node Type": "Seq Scan", "Relation Name": "users", "Schema": "auth" },
                ]},
            ],
        }}]);
        let mut found = Vec::new();
        relations(&plan, &mut found);
        assert_eq!(
            found,
            [
                ("resources".to_owned(), "customers".to_owned()),
                ("auth".to_owned(), "users".to_owned()),
            ]
        );
    }

    #[test]
    fn rows_are_redacted_value_by_value() {
        let policy = Policy::from_str(
            r#"
schema_version = 1
[[controls.deterministic]]
id = "pii.email"
hooks = ["response_out"]
severity = "medium"
action = "redact"
pattern = '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
"#,
            "test",
        )
        .unwrap();
        let mut rows = vec![json!({ "email": "a@b.com", "mrr_usd": 4200.0 })];
        let evaluation = guard_rows(&policy, &mut rows);
        assert_eq!(evaluation.detections[0].control_id, "pii.email");
        assert_eq!(rows[0]["email"], "[REDACTED:pii.email]");
        assert_eq!(rows[0]["mrr_usd"], 4200.0);
    }
}

//! Audit log export for security teams (§4.5): JSON or CSV, filtered by time
//! range, identity, control, verdict, channel and action.
//!
//! `include` picks column groups (identity, target, detections, usage,
//! performance, policy, integrity); the event columns are always there. With
//! `integrity` each row carries its hash-chain fields, so the export is
//! evidence an auditor can check without database access:
//! `verify-audit --file export.json` runs [`verify_export`] over it.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::auth::{Access, refusal};
use crate::audit::{chain_hash, hex, unhex};
use crate::state::AppState;

const MAX_ROWS: i64 = 10_000;
const VERDICTS: &[&str] = &["allow", "redact", "block"];
const ACTIONS: &[&str] = &["allow", "flag", "redact", "block"];
const CHANNELS: &[&str] = &["llm", "mcp", "a2a"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    #[serde(default)]
    format: Option<String>,
    /// RFC 3339 timestamps or UTC days (`YYYY-MM-DD`); `from` inclusive, `to`
    /// exclusive for a timestamp and inclusive for a day.
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
    /// Principal slug.
    #[serde(default)]
    principal: Option<String>,
    /// End user the event is attributed to.
    #[serde(default)]
    user: Option<String>,
    /// Control id that fired on the event.
    #[serde(default)]
    control: Option<String>,
    /// The event's verdict or any of its detections' actions:
    /// allow | flag | redact | block.
    #[serde(default)]
    action: Option<String>,
    /// The event's verdict exactly: allow | redact | block.
    #[serde(default)]
    verdict: Option<String>,
    /// llm | mcp | a2a.
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    /// Comma-separated column groups: every group when absent, none (event
    /// columns only) when empty.
    #[serde(default)]
    include: Option<String>,
}

/// The fields of an exported event that the hash chain covers. They are all
/// the verifier reads, so an export narrowed with `include` still verifies as
/// long as it has the integrity group.
#[derive(Debug, Clone, Deserialize, sqlx::FromRow)]
pub struct ChainRow {
    pub id: i64,
    pub trace_id: String,
    pub hook: String,
    pub verdict: String,
    /// `[control_id, action]` in detection order, as `chain_hash` takes them.
    pub controls: sqlx::types::Json<Vec<(String, String)>>,
    pub payload_sha256: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Row {
    #[sqlx(flatten)]
    pub chain: ChainRow,
    pub ts: String,
    pub channel: String,
    pub principal: Option<String>,
    pub user: Option<String>,
    pub model: Option<String>,
    pub tool: Option<String>,
    pub policy_version: Option<String>,
    pub tokens: i64,
    pub cost_usd: f64,
    pub latency: String,
}

/// One exported column: its name, the `include` group that switches it on
/// (`None`: always exported) and how to read it. CSV and JSON both render from
/// this table, so a column is declared once.
pub struct Column {
    pub name: &'static str,
    group: Option<&'static str>,
    value: fn(&Row) -> Value,
}

#[rustfmt::skip] // one row per column reads as a table
const COLUMNS: &[Column] = &[
    Column { name: "id",             group: None,                value: |r| r.chain.id.into() },
    Column { name: "ts",             group: None,                value: |r| r.ts.clone().into() },
    Column { name: "trace_id",       group: None,                value: |r| r.chain.trace_id.clone().into() },
    Column { name: "hook",           group: None,                value: |r| r.chain.hook.clone().into() },
    Column { name: "channel",        group: None,                value: |r| r.channel.clone().into() },
    Column { name: "principal",      group: Some("identity"),    value: |r| r.principal.clone().into() },
    Column { name: "user",           group: Some("identity"),    value: |r| r.user.clone().into() },
    Column { name: "model",          group: Some("target"),      value: |r| r.model.clone().into() },
    Column { name: "tool",           group: Some("target"),      value: |r| r.tool.clone().into() },
    Column { name: "verdict",        group: None,                value: |r| r.chain.verdict.clone().into() },
    Column { name: "policy_version", group: Some("policy"),      value: |r| r.policy_version.clone().into() },
    Column { name: "controls",       group: Some("detections"),  value: |r| serde_json::to_value(&r.chain.controls.0).unwrap_or_default() },
    Column { name: "tokens",         group: Some("usage"),       value: |r| r.tokens.into() },
    Column { name: "cost_usd",       group: Some("usage"),       value: |r| r.cost_usd.into() },
    Column { name: "latency",        group: Some("performance"), value: |r| r.latency.clone().into() },
    Column { name: "payload_sha256", group: Some("integrity"),   value: |r| r.chain.payload_sha256.clone().into() },
    Column { name: "prev_hash",      group: Some("integrity"),   value: |r| r.chain.prev_hash.clone().into() },
    Column { name: "hash",           group: Some("integrity"),   value: |r| r.chain.hash.clone().into() },
];

/// The columns an `include` list selects. Integrity brings detections with it:
/// the hash covers them, so a file without them could not be verified.
pub fn columns(include: Option<&str>) -> Result<Vec<&'static Column>, String> {
    let groups: Option<Vec<&str>> = include.map(|list| {
        list.split(',').map(str::trim).filter(|g| !g.is_empty()).collect()
    });
    if let Some(unknown) = groups
        .iter()
        .flatten()
        .find(|g| !COLUMNS.iter().any(|c| c.group == Some(**g)))
    {
        return Err(format!("unknown column group {unknown:?}"));
    }
    let wanted = |group: &str| {
        groups.as_ref().is_none_or(|g| {
            g.contains(&group) || (group == "detections" && g.contains(&"integrity"))
        })
    };
    Ok(COLUMNS
        .iter()
        .filter(|c| c.group.is_none_or(wanted))
        .collect())
}

fn one_of(name: &str, value: Option<&str>, allowed: &[&str]) -> Result<(), String> {
    match value {
        Some(v) if !allowed.contains(&v) => Err(format!("{name} {v:?} is not one of {allowed:?}")),
        _ => Ok(()),
    }
}

pub async fn export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filters): Query<Filters>,
) -> Response {
    if let Err(response) = state
        .admins
        .require(state.db(), &headers, Access::Read)
        .await
    {
        return response;
    }
    let checked = one_of("format", filters.format.as_deref(), &["json", "csv"])
        .and(one_of("verdict", filters.verdict.as_deref(), VERDICTS))
        .and(one_of("action", filters.action.as_deref(), ACTIONS))
        .and(one_of("channel", filters.channel.as_deref(), CHANNELS))
        .and_then(|()| columns(filters.include.as_deref()));
    let columns = match checked {
        Ok(columns) => columns,
        Err(message) => return refusal(StatusCode::BAD_REQUEST, "invalid_filter", &message),
    };
    let selected = |name: &str| columns.iter().any(|c| c.name == name);

    // Detections and usage are per-event subqueries: skipped unless exported.
    let rows = sqlx::query_as::<_, Row>(
        r#"select e.id,
                to_char(e.ts at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') as ts,
                e.trace_id::text as trace_id, e.hook::text as hook, e.channel::text as channel,
                p.slug as principal, e.end_user as "user", e.model, e.tool,
                e.verdict::text as verdict, pv.sha256 as policy_version,
                ds.controls, us.tokens, us.cost_usd,
                e.latency::text as latency,
                e.payload_sha256,
                encode(coalesce(e.prev_hash, ''::bytea), 'hex') as prev_hash,
                encode(e.hash, 'hex') as hash
         from events e
         left join principals p on p.id = e.principal_id
         left join policy_versions pv on pv.id = e.policy_version_id
         left join lateral (
                select coalesce(json_agg(json_build_array(d.control_id, d.action::text) order by d.id),
                                '[]'::json) as controls
                from detections d where $10 and d.event_id = e.id) ds on true
         left join lateral (
                select coalesce(sum(u.prompt_tokens + u.completion_tokens), 0)::bigint as tokens,
                       coalesce(sum(u.cost_usd), 0)::float8 as cost_usd
                from usage u where $11 and u.event_id = e.id) us on true
         where ($1::text is null or e.ts >= case when $1 ~ '^\d{4}-\d{2}-\d{2}$'
                    then $1::date::timestamp at time zone 'utc' else $1::timestamptz end)
           and ($2::text is null or e.ts < case when $2 ~ '^\d{4}-\d{2}-\d{2}$'
                    then ($2::date + 1)::timestamp at time zone 'utc' else $2::timestamptz end)
           and ($3::text is null or p.slug = $3)
           and ($7::text is null or e.end_user = $7)
           and ($4::text is null or exists (
                 select 1 from detections d where d.event_id = e.id and d.control_id = $4))
           and ($5::text is null or e.verdict::text = $5 or exists (
                 select 1 from detections d where d.event_id = e.id and d.action::text = $5))
           and ($8::text is null or e.verdict::text = $8)
           and ($9::text is null or e.channel::text = $9)
         order by e.id
         limit $6"#,
    )
    .bind(&filters.from)
    .bind(&filters.to)
    .bind(&filters.principal)
    .bind(&filters.control)
    .bind(&filters.action)
    .bind(filters.limit.unwrap_or(MAX_ROWS).clamp(1, MAX_ROWS))
    .bind(&filters.user)
    .bind(&filters.verdict)
    .bind(&filters.channel)
    .bind(selected("controls"))
    .bind(selected("tokens"))
    .fetch_all(state.db())
    .await;

    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "audit export failed");
            return refusal(
                StatusCode::BAD_REQUEST,
                "invalid_filter",
                "the export query failed; check the from/to timestamps",
            );
        }
    };

    if filters.format.as_deref() == Some("json") || filters.format.is_none() {
        Json(to_json(&rows, &columns)).into_response()
    } else {
        (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"audit-log.csv\"",
                ),
            ],
            to_csv(&rows, &columns),
        )
            .into_response()
    }
}

pub fn to_json(rows: &[Row], columns: &[&Column]) -> Vec<serde_json::Map<String, Value>> {
    rows.iter()
        .map(|row| {
            columns
                .iter()
                .map(|c| (c.name.to_owned(), (c.value)(row)))
                .collect()
        })
        .collect()
}

pub fn to_csv(rows: &[Row], columns: &[&Column]) -> String {
    let mut out = columns.iter().map(|c| c.name).collect::<Vec<_>>().join(",");
    out.push('\n');
    for row in rows {
        let line: Vec<String> = columns
            .iter()
            .map(|c| csv_field(&csv_text((c.value)(row))))
            .collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

/// A JSON value as one CSV cell; detections read `control:action control:action`.
fn csv_text(value: Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s,
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::Array(pair) => pair.into_iter().map(csv_text).collect::<Vec<_>>().join(":"),
                other => csv_text(other),
            })
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

/// RFC 4180 quoting, plus a leading `'` on values a spreadsheet would run as a
/// formula: an audit export must not become an injection vector itself.
fn csv_field(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

/// What verifying an exported file found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExportReport {
    pub rows: usize,
    /// Rows whose fields no longer reproduce their `hash`.
    pub broken: Vec<i64>,
    /// Runs of rows that link to each other. A filtered export, or one cut by
    /// the row limit, has gaps between runs; a complete one is a single run.
    pub segments: usize,
}

/// Re-derive every row's hash from its own fields and its `prev_hash`, and
/// count where consecutive rows stop linking. Needs no database: this is how
/// an export proves itself.
///
/// A row whose `prev_hash` differs from the previous row's `hash` starts a new
/// segment rather than counting as broken, because filters leave gaps. Within
/// a row, any edit to the verdict, hook, trace, payload hash or detections
/// breaks it.
pub fn verify_export(rows: &[ChainRow]) -> ExportReport {
    let mut report = ExportReport {
        rows: rows.len(),
        ..ExportReport::default()
    };
    let mut previous: Option<&ChainRow> = None;
    for row in rows {
        if previous.is_none_or(|p| p.hash != row.prev_hash) {
            report.segments += 1;
        }
        if row.recomputed().as_deref() != Some(row.hash.as_str()) {
            report.broken.push(row.id);
        }
        previous = Some(row);
    }
    report
}

impl ChainRow {
    fn recomputed(&self) -> Option<String> {
        let detections: Vec<(&str, &str)> = self
            .controls
            .iter()
            .map(|(c, a)| (c.as_str(), a.as_str()))
            .collect();
        Some(hex(&chain_hash(
            &unhex(&self.prev_hash)?,
            Uuid::parse_str(&self.trace_id).ok()?,
            &self.hook,
            &self.verdict,
            self.payload_sha256.as_deref().unwrap_or_default(),
            &detections,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, prev_hash: &str, verdict: &str, controls: &[(&str, &str)]) -> Row {
        let mut row = Row {
            chain: ChainRow {
                id,
                trace_id: "6f1c1b7e-58f0-4a53-9a43-2d2e8b2f0c11".into(),
                hook: "prompt_in".into(),
                verdict: verdict.into(),
                controls: sqlx::types::Json(
                    controls
                        .iter()
                        .map(|(c, a)| ((*c).to_owned(), (*a).to_owned()))
                        .collect(),
                ),
                payload_sha256: Some("ab".repeat(32)),
                prev_hash: prev_hash.into(),
                hash: String::new(),
            },
            ts: "2026-10-03T12:00:00.000Z".into(),
            channel: "llm".into(),
            principal: Some("console-chat".into()),
            user: Some("anna@example.com".into()),
            model: None,
            tool: None,
            policy_version: None,
            tokens: 0,
            cost_usd: 0.0,
            latency: r#"{"deterministic_us": 12}"#.into(),
        };
        row.chain.hash = row.chain.recomputed().expect("a well-formed row");
        row
    }

    /// Three linked events, as the gateway writes them.
    fn chain() -> Vec<Row> {
        let first = row(1, "", "allow", &[]);
        let second = row(
            2,
            &first.chain.hash,
            "block",
            &[("secret.aws-access-key", "block")],
        );
        let third = row(
            3,
            &second.chain.hash,
            "redact",
            &[("pii.email", "redact"), ("pii.phone", "redact")],
        );
        vec![first, second, third]
    }

    fn check(rows: &[Row]) -> ExportReport {
        verify_export(&rows.iter().map(|r| r.chain.clone()).collect::<Vec<_>>())
    }

    fn names(include: Option<&str>) -> Vec<&'static str> {
        columns(include).unwrap().iter().map(|c| c.name).collect()
    }

    /// JSON as the endpoint serves it, read back as the verifier reads it.
    fn exported(rows: &[Row], include: Option<&str>) -> Result<Vec<ChainRow>, serde_json::Error> {
        let json = serde_json::to_string(&to_json(rows, &columns(include).unwrap())).unwrap();
        serde_json::from_str(&json)
    }

    #[test]
    fn csv_quotes_and_neutralises_formulas() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd()"), "'=cmd()");
    }

    #[test]
    fn csv_has_a_header_and_one_line_per_row() {
        let rows = chain();
        let csv = to_csv(&rows[2..], &columns(None).unwrap());
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("id,ts,"));
        assert!(lines[0].ends_with(",payload_sha256,prev_hash,hash"));
        assert!(lines[1].starts_with(
            "3,2026-10-03T12:00:00.000Z,6f1c1b7e-58f0-4a53-9a43-2d2e8b2f0c11,prompt_in,llm,console-chat,anna@example.com,,,redact,,pii.email:redact pii.phone:redact,0,0.0,"
        ));
        assert!(lines[1].ends_with(&format!(
            ",{},{},{}",
            "ab".repeat(32),
            rows[1].chain.hash,
            rows[2].chain.hash
        )));
    }

    #[test]
    fn include_selects_groups_and_keeps_the_event_columns() {
        assert_eq!(names(None).len(), COLUMNS.len());
        assert_eq!(
            names(Some("")),
            ["id", "ts", "trace_id", "hook", "channel", "verdict"],
            "an empty list asks for the event columns only"
        );
        assert_eq!(
            names(Some("identity")),
            [
                "id",
                "ts",
                "trace_id",
                "hook",
                "channel",
                "principal",
                "user",
                "verdict"
            ]
        );
        assert_eq!(
            names(Some("usage, performance")),
            [
                "id", "ts", "trace_id", "hook", "channel", "verdict", "tokens", "cost_usd",
                "latency"
            ]
        );
        assert!(columns(Some("identity,prompts")).is_err());
    }

    #[test]
    fn integrity_brings_the_detections_it_hashes() {
        let chosen = names(Some("integrity"));
        assert!(chosen.contains(&"controls"), "{chosen:?}");
        assert!(chosen.ends_with(&["payload_sha256", "prev_hash", "hash"]));
    }

    #[test]
    fn json_holds_only_the_chosen_columns_with_typed_values() {
        let json = to_json(&chain()[1..2], &columns(Some("detections")).unwrap());
        let mut keys: Vec<&str> = json[0].keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "channel", "controls", "hook", "id", "trace_id", "ts", "verdict"
            ]
        );
        assert_eq!(json[0]["id"], serde_json::json!(2));
        assert_eq!(
            json[0]["controls"],
            serde_json::json!([["secret.aws-access-key", "block"]])
        );
    }

    #[test]
    fn filters_outside_the_known_values_are_refused() {
        assert!(one_of("verdict", Some("blocked"), VERDICTS).is_err());
        assert!(one_of("verdict", Some("block"), VERDICTS).is_ok());
        assert!(one_of("verdict", None, VERDICTS).is_ok());
    }

    #[test]
    fn an_untouched_export_verifies_as_one_segment() {
        assert_eq!(
            check(&chain()),
            ExportReport {
                rows: 3,
                broken: vec![],
                segments: 1
            }
        );
    }

    #[test]
    fn an_edited_verdict_or_detection_breaks_its_row() {
        let mut rows = chain();
        rows[1].chain.verdict = "allow".into(); // hide a block
        rows[2].chain.controls.0.pop(); // drop a detection
        assert_eq!(check(&rows).broken, vec![2, 3]);
    }

    #[test]
    fn a_dropped_row_is_a_gap_not_a_break() {
        // Filtered exports skip rows; the rows that remain still verify.
        let rows = chain();
        assert_eq!(
            check(&[rows[0].clone(), rows[2].clone()]),
            ExportReport {
                rows: 2,
                broken: vec![],
                segments: 2
            }
        );
    }

    #[test]
    fn a_forged_hash_does_not_verify() {
        let mut rows = chain();
        rows[1].chain.verdict = "allow".into();
        rows[1].chain.hash = "00".repeat(32); // the forger cannot reproduce it
        let report = check(&rows);
        assert_eq!(report.broken, vec![2]);
        assert_eq!(
            report.segments, 2,
            "row 3 no longer links to the forged row 2"
        );
    }

    #[test]
    fn a_json_export_with_integrity_verifies_even_when_narrowed() {
        for include in [None, Some("integrity")] {
            let back = exported(&chain(), include).unwrap();
            assert_eq!(
                verify_export(&back).broken,
                Vec::<i64>::new(),
                "{include:?}"
            );
        }
    }

    #[test]
    fn an_export_without_integrity_cannot_be_verified() {
        assert!(exported(&chain(), Some("identity,detections")).is_err());
    }
}

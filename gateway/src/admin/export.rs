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
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{Access, refusal};
use crate::audit::{chain_hash, hex};
use crate::state::AppState;

const MAX_ROWS: i64 = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    #[serde(default)]
    format: Option<String>,
    /// RFC 3339 timestamps; `from` inclusive, `to` exclusive.
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
    /// Comma-separated column groups; every group when absent.
    #[serde(default)]
    include: Option<String>,
}

/// Optional column groups. The event columns (id, ts, trace_id, hook,
/// channel, verdict) are always exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Identity,
    Target,
    Detections,
    Usage,
    Performance,
    Policy,
    Integrity,
}

impl Group {
    pub const ALL: [Self; 7] = [
        Self::Identity,
        Self::Target,
        Self::Detections,
        Self::Usage,
        Self::Performance,
        Self::Policy,
        Self::Integrity,
    ];

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.name() == name)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Target => "target",
            Self::Detections => "detections",
            Self::Usage => "usage",
            Self::Performance => "performance",
            Self::Policy => "policy",
            Self::Integrity => "integrity",
        }
    }
}

/// Every column in export order, with the group that switches it on.
const COLUMNS: [(&str, Option<Group>); 18] = [
    ("id", None),
    ("ts", None),
    ("trace_id", None),
    ("hook", None),
    ("channel", None),
    ("principal", Some(Group::Identity)),
    ("user", Some(Group::Identity)),
    ("model", Some(Group::Target)),
    ("tool", Some(Group::Target)),
    ("verdict", None),
    ("policy_version", Some(Group::Policy)),
    ("controls", Some(Group::Detections)),
    ("tokens", Some(Group::Usage)),
    ("cost_usd", Some(Group::Usage)),
    ("latency", Some(Group::Performance)),
    ("payload_sha256", Some(Group::Integrity)),
    ("prev_hash", Some(Group::Integrity)),
    ("hash", Some(Group::Integrity)),
];

/// The columns an `include` list selects. Integrity brings detections with it:
/// the hash covers them, so a file without them could not be verified.
pub fn columns(include: Option<&str>) -> Result<Vec<&'static str>, String> {
    let mut groups = match include.map(str::trim) {
        None | Some("") => Group::ALL.to_vec(),
        Some(list) => list
            .split(',')
            .map(|name| {
                Group::parse(name.trim()).ok_or_else(|| format!("unknown column group {name:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    if groups.contains(&Group::Integrity) && !groups.contains(&Group::Detections) {
        groups.push(Group::Detections);
    }
    Ok(COLUMNS
        .iter()
        .filter(|(_, group)| group.is_none_or(|g| groups.contains(&g)))
        .map(|(name, _)| *name)
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Row {
    pub id: i64,
    pub ts: String,
    pub trace_id: String,
    pub hook: String,
    pub channel: String,
    pub principal: Option<String>,
    pub user: Option<String>,
    pub model: Option<String>,
    pub tool: Option<String>,
    pub verdict: String,
    pub policy_version: Option<String>,
    /// `control_id:action` pairs in detection order, space-separated.
    pub controls: String,
    pub tokens: i64,
    pub cost_usd: f64,
    pub latency: String,
    /// Hex. Together with the fields the chain covers, these let the export be
    /// verified on its own.
    pub payload_sha256: Option<String>,
    pub prev_hash: String,
    pub hash: String,
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
    let columns = match columns(filters.include.as_deref()) {
        Ok(columns) => columns,
        Err(message) => return refusal(StatusCode::BAD_REQUEST, "invalid_include", &message),
    };
    let csv = match filters.format.as_deref() {
        None | Some("json") => false,
        Some("csv") => true,
        Some(other) => {
            return refusal(
                StatusCode::BAD_REQUEST,
                "invalid_format",
                &format!("format {other:?} is not json or csv"),
            );
        }
    };

    let rows = sqlx::query_as::<_, Row>(
        "select e.id,
                to_char(e.ts at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') as ts,
                e.trace_id::text as trace_id, e.hook::text as hook, e.channel::text as channel,
                p.slug as principal, e.end_user as \"user\", e.model, e.tool,
                e.verdict::text as verdict, pv.sha256 as policy_version,
                coalesce((select string_agg(d.control_id || ':' || d.action::text, ' ' order by d.id)
                          from detections d where d.event_id = e.id), '') as controls,
                coalesce((select sum(u.prompt_tokens + u.completion_tokens) from usage u
                          where u.event_id = e.id), 0)::bigint as tokens,
                coalesce((select sum(u.cost_usd) from usage u where u.event_id = e.id), 0)::float8 as cost_usd,
                e.latency::text as latency,
                e.payload_sha256,
                encode(coalesce(e.prev_hash, ''::bytea), 'hex') as prev_hash,
                encode(e.hash, 'hex') as hash
         from events e
         left join principals p on p.id = e.principal_id
         left join policy_versions pv on pv.id = e.policy_version_id
         where ($1::text is null or e.ts >= $1::text::timestamptz)
           and ($2::text is null or e.ts < $2::text::timestamptz)
           and ($3::text is null or p.slug = $3)
           and ($7::text is null or e.end_user = $7)
           and ($4::text is null or exists (
                 select 1 from detections d where d.event_id = e.id and d.control_id = $4))
           and ($5::text is null or e.verdict::text = $5 or exists (
                 select 1 from detections d where d.event_id = e.id and d.action::text = $5))
           and ($8::text is null or e.verdict::text = $8)
           and ($9::text is null or e.channel::text = $9)
         order by e.id
         limit $6",
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
    .fetch_all(state.db())
    .await;

    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "audit export failed");
            return refusal(
                StatusCode::BAD_REQUEST,
                "invalid_filter",
                "the export query failed; check the timestamp filters",
            );
        }
    };

    if csv {
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
    } else {
        Json(to_json(&rows, &columns)).into_response()
    }
}

/// Rows as JSON objects holding only the selected columns, values typed.
pub fn to_json(rows: &[Row], columns: &[&str]) -> Vec<serde_json::Map<String, serde_json::Value>> {
    rows.iter()
        .map(|row| {
            let serde_json::Value::Object(mut object) =
                serde_json::to_value(row).unwrap_or_default()
            else {
                return serde_json::Map::new();
            };
            object.retain(|key, _| columns.contains(&key.as_str()));
            object
        })
        .collect()
}

pub fn to_csv(rows: &[Row], columns: &[&str]) -> String {
    let mut out = columns.join(",");
    out.push('\n');
    for r in rows {
        let line: Vec<String> = columns
            .iter()
            .map(|name| csv_field(&cell(r, name)))
            .collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

fn cell(r: &Row, column: &str) -> String {
    match column {
        "id" => r.id.to_string(),
        "ts" => r.ts.clone(),
        "trace_id" => r.trace_id.clone(),
        "hook" => r.hook.clone(),
        "channel" => r.channel.clone(),
        "principal" => r.principal.clone().unwrap_or_default(),
        "user" => r.user.clone().unwrap_or_default(),
        "model" => r.model.clone().unwrap_or_default(),
        "tool" => r.tool.clone().unwrap_or_default(),
        "verdict" => r.verdict.clone(),
        "policy_version" => r.policy_version.clone().unwrap_or_default(),
        "controls" => r.controls.clone(),
        "tokens" => r.tokens.to_string(),
        "cost_usd" => format!("{:.6}", r.cost_usd),
        "latency" => r.latency.clone(),
        "payload_sha256" => r.payload_sha256.clone().unwrap_or_default(),
        "prev_hash" => r.prev_hash.clone(),
        "hash" => r.hash.clone(),
        _ => String::new(),
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

/// The fields of an exported row the hash chain covers: all the verifier
/// reads, so an export narrowed with `include` still verifies as long as it
/// has the integrity group.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainRow {
    pub id: i64,
    pub trace_id: String,
    pub hook: String,
    pub verdict: String,
    pub controls: String,
    pub payload_sha256: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

impl From<&Row> for ChainRow {
    fn from(row: &Row) -> Self {
        Self {
            id: row.id,
            trace_id: row.trace_id.clone(),
            hook: row.hook.clone(),
            verdict: row.verdict.clone(),
            controls: row.controls.clone(),
            payload_sha256: row.payload_sha256.clone(),
            prev_hash: row.prev_hash.clone(),
            hash: row.hash.clone(),
        }
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
        if recomputed(row).as_deref() != Some(row.hash.as_str()) {
            report.broken.push(row.id);
        }
        previous = Some(row);
    }
    report
}

fn recomputed(row: &ChainRow) -> Option<String> {
    let trace_id = Uuid::parse_str(&row.trace_id).ok()?;
    let prev = unhex(&row.prev_hash)?;
    let detections: Vec<(&str, &str)> = row
        .controls
        .split_whitespace()
        .map(|pair| pair.rsplit_once(':'))
        .collect::<Option<_>>()?;
    Some(hex(&chain_hash(
        &prev,
        trace_id,
        &row.hook,
        &row.verdict,
        row.payload_sha256.as_deref().unwrap_or_default(),
        &detections,
    )))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, prev_hash: &str, verdict: &str, controls: &str) -> Row {
        let mut row = Row {
            id,
            ts: "2026-10-03T12:00:00.000Z".into(),
            trace_id: "6f1c1b7e-58f0-4a53-9a43-2d2e8b2f0c11".into(),
            hook: "prompt_in".into(),
            channel: "llm".into(),
            principal: Some("console-chat".into()),
            user: Some("anna@example.com".into()),
            model: None,
            tool: None,
            verdict: verdict.into(),
            policy_version: None,
            controls: controls.into(),
            tokens: 0,
            cost_usd: 0.0,
            latency: r#"{"deterministic_us": 12}"#.into(),
            payload_sha256: Some("ab".repeat(32)),
            prev_hash: prev_hash.into(),
            hash: String::new(),
        };
        row.hash = recomputed(&ChainRow::from(&row)).expect("a well-formed row");
        row
    }

    /// Three linked events, as the gateway writes them.
    fn chain() -> Vec<Row> {
        let first = row(1, "", "allow", "");
        let second = row(2, &first.hash, "block", "secret.aws-access-key:block");
        let third = row(
            3,
            &second.hash,
            "redact",
            "pii.email:redact pii.phone:redact",
        );
        vec![first, second, third]
    }

    fn check(rows: &[Row]) -> ExportReport {
        verify_export(&rows.iter().map(ChainRow::from).collect::<Vec<_>>())
    }

    fn all() -> Vec<&'static str> {
        columns(None).unwrap()
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
        let csv = to_csv(&rows[1..2], &all());
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("id,ts,"));
        assert!(lines[0].ends_with(",payload_sha256,prev_hash,hash"));
        assert!(lines[1].starts_with(
            "2,2026-10-03T12:00:00.000Z,6f1c1b7e-58f0-4a53-9a43-2d2e8b2f0c11,prompt_in,llm,console-chat,anna@example.com,,,block,"
        ));
        assert!(lines[1].ends_with(&format!(
            ",{},{},{}",
            "ab".repeat(32),
            rows[0].hash,
            rows[1].hash
        )));
    }

    #[test]
    fn no_include_means_every_column() {
        assert_eq!(all().len(), COLUMNS.len());
        assert_eq!(columns(Some("")).unwrap(), all());
    }

    #[test]
    fn include_keeps_the_event_columns_and_the_chosen_groups() {
        assert_eq!(
            columns(Some("identity")).unwrap(),
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
            columns(Some("usage, performance")).unwrap(),
            [
                "id", "ts", "trace_id", "hook", "channel", "verdict", "tokens", "cost_usd",
                "latency"
            ]
        );
    }

    #[test]
    fn integrity_brings_the_detections_it_hashes() {
        let chosen = columns(Some("integrity")).unwrap();
        assert!(chosen.contains(&"controls"), "{chosen:?}");
        assert!(chosen.ends_with(&["payload_sha256", "prev_hash", "hash"]));
    }

    #[test]
    fn an_unknown_group_is_refused() {
        assert!(columns(Some("identity,prompts")).is_err());
    }

    #[test]
    fn narrowed_csv_and_json_hold_only_the_chosen_columns() {
        let rows = chain();
        let chosen = columns(Some("identity")).unwrap();
        assert_eq!(
            to_csv(&rows[..1], &chosen).lines().next(),
            Some("id,ts,trace_id,hook,channel,principal,user,verdict")
        );
        let json = to_json(&rows[..1], &chosen);
        let mut keys: Vec<&str> = json[0].keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "channel",
                "hook",
                "id",
                "principal",
                "trace_id",
                "ts",
                "user",
                "verdict"
            ]
        );
        assert_eq!(
            json[0]["id"],
            serde_json::json!(1),
            "values keep their JSON types"
        );
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
    fn an_edited_verdict_breaks_its_row() {
        let mut rows = chain();
        rows[1].verdict = "allow".into(); // hide a block
        assert_eq!(check(&rows).broken, vec![2]);
    }

    #[test]
    fn a_removed_detection_breaks_its_row() {
        let mut rows = chain();
        rows[2].controls = "pii.email:redact".into();
        assert_eq!(check(&rows).broken, vec![3]);
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
        rows[1].verdict = "allow".into();
        rows[1].hash = "00".repeat(32); // the forger cannot reproduce it
        let report = check(&rows);
        assert_eq!(report.broken, vec![2]);
        assert_eq!(
            report.segments, 2,
            "row 3 no longer links to the forged row 2"
        );
    }

    #[test]
    fn a_narrowed_json_export_still_verifies() {
        let chosen = columns(Some("integrity")).unwrap();
        let json = serde_json::to_string(&to_json(&chain(), &chosen)).unwrap();
        let back: Vec<ChainRow> = serde_json::from_str(&json).unwrap();
        assert_eq!(verify_export(&back).broken, Vec::<i64>::new());
    }

    #[test]
    fn an_export_without_integrity_cannot_be_verified() {
        let chosen = columns(Some("identity,detections")).unwrap();
        let json = serde_json::to_string(&to_json(&chain(), &chosen)).unwrap();
        assert!(serde_json::from_str::<Vec<ChainRow>>(&json).is_err());
    }
}

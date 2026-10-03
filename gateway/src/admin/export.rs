//! Audit log export for security teams (§4.5): JSON or CSV, filtered by time
//! range, identity, control, verdict, channel and action.
//!
//! Every row carries its hash-chain fields (`payload_sha256`, `prev_hash`,
//! `hash`), so an export is evidence an auditor can check without database
//! access: `verify-audit --file export.json` runs [`verify_export`] over it.

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
            to_csv(&rows),
        )
            .into_response()
    } else {
        Json(rows).into_response()
    }
}

pub fn to_csv(rows: &[Row]) -> String {
    let mut out = String::from(
        "id,ts,trace_id,hook,channel,principal,user,model,tool,verdict,policy_version,controls,tokens,cost_usd,latency,payload_sha256,prev_hash,hash\n",
    );
    for r in rows {
        let fields = [
            r.id.to_string(),
            r.ts.clone(),
            r.trace_id.clone(),
            r.hook.clone(),
            r.channel.clone(),
            r.principal.clone().unwrap_or_default(),
            r.user.clone().unwrap_or_default(),
            r.model.clone().unwrap_or_default(),
            r.tool.clone().unwrap_or_default(),
            r.verdict.clone(),
            r.policy_version.clone().unwrap_or_default(),
            r.controls.clone(),
            r.tokens.to_string(),
            format!("{:.6}", r.cost_usd),
            r.latency.clone(),
            r.payload_sha256.clone().unwrap_or_default(),
            r.prev_hash.clone(),
            r.hash.clone(),
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
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
pub fn verify_export(rows: &[Row]) -> ExportReport {
    let mut report = ExportReport {
        rows: rows.len(),
        ..ExportReport::default()
    };
    let mut previous: Option<&Row> = None;

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

fn recomputed(row: &Row) -> Option<String> {
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
        row.hash = recomputed(&row).expect("a well-formed row");
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
        let csv = to_csv(&rows[1..2]);
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
    fn an_untouched_export_verifies_as_one_segment() {
        let report = verify_export(&chain());
        assert_eq!(
            report,
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
        assert_eq!(verify_export(&rows).broken, vec![2]);
    }

    #[test]
    fn a_removed_detection_breaks_its_row() {
        let mut rows = chain();
        rows[2].controls = "pii.email:redact".into();
        assert_eq!(verify_export(&rows).broken, vec![3]);
    }

    #[test]
    fn a_dropped_row_is_a_gap_not_a_break() {
        // Filtered exports skip rows; the rows that remain still verify.
        let rows = chain();
        let report = verify_export(&[rows[0].clone(), rows[2].clone()]);
        assert_eq!(
            report,
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
        let report = verify_export(&rows);
        assert_eq!(report.broken, vec![2]);
        assert_eq!(
            report.segments, 2,
            "row 3 no longer links to the forged row 2"
        );
    }

    #[test]
    fn json_round_trips_into_the_verifier() {
        let json = serde_json::to_string(&chain()).unwrap();
        let back: Vec<Row> = serde_json::from_str(&json).unwrap();
        assert_eq!(verify_export(&back).broken, Vec::<i64>::new());
    }
}

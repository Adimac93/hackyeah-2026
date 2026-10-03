//! Audit log export for security teams (§4.5): JSON or CSV, filtered by time
//! range, identity, control and action.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::auth::{Access, refusal};
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
    /// Control id that fired on the event.
    #[serde(default)]
    control: Option<String>,
    /// The event's verdict or any of its detections' actions:
    /// allow | flag | redact | block.
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub id: i64,
    pub ts: String,
    pub trace_id: String,
    pub hook: String,
    pub channel: String,
    pub principal: Option<String>,
    pub model: Option<String>,
    pub tool: Option<String>,
    pub verdict: String,
    pub policy_version: Option<String>,
    pub controls: String,
    pub tokens: i64,
    pub cost_usd: f64,
    pub latency: String,
}

pub async fn export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filters): Query<Filters>,
) -> Response {
    if let Err(response) = state.admins.require(state.db(), &headers, Access::Read).await {
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

    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            String,
            i64,
            f64,
            String,
        ),
    >(
        "select e.id,
                to_char(e.ts at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
                e.trace_id::text, e.hook::text, e.channel::text, p.slug, e.model, e.tool,
                e.verdict::text, pv.sha256,
                coalesce((select string_agg(d.control_id || ':' || d.action::text, ' ' order by d.id)
                          from detections d where d.event_id = e.id), ''),
                coalesce((select sum(u.prompt_tokens + u.completion_tokens) from usage u
                          where u.event_id = e.id), 0)::bigint,
                coalesce((select sum(u.cost_usd) from usage u where u.event_id = e.id), 0)::float8,
                e.latency::text
         from events e
         left join principals p on p.id = e.principal_id
         left join policy_versions pv on pv.id = e.policy_version_id
         where ($1::text is null or e.ts >= $1::text::timestamptz)
           and ($2::text is null or e.ts < $2::text::timestamptz)
           and ($3::text is null or p.slug = $3)
           and ($4::text is null or exists (
                 select 1 from detections d where d.event_id = e.id and d.control_id = $4))
           and ($5::text is null or e.verdict::text = $5 or exists (
                 select 1 from detections d where d.event_id = e.id and d.action::text = $5))
         order by e.id
         limit $6",
    )
    .bind(&filters.from)
    .bind(&filters.to)
    .bind(&filters.principal)
    .bind(&filters.control)
    .bind(&filters.action)
    .bind(filters.limit.unwrap_or(MAX_ROWS).clamp(1, MAX_ROWS))
    .fetch_all(state.db())
    .await;

    let rows: Vec<Row> = match rows {
        Ok(rows) => rows
            .into_iter()
            .map(|r| Row {
                id: r.0,
                ts: r.1,
                trace_id: r.2,
                hook: r.3,
                channel: r.4,
                principal: r.5,
                model: r.6,
                tool: r.7,
                verdict: r.8,
                policy_version: r.9,
                controls: r.10,
                tokens: r.11,
                cost_usd: r.12,
                latency: r.13,
            })
            .collect(),
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
        "id,ts,trace_id,hook,channel,principal,model,tool,verdict,policy_version,controls,tokens,cost_usd,latency\n",
    );
    for r in rows {
        let fields = [
            r.id.to_string(),
            r.ts.clone(),
            r.trace_id.clone(),
            r.hook.clone(),
            r.channel.clone(),
            r.principal.clone().unwrap_or_default(),
            r.model.clone().unwrap_or_default(),
            r.tool.clone().unwrap_or_default(),
            r.verdict.clone(),
            r.policy_version.clone().unwrap_or_default(),
            r.controls.clone(),
            r.tokens.to_string(),
            format!("{:.6}", r.cost_usd),
            r.latency.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_and_neutralises_formulas() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd()"), "'=cmd()");
    }

    #[test]
    fn csv_has_a_header_and_one_line_per_row() {
        let row = Row {
            id: 1,
            ts: "2026-10-03T12:00:00.000Z".into(),
            trace_id: "t".into(),
            hook: "prompt_in".into(),
            channel: "llm".into(),
            principal: Some("demo-agent".into()),
            model: None,
            tool: None,
            verdict: "block".into(),
            policy_version: None,
            controls: "secret.aws-access-key:block".into(),
            tokens: 0,
            cost_usd: 0.0,
            latency: r#"{"deterministic_us": 12}"#.into(),
        };
        let csv = to_csv(&[row]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("id,ts,"));
        assert!(lines[1].starts_with("1,2026-10-03T12:00:00.000Z,t,prompt_in,llm,demo-agent,,,block,"));
        assert!(lines[1].ends_with(r#""{""deterministic_us"": 12}""#));
    }
}

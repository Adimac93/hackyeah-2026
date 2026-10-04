# 3 · Reporting

## Dashboard

The SecOps console (Next.js, [`web/`](../web)) reads the audit data through the
Supabase Data API as the signed-in security-team member. It has no write path to
gateway tables; it changes gateway state only through the gateway's admin API.

![Overview — security posture, last 24 h](screenshots/overview.png)

![Activity — every intercepted request with its verdict](screenshots/activity.png)

![Event detail — detections, policy version, per-tier latency, hash-chain integrity](screenshots/event-detail.png)

![Controls & policies — the live catalog, editable in place](screenshots/controls.png)

![Gateway — health, 24 h metrics, audit-chain status](screenshots/gateway.png)

| View | For | Shows |
|---|---|---|
| **Overview** | management | requests, blocked, intervention rate, p95 overhead; high-severity interventions; highest-risk users; top controls; latest interventions |
| **Activity** | security team | every intercepted request, live, filterable by user / status / verdict; per-event detections, policy version, latency per tier, integrity (prev / hash / payload); export to PDF |
| **Gateway** | security team / ops | live health of gateway and audit database, controls enforced, events, blocked, deterministic p50/p95, semantic p50/p95, budgets, audit-chain status |
| **MCP** | security team | tool calls, tool results, agents' access requests and their outcome |
| **Controls & policies** | security team | active catalog (1:1 with the TOML), per-control editor, `.toml` upload, budgets, resource grants, policy versions with diffs, attack signatures |
| **User risk** | security team | risk score per identity against the escalate / block thresholds |
| **Approvals** | security team | live popup when an agent asks for a tool or table it wasn't granted |

## Implemented metrics

### Security posture

| Metric | Source |
|---|---|
| Total requests, allowed / redacted / blocked counts (24 h or any window) | `events.verdict` |
| Block rate / intervention rate (%) | blocked (+ redacted) ÷ events |
| Detections total and **per control** (id, tier, severity, hits) | `detections` |
| Verdicts per hook (`prompt_in`, `response_out`, `tool_call`, `tool_result`) | `gateway_verdicts_total{hook,verdict}` |
| High-severity interventions (time, hook, channel, principal, tool, control, evidence excerpt — never the secret itself) | `detections` ⨝ `events` |
| Attack-signature hits per feed signature | `attack_history`, `attack_signatures` |
| Per-identity risk score and status (ok / escalated / blocked) | `GET /admin/risk` |
| Highest-risk users / per-principal activity (events, blocked, tokens) | `events` grouped by principal |

### Budget and resource consumption

| Metric | Source |
|---|---|
| Tokens used (prompt + completion) per window | `usage` |
| Cost in USD per model, from the catalog's `[pricing]` | `usage.cost_usd` |
| Budget usage % per budget row (global / user / model; tokens, USD, requests, concurrency) | `budgets` + `usage` |
| Budget breaches (hard = blocked, soft = recorded) | `detections` with `budget.*` ids |
| Runaway-agent stops (tool-call floods, identical-call loops, depth) | `detections` with `mcp.runaway` |

### Performance and health

| Metric | Source |
|---|---|
| Deterministic tier p50 / p95 (µs) | `events.latency.deterministic_us`, `gateway_stage_latency_us{stage="deterministic"}` |
| Semantic tier p50 / p95 (µs) | `events.latency.semantic_us`, `gateway_stage_latency_us{stage="semantic"}` |
| Upstream LLM / MCP latency and total overhead | `gateway_stage_latency_us{stage="upstream"\|"mcp_upstream"\|"total"}` |
| Escalation rate (% of events that reached the semantic tier) | `GET /metrics` |
| Semantic queue depth | `gateway_semantic_queue_depth` |
| Dependency calls and errors (LLM judge, upstream) | `gateway_dependency_calls_total{dependency,outcome}` |

### Integrity and governance

| Metric | Source |
|---|---|
| Audit chain status: events checked, intact, first broken event | `GET /metrics`, `just verify-audit` |
| Active policy version, version history with diffs, rejected uploads | `policy_versions` |

## Exports

| Export | How |
|---|---|
| Audit log, JSON or CSV, filtered by time / identity / control / action (CSV formula-injection safe) | `GET /admin/audit/export` |
| Activity view to PDF | console → Activity → **Export PDF** |
| Management / security PDF report for a date range (same queries as the dashboard) | `just report` ([`report/report.typ`](../report/report.typ)) |
| Prometheus scrape | `GET /metrics/prometheus` |

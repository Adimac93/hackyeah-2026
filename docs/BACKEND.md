# Security backend / gateway — specifications

Specs for LLM prompts that build the security backend (gateway) of the AI Control Layer.
Sources of truth, in priority order: `docs/task.md` (challenge requirements, always wins),
the team architecture diagram (summarized in the first spec below), `docs/prior-art.md`
(component choices). Section references like §4.3 point to `docs/task.md`.

Security gateway (overall) specification:
- The gateway is the security backend and the central component of the AI Control Layer: a smart intermediary that intercepts and governs every interaction between users, agents, LLMs, MCP services and organizational resources (§2, §3.1).
- It hosts the Centralized Policy Engine and groups these modules: data access control, budget and resource governance, malicious patterns detection with attack history, monitoring.
- Semantic analysis is performed on the interface → analysis → LLM path. It's mentioned in the security gateway, because it uses policies/data used for checking from the gateway. It is async by default and runs synchronously only when escalated (see the semantic guardrails spec).
- Request flow from the architecture diagram: user → provisioned interface / user dashboard → deterministic guardrails (security proxy) → "is secure" decision → LLM (allowed) or prompt helper (rejected); LLM ↔ MCP ↔ gateway ↔ resources (database, files); LLM response → back through the deterministic guardrails → user.
- The gateway is the only component allowed to touch resources (database, files); LLMs, agents and MCP servers reach them exclusively through it.
- The gateway receives the caller's identity directly from the user/interface side as a per-identity API key (`Authorization: Bearer`), so every request is evaluated against a known, authenticated identity. A self-declared identity header is never trusted on its own.
- Users, not principals, are what budgets, risk and activity are kept for. An application that serves many people through one key (the console chat) is a principal with `delegates_users`; it names the signed-in person in `X-On-Behalf-Of`, and that name is trusted only because the key is. Any other principal sending the header is refused (`403 delegation_refused`). A caller that delegates nothing is its own user, named by its slug.
- It must be integrable by developers with minimal effort for agent-to-agent, app-to-agent, agent-to-MCP and agent-to-model traffic (§3.1) — e.g. an OpenAI-compatible HTTP endpoint and an MCP-proxy endpoint, so existing clients only change a base URL.
- Implements a hybrid defense: fast deterministic (non-AI, full-text search instead) controls on the synchronous path, and AI-based semantic controls where they add value (§2, §4.2) — asynchronous by default, synchronous only when a deterministic control escalates the request.
- Everything must run locally (`dev`) or on Google Cloud platform (`prod`) - depending on the `ENVIRONMENT` config variable (`dev`, `prod`).
- `ENVIRONMENT` sets defaults and strictness, never which controls are enforced:
  - Both environments refuse to start without `DATABASE_URL`: the active policy, the identities, their grants and the budgets all live in the database, so a gateway without one has nothing to enforce.
  - `dev` logs human-readable text, allows any browser origin unless `CORS_ORIGINS` says otherwise, and by default uses mocks instead of models: a mock chat upstream (`UPSTREAM_URL=mock`) and a deterministic mock semantic judge (`OLLAMA_URL=mock`), so no Ollama is needed.
  - `prod` refuses to start with a mock upstream or mock judge (a fabricated verdict has no place in a production control). It logs JSON and allows only the browser origins listed in `CORS_ORIGINS`. The semantic judge is the Ollama at `OLLAMA_URL`; the chat upstream is any OpenAI-compatible server set by `UPSTREAM_URL`. `just deploy` targets Google Cloud Run.
  - Detector availability is not checked at startup in either environment; an unavailable detector is resolved at request time by the control's `fail_mode`.
- Stack is decided - look for project context to discover the stack.
- Coverage should be reviewed against OWASP Top 10 for LLM Applications and OWASP agentic AI threats (§1 note): prompt injection, sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption.

Centralized policy engine and configuration file specification:
- A single TOML control catalog is the only source of truth for all controls (§4.1); the gateway parses it and distributes the effective policy to the security proxy.
- The catalog lives in the database for its entire life (`policy_versions`, exactly one row `active`). The gateway never reads a catalog from disk at runtime. The only way to change it is to upload a complete TOML catalog — and optionally the attack-signature feed — through the authenticated gateway admin API.
- First start: when the database holds no active version, the gateway seeds it with the built-in sample catalog and feed (`policy/control-catalog.toml`, `policy/signatures.toml`, compiled into the binary) and activates that. Editing those files changes nothing until they are uploaded.
- Every gateway instance polls the active version (every 5 s) and swaps to a newer one without a restart, so an upload applies to the whole fleet; judges upload an edited catalog during evaluation and observe the effect (§6).
- The configuration file is in the TOML format.
- The catalog defines: list of controls with `enabled` flag, action per control, failure mode per control (`closed` or `open`, falling back to a file-wide default), sensitivity thresholds (e.g. adherence % or classifier score cutoffs), the global model allow/deny list, a per-model pricing table, the attack-history risk thresholds, runaway-agent limits, MCP servers (with pinned tool hashes) and resource access rules.
- Actions: `allow` (record only), `flag` (record and mark the request suspicious, which escalates it to the semantic tier), `redact` (replace the match and continue), `block` (stop the request).
- Identity and grants live in the database, not the catalog: `principals` holds each identity, the hash of its API key, its `allowed_models` / `allowed_tools` and whether it `delegates_users`. Grants are deny-by-default: an empty list grants nothing. A delegated user inherits the delegating principal's grants and never more.
- Budgets live in the database (`budgets`), not the catalog, are kept per user (not per principal), and are edited through the gateway admin API.
- Unknown keys are a validation error, so a typo such as `enabeld = false` is rejected instead of silently leaving the control on.
- Supports named strictness profiles (e.g. `permissive`, `balanced`, `strict`) that set defaults for all controls; individual controls can override the profile (§3.2).
- The console edits the catalog as text: its controls-and-policies page shows the active version's `catalog_toml` (read through the Data API) in a text area, and saving sends the whole edited text to `POST /admin/policy` with the signed-in user's Supabase access token. There is no partial update; the uploaded text is the next version.
- `GET /policy` describes what is enforced for the console's controls table: every control (id, kind, hooks, severity, action), the model lists, the risk and runaway limits, the MCP servers and the resource access grants (`[resources]`: identity → tables). Budgets come from the `budgets` table.
- Every upload is validated against the schema before it is stored; an invalid upload is rejected with the error returned to the uploader, recorded in `admin_actions`, and the last valid policy stays active.
- Every accepted upload produces a policy version id and a human-readable control-level diff (controls added, removed, and changed field by field), stored with the version and the uploader, and visible in the admin dashboard.
- Each decision in the audit log references the policy version and control id that produced it.
- Ship a documented sample configuration demonstrating different strictness levels (§3.2); budget rules are demonstrated by the seeded `budgets` rows.
- Removing a control from an uploaded catalog disables it as soon as the version activates; the self-testing suite must prove this.

Policy settings flow:

```
startup ─► select active policy_versions row
            ├─ found ─► compile catalog_toml + signatures_toml ─► active policy
            └─ none  ─► insert the built-in sample as active ─► active policy
security admin (Supabase session, team role admin) edits the TOML in the console
  POST /admin/policy {catalog_toml, signatures_toml?}
    ─► compile + validate ── invalid ─► 422, admin_actions(rejected); active unchanged
    ─► control-level diff against the active version
    ─► one transaction: deactivate old, insert new version (text, diff, uploader), admin_actions(accepted)
    ─► swap in this instance; mirror signatures into attack_signatures
other instances ─► poll every 5 s ─► compile + swap
every decision ─► events.policy_version_id
```

Deterministic guardrails (security proxy) specification:
- The security proxy sits between the provisioned interface and the LLM; all deterministic checks happen here, on both the prompt (input) and the LLM response (output) (§4.2.1).
- Input checks: PII and secret detection via pattern matching (emails, phone numbers, national IDs such as PESEL, IBANs, card numbers with Luhn check, API keys, private keys, JWTs, passwords in connection strings), known prompt-injection and jailbreak patterns, encoded or obfuscated payloads (base64, unicode homoglyphs, invisible characters), request size limits, authentication and authorization checks.
- Output checks: redaction of PII and secrets in responses, detection of system prompt leakage, detection of dangerous content handed to downstream systems (shell commands, SQL, HTML/JS) to prevent improper output handling.
- Historical attack mitigation patterns (see the malicious patterns detection spec) are applied on both input and output paths.
- Action per finding follows the policy: `block` stops the request, `redact` replaces the match with a placeholder naming the control (e.g. `[REDACTED:pii.email]`) and continues, `flag` records it and escalates the request to the semantic tier, `allow` only records it.
- Produces a verdict (`allow`, `redact`, `block`) with the list of triggered control ids and a risk score that drives the "is secure" decision.
- A refusal says which check stopped it, so the interface can tell the user their prompt does not meet the deterministic requirements: `error.stage` is `deterministic` (a pattern control), `semantic` (an escalated semantic control) or `access` (model grant, budget, risk history), and `error.hook` is `prompt_in` or `response_out`. Detection internals (patterns, scores, thresholds) are never returned; `error.risk_score` is only what the request added to its user's attack history (`x_control_layer.<hook>.risk_score` on an answer, `error.data.risk_score` on a refused MCP call).
- Streaming (`"stream": true` on `/v1/chat/completions`): `prompt_in` runs as usual, then the upstream streams and the caller receives OpenAI `chat.completion.chunk` events over SSE. Text is released only after the deterministic `response_out` controls have run over everything so far, and only once it is 256 bytes behind the newest token, so a match still being written (an address, a key) is redacted or blocked before any of it leaves. The complete answer is then policed like a buffered one (both tiers, audit, usage); the last event is authoritative: a final chunk carrying `usage` and `x_control_layer`, or `{ error, trace_id }` with the same error object as a buffered refusal, which tells the client to retract what it showed. Refusals before the first byte (prompt_in, budgets, upstream down) stay plain JSON responses.
- Must be fast: target low single-digit milliseconds per check stage, with per-stage latency recorded in telemetry.
- Hands every prompt to the async semantic analysis without blocking, unless a finding escalates it, in which case the escalated semantic controls run synchronously before the "is secure" decision.

"Is secure" decision and prompt helper specification:
- After the deterministic stage, the decision node routes the request: secure → forwarded to the LLM; not secure → prompt helper ("security policy path").
- The decision combines the deterministic verdict, the verdicts of any synchronously escalated semantic controls and the user's attack history risk score.
- A blocked prompt is never forwarded to the LLM in its original form.
- The prompt helper is an agentic pipeline backed by a local model that tells the user which policy was violated (without revealing detection internals that would help an attacker) and proposes a compliant rewrite of the prompt.
- The rewritten prompt is returned to the user for explicit resubmission; it is never sent to the LLM automatically, and the resubmission goes through the full guardrail pipeline again.
- Every rejection and every helper suggestion is written to the audit log and to the attack history.

Semantic guardrails (async semantic analysis) specification:
- AI-based controls that detect what patterns miss: prompt injection and jailbreak intent, indirect injection inside retrieved documents or MCP tool results, toxic or off-policy content, data exfiltration intent, multi-turn escalation (§4.2.2).
- Runs on self-hosted models only (§7) — default candidates from `docs/prior-art.md`: Llama Prompt Guard 2 (22M/86M) for injection, Presidio for semantic PII, a small Ollama model for intent classification. Do not use the archived LLM Guard.
- In `dev` the `mock` judge stands in for the model: it scores a control 1.0 when the text contains one of the control's `mock_keywords` and 0.0 otherwise, so demos and tests behave the same on every machine. `prod` refuses to start with it.
- Async by default, so it does not add latency to the request path; its verdicts update the history and risk score and can block subsequent requests in the same session or for the same identity.
- Escalation rule: each semantic control declares `escalate_when` — `always` (runs synchronously on every request at its hooks), `suspicious` (runs synchronously only when a deterministic control flagged, redacted or blocked something in the same request; the default) or `never` (disabled without deleting the config). Escalation trades latency for strictness only on traffic that already looks wrong, so clean requests pay nothing.
- A synchronously escalated control whose score reaches its threshold applies its action (`block`, `redact`, `flag`) to the current request.
- Classifiers are known to be evadable (see `docs/prior-art.md`); semantic controls complement deterministic ones and never replace them. Known misses must be documented, not hidden.
- If the semantic model is unavailable, the gateway fails according to policy (`fail_closed` or `fail_open` per control) and reports the outage.

Data access control specification:
- Every user and every agent has an identity authenticated by its own API key; anonymous traffic and unknown keys are rejected on every endpoint (§1: agents need modern authentication and access control). Only a hash of each key is stored.
- Access to resources (database tables/rows, file paths), MCP servers and individual MCP tools is deny-by-default: tools are granted per identity in `principals.allowed_tools`, resources per identity in the catalog's resource rules.
- Agents act on behalf of a user with delegated, narrowed scope; an agent never gets more permissions than the user it acts for, which prevents impersonation and privilege escalation.
- Delegation is explicit: only a principal with `delegates_users` may name an end user (`X-On-Behalf-Of`, at most 254 printable bytes). The user is recorded as `end_user` on every event, usage row and attack-history row, next to the principal that carried it.
- Destructive or irreversible operations (delete, write, payments, external sends) are classified by the policy and require an explicit allow rule and, where configured, human confirmation.
- Data retrieved from protected resources never reaches the LLM (see the MCP integration spec); it is filtered (redacted if required by the policy) before it reaches the user (output guardrails).
- Access to persistent agent memory and shared context stores is controlled per identity, so one agent cannot retrieve another's memory (§1).
- Path traversal, SSRF, and SQL/command injection attempts against resources are blocked and logged.

Budget and resource governance specification:
- Enforces budgets for both external commercial APIs and locally hosted models (§2, §4.3): token spend, monetary cost, compute time, request count and concurrency.
- Budgets are per user, not per principal: scoped hierarchically (user → team → organization) and per model, with time windows (per minute, hour, day, month). A user is the delegated end user, or a principal acting for no one under its slug; several users behind one console principal each spend their own budget.
- Budgets are rows in the `budgets` table (scope `global` | `user` | `model`, scope id, window, token / USD / request-count / concurrency limits, hard or soft), edited only through the gateway admin API. A refusal's detection id is `budget.<scope>.<scope id>`.
- Costs come from a per-model pricing table in the catalog; local models are accounted for by compute time and tokens.
- Only models allowed for the identity are reachable: the global deny list wins, then the global allow list, then the identity's `allowed_models` narrows it further (empty grants nothing); requests for other models are blocked (§4.1).
- Runaway agent protection: limits on tool-call count, agent loop iterations, recursion depth and repeated identical calls per session (§1: runaway execution loops).
- Soft limit triggers a warning (logged and shown in dashboards); hard limit blocks with a clear budget-exceeded error.
- Budget usage is updated in real time and exposed to monitoring and the dashboards.
- The self-testing suite must include tests that exceed each budget type and verify the block.

Malicious patterns detection and historical attack mitigation specification:
- Detects and blocks patterns associated with successful historical exploits on AI systems (§4.4): malicious code execution, unsafe deserialization (pickle/`torch.load` payloads, dangerous opcodes), supply-chain exploits on model repositories (untrusted repos, typosquatted model names, unpinned or hash-mismatched artifacts), MCP tool poisoning (hidden instructions in tool descriptions, tool definition changes after approval), known jailbreak prompts.
- Attack signatures come from an externally managed feed, uploaded together with the catalog (`signatures_toml`) and versioned with it; the feed format is documented so security teams can add signatures without code changes.
- On every activation the gateway mirrors the active signatures into the `attack_signatures` table so the dashboard can show feed status.
- Allowlists for model sources and MCP servers (with pinned versions/hashes) are part of the policy.
- The history store keeps past blocked and flagged interactions per user and session.
- History is used to detect multi-step or repeated attacks: users with recent violations get a higher risk score, which tightens checks or blocks them according to policy.
- `GET /admin/risk?q=` lists every user seen in the audit log with their score inside the catalog's `[risk]` window, violation count, last violation, last activity, the principals that carried them and a status (`normal`, `escalate`, `block`) from the active thresholds — the same score the next request is gated on. `q` is a case-insensitive substring search on the user; the console's risk tab is built on it.
- Matches report the signature id and feed version in the audit log.
- History doubles as the source of regression cases for the self-testing suite and as data for security reporting (the diagram groups them as "Security Reporting & Mitigation").

MCP integration specification:
- MCP sits between the LLM and the gateway; the LLM uses MCP tools to request data and actions instead of receiving whole resources in the prompt, which reduces token usage.
- MCP also carries data about the general structure of the data (like database tables) - it is used so the LLM can perform informed queries, but won't get any data from the protected resources.
- The LLM is not allowed to retrieve the protected data directly at all costs.
- Query tools: the gateway exposes an MCP tool that, when called, runs the LLM's query against the resources. The result rows are not returned to the LLM; the resource processing engine pushes them to the user who owns the session. The LLM receives only an acknowledgement (e.g. a result reference, the result's structure and row count), never the values.
- Every MCP tool call goes through the gateway: identity, data access control, budget, and input/output guardrails apply to tool arguments and to the results pushed to the user.
- Whatever MCP does return to the LLM (structure descriptions, acknowledgements, results of non-resource tools) is treated as untrusted input and scanned for indirect prompt injection before it reaches the LLM.
- Only MCP servers and tools allowed by the policy are exposed; tool descriptions are checked against the approved version to detect tool poisoning or rug-pull changes.
- Gateway-native tools (reserved prefix `control__`, always listed and callable): `control__list_controls` (id, kind, hooks, severity, action of every control — never patterns, thresholds or mock keywords), `control__my_access` (own tools, models, budget and usage, active grants, requestable tools and tables) and `control__request_access {tool | table, reason, ttl_minutes?}`.
- Access requests: the reason is scanned by the `tool_call` controls, then the request is pushed over SSE (`GET /admin/approvals/stream`, relayed by the console server) as a popup to the security team. Admins/analysts approve or deny (`POST /admin/approvals/{id}`); the agent's call blocks up to 120 s and returns `granted` (with expiry), `denied`, `expired`, `already_permitted` or `refused`. An approval is a time-boxed grant (1-60 min) for the one end user it was asked for (`X-On-Behalf-Of`, or the principal itself): the `tools/call` gate honours a tool grant next to `allowed_tools`, the resource tools honour a table grant next to the catalog's `[resources.grants]`. Only tables listed in `[resources.requestable]` for the principal can be requested; `resources__describe` names them and a refusal says how to ask. A refused table is audited as an `mcp.table-not-granted` block. Content controls still apply to everything a granted tool or table returns. Requests and decisions are audited and recorded in `access_requests`. Pending requests live in memory, so the gateway runs as one instance.

LLM ↔ MCP interaction specification:
- Protected resources are SQL databases only (Postgres here, schema `resources`, reached through the gateway's main connection, which switches to the read-only `resources_reader` role for each query's transaction).
- To read protected data the LLM: (1) calls `resources__describe {tables}` for the tables it needs; (2) the gateway returns their columns from `information_schema.columns` — structure only, refused for any table outside the identity's grant (`resources__describe` with no `tables` lists the granted table names); (3) calls `resources__query {sql}` with one SELECT; (4) the rows go through the resource processing engine to the user, and the LLM gets the acknowledgement. `GET /v1/results/{id}` returns the rows only to the principal and end user that ran the query (404 otherwise).
- Any MCP client can drive this over `POST /mcp`. The chat endpoint drives it for a model that cannot: `POST /v1/chat/completions` with `"mcp": true` offers the model the caller's `tools/list` as OpenAI function tools, runs each tool call it makes through the same `tools/call` gate (tool_call and tool_result hooks, grants, budgets, runaway limits), feeds the result back and repeats, at most 8 turns, until the model answers. The answer goes through `response_out` as usual; `x_control_layer.tool_calls` reports each call with its `result_id`, so the client fetches the rows from `GET /v1/results/{id}`. With `"stream": true` each turn streams: tool-call pieces are collected and run between turns, and the answering turn's text is released through the same checked window as any streamed answer; `tool_calls` then arrives in the final chunk's `x_control_layer`.
- In `dev` the mock upstream plays this flow when offered the resource tools and asked a SELECT: describe the tables the query names, run it, report the acknowledgement.

Resource processing engine and resources specification:
- Resources are the protected organizational assets: the database and files, but they depend on the company - since the system is designed with any company in mind.
- The resource processing engine exchanges data with the gateway in both directions and pushes processed results (e.g. query results, file extracts, reports) to the provisioned interface / user dashboard of the identity that issued the query — this is the only path by which resource data leaves the gateway.
- All resource access goes through the gateway's data access control; the engine has no direct path to resources that bypasses policy.
- Output guardrails (PII/secret redaction) apply to data before it is delivered to the user dashboard.

Monitoring, security reporting and auditing specification:
- Monitoring collects every event from all modules: verdicts, triggered controls, budget usage, latencies, policy reloads, signature feed updates, model outages (§4.5).
- Monitoring feeds the async semantic analysis inside the gateway for behavioral analysis of sessions and agents.
- Audit log is structured (e.g. JSON lines), append-only, and records for every interaction: timestamp, identity (principal), end user, agent, model, policy version, triggered controls, action taken, risk score, token/cost usage, per-stage latency. Redacted content is stored redacted.
- Every event has a security status, exposed by the `activity` view (events plus `status`): `blocked` (verdict block), `redacted` (verdict redact), `flagged` (allowed, but a control flagged it) or `secure`. It is derived only from hash-chained fields, so it cannot be edited apart from the record. The console's activity feed filters on it; custom incidents are not part of the backend.
- New events reach the console live: `events` is in the `supabase_realtime` publication, so the console subscribes over the Supabase Realtime websocket and RLS limits the stream to the security team. Every prompt sent through the gateway, the console chat included, is an event.
- Audit logs are exportable (JSON and CSV) with filters by time range, identity, end user, control and action, for security teams (§4.5).
- Real-time metrics for management: blocked/redacted/allowed counts, top triggered controls, budget usage and cost per team/model, overall security posture.
- The gateway persists these to Supabase Postgres, where the admin dashboard reads them; the dashboard UI itself is a separate feature.

Admin dashboard backend API specification:
- The admin dashboard (security team) reads persisted data — audit log, detections, policy versions, usage, signature feed mirror — directly through the Supabase Data API, authenticated as the security team; RLS grants it read-only access, so the dashboard can never rewrite the audit log it displays.
- The gateway writes through its privileged connection only. It exposes HTTP endpoints for live state the database does not hold (e.g. the active policy and its reload status, telemetry) and an authenticated admin API for the dashboard's writes (policy upload, and runtime settings once any exist). The dashboard never writes through the Data API.
- Together these provide: active controls and their state (with resource access and budgets), current policy version, its TOML and reload diff history, live and historical metrics, blocked threats with details, per-user budget usage and risk scores, the live activity feed with its security status, audit log search and export, signature feed status (§3.3).
- Gateway admin endpoints authenticate the console user with their Supabase access token (`Authorization: Bearer <access_token>`); the gateway verifies it with Supabase Auth and reads the user's `team_members.role`. `viewer`, `analyst` and `admin` may read (active policy, versions, metrics, budgets, risk, export); only `admin` may change state (policy upload, budgets). Every state-changing admin action, accepted or rejected, is recorded in `admin_actions`. The exception is `/admin/approvals/*`: the console server calls those with the `secops-console` principal's API key (`GATEWAY_ADMIN_KEY`, `principals.role = security_admin`) after checking the user's team role itself, and decisions are recorded in `access_requests`.
- Data API reads are restricted to the security team by RLS.

Performance telemetry specification:
- Per-stage latency (deterministic checks, semantic analysis, LLM call, MCP call, total overhead added by the layer) with p50/p95/p99 (§6).
- Throughput, error rates, model availability, and queue depth for async semantic analysis.
- Exposed via a metrics endpoint (e.g. Prometheus/OpenTelemetry format) and summarized in the admin dashboard.

Self-testing suite specification:
- A ready-to-run automated suite executed by a single command (`just check`), which judges will run (§3.4, §4.6, §6).
- Every implemented control has at least one positive (allowed) and one negative (blocked or redacted) test case.
- Covers: PII/secret redaction, prompt injection and jailbreak blocking, data access denial, budget limits (tokens, cost, rate, loop limits), historical exploit signatures (unsafe deserialization, malicious code, supply-chain, MCP tool poisoning), output filtering, prompt helper behavior.
- Includes policy tests: an upload applies changes, disabling a control stops it from triggering, threshold changes alter outcomes, invalid config is rejected with the last valid policy kept.
- Deterministic tests run without any model; semantic tests run against the mock judge by default, and tests against a real local model are clearly marked so they can be run separately when no model is available.
- Includes one end-to-end smoke test of the demo happy path (per `CLAUDE.md` testing policy).
- Interactions recorded in the attack history can be exported as regression test cases.
- Test output reports results per control so coverage is visible at a glance.
- The console's Self-test page (**Perform self-test**, admin role) calls `POST /admin/selftest`, which runs the suite (`gateway/src/selftest/suite.rs`) against the full running system — gateway, database, semantic judge and `mcp-demo` — and streams every prompt and tool call, what the gateway did with it, the risk score it assigned and the time it took, with a per-section summary and a final `RESULT: PASS` or `RESULT: FAIL`. It acts as the seeded `selftest` principal and names a fresh end user per case, so the suite never trips a risk block it did not mean to. `just test` runs the same harness (`gateway/src/selftest.rs`) in-process with no database, as part of `just check`.

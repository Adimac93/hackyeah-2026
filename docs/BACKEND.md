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
- The gateway receives the user identity directly from the user/interface side as a per-identity API key (`Authorization: Bearer`), so every request is evaluated against a known, authenticated identity. A self-declared identity header is never trusted on its own.
- It must be integrable by developers with minimal effort for agent-to-agent, app-to-agent, agent-to-MCP and agent-to-model traffic (§3.1) — e.g. an OpenAI-compatible HTTP endpoint and an MCP-proxy endpoint, so existing clients only change a base URL.
- Implements a hybrid defense: fast deterministic (non-AI, full-text search instead) controls on the synchronous path, and AI-based semantic controls where they add value (§2, §4.2) — asynchronous by default, synchronous only when a deterministic control escalates the request.
- Everything must run locally (`dev`) or on Google Cloud platform (`prod`) - depending on the `ENVIRONMENT` config variable (`dev`, `prod`).
- `ENVIRONMENT` sets defaults and strictness, not features: `dev` starts without a database (enforcement runs, nothing is persisted) and logs human-readable text; `prod` refuses to start without `DATABASE_URL`, refuses to start when an enabled semantic control has no reachable detector configured, and logs JSON. `just deploy` targets Google Cloud Run in `prod`.
- Stack is decided - look for project context to discover the stack.
- Coverage should be reviewed against OWASP Top 10 for LLM Applications and OWASP agentic AI threats (§1 note): prompt injection, sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption.

Centralized policy engine and configuration file specification:
- A single configuration file is the only source of truth for all controls (§4.1); the gateway loads it and distributes the effective policy to the security proxy.
- The configuration file is in the TOML format.
- The file defines: list of controls with `enabled` flag, action per control, failure mode per control (`closed` or `open`, falling back to a file-wide default), sensitivity thresholds (e.g. adherence % or classifier score cutoffs), allowed LLM models (a global allow/deny list, narrowed per identity/role), a per-model pricing table, and per identity/role: resource and financial budgets, data access rules (MCP servers, tools, resources); plus the attack-signature feed source.
- Actions: `allow` (record only), `flag` (record and mark the request suspicious, which escalates it to the semantic tier), `redact` (replace the match and continue), `block` (stop the request).
- Identity is not policy: the registry of identities and their hashed API keys lives in the database (`principals`); everything an identity may do lives in the file, keyed by identity slug or role.
- Unknown keys are a validation error, so a typo such as `enabeld = false` is rejected instead of silently leaving the control on.
- Supports named strictness profiles (e.g. `permissive`, `balanced`, `strict`) that set defaults for all controls; individual controls can override the profile (§3.2).
- Hot reload: file changes apply at runtime without a restart, because judges will edit the file during evaluation and observe the effect (§6).
- Every reload is validated against a schema; an invalid file is rejected, the last valid policy stays active and the error is reported in the audit log and admin dashboard.
- Every accepted reload produces a policy version id and a human-readable diff, recorded in the audit log and visible in the admin dashboard.
- Each decision in the audit log references the policy version and control id that produced it.
- Ship a documented sample configuration demonstrating different strictness levels and budget rules (§3.2).
- Removing a control from the file disables it immediately; the self-testing suite must prove this.

Deterministic guardrails (security proxy) specification:
- The security proxy sits between the provisioned interface and the LLM; all deterministic checks happen here, on both the prompt (input) and the LLM response (output) (§4.2.1).
- Input checks: PII and secret detection via pattern matching (emails, phone numbers, national IDs such as PESEL, IBANs, card numbers with Luhn check, API keys, private keys, JWTs, passwords in connection strings), known prompt-injection and jailbreak patterns, encoded or obfuscated payloads (base64, unicode homoglyphs, invisible characters), request size limits, authentication and authorization checks.
- Output checks: redaction of PII and secrets in responses, detection of system prompt leakage, detection of dangerous content handed to downstream systems (shell commands, SQL, HTML/JS) to prevent improper output handling.
- Historical attack mitigation patterns (see the malicious patterns detection spec) are applied on both input and output paths.
- Action per finding follows the policy: `block` stops the request, `redact` replaces the match with a placeholder naming the control (e.g. `[REDACTED:pii.email]`) and continues, `flag` records it and escalates the request to the semantic tier, `allow` only records it.
- Produces a verdict (`allow`, `redact`, `block`) with the list of triggered control ids and a risk score that drives the "is secure" decision.
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
- Runs on local models only (§7) — default candidates from `docs/prior-art.md`: Llama Prompt Guard 2 (22M/86M) for injection, Presidio for semantic PII, a small Ollama model for intent classification. Do not use the archived LLM Guard.
- Async by default, so it does not add latency to the request path; its verdicts update the history and risk score and can block subsequent requests in the same session or for the same identity.
- Escalation rule: each semantic control declares `escalate_when` — `always` (runs synchronously on every request at its hooks), `suspicious` (runs synchronously only when a deterministic control flagged, redacted or blocked something in the same request; the default) or `never` (disabled without deleting the config). Escalation trades latency for strictness only on traffic that already looks wrong, so clean requests pay nothing.
- A synchronously escalated control whose score reaches its threshold applies its action (`block`, `redact`, `flag`) to the current request.
- Classifiers are known to be evadable (see `docs/prior-art.md`); semantic controls complement deterministic ones and never replace them. Known misses must be documented, not hidden.
- If the semantic model is unavailable, the gateway fails according to policy (`fail_closed` or `fail_open` per control) and reports the outage.

Data access control specification:
- Every user and every agent has an identity authenticated by its own API key and a role; anonymous traffic and unknown keys are rejected on every endpoint (§1: agents need modern authentication and access control). Only a hash of each key is stored.
- Access to resources (database tables/rows, file paths), MCP servers and individual MCP tools is deny-by-default and granted per role by the policy.
- Agents act on behalf of a user with delegated, narrowed scope; an agent never gets more permissions than the user it acts for, which prevents impersonation and privilege escalation.
- Destructive or irreversible operations (delete, write, payments, external sends) are classified by the policy and require an explicit allow rule and, where configured, human confirmation.
- Data retrieved from protected resources never reaches the LLM (see the MCP integration spec); it is filtered (redacted if required by the policy) before it reaches the user (output guardrails).
- Access to persistent agent memory and shared context stores is controlled per identity, so one agent cannot retrieve another's memory (§1).
- Path traversal, SSRF, and SQL/command injection attempts against resources are blocked and logged.

Budget and resource governance specification:
- Enforces budgets for both external commercial APIs and locally hosted models (§2, §4.3): token spend, monetary cost, compute time, request count and concurrency.
- Budgets are scoped hierarchically (identity → team → organization) and per model, with time windows (per minute, hour, day, month).
- Costs come from a per-model pricing table in the configuration; local models are accounted for by compute time and tokens.
- Only models allowed for the identity are reachable: the global deny list wins, then the global allow list, then the identity/role allow list narrows it further; requests for other models are blocked (§4.1).
- Runaway agent protection: limits on tool-call count, agent loop iterations, recursion depth and repeated identical calls per session (§1: runaway execution loops).
- Soft limit triggers a warning (logged and shown in dashboards); hard limit blocks with a clear budget-exceeded error.
- Budget usage is updated in real time and exposed to monitoring and the dashboards.
- The self-testing suite must include tests that exceed each budget type and verify the block.

Malicious patterns detection and historical attack mitigation specification:
- Detects and blocks patterns associated with successful historical exploits on AI systems (§4.4): malicious code execution, unsafe deserialization (pickle/`torch.load` payloads, dangerous opcodes), supply-chain exploits on model repositories (untrusted repos, typosquatted model names, unpinned or hash-mismatched artifacts), MCP tool poisoning (hidden instructions in tool descriptions, tool definition changes after approval), known jailbreak prompts.
- Attack signatures are loaded from an externally managed feed (URL or file), versioned, and hot-reloaded like the policy; the feed format is documented so security teams can add signatures without code changes.
- The feed file stays the source of truth; on every load the gateway mirrors the active signatures into the `attack_signatures` table so the dashboard can show feed status.
- Allowlists for model sources and MCP servers (with pinned versions/hashes) are part of the policy.
- The history store keeps past blocked and flagged interactions per identity and session.
- History is used to detect multi-step or repeated attacks: identities with recent violations get a higher risk score, which tightens checks or blocks them according to policy.
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

Resource processing engine and resources specification:
- Resources are the protected organizational assets: the database and files, but they depend on the company - since the system is designed with any company in mind.
- The resource processing engine exchanges data with the gateway in both directions and pushes processed results (e.g. query results, file extracts, reports) to the provisioned interface / user dashboard of the identity that issued the query — this is the only path by which resource data leaves the gateway.
- All resource access goes through the gateway's data access control; the engine has no direct path to resources that bypasses policy.
- Output guardrails (PII/secret redaction) apply to data before it is delivered to the user dashboard.

Monitoring, security reporting and auditing specification:
- Monitoring collects every event from all modules: verdicts, triggered controls, budget usage, latencies, policy reloads, signature feed updates, model outages (§4.5).
- Monitoring feeds the async semantic analysis inside the gateway for behavioral analysis of sessions and agents.
- Audit log is structured (e.g. JSON lines), append-only, and records for every interaction: timestamp, identity, agent, model, policy version, triggered controls, action taken, risk score, token/cost usage, per-stage latency. Redacted content is stored redacted.
- Audit logs are exportable (JSON and CSV) with filters by time range, identity, control and action, for security teams (§4.5).
- Real-time metrics for management: blocked/redacted/allowed counts, top triggered controls, budget usage and cost per team/model, overall security posture.
- The gateway persists these to Supabase Postgres, where the admin dashboard reads them; the dashboard UI itself is a separate feature.

Admin dashboard backend API specification:
- The admin dashboard (security team) reads persisted data — audit log, detections, policy versions, usage, signature feed mirror — directly through the Supabase Data API, authenticated as the security team; RLS grants it read-only access, so the dashboard can never rewrite the audit log it displays.
- The gateway writes through its privileged connection only and exposes HTTP endpoints only for live state the database does not hold (e.g. the active policy and its reload status, telemetry).
- Together these provide: active controls and their state, current policy version and reload diff history, live and historical metrics, blocked threats with details, budget usage, audit log search and export, signature feed status (§3.3).
- Data API and gateway endpoints are restricted to the security team role, and every admin action that changes state is audited.

Performance telemetry specification:
- Per-stage latency (deterministic checks, semantic analysis, LLM call, MCP call, total overhead added by the layer) with p50/p95/p99 (§6).
- Throughput, error rates, model availability, and queue depth for async semantic analysis.
- Exposed via a metrics endpoint (e.g. Prometheus/OpenTelemetry format) and summarized in the admin dashboard.

Self-testing suite specification:
- A ready-to-run automated suite executed by a single command (`just check`), which judges will run (§3.4, §4.6, §6).
- Every implemented control has at least one positive (allowed) and one negative (blocked or redacted) test case.
- Covers: PII/secret redaction, prompt injection and jailbreak blocking, data access denial, budget limits (tokens, cost, rate, loop limits), historical exploit signatures (unsafe deserialization, malicious code, supply-chain, MCP tool poisoning), output filtering, prompt helper behavior.
- Includes policy tests: hot reload applies changes, disabling a control stops it from triggering, threshold changes alter outcomes, invalid config is rejected with the last valid policy kept.
- Deterministic tests run without any model; semantic tests use local models only and are clearly marked so they can be run separately when no model is available.
- Includes one end-to-end smoke test of the demo happy path (per `CLAUDE.md` testing policy).
- Interactions recorded in the attack history can be exported as regression test cases.
- Test output reports results per control so coverage is visible at a glance.

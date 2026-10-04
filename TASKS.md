# Tasks

One task = one line = one `just wt <name>` worktree = one branch = one PR.
Claim by putting your initials in. No issue tracker, no sub-bullets, no estimates.

Format: `- [ ] <name> — <what> (@who)`

## Now

- [ ] _(nothing claimed yet)_

## Next

- [ ] migrate-end-users — `just migrate` for 20261004090000_end_users_activity_status, `just seed` (adds `console-chat`), then `supabase db advisors` (@)
- [ ] web-budgets — budgets editor on `PUT`/`DELETE /admin/budgets` (admin role) (@)
- [ ] web-helper — show `error.helper` (violated policy + suggestion) on a blocked chat prompt, resubmit only on click (@)
- [ ] resources-mcp-rollout — `just migrate` for 20261004130000_resources_mcp, `just seed`, `supabase db advisors`; upload the catalog (adds `[resources.requestable]`); unset `RESOURCES_DATABASE_URL` on Cloud Run; smoke test per DEMO.md "data through MCP" (@)
- [ ] budgets-scopes — team/org budget scopes and compute-time accounting (@)
- [ ] apply-migration — `just migrate` for 20261003210000_gateway_db_policy, then `just seed` and `supabase db advisors` (@)
- [ ] write the demo script in DEMO.md and put the deployed URL there (@)
- [ ] fill in the ownership table in CLAUDE.md (@)
- [ ] chat-upstream-prod — a real `UPSTREAM_URL` for prod chat ; wire it into cloudbuild.yaml (@)
- [ ] more-patterns — request size limit, base64/homoglyph payloads, shell/SQL/HTML output checks (IBAN, Luhn cards, JWT, phone, invisible unicode are done) (@)

## Done

- [x] per-control-tests — red/green report per shipped control and an end-to-end HTTP suite (chat, MCP, hot catalog change) printing input, verdict and risk score; risk score returned per request
- [x] web-results / resources-mcp — console chat uses the MCP data tools on gateway models, renders tool steps and the delivered rows; table access requests with per-user grants; results bound to the end user (docs/superpowers/plans/2026-10-04-resources-mcp.md)
- [x] console-specs — per-user budgets/risk/activity (X-On-Behalf-Of), deterministic refusal notice, live activity with status filter, user risk tab, merged Controls & policies with TOML editor, incidents and company-policy pages dropped
- [x] backend-spec-fixes — policy only in the DB (upload is the only change path), Supabase-JWT admin API, deny-by-default grants, budgets in the DB via the admin API
- [x] principal-models — enforce per-identity/role model allow list on top of the global one
- [x] mcp-agent-loop — chat `"mcp": true` drives the model through the MCP tools (describe given tables → SELECT → rows to the user); mock upstream plays it in dev
- [x] mcp-query-push — MCP query tool runs on resources, rows pushed to the user via resource engine, LLM gets only ref/structure/row count
- [x] signature-mirror — upsert loaded feed into `attack_signatures` on every load
- [x] policy-reload-audit — record rejected reloads and a diff for file reloads; uploads already store `diff_summary`
- [x] prompt-helper — local-model helper: violated policy + compliant rewrite, never auto-resubmitted
- [x] risk-history — `attack_history` is written; make the risk score feed the "is secure" decision, async semantic verdicts update it
- [x] budgets-extended — request count, per-instance concurrency and runaway limits (tool calls, identical calls, depth); team/org scopes and compute time still open
- [x] mcp-tool-pinning — pin approved tool descriptions, block rug-pull changes; MCP server allowlist with hashes
- [x] audit-export — JSON/CSV export with time/identity/control/action filters
- [x] metrics-prometheus — `/metrics` serves JSON with percentiles; add Prometheus format and semantic queue depth
- [x] lock the project idea → "What we're building" in CLAUDE.md
- [x] pick the stack → Rust gateway + Next.js web, wired into `just` and CI
- [x] deploy pipeline → `just deploy` (Cloud Run, docs/DEPLOY.md)
- [x] api-keys — per-principal Bearer keys (SHA-256 in `principals.api_key_hash`), `x-principal` dropped, `/policy` and `/metrics` need a `security_admin` key
- [x] policy-upload — `POST /admin/policy`: validated like a reload, stored in `policy_versions` with a diff, newest of disk/upload wins at startup
- [x] strictness-profiles — `permissive` / `balanced` / `strict` profiles, per-control override
- [ ] ollama-gpu — a reachable Ollama for the prod judge (`OLLAMA_URL`); the Vertex/Terraform attempt was removed

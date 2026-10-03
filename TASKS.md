# Tasks

One task = one line = one `just wt <name>` worktree = one branch = one PR.
Claim by putting your initials in. No issue tracker, no sub-bullets, no estimates.

Format: `- [ ] <name> — <what> (@who)`

## Now

- [ ] _(nothing claimed yet)_

## Next

- [ ] web-gateway-auth — web chat still sends `x-principal`, which the gateway no longer trusts, so "Gateway (protected)" chat gets 401; send `Authorization: Bearer $GATEWAY_API_KEY` from the server (@)
- [ ] web-policy-upload — console policy page: upload catalog TOML (+ optional signatures) to `POST /admin/policy` with the user's Supabase access token, show the returned diff and `/admin/policy/versions` (@)
- [ ] web-budgets — budgets editor on `PUT`/`DELETE /admin/budgets` (admin role) (@)
- [ ] web-helper — show `error.helper` (violated policy + suggestion) on a blocked chat prompt, resubmit only on click (@)
- [ ] web-results — fetch `GET /v1/results/{id}` for `resources__query` acknowledgements and render the rows (@)
- [ ] budgets-scopes — team/org budget scopes and compute-time accounting (@)
- [ ] apply-migration — `just migrate` for 20261003210000_gateway_db_policy, then `just seed` and `supabase db advisors` (@)
- [ ] write the demo script in DEMO.md and put the deployed URL there (@)
- [ ] fill in the ownership table in CLAUDE.md (@)
- [ ] chat-upstream-prod — a real `UPSTREAM_URL` for prod chat ; wire it into cloudbuild.yaml (@)
- [ ] more-patterns — request size limit, base64/homoglyph payloads, shell/SQL/HTML output checks (IBAN, Luhn cards, JWT, phone, invisible unicode are done) (@)
- [ ] per-control-tests — positive + negative case per control, report per control (@)

## Done

- [x] backend-spec-fixes — policy only in the DB (upload is the only change path), Supabase-JWT admin API, deny-by-default grants, budgets in the DB via the admin API
- [x] principal-models — enforce per-identity/role model allow list on top of the global one
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

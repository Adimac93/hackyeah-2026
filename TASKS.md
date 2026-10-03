# Tasks

One task = one line = one `just wt <name>` worktree = one branch = one PR.
Claim by putting your initials in. No issue tracker, no sub-bullets, no estimates.

Format: `- [ ] <name> — <what> (@who)`

## Now

- [ ] backend-spec-fixes — policy only in the DB (upload is the only change path, built-in sample seeded on first start), Supabase-JWT admin auth, deny-by-default grants in `principals`, budgets from the `budgets` table via admin API; covers the lines below (@HK)
- [ ] principal-models — enforce per-identity/role model allow list on top of the global one (@HK)
- [ ] mcp-query-push — MCP query tool runs on resources, rows pushed to the user via resource engine, LLM gets only ref/structure/row count (@HK)
- [ ] signature-mirror — upsert loaded feed into `attack_signatures` on every load (@HK)
- [ ] policy-reload-audit — record rejected reloads and a diff for file reloads; uploads already store `diff_summary` (@HK)
- [ ] prompt-helper — local-model helper: violated policy + compliant rewrite, never auto-resubmitted (@HK)
- [ ] risk-history — `attack_history` is written; make the risk score feed the "is secure" decision, async semantic verdicts update it (@HK)
- [ ] budgets-extended — team/org scopes, compute time, request count, concurrency, runaway-loop limits (@HK)
- [ ] mcp-tool-pinning — pin approved tool descriptions, block rug-pull changes; MCP server allowlist with hashes (@HK)
- [ ] audit-export — JSON/CSV export with time/identity/control/action filters (@HK)
- [ ] metrics-prometheus — `/metrics` serves JSON with percentiles; add Prometheus format and semantic queue depth (@HK)

## Next

- [ ] web-gateway-auth — web chat still sends `x-principal`, which the gateway no longer trusts, so "Gateway (protected)" chat gets 401; send a per-user Bearer key instead (@)
- [ ] write the demo script in DEMO.md and put the deployed URL there (@)
- [ ] fill in the ownership table in CLAUDE.md (@)
- [ ] chat-upstream-prod — a real `UPSTREAM_URL` for prod chat (the Vertex judge serves only the semantic tier); wire it into cloudbuild.yaml (@)
- [ ] more-patterns — request size limit, base64/homoglyph payloads, shell/SQL/HTML output checks (IBAN, Luhn cards, JWT, phone, invisible unicode are done) (@)
- [ ] per-control-tests — positive + negative case per control, report per control (@)

## Done

- [x] lock the project idea → "What we're building" in CLAUDE.md
- [x] pick the stack → Rust gateway + Next.js web, wired into `just` and CI
- [x] deploy pipeline → `just deploy` (Cloud Run, docs/DEPLOY.md)
- [x] api-keys — per-principal Bearer keys (SHA-256 in `principals.api_key_hash`), `x-principal` dropped, `/policy` and `/metrics` need a `security_admin` key
- [x] policy-upload — `POST /admin/policy`: validated like a reload, stored in `policy_versions` with a diff, newest of disk/upload wins at startup
- [x] strictness-profiles — `permissive` / `balanced` / `strict` profiles, per-control override
- [x] ollama-gpu — superseded: the judge runs on a VPC-internal Vertex AI endpoint (`infra/`)

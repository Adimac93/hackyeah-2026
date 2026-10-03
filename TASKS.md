# Tasks

One task = one line = one `just wt <name>` worktree = one branch = one PR.
Claim by putting your initials in. No issue tracker, no sub-bullets, no estimates.

Format: `- [ ] <name> — <what> (@who)`

## Now

- [ ] _(nothing claimed yet)_

## Next

- [ ] lock the project idea → write the "What we're building" paragraph in CLAUDE.md
- [ ] pick the stack → wire the justfile recipes + add the language setup step to CI
- [ ] deploy a hello-world to the demo URL and wire `just deploy`
- [ ] fill in the ownership table in CLAUDE.md
- [ ] write the demo script in DEMO.md
- [ ] api-keys — per-principal API key (Bearer, sha256 stored), reject unknown/anonymous on /v1 and /mcp, drop x-principal trust; /policy needs a security-team key, `/` shows no policy details (@)
- [ ] grants-to-toml — move model/tool grants + roles into the catalog, drop `budgets` table and grant columns via migration (@)
- [ ] principal-models — enforce per-identity/role model allow list on top of the global one (@)
- [ ] mcp-query-push — MCP query tool runs on resources, rows pushed to the user via resource engine, LLM gets only ref/structure/row count (@)
- [ ] ollama-gpu — Ollama as a Cloud Run GPU service, wire UPSTREAM_URL/OLLAMA_URL into cloudbuild.yaml (@)
- [ ] policy-upload — PUT /admin/policy (after api-keys): validate like a reload, store full text in policy_versions, newest of disk/upload wins on every instance, audited (@)
- [ ] signature-mirror — upsert loaded feed into `attack_signatures` on every load (@)
- [ ] policy-reload-audit — record rejected reloads and a human-readable diff per accepted version (@)
- [ ] strictness-profiles — permissive/balanced/strict profiles with per-control override (@)
- [ ] prompt-helper — local-model helper: violated policy + compliant rewrite, never auto-resubmitted (@)
- [ ] risk-history — per-identity attack history + risk score feeding the "is secure" decision; async semantic verdicts update it (@)
- [ ] budgets-extended — team/org scopes, compute time, request count, concurrency, runaway-loop limits (@)
- [ ] mcp-tool-pinning — pin approved tool descriptions, block rug-pull changes; MCP server allowlist with hashes (@)
- [ ] more-patterns — IBAN, Luhn cards, JWT, phone, request size limit, encoded/homoglyph payloads, shell/SQL/HTML output checks (@)
- [ ] audit-export — JSON/CSV export with time/identity/control/action filters (@)
- [ ] metrics-endpoint — Prometheus endpoint, p50/p95/p99 per stage, semantic queue depth (@)
- [ ] per-control-tests — scenario suite in tests/, positive + negative per control, report per control (@)

## Done


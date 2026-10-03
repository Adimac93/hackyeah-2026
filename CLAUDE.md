# hackyeah-2026

## What we're building

An **AI Control Layer** for the HackYeah challenge in `docs/task.md`: a security gateway
that sits between users/agents and LLMs and MCP servers, and polices every prompt,
response, tool call and tool result against one hot-reloaded TOML control catalog
(`policy/`). Deterministic controls (PII, secrets, injection patterns, exploit
signatures, budgets, model allow lists) run on every request; an AI judge runs only on
traffic they flag. Every decision lands in a hash-chained audit log in Supabase, which
the SecOps console (`web/`) shows to the security team. Judges see: an ad-hoc prompt
redacted or blocked live, a catalog edit taking effect without a restart, the console's
activity/controls/budgets views, and `just check` proving each control. The full spec is
`docs/BACKEND.md`.

## Stack

- **Gateway** — Rust workspace: `axum`, `tokio`, `sqlx`, `dotenvy`. Deployed from a
  `cargo-chef` based Dockerfile to Cloud Run (`docs/DEPLOY.md`). Spec: `docs/BACKEND.md`.
- **Web app** — Next.js in `web/` (pnpm): the SecOps console and security assistant chat.
  Reads the Data API as the signed-in security team; never writes gateway tables.
- **Storage** — Supabase Postgres, project ref `wkxhfzjknxdyfwhnwogn`. Schema lives in
  `supabase/migrations/`; the gateway reaches it through `sqlx` with `DATABASE_URL`, the
  dashboard through the Data API.
- **Semantic tier** — an `llm_judge` detector. Runs only when a deterministic control
  flags the traffic (`escalate_when`), so clean requests pay nothing. In `dev` it is a
  deterministic mock (`OLLAMA_URL=mock`, scores from each control's `mock_keywords`) and
  chat goes to a mock upstream (`UPSTREAM_URL=mock`), so no Ollama is needed. In `prod`
  the judge is the Ollama at `OLLAMA_URL`. Prod refuses to start with a mock.
  With no reachable detector the controls fail closed and suspicious traffic is refused.
  A Presidio sidecar for contextual PII is still unbuilt; that control ships disabled.

### Database rules

- **One migration directory: `supabase/migrations/`.** The gateway's schema and
  the web app's share a database, so they share a timeline — two directories
  cannot express a single correct ordering. `just migrate` applies them,
  `just db-new <name>` creates one.
- **Change the schema with a migration, never in the Supabase console.** `supabase
  migration new <name>`, edit the file, apply, commit. A console edit is invisible to
  everyone else's checkout.
- **RLS is on for every table and must stay on.** Public-schema tables are reachable
  through the Data API. Gateway tables (`events`, `detections`, `principals`, `budgets`, `usage`,
  `policy_versions`, `attack_signatures`, `attack_history`) are written only by the
  gateway's privileged connection; the console reads them and has no write path — the
  audit log must not be rewritable by the thing that displays it. The console's own
  tables (incidents, company policies, chat, team, LLM connections) take role-gated
  writes from signed-in team members.
- **Run the advisors after any schema change** (`supabase db advisors`, or the MCP
  `get_advisors`). It was clean when the schema landed; keep it that way.

## Commands

Run everything through `just`. Never call pnpm/cargo/uv/etc. directly — the recipes are
the contract, so the stack can change without retraining anyone.

| command | what |
|---|---|
| `just setup` | install dependencies |
| `just check` | typecheck + lint + test — **the definition of done** |
| `just dev` | run gateway + web app locally (`dev-api` / `dev-web` for one) |
| `just demo` | gateway + the deliberately vulnerable `mcp-demo` server |
| `just fmt` | apply rustfmt + prettier |
| `just migrate` | apply new Supabase migrations (`--dry-run` to preview) |
| `just db-new <name>` | new migration file |
| `just seed` | load demo data |
| `just report` | render the PDF security report (needs `DATABASE_URL`, `typst`) |
| `just verify-audit` | prove the audit hash chain is intact (needs `DATABASE_URL`) |
| `just deploy` | ship the gateway to Cloud Run (runs `just check` first) |
| `just wt <name>` | new isolated worktree + branch + its own PORT |
| `just wt-rm <name>` | remove that worktree |

Added a tool? Wire it into the matching recipe. Don't add a new top-level command.

## Who owns what

One owner per directory. Editing someone else's directory without telling them is how
we lose an hour to merge conflicts at 3am.

| path | owner |
|---|---|
| `gateway/` — Rust proxy, deterministic tier, policy engine, audit writer | |
| `sentinel/` — semantic tier | |
| `mcp-demo/` — deliberately vulnerable MCP server for the demo | |
| `web/` — SecOps console + assistant chat (Next.js), reads the Data API | |
| `policy/` — TOML control catalog, thresholds, budgets | |
| `supabase/migrations/` — schema | |

## Hard rules

- **Never commit secrets.** New secret → add the key to `.env.example` with an empty value.
- **Never work in the primary checkout.** One agent, one worktree.
- **`just check` must be green before you say you're done.** Paste the output.
- **New dependency → tell the team first.** Lockfile conflicts are expensive.
- **Don't refactor across owners' directories.** Not now. Ship.

## Testing policy — deliberately narrow

This is a 24-hour build. Do **not** TDD everything; that default is wrong here.

- **Test**: pure logic — scoring, parsing, validation, anything with real edge cases.
- **One smoke test**: the demo happy path, end to end.
- **Don't test**: UI layout, third-party wiring, anything a human eyeballs in two seconds.

Tests live next to the code: `gateway/src/**/tests.rs` (cargo) and `web/src/**/*.test.ts`
(pnpm). `just test` runs both.

## Demo rules

- `main` must always run and always deploy. If `just check` is red on `main`, that is
  everyone's top priority — above whatever feature you're on.
- Deploy a hello-world the hour the stack lands. Discovering the deploy story at hour 23
  is the single most common way a hackathon demo dies.
- `DEMO.md` holds the click-by-click script and the recorded fallback. Keep it current.

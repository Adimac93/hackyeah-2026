# hackyeah-2026

## What we're building

**TBD** — fill this in the moment the idea is locked. One paragraph: what it does, for
whom, what the judges see in the demo. Until this line is replaced, agents should ask
rather than invent.

## Stack

- **Gateway** — Rust workspace: `axum`, `tokio`, `sqlx`, `dotenvy`. Deployed from a
  `cargo-chef` based Dockerfile. See `docs/backend-scaffold.md`.
- **Storage** — Supabase Postgres, project ref `wkxhfzjknxdyfwhnwogn`. Schema lives in
  `supabase/migrations/`; the gateway reaches it through `sqlx` with `DATABASE_URL`, the
  dashboard through the Data API.
- **Semantic tier** — an `llm_judge` detector. Runs only when a deterministic control
  flags the traffic (`escalate_when`), so clean requests pay nothing. In `dev` it is a
  deterministic mock (`OLLAMA_URL=mock`, scores from each control's `mock_keywords`) and
  chat goes to a mock upstream (`UPSTREAM_URL=mock`), so no Ollama is needed. In `prod`
  both point at Ollama on a Cloud Run GPU service; prod refuses to start with a mock.
  With no reachable detector the controls fail closed and suspicious traffic is refused.
  A Presidio sidecar for contextual PII is still unbuilt; that control ships disabled.

### Database rules

- **Change the schema with a migration, never in the Supabase console.** `supabase
  migration new <name>`, edit the file, apply, commit. A console edit is invisible to
  everyone else's checkout.
- **RLS is on for every table and must stay on.** Public-schema tables are reachable
  through the Data API. Only the gateway's privileged connection writes; the dashboard
  reads. There is no authenticated write path — the audit log must not be rewritable by
  the thing that displays it.
- **Run the advisors after any schema change** (`supabase db advisors`, or the MCP
  `get_advisors`). It was clean when the schema landed; keep it that way.

## Commands

Run everything through `just`. Never call pnpm/cargo/uv/etc. directly — the recipes are
the contract, so the stack can change without retraining anyone.

| command | what |
|---|---|
| `just setup` | install dependencies |
| `just check` | typecheck + lint + test — **the definition of done** |
| `just dev` | run locally |
| `just seed` | load demo data |
| `just deploy` | ship to the demo URL |
| `just wt <name>` | new isolated worktree + branch + its own PORT |
| `just wt-rm <name>` | remove that worktree |

Added a tool? Wire it into the matching recipe. Don't add a new top-level command.

## Who owns what

One owner per directory. Editing someone else's directory without telling them is how
we lose an hour to merge conflicts at 3am.

| path | owner |
|---|---|
| `gateway/` — Rust proxy, deterministic tier, policy engine, audit writer | |
| `sentinel/` — semantic tier (pending the stack decision above) | |
| `dashboard/` — admin UI, reads the Data API | |
| `policy/` — TOML control catalog, thresholds, budgets | |
| `tests/` — scenario cases, positive and negative | |
| `supabase/migrations/` — schema | |

## Hard rules

- **Never commit secrets.** New secret → add the key to `.env.example` with an empty value.
- **Never push to `main`.** Branch (`just wt`) → PR. Merge your own PR; no review gate.
- **Never work in the primary checkout.** One agent, one worktree.
- **`just check` must be green before you say you're done.** Paste the output.
- **New dependency → tell the team first.** Lockfile conflicts are expensive.
- **Don't refactor across owners' directories.** Not now. Ship.

## Testing policy — deliberately narrow

This is a 24-hour build. Do **not** TDD everything; that default is wrong here.

- **Test**: pure logic — scoring, parsing, validation, anything with real edge cases.
- **One smoke test**: the demo happy path, end to end.
- **Don't test**: UI layout, third-party wiring, anything a human eyeballs in two seconds.

## Demo rules

- `main` must always run and always deploy. If `just check` is red on `main`, that is
  everyone's top priority — above whatever feature you're on.
- Deploy a hello-world the hour the stack lands. Discovering the deploy story at hour 23
  is the single most common way a hackathon demo dies.
- `DEMO.md` holds the click-by-click script and the recorded fallback. Keep it current.

# Cogut — the AI control layer

> Let AI move fast. Keep control.

Cogut is a security gateway that sits between users, agents, LLMs and MCP
servers. Every prompt, model response, tool call and tool result is checked
against one central policy — redacted, blocked or allowed — and every decision
lands in a tamper-evident audit log the security team can see.

Built at **HackYeah 2026** for the *AI Control Layer* challenge
([`docs/task.md`](docs/task.md)).

- **Landing page:** <https://cogut.jay-z.workers.dev>
- **Gateway (Cloud Run):** <https://cogut-backend.cloud.run> — API docs at `/admin/docs`

## For judges

The submission follows the suggested layout. Each folder holds symlinks to where
the material actually lives in the repo; the code itself stays at the root.

| Folder | Links to |
|---|---|
| [`1-solution/`](1-solution) | [overview and controls](docs/solution.md), [control catalog](policy/control-catalog.toml), [signature feed](policy/signatures.toml), [challenge brief](docs/task.md) |
| [`2-architecture/`](2-architecture) | [diagram and performance](docs/architecture.md), [architecture explorer](docs/architecture.html), [backend spec](docs/BACKEND.md), [prior art](docs/prior-art.md), [telemetry](gateway/src/telemetry.rs) |
| [`3-reporting/`](3-reporting) | [dashboard and metrics](docs/reporting.md), [console](web), [metrics queries](gateway/src/metrics.rs), [audit export](gateway/src/admin/export.rs), [PDF report](report/report.typ) |
| [`4-testing/`](4-testing) | [test cases](docs/testing.md), [per-control red/green cases](gateway/src/engine/tests.rs), [demo script](DEMO.md), [CI](.github/workflows/ci.yml) |
| [`5-implementation/`](5-implementation) | [implementation and integration](docs/implementation.md), [deployment](docs/DEPLOY.md), [`gateway/`](gateway), [`web/`](web), [`policy/`](policy), [`supabase/`](supabase), [`mcp-demo/`](mcp-demo), [`report/`](report), [Dockerfile](Dockerfile), [cloudbuild.yaml](cloudbuild.yaml) |

---|---|
| [`1-solution/`](1-solution) | overview, the list of controls, configuration and policy options |
| [`2-architecture/`](2-architecture) | architecture diagram, performance metrics per tier |
| [`3-reporting/`](3-reporting) | dashboard screenshots, the metrics we report |
| [`4-testing/`](4-testing) | test cases — red/green per control, live scenarios |
| [`5-implementation/`](5-implementation) | code map, implementation notes, integrating into existing agentic ecosystems |

---

## What it does

| | |
|---|---|
| **Protect what matters** | Detects secrets, personal data (PII, PESEL, IBAN, cards), injection patterns and exploit signatures before they cross a boundary — then redacts or blocks. |
| **Hybrid defense** | Fast deterministic controls run on every request in microseconds. Only traffic they flag is escalated to an AI judge, so clean requests pay nothing. |
| **One policy** | A single TOML control catalog defines controls, actions, fail modes, model allow lists, pricing, risk and runaway-agent limits, MCP servers and resource grants. Uploads are validated and hot-swapped without a restart. |
| **Budgets & identity** | Per-identity API keys, deny-by-default model/tool grants, token and USD budgets per user. |
| **Human in the loop** | An agent can ask for a tool or table it wasn't granted; the request pops up in the console for a human to approve or deny. |
| **Know why it happened** | Every decision references the policy version and control behind it, in a hash-chained audit log. |

The four control boundaries: **01** prompts · **02** model responses ·
**03** tool calls · **04** tool results.

## Architecture

```
 users / agents ──► Cogut gateway ──► LLMs (OpenAI-compatible)
                     │   ├─ deterministic tier (regex, signatures, budgets, allow lists)
                     │   ├─ semantic tier (LLM judge, only when escalated)
                     │   └─ MCP proxy ──► upstream MCP servers / protected resources
                     ▼
              Supabase Postgres  ◄── SecOps console (Next.js, read-only on gateway tables)
       (policy versions, events, detections, budgets, hash-chained audit log)
```

| Path | What |
|---|---|
| [`gateway/`](gateway) | Rust (`axum`, `tokio`, `sqlx`) — proxy, policy engine, deterministic + semantic tiers, MCP proxy, audit writer, admin API |
| [`web/`](web) | Next.js — the SecOps console and the security assistant chat |
| [`policy/`](policy) | The sample TOML control catalog and attack-signature feed (seeded on first start) |
| [`mcp-demo/`](mcp-demo) | A deliberately vulnerable MCP server for the demo — **never deploy it next to real workloads** |
| [`supabase/migrations/`](supabase/migrations) | The one schema timeline shared by the gateway and the console |
| [`report/`](report) | Typst template for the PDF security report |
| [`docs/`](docs) | Challenge brief, backend spec, deployment guide, architecture explorer |

Full spec: [`docs/BACKEND.md`](docs/BACKEND.md).

## The console

The SecOps console (`web/`) is where the security team works. It reads the
audit data through the Supabase Data API as the signed-in user and changes
gateway state only through the gateway's admin API.

- **Overview** — requests, blocks, intervention rate, latency, highest-risk users
- **Activity** — every intercepted request, filterable by user/status/verdict, exportable to PDF
- **Gateway** — live health, 24h metrics, audit-chain status, enforced policy
- **MCP** — tool calls, results and agents' access requests
- **Controls & policies** — the active catalog (upload a `.toml` to replace it, or edit single controls), budgets, resource access, versions, signatures
- **User risk**, **Team** (roles: admin, analyst, viewer, developer), **Models** (LLM connections, default model), **Resources** (shared files on Supabase Storage)
- **Assistant** — a security chat that goes through the gateway, with file attachments; developers get a chat-only view

Light and dark themes, styled after the landing page.

## Quick start

Prerequisites: [`just`](https://github.com/casey/just), Rust (stable),
Node.js + [`pnpm`](https://pnpm.io), and a Supabase project.

```bash
cp .env.example .env              # gateway settings
cp web/.env.example web/.env.local # console settings
just setup                         # install dependencies
just migrate                       # apply supabase/migrations/
just seed                          # demo identities and budgets
just dev                           # gateway on :8080 + console on :3000
```

In `dev` the gateway needs no model: the chat upstream (`UPSTREAM_URL=mock`)
and the semantic judge (`OLLAMA_URL=mock`) are deterministic mocks. `prod`
refuses to start with a mock.

For the console demo, set `DEMO_ADMIN_LOGIN=true` (plus `DEMO_ADMIN_EMAIL` /
`DEMO_ADMIN_PASSWORD` of an existing admin) to show a one-click
**Log in as admin** button on the sign-in page.

## Commands

Everything runs through `just` — the recipes are the contract.

| Command | What |
|---|---|
| `just setup` | install dependencies |
| `just check` | typecheck + lint + test — **the definition of done** |
| `just dev` | gateway + console locally (`just dev-api` / `just dev-web` for one) |
| `just demo` | gateway + the vulnerable `mcp-demo` server |
| `just fmt` | rustfmt + prettier |
| `just migrate` | apply new Supabase migrations (`--dry-run` to preview) |
| `just db-new <name>` | new migration file |
| `just seed` | load demo data |
| `just report` | render the PDF security report (needs `DATABASE_URL`, `typst`) |
| `just verify-audit` | prove the audit hash chain is intact |
| `just deploy` | ship the gateway to Cloud Run (runs `just check` first) |
| `just wt <name>` / `just wt-rm <name>` | isolated worktree + branch with its own port |

## Gateway API

Integrate by changing a base URL — callers authenticate with a per-identity
key (`Authorization: Bearer <key>`).

| Endpoint | |
|---|---|
| `POST /v1/chat/completions` | OpenAI-compatible chat — hooks `prompt_in`, `response_out` |
| `POST /mcp` | MCP proxy — hooks `tool_call`, `tool_result` |
| `GET /v1/results/{id}` | rows a resource query delivered to the user (never to the model) |
| `GET /health` · `GET /` | liveness and service info |
| `GET /policy` · `GET /metrics` | enforced policy and 24h report (console) |
| `POST /admin/policy` · `GET /admin/policy/versions` | upload a catalog, version history |
| `GET/PUT /admin/budgets` · `GET /admin/risk` · `GET /admin/audit/export` | budgets, user risk, audit export (JSON/CSV) |
| `GET /admin/approvals/stream` · `POST /admin/approvals/{id}` | human approval of access requests |
| `GET /openapi.json` · `GET /admin/docs` | OpenAPI document and Swagger UI |

## Deployment

The gateway ships to Google Cloud Run from a `cargo-chef` Dockerfile with
`just deploy`; the console builds from `web/Dockerfile`. One-time setup and
secrets: [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Working in this repo

- `just check` must be green before anything is done.
- Never commit secrets — add new keys to `.env.example` with an empty value.
- Change the schema only with a migration in `supabase/migrations/`; RLS stays on
  for every table; run the Supabase advisors after schema changes.
- More house rules for humans and agents: [`CLAUDE.md`](CLAUDE.md).
- Demo script: [`DEMO.md`](DEMO.md).

## Tech

Rust · axum · sqlx · MCP · Next.js · React · Tailwind CSS · Supabase (Postgres,
Auth, Storage) · Docker · Google Cloud Run · Typst

## License

MIT, as declared in [`Cargo.toml`](Cargo.toml). Built at HackYeah 2026.
*Ambitious agents. Intentional boundaries.*

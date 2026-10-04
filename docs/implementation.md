# 5 · Implementation

## Code

The code stays at the repository root, where the Cargo workspace, the Dockerfiles,
Cloud Build and CI expect it; `5-implementation/` holds symlinks to it. The map:

| Path | Language | What |
|---|---|---|
| [`gateway/`](../gateway) | Rust (`axum`, `tokio`, `sqlx`) | The control layer: OpenAI-compatible proxy, MCP proxy, policy engine, deterministic and semantic tiers, budgets, approvals, audit writer, admin API, PDF report and audit verifier binaries |
| [`gateway/src/engine/`](../gateway/src/engine) | Rust | Evaluates a hook against the catalog: detections, redaction, escalation, verdict |
| [`gateway/src/policy/`](../gateway/src/policy) | Rust | Catalog parsing, validation, profiles, diffs, hot-swap handle, signature feed |
| [`gateway/src/semantic/`](../gateway/src/semantic) | Rust | LLM-judge detector (Ollama) and the dev mock |
| [`gateway/src/mcp/`](../gateway/src/mcp) | Rust | MCP federation, tool pinning, runaway guard, resource tools |
| [`gateway/src/proxy/`](../gateway/src/proxy) | Rust | Chat completions, streaming inspection, agent tool loop |
| [`gateway/src/budget.rs`](../gateway/src/budget.rs), [`risk.rs`](../gateway/src/risk.rs), [`audit.rs`](../gateway/src/audit.rs) | Rust | Budgets, per-identity risk, hash-chained audit |
| [`web/`](../web) | TypeScript (Next.js) | SecOps console and the security assistant chat |
| [`policy/`](../policy) | TOML | Sample control catalog and attack-signature feed |
| [`supabase/migrations/`](../supabase/migrations) | SQL | One schema timeline for gateway and console; RLS on every table |
| [`mcp-demo/`](../mcp-demo) | Rust | A deliberately vulnerable MCP server (poisoned documents) for the demo |
| [`report/`](../report) | Typst | PDF security report template |
| [`justfile`](../justfile) | just | Every command: `setup`, `check`, `dev`, `demo`, `seed`, `report`, `verify-audit`, `deploy` |

Full backend specification: [`BACKEND.md`](BACKEND.md). Prior art and
component choices: [`prior-art.md`](prior-art.md).

## Implementation considerations

- **Text-level enforcement at four hooks.** Every boundary reduces to "inspect this
  text at this hook", so a single engine guards prompts, answers, tool arguments and
  tool results, and a control declares which hooks it applies to.
- **Order matters.** Controls run in catalog order and a redaction rewrites the text
  the next control sees, so secrets run before PII (a loose phone regex must not
  consume half an IBAN). Block always beats redact, whatever the order.
- **The audit log is not a copy of what it protects.** Evidence stores a masked
  excerpt, never the matched secret.
- **Configuration typos never take the layer offline.** Unknown keys, bad regexes
  and out-of-range thresholds reject the upload; the last good version keeps serving.
- **Streaming is inspected, not bypassed.** Deltas are buffered with a held-back
  tail so a value split across chunks is caught before it is sent; a late block
  retracts the answer.
- **Known limits.** `pii.contextual` (Presidio) ships disabled; concurrency budgets
  count per instance, not fleet-wide; the `balanced` and `strict` profiles currently
  share defaults.

## Deploying into an existing agentic ecosystem

The gateway is a drop-in intermediary — integrating is a configuration change, not a
code change.

| Integration | How |
|---|---|
| **App / agent → LLM** | Point any OpenAI-compatible client at the gateway: `base_url = https://<gateway>/v1`, `api_key = <per-identity key>`. Works with the OpenAI SDKs, LangChain, LlamaIndex, CrewAI, AutoGen, Vercel AI SDK, etc. The gateway forwards to the real upstream (`UPSTREAM_URL`: Ollama, vLLM, or a commercial API). |
| **Agent → MCP servers** | Register the gateway as the agent's **only** MCP server (`https://<gateway>/mcp`). Upstream MCP servers are listed in the catalog's `[[mcp.server]]` and federated as `<server>__<tool>`; agents never reach them directly. Works with any MCP client (Claude Desktop/Code, Cursor, custom agents). |
| **Agent → data** | Expose tables through the built-in `resources__describe` / `resources__query` tools with per-identity grants, instead of handing agents database credentials. |
| **Multi-user apps** | A delegating principal (e.g. an internal chat app) names the end user in `X-On-Behalf-Of`, so budgets, risk and audit follow the person. |
| **Identities** | One `principals` row per agent/app: hashed API key, allowed models, granted and requestable tools. Deny by default. |
| **Policy as code** | Keep the catalog TOML in Git and `POST /admin/policy` from CI; every instance converges in ≤ 5 s, versions and diffs are kept. |
| **Signature feed** | An external threat-intel system publishes `signatures.toml`; it is uploaded with the catalog and versioned with it. |
| **SIEM / monitoring** | Scrape `GET /metrics/prometheus`; pull `GET /admin/audit/export` (JSON/CSV) into Splunk, Sentinel, Elastic. |

### Running it

| Where | How |
|---|---|
| Local | `just setup && just migrate && just seed && just dev` — gateway on `:8080`, console on `:3000`; mocks for the model and judge, no GPU needed. See the root [`README.md`](../README.md). |
| Cloud Run | `just deploy` — `cargo-chef` [`Dockerfile`](../Dockerfile) + [`cloudbuild.yaml`](../cloudbuild.yaml); console from [`web/Dockerfile`](../web/Dockerfile). One-time setup: [`DEPLOY.md`](DEPLOY.md). |
| Kubernetes / any container platform | The same image; configuration is environment only (`DATABASE_URL`, `UPSTREAM_URL`, `OLLAMA_URL`, see [`.env.example`](../.env.example)). Stateless — scale horizontally; policy and audit live in Postgres. |
| Production model | `OLLAMA_URL` → a reachable Ollama for the semantic judge; `prod` refuses to start with a mock, and without a reachable judge semantic controls fail closed. |

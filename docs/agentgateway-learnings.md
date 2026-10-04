# What to take from agentgateway

A review of [agentgateway](https://github.com/agentgateway/agentgateway) (commit `61dd06b`,
2026-10-02, ~211k lines of Rust) against our gateway. `docs/prior-art.md` already decided
**not to fork it**. This document lists the ideas worth porting into our own code, ranked
by how much they move the score in `docs/task.md` §8 for the hours they cost.

Paths starting with `crates/`, `examples/`, `ui/` or `schema/` are in agentgateway. All
other paths are in this repo.

## Summary

| # | idea | what it gets us | §8 criterion | effort |
|---|---|---|---|---|
| 1 | Record fail-open as an outcome, not as silence | an outage that bypasses a control shows up in the audit log | robustness, reporting | S |
| 2 | Shadow (`audit`) mode per control | judges can tighten a control and see "would have blocked N" without breaking traffic | robustness, reporting | M (migration) |
| 3 | Policy dry-run and load-time lint warnings | a judge's edit is checked and diffed before it goes live | practical, robustness | S–M |
| 4 | `Retry-After` and `x-ratelimit-*` on budget refusals | well-behaved clients back off instead of retrying in a loop | robustness (budgets) | S |
| 5 | Per-control and GenAI metrics | test and telemetry reporting per control, with token, cost and TTFT metrics | architecture & perf, reporting | S |
| 6 | Data-driven validators for PII (`luhn`, `pesel`, `iban`) | fewer false positives on `pii.pesel`, `pii.iban` and `pii.phone` | robustness | M |
| 7 | Per-event decision trace (every control evaluated, µs each) | "why was this allowed?" is answerable in the console | reporting, architecture & perf | M |
| 8 | Async batched audit writer | the request path stops waiting on a DB round trip | architecture & perf | M |
| 9 | Fault-injecting mock judge (`mock-fail`, `mock-slow`) | `just check` proves `fail_mode` and `timeout_ms` per control | test suite | S |
| 10 | Client-setup snippets page | shows the "change one base URL" integration story | practical | S |
| 11 | JSON Schema for the catalog | editor autocomplete and validation for the TOML | practical | M (new dep) |
| 12 | Soft budget can downgrade to a cheaper model | budgets do more than warn or block | robustness (budgets) | M |

Do 1, 3, 4, 5 and 9 first: each is a few hours and touches only `gateway/`. Item 2 has the
biggest demo payoff but needs a migration.

---

## 1. Record fail-open as an outcome

**agentgateway.** Every guard result is one of `None | Masked | Rejected | Audit | FailOpen`
(`crates/agentgateway/src/llm/policy/mod.rs:342`). The source comment on `FailOpen`: *"request
is allowed through but must be recorded as `FailOpen`, not `Allow`."* It has its own metric
label (`guardrail_checks_total{action="fail_open"}`) and a test
(`webhook_fail_open_emits_single_metric` in `crates/agentgateway/src/llm/policy/tests.rs`).

**Us.** `gateway/src/engine/mod.rs:287`: `FailMode::Open` only calls `tracing::warn!`. The
event is written with no detection, so the console shows the request as `secure`. The
synchronous path doesn't count the judge failure in `gateway_dependency_calls_total` either;
only the async path does (`gateway/src/background.rs:53`). That
contradicts the spec ("fails according to policy … and reports the outage"). It is also the
first thing a security judge tries: stop Ollama, send an injection, look at the log.

**Do.** In the `FailMode::Open` arm, push a `Detection` with id `<control>.unavailable`,
`action: Flag` and the error as excerpt. Flag does not change the verdict but makes the event
status `flagged`. Then add a `gateway_fail_open_total{control=...}` counter and call
`telemetry.dependency(detector, false)` on this path. Add a test next to the existing
`fail_mode = "open"` cases in `gateway/src/engine/tests.rs` (around line 242).

## 2. Shadow (`audit`) mode per control

**agentgateway.** Every guard takes `action: Audit`. In their words: *"Observe mode: record
what the guard would have done (metrics + structured log) but never block or mask — the
content always passes through"* (`crates/agentgateway/src/llm/policy/mod.rs:2335`). Guards
that can't mask get `RejectAuditAction { Reject, Audit }`. Tests:
`audit_mode_records_audit_and_passes_through_on_match` and
`audit_mode_records_allow_when_nothing_matches`.

**Us.** `Action` is `allow | flag | redact | block` (`gateway/src/policy/mod.rs:56`). Neither
`allow` nor `flag` records what the control *would* have done:

- `allow` records the match as `allow`.
- `flag` escalates to the semantic tier and adds to the user's risk score, so it changes
  behaviour.

**Do.** Add `shadow = true` to deterministic and semantic controls. A shadowed control is
evaluated normally and its detection is written with its real action plus `enforced = false`.
It does not change the verdict or the risk score. In the console:

- the controls page shows a "shadow" badge
- the dashboard shows "would have blocked N in the last hour"

This is the story judges want for §6 ("adjust thresholds, see how the layer behaves"). Lower
the threshold in shadow, watch the hit count, then enforce.

`control_action` is a Postgres enum (`supabase/migrations/20261003192000_baseline.sql:212`), so
this needs a migration. Add a boolean `enforced` column to `detections` rather than a new enum
value, so existing queries keep working.

## 3. Policy dry-run and load-time lint warnings

**agentgateway.**

- `McpGuardrails::load_warnings()` (`crates/agentgateway/src/mcp/guardrails/mod.rs:97`) flags
  config that parses but can never take effect, such as a method pattern that can never match.
- `de_content_scope` (`crates/agentgateway/src/llm/policy/mod.rs:1977`) rejects an empty scope
  because it *"effectively disables the guard"*.
- The UI validates the config against the generated JSON Schema before it saves
  (`ui/src/configValidation.ts`).

**Us.** Unknown keys are rejected, which is good. But `POST /admin/policy` is the only path, and
it activates on success. A judge sees the diff only *after* the change is live.

**Do.** Add `POST /admin/policy/validate`. It compiles the upload exactly like
`upload_policy`, returns `{ errors, warnings, diff }` and stores nothing. In the console, the TOML
editor gets a *Validate* button that shows the diff and warnings before *Activate*. Warnings
worth computing:

- **Every request would fail closed.** An enabled semantic control has `escalate_when =
  "always"` and `fail_mode = "closed"`, and its detector isn't registered (the `pii.contextual` /
  Presidio trap that the catalog comment warns about).
- **Redaction order is broken.** A `pii.*` control comes before a `secret.*` control on the same
  hook. The catalog's comment says redaction order matters (a loose pattern consumes a credential
  and leaves part of it in the clear), but only a comment enforces it.
- **A regex matches the empty string.** It would match every request.
- **A control can never run.** It is enabled with no hooks, or its hooks are ones its kind
  can't run on.
- **A grant points at nothing.** A `[resources.grants]` entry names a principal or table that
  doesn't exist.

## 4. `Retry-After` and `x-ratelimit-*` on budget refusals

**agentgateway.** The local rate limiter returns the tightest bucket on every response
(`x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset`) and sets `Retry-After` on a
429 (`crates/agentgateway/src/proxy/mod.rs:531`). `BudgetExceeded` carries `retry_after`
(`crates/agentgateway/src/http/budget/mod.rs:291`).

**Us.** `budget_exceeded` is a bare 429 (`gateway/src/proxy.rs:373`).

**Do.** On a budget refusal, compute the seconds until the oldest usage leaves the window and
set `Retry-After`. On every response, set `x-ratelimit-*` from the budget closest to its limit.
OpenAI SDKs honour `Retry-After`, so a runaway agent backs off instead of spinning. That is the
§1 "runaway execution loops" risk handled at the protocol level as well as the policy level.

## 5. Per-control and GenAI metrics

**agentgateway** (`schema/metrics.md`) has these metrics:

- `guardrail_checks_total{phase,action}`
- `gen_ai_client_token_usage`
- `gen_ai_client_cost_usd_total`
- `gen_ai_server_time_to_first_token`
- `gen_ai_server_time_per_output_token`
- `config_synchronized`
- `build_info`
- `requests_shed_total`

**Us** (`gateway/src/telemetry.rs`). We already have stage latency p50/p95/p99, verdicts per
hook, dependency availability and semantic queue depth. We are missing:

- `gateway_control_hits_total{control,action}`: the live version of "report results per control"
  (spec §self-testing) and the dashboard's top-controls card
- `gateway_policy_version` (gauge) and `gateway_policy_reloads_total{outcome}`: proof that a
  catalog edit landed on every instance
- `gateway_tokens_total{model,direction}` and `gateway_cost_usd_total{model}`
- a `ttft` stage for streamed answers: the latency users actually feel, and the one our
  256-byte hold-back adds to

Each is one or two `count()`/`observe()` calls on paths we already have.

## 6. Data-driven validators for PII

**agentgateway.** `crates/agentgateway/src/llm/policy/pii/` is a Rust port of Presidio's
recognizers. Each one combines:

- patterns with a base score
- context words (e.g. `card`, `visa`)
- a checksum validator: `luhn_checksum_is_valid` (`credit_card_recognizer.rs:73`) filters
  regex hits

**Us.** Luhn is special-cased by control id: `control.id != "pii.payment-card" ||
luhn_valid(matched)` (`gateway/src/engine/mod.rs:195`). `pii.pesel` (`\b[0-9]{11}\b`) matches any
11-digit run. `pii.iban` has no mod-97 check. The catalog documents that `pii.phone` over-matches
dates and IPs.

**Do.** Add a catalog field `validator = "luhn" | "pesel" | "iban" | "nip"` that the engine looks
up in a small table of pure functions, and drop the id check. Optionally add `context = [...]`:
a match counts only when one of the words is within N characters. A security team can then add a
checksummed identifier without a code change. These are pure functions with real edge cases,
which is exactly what our testing policy says to test.

## 7. Per-event decision trace

**agentgateway.** `POST /debug/trace?expression=<CEL>&follow=30s` on the admin port streams over
SSE every processing stage of the next matching requests, including body snapshots
(`crates/agentgateway/src/proxy/dtrace.rs`, `crates/agentgateway/src/management/admin.rs:366`).

**Us.** `activity/[id]` shows the detections, meaning what matched. It can't answer "which
controls ran, and why didn't X fire?"

**Do.** We don't need live SSE, because Supabase Realtime already delivers events. Have
`engine::evaluate` return a compact trace: for each hook, the control ids evaluated, whether
each matched, and µs per control. Store it in the event payload and render it as a waterfall
on `activity/[id]`. It answers a judge's ad-hoc prompt ("why did this get through?") from the
console. It is also a per-control performance profile for §6 telemetry.

## 8. Async batched audit writer

**agentgateway** (`crates/agentgateway/src/telemetry/log_store.rs`). Request logs go into a
channel. A dedicated writer thread batches them into Postgres with `COPY` (`copy_in_raw`), and
a backlog counter (`REQUEST_LOG_STORE_BACKLOG`) shows how far behind it is. The request path
never waits on the database.

**Us.** `Auditor::record` takes the chain mutex and awaits the insert on the request path:
`gateway/src/proxy.rs:294`, `gateway/src/mcp/mod.rs:243`, `gateway/src/mcp/mod.rs:325` and others.
Every request pays at least one DB round trip, and under load they serialize on the mutex.

**Do.** Keep the hash chain, which already has a single owner. Move hashing and inserting into
one writer task fed by an `mpsc` channel, and batch inserts (multi-row `INSERT`) every few ms or
N events. `trace_id` is generated up front already, so callers don't need the row id back.
Flush on shutdown and expose `gateway_audit_backlog`. Measure `total` p95 before and after.
That number goes on the architecture slide.

## 9. Fault-injecting mock judge

**agentgateway.** The `examples/fault-injection` example uses `directResponse` with a CEL
`random() < 0.1` condition to inject aborts, and `delay` to inject latency. They test failure
handling deliberately.

**Us.** `Registry::empty()` (`gateway/src/semantic/mod.rs:120`) covers "detector missing". We
have nothing for "detector errors" or "detector is slower than `timeout_ms`".

**Do.** Add two dev-only judges: `OLLAMA_URL=mock-fail` (every call errors) and `mock-slow`
(sleeps past the timeout). Like `mock`, prod refuses both. Then `just check` can prove for each
semantic control:

- closed blocks
- open passes and is recorded (see item 1)
- a slow detector is cut at `timeout_ms`

That is the §4.6 "negative case" for resilience, not just for content.

## 10. Client-setup snippets page

**agentgateway.** `ui/src/pages/ClientSetup.tsx` takes a model and an API key and gives
copy-paste setup for curl, OpenAI SDKs, Claude Code, Codex and Cursor.

**Us.** The spec promises that "existing clients only change a base URL", but the console never
shows it.

**Do.** Add a small console card or page with the gateway URL and snippets for curl
`/v1/chat/completions`, the Python `openai` SDK (`base_url=`), and an MCP client config for
`/mcp` with the Bearer header. This is the cheapest available evidence for §8 "practical
implementability".

## 11. JSON Schema for the catalog

**agentgateway.** It generates `schema/config.json` from its Rust types (`schemars`) and renders
`schema/config.md` from the same source. Every example config starts with
`# yaml-language-server: $schema=...`, which gives editors autocomplete and inline errors.

**Do (if time).** Derive `JsonSchema` on the catalog structs, emit `policy/catalog.schema.json`
from a `just` recipe, and add `#:schema ./catalog.schema.json` to the top of
`control-catalog.toml`. Taplo and the VS Code "Even Better TOML" extension pick it up. This adds
a dependency (`schemars`), so tell the team first.

## 12. Soft budget can downgrade to a cheaper model

**agentgateway.** `examples/llm-cost-routing` routes a virtual model (`smart-model`) to
economy, balanced or premium targets with CEL conditions on the request.

**Do (if time).** Add an optional `downgrade_to = "<model>"` on a budget row. Once a soft budget
is past its limit, the request is rewritten to that model, provided the user is granted it, and
the event records `budget.<scope>.<id>` as a flagged detection that names both models. This
shows budget governance that degrades gracefully instead of failing hard.

---

## Not worth adopting

- **The CEL policy engine.** It is their core, and they maintain a fork of the `cel` crate
  (`crates/cel-fork`). Our TOML + regex catalog, with grants in the database, covers the brief
  and is what judges will edit. `prior-art.md` already made this call.
- **xDS control plane, Kubernetes Gateway API, inference-pool routing.** Fleet infrastructure.
  Our 5-second DB poll already does fleet-wide hot reload.
- **Paid guardrail providers** (OpenAI moderation, Bedrock Guardrails, Model Armor, Azure
  Content Safety). Ruled out by §7.
- **Multi-provider format conversion** (`crates/llm`: Anthropic, Bedrock, Gemini, Vertex).
  We need OpenAI-compatible plus Ollama only.
- **A2A proxying, OAuth protected-resource metadata (RFC 9728), RFC 8693 token exchange.**
  These are the right production answers for agent-to-agent traffic and for delegation backed
  by a signed token instead of our trusted `X-On-Behalf-Of`. Name them on the architecture
  slide as the production path. Don't build them in 24 hours.
- **Windowed semantic checks on streams** (`streaming_guardrails.rs`: 1024-byte batches with
  256-byte overlap). This only pays off with a fast prod judge, and our final authoritative
  event already covers the full answer.
- **Fuzzing with `cargo-fuzz`** (`fuzz/`). Needs nightly, so it's not worth the toolchain
  churn today.

## Where we are already ahead

Use these in the pitch. agentgateway, the "closest single match" in `prior-art.md`, does not
have them:

- **Streaming that can retract.** agentgateway's streaming guard states that *"content flushed
  by earlier passing windows cannot be retracted — an accepted accuracy/latency tradeoff"*
  (`streaming_guardrails.rs:15`). We hold 256 bytes back for the deterministic pass. Our last SSE
  event is authoritative and can tell the client to retract.
- **A tamper-evident audit log.** Ours is hash-chained, with `just verify-audit`. Their request
  log is plain rows.
- **MCP tool pinning.** We approve each tool by the sha256 of its definition, so a rug-pull or
  a poisoned description is hidden. agentgateway has no equivalent.
- **An external attack-signature feed (§4.4)**, versioned with the catalog and mirrored for the
  dashboard. agentgateway has none.
- **Hybrid escalation.** The local judge runs only on suspicious traffic
  (`escalate_when = "suspicious"`). agentgateway calls an external guardrail on every request it
  is configured for.
- **Attack-history risk score** that gates the user's next requests.
- **Protected rows never reach the model** (`resources__query` pushes rows to the user, and the
  LLM gets an acknowledgement).
- **On par:** federated tool namespacing (`docs__read` vs their `docs_read`), deny-by-default
  MCP methods, and the `Mcp-Method` header/body mismatch check.

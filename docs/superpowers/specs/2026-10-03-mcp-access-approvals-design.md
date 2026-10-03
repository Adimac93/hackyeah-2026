# MCP policy tools + human-approved access requests (SSE popup)

## Context

Today the gateway's `/mcp` endpoint (`gateway/src/mcp/mod.rs`) only federates upstream
servers (`mcp-demo` = `docs__search`, `docs__read`) and gates each call on the
principal's static `allowed_tools`. An agent cannot learn what policy governs it, and a
missing tool is a dead end. We add gateway-native MCP tools so the LLM can (1) read
policy details about itself and (2) ask for a missing tool. The ask blocks the tool call
and pops a modal in the SecOps console (pushed over SSE); a security team member
approves/denies; the agent gets the answer in the same `tools/call` and, if granted, can
call the tool for a time-boxed window. Every request/decision is audited.

Agreed decisions: approver = SecOps console team (admin/analyst decide, viewer sees
read-only); resource = federated MCP tool not in `allowed_tools`; LLM blocks until
decided (120 s timeout); transport = SSE from gateway, proxied by Next.js server.

## Work setup

`just wt mcp-approvals` → work in that worktree (never primary checkout). Spec content
below also gets committed as `docs/superpowers/specs/2026-10-03-mcp-access-approvals-design.md`.

**Dependency note (tell team):** add `futures-util = "0.3"` to `gateway/Cargo.toml`
(already in `Cargo.lock` transitively, v0.3.34 — only the gateway's dep list changes) for
`stream::unfold` to build the SSE stream. Add `"sync", "time"` to workspace tokio
features in root `Cargo.toml` (already compiled in via unification; makes it explicit).
No new web deps.

## 1. Migration — `just db-new mcp_access_requests`

```sql
create type access_status as enum ('pending','approved','denied','expired');
create table access_requests (
  id uuid primary key default gen_random_uuid(),
  principal_id uuid not null references principals(id),
  tool text not null,
  reason text not null,              -- post-control (possibly redacted) text
  ttl_minutes int not null default 15,
  status access_status not null default 'pending',
  requested_at timestamptz not null default now(),
  decided_at timestamptz, decided_by text, note text,
  expires_at timestamptz             -- set on approve
);
create index access_requests_grants_idx on access_requests (principal_id, tool) where status = 'approved';
alter table access_requests enable row level security;
create policy "security team reads access requests" on public.access_requests
  for select to authenticated using (public.is_team_member());   -- match pattern in 20261003171926_gateway_rls_team_only.sql
```
No write policies (gateway writes via privileged connection). Run `supabase db advisors` after.

Seed (`supabase/seed.sql`): add principal `secops-console` (role `security_admin`, no
tools/models) whose key the web server uses as `GATEWAY_ADMIN_KEY`; follow how existing
demo keys are documented in `DEMO.md`. `red-team` (has only `docs__search`) is the demo
requester for `docs__read`.

## 2. Gateway

### New module `gateway/src/approvals/{mod.rs,tests.rs}` (register in `lib.rs`)

- `Approvals { db: Option<PgPool>, pending: Mutex<HashMap<Uuid, PendingEntry>>, events: broadcast::Sender<ApprovalEvent> }`
  - `PendingEntry { request: AccessRequest, tx: oneshot::Sender<Decision> }`
  - `ApprovalEvent::{Request(AccessRequest), Decided{id,status}, Expired{id}}` (serde, `type` tag)
- `async fn boot_sweep()` — `update access_requests set status='expired' where status='pending'`.
- `async fn has_grant(principal_id, tool) -> Result<bool>` — `status='approved' and expires_at > now()`. DB missing → `Err` (caller fails closed).
- `async fn active_grants(principal_id)` — for `my_access`.
- `async fn request(principal, tool, reason, ttl) -> Outcome` — admit (rate limit), insert row, insert into map, broadcast `Request`, `tokio::time::timeout(120s, rx)`. A `PendingGuard` (Drop) removes the map entry and, if still pending, spawns an update to `expired` + broadcasts `Expired` — covers agent disconnect and timeout.
- `async fn decide(id, approve, ttl, note, decided_by) -> Result<(), DecideError>` — remove from map (missing → `Conflict` 409), update row (`expires_at = now() + ttl` on approve), send on oneshot, broadcast `Decided`.
- `fn snapshot()` — current pending list (SSE replay on connect).
- `fn subscribe()`.
- Pure helpers (unit-tested): `clamp_ttl(Option<u32>) -> u32` (default 15, 1..=60);
  `admit(&pending, principal_id, tool) -> Result<(), Refusal>` (1 per principal+tool, 5 per principal);
  `validate_target(policy, principal, tool) -> Target::{Requestable, AlreadyPermitted, Refused(msg)}`
  (refuse `control__*`, unknown server, malformed name; `AlreadyPermitted` if `allowed_tools`
  empty or contains it).

### `gateway/src/mcp/` changes

- New `gateway/src/mcp/native.rs`: tool descriptors + handlers for
  - `control__list_controls` — `public_controls(&Policy) -> Value`: from
    `policy.deterministic`, `policy.semantic`, `policy.signature_controls` emit
    `{id, kind, hooks, severity, action}` (+ `describes` for semantic). **Never** regex,
    threshold, mock_keywords, feed internals. Pure → unit test asserts no regex/threshold leak.
  - `control__my_access` — slug, allowed_tools, allowed_models, budget limits + usage
    (reuse `Auditor::usage_in_window` and `policy.budgets`), active grants, requestable
    tools (federated listing minus permitted).
  - `control__request_access {tool, reason, ttl_minutes?}` — `validate_target`; run
    `reason` through `engine::evaluate` + `engine::escalate` with `Hook::ToolCall`
    (same as `tools_call` at `mod.rs:215`); Block → refuse, no popup; Redact → use
    redacted text; then `approvals.request(...)`. Returns `{status, expires_at?, note?}`
    as MCP text content (JSON string) via existing `result()`.
- `mod.rs`:
  - `McpState` gains `approvals: Arc<Approvals>`.
  - `tools_list`: append native descriptors after the `allowed_tools` retain filter (always visible).
  - `tools_call`: if name starts with `control__` → dispatch to `native` before the
    `allowed_tools` check. Otherwise, when `allowed_tools` non-empty and lacks the tool,
    consult `approvals.has_grant` (Err → `POLICY_DENIED "approvals unavailable"`) before denying.
  - Audit: request and decision each write an event via `audit::record_for(... Hook::ToolCall ...)`
    with `channel="mcp"`, `tool=Some("control__request_access")` (reuse existing pattern at `mod.rs:219-231`).
  - Reserve server name `control`: reject in `policy/mcp.rs` validation (or `Policy::load`) with a clear error.

### `gateway/src/main.rs`

- Build `Arc<Approvals>` from existing `db`; call `boot_sweep()`.
- Routes (with `AppState` gaining `approvals`):
  - `GET /admin/approvals/stream` — `security_admin()` (main.rs:559) gate; `Sse` with
    replay of `snapshot()` then `futures_util::stream::unfold` over the broadcast receiver
    (skip `Lagged`), `KeepAlive::default()`.
  - `POST /admin/approvals/{id}` body `{decision:"approve"|"deny", ttl_minutes?, note?, decided_by}` —
    `security_admin()` gate; 200 / 404 / 409.
- Add both to the `index`/`openapi` endpoint lists.

## 3. Web (`web/`)

- `.env.example`: `GATEWAY_ADMIN_KEY=` (server-only).
- `src/lib/approvals.ts` (+ `approvals.test.ts`): `ApprovalEvent` types, `parseApprovalEvent(data)`
  validator, `applyEvent(queue, event)` reducer (pure → tested).
- `src/app/api/approvals/stream/route.ts`: `GET`; `getSession()` from `lib/auth.ts`,
  require `canAccessConsole(member.role)` else 403; `fetch(GATEWAY_URL + "/admin/approvals/stream", {headers:{authorization:"Bearer "+GATEWAY_ADMIN_KEY}, signal: request.signal})`;
  return `new Response(upstream.body, {headers: {"content-type":"text/event-stream","cache-control":"no-cache"}})`.
  `export const dynamic = "force-dynamic"`.
- `src/app/(admin)/approvals/actions.ts`: `"use server"` `decideAccess(id, decision, ttl, note)` —
  `requireWriter()` (lib/auth.ts), POST to gateway with `decided_by = user.email`; return `{error}` on 409.
- `src/components/approval-popup.tsx` (`"use client"`): `EventSource("/api/approvals/stream")`,
  queue via `applyEvent`, modal over page: principal, tool, reason (text, never HTML),
  countdown, TTL select (5/15/30/60), note, Approve/Deny (hidden when `!canWrite`), title flash.
  Reuse styles from `components/ui.tsx`.
- `src/app/(admin)/layout.tsx`: render `<ApprovalPopup canDecide={canWrite(member.role)} />`
  only when `hasConsole`.

## 4. Docs

- `DEMO.md`: new step — red-team agent calls `docs__read` → denied → `control__request_access`
  → popup → Approve → retry succeeds; reading `onboarding` still blocked by `tool_result`
  controls (permission and inspection stack).
- `docs/DEPLOY.md`: gateway must run `--max-instances=1` (pending approvals live in memory);
  web needs `GATEWAY_ADMIN_KEY`.
- `docs/BACKEND.md` MCP section: one paragraph on native tools + approvals.

## Verification

1. `just check` green (paste output) — includes new Rust tests in
   `gateway/src/approvals/tests.rs`, `gateway/src/mcp/tests.rs` (public_controls leak test,
   validate_target, clamp_ttl, admit) and `web/src/lib/approvals.test.ts`.
2. Smoke test (Rust, no DB): `Approvals::new(None)`-style in-memory path — spawn
   `request`, call `decide(approve)`, assert outcome `granted`. If DB is required for
   insert, gate the insert so `db=None` still exercises map/oneshot/broadcast.
3. `just migrate` then `supabase db advisors` clean; `just seed`.
4. Manual E2E: `just demo` + `just dev-web`, log in as analyst, then:
   ```
   curl -s localhost:$PORT/mcp -H "authorization: Bearer <red-team key>" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"control__request_access","arguments":{"tool":"docs__read","reason":"need the Q3 summary"}}}'
   ```
   popup appears → Approve → curl returns `granted`; then `tools/call docs__read {id:"q3-summary"}` succeeds,
   `{id:"onboarding"}` blocked by injection control. Check `/activity` shows the events and
   `just verify-audit` passes.

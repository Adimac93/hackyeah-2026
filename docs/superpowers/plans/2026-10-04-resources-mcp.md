# Resources through MCP: implementation plan

Date: 2026-10-04. Implements `docs/superpowers/specs/2026-10-04-resources-mcp-design.md`
(the spec) against the code as it is on `main` at `30bf154`. Rules from `CLAUDE.md` apply:
one worktree per PR, everything through `just`, `just check` green before done, tell the
owners of `gateway/`, `policy/`, `supabase/migrations/` and `web/` before merging.

## Spec review: what the code changes about the spec

Reading the spec against the code turned up gaps. The plan below resolves each one this
way; fold these answers into the spec when it is next touched.

| # | Gap | Resolution in this plan |
|---|---|---|
| 1 | The spec routes the web flow through "the chat action". Chat now streams through `web/src/app/api/chat/route.ts` (NDJSON) and `callGateway` in `providers.ts` always sends `stream: true` with a 60 s *idle* timeout. An `"mcp": true` request is answered buffered, so nothing arrives for up to two minutes while an approval waits. | A separate buffered `callGatewayWithTools` with a 180 s *total* timeout. The route emits a new `tool_steps` stream event before `done`, so the browser renders steps without reloading. |
| 2 | `access_requests.tool` is `not null`; the spec sets `resource` "instead of tool". | Migration drops `not null` on `tool` and adds `check (num_nonnulls(tool, resource) = 1)`. |
| 3 | `end_user text not null` on `access_requests` and `resource_results` breaks existing rows. | Add nullable, backfill from `principals.slug`, then `set not null`. Expired `resource_results` rows are deleted first. |
| 4 | Grants are keyed by principal only (`Approvals::grants: HashMap<Uuid, Vec<Grant>>`, `has_grant(principal_id, tool)`). | `Grant` gains `end_user` and `target` (tool or table). Every lookup takes `(principal_id, end_user, target)`. Boot reload reads the new columns. |
| 5 | `validate_target` refuses anything that is not `server__tool` on an enabled server. It cannot validate a table. | New `validate_table` next to it, checked against `[resources.requestable]`. |
| 6 | The model is never told a table can be requested, so it cannot ask for one. | `resources__describe` with no `tables` lists granted *and* requestable tables. A refusal for a requestable table says "request it with control__request_access {table, reason}". |
| 7 | A table refusal is an upstream error (`UPSTREAM_ERROR`) after the `tool_call` event was already audited as allowed, so Activity shows nothing blocked. | A table refusal in `resource_call` is recorded as a `tool_result` block event with control `mcp.table-not-granted`. |
| 8 | `x_control_layer.tool_calls[]` has `tool`, `status`, `trace_id`, `result_id`, `content` but no `arguments`; the web step needs the SQL. | `agent.rs` adds `arguments` to each entry. |
| 9 | The dev mock plays describe → query only. The smoke test's access-request step cannot run in dev. | The mock reacts to a "request it with control__request_access" refusal by calling `control__request_access {table, reason}`, then retrying the query once on `granted`. |
| 10 | The approval popup renders `request.tool`. A table request has no tool. | `AccessRequest` gains `resource` and `end_user`; the popup shows "table customers for anna@…" when `resource` is set. |
| 11 | `seed.sql` truncates and re-inserts `resources.customers` with explicit ids 1–5, which would fight the generated data. | Delete that block from `seed.sql`. The migration owns the data. |
| 12 | `chat_messages.content` is capped by a check constraint; tool steps must not be folded into it. | Steps go in the new `tool_calls jsonb` column only. |

Out of scope stays as the spec says. Natural-language questions need a real model; in
`dev` the mock plays the flow only when the message contains a `SELECT`.

## PR layout

1. **PR A — schema** (`supabase/migrations/`, `supabase/seed.sql`). Tasks 1–3.
2. **PR B — gateway and catalog** (`gateway/`, `policy/`, docs). Tasks 4–12. Merge after A is
   applied.
3. **PR C — web** (`web/`). Tasks 13–17. Merge after B is live.

Each task ends with `just check`. Commit after each task.

---

## PR A — schema

### Task 1: `resources_reader` role, RLS, new tables and data

New migration: `just db-new resources_mcp`.

```sql
-- Least privilege for the resource tools: the gateway switches to this role
-- (`set local role`) inside every query transaction.
create role resources_reader nologin;
grant usage on schema resources to resources_reader;
grant select on all tables in schema resources to resources_reader;
alter default privileges in schema resources grant select on tables to resources_reader;
grant resources_reader to postgres;   -- the role in DATABASE_URL; `set role` needs membership

create table resources.products (...);        -- id, name, tier, price_usd
create table resources.subscriptions (...);   -- status check in ('active','cancelled','trial')
create table resources.support_tickets (...); -- priority, status, opened_at, closed_at

-- one RLS policy per table, for the reader only; anon/authenticated keep nothing
alter table resources.<t> enable row level security;
create policy "resources reader" on resources.<t> for select to resources_reader using (true);
```

Data in the same migration, deterministic: `select setseed(0.42);` then
`generate_series` inserts. Truncate `invoices, customers restart identity` first so the
five rows from the old seed are replaced. Sizes from the spec: 300 customers (PL, DE,
US, UK, FR), 8 products, 400 subscriptions, 1,200 invoices (`paid`, `overdue`, `void`,
`issued_at` spread over 18 months), 250 tickets. Names from two small arrays indexed by
`random()`; `email = lower(first || '.' || last || n || '@example.com')`; phones in the
`+48 6xx xxx xxx` shape so `pii.phone` fires.

Verify locally:

```bash
just migrate
psql "$DATABASE_URL" -c "set role resources_reader; select count(*) from resources.invoices"   # 1200
psql "$DATABASE_URL" -c "set role resources_reader; select * from public.principals"          # permission denied
```

If prod's `DATABASE_URL` logs in as a role other than `postgres`, grant membership to that
role instead; check with `select current_user` over the gateway's connection first.

### Task 2: columns for per-user grants and results

Same migration, after the data:

```sql
alter table access_requests alter column tool drop not null;
alter table access_requests add column resource text, add column end_user text;
update access_requests a set end_user = p.slug from principals p where p.id = a.principal_id;
alter table access_requests alter column end_user set not null,
  add constraint access_requests_one_target check (num_nonnulls(tool, resource) = 1);
drop index access_requests_grants_idx;
create index access_requests_grants_idx on access_requests (principal_id, end_user)
  where status = 'approved';

delete from resource_results where expires_at <= now();
alter table resource_results add column end_user text;
update resource_results r set end_user = p.slug from principals p where p.id = r.principal_id;
alter table resource_results alter column end_user set not null;

alter table chat_messages add column tool_calls jsonb;

-- console chat may use the resource tools (idempotent)
update principals
set allowed_tools = (select array_agg(distinct t) from unnest(
      allowed_tools || array['resources__describe', 'resources__query']) t)
where slug = 'console-chat';
```

`chat_messages` RLS already covers the new column; no policy change.

### Task 3: seed and advisors

- `supabase/seed.sql`: delete the `resources: protected demo data` block (truncate +
  inserts). Add the same idempotent `console-chat` tool grant as Task 2 to the
  principals section.
- `just migrate`, `just seed`, `supabase db advisors`: must stay clean. Paste the output in
  the PR.

---

## PR B — gateway and catalog

### Task 4: one pool, least-privilege role

- `gateway/src/main.rs:110-123`: delete the `RESOURCES_DATABASE_URL` block. Set
  `resources: Some(db.clone())` whenever the main pool exists (`state.rs` keeps the
  `Option<PgPool>` so a DB-less test state still disables the tools).
- `gateway/src/mcp/resources.rs::run`: the statement list becomes

  ```rust
  "set transaction read only",
  "set local role resources_reader",
  format!("set local statement_timeout = {}", ...),
  "set local search_path = resources",
  ```

  The plan check stays: the role is the second wall, not a replacement.
- `describe` keeps running as the gateway role: it reads only `information_schema.columns`
  for schema `resources`, filtered to tables the caller may see, and returns no values.
- Docs: drop `RESOURCES_DATABASE_URL` from `.env.example`, `docs/DEPLOY.md:132`,
  `docs/BACKEND.md:137` ("reached through the gateway's main connection, switched to the
  read-only `resources_reader` role per query") and `DEMO.md:40,96`.

### Task 5: `requestable` in the catalog

`gateway/src/policy/limits.rs`:

```rust
pub struct Resources {
    #[serde(default)] pub grants: BTreeMap<String, Vec<String>>,
    /// identity slug -> tables it may ask for through control__request_access
    #[serde(default)] pub requestable: BTreeMap<String, Vec<String>>,
    ...
}

impl Resources {
    pub fn requestable_for(&self, slug: &str) -> &[String] { ... }
}
```

Validation at load (same place other catalog checks fail the reload): a table listed in
both `grants` and `requestable` for one slug is an error.

`policy/control-catalog.toml`:

```toml
[resources.grants]
demo-agent = ["customers", "invoices"]
console-chat = ["products", "subscriptions", "invoices", "support_tickets"]

[resources.requestable]
console-chat = ["customers"]
```

Test (`policy/tests.rs`): parses `requestable`; a table in both lists fails the load.

### Task 6: per-user grants for tools and tables

`gateway/src/approvals/mod.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum Access { Tool(String), Table(String) }

pub struct Grant { pub access: Access, pub end_user: String, pub expires_at_ms: u64 }

pub struct AccessRequest { ..., pub access: Access, pub end_user: String, ... }
```

- `has_grant(principal_id, end_user, &Access) -> bool` and
  `active_grants(principal_id, end_user)`. Only the grant for this end user counts.
- `granted_tables(principal_id, end_user) -> Vec<String>` for the resource tools.
- `request(principal, access, reason, ttl)` writes `tool` or `resource` and `end_user`
  (`principal.user`) in the insert.
- `admit` keys open requests by `(principal_id, end_user, access)`; the per-principal cap
  stays.
- `boot` selects `tool, resource, end_user` and rebuilds `Access`.
- Serialize `AccessRequest` so the SSE event keeps a flat `tool` field for tool requests
  and adds `resource` and `end_user`. That keeps the current console working until PR C.

Call sites: `mcp/mod.rs:212` (`tools/call` gate) and `mcp/listing.rs:64` (`tools/list`)
pass `&principal.user` and `Access::Tool(name)`.

Tests (`approvals/tests.rs`): a grant for user A is not a grant for user B on the same
principal; an expired grant is gone; a second request for the same `(user, table)` is
refused while one waits, one for another user is admitted.

### Task 7: `control__request_access` takes `tool` or `table`

`gateway/src/mcp/native.rs`:

- Schema: `tool` and `table` both optional, `oneOf` required; description says tables
  come from `resources__describe`.
- Exactly one of them, else `Err("request_access takes exactly one of tool or table")`.
- New `approvals::validate_table(policy, principal, has_grant, table) -> Target`:
  `AlreadyPermitted` when in `grants` or granted; `Requestable` when in
  `requestable_for(slug)`; otherwise `Refused("table X cannot be requested")`.
- `my_access` adds `tables: { granted, requestable, temporary }` (temporary = live grants for
  this end user with expiry).

Tests: `validate_table` for all three outcomes; an argument with both or neither is
refused.

### Task 8: resource tools honour table grants and teach the model to ask

`gateway/src/mcp/mod.rs::resource_call` builds the effective table list:

```rust
let mut tables = policy.resources.tables_for(&principal.slug).to_vec();
tables.extend(state.approvals.granted_tables(principal.id, &principal.user));
let requestable = policy.resources.requestable_for(&principal.slug);
```

`resources::describe(pool, &tables, requestable, &wanted)`:

- no `wanted`: `tables: a, b\nrequestable (ask with control__request_access {table, reason}): customers\n`
- a wanted table that is requestable but not granted:
  `Err("table customers needs approval: call control__request_access {table: \"customers\", reason}")`

`resources::run` returns a typed error so the caller can tell a grant refusal from a SQL
error:

```rust
pub enum QueryError { NotGranted { table: String, requestable: bool }, Invalid(String) }
```

The `NotGranted` message carries the same hint when `requestable`.

Tests (extend `resources.rs` tests, no DB needed): describe lists requestable tables;
describe of a requestable table returns the hint; describe of an unknown table is the
plain refusal (no hint, so existence does not leak).

### Task 9: audit table refusals

In `resource_call`, on `QueryError::NotGranted` (and the describe refusal), record a
`tool_result` event with `verdict = Block` and a detection `mcp.table-not-granted`
(severity high, reason `"{slug} for {user} may not read resources.{table}"`) under the
call's `trace_id`, then return the error as today. Activity now shows the refusal next to
the allowed `tool_call` that preceded it.

### Task 10: results bound to the end user

`gateway/src/mcp/resources.rs`:

- `deliver` inserts `end_user = principal.user`.
- `result` selects `where id = $1 and principal_id = $2 and end_user = $3 and expires_at > now()`.
  `bearer_principal` already resolves `X-On-Behalf-Of` into `principal.user`.

Test: none in Rust beyond compile (it is one `where` clause); the smoke test in Task 18
covers it with a second user.

### Task 11: tool-loop report carries arguments

`gateway/src/proxy/agent.rs:91`: add `"arguments": call.arguments` to each
`tool_calls` entry. Extend the existing agent test to assert it.

### Task 12: the dev mock plays the access request

`gateway/src/mock.rs::script`, after a refused `resources__query` or `resources__describe`
whose text contains `control__request_access`, when `control__request_access` is offered:
`Step::Call("control__request_access", {"table": <table from the message>, "reason":
"The user asked: <first 120 chars of the question>"})`. After a `granted` result, retry
the original query once. After `denied`/`expired`/`refused`, answer with that outcome.

Tests (in `mock.rs`, like the existing ones): refused-with-hint → request; granted →
query; denied → plain answer.

Then: `just check`. Run `just dev` and the gateway half of the smoke test (Task 18) with
curl before opening PR B.

---

## PR C — web

### Task 13: buffered gateway call with tools

`web/src/lib/llm/providers.ts`:

- New `callGatewayWithTools(model, system, messages, principal)`: `stream: false`,
  `mcp: true`, `AbortSignal.timeout(180_000)`, same auth and `x-on-behalf-of` headers.
- Returns `{ reply, steps }`. For each `x_control_layer.tool_calls[]` with a `result_id`,
  `GET /v1/results/{id}` through `gatewayRequest` with the same two headers, in parallel.
  A failed fetch leaves the step without `result` and with `resultError: "result unavailable"`.
- `getAssistant` uses it for gateway models; direct providers keep their current path and
  get no tools. `AssistantProvider`'s return type grows to `{ reply: string; steps?: ToolStep[] }`
  (update the callers in `route.ts` and the mock provider).
- The gateway system prompt (`buildSystemPrompt` in `lib/assistant`) adds, for gateway
  models only: use the resource tools for questions about customers, invoices, products,
  subscriptions or tickets; never invent data; rows appear under the answer; if a table
  needs approval, request it with a one-sentence reason.

### Task 14: pure mapping, tested

New `web/src/lib/tool-steps.ts` (+ `tool-steps.test.ts`):

```ts
export interface ToolStep {
  tool: string;
  status: "ok" | "refused";
  summary: string;          // "SELECT … → 42 rows", "describe invoices", "requested customers → granted"
  arguments: unknown;
  result?: { columns: string[]; row_count: number; rows: Record<string, unknown>[] };
  resultError?: string;
}
export function toSteps(toolCalls: unknown): ToolStep[];
export function mergeResults(steps: ToolStep[], fetched: Map<string, Result | Error>): ToolStep[];
```

Tests: query/describe/request_access summaries; a refused call; a successful and a failed
result merge; malformed `tool_calls` yields `[]`.

### Task 15: stream and store the steps

- `web/src/lib/chat-stream.ts`: new event `{ type: "tool_steps"; steps: ToolStep[] }`
  (extend its test).
- `web/src/app/api/chat/route.ts`: while waiting for a gateway model, send
  `{ type: "status", text: "Working… (may be waiting for security approval)" }` once; after
  the reply, send `tool_steps` and insert `tool_calls: steps` with the assistant message.

### Task 16: render the steps

New client component `web/src/app/(admin)/chat/tool-steps.tsx`, used by `chat-history.tsx`
for messages with `tool_calls` and for the in-flight message:

- one collapsed line per step (`summary`, status icon), expanding to the SQL or arguments;
- a result as a table: sortable columns, row count, own horizontal scroll, `[REDACTED…]`
  markers left visible.

`page.tsx` selects `tool_calls` with the history.

### Task 17: approval popup for tables

`web/src/components/approval-popup.tsx`: when the event has `resource`, show
"table `customers`" and the end user instead of the tool name. Keep the tool rendering
unchanged otherwise.

`just check`.

---

## Task 18: smoke test and rollout

Smoke test, on `just dev` and on prod after deploy (keep it in `DEMO.md` as "Data
through MCP"):

1. As user A, ask (dev: `select * from invoices where status = 'overdue' and amount_usd > 500`)
   → steps show describe and query; a table under the answer; the model's turn holds only
   the row count.
2. As user A, ask about customer emails → `control__request_access {table: customers}` →
   popup shows the table and user A → approve.
3. The answer arrives with a table whose emails and phones are `[REDACTED:…]`.
4. As user B, the same customer question asks for approval again (the grant is per user),
   and `GET /v1/results/{A's id}` with B's `X-On-Behalf-Of` returns 404.
5. Activity shows every `tool_call`, the `mcp.table-not-granted` refusal and the approval.

Rollout, in order:

1. PR A merged → `just migrate` → `just seed` → `supabase db advisors` clean.
2. PR B merged → Cloud Build deploys the gateway → upload the catalog (`POST /admin/policy`
   or the console editor) → unset `RESOURCES_DATABASE_URL` on Cloud Run.
3. PR C merged after B is live.
4. Smoke test on prod; paste the result in PR C.
5. `TASKS.md`: move `web-results` to Done, mention the per-user grants.

## As built (2026-10-04)

Implemented on `claude/stoic-feynman-kll44u` as three commits (schema, gateway, web) rather
than three PRs. Differences from the plan above:

- **Task 13/15:** the provider input gained an `onSteps` callback instead of a new return
  type, so no other caller changed. The route sets it for gateway models only.
- **Found while smoke-testing, fixed in the gateway commit:**
  - `pii.phone` matched digit runs inside the result UUID, so about half of all
    `result_id`s reached the client corrupted. The ack is now also returned as MCP
    `structuredContent`, which the text redaction does not touch, and the tool loop reads
    `result_id` from there.
  - `pii.phone` also redacted every ISO date in result rows. A value that is wholly a
    date or timestamp now passes `guard_rows` untouched; anything else is redacted as
    before.
  - `columns` came back alphabetical (serde_json sorts keys); they now follow the query,
    from Postgres' statement description.
- New tables use `bigint generated always as identity` (Supabase Postgres best practice).
- Not run here: `supabase db advisors` (no access to the hosted project from this
  session). The migration and seed were applied to a local Postgres 16 with a Supabase
  shim, and the gateway half of the smoke test (Task 18 steps 1–5) passed against it.

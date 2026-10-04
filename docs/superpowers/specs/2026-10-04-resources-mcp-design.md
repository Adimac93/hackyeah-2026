# Resources through MCP: design

Date: 2026-10-04. Status: approved in conversation, pending spec review.

## Goal

Signed-in console users and external agents ask questions in natural language,
and the LLM answers from our organisation's data by calling MCP tools through
the gateway. Every call is policed and audited. The model sees only structure
and acknowledgements, never values; the rows go to the user who asked
(`docs/BACKEND.md`, MCP integration specification).

Success: a judge types "show me overdue invoices over 500 USD" in console chat,
sees the tool steps, and gets a real table under the answer. Asking for
customer details triggers a live access request that the security team
approves in the console popup, after which the table arrives with PII redacted.

## What exists today

- The gateway is already an MCP server (`POST /mcp`, `gateway/src/mcp/`) with
  native tools `resources__describe`, `resources__query` and `control__*`.
- `POST /v1/chat/completions` with `"mcp": true` runs the tool loop for a model
  that cannot speak MCP and reports `x_control_layer.tool_calls` with
  `result_id`s. Rows are fetched from `GET /v1/results/{id}`.
- `resources::run` runs the query in a read-only transaction with a statement
  timeout and `search_path = resources`, and checks every relation in the
  `EXPLAIN` plan against the principal's `[resources.grants]`.

Why it does not work in prod: console chat never sends `"mcp": true`;
`console-chat` has no tool or table grants; `resources.customers` and
`resources.invoices` are empty; `RESOURCES_DATABASE_URL` is unset, which
disables the resource tools.

## Decisions

| question | decision |
|---|---|
| Which data | Business data in schema `resources` (small-SaaS domain), extended and seeded |
| Database | The main database through `DATABASE_URL`. `RESOURCES_DATABASE_URL` is removed |
| Least privilege | `SET LOCAL ROLE resources_reader` inside each query transaction |
| Who may query what | Console users get non-PII tables outright; `customers` needs an approved access request |
| Result display | Under the answer: collapsible tool steps and a sortable result table |
| Where rows travel | Fetched server-side by the console and saved with the chat message |

## 1. Gateway

### Connection

The resource tools use the gateway's main pool. `main.rs` stops reading
`RESOURCES_DATABASE_URL`; the resource tools are enabled whenever the database
is. `resources::run` adds `set local role resources_reader` as the first
statement after `set transaction read only`. The role lasts only for that
transaction.

### Table grants

The catalog's `[resources]` section gains `requestable`:

```toml
[resources.grants]        # always allowed (exists today)
console-chat = ["products", "subscriptions", "invoices", "support_tickets"]

[resources.requestable]   # new: may be requested, refused until approved
console-chat = ["customers"]
```

A query is allowed when every relation in its plan is either in the
principal's `grants` or covered by a live temporary grant for this principal
**and this end user** (`Principal.user`, from `X-On-Behalf-Of`, or the
principal's own slug). `resources__describe` applies the same rule. A table in
neither list is refused as today.

### Access requests for tables

`control__request_access` accepts either `tool` or `table` (exactly one).
`access_requests` gains:

- `resource text null` — the table name; set instead of `tool`
- `end_user text not null` — who the grant is for

A table request is accepted only for a table in the principal's
`requestable`. Approval works as today (console popup, TTL 1–60 minutes, the
call blocks up to two minutes). The popup shows the end user and the table.
`control__my_access` lists granted, requestable and temporarily granted tables.

Tool requests also record `end_user`, so a delegating principal's grants are
per user for tools too.

### Results bound to the end user

`resource_results` gains `end_user text not null`. `GET /v1/results/{id}`
returns the rows only when both the principal and the end user match, and 404
otherwise, so a user cannot tell whether someone else's result exists. Row
redaction (`guard_rows`) is unchanged.

### What the model sees

Unchanged: column names and types, row count and `result_id`, never values.

## 2. Schema and data

One migration in `supabase/migrations/`:

- `create role resources_reader nologin`; `grant usage on schema resources`,
  `grant select on all tables in schema resources`, and default privileges for
  future tables. Granted to the gateway's login role so it can `SET ROLE`.
  Nothing else is granted to it.
- RLS enabled on every `resources` table with one policy:
  `for select to resources_reader using (true)`. `anon` and `authenticated`
  keep no access; the Data API does not expose the schema.
- New tables:
  - `products (id, name, tier, price_usd)`
  - `subscriptions (id, customer_id, product_id, status, started_at, cancelled_at)`
    with `status in ('active', 'cancelled', 'trial')`
  - `support_tickets (id, customer_id, subject, priority, status, opened_at, closed_at)`
- Data generated in the migration with `generate_series` after a fixed
  `setseed`, so every environment holds identical rows: about 300 customers
  (PL, DE, US, UK, FR), 8 products, 400 subscriptions, 1,200 invoices (paid,
  overdue, void) and 250 tickets. Names come from small first/last name lists;
  emails are `@example.com`; phone numbers are fake but well-formed, so the PII
  controls fire on results.
- `access_requests.resource`, `access_requests.end_user` and
  `resource_results.end_user` columns (section 1).
- `update principals set allowed_tools = …` for `console-chat` to include
  `resources__describe` and `resources__query` (idempotent).

`supabase/seed.sql` stops truncating and refilling `resources` and gets the
same `console-chat` tool grant.

Checks: `supabase db advisors` clean; `set role resources_reader; select * from
public.principals` fails with permission denied.

## 3. Policy

`policy/control-catalog.toml` gets the `grants` and `requestable` entries from
section 1. `demo-agent` keeps `["customers", "invoices"]`. The `docs` upstream
is out of scope and stays for `just demo`.

## 4. Web console

### Storage

Migration: `chat_messages.tool_calls jsonb null`. Each element:

```json
{ "tool": "resources__query", "status": "ok",
  "summary": "SELECT … → 42 rows",
  "arguments": { "sql": "…" },
  "result": { "columns": ["…"], "row_count": 42, "rows": [ … ] } }
```

`result` is present only for calls with a `result_id` whose fetch succeeded;
rows are already redacted and capped by `max_rows`. Existing RLS on
`chat_messages` covers the column.

### Server flow (`web/src/lib/llm/providers.ts`)

For gateway models only (direct providers bypass the control layer and get no
tools):

1. Send `"mcp": true`; timeout 180 s (an access request may wait two minutes).
2. Read `x_control_layer.tool_calls`; for each `result_id`, fetch
   `GET /v1/results/{id}` with the `console-chat` key and `X-On-Behalf-Of`.
3. Return the answer and the steps; the chat action stores both.

A failed result fetch marks that step "result unavailable"; the answer is still
saved. The system prompt for gateway models adds: use the resource tools for
questions about customers, invoices, products, subscriptions or tickets; never
invent data; the rows appear below the answer.

### UI

`chat-history.tsx` renders the steps through a new client component
`tool-steps.tsx`: each call is a collapsed line with its summary, expanding to
show the SQL or arguments; a result renders as a table with sortable columns
and the row count. `[REDACTED]` markers stay visible. Wide tables scroll inside
their own box. While a request is in flight the composer shows "Working… (may
be waiting for security approval)". Live per-step progress (streaming tool
events) is out of scope.

## 5. Testing, rollout, demo

Tests (narrow, per `CLAUDE.md`):

- gateway: table grant plus per-user temporary grant (same user passes, another
  user is refused); `requestable` parsing and refusal of an unlisted table;
  results lookup refuses another user's id; `request_access` with `table`.
- web: mapping `tool_calls` to stored steps and summaries; merging fetched
  results, including a failed fetch.
- one smoke test, run on `just dev` and on prod after deploy: overdue invoices →
  table; a question touching `customers` → access request; approve → table with
  emails redacted.

`just check` green.

Rollout:

1. Migrations via `just migrate`, then `supabase db advisors`.
2. Gateway and catalog in one PR; docs drop `RESOURCES_DATABASE_URL`
   (`docs/DEPLOY.md`, `docs/BACKEND.md`, `.env.example`).
3. Web in a second PR, merged after the gateway is live.
4. Both deploy through the Cloud Build triggers; the catalog takes effect on
   upload.
5. Smoke test on prod.

This touches `gateway/`, `policy/`, `supabase/migrations/` and `web/`; tell
those owners before merging.

`DEMO.md` gains "Data through MCP": invoices question → table (the model saw
only a row count); customer question → access request popup → approve →
redacted table; Activity shows every tool call in the audit log.

## Out of scope

- Streaming tool progress to the chat.
- Per-console-role table grants.
- Deploying the `docs` upstream (`mcp-demo`).
- Data sources other than SQL tables in schema `resources`.

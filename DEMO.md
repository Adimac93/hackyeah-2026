# Demo

The thing the judges actually see. Written now, updated as we build — not at hour 23.

## Demo URL

**TBD** — the gateway deploys with `just deploy` (Cloud Run service `backend`,
`docs/DEPLOY.md`); put its URL and the console's URL here once they are live.

## Script

Click by click, in order, with the exact words. Rehearse it once before presenting.

1. _(TBD)_
2. _(TBD)_
3. _(TBD)_

Target length: **3 minutes.**

### Beat: an agent asks a human for access

Console open and signed in as an analyst. `just demo` running (gateway + `mcp-demo`).
`GW` is the gateway URL; `RT` is `Authorization: Bearer red-team-dev-key`.

1. The red-team agent reads a document it was never granted — refused:
   `curl -s $GW/mcp -H "$RT" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docs__read","arguments":{"id":"q3-summary"}}}'`
   → `red-team may not call docs__read`.
2. It looks up its own policy (`control__my_access`): `docs__read` is listed under
   `requestable_tools`.
3. It asks: `"name":"control__request_access","arguments":{"tool":"docs__read","reason":"Need the Q3 summary for the board deck"}`.
   The curl hangs, and **the popup appears in the console** with the reason and a 120 s countdown.
4. Click **Approve** (15 min). The curl returns `{"status":"granted","expires_at_ms":…}`.
5. Repeat step 1 — the Q3 summary comes back.
6. Read `onboarding` with the same grant — **still blocked** by the injection control on
   `tool_result`. Say: "Permission and inspection stack. A human can grant a tool; nobody
   can grant a poisoned document."

### Beat: the model asks the database, the user gets the rows

`just demo` running. `DA` is `Authorization: Bearer demo-agent-dev-key`.

1. `curl -s $GW/v1/chat/completions -H "$DA" -H 'content-type: application/json' -d '{"model":"llama3.1:8b","mcp":true,"messages":[{"role":"user","content":"select full_name, email from customers"}]}'`
2. `x_control_layer.tool_calls` shows the model's two calls: `resources__describe`
   (the columns of `customers`, nothing else) and `resources__query` (`row_count`, a `result_id`).
   The answer holds no customer data. Say: "The model wrote the query. It never saw a row."
3. `curl -s $GW/v1/results/<result_id> -H "$DA"` — the rows, emails redacted on the way out.
4. Ask for `payroll` instead — `resources__describe` is refused: not in `demo-agent`'s grant.

### Beat: data through MCP in the console chat

Console chat on a gateway model (dev: `UPSTREAM_URL=mock` plays the model when the
message contains a SELECT; prod: ask in plain words).

1. Ask "show me overdue invoices over 500 USD" (dev: `select id, amount_usd, status,
   issued_at from invoices where status = 'overdue' and amount_usd > 500`). Under the
   answer: the collapsed tool steps (`describe invoices`, the SQL → *n* rows) and a
   sortable table. Say: "The model wrote the SQL and saw a row count. The table came to
   me, not to the model."
2. Ask for customer emails (dev: `select full_name, email, phone from customers where
   country = 'PL'`). The model is told `customers` needs approval and calls
   `control__request_access {table: customers}`; the approval popup shows the table and
   the person asking. Approve.
3. The table arrives with emails and phones `[REDACTED:…]`.
4. Sign in as someone else and ask the same: a fresh request. The grant was for one person.
5. Activity: every `tool_call`, the `mcp.table-not-granted` block, the approval.

## What it depends on

- Seeded data: `just seed` — two gateway principals with public demo keys:
  `demo-agent` (key `demo-agent-dev-key`, tools `docs__read`, `docs__search` and the
  `resources__*` tools) and `red-team` (key `red-team-dev-key`, `docs__search` only),
  plus `secops-console` (key `secops-console-dev-key`, `security_admin`, no tools) — the
  console's `GATEWAY_ADMIN_KEY` for the access-request popup. Budgets are `budgets` rows:
  global 2M tokens / $25 a day, `demo-agent` 50k tokens/hour hard, `red-team` 10k
  tokens/hour soft.
- The policy lives in the database. On first start the gateway seeds the sample in
  `policy/`; to change it live, upload an edited catalog (console policy page, or
  `POST /admin/policy` with an admin's Supabase access token). Every instance picks it
  up within 5 s.
- Services that must be up:
  - locally: `just dev` (gateway + console) or `just demo` (gateway + `mcp-demo` on
    :9310 for the MCP path). Dev uses the mock upstream and mock judge — no model needed.
  - prod: the gateway (`just deploy`) and a reachable Ollama judge (`OLLAMA_URL`).
    Without the judge, semantic controls fail closed.
    Prod chat also needs a real `UPSTREAM_URL` (TASKS.md `chat-upstream-prod`).
- Anything manual: _(TBD — ideally nothing)_

## Self-test

`just test system` starts the gateway and `mcp-demo` (logs in
`target/selftest-services.log`) and runs the self-test against them: prompts,
answers, identity and model grants, MCP tool calls and results, and the
attack-history block, each printed with its result and risk score. Needs
`DATABASE_URL` and `just seed` (the `selftest` principal, key
`selftest-dev-key`). To test a gateway that is already running, deployed or
local: `SELFTEST_URL=https://… just test system` (it must have `mcp-demo`
behind it as the `docs` server for the tool-result cases). The header says
whether the semantic judge is the mock or a real model.

## Fallback

Live demos fail on conference wifi. Before the final hour:

- [ ] record a full screen-capture run of the script
- [ ] screenshot every key screen
- [ ] put both somewhere openable offline, and link them here

## Known rough edges

Be honest with yourself here so nothing surprises you on stage.

- Console chat through the gateway returns 401: the web app still sends `x-principal`,
  the gateway only accepts `Authorization: Bearer` (TASKS.md `web-gateway-auth`). Demo
  the gateway with `curl` and a seeded key until that lands.
- `pii.contextual` ships disabled (no Presidio sidecar yet).
- `just verify-audit` on the shared Supabase reports one break, at event 31 (2026-10-03).
  Before migration `20261003201902`, every flagged detection failed its `attack_history`
  insert, the audit transaction silently rolled back, and the chain skipped the lost
  event. Fixed (column now `control_action`; a failed statement rolls back without
  advancing the chain), but the log is append-only, so that one gap stays. Either
  present it — "the verifier caught a real gap" — or demo on a fresh database.
- The gateway needs `DATABASE_URL` in every environment now, and the
  `20261003210000_gateway_db_policy` migration applied.
- Concurrency budgets count per gateway instance, not across the fleet.
- The `balanced` and `strict` profiles currently set the same defaults.
- The resource tools run on the main connection, switched per transaction to
  `resources_reader` (`SELECT` on schema `resources` only, from the
  `20261004130000_resources_mcp` migration); the gateway's own checks (single
  SELECT, read-only transaction, planner-verified table grants) are a second line.
- The Vertex judge bills ~$25/day while deployed; tear it down after the demo.

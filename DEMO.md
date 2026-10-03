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

## What it depends on

- Seeded data: `just seed` — two gateway principals with public demo keys:
  `demo-agent` (key `demo-agent-dev-key`, `security_admin`, tools `docs__read` and
  `docs__search`) and `red-team` (key `red-team-dev-key`, `member`, `docs__search` only),
  plus `secops-console` (key `secops-console-dev-key`, `security_admin`, no tools) — the
  console's `GATEWAY_ADMIN_KEY` for the access-request popup.
  Budgets come from `policy/control-catalog.toml`: global 2M tokens / $25 a day,
  `demo-agent` 50k tokens/hour hard, `red-team` 10k tokens/hour soft.
- Services that must be up:
  - locally: `just dev` (gateway + console) or `just demo` (gateway + `mcp-demo` on
    :9310 for the MCP path). Dev uses the mock upstream and mock judge — no model needed.
  - prod: the gateway (`just deploy`) and a reachable Ollama judge (`OLLAMA_URL`).
    Without the judge, semantic controls fail closed.
    Prod chat also needs a real `UPSTREAM_URL` (TASKS.md `chat-upstream-prod`).
- Anything manual: _(TBD — ideally nothing)_

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
- The Vertex judge bills ~$25/day while deployed; tear it down after the demo.

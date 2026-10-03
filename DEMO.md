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

## What it depends on

- Seeded data: `just seed` — two gateway principals with public demo keys:
  `demo-agent` (key `demo-agent-dev-key`, `security_admin`, tools `docs__read` and
  `docs__search`) and `red-team` (key `red-team-dev-key`, `member`, `docs__search` only).
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

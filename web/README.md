# web — SecOps console

The security team's view of the AI Control Layer (Next.js, pnpm). It reads the
gateway's tables through the Supabase Data API as the signed-in team member; RLS
makes those read-only, so the console can never rewrite the audit log it shows.
Its own tables (incidents, company policies, chat, team, LLM connections) take
role-gated writes.

| route        | what                                                                    |
| ------------ | ----------------------------------------------------------------------- |
| `/dashboard` | security overview: gateway events, incidents, company policies          |
| `/activity`  | every request the gateway intercepted, from the hash-chained audit log  |
| `/controls`  | principals, budgets and usage, policy versions, attack signatures       |
| `/policies`  | company security policies employees are bound by                        |
| `/incidents` | incidents raised from detections                                        |
| `/models`    | LLM connections for the assistant chat                                  |
| `/chat`      | security assistant; "Gateway (protected)" models go through the gateway |
| `/team`      | invite and manage team members                                          |

## Running

From the repo root, never with pnpm directly:

```bash
just setup     # installs web deps too
just dev-web   # console only; `just dev` runs the gateway alongside it
just check     # typecheck + eslint/prettier + node tests for both apps
```

Settings go in `web/.env.local`; `web/.env.example` lists them, and the root
`.env.example` explains each one. With `GATEWAY_URL` unset the chat still works
through the offline demo model.

Read `AGENTS.md` before writing code: this Next.js version differs from what
most models were trained on.

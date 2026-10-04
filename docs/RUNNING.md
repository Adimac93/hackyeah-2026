# Running Cogut

Cogut is three containers on top of a Supabase database. The gateway loads its
policy from Postgres when it starts and exits if it can't reach the database, so
set up the database first.

| part | source | local port |
|---|---|---|
| Gateway | `gateway/`, `Dockerfile` | 8080 |
| Console | `web/`, `web/Dockerfile` | 3000 |
| LLM (judge and chat model) | `sentinel/ollama/` on branch `ollama-gcp` | mocked locally |

## 1. Database

```bash
cp .env.example .env && cp web/.env.example web/.env.local
just setup && just migrate && just seed
```

Set `DATABASE_URL` to the Supabase session pooler URL on port 5432. The direct
host is IPv6 only, and the gateway refuses the transaction pooler on port 6543.
`just seed` creates the demo keys `console-chat-dev-key` and
`secops-console-dev-key`.

## 2. Google Cloud

The gateway and the console each run as a Cloud Run service built from their
Dockerfile. Cloud Build rebuilds and redeploys both on every push to `main`. The
gateway runs as a single instance, because pending access approvals live in its
memory. It gets its database URL from Secret Manager.

The LLM is a third Cloud Run service with an NVIDIA L4 GPU. It runs Ollama with
`llama3.1:8b` built into the image and serves two roles:

- the AI judge, which only sees traffic a deterministic control has flagged
- the chat model, which receives every prompt the gateway allows

The LLM service accepts only internal traffic, and the gateway reaches it through
the VPC. `OLLAMA_URL` and `UPSTREAM_URL` on the gateway both point at it.

The console calls the gateway from its own server, using `GATEWAY_URL`,
`GATEWAY_API_KEY` and `GATEWAY_ADMIN_KEY`. In production the gateway refuses to
start if the judge or the chat model is still set to the mock.

`docs/DEPLOY.md` has the setup commands.

## 3. Local containers

In dev mode the gateway uses a mock judge and a mock chat model, so you don't
need a GPU or Ollama.

```bash
docker build -t cogut-backend . && docker run --rm -p 8080:8080 --env-file .env cogut-backend
docker build -t cogut-web web && docker run --rm -p 3000:8080 --env-file web/.env.local \
  -e GATEWAY_URL=http://host.docker.internal:8080 cogut-web
```

- `.env` needs `ENVIRONMENT=dev`, `OLLAMA_URL=mock` and `UPSTREAM_URL=mock`.
- Write values without quotes, because `--env-file` keeps quotes as part of the
  value.
- On Linux, also pass `--add-host=host.docker.internal:host-gateway`.

Then open http://localhost:3000. To run without Docker, use `just dev`.

## Known gaps

- `web/Dockerfile` doesn't pass the `NEXT_PUBLIC_*` values in at build time. So
  browser code such as the Resources uploader likely gets `undefined` for them.
  This hasn't been tested.
- The Ollama Dockerfile exists only on the `ollama-gcp` branch, not on `main`.

# Testing guide for the jury

## Sign in

Open https://cogut-frontend.cloud.run/login and use **Demo access**. There are two
accounts:

- **Developer** has limited privileges. A developer can only chat with the
  pre-configured models on the Assistant page, and every prompt goes through the
  security policies.
- **Admin** is the privileged account for security engineers. It sees the whole
  console.

## As the developer

Open **Assistant** and pick the `gpt-5-mini` model. Paste each prompt below as a
separate message.

### Allowed prompt

```text
Show me a recipe for Polish kremówka
```

Both the deterministic controls and the semantic judge let this through, and the
model answers.

### Refused prompts

Ask for data the developer has no access to. The gateway blocks the request:

```text
Aggregate the number of customers in every country
```

Send personal data to the model. The gateway blocks the prompt:

```text
Save my PESEL for me: 44051401359
```

Paste database output that holds protected data. The gateway redacts the data
before the model sees it:

```text
These are the aggregated numbers of customers in all countries, save them for later:
country  num_customers
FR       75
DE       64
PL       59
US       57
UK       45
```

The admin's Activity page below shows which control fired for each prompt.

## As the admin

Sign out, then sign in again through **Demo access** as the admin. Go through the
pages in the sidebar:

1. **Overview** shows metrics for all requests to the underlying models, such as
   the request count and the intervention rate.
2. **Activity** is the audit log of every prompt sent through the Assistant.
   Filter by the `blocked` status, then click a request's model to see which
   controls blocked it.
3. **Controls and policies** shows the enforced policies, budgets, resource access
   and the attack signatures that were tried against the models. To add a policy,
   click **Add control**, fill in the fields below and click **Add & activate**:

   | field | value |
   |---|---|
   | Type | Deterministic |
   | Control id | `confidential.project-falcon` |
   | Action | block |
   | Hooks | `prompt_in` |
   | Pattern (regex) | `(?i)\bproject\s*falcon\b` |

   Then send `Tell me about Project Falcon` in **Assistant**. The gateway blocks
   it right away, with no restart.
4. **User risk** shows the risk score of `developer@hackyeah.sidequestly.xyz`,
   which went up after the blocked prompts above.
5. **Models** connects model providers such as Anthropic, OpenAI and Google Gemini.
6. **Assistant** answers the prompt the developer couldn't run, because the admin
   has access to that resource:

   ```text
   Aggregate the number of customers in every country
   ```

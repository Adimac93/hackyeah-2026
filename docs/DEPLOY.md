# Deploying the gateway to Cloud Run

One-time setup, then `just deploy`.

Deploy into a **throwaway project**, not an existing one. `mcp-demo` is a
deliberately vulnerable MCP server that serves poisoned documents, and nothing
in this repo should sit next to production workloads.

## 1. Project and APIs

```bash
export PROJECT=<your-project>
export REGION=europe-west1

gcloud config set project "$PROJECT"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com
```

## 2. Let the build write logs

The default compute service account used by Cloud Build no longer receives
project Editor automatically. Without this the build runs but produces no logs,
and the console reports "no logs were found for this build".

```bash
NUM=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${NUM}-compute@developer.gserviceaccount.com" \
  --role=roles/cloudbuild.builds.builder
```

## 3. Artifact Registry

```bash
gcloud artifacts repositories create gateway \
  --repository-format=docker --location="$REGION"
```

## 4. The database URL as a secret

It carries a password, so it does not belong in `--set-env-vars`, which lands in
build logs and in the service description.

**Use the session-mode pooler string.** Supabase's direct host
(`db.<ref>.supabase.co`) is IPv6-only and unreachable from Cloud Run. Transaction
mode (port 6543) breaks sqlx's prepared statements. Session mode, port 5432.

```bash
printf '%s' 'postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres' \
  | gcloud secrets create gateway-database-url --data-file=-

gcloud secrets add-iam-policy-binding gateway-database-url \
  --member="serviceAccount:${NUM}-compute@developer.gserviceaccount.com" \
  --role=roles/secretmanager.secretAccessor
```

## 5. Deploy

```bash
just deploy                      # defaults: europe-west1, service "backend"
just deploy us-central1 gateway  # or pick your own
```

`cloudbuild.yaml` sets a 30-minute timeout and an 8-core machine. A release
build of this workspace does not finish inside Cloud Build's 10-minute default,
and that failure looks like a code problem when it is not.

## 6. Configure the service

```bash
gcloud run services update backend --region="$REGION" \
  --update-env-vars=CORS_ORIGINS=https://<dashboard-origin>,UPSTREAM_URL=<openai-compatible-model-url>,OLLAMA_URL=<ollama-url>
```

`cloudbuild.yaml` already sets `ENVIRONMENT=prod` and the `DATABASE_URL` secret on
every deploy. `--update-env-vars` keeps both; `--set-env-vars` would wipe them.

### Judge and upstream on a Cloud Run Ollama (instead of Vertex)

The `ollama` Cloud Run service (GPU, `sentinel/ollama` image) serves both the
judge (`/api/generate`) and an OpenAI-compatible chat upstream (`/v1`). Its
ingress is `internal`, so the backend must send its traffic through the VPC, and
because the gateway calls the judge without an identity token, `ollama` grants
`roles/run.invoker` to `allUsers` — internal ingress is what keeps it private.

```bash
gcloud compute networks subnets update default --region="$REGION" \
  --enable-private-ip-google-access
gcloud run services add-iam-policy-binding ollama --region="$REGION" \
  --member=allUsers --role=roles/run.invoker
gcloud run services update backend --region="$REGION" \
  --network=default --subnet=default --vpc-egress=private-ranges-only \
  --update-env-vars=OLLAMA_URL=https://<ollama-url>,UPSTREAM_URL=https://<ollama-url>/v1,SEMANTIC_MODEL=llama3.1:8b
```

Never set `ingress=all` on `ollama` while `allUsers` can invoke it.

| variable | effect |
|---|---|
| `ENVIRONMENT` | `prod` switches logs to JSON so Cloud Logging reads severity, stops allowing every origin, and refuses to start with a `mock` upstream/judge |
| `CORS_ORIGINS` | comma-separated origins, or `*` for any. **Unset in prod means no browser may call the API.** Set it to the dashboard's origin, not `*` |
| `PORT` | injected by Cloud Run. A malformed value aborts startup rather than binding something else |
| `SUPABASE_URL` / `SUPABASE_PUBLISHABLE_KEY` | how the admin API verifies console users' access tokens. Unset, every admin route answers 503; enforcement is unaffected |
| `METRICS_TOKEN` | Bearer token for `GET /metrics/prometheus`. Unset disables it. Put it in Secret Manager |
| `RESOURCES_DATABASE_URL` | read-only connection for the `resources__query` MCP tool (a role with `SELECT` on schema `resources` only). Unset disables the resource tools |
| `UPSTREAM_URL` | where chat traffic goes: any OpenAI-compatible server (e.g. Ollama's `/v1`). Defaults to `mock`, which prod refuses |
| `OLLAMA_URL` | the semantic judge (Ollama). Defaults to `mock`, which prod refuses |
| `SEMANTIC_MODEL` | the judge's model name, default `llama3.1:8b` |
| `DATABASE_URL` | from Secret Manager. Required in every environment: the policy, identities, grants and budgets live there. An empty database is seeded with the built-in sample policy on first start |

**One instance.** `cloudbuild.yaml` deploys with `--max-instances=1`: a pending
access approval (`control__request_access`) lives in the gateway's memory, so the
agent's blocked call and the console's decision must land on the same instance.
Cloud Run's request timeout (default 300 s) also closes the console's SSE stream
periodically; the browser reconnects and the gateway replays what is pending.

## Troubleshooting

**"container failed to start and listen on PORT"** — the gateway loads its
policy from the database before binding. Check that `DATABASE_URL` is set and
reachable, and that the migrations are applied (`just migrate`); a missing
column aborts startup with the same symptom.

```bash
gcloud run services logs read backend --region="$REGION" --limit=50
```

**Builds time out** — raise `timeout` in `cloudbuild.yaml`.

**"ENVIRONMENT=prod refuses a mock"** — `UPSTREAM_URL` is unset, or the judge is
not a real `OLLAMA_URL`. The very first
`just deploy` fails this way because the service has no settings yet; step 6
sets them, and later deploys keep them.

**Semantic controls refuse everything** — the judge is unreachable and the
controls fail closed. Check that `OLLAMA_URL` points at a running Ollama with
`SEMANTIC_MODEL` pulled.

**Chat requests return 502** — `UPSTREAM_URL` points at nothing. This repo does
not provision a chat model (TASKS.md `chat-upstream-prod`). The MCP
path needs an upstream MCP server too: the catalog's `docs` server is the local
`mcp-demo`, which is not deployed.

## What is deliberately not deployed

- **`mcp-demo`** — serves poisoned documents by design. Run it locally.
- **`just report`** — needs the `typst` binary, which is not in the runtime image.
- **The web console** — not deployed by this repo; set its `GATEWAY_URL` to the
  service URL and add its origin to `CORS_ORIGINS`. Set `GATEWAY_ADMIN_KEY` (server
  side only) to a `security_admin` principal's key so the access-request popup works.

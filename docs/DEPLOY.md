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
  --update-env-vars=CORS_ORIGINS=https://<dashboard-origin>,UPSTREAM_URL=<openai-compatible-model-url>

# the semantic judge: VPC egress, SEMANTIC_BACKEND=vertex, VERTEX_JUDGE_* (infra/README.md)
gcloud run services update backend --region="$REGION" \
  $(terraform -chdir=infra output -raw backend_deploy_flags)
```

`cloudbuild.yaml` already sets `ENVIRONMENT=prod` and the `DATABASE_URL` secret on
every deploy. `--update-env-vars` keeps both; `--set-env-vars` would wipe them.

| variable | effect |
|---|---|
| `ENVIRONMENT` | `prod` switches logs to JSON so Cloud Logging reads severity, stops allowing every origin, and refuses to start without `DATABASE_URL` or with a `mock` upstream/judge |
| `CORS_ORIGINS` | comma-separated origins, or `*` for any. **Unset in prod means no browser may call the API.** Set it to the dashboard's origin, not `*` |
| `PORT` | injected by Cloud Run. A malformed value aborts startup rather than binding something else |
| `POLICY_PATH` | defaults to `policy/control-catalog.toml`, shipped inside the image |
| `UPSTREAM_URL` | where chat traffic goes: any OpenAI-compatible server (e.g. Ollama's `/v1`). Defaults to `mock`, which prod refuses |
| `SEMANTIC_BACKEND` | `vertex` sends the judge to the VPC-internal Vertex endpoint; set by `backend_deploy_flags` |
| `VERTEX_JUDGE_URL` / `VERTEX_JUDGE_IP` / `VERTEX_JUDGE_CA` | the judge's address and self-signed CA; set by `backend_deploy_flags` (CA from Secret Manager) |
| `OLLAMA_URL` | the judge when `SEMANTIC_BACKEND` is not `vertex`. Defaults to `mock`, which prod refuses |
| `SEMANTIC_MODEL` | the judge's model name, default `llama3.1:8b` |
| `DATABASE_URL` | from Secret Manager. Required in prod; the gateway refuses to start without it |

## Troubleshooting

**"container failed to start and listen on PORT"** — the gateway loads its
policy before binding and refuses to start without one. Check `policy/` is in
the image, and that `DATABASE_URL` (if set) is reachable; an unreachable
database aborts startup with the same symptom.

```bash
gcloud run services logs read backend --region="$REGION" --limit=50
```

**Builds time out** — raise `timeout` in `cloudbuild.yaml`.

**"ENVIRONMENT=prod refuses a mock"** — `UPSTREAM_URL` is unset, or the judge is
neither `SEMANTIC_BACKEND=vertex` nor a real `OLLAMA_URL`. The very first
`just deploy` fails this way because the service has no settings yet; step 6
sets them, and later deploys keep them.

**Semantic controls refuse everything** — the judge is unreachable and the
controls fail closed. Check the Vertex endpoint is deployed (`just infra`) and
re-run the CA capture job after it is recreated (`infra/README.md`).

**Chat requests return 502** — `UPSTREAM_URL` points at nothing. This repo does
not provision a chat model (TASKS.md `chat-upstream-prod`); the Vertex endpoint
serves only the semantic judge. The MCP
path needs an upstream MCP server too: the catalog's `docs` server is the local
`mcp-demo`, which is not deployed.

## What is deliberately not deployed

- **`mcp-demo`** — serves poisoned documents by design. Run it locally.
- **`just report`** — needs the `typst` binary, which is not in the runtime image.
- **The web console** — not deployed by this repo; set its `GATEWAY_URL` to the
  service URL and add its origin to `CORS_ORIGINS`.

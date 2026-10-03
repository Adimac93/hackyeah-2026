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
  --set-env-vars=ENVIRONMENT=prod,CORS_ORIGINS='*'
```

| variable | effect |
|---|---|
| `ENVIRONMENT` | `prod` switches logs to JSON so Cloud Logging reads severity, and stops allowing every origin |
| `CORS_ORIGINS` | comma-separated origins, or `*` for any. **Unset in prod means no browser may call the API.** CORS restricts browsers only; with no authentication on the gateway, a wildcard exposes nothing curl could not already reach |
| `PORT` | injected by Cloud Run. A malformed value aborts startup rather than binding something else |
| `POLICY_PATH` | defaults to `policy/control-catalog.toml`, shipped inside the image |
| `UPSTREAM_URL` | where model traffic goes. Defaults to `localhost:11434`, which is nothing on Cloud Run |
| `DATABASE_URL` | from Secret Manager. Absent, the gateway still enforces but persists nothing |
| `OLLAMA_URL` | the semantic judge. Same model host as `UPSTREAM_URL` on Cloud Run |
| `MODEL_AUTH` | `google` sends a Google identity token to the model host. Required for the private `ollama` service |

## 7. The model host

Ollama on Cloud Run with one NVIDIA L4, the model baked into the image
(`ollama/`). One service serves both model traffic (`UPSTREAM_URL`) and the
semantic judge (`OLLAMA_URL`).

**Cost.** About $1 per hour while an instance runs (L4 plus 4 vCPU / 16 GiB),
nothing when scaled to zero. `--max-instances=1` caps it at one GPU whatever
the traffic. Before judging, set `--min-instances=1` to skip the cold start,
and set it back to 0 afterwards.

**Private.** The service rejects unauthenticated calls; an open Ollama is a
free GPU for anyone who finds the URL. The gateway's service account is
granted `run.invoker` and mints identity tokens itself (`MODEL_AUTH=google`).

```bash
# build, push, deploy: ~10 minutes, most of it pulling the 5 GB model
gcloud builds submit --config ollama/cloudbuild.yaml ollama

OLLAMA=$(gcloud run services describe ollama --region="$REGION" --format='value(status.url)')
SA=$(gcloud run services describe backend --region="$REGION" \
  --format='value(spec.template.spec.serviceAccountName)')
gcloud run services add-iam-policy-binding ollama --region="$REGION" \
  --member="serviceAccount:$SA" --role=roles/run.invoker

gcloud run services update backend --region="$REGION" \
  --update-env-vars=UPSTREAM_URL=$OLLAMA,OLLAMA_URL=$OLLAMA,MODEL_AUTH=google

# demo window
gcloud run services update ollama --region="$REGION" --min-instances=1
# after
gcloud run services update ollama --region="$REGION" --min-instances=0
```

Talk to it directly with your own identity:

```bash
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" "$OLLAMA/api/tags"
```

A first request after idle waits for an instance and the model load, tens of
seconds. GPU quota is per region; a "quota exceeded" deploy means requesting
Cloud Run L4 quota for the region in IAM → Quotas.

## Troubleshooting

**"container failed to start and listen on PORT"** — the gateway loads its
policy before binding and refuses to start without one. Check `policy/` is in
the image, and that `DATABASE_URL` (if set) is reachable; an unreachable
database aborts startup with the same symptom.

```bash
gcloud run services logs read backend --region="$REGION" --limit=50
```

**Builds time out** — raise `timeout` in `cloudbuild.yaml`.

**Chat requests return 502** — `UPSTREAM_URL` points at nothing reachable.
Check section 7: the `ollama` service exists, `UPSTREAM_URL` is its URL, and
`MODEL_AUTH=google` is set. A 403 from the model host in the logs means the
gateway's service account is missing `run.invoker` on `ollama`.

## What is deliberately not deployed

- **`mcp-demo`** — serves poisoned documents by design. Run it locally.
- **`just report`** — needs the `typst` binary, which is not in the runtime image.

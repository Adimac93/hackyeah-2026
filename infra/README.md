# infra

The semantic judge in production: our Ollama image (`sentinel/ollama/`) on a Vertex AI
endpoint with one L4 GPU, reachable **only inside the `default` VPC** through Private
Service Connect. Nothing outside the VPC can resolve or route to it, and calls still need
an OAuth token, which the gateway takes from the metadata server.

Everything is in Terraform except the image build, which `image.tf` runs through
`gcloud builds submit` whenever `sentinel/ollama/` changes.

## Cost

Vertex does not scale to zero: **~$1/hour (~$25/day) for as long as the judge is deployed.**
Tear it down when you're not demoing:

    terraform -chdir=infra destroy -target=google_vertex_ai_endpoint_with_model_garden_deployment.judge

## First time

    gcloud storage buckets create gs://project-3b1f59f2-cb77-4d59-bae-tfstate --location=europe-west1 --uniform-bucket-level-access
    just setup     # terraform init
    just deploy    # terraform apply; review the plan before saying yes

Then capture the endpoint's self-signed certificate. It only exists after deploy and is only
reachable inside the VPC, so a job running in the VPC fetches it into Secret Manager:

    gcloud run jobs execute judge-ca-capture --region=europe-west1 --wait

Re-run it whenever the deployment is recreated.

## Wiring the backend

Terraform does not own the `backend` Cloud Run service. Add this to its deploy command:

    terraform -chdir=infra output -raw backend_deploy_flags

That gives it Direct VPC egress (private ranges only: Supabase and other public traffic
still go out directly), the judge URL and IP, and the CA as `VERTEX_JUDGE_CA`.

## Checking isolation

From the laptop, `terraform -chdir=infra output -raw judge_host` does not resolve.
From inside the VPC, the judge answers `POST <judge_url>` with an Ollama `/api/generate` body
and a bearer token.

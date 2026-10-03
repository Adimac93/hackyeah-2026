# hackyeah-2026 — the single entrypoint for humans and agents.
#
# RULE: agents and teammates call `just <recipe>`. Never the underlying tool.
# When you add a toolchain, wire it into the matching recipe below instead of
# teaching the team a new command.
#
# Two apps live here: the Rust gateway at the root and the Next.js web app in
# web/. The core recipes cover both, because "done" has to mean both are green.

set shell := ["bash", "-uc"]
# Load `.env` for local-only values such as DATABASE_URL. `.env` is gitignored.
set dotenv-load := true

repo := justfile_directory()

default:
    @just --list --unsorted

# install dependencies for both apps
setup:
    cargo fetch --locked
    command -v terraform >/dev/null || brew install hashicorp/tap/terraform
    terraform -chdir=infra init -input=false
    cd web && pnpm install --frozen-lockfile

# the one gate: `just check` green == done. Nothing else counts.
check: typecheck lint test
    @echo "check: OK"

typecheck:
    cargo check --workspace --all-targets
    cd web && pnpm typecheck

# clippy + rustfmt for the gateway; eslint + prettier (@solvro/config) for web.
# `just fmt` fixes what is fixable.
lint:
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cd web && pnpm lint && pnpm format:check

test:
    cargo test --workspace --all-targets
    cd web && pnpm test

# gateway and web app together — what you want for the demo
dev:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p gateway --bin gateway
    ./target/debug/gateway &
    api_pid=$!
    trap 'kill $api_pid 2>/dev/null || true' EXIT
    cd web && pnpm dev

# just the gateway; needs DATABASE_URL, set UPSTREAM_URL/OLLAMA_URL in .env to override the mocks
dev-api:
    cargo run -p gateway --bin gateway

# just the web app
dev-web:
    cd web && pnpm dev

# apply formatting to both
fmt:
    cargo fmt
    cd web && pnpm format

# render the management/security report; requires DATABASE_URL and typst
report:
    cargo run --quiet -p gateway --bin report

# prove the audit log has not been edited; requires DATABASE_URL
verify-audit:
    cargo run --quiet -p gateway --bin verify-audit

# new schema migration: just db-new add_something
db-new NAME:
    supabase migration new {{NAME}}

# One migration directory for one database: the gateway's schema and the web
# app's share a timeline, so a single ordering is the only one that can be
# correct.
#
# apply pending supabase/migrations: just migrate (preview: just migrate --dry-run)
migrate *FLAGS:
    #!/usr/bin/env bash
    set -euo pipefail
    # the URL may live in web/.env.local next to the other Supabase settings
    if [ -z "${SUPABASE_DB_URL:-}" ] && [ -f web/.env.local ]; then set -a; . ./web/.env.local; set +a; fi
    url="${SUPABASE_DB_URL:-${DATABASE_URL:-}}"
    : "${url:?set DATABASE_URL or SUPABASE_DB_URL (Supabase → Connect → connection string)}"
    pnpm dlx supabase@2.119.0 db push --db-url "$url" {{FLAGS}}

# load demo data: gateway identities and budgets, then the web fixtures
seed:
    #!/usr/bin/env bash
    set -euo pipefail
    url="${DATABASE_URL:-${SUPABASE_DB_URL:-}}"
    : "${url:?set DATABASE_URL (or SUPABASE_DB_URL) in .env}"
    psql "$url" -v ON_ERROR_STOP=1 -f supabase/seed.sql

# run the gateway and the deliberately vulnerable demo MCP server together
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p gateway --bin gateway -p mcp-demo --bin mcp-demo
    ./target/debug/mcp-demo &
    demo_pid=$!
    trap 'kill $demo_pid 2>/dev/null || true' EXIT
    ./target/debug/gateway

# ship the gateway to Cloud Run. See docs/DEPLOY.md for first-time setup.
deploy region="europe-west1" service="backend": check
    gcloud builds submit \
      --config cloudbuild.yaml \
      --substitutions=_REGION={{region}},_SERVICE={{service}}

# provision/update the Vertex AI judge infrastructure (bills ~$25/day while up).
# Shows the plan and waits for a yes. See infra/README.md.
infra:
    terraform -chdir=infra apply

# new isolated worktree for an agent or a task: just wt my-feature
wt NAME:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="{{repo}}/../hackyeah-2026-{{NAME}}"
    if [ -e "$dir" ]; then echo "already exists: $dir" >&2; exit 1; fi
    git -C "{{repo}}" worktree add -b "{{NAME}}" "$dir"
    if [ -f "{{repo}}/.env" ]; then cp "{{repo}}/.env" "$dir/.env"; fi
    # deterministic per-branch port so parallel dev servers never collide
    port=$(( 3000 + ( $(printf '%s' "{{NAME}}" | cksum | cut -d' ' -f1) % 50 + 1 ) * 10 ))
    echo "PORT=$port" >> "$dir/.env"
    echo
    echo "worktree  $dir"
    echo "branch    {{NAME}}"
    echo "PORT      $port"

# remove a worktree created by `just wt`
wt-rm NAME:
    #!/usr/bin/env bash
    set -euo pipefail
    git -C "{{repo}}" worktree remove ${FORCE:+--force} "{{repo}}/../hackyeah-2026-{{NAME}}"
    echo "removed worktree {{NAME}} (branch kept)"

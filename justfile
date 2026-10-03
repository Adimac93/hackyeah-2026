# hackyeah-2026 — the single entrypoint for humans and agents.
#
# RULE: agents and teammates call `just <recipe>`. Never the underlying tool.
# When you add a toolchain, wire it into the matching recipe below instead of
# teaching the team a new command. The stack plugs in here and nowhere else.

set shell := ["bash", "-uc"]

repo := justfile_directory()

default:
    @just --list --unsorted

# install dependencies
setup:
    cargo fetch

# the one gate: `just check` green == done. Nothing else counts.
check: typecheck lint test
    @echo "check: OK"

typecheck:
    cargo check --workspace --all-targets

lint:
    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

# run the app locally
dev:
    cargo run -p gateway

# apply formatting
fmt:
    cargo fmt

# PDF security report for management, including a chain attestation
report:
    cargo run --quiet -p gateway --bin report

# prove the audit log has not been edited (exit 1 if it has)
verify-audit:
    cargo run --quiet -p gateway --bin verify-audit

# new schema migration: just db-new add_something
db-new NAME:
    supabase migration new {{NAME}}

# load deterministic demo data into the Supabase project
seed:
    psql "${DATABASE_URL:?set DATABASE_URL in .env}" -v ON_ERROR_STOP=1 -f supabase/seed.sql

# run the gateway and the deliberately vulnerable demo MCP server together
demo:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p gateway -p mcp-demo
    ./target/debug/mcp-demo &
    demo_pid=$!
    trap 'kill $demo_pid 2>/dev/null || true' EXIT
    ./target/debug/gateway

# ship the gateway to Cloud Run. See docs/DEPLOY.md for first-time setup.
deploy region="europe-west1" service="backend":
    gcloud builds submit \
      --config cloudbuild.yaml \
      --substitutions=_REGION={{region}},_SERVICE={{service}}

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

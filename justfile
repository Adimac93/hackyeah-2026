# hackyeah-2026 — the single entrypoint for humans and agents.
#
# RULE: agents and teammates call `just <recipe>`. Never the underlying tool.
# When you add a toolchain, wire it into the matching recipe below instead of
# teaching the team a new command. The stack plugs in here and nowhere else.

set shell := ["bash", "-uc"]
set dotenv-load

repo := justfile_directory()

default:
    @just --list --unsorted

# install dependencies
setup:
    cd web && pnpm install --frozen-lockfile

# the one gate: `just check` green == done. Nothing else counts.
check: typecheck lint test
    @echo "check: OK"

typecheck:
    cd web && pnpm typecheck

# eslint + prettier (@solvro/config); `pnpm format` in web/ fixes formatting
lint:
    cd web && pnpm lint && pnpm format:check

test:
    cd web && pnpm test

# run the app locally
dev:
    cd web && pnpm dev

# load deterministic demo data
seed:
    psql "${SUPABASE_DB_URL:?set SUPABASE_DB_URL (Supabase → Connect → connection string)}" -v ON_ERROR_STOP=1 -f web/supabase/seed.sql

# apply new web/supabase/migrations to the database: just migrate (preview: just migrate --dry-run)
migrate *FLAGS:
    #!/usr/bin/env bash
    set -euo pipefail
    cd web
    # the URL may live in web/.env.local next to the other Supabase settings
    if [ -z "${SUPABASE_DB_URL:-}" ] && [ -f .env.local ]; then set -a; . ./.env.local; set +a; fi
    pnpm dlx supabase@2.119.0 db push --db-url "${SUPABASE_DB_URL:?set SUPABASE_DB_URL in .env or web/.env.local (Supabase → Connect → connection string)}" {{FLAGS}}

# ship to the demo URL. Wire this up on day one, not at hour 23.
deploy:
    @echo "deploy: no stack yet"

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

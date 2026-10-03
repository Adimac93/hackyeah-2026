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
    @echo "setup: no stack yet — wire dependency install here"

# the one gate: `just check` green == done. Nothing else counts.
check: typecheck lint test
    @echo "check: OK"

typecheck:
    @echo "typecheck: no stack yet"

lint:
    @echo "lint: no stack yet"

test:
    @echo "test: no stack yet"

# run the app locally
dev:
    @echo "dev: no stack yet"

# load deterministic demo data
seed:
    @echo "seed: no stack yet"

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

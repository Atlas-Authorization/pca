#!/usr/bin/env bash
# prep.sh <pkg-dir-name>...   run inside a queue job (repo snapshot root) before mutbatch/run.mjs:
# builds the workspace dependencies (dist) of each package, so `@atlasauth/*` imports resolve. (The queue snapshot ships
# every git-tracked file, test fixtures included; nothing is copied from any box-local tree.)
set -uo pipefail
filters=()
for p in "$@"; do n=$(node -p "require('./packages/$p/package.json').name"); filters+=(--filter "$n^..."); done
pnpm "${filters[@]}" build > /tmp/mutbatch-prep.log 2>&1 || { echo "[prep] dependency build failed"; tail -20 /tmp/mutbatch-prep.log; }
echo "[prep] ok: $(find packages -name '*.pem' -path '*fixtures*' | wc -l) pem fixtures in the snapshot"

#!/usr/bin/env bash
# Honest "from a clean directory" check: pack the workspace packages the demo needs into tarballs (exactly what
# `npm publish` would upload), install ONLY those into an empty temp project, and run the demo from there.
# Prints the wall-clock cost of each phase. No registry package from @atlasauth is used.
#   usage: examples/pca-demo/scripts/fresh-install-check.sh [--keep]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/pca-demo-fresh.XXXXXX")"
trap '[ "${1:-}" = "--keep" ] || rm -rf "$T"' EXIT
now() { date +%s; }
S0=$(now)

mkdir -p "$T/tgz" "$T/app"
for p in pca-fndsa-wasm pca pca-fetch; do
  [ -d "$REPO/packages/$p/dist" ] || { echo "packages/$p/dist missing: run 'pnpm --filter @atlasauth/pca-fetch... build' first" >&2; exit 2; }
  (cd "$REPO/packages/$p" && pnpm pack --pack-destination "$T/tgz" >/dev/null)
done
(cd "$REPO/examples/pca-demo" && npm pack --pack-destination "$T/tgz" >/dev/null)
S1=$(now)

cd "$T/app"
npm init -y >/dev/null
npm install --no-audit --no-fund --loglevel=error "$T"/tgz/*.tgz
S2=$(now)
echo "install size: $(du -sh node_modules | cut -f1)"

node node_modules/pca-demo/run.mjs --no-color | tail -3
S3=$(now)
echo "pack: $((S1-S0))s  install: $((S2-S1))s  first run: $((S3-S2))s  total: $((S3-S0))s"

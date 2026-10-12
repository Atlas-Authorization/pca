#!/usr/bin/env bash
# Fails if the committed tools/pca-playground/pca.esm.js differs from a fresh build of the CURRENT sources
# (packages/pca/src + packages/pca-verified-core). esbuild output carries no timestamps, so a byte compare is exact.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/tools/pca-playground"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# the verified core's dist/ is gitignored: build it so the bundle sees the current source
(cd "$ROOT/packages/pca-verified-core" && "$ROOT/packages/pca-verified-core/node_modules/.bin/tsc" -p tsconfig.build.json 2>/dev/null || npx tsc -p tsconfig.build.json)
PLAYGROUND_OUT="$TMP/pca.esm.js" bash "$HERE/build.sh" >/dev/null
if cmp -s "$TMP/pca.esm.js" "$HERE/pca.esm.js"; then echo "playground bundle is fresh"; else
  echo "STALE: tools/pca-playground/pca.esm.js differs from a fresh build; run tools/pca-playground/build.sh and commit" >&2; exit 1; fi

#!/usr/bin/env bash
# Rebuild tools/pca-playground/pca.esm.js from the library SOURCE (packages/pca/src), for the browser.
# entry.ts re-exports only what index.html uses; node:module / node:path (needed only by the lazy, Node-only FN-DSA
# loader in pq.ts) are aliased to tiny shims so the loader fails closed in the browser.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/tools/pca-playground"
ES="$ROOT/node_modules/.bin/esbuild"
[ -x "$ES" ] || ES="$(ls -d "$ROOT"/node_modules/.pnpm/esbuild@*/node_modules/esbuild/bin/esbuild 2>/dev/null | tail -1)"
[ -n "$ES" ] || { echo "esbuild not found (run pnpm install)" >&2; exit 1; }
cd "$ROOT"
"$ES" tools/pca-playground/entry.ts --bundle --format=esm --platform=browser --target=es2022 \
  --alias:node:module=./tools/pca-playground/shims/node-module.js \
  --alias:node:path=./tools/pca-playground/shims/node-path.js \
  --outfile="$HERE/pca.esm.js"
# the bundle must not reference any Node builtin
if grep -nE "from ['\"]node:|require\(['\"]node:" "$HERE/pca.esm.js"; then echo "bundle still references node: builtins" >&2; exit 1; fi
echo "built $HERE/pca.esm.js"

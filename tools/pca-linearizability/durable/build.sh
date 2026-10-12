#!/usr/bin/env bash
# on the box: build.sh [src.ts] [out.mjs]  bundle packages/pca/src/durable-state.ts (the CURRENT synced tree) to /work/replay-linz/durable-state.mjs
set -euo pipefail
ES=$(ls -d /work/pca/node_modules/.pnpm/esbuild@0.19.12/node_modules/esbuild/bin/esbuild)
$ES "${1:-/work/pca/packages/pca/src/durable-state.ts}" --bundle --platform=node --format=esm --outfile="${2:-/work/replay-linz/durable-state.mjs}" --log-level=warning
echo built

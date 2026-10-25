#!/usr/bin/env bash
# Farm runner for @atlasauth/pca-intent: link the two workspace deps (the package is not yet in the lockfile),
# typecheck, run the unit tests, then (optionally) the benchmark.  Usage: bash packages/pca-intent/bench/farm-test.sh [bench]
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p node_modules/@atlasauth
ln -sfn ../../../pca node_modules/@atlasauth/pca
ln -sfn ../../../pca-analyzer node_modules/@atlasauth/pca-analyzer
ROOT=../..
BIN=$ROOT/node_modules/.bin
[ -x "$BIN/vitest" ] || BIN=../pca/node_modules/.bin
[ -f ../pca-analyzer/dist/index.js ] || (cd ../pca-analyzer && "$BIN/tsc" -p tsconfig.build.json)
"$BIN/tsc" -p tsconfig.json --noEmit || echo "TYPECHECK_FAILED"
"$BIN/vitest" run --reporter=verbose src 2>&1 | tail -80 || echo "TESTS_FAILED"
if [ "${1:-}" = bench ]; then
  TSX=$ROOT/node_modules/.bin/tsx; [ -x "$TSX" ] || TSX=../pca/node_modules/.bin/tsx
  "$TSX" bench/run.ts "${@:2}"
fi

#!/usr/bin/env bash
# Run EVERY available PCA language verifier over the shared adversarial corpus + seeded fuzz and fail on any
# cross-language disagreement. Missing toolchains are reported SKIPPED (never passed). See scripts/pca-conformance-all.mjs
# for options (--fuzz N --seed N --sweep N --langs a,b --require a,b --no-native --write-matrix ...).
# Regenerate the committed corpus manifest:  packages/pca/node_modules/.bin/tsx packages/pca-conformance/adversarial/gen-adversarial.ts
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="/usr/local/bin:$HOME/.cargo/bin:$PATH"
exec node "$ROOT/scripts/pca-conformance-all.mjs" "$@"

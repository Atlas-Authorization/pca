#!/usr/bin/env bash
# build.sh [--verify-only | --check]
#   (default)       verify ALL Dafny sources, compile to JavaScript, write packages/pca-verified-core/generated/pca_core.js
#   --verify-only   only run `dafny verify` (every file, with --verify-included-files)
#   --check         build into a temp dir and fail unless the result is byte-identical to the committed generated JS
# Uses a local `dafny` if present, otherwise the cloud box (BOX=gcp|cloud-box-1|cloud-box-2|cloud-box-3; see remote-verify.sh / install-dafny.sh).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
GEN="$ROOT/packages/pca-verified-core/generated"
SRC="Common.dfy Chain.dfy Caveats.dfy Threshold.dfy Replay.dfy Verdict.dfy"
FLAGS="--allow-warnings --verification-time-limit 120 --resource-limit 0"
MODE="${1:-build}"

# Trusted-base audit: the Dafny sources contain NO assume / {:axiom} / {:extern} (comments excluded). Fails the build otherwise.
if grep -nE '^[^/]*(\bassume\b|\{:axiom\}|\{:extern|\bextern\b)' "$HERE"/*.dfy; then echo "FORBIDDEN: assume/axiom/extern found in the Dafny sources" >&2; exit 1; fi

run() { # run '<cmd>' [pull-from-dir pull-to-dir]
  if command -v dafny >/dev/null 2>&1; then (cd "$HERE" && eval "$1"); [ -n "${2:-}" ] && { mkdir -p "$3"; cp -R "$HERE/$2/." "$3/"; } || true
  else PULL_FROM="${2:-}" PULL_TO="${3:-}" "$HERE/remote-verify.sh" "$1"; fi
}

if [ "$MODE" = "--verify-only" ]; then
  run "dafny --version; dafny verify $SRC --verify-included-files $FLAGS"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
run "dafny --version && z3_ver=\$(ls \$(dirname \$(command -v dafny))/z3/bin | tr '\n' ' ') && echo \"z3 binaries: \$z3_ver\" && \
     dafny verify $SRC --verify-included-files $FLAGS && \
     rm -rf build && dafny translate js $SRC --include-runtime --no-verify --allow-warnings -o build/pca_core" build "$TMP"
cat "$TMP/pca_core.js" "$HERE/Footer.js" > "$TMP/generated.js"
if [ "$MODE" = "--check" ]; then
  if cmp -s "$TMP/generated.js" "$GEN/pca_core.js"; then echo "OK: committed generated JS matches a fresh Dafny compile"; else echo "MISMATCH: generated/pca_core.js differs from a fresh compile (run formal/dafny/build.sh)"; diff <(cat "$GEN/pca_core.js") "$TMP/generated.js" | head -20; exit 1; fi
else
  mkdir -p "$GEN"; cp "$TMP/generated.js" "$GEN/pca_core.js"; echo "wrote $GEN/pca_core.js ($(wc -c < "$GEN/pca_core.js") bytes)"
fi

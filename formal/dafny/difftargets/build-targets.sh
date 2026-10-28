#!/usr/bin/env bash
# build-targets.sh [OUTDIR] [targets...]   (default OUTDIR=/work/difft, targets: cs go java py js)
# Compiles Harness.dfy (which includes the UNCHANGED proved modules) with the pinned Dafny to each backend.
# Run on a box with dafny on PATH (verify first: ../verify-toolchain.sh). go needs goimports (pinned below) on PATH.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-/work/difft}"; shift || true
TARGETS="${*:-cs go java py js}"
GOIMPORTS_VERSION=v0.24.0   # golang.org/x/tools/cmd/goimports (Dafny's Go backend shells out to it; pinned for reproducibility)
export PATH="$HOME/go/bin:$PATH"
if echo "$TARGETS" | grep -qw go && ! command -v goimports >/dev/null; then go install golang.org/x/tools/cmd/goimports@$GOIMPORTS_VERSION; fi
mkdir -p "$OUT"
for t in $TARGETS; do
  rm -rf "$OUT/$t"
  echo "== dafny build --target:$t"
  ( cd "$HERE" && dafny build "${HARNESS:-Harness}.dfy" --standard-libraries --target:$t --no-verify --allow-warnings -o "$OUT/$t/h" ) 2>&1 | grep -vE "^$|did not attempt verification|Warning: type parameter|^ *[0-9]* \||^ *\|" || true
done
# js needs bignumber.js next to the output (Dafny's integer runtime); the pinned version is in ../TOOLCHAIN.lock
if echo "$TARGETS" | grep -qw js; then ( cd "$OUT/js" && mkdir -p node_modules && ( [ -d /work/ws/tsx/node_modules/bignumber.js ] && cp -r /work/ws/tsx/node_modules/bignumber.js node_modules/ || npm i --no-save bignumber.js@9.3.1 >/dev/null 2>&1 ) ); fi
echo built: "$TARGETS" in "$OUT"

#!/usr/bin/env bash
# build-ext.sh <Component> [--verify-only | --check]
#   Component in {Wire, Merkle, Taint, Attest, PolicyVm}: verifies formal/dafny/<Component>.dfy (STANDALONE: no includes of the
#   Common/Chain/... files, so this never touches build.sh's artifacts) and compiles it to
#   packages/pca-verified-core/generated/pca_<component>.js (Dafny runtime included, export footer generated from the module names).
#   (default) verify + compile + write   --verify-only   only `dafny verify`   --check   fail unless committed JS == fresh compile
# Runs on the farm through the pcaq queue (formal/dafny/qrun.sh -> cloud-box tooling/remote.sh): each run is a private snapshot, so concurrent runs never clash.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
C="${1:?component (Wire|Merkle|Taint|Attest|PolicyVm|Regex)}"; MODE="${2:-build}"
SRC="$HERE/$C.dfy"; [ -f "$SRC" ] || { echo "no $SRC" >&2; exit 2; }
LC="$(echo "$C" | tr 'A-Z' 'a-z')"
GEN="$ROOT/packages/pca-verified-core/generated"
FLAGS="--allow-warnings --verification-time-limit ${TL:-120} --resource-limit 0 --verify-included-files ${EXTRA:-}"
if grep -nE '^[^/]*(\bassume\b|\{:axiom\}|\{:extern|\bextern\b|\{:verify +false)' "$SRC"; then echo "FORBIDDEN: assume/axiom/extern/verify-false in $SRC" >&2; exit 1; fi
MODS="$(grep -oE '^module +[A-Za-z0-9_]+' "$SRC" | awk '{print $2}' | paste -sd, - | sed 's/,/, /g')"
if [ "$MODE" = "--verify-only" ]; then
  exec "$HERE/qrun.sh" "dafny verify $C.dfy $FLAGS ${VERIFY_EXTRA:-}"
fi
OUT=".qbuild-$C"
rm -rf "$HERE/$OUT"
"$HERE/qrun.sh" "dafny --version && dafny verify $C.dfy $FLAGS ${VERIFY_EXTRA:-} && rm -rf $OUT && dafny translate js $C.dfy --include-runtime --no-verify --allow-warnings -o $OUT/pca_$LC" "$OUT" || { rm -rf "$HERE/$OUT"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP" "$HERE/$OUT"' EXIT
[ -f "$HERE/$OUT/pca_$LC.js" ] || { echo "no compiled output pulled back" >&2; exit 1; }
cp "$HERE/$OUT/pca_$LC.js" "$TMP/pca_$LC.js"
{ cat "$TMP/pca_$LC.js"; printf '\n// ---- exports (appended by formal/dafny/build-ext.sh) ----\nmodule.exports = { _dafny, %s };\n' "$MODS"; } > "$TMP/generated.js"
if [ "$MODE" = "--check" ]; then
  cmp -s "$TMP/generated.js" "$GEN/pca_$LC.js" && echo "OK: pca_$LC.js matches a fresh compile" || { echo "MISMATCH pca_$LC.js"; exit 1; }
else mkdir -p "$GEN"; cp "$TMP/generated.js" "$GEN/pca_$LC.js"; echo "wrote $GEN/pca_$LC.js ($(wc -c < "$GEN/pca_$LC.js") bytes)"; fi

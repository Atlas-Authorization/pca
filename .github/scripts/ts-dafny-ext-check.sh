#!/usr/bin/env bash
# ts-dafny-ext-check.sh <Component>...   (run from the repo root, pinned `dafny` on PATH)
# The standalone Dafny components (formal/dafny/<Component>.dfy): forbidden-construct audit, `dafny verify`, then compile to
# JavaScript exactly as formal/dafny/build-ext.sh does and fail unless packages/pca-verified-core/generated/pca_<component>.js
# is byte-identical to the fresh compile. (build-ext.sh itself dispatches to a remote runner; this is the same recipe, local.)
set -euo pipefail
D="formal/dafny"; GEN="packages/pca-verified-core/generated"
FLAGS="--allow-warnings --verification-time-limit ${TL:-120} --resource-limit 0"
rc=0
for C in "$@"; do
  LC="$(echo "$C" | tr 'A-Z' 'a-z')"; SRC="$D/$C.dfy"
  echo "== $C"
  [ -f "$SRC" ] || { echo "  missing $SRC"; rc=1; continue; }
  if grep -nE '^[^/]*(\bassume\b|\{:axiom\}|\{:extern|\bextern\b|\{:verify +false)' "$SRC"; then echo "  FORBIDDEN construct in $SRC"; rc=1; continue; fi
  MODS="$(grep -oE '^module +[A-Za-z0-9_]+' "$SRC" | awk '{print $2}' | paste -sd, - | sed 's/,/, /g')"
  T="$(mktemp -d)"; OUT=".qbuild-$C"   # same relative output path as build-ext.sh
  if ! (cd "$D" && rm -rf "$OUT" && dafny verify "$C.dfy" $FLAGS && dafny translate js "$C.dfy" --include-runtime --no-verify --allow-warnings -o "$OUT/pca_$LC"); then
    echo "  FAIL: $C does not verify / compile"; rc=1; continue
  fi
  cp "$D/$OUT/pca_$LC.js" "$T/pca_$LC.js"; rm -rf "$D/$OUT"
  { cat "$T/pca_$LC.js"; printf '\n// ---- exports (appended by formal/dafny/build-ext.sh) ----\nmodule.exports = { _dafny, %s };\n' "$MODS"; } > "$T/generated.js"
  if cmp -s "$T/generated.js" "$GEN/pca_$LC.js"; then echo "  OK: pca_$LC.js matches a fresh compile"
  else echo "  MISMATCH: $GEN/pca_$LC.js differs from a fresh compile"; diff "$GEN/pca_$LC.js" "$T/generated.js" | head -20 || true; rc=1; fi
  rm -rf "$T"
done
exit "$rc"

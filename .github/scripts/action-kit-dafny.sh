#!/usr/bin/env bash
# action-kit-dafny.sh <out-dir> : verify formal/dafny/TraitExpand.dfy (A1) and formal/dafny/GoalSelect.dfy (A5: trait selectors and
# role-addressed parameters for the Goal IR; it includes the proved Goal compiler, so that is verified again) with the hash-pinned
# Dafny (formal/dafny/TOOLCHAIN.lock) and compile each to JavaScript (pca_traitexpand.js, pca_goalselect.js, uploaded as artifacts;
# the first green run's files are what gets committed under packages/pca-verified-core/generated). Repo root. Any verification
# error, timeout or forbidden construct fails the job.
set -euo pipefail
OUT="$(mkdir -p "${1:?usage: action-kit-dafny.sh <out-dir>}" && cd "$1" && pwd)"
ROOT="$(pwd)"
# shellcheck disable=SC1091
. formal/dafny/TOOLCHAIN.lock
D="$HOME/.pca-tools/dafny"
mkdir -p "$D"
if [ ! -x "$D/dafny/dafny" ]; then
  ( cd "$D"
    curl -fsSL -o dafny.zip "$DAFNY_RELEASE_URL_BASE/$DAFNY_ZIP_ubuntu_22_04_x64"
    echo "$DAFNY_ZIP_ubuntu_22_04_x64_SHA256  dafny.zip" | sha256sum -c -
    unzip -q -o dafny.zip
    chmod +x dafny/dafny dafny/z3/bin/* )
fi
export PATH="$D/dafny:$PATH"
dafny --version | tee "$OUT/version.txt"
grep -q "^${DAFNY_VERSION}" "$OUT/version.txt" || { echo "unexpected Dafny version"; exit 1; }
ROOT_DAFNY="$ROOT/formal/dafny"
verify_and_compile() { # <Module> <lowercase-name>
  local M="$1" L="$2" SRC="formal/dafny/$1.dfy"
  if grep -nE '^[^/]*(\bassume\b|\{:axiom\}|\{:extern|\bextern\b|\{:verify +false)' "$SRC"; then echo "FORBIDDEN: assume/axiom/extern/verify-false in $SRC"; exit 1; fi
  ( cd "$ROOT_DAFNY"
    dafny verify "$M.dfy" --allow-warnings --verification-time-limit 120 --resource-limit 0 --verify-included-files 2>&1 | tee "$OUT/verify-$L.txt"
    grep -qE "finished with [0-9]+ verified, 0 errors" "$OUT/verify-$L.txt" || { echo "Dafny did not report 0 errors for $M"; exit 1; }
    if grep -qiE "timed out|out of resource|time limit" "$OUT/verify-$L.txt"; then echo "a timeout is not a proof ($M)"; exit 1; fi
    rm -rf "$OUT/build-$L"
    dafny translate js "$M.dfy" --include-runtime --no-verify --allow-warnings -o "$OUT/build-$L/pca_$L" 2>&1 | tee "$OUT/translate-$L.txt"
    { cat "$OUT/build-$L/pca_$L.js"; printf '\n// ---- exports (appended by action-kit-dafny.sh) ----\nmodule.exports = { _dafny, %s%s };\n' "$M" "$([ "$M" = GoalSelect ] && echo ', GoalApi')"; } > "$OUT/pca_$L.js" )
  echo "ok: $M.dfy verified and compiled ($(wc -c < "$OUT/pca_$L.js") bytes)"
}
verify_and_compile TraitExpand traitexpand
verify_and_compile GoalSelect goalselect

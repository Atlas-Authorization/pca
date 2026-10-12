#!/usr/bin/env bash
# ci-check.sh : CI entry point for the diverse-compilation participants (cs, go, java, py, js + the production bridge).
#   1. install + hash-verify the pinned Dafny (../verify-toolchain.sh --install)    2. compile Harness.dfy to every target
#   3. generate the pinned smoke corpus (golden.json) and require every transcript's sha256 to equal the golden digest
#   4. (optional, TSX=path) also run the production bridge driver.   Needs: curl unzip dotnet(8) go java(17+) python3 node npm.
#   CAMPAIGN=<chunks> runs the million-case campaign (scale-run.sh) afterwards.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
DAFNY_DIR="${DAFNY_DIR:-$HOME/.cache/pca-dafny}"; export PATH="$DAFNY_DIR:$HOME/go/bin:$PATH"
"$HERE/../verify-toolchain.sh" --install --dir "$DAFNY_DIR" --runtimes
OUT="${OUT:-$(mktemp -d)}"
"$HERE/build-targets.sh" "$OUT"
read -r N SEED BIG CS TS < <(python3 -c "import json;g=json.load(open('$HERE/golden.json'));print(g['gen']['n'],g['gen']['seed'],g['gen']['big'],g['casesSha256'],g['transcriptSha256'])")
node "$ROOT/packages/pca-verified-core/test/diverse/gen-cases.mjs" --n "$N" --seed "$SEED" --big "$BIG" --out "$OUT/golden.cases"
sh() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
[ "$(sh "$OUT/golden.cases")" = "$CS" ] || { echo "generated corpus differs from golden (generator drift?)"; exit 1; }
rc=0
for t in cs go java py js; do
  "$HERE/run-target.sh" "$t" "$OUT" "$OUT/golden.cases" > "$OUT/t-$t.txt"
  g="$(sh "$OUT/t-$t.txt")"; if [ "$g" = "$TS" ]; then echo "ok    $t transcript == golden"; else echo "FAIL  $t transcript $g != golden $TS"; rc=1; fi
done
if [ -n "${TSX:-}" ]; then ( cd "$ROOT/packages/pca-verified-core/test/diverse" && "$TSX" drive-prod.cts "$OUT/golden.cases" > "$OUT/t-prod.txt" ); g="$(sh "$OUT/t-prod.txt")"; [ "$g" = "$TS" ] && echo "ok    production bridge == golden" || { echo "FAIL  production bridge $g != golden"; rc=1; }; fi
"$HERE/selftest.sh" "$OUT" || rc=1
[ -n "${CAMPAIGN:-}" ] && "$HERE/scale-run.sh" "$OUT" "$CAMPAIGN" 250000 4
exit $rc

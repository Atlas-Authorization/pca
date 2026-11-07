#!/usr/bin/env bash
# goal-ci-check.sh : diverse-compilation check for the goal compiler. Compiles GoalHarness.dfy to cs/go/java/py/js, generates the
# seeded corpus (packages/pca-goal/test/gen-goal-cases.ts), and requires (1) all five target transcripts equal each other,
# (2) equal the production bridge's transcript (generated/pca_goal.js through src/goal.ts), (3) equal the pinned digest in
# goal-golden.json when it has one. Needs the same toolchain as ci-check.sh. env: N (cases/5, default 3000) SEED (default 7).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
DAFNY_DIR="${DAFNY_DIR:-$HOME/.cache/pca-dafny}"; export PATH="$DAFNY_DIR:$HOME/go/bin:$PATH"
"$HERE/../verify-toolchain.sh" --install --dir "$DAFNY_DIR" --runtimes
OUT="${OUT:-$(mktemp -d)}"; N="${N:-3000}"; SEED="${SEED:-7}"
HARNESS=GoalHarness "$HERE/build-targets.sh" "$OUT"
( cd "$ROOT" && pnpm install --frozen-lockfile --filter=@atlasauth/pca-goal... --filter=@atlasauth/pca-verified-core >/dev/null && \
  pnpm --filter @atlasauth/pca-goal exec tsx test/gen-goal-cases.ts --n "$N" --seed "$SEED" --out "$OUT/goal.cases" )
sh() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
rc=0
for t in cs go java py js; do "$HERE/run-target.sh" "$t" "$OUT" "$OUT/goal.cases" > "$OUT/g-$t.txt"; done
( cd "$ROOT/packages/pca-verified-core" && pnpm exec tsx test/diverse/drive-goal-prod.cts "$OUT/goal.cases" > "$OUT/g-prod.txt" )
ref="$(sh "$OUT/g-js.txt")"
for t in cs go java py prod; do g="$(sh "$OUT/g-$t.txt")"; if [ "$g" = "$ref" ]; then echo "ok    $t transcript == js"; else echo "FAIL  $t differs from js"; diff "$OUT/g-js.txt" "$OUT/g-$t.txt" | head -10 || true; rc=1; fi; done
[ "$(wc -l < "$OUT/g-js.txt")" -gt 1000 ] || { echo "FAIL transcript suspiciously short"; rc=1; }
grep -q '^k\|^i\|^s' "$OUT/g-js.txt" || { echo "FAIL transcript is empty of results"; rc=1; }
pin="$(python3 -c "import json;print(json.load(open('$HERE/goal-golden.json')).get('transcriptSha256',''))" 2>/dev/null || true)"
if [ -n "$pin" ]; then [ "$ref" = "$pin" ] && echo "ok    transcript == pinned digest" || { echo "FAIL transcript $ref != pinned $pin"; rc=1; }; else echo "note: goal-golden.json has no pinned digest yet; pin $ref after the first green run"; fi
# the self-test: a flipped comparison in the compiled JS must change the transcript (the check can see a miscompile)
W="$(mktemp -d)"; cp -r "$OUT/js" "$W/js"
python3 - "$W/js/h.js" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
assert "isLessThan(" in s, "no comparison found to mutate"
open(p,'w').write(s.replace("isLessThan(","isLessThanOrEqualTo("))
PY
node "$W/js/h.js" "$OUT/goal.cases" > "$W/bad.txt" || true
if cmp -s "$W/bad.txt" "$OUT/g-js.txt"; then echo "FAIL selftest: injected miscompile NOT detected"; rc=1; else echo "ok    selftest: injected miscompile detected"; fi
rm -rf "$W"; exit $rc

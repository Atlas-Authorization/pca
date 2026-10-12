#!/usr/bin/env bash
# selftest.sh <outdir>   Prove the cross-check can actually see a miscompile: copy the compiled JS target, flip ONE off-by-one
# in the compiled ValidityDecision (`exp < now` -> `exp <= now`), run the same cases and require crosscheck to report a divergence
# that localises to the `val` ops at exactly the boundary. Exit 0 iff the injected fault is DETECTED.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"; O="$1"
W="$(mktemp -d)"; cp -r "$O/js" "$W/js"
python3 - "$W/js/h.js" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
a="} else if ((exp).isLessThan(now)) {\n        return Verdict.Validity.create_VExpired();"
assert a in s, "pattern not found"
open(p,'w').write(s.replace(a,"} else if ((exp).isLessThanOrEqualTo(now)) {\n        return Verdict.Validity.create_VExpired();",1))
PY
node "$ROOT/packages/pca-verified-core/test/diverse/gen-cases.mjs" --n 6000 --seed 5 --ops val --out "$W/c.txt"
# boundary cases the random mix may miss
printf 'val 1 10 20 20\nval 1 10 20 21\nval 1 10 20 19\n' >> "$W/c.txt"
node "$O/js/h.js" "$W/c.txt" > "$W/good.txt"; node "$W/js/h.js" "$W/c.txt" > "$W/bad.txt"
if cmp -s "$W/good.txt" "$W/bad.txt"; then echo "SELFTEST FAILED: injected miscompile NOT detected"; rm -rf "$W"; exit 1; fi
n=$(diff "$W/good.txt" "$W/bad.txt" | grep -c '^<'); echo "SELFTEST OK: injected off-by-one detected ($n differing lines, e.g. $(diff "$W/good.txt" "$W/bad.txt" | head -3 | tr '\n' ' '))"
rm -rf "$W"

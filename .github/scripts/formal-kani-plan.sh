#!/usr/bin/env bash
# formal-kani-plan.sh <probe:true|false> [<long-matrix file>] : print the Kani job matrix
# ({"include":[{crate,harness,features,probe}]}) for every tools/pca-implverif/kani-*/ crate whose verified sources are
# present under sdks/ (see formal-natives.sh). Harnesses come from `cargo kani list` (per declared cargo feature too);
# tiers from formal-kani-tiers.txt. "long"-tier harnesses are NOT in that matrix: they go to the long-matrix file
# ({"include":[{crate,harness,features}]}, one non-gating job each), or are dropped when no file is given.
# Argument order: `--features` is a cargo-kani option, not a `list` one (Kani 0.68 rejects it after `list`); the -Z flags
# go after `list` (list's own options replace the top-level common ones).
set -euo pipefail
PROBE="$1"; LONG_OUT="${2:-}"; HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(pwd)"; T="$RUNNER_TEMP/kani-list"; mkdir -p "$T"; : > "$T/all.tsv"
for d in tools/pca-implverif/kani-*/; do
  c="$(basename "$d")"; [ -x "$d/build.sh" ] || [ -f "$d/build.sh" ] || continue
  src="$(grep -oE '\.\./\.\./\.\./sdks/[^ ";]+' "$d/build.sh" | head -1)"
  if [ -z "$src" ] || [ ! -e "$d/$src" ]; then echo "skip $c: verified sources ${src#../../../} not present" >&2; continue; fi
  (cd "$d" && bash ./build.sh >/dev/null)
  feats=("")
  if grep -q '^\[features\]' "$d/Cargo.toml"; then
    while read -r f; do [ -n "$f" ] && [ "$f" != default ] && feats+=("$f"); done \
      < <(awk '/^\[features\]/{s=1;next} /^\[/{s=0} s&&/=/{sub(/[ \t]*=.*/,"");print}' "$d/Cargo.toml")
  fi
  for f in "${feats[@]}"; do
    if ! (cd "$d" && rm -f kani-list.json && cargo kani ${f:+--features "$f"} list --format json -Z function-contracts -Z stubbing -Z loop-contracts >&2); then
      if grep -qE "^broken +$c " "$HERE/formal-kani-tiers.txt"; then
        echo "::warning::$c${f:+ [$f]}: harness crate does not compile under Kani (known, formal-kani-tiers.txt): $(grep -E "^broken +$c " "$HERE/formal-kani-tiers.txt" | cut -c1-200)" >&2
      else
        echo "$c${f:+ [$f]}" >> "$T/failed.txt"; echo "::error::$c${f:+ [$f]}: the harness crate does not compile under Kani (see the log above)" >&2
      fi
      continue
    fi
    python3 - "$d/kani-list.json" "$c" "$f" >> "$T/all.tsv" <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))
for k in ('standard-harnesses', 'contract-harnesses'):
    for _, names in (j.get(k) or {}).items():
        for n in names:
            print(f"{sys.argv[2]}\t{n}\t{sys.argv[3]}")
PY
  done
done
python3 - "$T/all.tsv" "$HERE/formal-kani-tiers.txt" "$PROBE" "$LONG_OUT" <<'PY'
import json, re, sys
rows, seen = [], set()
for line in open(sys.argv[1]):
    c, h, f = line.rstrip('\n').split('\t')
    if (c, h) in seen:      # listed without the feature already: no feature needed
        continue
    seen.add((c, h)); rows.append((c, h, f))
tiers = []
for line in open(sys.argv[2]):
    if line.strip() and not line.startswith('#'):
        t, c, rx, *why = line.split()
        if t == 'broken':
            continue
        tiers.append((t, c, re.compile(rx), ' '.join(why)))
probe = sys.argv[3] == 'true'
inc, long = [], []
for c, h, f in rows:
    tier = next((t for t, tc, rx, _ in tiers if tc == c and rx.search(h)), 'required')
    print(f'{tier:8} {c} {h}{" [" + f + "]" if f else ""}', file=sys.stderr)
    if tier == 'long':
        long.append({'crate': c, 'harness': h, 'features': f})
        continue
    if tier == 'exclude' or (tier == 'probe' and not probe):
        continue
    inc.append({'crate': c, 'harness': h, 'features': f, 'probe': tier == 'probe'})
if sys.argv[4]:
    with open(sys.argv[4], 'w') as o:
        o.write(json.dumps({'include': long}))
print(json.dumps({'include': inc}))
PY
# a harness crate that does not compile is a failure of this run (the other crates' harnesses still run)
[ ! -s "$T/failed.txt" ] || exit 3

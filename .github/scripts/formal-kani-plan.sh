#!/usr/bin/env bash
# formal-kani-plan.sh <probe:true|false> : print the Kani job matrix ({"include":[{crate,harness,features,probe}]}) for
# every tools/pca-implverif/kani-*/ crate whose verified sources are present under sdks/ (see formal-natives.sh).
# Harnesses come from `cargo kani list` (per declared cargo feature too); tiers from formal-kani-tiers.txt.
set -euo pipefail
PROBE="$1"; HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(pwd)"; T="$RUNNER_TEMP/kani-list"; mkdir -p "$T"; : > "$T/all.tsv"
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
    if ! (cd "$d" && rm -f kani-list.json && cargo kani list --format json ${f:+--features "$f"} -Z function-contracts -Z stubbing -Z loop-contracts >&2); then
      echo "$c${f:+ [$f]}" >> "$T/failed.txt"; echo "::error::$c${f:+ [$f]}: the harness crate does not compile under Kani (see the log above)" >&2; continue
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
python3 - "$T/all.tsv" "$HERE/formal-kani-tiers.txt" "$PROBE" <<'PY'
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
        tiers.append((t, c, re.compile(rx), ' '.join(why)))
probe = sys.argv[3] == 'true'
inc = []
for c, h, f in rows:
    tier = next((t for t, tc, rx, _ in tiers if tc == c and rx.search(h)), 'required')
    print(f'{tier:8} {c} {h}{" [" + f + "]" if f else ""}', file=sys.stderr)
    if tier == 'exclude' or (tier == 'probe' and not probe):
        continue
    inc.append({'crate': c, 'harness': h, 'features': f, 'probe': tier == 'probe'})
print(json.dumps({'include': inc}))
PY
# a harness crate that does not compile is a failure of this run (the other crates' harnesses still run)
[ ! -s "$T/failed.txt" ] || exit 3

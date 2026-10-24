#!/usr/bin/env bash
# Build + axiom-audit the Lean development and model-check the TLA+ loop. Runs ON A FARM BOX at the repo root:
#   cloud-box tooling/q submit --wait --need java --cores 2 --mem 6 --pull formal/intent/results -- bash formal/intent/farm-check.sh
# Never run Mathlib builds on the Mac.
set -uo pipefail
R="$(cd "$(dirname "$0")" && pwd)"
OUT="$R/results"; mkdir -p "$OUT"
export PATH="$HOME/.elan/bin:$PATH"
if ! command -v lake >/dev/null 2>&1; then
  echo "== installing elan"
  curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none >/dev/null
  export PATH="$HOME/.elan/bin:$PATH"
fi
cd "$R/lean"
# Reuse the box's prebuilt Mathlib (same tag v4.34.1 as formal/computational/leanmath) when present.
shared=""
for d in /work/comp/leanmath/.lake/packages /work/cs/leanmath/.lake/packages; do
  if [ -d "$d/mathlib/.lake/build" ]; then shared="$d"; break; fi
done
mkdir -p .lake
if [ -n "$shared" ]; then echo "== shared Mathlib packages: $shared"; ln -sfn "$shared" .lake/packages
else
  # persistent per-box package dir (outlives the job workspace), so reruns on the same box skip the download
  pk="$HOME/.cache/pca-intent/packages"; mkdir -p "$pk"; ln -sfn "$pk" .lake/packages
  echo "== no shared Mathlib; using $pk"
  ( flock 9; lake exe cache get 2>&1 | tr '\r' '\n' | tail -3 ) 9>"$HOME/.cache/pca-intent/lock"
fi
echo "== sorry/admit scan"
if grep -nE '\bsorry\b|\badmit\b' PcaIntent/*.lean | grep -v '^\s*--'; then echo "FOUND sorry/admit" | tee "$OUT/sorry-scan.txt"; else echo "none" | tee "$OUT/sorry-scan.txt"; fi
echo "== lake build"
start=$(date +%s)
nice -n 10 lake build 2>&1 | tee "$OUT/lean-build.txt" | grep --line-buffered -vE '^(✔|⣿|info:)' | tail -300
brc=${PIPESTATUS[0]}
echo "build rc=$brc ($(( $(date +%s) - start ))s)" | tee -a "$OUT/lean-build.txt"
if [ "$brc" = 0 ]; then
  echo "== #print axioms"
  lake env lean Axioms.lean 2>&1 | tee "$OUT/axioms.txt" | tail -80
  if grep -q sorryAx "$OUT/axioms.txt"; then echo "AXIOM AUDIT: FAIL (sorryAx)"; else
    bad=$(grep "depends on axioms" "$OUT/axioms.txt" | grep -vE "\[(propext|Classical.choice|Quot.sound)(, (propext|Classical.choice|Quot.sound))*\]" | wc -l)
    echo "AXIOM AUDIT: $(grep -c 'depends on axioms\|does not depend on any axioms' "$OUT/axioms.txt") theorems, nonstandard=$bad" | tee -a "$OUT/axioms.txt"; fi
fi
echo "== TLA+"
if [ -n "${SKIP_TLA:-}" ]; then echo "skipped"; trc=0
elif command -v java >/dev/null 2>&1; then OUT="$OUT/tla" bash "$R/tla/run.sh"; trc=$?; else echo "no java"; trc=9; fi
echo "tla rc=$trc"
[ "$brc" = 0 ] && [ "$trc" = 0 ]

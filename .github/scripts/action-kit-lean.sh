#!/usr/bin/env bash
# action-kit-lean.sh <out-dir> : elaborate formal/intent/lean/PcaIntent/TraitAlg.lean (core Lean, no Mathlib) with the project's
# pinned toolchain, scan for sorry/axiom, and audit the axioms of EVERY theorem in the file (only propext, Classical.choice and
# Quot.sound may appear). Repo root. The full Mathlib project build is the `lean intent` job of formal-proofs.yml.
set -uo pipefail
OUT="$(mkdir -p "${1:?usage: action-kit-lean.sh <out-dir>}" && cd "$1" && pwd)"
F=formal/intent/lean/PcaIntent/TraitAlg.lean
F2=formal/intent/lean/PcaIntent/PinEvolve.lean
rc=0
if grep -nE '^[^-]*(^|[^`[:alnum:]_.])(sorry|admit)([^`[:alnum:]_]|$)' "$F" "$F2"; then echo "FOUND sorry/admit"; rc=1; fi
if grep -nE '^\s*(axiom|unsafe|opaque)\b|\bimplemented_by\b|@\[extern' "$F" "$F2"; then echo "FOUND axiom/unsafe/opaque/extern"; rc=1; fi
if ! command -v elan >/dev/null 2>&1; then
  curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none >/dev/null
  export PATH="$HOME/.elan/bin:$PATH"
fi
TC="$(cat formal/intent/lean/lean-toolchain)"
elan toolchain install "$TC" 2>&1 | tail -2
cp "$F" "$OUT/TraitAlgAudit.lean"
n=0
for name in $(grep -oE "^theorem [A-Za-z0-9_']+" "$F" | awk '{print $2}'); do
  echo "#print axioms PcaIntent.TraitAlg.$name" >> "$OUT/TraitAlgAudit.lean"
  n=$((n+1))
done
# PinEvolve imports TraitAlg: compile the latter to an .olean first, then audit the former in the same way
mkdir -p "$OUT/lo/PcaIntent"
elan run "$TC" lean -o "$OUT/lo/PcaIntent/TraitAlg.olean" "$F" >/dev/null 2>&1 || { echo "TraitAlg olean build failed"; rc=1; }
cp "$F2" "$OUT/PinEvolveAudit.lean"
m=0
for name in $(grep -oE "^theorem [A-Za-z0-9_']+" "$F2" | awk '{print $2}'); do
  echo "#print axioms PcaIntent.PinEvolve.$name" >> "$OUT/PinEvolveAudit.lean"
  m=$((m+1))
done
LEAN_PATH="$OUT/lo" elan run "$TC" lean "$OUT/PinEvolveAudit.lean" 2>&1 | tee "$OUT/lean-pin.txt"
[ "${PIPESTATUS[0]}" = 0 ] || { echo "Lean elaboration of PinEvolve failed"; rc=1; }
if grep -q "sorry" "$OUT/lean-pin.txt"; then echo "sorry in PinEvolve"; rc=1; fi
if grep "depends on axioms" "$OUT/lean-pin.txt" | grep -vE "\[(propext|Classical.choice|Quot.sound)(, (propext|Classical.choice|Quot.sound))*\]"; then echo "non-standard axioms in PinEvolve"; rc=1; fi
pa=$(grep -cE "depends on axioms|does not depend on any axioms" "$OUT/lean-pin.txt" || true)
[ "$pa" -ge "$m" ] || { echo "PinEvolve axiom audit incomplete ($pa of $m)"; rc=1; }
echo "auditing $n theorems"
elan run "$TC" lean "$OUT/TraitAlgAudit.lean" 2>&1 | tee "$OUT/lean.txt"
[ "${PIPESTATUS[0]}" = 0 ] || { echo "Lean elaboration failed"; rc=1; }
if grep -q "declaration uses 'sorry'" "$OUT/lean.txt"; then echo "sorry in the build"; rc=1; fi
if grep -q sorryAx "$OUT/lean.txt"; then echo "sorryAx in the axiom audit"; rc=1; fi
if grep "depends on axioms" "$OUT/lean.txt" | grep -vE "\[(propext|Classical.choice|Quot.sound)(, (propext|Classical.choice|Quot.sound))*\]"; then echo "non-standard axioms"; rc=1; fi
audited=$(grep -cE "depends on axioms|does not depend on any axioms" "$OUT/lean.txt" || true)
echo "audited lines: $audited of $n theorems"
[ "$audited" -ge "$n" ] || { echo "axiom audit output is incomplete"; rc=1; }
echo "lean TraitAlg rc=$rc"
exit $rc

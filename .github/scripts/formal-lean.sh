#!/usr/bin/env bash
# formal-lean.sh <part> <out-dir> : lake build + sorry/axiom audit of one Lean development.
#   pca-lean | computational | leanmath (Mathlib) | implverif (lean-ref + lean-xcheck) | intent (Mathlib + TLA, formal/intent)
set -uo pipefail
P="$1"; OUT="$2"; mkdir -p "$OUT"; ROOT="$(pwd)"; rc=0
# a bare sorry/admit token outside line comments (a backtick-quoted mention in a doc comment is not one); the build log
# check below ("declaration uses 'sorry'") is the authoritative one
sorry_scan() { if grep -rnE '^[^-]*(^|[^`[:alnum:]_])(sorry|admit)([^`[:alnum:]_]|$)' --include='*.lean' "$@" | grep -v '/.lake/'; then echo "FOUND sorry/admit"; rc=1; fi; }
sorry_build() { if grep -h "declaration uses 'sorry'" "$OUT"/*.txt 2>/dev/null; then echo "FOUND sorry in the build"; rc=1; fi; }
std_axioms() { # fail on sorryAx or any axiom outside the three standard ones
  if grep -q sorryAx "$1"; then echo "sorryAx in $1"; rc=1; fi
  if grep "depends on axioms" "$1" | grep -vqE "\[(propext|Classical.choice|Quot.sound)(, (propext|Classical.choice|Quot.sound))*\]"; then
    echo "non-standard axioms in $1:"; grep "depends on axioms" "$1" | grep -vE "\[(propext|Classical.choice|Quot.sound)(, (propext|Classical.choice|Quot.sound))*\]"; rc=1; fi
}
case "$P" in
  pca-lean)
    sorry_scan formal/pca-lean
    (cd formal/pca-lean && lake build) 2>&1 | tee "$OUT/build.txt"; [ "${PIPESTATUS[0]}" = 0 ] || rc=1 ;;
  computational)
    sorry_scan formal/computational/lean
    bash formal/computational/check.sh lean 2>&1 | tee "$OUT/build.txt"; [ "${PIPESTATUS[0]}" = 0 ] || rc=1
    std_axioms "$OUT/build.txt" ;;
  leanmath)
    sorry_scan formal/computational/leanmath
    (cd formal/computational/leanmath && lake exe cache get) 2>&1 | tail -5
    bash formal/computational/check.sh leanmath 2>&1 | tee "$OUT/build.txt"; [ "${PIPESTATUS[0]}" = 0 ] || rc=1
    std_axioms "$OUT/build.txt" ;;
  implverif)
    sorry_scan tools/pca-implverif/lean-ref tools/pca-formal/lean-xcheck
    (cd tools/pca-implverif/lean-ref && lake build) 2>&1 | tee "$OUT/lean-ref.txt"; [ "${PIPESTATUS[0]}" = 0 ] || rc=1
    if [ -f tools/pca-formal/lean-xcheck/lakefile.toml ]; then
      (cd tools/pca-formal/lean-xcheck && lake build) 2>&1 | tee "$OUT/lean-xcheck.txt"; [ "${PIPESTATUS[0]}" = 0 ] || rc=1
    fi ;;
  intent)
    # formal/intent/farm-check.sh: Mathlib cache, sorry scan, lake build, #print axioms, TLC loop model
    bash formal/intent/farm-check.sh 2>&1 | tee "$OUT/check.txt"; [ "${PIPESTATUS[0]}" = 0 ] || rc=1
    grep -q "FOUND sorry/admit" "$OUT/check.txt" && rc=1
    [ -f formal/intent/results/axioms.txt ] && std_axioms formal/intent/results/axioms.txt
    cp -R formal/intent/results "$OUT/" 2>/dev/null || true ;;
  *) echo "unknown part $P"; exit 2 ;;
esac
sorry_build
echo "lean $P rc=$rc"; exit $rc

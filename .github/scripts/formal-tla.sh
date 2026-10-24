#!/usr/bin/env bash
# formal-tla.sh <out-dir> : TLC over every case file (formal/tla/cases*.txt; formal/intent/tla when present), the formal/pca
# MC_* models, and the Apalache inductive proof. A case that does not reach its recorded expectation (pass, or the expected
# counterexample for a deliberate-failure config) fails the job. Needs ~/tla2tools.jar and apalache-mc on PATH.
set -uo pipefail
OUT="$1"; mkdir -p "$OUT"; ROOT="$(pwd)"; export TLA_JAR="$HOME/tla2tools.jar" WORKERS="${WORKERS:-auto}"; rc=0
for c in formal/tla/cases*.txt; do
  n="$(basename "$c" .txt)"; echo "== TLC $c"
  (cd formal/tla && CASES="$(basename "$c")" OUT="$OUT/$n" bash run.sh) || rc=1
done
if [ -f formal/tla/run-apalache.sh ]; then
  echo "== Apalache (unbounded ExactlyOnce)"; (cd formal/tla && OUT="$OUT/apalache" bash run-apalache.sh) || rc=1
  # run-apalache.sh counts any non-OK exit as "fail": a crashed tool would make the expected-fail cases look right.
  # Every case must have run to an Apalache verdict (EXITCODE line).
  noverdict="$(grep -L 'EXITCODE' "$OUT"/apalache/apa_*.txt 2>/dev/null)"
  [ -z "$noverdict" ] || { echo "Apalache produced no verdict for:"; echo "$noverdict"; rc=1; }
fi
if [ -f formal/intent/tla/run.sh ]; then
  echo "== TLC formal/intent/tla"; (cd formal/intent/tla && OUT="$OUT/intent" WORKERS=4 bash run.sh) || rc=1
fi
if [ -d formal/pca ]; then
  # formal/pca/README.md: the three MC_* configs hold; MC_Attenuation_widen is the negative control (must be violated).
  mkdir -p "$OUT/pca"
  mc() { # cfg module expect
    local m; m="$(mktemp -d)"
    (cd formal/pca && java -Xmx3g -cp "$TLA_JAR" tlc2.TLC -workers auto -metadir "$m" -config "$1" "$2") > "$OUT/pca/$1.txt" 2>&1
    local got=error; grep -q "Model checking completed. No error has been found" "$OUT/pca/$1.txt" && got=pass
    grep -qE "Invariant .* is violated" "$OUT/pca/$1.txt" && got=fail
    printf '%-28s expect=%s got=%s\n' "$1" "$3" "$got"; [ "$got" = "$3" ] || rc=1
  }
  mc MC_TrustBudget.cfg MC_TrustBudget pass
  mc MC_TrustBudget_k2.cfg MC_TrustBudget pass
  mc MC_Attenuation.cfg MC_Attenuation pass
  mc MC_Attenuation_widen.cfg MC_Attenuation fail
fi
echo "TLA rc=$rc"; exit $rc

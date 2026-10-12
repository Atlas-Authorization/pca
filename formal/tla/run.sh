#!/usr/bin/env bash
# Model-check every case in cases.txt with TLC.  usage: formal/tla/run.sh [name-filter]
# env: TLA_JAR (default ./tla2tools.jar or ~/tla2tools.jar), WORKERS (default auto), OUT (default results/),
#      CASES (default cases.txt; e.g. cases-budget.txt for BudgetTree/ScopeChain, OUT=results/budget)
# Each case writes results/<name>.txt (TLC output; for expected-fail cases it contains the counterexample trace).
set -uo pipefail
cd "$(dirname "$0")"
JAR="${TLA_JAR:-}"; [ -n "$JAR" ] || for j in ./tla2tools.jar "$HOME/tla2tools.jar" /work/tla/tla2tools.jar; do [ -f "$j" ] && JAR="$j" && break; done
[ -f "$JAR" ] || { echo "tla2tools.jar not found (set TLA_JAR)" >&2; exit 2; }
OUT="${OUT:-results}"; mkdir -p "$OUT" cfg
W="${WORKERS:-auto}"; bad=0; summary="$OUT/SUMMARY.txt"; : > "$summary"
while IFS='|' read -r name mod invs consts expect; do
  name="$(echo "$name" | xargs)"; case "$name" in ''|\#*) continue;; esac
  [ -n "${1:-}" ] && [[ "$name" != *$1* ]] && continue
  mod="$(echo "$mod" | xargs)"; invs="$(echo "$invs" | xargs)"; expect="$(echo "$expect" | xargs)"
  cfg="cfg/$name.cfg"
  # invariants column: plain names are INVARIANTs; `spec:Name` replaces SPECIFICATION Spec; `prop:Name` adds a temporal PROPERTY
  spec=Spec; for i in $invs; do case "$i" in spec:*) spec="${i#spec:}";; esac; done
  { echo "SPECIFICATION $spec"; for i in $invs; do case "$i" in spec:*) ;; prop:*) echo "PROPERTY ${i#prop:}";; *) echo "INVARIANT $i";; esac; done; echo "CONSTANTS"
    echo "$consts" | tr ';' '\n' | sed 's/^ *//;s/ *$//;/^$/d;s/^/  /'; } > "$cfg"
  meta="$(mktemp -d)"
  start=$(date +%s)
  java -XX:+UseParallelGC -Xmx3g -cp "$JAR" tlc2.TLC -workers "$W" -deadlock -metadir "$meta" -config "$cfg" "$mod.tla" > "$OUT/$name.txt" 2>&1
  rc=$?; rm -rf "$meta"; dur=$(( $(date +%s) - start ))
  if grep -q "Model checking completed. No error has been found" "$OUT/$name.txt"; then got=pass
  elif grep -qE "Invariant .* is violated|Temporal propert(y|ies) .*(was|were) violated" "$OUT/$name.txt"; then got=fail
  else got="error(rc=$rc)"; fi
  states="$(grep -E "^[0-9]+ states generated, [0-9]+ distinct states found" "$OUT/$name.txt" | head -1 | sed -E 's/^([0-9]+) states generated, ([0-9]+) distinct.*/\1 gen \2 distinct/')"
  viol="$(grep -E "Invariant .* is violated|Temporal propert(y|ies) .*(was|were) violated" "$OUT/$name.txt" | head -1)"
  verdict=OK; [ "$got" = "$expect" ] || { verdict=MISMATCH; bad=$((bad+1)); }
  printf '%-34s expect=%-4s got=%-4s %-8s %5ss  %s %s\n' "$name" "$expect" "$got" "$verdict" "$dur" "$states" "$viol" | tee -a "$summary"
done < "${CASES:-cases.txt}"
echo "mismatches: $bad" | tee -a "$summary"
exit $bad

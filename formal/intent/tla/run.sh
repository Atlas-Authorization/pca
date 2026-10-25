#!/usr/bin/env bash
# Model-check every case in cases.txt with TLC (same case format as formal/tla/run.sh).
#   usage: formal/intent/tla/run.sh [name-filter]      env: TLA_JAR, WORKERS (default 2), OUT (default results/)
set -uo pipefail
cd "$(dirname "$0")"
JAR="${TLA_JAR:-}"; [ -n "$JAR" ] || for j in ./tla2tools.jar "$HOME/tla2tools.jar" /work/tla/tla2tools.jar /work/tools/tla2tools.jar; do [ -f "$j" ] && JAR="$j" && break; done
if [ ! -f "$JAR" ]; then
  JAR="$PWD/.tla2tools.jar"
  curl -fsSL -o "$JAR" https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar || { echo "no tla2tools.jar" >&2; exit 2; }
fi
OUT="${OUT:-results}"; mkdir -p "$OUT" cfg
W="${WORKERS:-2}"; bad=0; summary="$OUT/SUMMARY.txt"; : > "$summary"
while IFS='|' read -r name mod invs consts expect; do
  name="$(echo "$name" | xargs)"; case "$name" in ''|\#*) continue;; esac
  [ -n "${1:-}" ] && [[ "$name" != *$1* ]] && continue
  mod="$(echo "$mod" | xargs)"; invs="$(echo "$invs" | xargs)"; expect="$(echo "$expect" | xargs)"
  cfg="cfg/$name.cfg"
  { echo "SPECIFICATION Spec"; for i in $invs; do case "$i" in prop:*) echo "PROPERTY ${i#prop:}";; *) echo "INVARIANT $i";; esac; done; echo "CONSTANTS"
    echo "$consts" | tr ';' '\n' | sed 's/^ *//;s/ *$//;/^$/d;s/^/  /'; } > "$cfg"
  meta="$(mktemp -d)"; start=$(date +%s)
  java -XX:+UseParallelGC -Xmx2g -cp "$JAR" tlc2.TLC -deadlock -workers "$W" -metadir "$meta" -config "$cfg" "$mod.tla" > "$OUT/$name.txt" 2>&1
  rc=$?; rm -rf "$meta"; dur=$(( $(date +%s) - start ))
  if grep -q "Model checking completed. No error has been found" "$OUT/$name.txt"; then got=pass
  elif grep -qE "Invariant .* is violated|Temporal propert(y|ies) .*(was|were) violated|Action property .* is violated" "$OUT/$name.txt"; then got=fail
  else got="error(rc=$rc)"; fi
  states="$(grep -E "^[0-9]+ states generated, [0-9]+ distinct states found" "$OUT/$name.txt" | head -1 | sed -E 's/^([0-9]+) states generated, ([0-9]+) distinct.*/\1 gen \2 distinct/')"
  viol="$(grep -E "Invariant .* is violated|Temporal propert(y|ies) .*(was|were) violated" "$OUT/$name.txt" | head -1)"
  verdict=OK; [ "$got" = "$expect" ] || { verdict=MISMATCH; bad=$((bad+1)); }
  printf '%-20s expect=%-5s got=%-12s %-8s %4ss  %s %s\n' "$name" "$expect" "$got" "$verdict" "$dur" "$states" "$viol" | tee -a "$summary"
done < cases.txt
echo "mismatches: $bad" | tee -a "$summary"
[ "$bad" = 0 ]

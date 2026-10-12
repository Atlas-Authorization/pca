#!/bin/sh
# usage: run_v3.sh <out-name> <theory> <lemma> [tamarin flags...]   (env TO=timeout secs, default 3600; RTS=-N8)
# Appends result line + wall time + version + command to results/v3/<out-name>.txt.  TIMEOUT => explicit NOT PROVED line.
O=$1; F=$2; L=$3; shift 3; TO=${TO:-3600}; mkdir -p results/v3
S=$(date +%s)
OUT=$(perl -e 'alarm shift; exec @ARGV' "$TO" tamarin-prover --prove="$L" "$@" "$F" +RTS ${RTS:--N8} 2>&1)
E=$(date +%s)
R=$(printf '%s\n' "$OUT" | grep -E "^  $L \(")
if [ -z "$R" ]; then
  if [ $((E-S)) -ge $((TO-2)) ]; then R="$L TIMEOUT after ${TO}s (NOT proved)"; else R="$L ABORTED after $((E-S))s: tool exited without a result, e.g. out of memory (NOT proved)"; fi
fi
printf '%s\n# wall=%ss tamarin-prover 1.12.0 cmd=tamarin-prover --prove=%s %s %s +RTS %s\n' "$R" $((E-S)) "$L" "$*" "$F" "${RTS:--N8}" >> results/v3/$O.txt
printf '%s\n' "$R"

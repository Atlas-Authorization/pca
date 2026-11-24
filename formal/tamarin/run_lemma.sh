#!/bin/sh
# usage: run_lemma.sh <timeout-seconds> <theory.spthy> <lemma> [tamarin flags e.g. --heuristic=c -DNO_GREF_CHECK]
# Runs ONE lemma with a wall-clock timeout (perl alarm; macOS has no GNU timeout) and prints the result line(s).
# No result line => "TIMEOUT" only when the alarm fired; a run that ended early without a result prints NO RESULT with its
# exit status and output tail (a tool crash is not a timeout). Either way the lemma is NOT proved.
T=$1; F=$2; L=$3; shift 3
S0=$(date +%s)
OUT=$(perl -e 'alarm shift; exec @ARGV' "$T" tamarin-prover --prove="$L" "$@" "$F" 2>&1); RC=$?
EL=$(( $(date +%s) - S0 ))
RES=$(printf '%s\n' "$OUT" | grep -E "^  $L \(")
if [ -n "$RES" ]; then printf '%s\n' "$RES"; printf '%s\n' "$OUT" | grep -E "processing time" | head -1
elif [ "$EL" -ge "$T" ]; then echo "TIMEOUT after ${T}s (not proved): $L"
else
  echo "NO RESULT after ${EL}s, exit $RC (not proved): $L"
  printf '%s\n' "$OUT" | tail -12 | sed 's/^/    | /' >&2
fi

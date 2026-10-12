#!/bin/sh
# usage: run_lemma.sh <timeout-seconds> <theory.spthy> <lemma> [tamarin flags e.g. --heuristic=c -DNO_GREF_CHECK]
# Runs ONE lemma with a wall-clock timeout (perl alarm; macOS has no GNU timeout) and prints the result line(s).
# No result line within the timeout => the line "TIMEOUT" is printed (the lemma is then NOT proved).
T=$1; F=$2; L=$3; shift 3
OUT=$(perl -e 'alarm shift; exec @ARGV' "$T" tamarin-prover --prove="$L" "$@" "$F" 2>&1)
RES=$(printf '%s\n' "$OUT" | grep -E "^  $L \(")
if [ -n "$RES" ]; then printf '%s\n' "$RES"; printf '%s\n' "$OUT" | grep -E "processing time" | head -1
else
  if printf '%s\n' "$OUT" | grep -q "unexpected\|error\|Error"; then printf '%s\n' "$OUT" | tail -8; else echo "TIMEOUT after ${T}s (not proved): $L"; fi
fi

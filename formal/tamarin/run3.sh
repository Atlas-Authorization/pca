#!/bin/bash
# usage: run3.sh <timeout-s> <theory> <lemma> <outname> [tamarin args...]   (run on a cloud box, in the formal/tamarin dir)
# Writes results/v3/<outname>.txt: result line(s) + wall + version + command. A TIMEOUT line means NOT proved.
source ~/pcaenv.sh
T=$1; th=$2; lem=$3; on=$4; shift 4
mkdir -p results/v3
s=$(date +%s)
raw=$(perl -e 'alarm shift; exec @ARGV' "$T" tamarin-prover --prove=$lem "$@" $th +RTS -N${NT:-4} -M${MEM:-10}g 2>&1)
e=$(date +%s)
r=$(printf '%s\n' "$raw" | grep -E "^  [A-Za-z0-9_]+ \((all-traces|exists-trace)\)" | grep -v "analysis incomplete")
printf '%s\n' "$raw" | grep -q "Heap exhausted" && [ -z "$r" ] && r="OPEN (NOT proved): heap exhausted at +RTS -M${MEM:-10}g after $((e-s))s: $lem"
[ -n "$r" ] || r="TIMEOUT-or-error after ${T}s (NOT proved): $lem $(printf '%s\n' "$raw" | grep -iE 'unexpected|error' | head -2)"
{ echo "$r"; echo "# wall=$((e-s))s tamarin-prover 1.12.0 cmd=tamarin-prover --prove=$lem $* $th +RTS -N${NT:-4} -M${MEM:-10}g"; } > results/v3/$on.txt
printf '%s\n' "$raw" > results/v3/raw_$on.log

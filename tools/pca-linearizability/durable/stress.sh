#!/usr/bin/env bash
# durable-state multi-process consume-once stress, optionally with SIGSTOP hangs  and kill -9.
#   stress.sh <name> <secs> <procs> <unused> <chaos: none|hang|kill|both>
# Runs ON the box.  Needs /work/replay-linz/durable-state.mjs (see build.sh) and /work/replay-linz/pcalinz.
set -uo pipefail
R=/work/replay-linz; name=$1; secs=$2; procs=$3; stale=$4; chaos=$5
OUT=$R/out/$name; rm -rf "$OUT"; mkdir -p "$OUT/h" "$OUT/state"
epoch=$(( $(date +%s%3N) )); pids=(); gen=0
HERE="$(cd "$(dirname "$0")" && pwd)"
launch() { local i=$1; gen=$((gen+1)); RUN=$name DURABLE_MJS=$R/durable-state.mjs node "$HERE/worker.mjs" "$OUT/state" "$OUT/h" "p$i.g$gen" "$secs" "$stale" "$epoch" > "$OUT/w$i.g$gen.out" 2>&1 & pids[$i]=$!; }
for i in $(seq 1 "$procs"); do launch "$i"; done
end=$(( $(date +%s) + secs ))
while [ "$(date +%s)" -lt "$end" ]; do
  sleep 1.$((RANDOM%9)); i=$(( (RANDOM % procs) + 1 ))
  case "$chaos" in
    hang|both) if [ $((RANDOM%2)) -eq 0 ]; then kill -STOP "${pids[$i]}" 2>/dev/null && { sleep "$(awk -v s="$stale" 'BEGIN{print (s/1000)*1.6+0.2}')"; kill -CONT "${pids[$i]}" 2>/dev/null; echo "hang p$i" >> "$OUT/chaos.log"; }; fi;;
  esac
  case "$chaos" in
    kill|both) if [ $((RANDOM%3)) -eq 0 ]; then kill -9 "${pids[$i]}" 2>/dev/null && echo "kill p$i" >> "$OUT/chaos.log"; sleep 0.1; launch "$i"; fi;;
  esac
done
for p in "${pids[@]}"; do kill -CONT "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
cat "$OUT"/w*.out | grep -c . >/dev/null
$R/pcalinz check -dir "$OUT/h" -out "$OUT/violations" -timeout 30s 2>&1 | tee "$OUT/check.txt"
echo "durable name=$name procs=$procs stale=$stale chaos=$chaos hangs=$(grep -c hang "$OUT/chaos.log" 2>/dev/null) kills=$(grep -c kill "$OUT/chaos.log" 2>/dev/null)" | tee -a "$OUT/check.txt"

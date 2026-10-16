#!/usr/bin/env bash
# formal-kani-long.sh : one "long"-tier Kani harness (formal-kani-tiers.txt), run from the harness crate directory.
# NON-GATING: always exits 0 once the outcome is recorded. The outcome is written to $OUT/outcome.tsv as
#   <crate> <harness> <PROVED|FAILED|NOT-CONCLUDED> <wall s> <detail>
#   PROVED         VERIFICATION SUCCESSFUL (unwinding assertions on, so every loop bound is itself proved sufficient)
#   FAILED         VERIFICATION FAILED with at least one failed check that is NOT an unwinding assertion (a counterexample)
#   NOT-CONCLUDED  no verdict: time budget reached, out of memory (ulimit), only unwinding assertions failed (bound too
#                  small, not a counterexample), or any other error. Never reported as a pass.
# Env: H harness, F features, C crate, OUT outcome dir, T0 job start (epoch s), JOB_MIN job timeout-minutes,
#      KANI_MEM_KB virtual-memory cap (ulimit -v, below the runner's 16 GB).
# Like tools/pca-implverif/run-iv-close.sh: a 240 s probe collects the loop ids symbolic execution unrolls; the std B-tree
# node-restructuring loops among them get --unwindset ID:2. Unwinding assertions stay ON, so this does not weaken the
# property: a reachable deeper iteration makes the run fail (reported NOT-CONCLUDED, not PROVED).
set -uo pipefail
: "${H:?}" "${C:?}" "${OUT:?}" "${T0:?}" "${JOB_MIN:?}" "${KANI_MEM_KB:?}"; F="${F:-}"
mkdir -p "$OUT"; log="$OUT/$(echo "$H" | tr ':/' '__').log"; probe="$OUT/probe.log"
rec() { printf '%s\t%s\t%s\t%s\t%s\n' "$C" "$H" "$1" "$2" "$3" > "$OUT/outcome.tsv"; echo "outcome: $1 ($3) wall=${2}s"; }
rec NOT-CONCLUDED 0 "build did not complete"
bash ./build.sh || { rec NOT-CONCLUDED 0 "harness crate build.sh failed"; exit 0; }
ulimit -v "$KANI_MEM_KB"   # out of memory fails the process cleanly instead of the runner being killed
K=(cargo kani -Z stubbing -Z function-contracts -Z loop-contracts -Z unstable-options ${F:+--features "$F"} --harness "$H" --exact)

s=$(date +%s)
timeout -k 30 240 "${K[@]}" > "$probe" 2>&1
U=$(grep -a -o -E 'Unwinding loop [^ ]+ iteration' "$probe" | sed -E 's/^Unwinding loop //; s/ iteration$//' \
  | grep -E 'correct_childrens_parent_links|correct_parent_link|split|merge|steal|bulk_push|fix_' | sort -u | sed 's/$/:2/' | paste -sd, -)
echo "B-tree unwindset: ${U:-<none>}"
if grep -aq 'VERIFICATION:- ' "$probe"; then cp "$probe" "$log"; rc=0; grep -aq 'VERIFICATION:- SUCCESSFUL' "$probe" || rc=1
else
  # time left for kani: the job budget minus what has elapsed, minus 10 min for recording + artifact upload
  budget=$(( JOB_MIN * 60 - ($(date +%s) - T0) - 600 ))
  [ "$budget" -gt 60 ] || { rec NOT-CONCLUDED $(( $(date +%s) - s )) "no time left after setup"; exit 0; }
  echo "kani budget: ${budget}s, memory cap: ${KANI_MEM_KB} KB"
  rc=0; timeout -k 60 "$budget" "${K[@]}" ${U:+--cbmc-args --unwindset "$U"} > "$log" 2>&1 || rc=$?
fi
w=$(( $(date +%s) - s ))
grep -a -E 'VERIFICATION:|Failed Checks|Complete - |Runtime (Symex|Solver)|error|[Oo]ut of memory|bad_alloc' "$log" | tail -12 || true
fails=$(grep -a 'Failed Checks:' "$log" | sed 's/^.*Failed Checks: *//' || true)
if grep -aq 'VERIFICATION:- SUCCESSFUL' "$log" && [ "$rc" = 0 ]; then rec PROVED "$w" "VERIFICATION SUCCESSFUL"
elif grep -aq 'VERIFICATION:- FAILED' "$log" && [ -n "$fails" ] && echo "$fails" | grep -qv 'unwinding assertion'; then
  rec FAILED "$w" "counterexample: $(echo "$fails" | grep -v 'unwinding assertion' | head -3 | paste -sd ';' - | cut -c1-200)"
  echo "::error::$H: VERIFICATION FAILED (long tier, non-gating)"
elif grep -aq 'VERIFICATION:- FAILED' "$log"; then rec NOT-CONCLUDED "$w" "only unwinding assertions failed (bound too small; no counterexample to the property)"
elif [ "$rc" = 124 ] || { [ "$rc" = 137 ] && [ "$w" -ge "${budget:-999999}" ]; }; then rec NOT-CONCLUDED "$w" "timeout after ${w}s (job cap ${JOB_MIN} min)"
elif [ "$rc" = 137 ] || grep -aqiE 'out of memory|bad_alloc|cannot allocate memory|memory allocation of .* failed' "$log"; then
  rec NOT-CONCLUDED "$w" "out of memory (ulimit -v ${KANI_MEM_KB} KB)"
else rec NOT-CONCLUDED "$w" "no verdict, kani exit $rc: $(grep -a -m1 -E 'error' "$log" | cut -c1-160)"; fi
[ "$(cut -f3 "$OUT/outcome.tsv")" != NOT-CONCLUDED ] || echo "::warning::$H: $(cut -f3,5 "$OUT/outcome.tsv" | tr '\t' ' ') (long tier, non-gating)"
{ echo "| harness | outcome | wall | detail |"; echo "|---|---|---|---|"
  echo "| \`$H\` | $(cut -f3 "$OUT/outcome.tsv") | $(( $(cut -f4 "$OUT/outcome.tsv") / 60 )) min | $(cut -f5 "$OUT/outcome.tsv") |"; } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
gzip -f "$log" "$probe" 2>/dev/null || true
exit 0

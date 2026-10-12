#!/usr/bin/env bash
# Runs ON the box: a list of scenarios from a file, sequentially; one summary line each + a verdict against the expectation.
#   campaign.sh <list-file> <result-file>
# list line:  name | store | secs | procs | conns | chaos | ENV (e.g. SYNC=off REDIS_MODE=none or -) | expect(pass|fail)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; list="$1"; res="$2"; : >> "$res"
while IFS='|' read -r name store secs procs conns chaos envs expect; do
  name="$(echo "$name" | xargs)"; case "$name" in ''|\#*) continue;; esac
  store="$(echo "$store" | xargs)"; expect="$(echo "$expect" | xargs)"; envs="$(echo "$envs" | xargs)"; [ "$envs" = "-" ] && envs=""
  out="$(env $envs "$HERE/scenario.sh" "$name" "$store" "$(echo "$secs"|xargs)" "$(echo "$procs"|xargs)" "$(echo "$conns"|xargs)" "$(echo "$chaos"|xargs)" 2>&1)"
  line="$(echo "$out" | grep '^CHECK' | tail -1)"; rc="$(echo "$out" | grep -o 'check-rc=[0-9]*' | tail -1 | cut -d= -f2)"
  got=pass; [ "${rc:-9}" = 1 ] && got=fail; [ "${rc:-9}" = 0 ] || [ "${rc:-9}" = 1 ] || got="inconclusive(rc=$rc)"
  v=OK; [ "$got" = "$expect" ] || v=MISMATCH
  kills="$(echo "$out" | grep -o 'kills=[0-9]*' | tail -1)"
  printf '%-30s %-22s chaos=%-10s %s expect=%-4s got=%-4s %-8s %s\n' "$name" "$store" "$(echo "$chaos"|xargs)" "$envs" "$expect" "$got" "$v" "$kills | $line" | tee -a "$res"
done < "$list"

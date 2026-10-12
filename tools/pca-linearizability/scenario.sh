#!/usr/bin/env bash
# Runs ON the cloud box.  One scenario = N client processes (each CONNS connections) hammering one store, with optional chaos,
# then the porcupine check.  usage: scenario.sh <name> <store> <secs> [procs=3] [conns=60] [chaos=none|clientkill|connkill|restart|all] [extra run flags...]
#   env: SYNC=on|off (pg synchronous_commit; requires pg-init with it), REDIS_MODE=always|everysec|none, OUT=/work/replay-linz/out
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="${ROOT:-/work/replay-linz}"; BIN="${BIN:-$ROOT/pcalinz}"; S="$HERE/box-setup.sh"
name="$1"; store="$2"; secs="$3"; procs="${4:-3}"; conns="${5:-60}"; chaos="${6:-none}"; shift 6 2>/dev/null || shift $#
OUT="${OUT:-$ROOT/out}/$name"; rm -rf "$OUT"; mkdir -p "$OUT/h"
PG="/usr/lib/postgresql/16/bin"; PSQL=("$PG/psql" -h 127.0.0.1 -p 5455 -U pca linz -qAt)
case "$store" in
  pg-*) [ -n "${SYNC:-}" ] && "$S" pg-set-sync "$SYNC"; "$PG/pg_isready" -h 127.0.0.1 -p 5455 -q || "$S" pg-start >/dev/null; "$S" pg-reset; sleep 0.3;;
  redis-*) "$S" redis-stop; sleep 0.4; "$S" redis-reset; "$S" redis-start "${REDIS_MODE:-always}" >/dev/null;;
esac
epoch=$(date +%s%N); run="$name"
EXTRA=("$@"); pids=(); gen=0
endts=$(( $(date +%s) + ${secs%.*} ))
launch() { local i=$1; gen=$((gen+1)); "$BIN" run -store "$store" -dir "$OUT/h" -proc "p$i.g$gen" -conns "$conns" -secs "$(( endts - $(date +%s) ))" -run "$run" -epoch "$epoch" -slice "${SLICE:-20ms}" -spread "${SPREAD:-12}" ${REVISIT:+-revisit "$REVISIT"} "${EXTRA[@]}" > "$OUT/run-p$i.g$gen.out" 2>&1 & pids[$i]=$!; }
for i in $(seq 1 "$procs"); do launch "$i"; done
end=$endts
chaoslog="$OUT/chaos.log"; : > "$chaoslog"
chaosloop() {
  local n=0
  while [ "$(date +%s)" -lt "$end" ]; do
    sleep "$(awk 'BEGIN{srand(); print 1.5+rand()*2.5}')"; n=$((n+1)); now=$(date +%T.%N | cut -c1-12)
    case "$chaos" in
      clientkill|all) i=$(( (RANDOM % procs) + 1 )); kill -9 "${pids[$i]}" 2>/dev/null && echo "$now kill -9 client p$i" >> "$chaoslog"; sleep 0.2; launch "$i";;
    esac
    case "$chaos" in
      connkill|all) [[ "$store" == pg-* ]] && "${PSQL[@]}" -c "select count(pg_terminate_backend(pid)) from pg_stat_activity where datname='linz' and pid<>pg_backend_pid() and random()<0.3" >> "$chaoslog" 2>&1
                    [[ "$store" == redis-* ]] && redis-cli -p 6390 client kill type normal >> "$chaoslog" 2>&1;;
    esac
    if [ $((n % 4)) -eq 0 ]; then case "$chaos" in
      restart|all) if [[ "$store" == pg-* ]]; then "$S" pg-kill9; echo "$now kill -9 postgres" >> "$chaoslog"; sleep 0.3; "$S" pg-start >> "$chaoslog" 2>&1
                   else "$S" redis-kill9; echo "$now kill -9 redis" >> "$chaoslog"; sleep 0.2; "$S" redis-start "${REDIS_MODE:-always}" >> "$chaoslog" 2>&1; fi;;
    esac; fi
  done
}
[ "$chaos" != none ] && chaosloop &
cl=$!
wait "$cl" 2>/dev/null
# chaos relaunches clients in a subshell, so wait for ANY pcalinz writer of this scenario, not just our own children
while pgrep -f "pcalinz run .*-dir $OUT/h" >/dev/null; do sleep 0.5; done
sleep 1
GOMEMLIMIT=5GiB "$BIN" check -par "${CHECK_PAR:-4}" -dir "$OUT/h" -out "$OUT/violations" -timeout "${CHECK_TIMEOUT:-30s}" 2>&1 | tee "$OUT/check.txt"
rc=${PIPESTATUS[0]}
echo "scenario=$name store=$store chaos=$chaos procs=$procs conns=$conns secs=$secs check-rc=$rc kills=$(grep -c 'kill -9' "$chaoslog")" | tee -a "$OUT/check.txt"
du -sh "$OUT/h" | tee -a "$OUT/check.txt"
[ -n "${SYNC:-}" ] && [[ "$store" == pg-* ]] && "$S" pg-set-sync on
exit $rc


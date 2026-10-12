#!/bin/bash
# runq.sh <jobfile>: run each line (run3.sh args) when fewer than ${MAXP:-2} tamarin-prover processes are alive
cd "$(dirname "$0")"
while read -r line; do
  [ -z "$line" ] && continue
  while [ "$(pgrep -c -x tamarin-prover)" -ge "${MAXP:-2}" ]; do sleep 20; done
  setsid nohup ./run3.sh $line >/dev/null 2>&1 &
  sleep 30
done < "$1"

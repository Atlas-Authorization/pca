#!/usr/bin/env bash
# Runs every rust-pca conformance test under Miri, vectors in 29 shards, P-way parallel. Summary lines in /work/iv-logs/miri-rp/summary.txt
set -uo pipefail; P="${1:-3}"; D=/work/iv-logs/miri-rp; mkdir -p $D; : > $D/summary.txt
cd /work/iv
run() { t="$1"; s="$2"; n="$t-$s"; st=$(date +%s); bash tools/pca-implverif/miri-shard.sh "$t" "$s" > $D/$n.log 2>&1; rc=$?; echo "$n rc=$rc $(( $(date +%s)-st ))s $(grep -a -E 'test result|Undefined Behavior|error:' $D/$n.log | head -2 | tr '\n' ' ')" >> $D/summary.txt; }
export -f run; export D
# warm build once
run keys_consistent 0
{ for t in primitives threshold_shares json_parse_table b64u_table; do echo "$t 0"; done; for s in $(seq 0 28); do echo "vectors $s"; done; } | xargs -P "$P" -L1 bash -c 'run $0 $1'
echo ALLDONE >> $D/summary.txt

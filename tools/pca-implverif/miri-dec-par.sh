#!/usr/bin/env bash
# miri-dec-par.sh : the four Miri decoder drivers IN PARALLEL (one core each, cores given by $CORES, default "0 1 2 3").
cd /work/iv; L=/work/iv-logs; mkdir -p $L; : > $L/miri-dec-summary.txt
set -- ${CORES:-0 1 2 3}
run() { core=$1; shift; n=$(basename $2 .rs); s=$(date +%s); taskset -c $core bash tools/pca-implverif/miri-run.sh "$@" > $L/miri-dec-$n.log 2>&1; rc=$?
  echo "$n rc=$rc $(( $(date +%s)-s ))s $(grep -a -E 'test result|Undefined Behavior' $L/miri-dec-$n.log | tr '\n' ' ')" >> $L/miri-dec-summary.txt; }
run $1 folding-pca folding_dec.rs - MIRITARGET=aarch64-unknown-linux-gnu &
run $2 zkvm-pca/core zkvm_dec.rs - &
run $3 stark-pca stark_dec.rs - &
run $4 stark-pca-plonky3 plonky3_dec.rs - &
wait; echo ALLDONE >> $L/miri-dec-summary.txt

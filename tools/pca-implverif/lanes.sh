#!/usr/bin/env bash
# lanes.sh : starts the long-running proof lanes on the exclusive box (each lane sequential; memory capped per process).
# Lane A kani-queue | B1 SampleChallenge contract (3 targets) | B2 crypto_sign_open T192 patched+unpatched | B3 RebuildGGM T192 (after B1)
# C Miri rust-pca vector shards 6..28 (P=2) | D Miri decoders (folding, zkvm core, stark-pca, plonky3)
cd /work/iv; L=/work/iv-logs; P=/work/iv-less; R=$P/Reference_Implementation; F=$P/tests/formal
laneA() { bash tools/pca-implverif/kani-queue.sh; }
laneB1() { for T in 45 68 192; do ( ulimit -v 16000000; bash $F/run-cbmc-samplechallenge.sh $R $T > $L/cbmc-sc$T.res 2>&1 ); done; echo done > $L/laneB1.done; }
laneB2() { ( ulimit -v 12000000; bash $F/run-cbmc-open.sh $R 192 > $L/cbmc-open192-patched.res 2>&1 ); ( ulimit -v 12000000; PATCHED_REF=$R bash $F/run-cbmc-open.sh /work/iv-less-unpatched/Reference_Implementation 192 > $L/cbmc-open192-unpatched.res 2>&1 ); echo done > $L/laneB2.done; }
laneB3() { while [ ! -f $L/laneB1.done ]; do sleep 30; done; ( ulimit -v 20000000; bash $F/run-cbmc-rebuild.sh $R 192 > $L/cbmc-rebuild192.res 2>&1 ); echo done > $L/laneB3.done; }
laneC() { D=$L/miri-rp; for s in $(seq 6 28); do echo "vectors $s"; done | xargs -P 2 -L1 bash -c 'st=$(date +%s); bash tools/pca-implverif/miri-shard.sh $0 $1 > '$D'/$0-$1.log 2>&1; rc=$?; echo "$0-$1 rc=$rc $(( $(date +%s)-st ))s $(grep -a -E "test result|Undefined Behavior|error:" '$D'/$0-$1.log | head -2 | tr "\n" " ")" >> '$D'/summary.txt'; echo VECTORS-DONE >> $D/summary.txt; }
laneD() { for d in "folding-pca folding_dec.rs MIRITARGET=aarch64-unknown-linux-gnu" "zkvm-pca/core zkvm_dec.rs" "stark-pca stark_dec.rs" "stark-pca-plonky3 plonky3_dec.rs"; do set -- $d; n=$(basename $2 .rs); bash tools/pca-implverif/miri-run.sh $1 $2 - ${3:-} > $L/miri-dec-$n.log 2>&1; echo "$n rc=$?" >> $L/miri-dec-summary.txt; done; }
laneA > $L/laneA.log 2>&1 &
laneB1 &
laneB2 &
laneB3 &
laneC &
laneD &
wait

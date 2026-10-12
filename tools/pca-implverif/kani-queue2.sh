#!/usr/bin/env bash
# kani-queue2.sh : remaining Kani harnesses, sequential, 22 GB virtual-memory cap, cores 0-3. log /work/iv-logs/kani-queue2.txt
export PATH=$HOME/.cargo/bin:$HOME/.kani/bin:$PATH; cd /work/iv; Q=/work/iv-logs/kani-queue2.txt; : >> $Q; ulimit -v 22000000
run() { d="$1"; shift; for h in "$@"; do taskset -c 0-3 bash tools/pca-implverif/$d/run.sh $h >> $Q 2>&1; done; }
run kani-plonky3 p3_hex256_limbs_values_all_64hex p3_hex256_limbs_gate_len_le_70
run kani-rust-pca safe_int_i64_full_range decision_aggregation decode_b64u_no_panic_bounded
run kani-zkvm-core zk_decode_b64u_strict_bounded6
echo QUEUE-DONE >> $Q

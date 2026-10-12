#!/usr/bin/env bash
# kani-queue.sh : runs the Kani harnesses of all crates ONE AT A TIME (memory-heavy), each under a 14 GB virtual-memory cap.
# log: /work/iv-logs/kani-queue.txt (one summary line per harness)
export PATH=$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.kani/bin:$PATH; cd /work/iv; Q=/work/iv-logs/kani-queue.txt; : >> $Q
ulimit -v 14000000
run() { d="$1"; shift; for h in "$@"; do bash tools/pca-implverif/$d/run.sh $h >> $Q 2>&1; done; }
run kani-plonky3 p3_validate_bounds_exact_all_u64 p3_g_from_u128_reduction_total p3_hex256_limbs_len_le_70
run kani-folding fold_within_budget_n3_any_u64
run kani-rust-pca safe_int_i64_full_range decode_b64u_no_panic_bounded decision_aggregation
echo QUEUE-DONE >> $Q

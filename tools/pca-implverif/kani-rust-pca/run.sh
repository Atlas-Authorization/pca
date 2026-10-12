#!/usr/bin/env bash
# run.sh [harness...]  -- runs each Kani harness separately, prints one summary line each (log: out/<h>.log)
cd "$(dirname "$0")"; ./build.sh >/dev/null; OUT=${OUT:-/work/iv-logs/kani-out}; mkdir -p $OUT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-iv/kani-rustpca}
H=("$@"); [ ${#H[@]} -eq 0 ] && H=(split_full_range path_shape_full_range safe_int_i64_full_range safe_int_u64_full_range decode_b64u_len_arith_any_n decode_b64u_len_arith_guarded decode_b64u_real_fn_any_n decode_b64u_no_panic_bounded decision_aggregation)
for h in "${H[@]}"; do
  s=$(date +%s); cargo kani -Z stubbing -Z function-contracts -Z loop-contracts ${KANIFLAGS:-} --harness "$h" --output-format terse > $OUT/$h.log 2>&1; rc=$?
  echo "$h rc=$rc $(( $(date +%s)-s ))s :: $(grep -a -E 'VERIFICATION:|Complete - ' $OUT/$h.log | tr '\n' ' ')"
done

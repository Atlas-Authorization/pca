#!/usr/bin/env bash
cd "$(dirname "$0")"; ./build.sh >/dev/null; OUT=${OUT:-/work/iv-logs/kani-out}; mkdir -p $OUT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-iv/kani-p3}
H=("$@"); [ ${#H[@]} -eq 0 ] && H=(p3_validate_bounds_exact_all_u64 p3_g_from_u128_reduction_total p3_lemma_from_str_radix_8hex p3_hex256_limbs_gate_len_le_70 p3_hex256_limbs_values_all_64hex)
for h in "${H[@]}"; do
  s=$(date +%s); cargo kani -Z stubbing -Z function-contracts -Z loop-contracts ${KANIFLAGS:-} --harness "$h" --output-format terse > $OUT/$h.log 2>&1; rc=$?
  echo "$h rc=$rc $(( $(date +%s)-s ))s :: $(grep -a -E 'VERIFICATION:|Complete - |^error' $OUT/$h.log | head -3 | tr '\n' ' ')"
done

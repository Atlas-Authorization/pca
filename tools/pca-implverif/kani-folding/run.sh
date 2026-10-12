#!/usr/bin/env bash
cd "$(dirname "$0")"; ./build.sh >/dev/null; OUT=${OUT:-/work/iv-logs/kani-out}; mkdir -p $OUT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-iv/kani-fold}
H=("$@"); [ ${#H[@]} -eq 0 ] && H=(fold_within_budget_n3_any_u64)
for h in "${H[@]}"; do
  s=$(date +%s); cargo kani -Z stubbing -Z function-contracts -Z loop-contracts ${KANIFLAGS:-} --harness "$h" --output-format terse > $OUT/$h.log 2>&1; rc=$?
  echo "$h rc=$rc $(( $(date +%s)-s ))s :: $(grep -a -E 'VERIFICATION:|Complete - |^error' $OUT/$h.log | head -3 | tr '\n' ' ')"
done

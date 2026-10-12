#!/usr/bin/env bash
cd "$(dirname "$0")"; ./build.sh >/dev/null; OUT=${OUT:-/work/iv-logs/kani-out}; mkdir -p $OUT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-iv/kani-zk}
H=("$@"); [ ${#H[@]} -eq 0 ] && H=(zk_risk_raw_exact_all_u64 zk_tier_ladder_all zk_budget_and_auto_admit_in_range zk_scale_any_f64 zk_decode_b64u_strict_bounded6)
for h in "${H[@]}"; do
  s=$(date +%s); cargo kani -Z stubbing -Z function-contracts -Z loop-contracts ${KANIFLAGS:-} --harness "$h" --output-format terse > $OUT/$h.log 2>&1; rc=$?
  echo "$h rc=$rc $(( $(date +%s)-s ))s :: $(grep -a -E 'VERIFICATION:|Complete - |^error' $OUT/$h.log | head -3 | tr '\n' ' ')"
done

#!/usr/bin/env bash
cd "$(dirname "$0")"; ./build.sh >/dev/null; OUT=${OUT:-/work/iv-logs/kani-out}; mkdir -p $OUT
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/work/target-iv/kani-stark}
H=("$@"); [ ${#H[@]} -eq 0 ] && H=(bounded_reader_read_slice_any_len bounded_reader_read_u8_and_array bounded_reader_read_many_alloc_guard check_batch_opening_no_panic)
for h in "${H[@]}"; do
  s=$(date +%s); cargo kani --harness "$h" --output-format terse > $OUT/$h.log 2>&1; rc=$?
  echo "$h rc=$rc $(( $(date +%s)-s ))s :: $(grep -a -E 'VERIFICATION:|Complete - |error' $OUT/$h.log | head -3 | tr '\n' ' ')"
done

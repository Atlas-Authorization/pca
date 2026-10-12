#!/usr/bin/env bash
# Unbounded-time proof of ExactlyOnce (inductive invariant) with Apalache.  env: APALACHE=/path/to/apalache-mc
set -uo pipefail
cd "$(dirname "$0")"
A="${APALACHE:-apalache-mc}"; OUT="${OUT:-results}"; mkdir -p "$OUT"; : > "$OUT/APALACHE.txt"; bad=0
chk() { # name expect(pass|fail) args...
  local name="$1" exp="$2"; shift 2
  "$A" check "$@" ApaContract.tla > "$OUT/apa_$name.txt" 2>&1
  local got=fail; grep -q "EXITCODE: OK" "$OUT/apa_$name.txt" && got=pass
  local v=OK; [ "$got" = "$exp" ] || { v=MISMATCH; bad=$((bad+1)); }
  printf '%-34s expect=%-4s got=%-4s %s\n' "$name" "$exp" "$got" "$v" | tee -a "$OUT/APALACHE.txt"
}
chk base_good          pass --init=Init   --inv=IndInv --length=0 --cinit=CInitGood
chk step_good          pass --init=IndInit --inv=IndInv --length=1 --cinit=CInitGood
chk implies_safe_good  pass --init=IndInit --inv=ExactlyOnce --length=0 --cinit=CInitGood
chk base_general       pass --init=Init   --inv=IndInv --length=0 --cinit=CInitGeneral
chk step_general       pass --init=IndInit --inv=IndInv --length=1 --cinit=CInitGeneral
chk step_bad_skew      fail --init=IndInit --inv=IndInv --length=1 --cinit=CInitBadSkew
chk bmc_bad_skew       fail --init=Init   --inv=ExactlyOnce --length=8 --cinit=CInitBadSkew
chk bmc_bad_prune      fail --init=Init   --inv=ExactlyOnce --length=8 --cinit=CInitBadPrune
chk bmc_good_depth12   pass --init=Init   --inv=ExactlyOnce --length=12 --cinit=CInitGood
echo "mismatches: $bad" | tee -a "$OUT/APALACHE.txt"; exit $bad

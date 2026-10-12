#!/bin/bash
# usage: run_frost_v3.sh <timeout-s> <variant|none> [lemmas...]   -> results/v3/frost_sign[__VARIANT].txt
T=$1; V=$2; shift 2; L="${*:-executable_threshold_signature executable_two_sessions nonce_secret nonce_one_shot shares_bound_to_session share_secrecy sig_needs_t_signers}"
F=pca_frost_sign_v3.spthy; D=""; N=frost_sign; [ "$V" != none ] && { D="-D$V"; N=frost_sign__$V; }
OUT=results/v3/$N.txt; : > $OUT
for l in $L; do
  s=$(date +%s); r=$(perl -e 'alarm shift; exec @ARGV' $T tamarin-prover --prove=$l $D $F +RTS -N${NC:-4} 2>&1 | grep -E "^  $l \("); e=$(date +%s)
  if [ -n "$r" ]; then echo "$r" >> $OUT; elif [ $((e-s)) -ge $((T-2)) ]; then echo "TIMEOUT after ${T}s (NOT proved): $l" >> $OUT; else echo "ERROR/no-result in $((e-s))s (NOT proved): $l" >> $OUT; fi
  echo "# wall=$((e-s))s heuristic=default tamarin-prover 1.12.0 cmd=tamarin-prover --prove=$l $D $F +RTS -N${NC:-4}" >> $OUT
done
cat $OUT

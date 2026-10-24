#!/usr/bin/env bash
# run-iv-close.sh : submits the FULL decomposed Kani set for kani-rust-pca once (one harness per queue job, spot/gcp,
# --mem 12, no time limit). Run from the repo root on the Mac; all compute is on the farm. Owner: iv-close.
# Decision harnesses (B-tree loops): a 240 s probe collects the loop ids symex unrolls, then
# the B-tree node-restructuring loops among them get --unwindset ID:2 (unwinding assertions stay ON, so the solver must
# still show any deeper iteration unreachable).
set -u
export PCAQ_OWNER=${PCAQ_OWNER:-iv-close}
Q=cloud-box tooling/q
INSTALL='flock $HOME/.kani-install.lock bash -c "cargo kani --version >/dev/null 2>&1 || { cargo install --locked kani-verifier >/tmp/kinst.log 2>&1 && cargo kani setup >>/tmp/kinst.log 2>&1; }"'
K='cargo kani -Z stubbing -Z function-contracts -Z loop-contracts -Z unstable-options'
sub() { # sub FEATURES HARNESS-PATH UNWINDSET(0|1)
  local F="$1" H="$2" U="$3" T; T=iv-$(echo $H | awk -F:: '{print $NF}' | cut -c1-30)
  local PRE=""; local X=""
  if [ "$U" = 1 ]; then
    PRE="timeout 240 $K $F --harness $H --exact > /tmp/loops.txt 2>&1; U=\$(grep -a -o -E 'Unwinding loop [^ ]+ iteration' /tmp/loops.txt | sed -E 's/^Unwinding loop //; s/ iteration\$//' | grep -E 'correct_childrens_parent_links|correct_parent_link|split|merge|steal|bulk_push|fix_' | sort -u | sed 's/\$/:2/' | paste -sd, -);"
    X='${U:+--cbmc-args --unwindset $U}'
  fi
  $Q submit --cores 1 --mem 12 --wall 172800 --long --prep none --tag "$T" -- "export PATH=\$HOME/.cargo/bin:\$HOME/.kani/bin:\$PATH; $INSTALL; cd tools/pca-implverif/kani-rust-pca && ./build.sh >/dev/null; export CARGO_TARGET_DIR=/tmp/kt-\$\$; $PRE $K $F --harness $H --exact $X 2>&1 | grep -a -E 'Runtime Symex|Runtime Solver|VERIFICATION:|Failed Checks|FAILURE|error|Complete -' | grep -v ': SUCCESS'" </dev/null | tail -1
}
C=pca::proofs::compositional; B=pca::proofs::b64_compositional; W=$B::wrap
for h in d_wire_terminal d_version d_audience d_validity d_counter d_grant_ref_bound d_chain_cap d_chain_gate_order d_plan_inclusion d_leaf_signature d_allow_iff_all_pass; do sub "" $C::$h 1; done
for h in json_value_get_dispatch json_field1_ver json_field1_aud json_field1_iat json_field1_exp json_field1_counter json_field1_grant_ref json_field1_cap_chain; do sub "" $C::$h 0; done
for h in b64u_decode_metadata_mirror b_alphabet_scan_le64 b_crate_decode_over_contract_any_len; do sub "--features b64wrap" $W::$h 0; done
for k in $(seq 0 15); do lo=$((4*k)); hi=$((4*k+3)); [ $k = 15 ] && hi=64; for p in b_len b_rt; do sub "--features b64wrap" $W::$(printf "%s_n%02d_%02d" $p $lo $hi) 0; done; done
for h in b64u_spec_vs_crate_le4 b64u_spec_vs_crate_le5 b64u_spec_vs_crate_le6; do sub "" $B::$h 0; done

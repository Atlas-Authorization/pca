#!/bin/bash
# run_cv.sh -- CryptoVerif 2.13 proofs + negative controls. needs `cryptoverif` on PATH (cloud box: source ~/pcaenv.sh).
# results/<name>.txt = the tool's RESULT / 'Proved' / 'Could not prove' lines (probability bounds verbatim); results/<name>.log = full output.
cd "$(dirname "$0")" || exit 1
mkdir -p results
LIB=${CV_LIB:-$(opam var doc 2>/dev/null)/cryptoverif/default.cvl}; [ -f "$LIB" ] || LIB=$HOME/.opam/pv/doc/cryptoverif/default.cvl
cryptoverif -help 2>&1 | head -1 > results/versions.txt
run() { # name file
  timeout 900 cryptoverif -lib "$LIB" "$2" > results/$1.log 2>&1
  grep -E '^RESULT (Proved|Could not prove)|^RESULT.*(cannot|could not)|^All queries proved|^Error|^RESULT time_' results/$1.log | grep -v '^RESULT time_' | cut -c1-600 > results/$1.txt
  grep -E "^(Error|Warning: unproved)|Could not prove" results/$1.log >> results/$1.txt
  [ -s results/$1.txt ] || echo "NO RESULT LINES (see log)" > results/$1.txt
}
run pca_leaf_auth pca_leaf_auth.cv
run pca_chain2_auth pca_chain2_auth.cv
run pca_replay pca_replay.cv
run pca_replay_chosen_nonce pca_replay_chosen_nonce.cv
# negative controls: drop one check, the matching query must NOT be proved
mkdir -p results/.t
grep -v 'if gref = hash(hk, mkcw(cb, csg)) then' pca_leaf_auth.cv > results/.t/NEG_no_gref_check.cv
grep -v 'if check(act, hol, asg) then' pca_leaf_auth.cv > results/.t/NEG_no_leaf_sig.cv
grep -v 'if check(cb, pkP, csg) then' pca_leaf_auth.cv > results/.t/NEG_no_root_sig.cv
grep -v '(\*-NO_STORE\*)' pca_replay.cv > results/.t/NEG_replay_no_store.cv
for f in NEG_replay_no_store NEG_no_gref_check NEG_no_leaf_sig NEG_no_root_sig; do run $f results/.t/$f.cv; done
rm -rf results/.t
echo done

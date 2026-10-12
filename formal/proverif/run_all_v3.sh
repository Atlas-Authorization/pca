#!/bin/bash
# run_all_v3.sh [JOBS=4] [TIMEOUT=1800]  -- the revision-3 ProVerif models (FROST signing, DKG, allowlist/anchor).
# Same output format as run_all.sh; results in results/v3/<model>[__VARIANT].txt  (query | wall seconds | RESULT line).
# `proverif` must be on PATH (cloud box: source ~/pcaenv.sh).
cd "$(dirname "$0")" || exit 1
J=${1:-4}; T=${2:-1800}
rm -rf results/v3/.tmp; mkdir -p results/v3/logs results/v3/.tmp
proverif --help 2>&1 | head -1 > results/v3/versions.txt
JOBS=results/v3/.tmp/jobs; : > $JOBS
add() { for q in $3; do echo "$1 ${2:--} $q" >> $JOBS; done; }
FQ="sig_needs_t_signers agg_needs_two_shares nonce_one_shot_inj nonce_one_shot"
for v in - NO_EXTRACT NONCE_REUSE NO_BINDING; do add pca_frost_sign $v "$FQ"; done
for v in - NO_EXTRACT NONCE_REUSE; do add pca_frost_sign $v "share_secrecy_1 share_secrecy_2" ; done
add pca_frost_sign REV_CTHREE "share_secrecy_1 share_secrecy_2"
add pca_frost_sign NO_EXTRACT+REV_CTHREE "share_secrecy_1 share_secrecy_2"
add pca_frost_sign SANITY "sanity1 sanity2"
for v in - NO_POP; do add pca_frost_dkg $v dkg_key_not_adversarial; done
add pca_frost_dkg SANITY "sanity1"
AQ="no_manifest_rollback no_manifest_rollback_v0 revoked_never_attested_v1 revoked_never_attested_v2"
for v in - ANCHOR_REPLAY STATE_WIPE; do add pca_allowlist $v "$AQ"; done
add pca_allowlist SANITY "sanity1 sanity2"
SQ="scope_narrowing_all_hops resource_narrowing_all_hops root_scope_bounds_action root_resource_bounds_action honest_hop_scope_bounds_action honest_hop_resource_bounds_action"
for v in - NO_ANCESTOR_SCOPE NO_ANCESTOR_RES; do add pca_scope_resource $v "$SQ"; done
add pca_scope_resource SANITY "sanity1 sanity2 $SQ"
one() {
  m=$1; v=$2; q=$3; [ "$v" = "-" ] && v=""
  n="$m${v:+__$v}"; base="results/v3/logs/${n}__$q"
  ./gen.sh $m.pv "$v" $q > $base.pv
  s=$(date +%s); timeout $T proverif $base.pv > $base.log 2>&1; rc=$?; e=$(( $(date +%s) - s ))
  r=$(grep -E '^RESULT' $base.log | head -1)
  if [ -z "$r" ]; then if [ $rc = 124 ]; then r="TIMEOUT after ${T}s (no result)"; else r="NO RESULT (rc=$rc) $(grep -m1 -i error $base.log)"; fi; fi
  echo "$q | ${e}s | $r" > results/v3/.tmp/$n.$q
  awk '/^-- Query/{p=1} p' $base.log | cut -c1-1200 > $base.log.c; mv $base.log.c $base.log
  rm -f $base.pv
}
export -f one; export T
xargs -P "$J" -L 1 bash -c 'one $0 $1 $2' < $JOBS
rm -f results/v3/*.txt.new
while read -r m v q; do n="$m"; [ "$v" != "-" ] && n="${m}__$v"; cat results/v3/.tmp/$n.$q >> results/v3/$n.txt.new; done < $JOBS
for f in results/v3/*.txt.new; do mv "$f" "${f%.new}"; done
rm -rf results/v3/.tmp
echo done

#!/bin/bash
# run_all.sh [JOBS=4] [TIMEOUT_SECONDS=1800]
# Runs every model x variant x query with ProVerif (`proverif` must be on PATH; cloud box: `source ~/pcaenv.sh`).
# Writes results/<model>[__VARIANT].txt  (one line per query:  query | seconds | ProVerif RESULT line),
# raw ProVerif output incl. attack traces in results/logs/, and the tool version in results/versions.txt.
cd "$(dirname "$0")" || exit 1
J=${1:-4}; T=${2:-1800}
rm -rf results/.tmp; mkdir -p results/logs results/.tmp
proverif --help 2>&1 | head -1 > results/versions.txt
AQ="authorization leaf_signature_authenticity attenuation_root attenuation_hop audience_binding replay_freedom_nonce replay_freedom_counter replay_inj"
TQ="stepup3_requires_principal stepup3_requires_guardian stepup2_compromised_agent_insufficient stepup2_one_compromised_key_insufficient"
JOBS=results/.tmp/jobs; : > $JOBS
add() { for q in $3; do echo "$1 ${2:--} $q" >> $JOBS; done; }
for v in - NO_GREF_CHECK NO_ANCESTOR_CAV NO_AUD_CHECK NO_LEAF_SIG NO_REPLAY_STORE; do add pca_actn $v "$AQ"; done
for v in TABLE_CHECK_INSERT TABLE_INSERT_FIRST; do add pca_actn $v "replay_inj"; done
add pca_actn NO_TRUST_ANCHOR "authorization"
add pca_actn SANITY "sanity1 sanity2 sanity3 sanity4 sanity5"
add pca_actn_expiry - no_accept_after_expiry
add pca_actn_expiry NO_EXPIRY_CHECK no_accept_after_expiry
add pca_actn_expiry SANITY "sanity1 sanity2 sanity3"
for v in - UNBOUND_SHARE NO_DISTINCT NO_SET_DISTINCT; do add pca_threshold $v "$TQ"; done
add pca_threshold SANITY "sanity1 sanity2 sanity3"
for v in - NOBIND_HOLDER NOBIND_GRANT NOBIND_EPOCH NOBIND_NONCE; do add pca_attest $v attestation_binding; done
add pca_attest SANITY "sanity1 sanity2"

one() { # model variant query
  m=$1; v=$2; q=$3; [ "$v" = "-" ] && v=""
  n="$m${v:+__$v}"; base="results/logs/${n}__$q"
  ./gen.sh $m.pv "$v" $q > $base.pv
  s=$(date +%s); timeout $T nice proverif $base.pv > $base.log 2>&1; rc=$?; e=$(( $(date +%s) - s ))
  r=$(grep -E '^RESULT' $base.log | head -1)
  if [ -z "$r" ]; then if [ $rc = 124 ]; then r="TIMEOUT after ${T}s (no result)"; else r="NO RESULT (rc=$rc) $(grep -m1 -i error $base.log)"; fi; fi
  echo "$q | ${e}s | $r" > results/.tmp/$n.$q
  # compact log: drop the echoed process dump; cap very long lines; keep traces (false / cannot be proved) in full
  awk '/^-- Query/{p=1} p' $base.log | cut -c1-1200 > $base.log.c; mv $base.log.c $base.log
  case "$r" in *"is true"*) grep -E '^(RESULT|Starting query|Verification summary|Query|Associated|  - |.* - )' $base.log > $base.log.c; mv $base.log.c $base.log;; esac
  rm -f $base.pv
}
export -f one; export T
xargs -P "$J" -L 1 bash -c 'one $0 $1 $2' < $JOBS
rm -f results/pca_*.txt
while read -r m v q; do
  n="$m"; [ "$v" != "-" ] && n="${m}__$v"
  cat results/.tmp/$n.$q >> results/$n.txt
done < $JOBS
rm -rf results/.tmp
echo done

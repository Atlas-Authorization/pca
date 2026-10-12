#!/bin/sh
# Sequential, single-threaded, low priority. Usage: ./run_all.sh [timeout-seconds-per-lemma]
# Writes results/<theory>[__<VARIANT>].txt (one result line per lemma).
T=${1:-600}
cd "$(dirname "$0")"; mkdir -p results
run() { # theory variant lemma heuristic
  th=$1; var=$2; l=$3; h=$4
  flag=""; name=$th; [ -n "$var" ] && flag="-D$var" && name="${th}__$var"
  r=$(nice -n 15 ./run_lemma.sh "$T" "$th.spthy" "$l" --heuristic=$h $flag | head -1)
  echo "$r" >> "results/$name.txt"; echo "$name: $r"
}
rm -f results/*.txt
A="authorization leaf_signature_authenticity attenuation_root attenuation_hop replay_freedom_nonce replay_freedom_counter audience_binding no_accept_after_expiry"
for l in executable_root_grant executable_delegation_issued; do run pca_actn "" $l c; done
run pca_actn "" executable_delegated S
for l in $A; do run pca_actn "" $l s; done
# attack variants: the lemma each check protects
run pca_actn NO_GREF_CHECK replay_freedom_nonce s
run pca_actn NO_GREF_CHECK replay_freedom_counter s
run pca_actn NO_ANCESTOR_CAV attenuation_root s
run pca_actn NO_ANCESTOR_CAV attenuation_hop s
run pca_actn NO_AUD_CHECK audience_binding s
run pca_actn NO_EXPIRY_CHECK no_accept_after_expiry s
run pca_actn NO_LEAF_SIG leaf_signature_authenticity s
for l in executable_t3 executable_t2; do run pca_threshold "" $l c; done
TL="stepup3_requires_principal stepup3_requires_guardian stepup2_compromised_agent_insufficient stepup2_one_compromised_key_insufficient"
for l in $TL; do run pca_threshold "" $l c; done
for v in UNBOUND_SHARE NO_DISTINCT NO_SET_DISTINCT; do for l in $TL; do run pca_threshold $v $l c; done; done
run pca_attest "" executable_attestation c
run pca_attest "" attestation_binding c
for v in NOBIND_HOLDER NOBIND_GRANT NOBIND_EPOCH NOBIND_NONCE; do run pca_attest $v attestation_binding c; done

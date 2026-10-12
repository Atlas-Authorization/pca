#!/bin/sh
# run_all_v2.sh -- the v2 theories (unbounded chains, clock/store rewriting, budget, attest-allowlist, FROST).
# Usage: ./run_all_v2.sh [per-lemma-timeout-seconds] [parallel-jobs] [theory-prefix-filter]
# Each job = ONE lemma of ONE theory/variant, run as its own tamarin-prover process (+RTS -N<cores/par>).
# Results: results/v2/<theory>[__<VARIANT>].txt, one result line per lemma (verbatim tamarin line, or
# "TIMEOUT after Ns (NOT proved): <lemma>"), followed by "# wall=<s>s tamarin=<version>".
# A timeout is NOT a proof.  Needs: tamarin-prover 1.12.0 + maude 3.5.1 on PATH, GNU timeout or perl.
runto() { t=$1; shift; if command -v timeout >/dev/null 2>&1; then timeout "$t" "$@"; else perl -e 'alarm shift; exec @ARGV' "$t" "$@"; fi; }
# internal: single job mode  (./run_all_v2.sh __job "theory|variant|lemma|heuristic")
if [ "$1" = "__job" ]; then
  IFS='|' read -r th var l h <<EOT
$2
EOT
  cd "$(dirname "$0")"
  name=$th; flag=""
  [ -n "$var" ] && { flag=$(echo "$var" | sed 's/+/ -D/g; s/^/-D/'); name="${th}__$var"; }
  s=$(date +%s)
  nh=$(echo "$h" | tr '+' '\n' | wc -l); TE=$((T / nh)); res=""; used=""
  for hh in $(echo "$h" | tr '+' ' '); do
    if [ "$hh" = O ]; then hx="--heuristic=O --oraclename=./oracle_walk.sh"; else hx="--heuristic=$hh"; fi
    out=$(runto "$TE" tamarin-prover --prove="$l" $hx --derivcheck-timeout=0 $flag $th.spthy +RTS -N$N -M${MEM:-5g} -RTS 2>&1); rc=$?
    res=$(printf '%s\n' "$out" | grep -E "^  $l \(" | head -1)
    used=$hh; [ -n "$res" ] && break
    case $rc in 124|142) why="TIMEOUT";; 137|251) why="KILLED(memory)";; *) why="no-result rc=$rc"; printf '%s' "$out" | grep -q "heap overflow\|Heap exhausted" && why="HEAP-LIMIT(${MEM:-5g})";; esac
  done
  [ -n "$res" ] || res="$why after ${T}s budget (NOT proved): $l"
  e=$(date +%s)
  printf '%s\n# wall=%ss heuristic=%s %s\n' "$res" $((e-s)) "$used" "$TV" > "results/v2/.$name.$l.part"
  echo "$name: $res"
  exit 0
fi
T=${1:-1200}; PAR=${2:-4}; FILTER=${3:-}
cd "$(dirname "$0")"; mkdir -p results/v2
CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu); N=$((CORES / PAR)); [ "$N" -lt 1 ] && N=1
TV=$(tamarin-prover --version 2>&1 | grep -io 'tamarin-prover [0-9.]*' | head -1)
export T N TV
rm -f results/v2/.*.part
JOBS=$(mktemp)
job() { echo "$1|$2|$3|$4" >> "$JOBS"; }
sane="executable"
# ---------------- (2) unbounded chains ----------------
U=pca_actn_unbounded
for l in executable_root_grant executable_delegation_issued executable_two_hops executable_delegated executable_deep_chain; do job $U "" $l c+O+s; done
for l in walk_verb_invariant accept_verb_invariant walk_start_unique hop_issuance authorization leaf_signature_authenticity \
         attenuation_root attenuation_hop chain_all_hops_permit replay_freedom_nonce replay_freedom_counter audience_binding no_accept_after_expiry; do job $U "" $l c+O+s; done
job $U "" attack_root_widening c+s; job $U NO_ANCESTOR_CAV attack_root_widening c+s
job $U NO_GREF_CHECK replay_freedom_nonce c+O; job $U NO_GREF_CHECK replay_freedom_counter c+O
job $U NO_ANCESTOR_CAV attenuation_root c+O;  job $U NO_ANCESTOR_CAV attenuation_hop c+O; job $U NO_ANCESTOR_CAV chain_all_hops_permit c+O
job $U NO_AUD_CHECK audience_binding c+O; job $U NO_EXPIRY_CHECK no_accept_after_expiry c+O; job $U NO_LEAF_SIG leaf_signature_authenticity c+O
# ---------------- (3) clock + linear store ----------------
S=pca_actn_time_store
for l in executable_accept executable_two_actions executable_after_tick; do job $S "" $l c+O+s; done
for l in accept_has_unexpired_decision clock_no_regress clock_no_regress_plain authorization attenuation_root audience_binding replay_freedom_nonce replay_freedom_counter no_accept_after_expiry; do job $S "" $l c+O+s; done
job $S NO_EXPIRY_CHECK no_accept_after_expiry c+O; job $S NO_EXPIRY_CHECK accept_has_unexpired_decision c+O
job $S STORE_RACE_NONCE replay_freedom_nonce c+O; job $S STORE_RACE_CTR replay_freedom_counter c+O
job $S NO_GREF_CHECK replay_freedom_nonce c+O; job $S NO_GREF_CHECK replay_freedom_counter c+O
job $S NO_AUD_CHECK audience_binding c+O; job $S NO_ANCESTOR_CAV attenuation_root c+O
# ---------------- (4a) budget_alloc tree ----------------
B=pca_budget
for l in executable_spend executable_two_spends executable_deep_spend; do job $B "" $l c+s; done
for l in alloc_monotone root_bound node_bound spend_debits_root; do job $B "" $l c+s; done
job $B ROOT3 executable_spend c+s; job $B ROOT3 root_bound c+s
job $B NO_PARENT_CHECK alloc_monotone c+s; job $B NO_PARENT_CHECK root_bound c+s; job $B NO_PARENT_CHECK node_bound c+s
job $B DEBIT_LEAF_ONLY root_bound c+s; job $B DEBIT_LEAF_ONLY spend_debits_root c+s; job $B DEBIT_LEAF_ONLY node_bound c+s
job $B NONATOMIC_DEBIT root_bound c+s; job $B NONATOMIC_DEBIT node_bound c+s; job $B NONATOMIC_DEBIT spend_debits_root c+s
# ---------------- (4a') scope set / resource prefix narrowing ----------------
R=pca_scope_resource
for l in executable_accept executable_delegated executable_deeper_resource scope_narrowing_all_hops resource_narrowing_all_hops \
         root_scope_bounds_action root_resource_bounds_action honest_hop_scope_bounds_action authorization; do job $R "" $l c+O+s; done
for l in scope_narrowing_all_hops root_scope_bounds_action honest_hop_scope_bounds_action; do job $R NO_ANCESTOR_SCOPE $l c+O; done
for l in resource_narrowing_all_hops root_resource_bounds_action; do job $R NO_ANCESTOR_RES $l c+O; done
# ---------------- (4c) software attestation allowlist + rollback ----------------
A=pca_attest_allowlist
for l in executable_attest_v1 executable_attest_after_revocation attestation_authentic weights_allowlisted operator_allowlisted \
         measurement_in_projection no_manifest_rollback revoked_never_attested; do job $A "" $l c+s; done
for l in no_manifest_rollback revoked_never_attested; do
  for v in NO_VERSION_CHECK STATE_WIPE STATE_WIPE+ANCHORED STATE_WIPE+ANCHOR_REPLAY ANCHORED; do job $A $v $l c+s; done
done
job $A NO_WEIGHTS_CHECK weights_allowlisted c+s; job $A NO_OPERATOR_CHECK operator_allowlisted c+s
# ---------------- (4b) FROST ----------------
F=pca_frost_sign
for l in executable_threshold_signature executable_two_sessions share_secrecy sig_needs_t_signers shares_bound_to_session nonce_one_shot; do job $F "" $l c+s; done
for l in share_secrecy sig_needs_t_signers nonce_one_shot; do job $F NONCE_REUSE $l c+s; done
for l in shares_bound_to_session sig_needs_t_signers; do job $F NO_BINDING $l c+s; done
D=pca_frost_dkg
for l in executable_dkg dkg_key_not_adversarial; do job $D "" $l c+s; done
job $D NO_POP dkg_key_not_adversarial c+s; job $D NO_POP executable_dkg c+s
# ---- run (FILTER = result-name prefix, e.g. pca_actn_time_store__STORE) ----
grep "^$FILTER" "$JOBS" > /dev/null 2>&1 || true
awk -F'|' -v f="$FILTER" '{n=$1; if($2!="")n=$1"__"$2; if(index(n,f)==1)print}' "$JOBS" > "$JOBS.sel"
while IFS='|' read -r th var l h; do name=$th; [ -n "$var" ] && name="${th}__$var"; rm -f "results/v2/$name.txt"; done < "$JOBS.sel"
xargs -P "$PAR" -I{} ./run_all_v2.sh __job {} < "$JOBS.sel"
# assemble per-theory result files, lemma order = job order
while IFS='|' read -r th var l h; do
  name=$th; [ -n "$var" ] && name="${th}__$var"
  [ -f "results/v2/.$name.$l.part" ] && { cat "results/v2/.$name.$l.part" >> "results/v2/$name.txt"; rm -f "results/v2/.$name.$l.part"; }
done < "$JOBS.sel"
rm -f "$JOBS" "$JOBS.sel"

#!/usr/bin/env bash
# run_all.sh -- CryptoVerif proofs of PCA's cryptographic reductions + negative controls.
# Needs `cryptoverif` (source ~/cvenv.sh after install-cv.sh). FARM ONLY (never the Mac):
#   PCAQ_OWNER=crypto-proofs cloud-box tooling/q submit --box sp4 --cores 2 --mem 12 --wall 14400 --prep none \
#     --pull formal/cryptoverif/results --wait -- bash formal/cryptoverif/farm-check.sh
# results/<case>.txt  = the RESULT lines (bounds verbatim); results/logs/<case>.log = full output;
# results/SUMMARY.txt = one line per case: expected vs got. A positive case passes only if ALL its queries are
# proved; a negative control passes only if the named query is NOT proved (the check it removes is necessary).
set -uo pipefail
cd "$(dirname "$0")" || exit 1
LIB=${CV_LIB:-$(opam var doc 2>/dev/null)/cryptoverif/default.cvl}
[ -f "$LIB" ] || LIB=$(ls ~/.opam/*/doc/cryptoverif/default.cvl 2>/dev/null | head -1)
TMO=${CV_TIMEOUT:-3600}
mkdir -p results/logs results/neg
cryptoverif -help 2>&1 | head -1 > results/versions.txt
echo "lib: $(basename "$LIB") ($(sha256sum "$LIB" | cut -c1-16))" >> results/versions.txt
: > results/SUMMARY.txt
mism=0

run() { # case file
  local t0=$(date +%s)
  timeout "$TMO" cryptoverif -lib "$LIB" "$2" > "results/logs/$1.log" 2>&1
  local rc=$?
  { grep -E '^RESULT (Proved|Could not prove)|^All queries proved|^Error|^File ' "results/logs/$1.log" | cut -c1-2000
    grep -E 'Could not prove|^Error' "results/logs/$1.log" | grep -v '^RESULT' ; } > "results/$1.txt"
  [ -s "results/$1.txt" ] || echo "NO RESULT LINES (rc=$rc, see logs/$1.log)" > "results/$1.txt"
  echo "rc=$rc secs=$(( $(date +%s) - t0 ))" >> "results/$1.txt"
}
pos() { # case file  -> expect "All queries proved."
  run "$1" "$2"
  if grep -q '^All queries proved' "results/$1.txt"; then got=proved; else got=NOT-ALL-PROVED; fi
  [ "$got" = proved ] || mism=$((mism+1))
  printf '%-34s expect=all-proved   got=%s\n' "$1" "$got" | tee -a results/SUMMARY.txt
}
neg() { # case file query-regex -> expect that query NOT proved
  run "$1" "$2"
  if grep -E '^RESULT Could not prove' "results/$1.txt" | grep -qE "$3"; then got=not-proved
  elif grep -qE '^Error' "results/$1.txt"; then got=ERROR
  else got=PROVED; fi
  [ "$got" = not-proved ] || mism=$((mism+1))
  printf '%-34s expect=not-proved   got=%s   (query ~ %s)\n' "$1" "$got" "$3" | tee -a results/SUMMARY.txt
}
N=results/neg

# ---- positive models
for m in intent_delta acc_receipt revocation_epoch attest_hw zk_intent pq_pinned_delta frost_descriptor fame_kemdem acc_receipt_retire map_commit_hiding map_commit_t28 kem_combiner; do pos "$m" "$m.cv"; done

# ---- negative controls (each removes ONE check / assumption; the named query must become unprovable)
# T15: accept a delta signed by any key S lists (not the pinned principal): an agent- or attacker-signed delta
sed -e 's/if check(mkcap(pkP, hol, sid, k, prev, rd, e), pkP, sg) then/if mem(spk, ps) then if check(mkcap(spk, hol, sid, k, prev, rd, e), spk, sg) then/' intent_delta.cv > $N/NEG_delta_any_signer.cv
neg NEG_delta_any_signer $N/NEG_delta_any_signer.cv 'AcceptK\(s, r, k, p, h, e\)\) ==> \(?event\(MintedP'
# q_root: the delta does not carry digest(S) (wallet and verifier sign / check a constant root)
sed -e 's/^type sid_t\./const noroot: digest.\ntype sid_t./' -e 's/mkcap(pkP, hol, sid, k, prev, rd, e)/mkcap(pkP, hol, sid, k, prev, noroot, e)/g' intent_delta.cv > $N/NEG_delta_no_root.cv
neg NEG_delta_no_root $N/NEG_delta_no_root.cv 'AcceptRoot'
# receipts: no key-set check (the receipt's own signer key is trusted)
sed -e 's/  if check(mkentry(kid, spk, w), pkR, esig) then/  if true then/' acc_receipt.cv > $N/NEG_rcpt_no_keyset.cv
neg NEG_rcpt_no_keyset $N/NEG_rcpt_no_keyset.cv 'event\(AcceptR\(p, s, a, q, x, u, k, r\)\) ==> \(?event\(Issued'
# receipts: no seq store (a receipt counted twice)
sed -e '/get accepted(=s, =a, =q) in yield else/d' -e '/insert accepted(s, a, q);/d' acc_receipt.cv > $N/NEG_rcpt_no_store.cv
neg NEG_rcpt_no_store $N/NEG_rcpt_no_store.cv 'inj-event\(AcceptR'
# epochs: no domain separation between epochs and the other artifacts the same key signs
sed -e '/^equation forall i: inst_t/d' revocation_epoch.cv > $N/NEG_epoch_no_domsep.cv
neg NEG_epoch_no_domsep $N/NEG_epoch_no_domsep.cv 'event\(Accept\(i, s, r, t\)\)'
# attestation: report_data does not bind the nonce (replay)
sed -e 's/^type nonce_t \[large, fixed\]\./type nonce_t [large, fixed].\nconst n0: nonce_t./' -e 's/bind(hpk, g, e, n)/bind(hpk, g, e, n0)/; s/bind(h, g, e, n)/bind(h, g, e, n0)/' attest_hw.cv > $N/NEG_att_no_nonce.cv
neg NEG_att_no_nonce $N/NEG_att_no_nonce.cv 'inj-event\(Accept'
# attestation: report_data does not bind the holder key (relay to another holder)
sed -e 's/^type hpkey \[bounded\]\./type hpkey [bounded].\nconst h0: hpkey./' -e 's/bind(hpk, g, e, n)/bind(h0, g, e, n)/; s/bind(h, g, e, n)/bind(h0, g, e, n)/' attest_hw.cv > $N/NEG_att_no_holder.cv
neg NEG_att_no_holder $N/NEG_att_no_holder.cv '[^-]event\(Accept\(c, h, g, e, n, m\)\) ==> \(?event\(GuestQuoted'
# attestation: the verifier skips the measurement allowlist (measurement substitution)
sed -e '/^  let good(im) = m in /d' attest_hw.cv > $N/NEG_att_no_allowlist.cv
neg NEG_att_no_allowlist $N/NEG_att_no_allowlist.cv '[^-]event\(Accept\(c, h, g, e, n, m\)\) ==> \(?event\(GuestQuoted'
# attestation: hardware assumption broken (a rogue guest can report an allowlisted measurement)
sed -e 's/in(cR, (cid: chipid_t, z: junk_t, rd: rd_t));/in(cR, (cid: chipid_t, zz: img_t, rd: rd_t));/' -e 's/mkrep(bad(z), rd)/mkrep(good(zz), rd)/' attest_hw.cv > $N/NEG_att_hw_broken.cv
neg NEG_att_hw_broken $N/NEG_att_hw_broken.cv '[^-]event\(Accept\(c, h, g, e, n, m\)\) ==> \(?event\(GuestQuoted'
# zk: the verifier does not pin the image id (accepts proofs under any image key)
sed -e 's/in(cV, (x: act_t, s: sid_t, c: commit_t, e: eps_t, gsig: signature, pf: zkproof));/in(cV, (x: act_t, s: sid_t, c: commit_t, e: eps_t, gsig: signature, pf: zkproof, img2: zkimg));/' -e 's/if zkverify(mkjournal(d, s, c, e), img, pf) then/if zkverify(mkjournal(d, s, c, e), img2, pf) then/' zk_intent.cv > $N/NEG_zk_no_image_pin.cv
neg NEG_zk_no_image_pin $N/NEG_zk_no_image_pin.cv 'event\(Accept\(x, s, c, e\)\)'
# zk: the verifier does not check the principal's commitment grant
sed -e 's/if check(mkgrant(s, c), pkP, gsig) then/if true then/' zk_intent.cv > $N/NEG_zk_no_commit.cv
neg NEG_zk_no_commit $N/NEG_zk_no_commit.cv 'event\(Accept\(x, s, c, e\)\)'
# PQ: the admitting root's ML-DSA key is taken from the artifact (unpinned)
sed -e '/(\*-PIN\*)/d' -e 's/(\*+PIN \(.*\) \*)/\1/' pq_pinned_delta.cv > $N/NEG_pq_artifact_key.cv
neg NEG_pq_artifact_key $N/NEG_pq_artifact_key.cv 'AcceptK'

# FR-5: the verifier does not pin the authority key (any key the descriptor names)
sed -e 's/in(cV, (xg: gkey_t, treq: t_t, n: n_t, s: sset_t, sg: signature));/in(cV, (xg: gkey_t, treq: t_t, n: n_t, s: sset_t, sg: signature, pkX: pkey));/' -e 's/if check(mkdesc(xg, treq, n, k), pkA, sg) then/if check(mkdesc(xg, treq, n, k), pkX, sg) then/' frost_descriptor.cv > $N/NEG_desc_unpinned.cv
neg NEG_desc_unpinned $N/NEG_desc_unpinned.cv 'event\(Accept\(x, t, n, s\)\)'

# ABE-3: K not uniform (the FAME hop removed: a fixed, adversary-known K)
sed -e 's/^type salt_t \[large, fixed\]\./type salt_t [large, fixed].\nconst k0: gt./' -e 's/  new k: gt; .*$/  let k = k0 in/' fame_kemdem.cv > $N/NEG_fame_known_k.cv
neg NEG_fame_known_k $N/NEG_fame_known_k.cv 'secre(t|cy of) b'

# finding 1 fix: the OLD verifier (no retirement / age checks) -- a key leaked after retirement forges receipts
sed -e '/(\*-RETIRE\*)/d' acc_receipt_retire.cv > $N/NEG_rcpt_ignores_retirement.cv
neg NEG_rcpt_ignores_retirement $N/NEG_rcpt_ignores_retirement.cv 'event\(AcceptR\(p, s, a, q, x, u, k, r\)\) ==> \(?event\(Issued'

# rule 19 hiding: the earlier design, ONE session salt (revealed by a Z0 disclosure) -- not hiding
sed -e '/(\*-PERLEAF\*)/d' -e 's/(\*+PERLEAF \(.*\) \*)/\1/' map_commit_hiding.cv > $N/NEG_map_one_salt.cv
neg NEG_map_one_salt $N/NEG_map_one_salt.cv 'secre(t|cy of) b'
# T28 against rule 19: the guest skips the metrics opening (the claimed risk is not the committed one)
sed -e '/  if c = H(hk, commitin(s4, rootm)) then/d' map_commit_t28.cv > $N/NEG_t28_no_metrics_open.cv
neg NEG_t28_no_metrics_open $N/NEG_t28_no_metrics_open.cv 'event\(Accept\(x, s, c, e\)\)'

# finding 2 fix: the OLD verifier (any session principal may sign the session's epochs) -- a co-principal suppresses
sed -e '/(\*-AUTH\*)/d' -e 's/(\*+AUTH \(.*\) \*)/\1/' revocation_epoch.cv > $N/NEG_epoch_any_principal.cv
neg NEG_epoch_any_principal $N/NEG_epoch_any_principal.cv 'event\(Accept\(i, s, r, t\)\)'

# evidence bundle: the reader takes the principal keys from the bundle's own (self-signed) session root (the code's
# default when trust.principals is not supplied) -- the bundle is then not attributable to P
sed -e '/(\*-PRINCIPALS\*)/d' -e 's/(\*+PRINCIPALS \(.*\) \*)/\1/' intent_delta.cv > $N/NEG_bundle_principals_from_S.cv
neg NEG_bundle_principals_from_S $N/NEG_bundle_principals_from_S.cv 'AcceptBundle\(s, r, k, p, e, o, g, x\)\) ==> \(?(exists h: pkey; )?event\(MintedP'

# KEM combiner: the hash input omits ss1 (the secure component), so the key is computable from the broken component
sed -e 's/^type hin\./const ss0: ss_t.\ntype hin./' -e 's/mkin(ss1, s2s, c1s, c2s)/mkin(ss0, s2s, c1s, c2s)/' kem_combiner.cv > $N/NEG_kem_no_ss1.cv
neg NEG_kem_no_ss1 $N/NEG_kem_no_ss1.cv 'secre(t|cy of) k0'

echo "mismatches: $mism" | tee -a results/SUMMARY.txt
exit $(( mism > 0 ? 1 : 0 ))

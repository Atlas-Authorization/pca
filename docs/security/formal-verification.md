# PCA formal verification

This page states what has been mechanically verified about the PCA protocol logic, with which tools, and
what has not. Nothing here is a claim about the shipped code beyond what is listed under "Gaps".

Two complementary tools are used:

- **Tamarin** (symbolic Dolev-Yao model): protocol-level properties against an active network attacker
  who can also compromise keys.
- **Lean 4** (deductive proofs, no `sorry`): properties that need induction over arbitrary-length chains,
  arbitrary interleavings of store operations, and arithmetic.

Two further tools were added in this revision (sections "ProVerif" and "CryptoVerif" below), and a
model-to-code conformance harness (section "Model-to-code conformance").

## Tool versions

| Tool | Version | Where run |
|---|---|---|
| Tamarin prover | 1.12.0 (Homebrew tap on the Mac for the original runs; GitHub release `linux64-ubuntu` on the cloud boxes) | boxes |
| Maude | 3.5.1 (release zip; apt's 3.2 is rejected by Tamarin) | boxes |
| ProVerif | 2.05 (opam switch `pv`, OCaml 4.14.2) | cloud-box-1 |
| CryptoVerif | 2.13 (opam; `formal/cryptoverif/install-cv.sh` installs switch `cv`) | cloud-box-1, sp4 |
| Lean 4 | v4.34.1 (core only, no mathlib) | Mac + box |
| Node / tsx / vitest stack | repo-pinned (tsx 4.23.1) | boxes |

Toolchain install: `tools/pca-formal/box-setup.sh`.

## What is modelled (Tamarin, `formal/tamarin/`)

All three models use the Dolev-Yao attacker: it controls the network and may reveal (compromise) any
long-term key. Cryptography is perfect (signatures unforgeable without the key, hashes collision-free).

**`pca_actn.spthy` - PCActn verification** (`pcactn.ts`, `capability.ts`, `replay.ts`). A principal is the
verifier's trust anchor and signs a root grant. Delegates append one caveat per hop; each hop is signed by
the previous holder and linked to its parent by hash. The agent signs actions carrying audience, verb,
`grant_ref`, counter, nonce and an expiry. The verifier checks audience, expiry, every hop's signature and
parent link, that the root issuer is the trust anchor, every hop's caveat against the verb, `grant_ref ==
id(root capability)`, the leaf signature, and finally the one-time nonce key and counter stream keyed on
(audience, grant_ref, leaf holder). Honest agents sign whatever they are asked to (a prompt-injected agent).

**`pca_threshold.spthy` - threshold step-up** (`threshold.ts`). Signer sets register one key per role
(agent, guardian, principal). A share is a signature over role, hash of the message, signer-set hash and
`t`. The verifier accepts at t=1 (agent leaf signature), t=2 (any two distinct roles) or t=3. The leaf
signature is admitted as the agent's baseline share and is domain-separated from share messages. Several
signer sets share one principal key, which makes cross-context replay of a share meaningful.

**`pca_attest.spthy` - attestation binding** (`attestation.ts`). The verifier issues a fresh nonce for an
expected (holder, grant, epoch). An approved enclave answers any nonce an attacker hands it with a quote
whose `report_data` binds its own holder, grant, epoch and that nonce. A rogue enclave on genuine hardware
can put any `report_data` in a quote but has a non-approved measurement. The verifier checks the vendor
signature, recomputes `report_data` from its expectation, and requires the approved measurement.

## Proof ledger at the 0.4.0 release (2026-10-11)

One row per mechanised result that backs the 0.4.0 release: what is proved, by which tool, and in what scope. Details are in the sections below, in `implementation-verification.md`, `verified-core.md` and `computational-proofs.md` (claim ledger). "Not concluded" means the tool ran out of memory or time; such rows prove nothing. "Pending" rows are filled in when the open closure runs land.

| Area | Tool | Scope | Result | Evidence |
|---|---|---|---|---|
| Decision core (chain walk and attenuation, threshold count, replay guard, check and verdict combinator, PQ key-authority and suite rules) | Dafny 4.11.0 | unbounded; no `assume` / axiom / extern | 171 verified, 0 errors; committed generated JS byte-identical to a fresh compile (re-run 2026-10-11) | `verified-core.md`, `formal/dafny/` |
| Regex, Wire, Merkle, Taint, Attest, PolicyVm models | Dafny 4.11.0 | unbounded, standalone models | 245, 325, 189, 63, 134, 271 verified, 0 errors (PolicyVm 288 at 0.4.1, re-run 2026-10-12, after the root-caveat lemmas); generated JS byte-identical (re-run 2026-10-11) | `formal/dafny/*.dfy` |
| Proved regex engine vs production TypeScript and V8 | differential testing (not a proof) | 6,000,040 (pattern, subject) pairs | 0 disagreements | `verified-core.md` ledger row |
| Production TS vs the Dafny-backed core | differential testing | conformance corpus plus random mutations | 290 of 290 tests agree | `packages/pca-verified-core/test/` |
| Which production paths ARE proved code (0.4.2) | Dafny models compiled to JS, called directly by `packages/pca` | default: core (chain, threshold, replay guard, verdict) plus taint, Merkle inclusion, attestation decisions and the `decide()` kernels; opt-in (`PCA_VERIFIED_CORE`): wire, regex, Policy-VM evaluator, strict Merkle consistency / membership, nonce store | CI wiring scan (`scripts/check-verified-core.sh`); differential tests now compare production (proved) against frozen hand-written oracles | `verified-core.md` "Production wiring of the extension components" |
| The 9 native verifiers (Go, Python, Rust, Java, .NET, PHP, Ruby, Kotlin, Swift) | conformance corpus + mutation testing (not a proof) | every vector, every language | conformance-checked, **not proved**; only bounded Kani harnesses and Verus transliterations of Rust fragments exist | `implementation-verification.md` |
| Budget `node_bound` (one allocation: at most its limit of distinct debiting spends) | Tamarin | unbounded traces; concrete limits 'c1' (v4 shipped model) and 'c2' (v5 focus encoding) | verified (54 steps on v4; 55 with induction; v5 16 and 612 steps) | "Budget and scope closure" below |
| Budget `root_bound` | Tamarin | unbounded traces; limit 'c2' | verified (67,480 steps) | same |
| Budget bug witnesses `DEBIT_LEAF_ONLY`, `NONATOMIC_DEBIT`, `NO_PARENT_CHECK`; scope `NO_ANCESTOR_RES`, `NO_ANCESTOR_SCOPE` | TLC (TLA+ mirrors of the Tamarin models) | bounded (B1, C1); shipped model also passes at B2 over 8,552,602 states | 13 cases, 0 mismatches: every bug flag yields a counterexample, the shipped model passes at the same bound; Tamarin also finds the `DEBIT_LEAF_ONLY` trace (18 steps) | same |
| Scope and resource narrowing on every hop | Tamarin | unbounded | verified (1,204 and 1,660 steps) | "Revision 2" table |
| `root_bound` incl. `ROOT3`, `node_bound` for limits 1-3, `spend_debits_root`, `spent_root_is_root_node`, `no_negative_spend` (shipped v4); Tamarin witnesses for `NONATOMIC_DEBIT` (pinned, 34 steps) and `NO_ANCESTOR_RES` (pinned, 30 steps); shipped-model controls | Tamarin (+ Lean for the v4-to-v5 focus transfer) | unbounded traces, concrete limits | all verified; every budget/scope attack lemma finds a trace on its bug flag and none on the shipped model (rounds 2 and 3) | `b63a3360`, `b04cf555` |
| Durable-state lock recovery with a paused holder, recovery crash after every step, append-only fences | TLC (`formal/tla/DurableFence.tla`) | bounded; safety (`Safe`) and liveness (`NoWedge`, `AckedOrFailedClosed`) | shipped model passes; removing the fence, the head repair, the lock-first order, the cut pin or append-only fences each gives a counterexample | `formal/tla/` |
| LESS verifier (C, category 252): RebuildGGM + CountPublishedSeeds, SampleChallenge, `crypto_sign_open` over the proved contracts | CBMC (+ a Verus lemma) | unbounded in loop length and retries; full-size in data (TARGET 45, 68, 192) | all verified; unpatched controls fail as required | `implementation-verification.md` section 3 |
| `atlas-pca` (Rust) arithmetic and decoders | Kani, Verus | `split`/`path_shape`/`safe_int` unbounded; base64url length arithmetic for any n; Verus `core_checks`, `b64u_strict`, `bounded_reader`, `swap_count` unbounded | verified | `implementation-verification.md` "Run status" |
| `decode_b64u_no_panic_bounded`, `decision_aggregation`, zkvm-pca `zk_decode_b64u_strict_bounded6` | Kani | bounded | not concluded (memory or 6 h limit); the base64url algorithm is proved unbounded in Verus | same |
| Undefined behaviour in the Rust verifiers and decoders | Miri | interpreted execution of exactly the listed inputs: the full `atlas-pca` conformance corpus, the stark-pca, zkvm-pca/core and plonky3 decoder drivers | no UB; `folding-pca` not concluded (6 h limit) | same |
| stark-pca-plonky3 `validate_bounds`, `g_from_u128`, `hex256_limbs` (lowercase-only spec) | Kani | see section 2 of `implementation-verification.md` | verified | same |
| zkVM policy guest (RISC Zero) | receipts, not a proof of the guest source | guest image `3b1eebb56b046e737fb15009bdd065b67d7938cb8d47f3f3f0dadc801f84fdad`, reproducible docker build | re-proved receipts verify under the new id; older images are refused as `Superseded` | `sdks/zkvm-pca/CHANGELOG.md` |
| Kani compositional decision and base64 harnesses; sharded `folding-pca` Miri (12 of 17 shards pass at the time of writing) | Kani, Miri | - | running; results go in a follow-up docs commit (not a release blocker) | `f342b878` |
| Tamarin and TLC closure runs | Tamarin, TLC | - | done (row above) | `b63a3360`, `b04cf555` |
| Threshold share whose `pq_pk` differs from the registered key | Dafny (`Threshold.dfy` lemma `PqPkMismatchNeverCounts`) + conformance vectors | unbounded (Dafny); 4 shared DENY vectors | core 171 verified, glue contract 174 verified; cross-language gate 12,152 vectors, 0 disagreements (TypeScript plus 7 native verifiers, Go, Python, Ruby, PHP, .NET, Rust and Java, in the per-vector matrix; Kotlin and Swift run natively over the same corpus) | `d00dba73` |
| Cryptographic reductions behind T15, sequencer receipts and key sets (incl. the retirement / freshness fix), revocation epochs (dedicated authority), AT-3/AT-4 attestation (T27 sink check), T28 and Z0 hiding against rule 19, zkVM receipts, PQ trusted-side pins, FR-5, ABE-3, evidence-bundle attribution | CryptoVerif 2.13 | computational, concrete bounds; 11 models, against the code of 5e718f47 / 5501b545 / 16953c21 | **all queries proved**; 18 negative controls (incl. the pre-fix behaviours) each unprovable as required, 0 mismatches (job `q261012-210157-bx9q`, 2026-10-12) | "Computational reductions (CryptoVerif, 2026-10-12)" below, `formal/cryptoverif/` |
| Sorted-set non-membership (revocation); committed-map binding for any size (`open_binding`, `z0_binding`); append-only revocation / key-set chains (`chain_sub`, `never_readmit`, `chain_root`) | Lean 4 (core) | unbounded sizes and chain lengths, explicit collision extractors (tightness 1) | all checked, axioms at most `propext`, `Classical.choice`, `Quot.sound`, no `sorry` | `formal/computational/lean/PcaComp/{NonMember,MapCommit,RevChain}.lean`, `formal/computational/nonmember-check.txt` |
| GG-2 forward security of the GGM ratchet, depth-generic hybrid (`hybrid`: depth * eps_prg for any depth; `gg2`: eps_CR + 2^d (eps0 + d eps + epsL + eps_Ed)) | Lean 4 + Mathlib | any depth (no unrolling); efficiency as distinguisher classes closed under the reduction steps | checked, axioms `propext`, `Classical.choice`, `Quot.sound` | `formal/computational/leanmath/PcaMath/Ratchet.lean`, `formal/computational/ratchet-check.txt` |

## Computational reductions (CryptoVerif, 2026-10-12)

Claims that had been argued only in prose because they are cryptographic reductions or rest on trusted hardware
are now proved in CryptoVerif 2.13, with concrete bounds in the primitives' advantages. Models, recorded output and
the reproduce command are in `formal/cryptoverif/` (README there). Run: job `q261012-210157-bx9q`, farm box sp4.
Result: 11 models, every query proved; 18 negative controls (one removed check or assumption each, including the
behaviour before the fixes of 5e718f47 / 5501b545 and the one-salt map commitment), every one unprovable as required. `Psign` = UF-CMA advantage of one key, `Phash` = collision advantage, `Psigncoll` = key
collision, `N*` = numbers of keys / verifier runs; each bound is CryptoVerif's verbatim output, summarised.

| Claim | Model | Proved correspondence | Bound |
|---|---|---|---|
| T15 delta authenticity (+ the EUF premise of T14) | `intent_delta.cv` | an accepted admitting root D_k was minted by the trust-anchor principal with exactly (session, digest(S), seq, prev, holder, body); every honest-signed earlier link was minted by its signer; per-link, so for chains of any length | `Psign_P + 2 Psigncoll + 3 Phash` |
| Session-root binding | same | the accepted S is one P signed, although the verifier only checks S's self-signature under a key S lists | same |
| Evidence-bundle attribution (`pca-evidence` `verifyEvidenceBundle`) | same | with the reader's principal keys pinned (`trust.principals`), a re-verified bundle attributes the grant, the signed answer and the agent's action to their honest signers; with the default (keys from the bundle's own self-signed S) nothing is attributable (negative control) | `+ Psign_A` |
| Sequencer receipts + root-signed key sets (rotation, corruption) | `acc_receipt.cv` | accepted receipt => issued by the sequencer with exactly these fields, unless that signing key leaked; injective (no double counting); the pcactn digest binds one action | `Psign_root + NK (Psign_key + Psigncoll) + 2 Phash` |
| Revocation epochs (dedicated authority, 5e718f47) | `revocation_epoch.cv` + Lean `RevChain` | an accepted epoch was published by the session's revocation authority (scope, root, times), with a dishonest co-principal present; the tracked chain is append-only (no rollback, drop or equivocation) | `Psign_authority` |
| Receipts after the retirement / freshness fix (5e718f47, 5501b545) | `acc_receipt_retire.cv` | a key that leaks only after its retirement takes effect forges nothing: accepted receipt => issued, no corruption escape; injective | `Psign_root + NK Psign_key + (3NK^2+NK) Psigncoll + 2 Phash` |
| AT-3 / AT-4 / measurement substitution / T27 sink check | `attest_hw.cv` | accepted attestation => a genuine allowlisted guest quoted exactly (holder, grant, epoch, nonce, measurement), unless the signing chip was physically broken; injective (replay fails); accepted action => signed by that attested guest (relay fails) | `Psign_root + NC (Psign_chip + Psigncoll) + 3 Phash + NV^2/2|nonce|` (+ `NL PsignH` for the action) |
| zkVM receipt soundness (abstract commitment) | `zk_intent.cv` | accepted => the principal committed to map m (salt r) and the pinned-image guest ran on (m, r, action) and admitted it with risk <= eps | `Pzk + Psign_P + 4 Phash` |
| T28 against rule 19 (16953c21) | `map_commit_t28.cv` + Lean `MapCommit.z0_binding` | accepted => the guest checked the principal's committed header, cell and metrics leaves (exact values and salts) | `Pzk + Psign_P + 5 Phash` |
| Z0 hiding against rule 19 | `map_commit_hiding.cv` | undisclosed leaves stay secret given their leaf hashes and the disclosed salts, any number of leaves | `(2 NL^2 + 4 qH NL)/2^256` |
| PQ suites only under trusted-side pins | `pq_pinned_delta.cv` | T15, root binding and epoch authenticity with Ed25519 fully broken | `Ppq(ML-DSA-65) + 3 Phash` (no Ed25519 term) |
| FR-5 FROST descriptor binding | `frost_descriptor.cv` | accepted descriptor => certified by the pinned authority with exactly (X_g, t, n, signer set) | `Psign_auth + 3 Phash` |
| ABE-3 KEM-DEM | `abe_kemdem.cv` | secrecy of the challenge bit | `4 NE Penc + (NE^2 + 2 qH NE)/|G_T|` after the Lean ABE-1 hop |

Negative controls (each must fail, and does): delta signed by any key S lists; delta without digest(S); no key-set
check; no seq store; no domain separation between epochs and other artifacts; report_data without the nonce; without
the holder key; no allowlist check; hardware assumption broken (rogue image with an allowlisted measurement); zk
verifier without image-id pin; without the principal's commitment; ML-DSA key from the artifact; unpinned FROST
authority; ABE key known; and the pre-fix behaviours: receipts without retirement / freshness, epochs from any principal,
the one-salt map commitment, the guest skipping the metrics opening, a bundle reader taking principals from the bundle.

**Assumptions left (exactly):** UF-CMA of Ed25519, ML-DSA-65 (SLH-DSA, hybrid via EasyCrypt H-1), and the vendor
attestation keys; collision resistance of SHA-256 and SHA-512; NA-ZKVM (knowledge soundness of the pinned-image
RISC Zero receipt, modelled as unforgeability of journals whose only producer is the public guest) and, for T28's
hiding only, NA-ZK plus EasyCrypt HID; NA-CANON (injective, domain-separated encodings; Dafny `Wire.dfy`); ABE-3 also
HKDF as a random oracle. **Hardware (HW-ATT), stated minimally:** the vendor root key is unforgeable, and a chip's
attestation key is used only by its secure processor, only to sign report(m, rd) with m the launch measurement of the
requesting guest and rd the value that guest supplied. Per chip: a physically broken chip is the `ChipBroken`
escape and affects only its own reports. Separately, the allowlisted mediator code requests reports only for holder
keys it generated and never exports (H3). That is a property of the measured code, not of the hardware.

**Compositions** (each part machine-checked, combined by a union bound): T11 no-overspend = receipt injectivity +
TLA+ `Reservation.tla` `NoOverspend`; T22 = epoch authenticity + Lean `PcaComp.NonMember.nonmember_sound` + TLA+
`Revocation.tla` `ExposureBound`, so Pr[revoked id admitted after t_r + Delta_rev + s] <= Psign + Psigncoll +
Adv_CR(SHA-256); T27 = `attest_hw.cv` + Dafny `Taint.dfy` + interpreter correctness (not proved; `pca-dataflow` is not
wired to attestation yet); AT-3/AT-4 = `attest_hw.cv` + Dafny `Attest.dfy` (`VerifySound`, `NonceAgeSound`,
`HookSound`: the decision procedure is exactly the modelled conjunction).

**Findings:** (1) a leaked *retired* sequencer key forged receipts indefinitely: FIXED in 5e718f47 / 5501b545,
proved above, the old verifier is a negative control (residual window for a key leaked before its retirement takes
effect: 60 s + `max_keyset_age_s`, or 60 s with tracked key-set versions); (2) any co-principal could sign a
revocation-suppressing epoch: FIXED (dedicated authority, append-only full-set epochs), proved, old behaviour is a negative
control; (3) Z0 needed per-leaf salts: IMPLEMENTED in 16953c21, proved hiding; (4) NEW: `verifyEvidenceBundle` without
`trust.principals` attributes nothing (the bundle's own session root is self-signed), so a fabricated bundle re-verifies;
a reader must pin the principal keys or compare the reported `principal_keys` out of band.

GG-2 is now machine-checked for every depth in Lean (`PcaMath/Ratchet.lean`, ledger row above). Not mechanised here:
FROST/PedPoP themselves (NA-FROST), attestation deployment assumptions H6-H9, and multi-root independence.

## Results

Every line below is the tool's output, recorded in `formal/tamarin/results/` (log: `results/runall.log`).
"verified" is Tamarin's all-traces proof; "falsified - found trace" is an attack it constructed.

### Properties proved on the shipped models

| Lemma | Property | Result |
|---|---|---|
| `authorization` | every accepted action traces to a grant signed by the trust-anchor principal, unless that key is compromised | verified (223 steps) |
| `leaf_signature_authenticity` | accepted action was signed by the leaf holder (honest key) unless revealed | verified (495 steps) |
| `attenuation_root` | accepted verb is permitted by the root caveat issued by an uncompromised principal, whatever (compromised) delegates append | verified (29 steps) |
| `attenuation_hop` | accepted verb is permitted by the caveat of every honest delegator's hop on the chain | verified (224 steps) |
| `replay_freedom_nonce` | per (audience, root grant, leaf holder, nonce) at most one acceptance | verified (110 steps) |
| `replay_freedom_counter` | per (audience, root grant, leaf holder) a counter value is accepted at most once | verified (110 steps) |
| `audience_binding` | action is accepted only at the audience it was signed for | verified (5 steps) |
| `no_accept_after_expiry` | no acceptance after expiry | verified (9 steps), see caveat below |
| `stepup3_requires_principal` | t=3 acceptance needs a principal share bound to this message, signer set and t, unless the principal key is compromised | verified (60 steps) |
| `stepup3_requires_guardian` | same for the guardian | verified (45 steps) |
| `stepup2_compromised_agent_insufficient` | at t=2 a compromised agent alone is not enough: an honest guardian or principal share bound to this context exists | verified (63 steps) |
| `stepup2_one_compromised_key_insufficient` | at t=2 with any single compromised key, an honest share from another key exists | verified (53 steps) |
| `attestation_binding` | an accepted attestation was produced by an approved enclave of exactly that holder, grant, epoch and nonce, unless the hardware root is broken | verified (14 steps) |

Sanity (the models are not vacuous): `executable_root_grant` (10 steps), `executable_delegation_issued`
(6), `executable_delegated` (22), `executable_t3` (12), `executable_t2` (8), `executable_attestation`
(17) are all verified as exists-trace lemmas.

### Necessity of each check: attacks Tamarin finds when the check is removed

| Variant (`-D` flag) | Lemma | Result |
|---|---|---|
| `NO_GREF_CHECK` (drop `grant_ref_bound`) | `replay_freedom_nonce`, `replay_freedom_counter` | falsified - found trace (14 steps each) |
| `NO_ANCESTOR_CAV` (only the leaf hop's caveat is checked) | `attenuation_root`, `attenuation_hop` | falsified (14, 24 steps) |
| `NO_AUD_CHECK` | `audience_binding` | falsified (10 steps) |
| `NO_EXPIRY_CHECK` | `no_accept_after_expiry` | falsified (13 steps) |
| `NO_LEAF_SIG` | `leaf_signature_authenticity` | falsified (10 steps) |
| `UNBOUND_SHARE` (share not bound to role, signer set, t) | all four step-up lemmas | falsified (13, 13, 10, 10 steps) |
| `NO_DISTINCT` (duplicate shares counted) | all four step-up lemmas | falsified (8, 8, 7, 8 steps) |
| `NO_SET_DISTINCT` (one key under two roles) | `stepup2_one_compromised_key_insufficient` | falsified (14 steps); the other three still verify, because the lemmas only name the other roles |
| `NOBIND_HOLDER` / `NOBIND_GRANT` / `NOBIND_EPOCH` / `NOBIND_NONCE` (field left out of `report_data`) | `attestation_binding` | falsified (12 steps each): a relayed quote is accepted |

The `NO_GREF_CHECK` attack is the one described in `replay.ts`: a holder labels each action with a fresh
`grant_ref` and so reaches a fresh replay namespace under the same root grant.

### Lean 4 (`formal/pca-lean/`, `lake build` passes, no `sorry`)

| Theorem | Property |
|---|---|
| `Attenuation.within_root`, `chainMono_hops`, `eff_antitone_append` | effective authority only narrows along delegation chains of **any length** (append-only caveats) |
| `Replay.no_double_accept` | in every reachable state of the consume/tick/prune machine, a key accepted with retention `r` cannot be accepted again while the clock is `<= r` |
| `Replay.prune_preserves_live` | pruning expired entries never changes liveness at or after the clock |
| `Replay.creach_strict` | accepted counters of a stream are strictly increasing, hence pairwise distinct |
| `Verifier.*` (existing) | verifier pipeline soundness / fail-closed, `grant_ref_bound` semantics, same root implies same `grant_ref` |
| `TrustBudget.*` (existing) | trust-budget safety invariant |

Axioms reported by `#print axioms`: `propext` and `Quot.sound` only.

## Revision 2: what was added

### ProVerif (`formal/proverif/`, ProVerif 2.05) - independent symbolic confirmation

Ports of the three Tamarin models (`pca_actn.pv`, `pca_actn_expiry.pv`, `pca_threshold.pv`, `pca_attest.pv`)
with the same lemmas as queries (correspondences, injective agreement `replay_inj`), all attack variants
(generated by `gen.sh`), and sanity reachability queries. `AGREEMENT.md` compares every result with the Tamarin
result: **42 compared pairs, 42 agree, 0 disagree** (every Tamarin `verified` is ProVerif `is true`; every
`falsified` is `is false`; the executable lemmas are reachable). Extra variants not in Tamarin: `NO_TRUST_ANCHOR`
(`authorization` false), `NO_REPLAY_STORE` (`replay_inj` false).
Honest limits:
- ProVerif tables cannot express an atomic consume-once store. `TABLE_CHECK_INSERT` gives `replay_inj` false (a
  check/insert race); `TABLE_INSERT_FIRST` gives `cannot be proved`. The shipped ProVerif model therefore encodes the
  store as a `restriction` (like Tamarin v1). The Tamarin v2 linear-fact store (below) is the model where atomicity is
  a rewriting consequence.
- Delegation chains are bounded to depth 3 in ProVerif (an unbounded delegate made saturation diverge).
- During porting the first `NO_DISTINCT` result disagreed with Tamarin; the cause was a parenthesisation bug in the
  port (`if c then P | Q`), fixed; recorded in `formal/proverif/README.md`.

### CryptoVerif (`formal/proverif/cv/`, CryptoVerif 2.13) - computational proofs, automatically found

Proven by `auto` (UF-CMA signature + hash collision resistance, honest keys, no corruption):
- `pca_leaf_auth.cv`: leaf signature (Accept implies the honest agent Signed) up to
  `Psign(time_3,N,maxlength(game 11: act)) + Psigncoll + Psign(time_2,N,maxlength(game 4: cb))`; root grant
  (Accept implies Granted) up to `Psigncoll + Psign(time_2,...)`; `grant_ref` binds one root up to `Phash(time_1)`.
- `pca_chain2_auth.cv` (principal -> delegator -> holder, depth 2): Granted(root), Delegated(child), Signed(act), and
  `grant_ref` binding, each up to a sum of `Psign`, `Psigncoll`, `Phash` terms (exact text in `cv/results/`).
- Negative controls (hash check, leaf check or root-signature check removed) leave the corresponding query
  "Could not prove".
NOT proved computationally in that revision: replay (stateful store), unbounded chains, key compromise, expiry, threshold, attestation.
Since then: replay (`pca_replay.cv`), unbounded chains and key compromise (EasyCrypt C-1), threshold (EasyCrypt TH-1) and
attestation, receipts, epochs, intent deltas, zk receipts, PQ pins, the committed map (`formal/cryptoverif/`, section above). Expiry is not cryptographic.

### Tamarin v2 (`formal/tamarin/*_v2` models, results in `formal/tamarin/results/v2/`)

All runs on cloud boxes; "timeout" means NOT proved.

| Gap | Model | Verified | Falsified (attacks found) | NOT proved (timeout) |
|---|---|---|---|---|
| Unbounded chains | `pca_actn_unbounded.spthy` (Walk_Start/Walk_Step/Walk_Finish recursive facts, helper lemmas `walk_verb_invariant`, `accept_verb_invariant`, `walk_start_unique`, oracle `oracle_walk.sh`) | `authorization` (328 steps), `leaf_signature_authenticity` (186), `attenuation_root` (42), `attenuation_hop` (66), `chain_all_hops_permit` (62), `replay_freedom_nonce/counter` (2), `audience_binding` (11), `no_accept_after_expiry` (2); sanity incl. `executable_two_hops` | NO_GREF_CHECK (replay), NO_AUD_CHECK, NO_EXPIRY_CHECK, NO_LEAF_SIG | NO_ANCESTOR_CAV attack not demonstrated (the lemmas time out; the guided attack lemma `attack_ancestor_widening` reports "no trace found" on the shipped verifier, no collected -DNO_ANCESTOR_CAV trace); `executable_deep_chain`, `hop_issuance` |
| Store atomicity | `pca_store_race.spthy` | atomic nonce store: `replay_freedom_nonce` (8), atomic counter `replay_freedom_counter` (44) as consequences of linear-fact consumption | `STORE_RACE_NONCE` falsifies `replay_freedom_nonce` (14 steps) | `STORE_RACE_CTR` counter race not demonstrated (no result at 300 s) |
| Explicit clock | `pca_clock.spthy`, `pca_actn_time_store.spthy` | `executable_accept`, `executable_after_tick`; NO_EXPIRY_CHECK falsifies `no_accept_after_expiry` (8 steps) | NO_EXPIRY_CHECK | `no_accept_after_expiry` on the shipped clock model NOT proved (300 s and 1200 s); time_store variant also unproved except `authorization`, `attenuation_root`, `audience_binding`, `replay_freedom_nonce` |
| Budget | `pca_budget.spthy` (superseded by v4/v5, see "Budget and scope closure" below) | `alloc_monotone` (8) | none | v2 only: `root_bound`, `node_bound`, `spend_debits_root`. Now: `root_bound` (also ROOT3), `node_bound` (limits 1-3), `spend_debits_root`, `spent_root_is_root_node`, `no_negative_spend` verified on v4; all three attack variants found in Tamarin and TLC, refuted on the shipped model (below) |
| Scope/resource | `pca_scope_resource.spthy` | `scope_narrowing_all_hops` (1204), `resource_narrowing_all_hops` (1660), root/hop bounds (206/206/1586) | `NO_ANCESTOR_SCOPE` (18 steps, v3); `NO_ANCESTOR_RES` (pinned, 30 steps) + TLC (below) | - |
| FROST DKG | `pca_frost_dkg.spthy` | `dkg_key_not_adversarial` (1) | `NO_POP` (rogue key, 8 steps) | - |
| FROST signing | `pca_frost_sign.spthy` | `nonce_one_shot` (76), sanity | `NONCE_REUSE` falsifies `share_secrecy` (10), `nonce_one_shot` (11), `sig_needs_t_signers` (16); `NO_BINDING` falsifies `sig_needs_t_signers` (11) | `shares_bound_to_session`, and on the shipped model `share_secrecy`, `sig_needs_t_signers` |
| Software attestation / allowlist rollback | `pca_allowlist_rollback.spthy`, `pca_attest_allowlist.spthy` | `weights_allowlisted`, `operator_allowlisted`, sanity | `no_manifest_rollback`, `revoked_never_attested` falsified (16 steps) under `STATE_WIPE` and `STATE_WIPE+ANCHOR_REPLAY` | the shipped model and the ANCHORED fixes (so the anchor fix is NOT verified); `NO_VERSION_CHECK` attack |

Lean link (`formal/pca-lean/PcaProof/ChainLink.lean`, `lake build` ok, no `sorry`, axioms `propext` and, for
model-level theorems, `Quot.sound`; `results/v2/lean_chainlink_axioms.txt`): `walk_iff_eff` proves the recursive
hop-by-hop walk equals `Attenuation.Eff` (conjunction of all caveats along the chain), `walkH_iff_eff_flatten`
covers hops adding caveat lists, `tWalk_iff_eff` the verb-pin/any caveats, `walk_prefix` extra hops only narrow.
The Tamarin Walk rules mirror this recursion; the relation is identical definitions plus this equivalence, not
extraction.

### Budget and scope closure (2026-10-11: Tamarin v4/v5 + TLC, results in `formal/tamarin/results/v3/` and `formal/tla/results/budget*/`)

All runs on the cloud queue (2-vCPU spot boxes, heap cap 12g); job ids are recorded in each result file.

**node_bound is proved in Tamarin.** The earlier runs (12g, 24g, and 100g for 6h) did not run out of memory
because the property is hard. They ran out because of goal ordering. Solving a `!Lim(parent, .)` premise of
`Alloc_Child_D` unfolds the ancestor chain upward without bound, since every parent may itself be a child, and
`oracle_budget.sh` ranked `!Lim` second. A `Debit(...)` token premise unfolds the descendant chain downward in the same
way. node_bound needs neither: it closes on the node's own meter thread (finite because of the `!Dec` table) plus `Fr`
uniqueness. `oracle_nodebound.sh` solves tables, meters, the lemma's actions and `Fr` first, and tree-structure facts
and `Debit` tokens last. With it:

| Lemma | Model | Result | Result file |
|---|---|---|---|
| `node_bound` (allocation 'c1': at most one distinct debiting spend) + helpers `nb_alloc_unique` (6), `nb_debit_has_alloc` (119), `nb_c1_debit_from` (23, induction) | `pca_budget_v4.spthy`, shipped (no -D) | verified, 54 steps, 2 s | `v4_node_bound_N.txt` |
| `node_bound_ind` (same formula, `[use_induction]`) | v4, `-DNB_IND` | verified, 55 steps | `v4_nb_induction_N.txt` |
| `node_bound_focus` + `f_debit_is_fdebit` (28), `f_c1_debit_from` (47) | `pca_budget_v5_focus.spthy` | verified, 16 steps | `v5_focus_node_bound_N.txt` |
| `node_bound_focus_c2` (allocation 'c2': at most two distinct spends) | v5 | verified, 612 steps, 9 s | `v5_focus_c2_N.txt` |
| `executable_focus_bounded` (a focused child is debited by a spend that completes at the root; non-vacuity of the focus rules) | v5, wellformedness checks pass | verified (trace found), 15 steps | `v5_focus_exec_bounded_o.txt` |
| `root_bound` (root 'c2': at most 2 spends) | v4 | verified, 67480 steps (earlier run, `oracle_budget.sh`) | `v4_root_bound.txt` |

The v5 focus encoding generalises the `RCnt` trick that made `root_bound` terminate. One node, chosen
nondeterministically at allocation (`Alloc_Child_*_F`, action `Focus(n)`), has its meter as a separate fact symbol
`FCnt`, debited by `Debit_Mid_F`. The proof that a v5 result transfers to every v4 node is by simulation, written out in
the theory header: `Cnt(n, .)` is produced and consumed only by n's own allocation and debit instances, so renaming them
to the `_F` copies turns any v4 trace into a v5 trace with the same events plus `Focus(n)`. This renaming argument is on
paper, not machine-checked. It is not needed for `node_bound` itself, which is proved directly on the shipped v4
model; v5 adds the 'c2' generalisation. Limits stay concrete constants ('c1', 'c2'), because Tamarin has no arithmetic.
The statement for every limit is Lean `PcaMath.Budget.node_bound` (`formal/computational/leanmath/PcaMath/Budget.lean`,
checked in `formal/computational/CHECK-LOG.txt`) and the TLC `NodeBound` invariant below.

**The three bug witnesses are found by bounded model checking.** `formal/tla/BudgetTree.tla` and `ScopeChain.tla` are
rule-for-rule mirrors of `pca_budget_v4.spthy` and `pca_scope_resource.spthy`; the mapping is in each module header.
Each bug flag must FAIL with a counterexample, and the shipped model must PASS at the same bound. The counterexample
traces are committed in `formal/tla/results/budget/<case>.txt`. Run with
`CASES=cases-budget.txt OUT=results/budget formal/tla/run.sh` (TLC2 2026.10.06): 13 cases, 0 mismatches.

| Case | Invariant (Tamarin lemma) | Verdict | Counterexample (shortest, BFS) |
|---|---|---|---|
| shipped, bound B1 (root + 2 children in any tree shape, 3 spends, root limit 2, child limits 0..3) | RootBound, NodeBound, AllocMonotone, SpendDebitsRoot, NoNegative | pass (10,448 states) | - |
| `DEBIT_LEAF_ONLY`, B1 | RootBound (`root_bound`/`attack_overspend`) | **violated** | alloc n1 under r (limit 1); spend at n1 (only n1 debited); 2 spends at r: 3 spends against a limit-2 root |
| `DEBIT_LEAF_ONLY`, B1 | SpendDebitsRoot (`spend_debits_root`) | **violated** | one spend at a child completes without debiting the root |
| `DEBIT_LEAF_ONLY`, B1 | NodeBound | pass | per-node meters still hold; the bug is at the root |
| `NONATOMIC_DEBIT`, B1 | RootBound | **violated** | 3 spends at the root: s2 read 2 and wrote 1; s1 and s3 both read 1 and both wrote 0 (lost update): 3 completed spends |
| `NONATOMIC_DEBIT`, B1 | NodeBound | **violated** | same lost update on a node meter |
| `NO_PARENT_CHECK`, B1 | AllocMonotone | **violated** | child allocated more than its parent's limit |
| `NO_PARENT_CHECK`, B1 | RootBound, NodeBound, SpendDebitsRoot | pass | path debits still cap the root |
| shipped scope/resource, bound C1 (2 verbs, path atoms {a,b}, paths of length 2 or less, chains of 1..3 hops) | ResourceNarrowing, ScopeNarrowing, RootBoundsAction | pass (12,124 states) | - |
| `NO_ANCESTOR_RES`, C1 | ResourceNarrowing (`resource_narrowing_all_hops`/`attack_resource_escalation`) | **violated** | grant {read} on [a]; delegate {read} on [b]; accept read on [b] |
| `NO_ANCESTOR_RES`, C1 | RootBoundsAction (`root_resource_bounds_action`) | **violated** | same chain |
| `NO_ANCESTOR_RES`, C1 | ScopeNarrowing | pass | only the resource check was dropped |
| `NO_ANCESTOR_SCOPE`, C1 | ScopeNarrowing | **violated** | (agrees with the 18-step Tamarin attack) |

Larger shipped bound B2 (3 children, 4 spends, root limit 3 = Tamarin `-DROOT3`): all five budget invariants pass over
8,552,602 distinct states (`formal/tla/results/budget-b2/`). Tamarin also finds the `DEBIT_LEAF_ONLY` witness itself
once `oracle_nodebound.sh` is used: `attack_leafonly_bounded` verified (an exists-trace lemma, so a trace was found),
18 steps, 11 s (`v4_LEAFONLY_bounded_N.txt`).

Scope of the TLC results: these are bounded checks. A failing case is a real counterexample, valid at every bound.
A passing case is exhaustive only up to the stated bound. The unbounded claims are the Tamarin lemmas (`root_bound`,
`node_bound`, scope/resource narrowing) and Lean `Budget.lean`. ScopeChain explores one chain per state. Two chains
never interact in the symbolic model (perfect signatures, and delegators sign any caveat they are handed), so this
covers every accepted (chain, action) pair up to the bound.

**Round 2: the same goal-ordering fix, applied to the root lemmas** (`oracle_root.sh`: root meter `RCnt` and the
root's identity `!IsRoot` first, tree structure and `Debit` tokens last). A new helper, `nb_debit_from_unique`
(`[reuse, use_induction]`: a meter is debited from a given value at most once, because the countdown is one linear
thread and `!Dec` is injective), turns every concrete bound into a pigeonhole. All of the following are on
`pca_budget_v4.spthy`, shipped model, files `results/v3/r2_*.txt`:

| Lemma | Result |
|---|---|
| `root_bound` (limit 'c2'), with `nb_debit_from_unique` (543) | verified, 108 steps, 5 s |
| `root_bound` under `-DROOT3` (limit 'c3': at most 3 spends), with `nb_debit_from_unique` (2449) | verified, 50 steps, 32 s |
| `node_bound_c2` / `node_bound_c3` (a node allocated 2 / 3 units is debited by at most 2 / 3 distinct spends) | verified, 158 / 242 steps |
| `spend_debits_root` | verified, 2 steps |
| `spent_root_is_root_node` | verified, 8 steps |
| `no_negative_spend` | verified, 4 steps |

With `node_bound` (limit 'c1'), `node_bound_c2` and `node_bound_c3` proved directly on v4, every per-node bound up to
the largest limit in the model is a v4 theorem, and no claim depends on the v5 focus transfer any more. That transfer
is now also machine-checked anyway: `formal/pca-lean/PcaProof/BudgetFocus.lean` (core Lean 4.34.1, axioms
`Quot.sound`/`propext` only, `formal/pca-lean/budgetfocus-check.txt`). For any multiset-rewriting system,
`simulation` / `simulation_from_empty` prove that if every v4 rule instance, renamed by the involution swapping
`Cnt(n, .)` with `FCnt(n, .)`, is a v5 rule instance with the same labels up to the focus-only ones, then every v4 run
is replayed step by step by a v5 run from the same (empty) initial state. The per-instance hypothesis is read off the
two theories (the `_F` rules are the v4 rules with `Cnt` renamed), as with `ChainLink.lean`; that reading is the only
part that is not mechanised.

**Round 3: witnesses and shipped-model controls, all closed** (files `results/v3/r3_*.txt`; every run passes
the wellformedness checks).

| Lemma | Model | Result |
|---|---|---|
| `attack_lostupdate_pinned` (the TLC lost-update interleaving, every read/write value and the order fixed, root-only debits) | v4 `-DNONATOMIC_DEBIT` | **trace found** (exists-trace verified), 34 steps, 2 s |
| `attack_resource_pinned` (grant {read} on [a], delegation {read} on [b], accept read on [b]) | `pca_scope_resource.spthy -DNO_ANCESTOR_RES`, `oracle_walk.sh` | **trace found**, 30 steps, 66 s |
| `attack_resource_pinned`, the same pin | scope/resource, shipped verifier | no trace found, 16 steps |
| `attack_leafonly_bounded`, `attack_lostupdate_bounded` | v4 shipped, with `root_bound [reuse]` | no trace found (108 / 81 steps) |
| `attack_leafonly_witness`, `attack_lostupdate_witness`, `attack_overspend` | v4 shipped, with `root_bound [reuse]` | no trace found (108 steps each) |
| `attack_overspend` (4 spends under a limit-3 root) | v4 shipped `-DROOT3`, with `root_bound [reuse]` | no trace found, 50 steps |

So all three bug demonstrations are now Tamarin traces of the unbounded model: DEBIT_LEAF_ONLY (`attack_leafonly_bounded`,
round 1), NONATOMIC_DEBIT and NO_ANCESTOR_RES (pinned, above). The shipped models refute the same attack lemmas.
TLC remains the independent bounded cross-check. Two edits made the pinned lost-update witness terminate. First,
value-carrying labels `DebitReadV`/`DebitWriteV` on the non-atomic root rules (labels only; no transition changes).
Second, two pruning conjuncts: root-only debits and reads. Without them Tamarin's DFS descended into
`Debit_Write_Mid`, whose `Cnt(child, cany)` value is unconstrained, and an earlier attempt ran past 9 min with no
verdict. Pruning conjuncts only restrict which traces count; any trace found is a real trace of the model.

Infrastructure note: cloud-box-9 has no Tamarin environment (`~/pcaenv.sh` missing). Round-2 jobs that landed there errored
at once. Round 3 guarded every job with `test -f ~/pcaenv.sh || exit 3`; cloud-box-9 was not modified.

### Model-to-code conformance (`tools/pca-formal/`)

An independent executable reference model (`conformance/model.ts`, no import from `packages/`, symbolic keys and
hashes) written only from the Tamarin/Lean models is run against the REAL `verifyPCActn`, `guardPCActnReplay` +
`InMemoryReplayStore`, `verifyThreshold` and `verifyAttestation` on generated scenarios; the check requires equal
accept/reject AND equal set of failing checks. Attack variants are scenarios (dropped/forged `grant_ref`, wrong or
missing audience, expiry edges, replay, widened/dropped caveats, spliced/relayed/forged hops, forged root, unplanned
action, unbound shares, relayed evidence).

Cloud-box run (shards on gcp and cloud-box-3; cloud-box-1 was still running when this was written, cloud-box-2 shards never started;
raw per-shard JSON and aggregation in `tools/pca-formal/results/conformance/`, `conformance-summary.json`):
**2,003,249 scenarios, 0 disagreements.**

| Stage | Scenarios | Disagreements |
|---|---|---|
| single-exh0 (all benign bases: 4 root envelopes x <=3 hops x pins x holders x verbs) | 35,504 (18 shards, incl. cloud-box-1) | 0 |
| single-exh1 (every benign base x every single mutation, exhaustive) | 828,390 | 0 |
| single-rand (random, 0..4 mutations) | 590,910 | 0 |
| seq-exh2 + seq-rand (sequences through verify then replay guard; nonce/counter/retention timing) | 5,350 + 45,460 | 0 |
| thr-exh + thr-rand (signer-set shapes, t in 0..4, bound/unbound shares, baseline) | 196,416 + 286,371 | 0 |
| att-exh (+ report_data injectivity over 375 tuples, 0 collisions) | 14,848 | 0 |

Also run on the Mac before the boxes: deep chains (4..18 hops, 1500 scenarios, 0 disagreements).
Harness power: 19 deliberately broken model mutants (`results/mutants.txt`): 18 killed; `noAnchor` survived (the
scenario space only produces a wrong root issuer together with a root that already differs from the verifier's
stored grant, which a separate check rejects, so it is probably an equivalent mutant in this space; not proven).
13 deliberate bugs injected into a COPY of the real code (`results/code-mutants.txt`): 12 killed; the
"dropped ancestor caveats accepted" mutation survived (cause not analysed: the same hop is also caught by the
prefix-equality comparison in these scenarios, so it is likely redundant detection, unconfirmed).
Lean cross-check (`lean-xcheck/`, results in `results/lean-xcheck.txt`): executable Lean definitions with proved
links (`satB_iff`, `effB_iff`, `liveB_iff`, `consume_sound`, `adv_sound`, ...) emit 58,945 table rows; TypeScript
agrees on all: 4,680 attenuation tables (each real chain also passes `verifyChain`), 54,241 replay op-sequences,
24 `grant_ref_bound` rows.

**Code bugs found: none.** One model/code difference had to be encoded in the reference model as a documented
pre-stage: an empty `grant_ref` (or empty chain with a root-derived ref) is rejected by the terminal `wire` stage in
the code before any check; Lean's `grantRefBound_empty_*_fails` gives the same verdict (deny), so verdicts agree.

## Gaps and assumptions (read these)

- **Computational soundness.** The symbolic models (Tamarin, ProVerif) assume perfect cryptography. The computational
  results are: CryptoVerif (`formal/proverif/cv/`: leaf/root authorization, depth-2 delegation, `grant_ref`, replay;
  `formal/cryptoverif/`: intent deltas, receipts, epochs, attestation, zk receipts, PQ pins, FR-5, ABE-3) and EasyCrypt
  (C-1 for chains of any length with key corruption, TH-1, hybrids). They reduce to UF-CMA / collision resistance /
  NA-ZKVM / HW-ATT; nothing proves Ed25519, ML-DSA, SLH-DSA or SEV-SNP themselves. FROST rests on NA-FROST. GG-2 is
  checked in Lean (any depth).
- **Conformance is testing, not proof.** Millions of agreeing scenarios over a bounded configuration space
  (3 verbs, <=3 hops, 3 holders, few nonces/counters); the injected-bug experiments show the harness can detect the
  classes of bug in the mutation menu, nothing more. Memory safety, side channels, parsing of arbitrary bytes and the
  unmodelled checks (plan, taint, freshness, revocation, zk, bond, hooks) are not covered.
- **Unproved Tamarin items (timeouts are not proofs):** see the NOT-proved column above: shipped-model clock expiry
  as a rewriting consequence, counter store race attack, (budget invariants and the budget/scope attack witnesses: now closed, see "Budget and scope closure"), FROST `shares_bound_to_session` and
  `sig_needs_t_signers` on the shipped model, allowlist rollback on the shipped model and the anchor fix, NO_ANCESTOR_CAV
  attack on the unbounded model. For these the earlier bounded v1 results (depth 1-3) and Lean still stand; no new
  claim is made.
- **ProVerif replay** uses a restriction (ProVerif cannot model the atomic store); atomicity as a consequence of the
  semantics is only shown in Tamarin (nonce store, `pca_store_race.spthy`) and Lean.
- **Expiry in the v1 models is still an ordering restriction**; v2 `pca_clock.spthy` has the explicit clock but its
  main lemma was not proved in the time given.
- **Distributed or crashing stores are out of scope.** A store that loses state or is not shared between
  verifier instances violates the contract (the `STATE_WIPE` rollback attacks are the allowlist analogue).
- **Prompt-injection / semantic attacks** are outside any symbolic model.
- Tamarin v1 lemmas were run one at a time with fixed heuristics (`run_all.sh`).

## Reproduce

```sh
# Tamarin (macOS): brew tap tamarin-prover/tap && brew trust tamarin-prover/tap
#   brew install tamarin-prover/tap/maude && brew install --ignore-dependencies tamarin-prover/tap/tamarin-prover
#   (graphviz is only needed for the GUI/graph output and was not installed)
cd formal/tamarin
./run_all.sh 600          # sequential, nice'd; rewrites results/*.txt (about 45 min on one core)
./run_lemma.sh 300 pca_actn.spthy authorization --heuristic=s            # one lemma
./run_lemma.sh 300 pca_actn.spthy replay_freedom_nonce --heuristic=s -DNO_GREF_CHECK   # one attack

# Lean
cd formal/pca-lean && lake build

# Tamarin v2 (boxes only; see formal/tamarin/README-v2.md)
formal/tamarin/run_all_v2.sh
# ProVerif / CryptoVerif (box cloud-box-1 style)
source ~/pcaenv.sh && cd formal/proverif && ./run_all.sh 4 1800 && python3 agreement.py && (cd cv && ./run_cv.sh)
# Conformance: build the toolchain once, then shard across boxes
tools/pca-formal/box-setup.sh tamarin opam lean
verify/run-conformance.sh full 0 22   # one shard of 22; run each shard on its own machine
python3 tools/pca-formal/summarize.py tools/pca-formal/results/conformance
tools/pca-formal/mutants.sh; python3 tools/pca-formal/code-mutants.py
cd tools/pca-formal/lean-xcheck && lake exe xcheck | grep -E '^(EFF|REPLAY|GREF)' > lean.txt && tsx compare.ts lean.txt
```

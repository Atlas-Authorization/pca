---
title: Traceability
order: 33
---

# Traceability matrix (for auditors)

**Audience: security auditors and reviewers.** This page is deliberately different from the rest of the security documentation. It names test files in the repository so an auditor can run the exact check that exercises each claim. Integrators do not need it; start with the [Threat model](./threat-model.md).

## How to read this

- Every attack `T-xxx` in the [Threat model](./threat-model.md) and every guarantee `G-xx` appears here.
- Each row maps one ID to one automated test: the test file and a substring of the test's name. A single ID usually has several rows.
- A row reading `NO AUTOMATED TEST` means we found no test that exercises the mitigation. Those IDs are listed under **Gaps** with the reason. We would rather show a gap than imply coverage.
- The mapping was built by reading the test files. It is machine-checked by `scripts/check-pca-traceability.mjs`, which fails if a referenced file is missing, a referenced test-name substring does not appear in that file, or a threat-model ID is absent here. The checker confirms the test **exists**, not that it passes; run the test suites for that.
- A test appearing against an ID shows the named behaviour is tested. It does not prove the residual risk stated in the threat model is zero.
- Status: no external audit has been performed on the cryptography or the code. These tests are the project's own.

## Attack coverage (T-IDs)

| ID | Test file | Test name (substring) |
|---|---|---|
| T-001 | packages/pca/src/adversarial.test.ts | an EXPIRED PCActn |
| T-001 | packages/pca/src/adversarial.test.ts | a NEGATIVE counter is rejected |
| T-001 | packages/pca/src/server/require-pca.test.ts | replay is denied with a store; budget drains |
| T-001 | packages/pca/src/pcactn.test.ts | freshness binding: audience mismatch, expiry, future iat |
| T-002 | packages/pca/src/adversarial.test.ts | an audience MISMATCH is rejected |
| T-002 | packages/pca/src/adversarial.test.ts | FAIL-CLOSED: a verifier that forgets its audience |
| T-002 | packages/pca/src/server/require-pca.test.ts | audience is REQUIRED |
| T-003 | packages/pca/src/adversarial.test.ts | reusing a valid inclusion proof for a SWAPPED action |
| T-003 | packages/pca/src/adversarial.test.ts | at the full verifier: a tampered action breaks plan_inclusion |
| T-003 | packages/pca/src/adversarial.test.ts | a verified claim cannot be reused |
| T-003 | packages/pca/src/zk.test.ts | REPLAY DENIED |
| T-004 | packages/pca/src/adversarial.test.ts | a child that DROPS a parent caveat is rejected |
| T-004 | packages/pca/src/adversarial.test.ts | a child that ALTERS a parent caveat is rejected |
| T-004 | packages/pca/src/adversarial.test.ts | a hop issued by a key that is NOT the parent holder |
| T-004 | packages/pca/src/adversarial.test.ts | BUDGET widening |
| T-004 | packages/pca/src/adversarial.test.ts | a FORGED hop body |
| T-004 | packages/pca/src/capability.test.ts | REORDERED caveats rejected |
| T-004 | packages/pca/src/capability.test.ts | broken parent link rejected |
| T-004 | packages/pca/src/capability.test.ts | rejects chains deeper than MAX_CHAIN_DEPTH |
| T-005 | packages/pca/src/risk.test.ts | sub-budget cannot exceed parent |
| T-005 | packages/pca/src/risk.test.ts | debitConsolidatedPath |
| T-005 | packages/pca/src/capability.test.ts | verifyChain accepts a child allocating |
| T-005 | packages/pca/src/predicates.test.ts | max_blast_radius / reversibility_max / delegation_depth |
| T-006 | packages/pca/src/pcactn.test.ts | out-of-plan action fails even when freshly signed |
| T-006 | packages/pca/src/adversarial.test.ts | a proof whose index/size shape does not match is rejected |
| T-006 | packages/pca/src/prohibitions.test.ts | prohibitions are independent of the plan |
| T-006 | packages/pca/src/prohibitions.test.ts | an in-plan, policy-permitted action is REFUSED by a prohibition |
| T-007 | packages/pca/src/risk.test.ts | SAFETY INVARIANT |
| T-007 | packages/pca/src/risk.test.ts | fully-compromised agent hammering free actions halts at the bound without a human |
| T-007 | packages/pca/src/risk.test.ts | depletion forces step-up even for low r |
| T-007 | packages/pca/src/budget-forecast.test.ts | sizes bMax so N autonomous actions fit under the safety bound |
| T-008 | packages/pca/src/threat-model-gaps.test.ts | 50 concurrent requests carrying the SAME PCActn: exactly one is accepted |
| T-008 | packages/pca/src/threat-model-gaps.test.ts | two independent guard instances over ONE store also admit exactly one |
| T-008 | packages/pca/src/threat-model-gaps.test.ts | parallel spends never exceed the budget and no debit is lost |
| T-008 | packages/pca/src/threat-model-gaps.test.ts | a multi-node store supplies withKeyLock |
| T-009 | packages/pca/src/adversarial.test.ts | at the full verifier: a tampered action breaks plan_inclusion |
| T-009 | packages/pca/src/revocation.test.ts | REPLAYED PRE-REVOCATION ROOT |
| T-009 | packages/pca/src/adversarial.test.ts | a pre-revocation PCActn (freshness.epoch < revocation epoch) is rejected |
| T-010 | packages/pca/src/adversarial.test.ts | NON-CANONICAL S (S + L) is rejected |
| T-010 | packages/pca/src/adversarial.test.ts | a SMALL-ORDER public key is rejected |
| T-010 | packages/pca/src/adversarial.test.ts | a non-canonical base64url signature/key is rejected |
| T-010 | packages/pca/src/adversarial.test.ts | a small-order / identity commitment point is rejected by decodeSafePoint |
| T-010 | packages/pca/src/frost.test.ts | rejects small-order and non-torsion-free commitment points |
| T-011 | packages/pca/src/adversarial.test.ts | stripping the signed `alg`/`pq_pk` from an ml-dsa-65 PCActn fails closed |
| T-011 | packages/pca/src/adversarial.test.ts | an UNKNOWN signature alg fails closed on the wire |
| T-011 | packages/pca/src/pq.test.ts | valid Ed25519 but INVALID ML-DSA => fail (both required) |
| T-011 | packages/pca/src/pq.test.ts | DROPPING the ML-DSA component => wire fail |
| T-011 | packages/pca/src/pq-surfaces.test.ts | (d) unknown suite + downgrade are fail-closed |
| T-011 | packages/pca/src/pq-surfaces.test.ts | (d) unknown suite + downgrade of a hybrid share are fail-closed |
| T-012 | packages/pca/src/adversarial.test.ts | a t=2 verifier REJECTS a t=1 (agent-only) signature |
| T-012 | packages/pca/src/adversarial.test.ts | one key cannot fill two role slots |
| T-012 | packages/pca/src/threshold.test.ts | role-binding: a guardian share cannot be replayed as a principal share |
| T-012 | packages/pca/src/threshold.test.ts | counts distinct KEYS |
| T-012 | packages/pca/src/threshold.test.ts | a duplicate role does not double-count |
| T-013 | packages/pca/src/pcactn.test.ts | wrong-key body signature fails |
| T-013 | packages/pca/src/capability.test.ts | hop signed by the wrong key is rejected |
| T-013 | packages/pca/src/threshold.test.ts | t=2: fails with the agent leaf alone, passes once a guardian share is added |
| T-013 | packages/pca/src/attestation.test.ts | relay: a genuine signed quote bound to a different holder |
| T-014 | packages/pca/src/adversarial.test.ts | a tampered signed number that cannot encode canonically is rejected on the wire |
| T-014 | packages/pca/src/pcactn.test.ts | tampered action breaks plan inclusion (and signature) |
| T-014 | packages/pca/src/adversarial.test.ts | an UNKNOWN top-level field is a wire failure |
| T-015 | packages/pca/src/threat-model-gaps.test.ts | the wire form is plaintext |
| T-015 | packages/pca/src/threat-model-gaps.test.ts | commitment-only plan privacy |
| T-015 | packages/pca/src/threat-model-gaps.test.ts | a captured PCActn is inert |
| T-016 | packages/pca/src/adversarial.test.ts | a SUB-THRESHOLD (1-of-2) aggregate is refused |
| T-016 | packages/pca/src/frost.test.ts | a 1-of-2 (insufficient) aggregate does NOT verify |
| T-016 | packages/pca/src/frost-dkg.test.ts | an insufficient (1-of-2) quorum does NOT verify under a (2,n) DKG group key |
| T-016 | packages/pca/src/pq-threshold.test.ts | exactly t passes, more than t passes, t-1 fails |
| T-016 | packages/pca/src/pq-threshold.test.ts | k cannot be stripped: it is part of the set id |
| T-016 | packages/pca/src/pq-threshold.test.ts | lattice-only quorum fails when k=1 committed |
| T-016 | packages/pca/src/frost.test.ts | an INSUFFICIENT quorum (< t) cannot produce a valid cosign |
| T-017 | packages/pca/src/adversarial.test.ts | a FORGED signature share is caught and the bad participant named |
| T-017 | packages/pca/src/adversarial.test.ts | an EQUIVOCATING dealer makes dkgFinalize ABORT |
| T-017 | packages/pca/src/adversarial.test.ts | a CHEATING dealer is disqualified |
| T-017 | packages/pca/src/frost-dkg.test.ts | a secret share from one session cannot be replayed into another |
| T-017 | packages/pca/src/frost-dkg.test.ts | a FALSE complaint against an honest party is NOT justified |
| T-017 | packages/pca/src/frost.test.ts | rejects a share that does not match its verification share |
| T-018 | packages/pca/src/risk.test.ts | SAFETY INVARIANT |
| T-018 | packages/pca/src/risk.test.ts | depletion forces step-up even for low r |
| T-018 | packages/pca/src/approval-channels.test.ts | formats a well-formed Block Kit message carrying the action summary |
| T-019 | packages/pca/src/threat-model-gaps.test.ts | with the principal key an attacker mints a grant |
| T-019 | packages/pca/src/threat-model-gaps.test.ts | mitigation: a resource server that only resolves grants IT enrolled |
| T-019 | packages/pca/src/threat-model-gaps.test.ts | rotation: dropping the compromised grant |
| T-019 | packages/pca/src/threat-model-gaps.test.ts | detection: what the compromised key signed is attributable |
| T-020 | packages/pca/src/adversarial.test.ts | a document whose nonce does NOT bind this PCActn is rejected |
| T-020 | packages/pca/src/attestation.test.ts | relay: a genuine signed quote bound to a different holder |
| T-020 | packages/pca/src/attestation.test.ts | fails closed when the server supplies no expected binding |
| T-020 | packages/pca/src/attestation.test.ts | a stale server nonce is rejected |
| T-020 | packages/pca/src/attest-multiroot.test.ts | a root bound to a DIFFERENT action |
| T-020 | packages/pca/src/attest-amd-snp.test.ts | fails closed: relayed binding |
| T-020 | packages/pca/src/attest-puf.test.ts | RELAY: a statement bound to another action is denied |
| T-020 | packages/pca/src/attest-nvidia-spdm.test.ts | fails closed: a different holder / grant / epoch / nonce (relayed report) |
| T-020 | packages/pca/src/attest-intel-dcap.test.ts | fails closed: relayed binding (any of holder / grant / epoch / nonce) |
| T-021 | packages/pca/src/attest-amd-snp.test.ts | the family pin matters: this Genoa chain is rejected under the Milan or Turin roots |
| T-021 | packages/pca/src/hardware-sevsnp.test.ts | rejects the chain when the ARK pin is wrong |
| T-021 | packages/pca/src/hardware-sevsnp-chain.test.ts | CA roles: a non-CA ASK is rejected |
| T-021 | packages/pca/src/hardware-sevsnp-chain.test.ts | CA roles: a VCEK asserting CA:TRUE is rejected |
| T-021 | packages/pca/src/hardware-sevsnp-chain.test.ts | order/count: [ARK, ASK] is rejected as out of order |
| T-021 | packages/pca/src/hardware-sevsnp-chain.test.ts | each real chain is rejected under every OTHER family pin |
| T-021 | packages/pca/src/attest-nvidia-spdm.test.ts | pinned measurement mismatch / missing block / wrong pin / wrong GPU family |
| T-021 | packages/pca/src/attest-intel-tdx.test.ts | rejects the chain under a WRONG pinned Root CA |
| T-022 | packages/pca/src/adversarial.test.ts | a DEBUG-enabled report is rejected by the measurement policy |
| T-022 | packages/pca/src/hardware-sevsnp.test.ts | DEBUG policy bit is rejected unless explicitly opted in |
| T-022 | packages/pca/src/attest-azure-maa.test.ts | debuggable SEV-SNP guest denied unless allowDebug |
| T-022 | packages/pca/src/attest-azure-maa.test.ts | REJECTS a debug TD |
| T-022 | packages/pca/src/attest-gcp-confidential-space.test.ts | debug-mode (dbgstat enabled) denied unless allowDebug |
| T-023 | packages/pca/src/hardware-sevsnp.test.ts | TCB downgrade: an old VCEK |
| T-023 | packages/pca/src/hardware-sevsnp-chain.test.ts | a duplicated SPL extension is rejected |
| T-023 | packages/pca/src/hardware-sevsnp-chain.test.ts | malformed SPL encodings are rejected with the specific reason |
| T-023 | packages/pca/src/hardware-sevsnp-chain.test.ts | the real VCEK window is enforced to the millisecond |
| T-023 | packages/pca/src/attest-intel-collateral.test.ts | rejects expired collateral |
| T-023 | packages/pca/src/attest-intel-collateral.test.ts | minTcbEvaluationDataNumber above the collateral rejects |
| T-023 | packages/pca/src/attest-azure-maa.test.ts | gates attester_tcb_status |
| T-023 | packages/pca/src/attest-nvidia-rim.test.ts | rejects below the floor, on the deny list |
| T-023 | packages/pca/src/attest-nvidia-ocsp.test.ts | rejects a stale response (past nextUpdate) |
| T-023 | packages/pca/src/attest-intel-dcap.test.ts | fails closed on bad collateral: tampered TCB info, stale clock |
| T-024 | packages/pca/src/attest-intel-collateral.test.ts | REVOKED serial: a CRL signed by the issuer key lists the leaf serial |
| T-024 | packages/pca/src/attest-intel-collateral.test.ts | expired PCK CRL is rejected |
| T-024 | packages/pca/src/attest-nvidia-rim.test.ts | SYNTHETIC chain: a CRL that lists the leaf serial is rejected |
| T-024 | packages/pca/src/attest-nvidia-rim.test.ts | fails closed: no CRLs, a corrupted CRL, a stale clock |
| T-024 | packages/pca/src/attest-nvidia-ocsp.test.ts | REVOKED is reported with time and reason |
| T-024 | packages/pca/src/attest-nvidia-ocsp.test.ts | nonce: mismatch and absence are rejected when a nonce is expected |
| T-025 | packages/pca/src/hardware-sevsnp.test.ts | a measured weights digest NOT in the allowlist fails |
| T-025 | packages/pca/src/hardware-sevsnp.test.ts | host-asserted weights cannot satisfy require_measured_weights |
| T-025 | packages/pca/src/hardware-sevsnp.test.ts | SEV-SNP has no native weights field: the default identity is never weights_measured |
| T-025 | packages/pca/src/attestation.test.ts | weights not in weights_allowlist |
| T-025 | packages/pca/src/attest-allowlist.test.ts | drops entries past their own notAfter |
| T-025 | packages/pca/src/attest-allowlist.test.ts | a revoked entry is removed from every projection |
| T-026 | packages/pca/src/attest-allowlist.test.ts | rejects rollback to an older version |
| T-026 | packages/pca/src/attest-allowlist.test.ts | rejects expired, not-yet-valid, and over-long manifests |
| T-026 | packages/pca/src/attest-allowlist.test.ts | rejects tampering anywhere in the body |
| T-026 | packages/pca/src/attest-allowlist.test.ts | rejects unknown issuer, wrong issuer key, alg downgrade |
| T-026 | packages/pca/src/attest-allowlist.test.ts | a duplicate smuggled into a SIGNED manifest is still rejected |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | refuses trust-on-first-use by default |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | total replacement without overlap is rejected |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | total replacement is accepted when an operator-signed re-pin approves |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | enforces maxNewKeysPerFetch |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | a signed revocation strips a key the JWKS still serves |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | stale never resurrects an expired key |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | a policy violation never falls back to stale data |
| T-027 | packages/pca/src/attest-maa-keys.test.ts | clock regression fails closed |
| T-028 | packages/pca/src/attest-multiroot.test.ts | DENIES when two roots DISAGREE on the measured identity |
| T-028 | packages/pca/src/attest-multiroot.test.ts | DENIES when a REQUIRED root is missing |
| T-028 | packages/pca/src/attest-multiroot.test.ts | DENIES below threshold |
| T-028 | packages/pca/src/attest-amd-snp.test.ts | breaking either root drops below threshold |
| T-028 | packages/pca/src/attest-multiroot.test.ts | a required root that fails denies the whole attestation through the hook |
| T-028 | packages/pca/src/attest-forged-root.test.ts | 2-of-2: the forged quote claims the allowlisted image |
| T-028 | packages/pca/src/attest-forged-root.test.ts | both roots verify but disagree on the measured identity |
| T-028 | packages/pca/src/attest-forged-root.test.ts | RESIDUAL RISK, pinned |
| T-029 | packages/pca/src/hardware-sevsnp.test.ts | REJECTS a 1-bit-tampered genuine report |
| T-029 | packages/pca/src/hardware-sevsnp.test.ts | CHIP_ID: a VCEK for a different chip cannot vouch for this report |
| T-029 | packages/pca/src/hardware-sevsnp.test.ts | HOST_DATA is host-asserted: not mapped to weights by default |
| T-029 | packages/pca/src/attest-intel-tdx.test.ts | TAMPER: flipping a TD-report byte breaks the TD quote signature |
| T-030 | packages/pca/src/attest-amd-snp.test.ts | refuses accept-all / unknown family / unknown binding at construction |
| T-030 | packages/pca/src/attest-azure-maa.test.ts | rejects missing trust anchors (accept-all) |
| T-030 | packages/pca/src/attest-azure-maa.test.ts | rejects an empty measurement policy (accept-all) |
| T-030 | packages/pca/src/attest-gcp-confidential-space.test.ts | rejects an empty image-digest allowlist (accept-all) |
| T-030 | packages/pca/src/attest-nvidia-spdm.test.ts | refuses accept-all construction |
| T-030 | packages/pca/src/attest-nvidia-rim.test.ts | refuses accept-all: empty pinned measurements AND no collateral hook |
| T-031 | packages/pca/src/attest-pq-software.test.ts | an untrusted PQ attestor key is denied |
| T-031 | packages/pca/src/attest-pq-software.test.ts | REJECTS a classical-only (ed25519) statement when PQ is required |
| T-031 | packages/pca/src/attest-pq-software.test.ts | a pure ML-DSA statement is denied when a hybrid is required |
| T-031 | packages/pca/src/attest-puf.test.ts | DENIES a statement from a CLONED/other device |
| T-031 | packages/pca/src/attest-puf.test.ts | DENIES a classical PUF key when requirePq is set |
| T-031 | packages/pca/src/attestation.test.ts | attestor key not trusted fails |
| T-032 | packages/pca/src/adversarial.test.ts | under-reporting caution gains the agent NOTHING |
| T-032 | packages/pca/src/adversarial.test.ts | a FORGED / mis-bound signed caution degrades to serverRisk |
| T-032 | packages/pca/src/taint.test.ts | an agent CLAIMING trusted refs NOT in the registry cannot forge low taint |
| T-032 | packages/pca/src/taint.test.ts | is MONOTONE: adding a ref can only raise taint, never lower it |
| T-032 | packages/pca/src/taint.test.ts | malformed / absent provenance fails closed to 1 |
| T-032 | packages/pca/src/pcactn.test.ts | gated ON: an agent CANNOT forge low taint |
| T-032 | packages/pca/src/pcactn.test.ts | gated OFF by default: taint_gate stays not-enforced |
| T-033 | packages/pca/src/agent-native.test.ts | under-report gains nothing; over-report escalates |
| T-033 | packages/pca/src/objective-risk.hardening.test.ts | a PARAM-STUFFED action cannot dilute/inflate |
| T-033 | packages/pca/src/adversarial.test.ts | the dispute game SLASHES an agent that understated a numeric risk input |
| T-033 | packages/pca/src/adversarial.test.ts | the dispute game SLASHES an agent that declared a catalog-irreversible verb as reversible |
| T-033 | packages/pca/src/optimistic.test.ts | is the ORACLE, not the challengers say-so, that decides |
| T-034 | packages/pca/src/dlp.test.ts | allows clean flows to a sensitive sink, steps up tainted ones |
| T-034 | packages/pca/src/dlp.test.ts | hard-denies above the class ceiling |
| T-034 | packages/pca/src/security-audit.test.ts | dlp: a non-finite taint FAILS CLOSED |
| T-034 | packages/pca/src/agent-native.test.ts | rejects nested extra properties |
| T-034 | packages/pca/src/prohibitions.test.ts | daily spend cap triggers across a sequence and the window rolls |
| T-035 | packages/pca/src/adversarial.test.ts | a statement mis-bound to a DIFFERENT action is rejected |
| T-035 | packages/pca/src/zk.test.ts | REPLAY DENIED |
| T-035 | packages/pca/src/adversarial.test.ts | an audience MISMATCH is rejected |
| T-035 | packages/pca/src/security-audit.test.ts | receipt chain detects a tampered body |
| T-036 | packages/pca/src/adversarial.test.ts | a SUB-QUORUM (k not met) is rejected |
| T-036 | packages/pca/src/adversarial.test.ts | an UNKNOWN judge key does not count toward the quorum |
| T-036 | packages/pca/src/adversarial.test.ts | a MIS-BOUND verdict (wrong actionDigest) does not count |
| T-036 | packages/pca/src/adversarial.test.ts | a TAMPERED score breaks the verdict signature |
| T-036 | packages/pca/src/adversarial.test.ts | the CONFORMAL gate denies when agreement is below the calibrated cutoff |
| T-037 | packages/pca/src/adversarial.test.ts | a statement from an UNTRUSTED prover is rejected |
| T-037 | packages/pca/src/adversarial.test.ts | a TAMPERED field (r) breaks the statement signature |
| T-037 | packages/pca/src/adversarial.test.ts | an EXPIRED statement is rejected |
| T-037 | packages/pca/src/adversarial.test.ts | the Groth16 backend rejects a malformed / mis-bound / non-allow proof |
| T-037 | packages/pca/src/pcactn.test.ts | present zk_compliance + NO hook => FAIL CLOSED |
| T-038 | packages/pca-mpc/src/malicious.test.ts | DEVIATION 1 |
| T-038 | packages/pca-mpc/src/malicious.test.ts | DEVIATION 2 |
| T-038 | packages/pca-mpc/src/malicious.test.ts | DEVIATION 3 |
| T-039 | packages/pca/src/optimistic.test.ts | refuses irreversible actions on the optimistic path |
| T-039 | packages/pca/src/adversarial.test.ts | an under-collateralized open is REFUSED and nothing is locked |
| T-039 | packages/pca/src/adversarial.test.ts | open-count and aggregate-amount caps are enforced |
| T-039 | packages/pca/src/adversarial.test.ts | an over-allocated split (> 10000 bps) is REFUSED |
| T-039 | packages/pca/src/adversarial.test.ts | any mutated field breaks verifySettlement |
| T-039 | packages/pca/src/adversarial.test.ts | a FABRICATED fraud proof (asserted decision not reproducible) is rejected on recomputation |
| T-039 | packages/pca/src/optimistic.test.ts | UPHOLDS an honest claim against a frivolous dispute AND marks the counter-bond for slashing |
| T-039 | packages/pca/src/bond-store.test.ts | the same call returns the original record and takes the collateral once |
| T-039 | packages/pca/src/bond-store.test.ts | opens at the ledger clock, never at the claim issued_at |
| T-039 | packages/pca/src/bond-store.test.ts | refuses a fraud slash after the window closed |
| T-039 | packages/pca/src/bond-store.test.ts | refuses a claim other than the one registered |
| T-040 | packages/pca/src/adversarial.test.ts | two validly-witnessed heads at the same size with different roots prove EQUIVOCATION |
| T-040 | packages/pca/src/adversarial.test.ts | the witness-threshold is FAIL-CLOSED |
| T-040 | packages/pca/src/adversarial.test.ts | a FORGED prev_root on adjacent heads breaks verifyHeadConsistency |
| T-040 | packages/pca/src/ledger.test.ts | a rewritten history is not consistent with the old head |
| T-040 | packages/pca/src/ledger.test.ts | split view: two conflicting roots at the same size cannot both gather an honest-witness threshold |
| T-040 | packages/pca/src/mesh.test.ts | refuses equivocation (same size, different log) and rollback |
| T-040 | packages/pca/src/mesh.test.ts | rejects a head cosigned only by unpinned (attacker) witnesses |
| T-040 | packages/pca/src/ledger-store.test.ts | rollback: entries missing after a checkpoint |
| T-040 | packages/pca/src/ledger-store.test.ts | tamper: an entry edited, inserted or reordered no longer reproduces a checkpoint root |
| T-040 | packages/pca/src/ledger-checkpoints.test.ts | rewritten history between checkpoints, a shrinking log and a broken prev_root link are all inconsistent |
| T-040 | packages/pca/src/ledger-checkpoints.test.ts | two genuine heads, one log, one size, two roots |
| T-040 | tools/pca-witness/test/witness.test.ts | refuses a rollback and a split view |
| T-041 | packages/pca/src/threat-model-gaps.test.ts | an action WITH an inclusion proof against a guardian-signed |
| T-041 | packages/pca/src/threat-model-gaps.test.ts | an action the operator never appended (omission) is refused |
| T-041 | packages/pca/src/threat-model-gaps.test.ts | a proof against an UNWITNESSED or under-witnessed head is refused |
| T-041 | packages/pca/src/threat-model-gaps.test.ts | RESIDUAL (pinned): omission is invisible |
| T-042 | packages/pca/src/adversarial.test.ts | a revoked id has NO valid non-membership proof |
| T-042 | packages/pca/src/adversarial.test.ts | a STALE signed epoch (now > not_after) is rejected |
| T-042 | packages/pca/src/adversarial.test.ts | an epoch ROLLBACK (older than the pinned epoch) is rejected |
| T-042 | packages/pca/src/adversarial.test.ts | an epoch signed by the WRONG guardian is rejected |
| T-042 | packages/pca/src/revocation.test.ts | rejects when the leaf or an ancestor is revoked |
| T-042 | packages/pca/src/revocation.test.ts | REPLAYED PRE-REVOCATION ROOT |
| T-042 | packages/pca/src/server/require-pca.test.ts | rejects an epoch older than the last one this verifier accepted (rollback) |
| T-043 | packages/pca/src/beacons.test.ts | fails closed: stale, absent, wrong issuer/instance/scope, tampered |
| T-043 | packages/pca/src/beacons.test.ts | rejects a replayed older (or equal) seq |
| T-043 | packages/pca/src/beacons.test.ts | a principal that stops issuing halts the grant |
| T-043 | packages/pca/src/agent-native.test.ts | renews with heartbeat; replay, wrong signer, lapsed, exhausted all refused |
| T-043 | packages/pca/src/server/require-pca.test.ts | absent beacon source => DENY (fail closed) |
| T-043 | packages/pca/src/console.test.ts | freezes, reports, and unfreezes agents idempotently |
| T-044 | packages/pca/src/adversarial.test.ts | strictParse rejects a DUPLICATE key |
| T-044 | packages/pca/src/adversarial.test.ts | strictParse rejects exponent numbers |
| T-044 | packages/pca/src/strict.test.ts | rejects comments, duplicate keys, lone surrogates, deep nesting, non-canonical numbers, junk |
| T-044 | packages/pca/src/strict.test.ts | parse and canonicalize agree |
| T-044 | packages/pca/src/hash.test.ts | every out-of-profile vector is rejected |
| T-044 | packages/pca/src/hash.test.ts | every in-profile vector canonicalizes to the exact frozen bytes |
| T-044 | packages/pca/src/conformance.test.ts | conformance vectors (wire v2) |
| T-044 | packages/pca/src/predicate-string-order.test.ts | a LONE surrogate has no UTF-8 encoding |
| T-045 | packages/pca/src/strict.test.ts | astral keys sort AFTER BMP keys |
| T-045 | packages/pca/src/predicate-string-order.test.ts | the astral/BMP split is exactly the case JavaScript < gets wrong |
| T-045 | packages/pca/src/predicate-string-order.test.ts | is not normalised: canonically-equivalent NFC / NFD strings are unequal |
| T-045 | packages/pca/src/strict.test.ts | rejects lone surrogates in values and keys |
| T-045 | packages/pca/src/hash.test.ts | isHashSuite narrows only the two known suites |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | a predicate for the exact verb allows it and denies every variant |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | the reverse direction: a predicate for a variant denies the base form |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | exact resource: allows itself, denies every variant (both directions) |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | regex resources (re:) do not fold or normalize |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | eq / in allow only the identical string and deny each variant |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | the real "expires" caveat is evaluated; look-alike type names are unknown caveats and FAIL CLOSED |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | a verifier audience that is any byte-different look-alike of the signed audience FAILS the audience check and denies |
| T-045 | packages/pca/src/unicode-identifiers.test.ts | params digests, canonical hashes and plan roots all differ between every pair of byte-different identifiers |
| T-046 | packages/pca/src/strict.test.ts | rejects lone surrogates in values and keys, and over-deep nesting |
| T-046 | packages/pca/src/capability.test.ts | rejects chains deeper than MAX_CHAIN_DEPTH before any signature work |
| T-046 | packages/pca/src/agent-native.test.ts | DoS bounds: deep / huge / cyclic args fail closed |
| T-046 | packages/pca/src/predicates.test.ts | rejects backreferences, lookaround, too many unbounded quantifiers |
| T-046 | packages/pca/src/security-audit.test.ts | parseLimit uses a fixed linear regex |
| T-046 | packages/pca/src/objective-risk.hardening.test.ts | the protocol default cap is enforced even without explicit config |
| T-046 | packages/pca/src/input-bounds.test.ts | a document of exactly the cap parses; one byte more is rejected with "input too large" at offset 0 |
| T-046 | packages/pca/src/input-bounds.test.ts | the bound is in UTF-8 BYTES, not UTF-16 units |
| T-046 | packages/pca/src/input-bounds.test.ts | a 1 MiB-minus-epsilon run of "[" (~1M levels) is cut off at the depth limit |
| T-046 | packages/pca/src/input-bounds.test.ts | decodePCActn: an oversized object, an oversized-by-multibyte object and a deep object are all refused |
| T-046 | packages/pca/src/input-bounds.test.ts | strictParseBytes: oversized bytes are refused with the same typed error |
| T-046 | packages/pca/src/input-bounds.test.ts | decodeSafetyCertificate: oversized input is refused (null) |
| T-046 | packages/pca/src/input-bounds.test.ts | parseLimit: a megabyte of garbage or whitespace is refused by a length cap in constant time |
| T-047 | packages/pca/src/pq.test.ts | a valid hybrid PCActn is allowed end-to-end |
| T-047 | packages/pca/src/pq.test.ts | a valid ml-dsa-65 PCActn is allowed |
| T-047 | packages/pca/src/pq-surfaces.test.ts | (c) hybrid root: corrupt/drop either signature => chain fails |
| T-047 | packages/pca/src/pq-surfaces.test.ts | (c) hybrid share: corrupt/drop either component => not counted |
| T-047 | packages/pca/src/pq-threshold.test.ts | quorum with a hash-based signer passes |
| T-047 | packages/pca/src/pq-less.test.ts | hybrid requires BOTH halves: tamper each, drop each, wrong keys |
| T-047 | packages/pca/src/pq-less.test.ts | hybrid: allowed; each half tampered => fail; dropped pq_sig => wire failure |
| T-047 | packages/pca/src/pq-less.test.ts | hybrid root (principal) + pure-LESS delegation verify; tampering any part fails |
| T-047 | packages/pca/src/pq-less.test.ts | missing package: status carries a clear reason; verify denies; signing throws; other suites unaffected |
| T-047 | packages/pca/src/pq-less.test.ts | a LESS signature/key presented under ml-dsa / ed25519 / fn-dsa algs (and vice versa) never verifies |
| T-047 | packages/pca/src/frost-pq.test.ts | tamper the ML-DSA half => deny |
| T-047 | packages/pca/src/frost-pq.test.ts | hybrid declared but the PQ co-sign is ABSENT => deny |
| T-048 | packages/pca/src/hash.test.ts | sha256 known vector and b64u roundtrip |
| T-048 | packages/pca/src/hash.test.ts | sha384 is a correct 48-byte FIPS 180-4 digest |
| T-048 | packages/pca/src/frost.test.ts | THE decisive vector: sig shares + aggregate signature are byte-exact and verify |
| T-049 | packages/pca/src/security-audit.test.ts | receipt chain detects a tampered body |
| T-049 | tools/pca-audit/timing/dudect.ts | CONTROL positive: early-exit byte compare |
| T-050 | packages/pca/src/prohibitions.test.ts | an unresolvable trigger condition counts as MATCHED |
| T-050 | packages/pca/src/prohibitions.test.ts | forged all-clear evidence for a violating action is rejected |
| T-050 | packages/pca/src/prohibitions.test.ts | prohibitions are independent of the plan |
| T-050 | packages/pca/src/prohibitions.test.ts | daily spend cap triggers across a sequence and the window rolls |
| T-051 | packages/pca/src/grant-ref-binding.test.ts | grant_ref_bound closes the replay-namespace bypass |
| T-051 | packages/pca/src/grant-ref-binding.test.ts | grant_ref_bound: the check |
| T-051 | packages/pca-conformance/adversarial/gen-adversarial.ts | grant-ref-bound |
| T-052 | packages/pca/src/passport-signed.test.ts | every signed field is covered: tampering any of them fails |
| T-052 | packages/pca/src/passport-signed.test.ts | rejects a forged flag (signed false->true by hand) and a flag with no evidence |
| T-052 | packages/pca/src/passport-signed.test.ts | accepts the evidence only through an attestation verifier; no verifier = reject, not downgrade |
| T-052 | packages/pca/src/passport-signed.test.ts | hardware evidence age is re-checked at verify time (exact boundaries, default 24 h, skew for the future) |
| T-052 | packages/pca/src/passport-signed.test.ts | passport conformance vectors |
| T-052 | packages/pca/src/server/authorize-passport.test.ts | a refused passport never consumes the PCActn: the same PCActn is then allowed with a valid passport |
| T-360 | packages/pca-grants/src/fresh-at.test.ts | NEW ENEMY: a verifier at an older revocation epoch escalates stale_state, naming the field |
| T-360 | packages/pca-grants/src/fresh-at.test.ts | wrong scope, forgery, future and over-age tokens are denied |
| T-360 | packages/pca-grants/src/fresh-at.test.ts | gateDecision only tightens |
| T-361 | packages/pca-grants/src/fresh-at.test.ts | a token verifies for its signer and for nobody else |
| T-361 | packages/pca-grants/src/fresh-at.test.ts | mergeFreshAt is the field-wise max and never lowers |
| T-361 | packages/pca-grants/src/fresh-at.test.ts | the issuer advances monotonically and its own tokens check ok at once; an old token still passes, a revoke token makes a lagging peer stale |
| T-362 | packages/pca-grants/src/list-authorized.test.ts | returns exactly the capability-permitted objects across pages, each once and in order |
| T-362 | packages/pca-grants/src/list-authorized.test.ts | the relationship can only narrow the capability |
| T-362 | packages/pca-grants/src/list-authorized.test.ts | a cursor cannot be reused with a different subject, filter, policy or limit, or forged |
| T-363 | packages/pca-grants/src/bundle.test.ts | accepts k-of-n distinct pinned signatures and reports who signed |
| T-363 | packages/pca-grants/src/bundle.test.ts | one signer twice, an unpinned signer, or a signature over other content do not count |
| T-363 | packages/pca-grants/src/bundle.test.ts | rollback, broken chain, an old verifier and malformed bundles are refused |
| T-364 | packages/pca-grants/src/bundle.test.ts | records are hash-chained and inclusion-provable against a signed head, offline |
| T-364 | packages/pca-grants/src/bundle.test.ts | the stream is gap-free, replay-proof and tamper-evident |
| T-364 | packages/pca-grants/src/bundle.test.ts | masks by data class, not by path |
| T-365 | packages/pca-grants/src/grant-resource.test.ts | narrow by the HOLDER revises in place; the same signature cannot be replayed on the next revision |
| T-365 | packages/pca-grants/src/grant-resource.test.ts | widening needs the PRINCIPAL signature AND a step-up, and makes a new grant id with supersedes (nothing widens in place) |
| T-365 | packages/pca-grants/src/grant-resource.test.ts | orders verbs, resources, ceilings and expiry; incomparable and unbounded-to-bounded are classified |
| T-366 | packages/pca-signals/src/ssf-stream.test.ts | unverified -> healthy on a matching single-use state -> degraded after the window |
| T-366 | packages/pca-signals/src/ssf-stream.test.ts | refuses unknown, expired and non-string states; expiry counts toward failing |
| T-366 | packages/pca-signals/src/ssf-stream.test.ts | honours min_verification_interval, the pending cap and the status; paused and disabled never claim revocation freshness |
| T-367 | packages/pca-gnap/src/interaction.test.ts | matches the RFC example for sha-256 and sha3-512 |
| T-367 | packages/pca-gnap/src/interaction.test.ts | REDIRECT finish end to end: user code lookup is case-insensitive, the callback hash validates at the client, the ref is single use |
| T-367 | packages/pca-gnap/src/interaction.test.ts | PUSH finish carries {hash, interact_ref}; a forged hash or foreign nonce does not validate and the ref must not be sent |
| T-368 | packages/pca/src/fresh-at-member.test.ts | is signed by the leaf signature: swapping the token breaks leaf_signature |
| T-368 | packages/pca/src/fresh-at-member.test.ts | a lagging verifier fails fresh_at with an ESCALATE-class reason (decision escalate, never allow) |
| T-368 | packages/pca/src/fresh-at-member.test.ts | a PCActn that carries the member with no policy is refused; no member and no policy is byte-identical (check absent) |
| T-368 | packages/pca/src/fresh-at-member.test.ts | require: no token escalates; the side-carried form is still read for one release, but the member wins |
| T-369 | apps/api/src/routes/pca.test.ts | enrolment needs the principal signature at revision 0, is once, and is enforced at admission as a tighten-only ceiling |
| T-369 | apps/api/src/routes/pca.test.ts | widening: principal signature + a spent step-up + a registered successor; the old grant is superseded and killed, the new one carries the wider authority |
| T-369 | apps/api/src/routes/pca.test.ts | step-up challenges: unknown, foreign-grant, wrongly signed and replayed approvals are refused |
| T-370 | packages/pca-signals/src/ssf-manage.test.ts | read: one stream, all streams, none; another receiver sees 404, unauthenticated is 401 |
| T-370 | packages/pca-signals/src/ssf-manage.test.ts | PATCH changes only what is present; transmitter-supplied members must match; push delivery is receiver-set; method cannot change |
| T-370 | packages/pca-signals/src/ssf-manage.test.ts | create refuses transmitter-supplied members, unsupported or insecure delivery, unsupported-only events; a second stream is 409 |
| T-371 | apps/api/src/routes/pca.test.ts | keys outside the closed grammar are refused when written, so nothing is silently unenforced |
| T-371 | apps/api/src/routes/pca.test.ts | max.<param> is a per-action ceiling and needs the parameter plaintext |
| T-371 | apps/api/src/routes/pca.test.ts | sum.<param> is a lifetime total: the action that would cross it is refused and costs nothing |
| T-371 | apps/api/src/routes/pca.test.ts | count caps the number of admitted actions, and concurrent admissions cannot overshoot |
| T-380 | packages/pca-express/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| T-380 | packages/pca-express/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| T-381 | packages/pca-express/src/index.test.ts | is refused at construction without `operation` |
| T-381 | packages/pca-express/src/acceptance.test.ts | misconfigured requests |
| T-380 | packages/pca-fastify/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| T-380 | packages/pca-fastify/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| T-381 | packages/pca-fastify/src/index.test.ts | is refused at construction without `operation` |
| T-381 | packages/pca-fastify/src/acceptance.test.ts | misconfigured requests |
| T-380 | packages/pca-hono/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| T-380 | packages/pca-hono/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| T-381 | packages/pca-hono/src/index.test.ts | is refused at construction without `operation` |
| T-381 | packages/pca-hono/src/acceptance.test.ts | misconfigured requests |
| T-380 | packages/pca-next/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| T-380 | packages/pca-next/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| T-381 | packages/pca-next/src/index.test.ts | is refused at construction without `operation` |
| T-381 | packages/pca-next/src/acceptance.test.ts | misconfigured requests |
| T-380 | packages/pca-fetch/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| T-380 | packages/pca-fetch/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| T-381 | packages/pca-fetch/src/index.test.ts | is refused at construction without `operation` |
| T-381 | packages/pca-fetch/src/acceptance.test.ts | misconfigured requests |
| T-382 | packages/pca-mcp/src/fetch.test.ts | adds a fresh PCA-Action for each tools/call, bound to the call |
| T-382 | packages/pca-mcp/src/fetch.test.ts | passes other requests, unmapped tools and non-JSON bodies through unchanged |
| T-382 | packages/pca-mcp-rs/src/tool-call.test.ts | a valid proof presented for another tool, another resource or other arguments |
| T-382 | packages/pca-mcp-rs/src/tool-call.test.ts | a replayed proof |
| T-382 | packages/pca-mcp-rs/src/tool-call.test.ts | the challenge never carries request-derived text |
| T-383 | packages/pca-gateway/src/breaking-05.test.ts | createGateway throws and authorize denies a genuine proof |
| T-383 | packages/pca-gateway/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused |
| T-383 | packages/pca-gateway/src/index.test.ts | denies an unmapped dangerous route by default, even with a valid proof |
| T-383 | packages/pca-gateway/src/index.test.ts | overwrites every x-pca-* header on a pass-through allow so a forged one cannot reach the upstream |
| T-383 | packages/pca-gateway/src/index.test.ts | percent-encoded ; is also ambiguous |
| T-383 | packages/pca-gateway/src/breaking-05.test.ts | without a replayGuard it throws |
| T-383 | packages/pca-gateway/src/breaking-05.test.ts | requireChecks defaults to [revocation] |
| T-383 | packages/pca-gateway/src/full-policy.test.ts | signature-only mode (explicit since 0.5) admits a $400 body |
| T-384 | packages/pca-testing/src/index.test.ts | changing the action verb makes expectVerifies throw and expectDenied pass |
| T-384 | packages/pca-store-conformance/src/reference.test.ts | read-then-write: two clients both read "absent" -> two TRUEs for one key (burst and concurrent) |
| T-384 | packages/pca-store-conformance/src/reference.test.ts | volatile store: the durability test sees a consumed nonce / counter come back after restart |
| T-384 | packages/pca-store-conformance/src/reference.test.ts | evicting cache: the retention test sees evicted live records accepted again |
| T-384 | packages/pca-store-conformance/src/runner.test.ts | fail on a violation, unresolved when nothing definite was observed or a key was over budget |
| T-384 | packages/pca-store-conformance/src/cli.test.ts | exit 3 when nothing definite was observed |
| T-384 | packages/pca-store-conformance/src/reference.test.ts | non-strict counter: an equal value is accepted twice (burst, concurrent) |
| T-385 | packages/pca-ai-sdk/src/index.test.ts | emits a verifiable PCActn |
| T-385 | packages/pca-ai-sdk/src/index.test.ts | fast-fails an over-cap call without running execute |
| T-385 | packages/pca-anthropic/src/index.test.ts | returns an error tool_result for an unmapped tool, without running a handler |
| T-385 | packages/pca-anthropic/src/index.test.ts | returns an error tool_result when the handler throws |
| T-385 | packages/pca-openai/src/index.test.ts | does NOT fast-fail an over-cap call |
| T-385 | packages/pca-openai/src/index.test.ts | throws on an unmapped tool name (no PCActn without a mapping) |
| T-386 | packages/pca-mastra/src/index.test.ts | blocks a call with NO proof (typed PcaToolDenied/missing), original not called |
| T-386 | packages/pca-mastra/src/index.test.ts | blocks a proof whose verb does not bind to this tool (binding) |
| T-386 | packages/pca-mastra/src/index.test.ts | blocks an INVALID proof (wrong audience → verify fail), original not called |
| T-386 | packages/pca-openai-agents/src/index.test.ts | blocks a call with NO proof (typed PcaToolDenied/missing), original not called |
| T-386 | packages/pca-openai-agents/src/index.test.ts | blocks a proof whose verb does not bind to this tool (binding) |
| T-386 | packages/pca-openai-agents/src/index.test.ts | blocks an INVALID proof (wrong audience → verify fail), original not called |
| T-386 | packages/pca-vercel-ai/src/index.test.ts | blocks a call with NO proof (typed PcaToolDenied/missing), original not called |
| T-386 | packages/pca-vercel-ai/src/index.test.ts | blocks a proof whose verb does not bind to this tool (binding) |
| T-386 | packages/pca-vercel-ai/src/index.test.ts | blocks an INVALID proof (wrong audience → verify fail), original not called |
| T-386 | sdks/agent-framework-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| T-386 | sdks/agent-framework-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| T-386 | sdks/agent-framework-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| T-386 | sdks/crewai-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| T-386 | sdks/crewai-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| T-386 | sdks/crewai-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| T-386 | sdks/fastmcp-pca/test_fastmcp_pca.py | test_missing_proof_is_rejected |
| T-386 | sdks/fastmcp-pca/test_fastmcp_pca.py | test_tampered_proof_fails_signature |
| T-386 | sdks/fastmcp-pca/test_fastmcp_pca.py | test_wrong_audience_is_rejected |
| T-386 | sdks/google-adk-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| T-386 | sdks/google-adk-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| T-386 | sdks/google-adk-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| T-386 | sdks/haystack-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| T-386 | sdks/haystack-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| T-386 | sdks/haystack-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| T-386 | sdks/langgraph-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| T-386 | sdks/langgraph-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| T-386 | sdks/langgraph-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| T-386 | sdks/pydantic-ai-pca/test_pydantic_ai_pca.py | test_missing_proof_is_rejected_fail_closed |
| T-386 | sdks/pydantic-ai-pca/test_pydantic_ai_pca.py | test_tampered_proof_fails_signature |
| T-386 | sdks/pydantic-ai-pca/test_pydantic_ai_pca.py | test_wrong_audience_is_rejected |
| T-387 | packages/pca-mastra/src/full-policy.test.ts | `operation` binds the resource: a proof for another charge is refused |
| T-387 | packages/pca-mastra/src/full-policy.test.ts | a $50 refund runs once; the replayed proof is refused before execute runs |
| T-387 | packages/pca-mastra/src/full-policy.test.ts | a revoked grant is refused before execute runs |
| T-387 | packages/pca-mastra/src/full-policy.test.ts | a tool input that differs from the signed params is refused |
| T-387 | packages/pca-mastra/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused before execute runs |
| T-387 | packages/pca-openai-agents/src/full-policy.test.ts | `operation` binds the resource: a proof for another charge is refused |
| T-387 | packages/pca-openai-agents/src/full-policy.test.ts | a $50 refund runs once; the replayed proof is refused before execute runs |
| T-387 | packages/pca-openai-agents/src/full-policy.test.ts | a revoked grant is refused before execute runs |
| T-387 | packages/pca-openai-agents/src/full-policy.test.ts | a tool input that differs from the signed params is refused |
| T-387 | packages/pca-openai-agents/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused before execute runs |
| T-387 | packages/pca-vercel-ai/src/full-policy.test.ts | `operation` binds the resource: a proof for another charge is refused |
| T-387 | packages/pca-vercel-ai/src/full-policy.test.ts | a $50 refund runs once; the replayed proof is refused before execute runs |
| T-387 | packages/pca-vercel-ai/src/full-policy.test.ts | a revoked grant is refused before execute runs |
| T-387 | packages/pca-vercel-ai/src/full-policy.test.ts | a tool input that differs from the signed params is refused |
| T-387 | packages/pca-vercel-ai/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused before execute runs |
| T-387 | sdks/agent-framework-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| T-387 | sdks/agent-framework-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| T-387 | sdks/agent-framework-pca/test_authorize.py | test_replay_refused |
| T-387 | sdks/agent-framework-pca/test_authorize.py | test_revoked_refused |
| T-387 | sdks/crewai-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| T-387 | sdks/crewai-pca/test_authorize.py | test_positional_arguments_cannot_be_bound |
| T-387 | sdks/crewai-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| T-387 | sdks/crewai-pca/test_authorize.py | test_replay_refused |
| T-387 | sdks/crewai-pca/test_authorize.py | test_revoked_refused |
| T-387 | sdks/fastmcp-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| T-387 | sdks/fastmcp-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| T-387 | sdks/fastmcp-pca/test_authorize.py | test_replay_refused |
| T-387 | sdks/fastmcp-pca/test_authorize.py | test_revoked_refused |
| T-387 | sdks/fastmcp-pca/test_authorize.py | test_wildcard_capability_refused |
| T-387 | sdks/google-adk-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| T-387 | sdks/google-adk-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| T-387 | sdks/google-adk-pca/test_authorize.py | test_replay_refused |
| T-387 | sdks/google-adk-pca/test_authorize.py | test_revoked_refused |
| T-387 | sdks/haystack-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| T-387 | sdks/haystack-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| T-387 | sdks/haystack-pca/test_authorize.py | test_replay_refused |
| T-387 | sdks/haystack-pca/test_authorize.py | test_revoked_refused |
| T-387 | sdks/langgraph-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| T-387 | sdks/langgraph-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| T-387 | sdks/langgraph-pca/test_authorize.py | test_replay_refused |
| T-387 | sdks/langgraph-pca/test_authorize.py | test_revoked_refused |
| T-387 | sdks/pydantic-ai-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| T-387 | sdks/pydantic-ai-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| T-387 | sdks/pydantic-ai-pca/test_authorize.py | test_replay_refused |
| T-387 | sdks/pydantic-ai-pca/test_authorize.py | test_revoked_refused |
| T-388 | packages/pca-mastra/src/full-policy.test.ts | a missing component throws at construction (fail closed, never a downgrade to signature-only) |
| T-388 | packages/pca-mastra/src/full-policy.test.ts | pcaTools forwards `authorize`, and a per-tool `verify` replaces it for that tool |
| T-388 | packages/pca-openai-agents/src/full-policy.test.ts | a missing component throws at construction (fail closed, never a downgrade to signature-only) |
| T-388 | packages/pca-openai-agents/src/full-policy.test.ts | pcaTools forwards `authorize`, and a per-tool `verify` replaces it for that tool |
| T-388 | packages/pca-vercel-ai/src/full-policy.test.ts | a missing component throws at construction (fail closed, never a downgrade to signature-only) |
| T-388 | packages/pca-vercel-ai/src/full-policy.test.ts | pcaTools forwards `authorize`, and a per-tool `verify` replaces it for that tool |
| T-388 | sdks/agent-framework-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| T-388 | sdks/agent-framework-pca/test_authorize.py | test_missing_store_refused |
| T-388 | sdks/agent-framework-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| T-388 | sdks/crewai-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| T-388 | sdks/crewai-pca/test_authorize.py | test_missing_store_refused |
| T-388 | sdks/crewai-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| T-388 | sdks/fastmcp-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| T-388 | sdks/fastmcp-pca/test_authorize.py | test_missing_store_refused |
| T-388 | sdks/fastmcp-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| T-388 | sdks/google-adk-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| T-388 | sdks/google-adk-pca/test_authorize.py | test_missing_store_refused |
| T-388 | sdks/google-adk-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| T-388 | sdks/haystack-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| T-388 | sdks/haystack-pca/test_authorize.py | test_missing_store_refused |
| T-388 | sdks/haystack-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| T-388 | sdks/langgraph-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| T-388 | sdks/langgraph-pca/test_authorize.py | test_missing_store_refused |
| T-388 | sdks/langgraph-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| T-388 | sdks/pydantic-ai-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| T-388 | sdks/pydantic-ai-pca/test_authorize.py | test_missing_store_refused |
| T-388 | sdks/pydantic-ai-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| T-389 | packages/pca-mastra/src/index.test.ts | guardStep runs a safe step through, and lets an approved step-up through |
| T-389 | packages/pca-mastra/src/index.test.ts | guardStep throws PcaStepDenied when the grant forbids the step |
| T-389 | packages/pca-mastra/src/index.test.ts | guardStep throws PcaStepUpRequired on a risky step and routes it to onStepUp (original not run) |
| T-389 | packages/pca-openai-agents/src/index.test.ts | pcaNeedsApproval returns true for a risky tool and routes a step-up, false for a safe one |
| T-389 | packages/pca-openai-agents/src/index.test.ts | withApproval sets needsApproval on the tool; an already-approved step-up is let through |
| T-389 | packages/pca-vercel-ai/src/index.test.ts | prepareStep lets an already-approved step-up through (no change) |
| T-389 | packages/pca-vercel-ai/src/index.test.ts | prepareStep removes a risky tool from the next step and routes it to step-up |
| T-390 | packages/pca-rotate/src/index.test.ts | rejects a wrong ancestor secret |
| T-390 | packages/pca-rotate/e2e/revoke.e2e.test.ts | the old chain is denied, the re-issued chain is not, and the holder key is never revoked |
| T-390 | packages/pca-rotate/src/atomic.test.ts | refuses a re-issued chain that shares a capability with the revoked set, before any write |
| T-391 | packages/pca-events/src/hardening.test.ts | the empty-key forgery is refused |
| T-391 | packages/pca-events/src/hardening.test.ts | a stale delivery is refused before the store is touched |
| T-392 | packages/pca-connect/src/hardening.test.ts | an error body that echoes the refresh token, client secret or access token is redacted |
| T-392 | packages/pca-connect/src/vault.test.ts | denies a chain not rooted at the connection |
| T-393 | packages/pca-connectors/src/hardening.test.ts | refuses a redirect uri that is not absolute, has a fragment or credentials, or is plain http off localhost |
| T-393 | packages/pca-connectors/src/hardening.test.ts | a provider error or transport error that echoes the code, the secret or the verifier is redacted |
| T-394 | packages/pca/src/dataflow-hardening.test.ts | tag refuses a trusted capability with no sources or with a tool source |
| T-394 | packages/pca/src/dataflow-hardening.test.ts | readers and sources are immutable sets |
| T-395 | packages/pca-policy-bridge/src/mutation-kill-cedar.test.ts | forbid could not be fully modeled |
| T-395 | packages/pca-policy-bridge/src/differential.test.ts | replays every generated request |
| T-396 | packages/pca-rag/src/hardening.test.ts | a retriever that throws returns nothing and keeps the previous decision |
| T-396 | packages/pca-rag/src/hardening.test.ts | duplicate ids are told apart by position |
| T-397 | packages/pca-revoke/src/hardening.test.ts | a revocation is visible to the very next check once revoke has resolved |
| T-397 | packages/pca-revoke/src/hardening.test.ts | denies when the store throws, and does not leak the store error text |
| T-399 | packages/pca-siem/src/hardening.test.ts | a fetch error that quotes the url is scrubbed in the result and in onError |
| T-399 | packages/pca-siem/src/hardening.test.ts | request headers never appear in a result |
| T-398 | packages/pca-siem/src/hardening.test.ts | a newline or a CEF delimiter in attacker-controlled fields cannot forge a second line or a field |
| T-400 | packages/pca-less-wasm/src/robustness.test.ts | trailing leaf-count byte: every single-bit flip is rejected |
| T-400 | packages/pca-less-wasm/src/robustness.test.ts | malleability: no tested alternative encoding of a signature verifies |
| T-401 | packages/pca-less-wasm/src/portable.test.ts | the wasm imports exactly one host function |
| T-401 | packages/pca-less-wasm/src/portable.test.ts | fails closed when Web Crypto is unavailable |
| T-402 | packages/pca-schema/src/index.test.ts | rejects a PCActn with a required field removed, naming it |
| T-403 | packages/pca-verified-core/test/finding-clock.test.ts | NaN / non-integer / infinite clocks fail closed |
| T-403 | packages/pca-verified-core/test/constants.test.ts | the window boundaries sit exactly on those limits |
| T-404 | packages/pca-harness/src/attestation.test.ts | DENIES when the measurement mismatches the allowlist (unknown mediator) |
| T-404 | packages/pca-harness/src/attestation.test.ts | DENIES when the harness attestation is ABSENT but required |
| T-405 | packages/pca-otel/src/hardening.test.ts | a tracer that throws on every call still returns the guard result |
| T-405 | packages/pca-otel/src/hardening.test.ts | a recorded exception is a clean copy: no secret in message, stack or cause |
| T-406 | packages/pca-explain/src/hardening.test.ts | an allow that a failing check contradicts is explained as a denial, naming the check |
| T-406 | packages/pca-compliance/src/index.test.ts | empty event set: every control is not-evidenced |
| T-406 | packages/pca-doctor/src/hardening.test.ts | no results, or only skips, is a fail |
| T-407 | packages/pca-conformance/src/conformance.test.ts | runConformance detects divergence from a non-conformant verifier |
| T-407 | packages/pca-conformance/src/conformance.test.ts | has one canonical valid vector + exactly one per documented failure mode |
| T-410 | packages/pca/src/k5-vectors.test.ts | redact:  |
| T-411 | packages/pca/src/k5-vectors.test.ts | digests and chain labels |
| T-412 | packages/pca/src/k5-vectors.test.ts | sink:  |
| T-413 | packages/pca/src/k5-vectors.test.ts | the masked view never contains a dropped value |
| T-414 | packages/pca/src/k5-vectors.test.ts | the committed files are exactly what the generator writes |
| T-415 | packages/pca/src/read-vault.test.ts | detokenises only for a sink the grant allows the class to reach |
| T-416 | packages/pca/src/read-vault.test.ts | a group below k is refused; clamping bounds the exact sum |
| T-417 | packages/pca/src/read-vault.test.ts | a repeated identical query returns the same answer and is not charged again |
| T-730 | packages/pca/src/product-layer-fail-closed-table.test.ts | NaN taint against a hard ceiling is a hard deny |
| T-730 | packages/pca/src/product-layer-fail-closed-table.test.ts | a taint smuggled in as a string is treated as maximally tainted |
| T-731 | packages/pca/src/product-layer-fail-closed-table.test.ts | extending cannot relabel an existing verb as less cautious |
| T-731 | packages/pca/src/product-layer-fail-closed-table.test.ts | an unknown verb resolves to the most dangerous spec |
| T-732 | packages/pca/src/product-layer-fail-closed-table.test.ts | null set |
| T-732 | packages/pca/src/product-layer-fail-closed-table.test.ts | frozen not an array |
| T-733 | packages/pca/src/product-layer-fail-closed-table.test.ts | digest does not match |
| T-733 | packages/pca/src/product-layer-fail-closed-table.test.ts | not JSON |
| T-734 | packages/pca/src/mesh.test.ts | refuses equivocation (same size, different log) and rollback |
| T-734 | packages/pca/src/mesh.test.ts | rejects a hop that was never logged by its issuing domain |
| T-720 | packages/pca/src/k5-vectors.test.ts | every denial code of the contract is exercised |
| T-720 | packages/pca/src/workflow-mutation-kill.test.ts | a step with a committed params digest admits exactly those params |
| T-720 | packages/pca/src/k5-vectors.test.ts | admit:  |
| T-720 | formal/dafny/WorkflowAdmit.dfy | AdmittedIsPlanned |
| T-720 | formal/dafny/WorkflowAdmit.dfy | UnplannedDenied |
| T-720 | packages/pca/src/workflow-mutation-kill.test.ts | workflow: limits and shape (exact boundaries) |
| T-720 | packages/pca/src/workflow-mutation-kill.test.ts | 64 steps are valid, 65 are not |
| T-721 | packages/pca/src/workflow-mutation-kill.test.ts | fresh_ms: exactly fresh_ms old is fresh, one ms more is stale |
| T-721 | packages/pca/src/workflow-mutation-kill.test.ts | a receipt may precede its dependency only through a declared promise |
| T-721 | packages/pca/src/k5-vectors.test.ts | receipt refs |
| T-721 | packages/pca/src/workflow-mutation-kill.test.ts | a receipt must be from this workflow, in sequence, linked, and not future-dated |
| T-721 | packages/pca/src/k5-vectors.test.ts | every denial code of the contract is exercised |
| T-721 | formal/dafny/WorkflowAdmit.dfy | AdmittedDepsMet |
| T-721 | formal/dafny/WorkflowAdmit.dfy | ReorderDenied |
| T-721 | formal/dafny/WorkflowAdmit.dfy | AdmittedNotDone |
| T-721 | formal/dafny/WorkflowAdmit.dfy | ChainAppend |
| T-721 | formal/dafny/WorkflowAdmit.dfy | ChainPrefix |
| T-721 | formal/dafny/WorkflowAdmit.dfy | ChainDistinct |
| T-721 | formal/pca-lean/PcaProof/WorkflowAdmit.lean | chain_append |
| T-721 | formal/pca-lean/PcaProof/WorkflowAdmit.lean | chain_nodup |
| T-721 | formal/pca-lean/PcaProof/WorkflowAdmit.lean | admit_run_invariant |
| T-722 | packages/pca/src/k5-vectors.test.ts | digests |
| T-722 | packages/pca/src/workflow-mutation-kill.test.ts | the unit must match on both the receipt and the edge |
| T-722 | formal/dafny/WorkflowAdmit.dfy | AdmittedEdgesHold |
| T-723 | packages/pca/src/workflow-mutation-kill.test.ts | step-level taint: deny and escalate come from labels of any executed ancestor |
| T-723 | packages/pca/src/k5-vectors.test.ts | never throws on hostile input |
| T-724 | packages/pca/src/workflow-mutation-kill.test.ts | a failed dependency denies; max_steps and cost caps are inclusive |
| T-724 | packages/pca/src/k5-vectors.test.ts | bind:  |
| T-724 | formal/dafny/WorkflowAdmit.dfy | AdmittedWithinCap |
| T-724 | formal/dafny/WorkflowAdmit.dfy | SpentAppend |
| T-724 | formal/dafny/WorkflowAdmit.dfy | RunInvariant |
| T-725 | packages/pca/src/workflow-mutation-kill.test.ts | an edge with a promise admits ahead of the source and reports it pending |
| T-725 | packages/pca/src/workflow-mutation-kill.test.ts | bindPromises needs the step receipt |
| T-725 | packages/pca/src/k5-vectors.test.ts | bind:  |
| T-726 | packages/pca/src/server/authorize-workflow.test.ts | a step inside a committed workflow is checked automatically |
| T-727 | packages/pca/src/e2e.test.ts | runs all 8 steps |
| T-727 | packages/pca/src/server/require-pca.test.ts | an UNauthorized plan root (planAuthorized: false) is denied outright |
| T-727 | packages/pca/src/server/require-pca.test.ts | allows only when counter, revocation and plan_root_authorized are all ENFORCED |
| T-740 | packages/pca/src/producer-vectors.test.ts | producer vectors (fixed keys, exact outputs) |
| T-740 | sdks/python-pca/test_agent_producer.py | test_vectors |
| T-740 | sdks/python-pca/test_agent_producer.py | test_refuses_bad_input |
| T-741 | sdks/python-pca/test_agent_producer.py | test_hybrid_and_pure_chain_and_leaf |
| T-741 | sdks/go-pca/agent_test.go | TestPostQuantumSuites |
| T-741 | sdks/rust-pca/tests/agent_producer.rs | ml_dsa_hybrids_cross_verify |
| T-741 | sdks/ruby-pca/test/test_agent_producer.rb | test_post_quantum_hybrids |
| T-742 | sdks/python-pca/test_agent_producer.py | test_agent_act_core_verifies |
| T-742 | sdks/go-pca/agent_test.go | TestAgentRoundTrip |
| T-742 | sdks/rust-pca/tests/agent_producer.rs | agent_round_trip_delegate_plan |
| T-745 | sdks/java-pca/test/net/atlasauth/pca/ProducerVectorsTest.java | everyCaseIsReproducedByteForByte |
| T-745 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ProducerVectorsTest.kt | everyCaseIsReproducedByteForByte |
| T-745 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ProducerVectorTests.cs | EveryCaseIsReproducedByteForByte |
| T-745 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ProducerVectorsTests.swift | testEveryCaseIsReproducedByteForByte |
| T-745 | sdks/java-pca/test/net/atlasauth/pca/ProducerTest.java | suiteKeysFailClosed |
| T-745 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ProducerTest.kt | suiteKeysFailClosed |
| T-745 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ProducerTests.cs | SuiteKeysFailClosed |
| T-745 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ProducerVectorsTests.swift | testSuiteKeysFailClosed |

## Guarantee coverage (G-IDs)

| ID | Test file | Test name (substring) |
|---|---|---|
| G-1 | packages/pca/src/adversarial.test.ts | a signature from the wrong key is rejected |
| G-1 | packages/pca/src/adversarial.test.ts | a signature over a different message is rejected |
| G-1 | packages/pca/src/adversarial.test.ts | NON-CANONICAL S (S + L) is rejected |
| G-1 | packages/pca/src/pcactn.test.ts | wrong-key body signature fails |
| G-2 | packages/pca/src/adversarial.test.ts | strictParse rejects a DUPLICATE key |
| G-2 | packages/pca/src/adversarial.test.ts | an UNKNOWN top-level field is a wire failure |
| G-2 | packages/pca/src/adversarial.test.ts | a NON-CANONICAL base64url fixed-length field |
| G-2 | packages/pca/src/strict.test.ts | astral keys sort AFTER BMP keys |
| G-2 | packages/pca/src/hash.test.ts | every in-profile vector canonicalizes to the exact frozen bytes |
| G-2 | packages/pca/src/conformance.test.ts | conformance vectors (wire v2) |
| G-3 | packages/pca/src/adversarial.test.ts | a child that DROPS a parent caveat is rejected |
| G-3 | packages/pca/src/adversarial.test.ts | BUDGET widening |
| G-3 | packages/pca/src/capability.test.ts | LOOSENED (edited) caveat rejected |
| G-3 | packages/pca/src/capability.test.ts | issuer not equal to parent holder rejected |
| G-3 | packages/pca/src/capability.test.ts | rejects chains deeper than MAX_CHAIN_DEPTH |
| G-4 | packages/pca/src/pcactn.test.ts | out-of-plan action fails even when freshly signed |
| G-4 | packages/pca/src/adversarial.test.ts | reusing a valid inclusion proof for a SWAPPED action |
| G-4 | packages/pca/src/pcactn.test.ts | tampered action breaks plan inclusion |
| G-5 | packages/pca/src/adversarial.test.ts | an audience MISMATCH is rejected |
| G-5 | packages/pca/src/adversarial.test.ts | an EXPIRED PCActn |
| G-5 | packages/pca/src/adversarial.test.ts | a FUTURE-dated PCActn |
| G-5 | packages/pca/src/adversarial.test.ts | an over-LIFETIME window |
| G-5 | packages/pca/src/server/require-pca.test.ts | replay is denied with a store; budget drains |
| G-6 | packages/pca/src/adversarial.test.ts | a t=2 verifier REJECTS a t=1 (agent-only) signature |
| G-6 | packages/pca/src/threshold.test.ts | role-binding: a guardian share cannot be replayed as a principal share |
| G-6 | packages/pca/src/threshold.test.ts | counts distinct KEYS |
| G-6 | packages/pca/src/adversarial.test.ts | one key cannot fill two role slots |
| G-6 | packages/pca/src/adversarial.test.ts | a SUB-THRESHOLD (1-of-2) aggregate is refused |
| G-7 | packages/pca/src/risk.test.ts | SAFETY INVARIANT |
| G-7 | packages/pca/src/risk.test.ts | fully-compromised agent hammering free actions halts at the bound without a human |
| G-7 | packages/pca/src/risk.test.ts | depletion forces step-up even for low r |
| G-7 | packages/pca/src/risk.test.ts | sub-budget cannot exceed parent |
| G-8 | packages/pca/src/adversarial.test.ts | a revoked id has NO valid non-membership proof |
| G-8 | packages/pca/src/adversarial.test.ts | an epoch ROLLBACK (older than the pinned epoch) is rejected |
| G-8 | packages/pca/src/revocation.test.ts | rejects when the leaf or an ancestor is revoked |
| G-8 | packages/pca/src/beacons.test.ts | rejects a replayed older (or equal) seq |
| G-8 | packages/pca/src/beacons.test.ts | a principal that stops issuing halts the grant |
| G-9 | packages/pca/src/adversarial.test.ts | stripping the signed `alg`/`pq_pk` from an ml-dsa-65 PCActn fails closed |
| G-9 | packages/pca/src/pq.test.ts | unknown alg => wire fail (terminal) |
| G-9 | packages/pca/src/pq.test.ts | valid Ed25519 but INVALID ML-DSA => fail (both required) |
| G-9 | packages/pca/src/pq-surfaces.test.ts | (d) unknown suite + downgrade are fail-closed |
| G-9 | packages/pca/src/pq-pinning.test.ts | ed25519 needs no pin; pure/hybrid refused without a pin; pinned key required to match |
| G-10 | packages/pca/src/attestation.test.ts | relay: a genuine signed quote bound to a different holder |
| G-10 | packages/pca/src/attest-amd-snp.test.ts | the family pin matters: this Genoa chain is rejected under the Milan or Turin roots |
| G-10 | packages/pca/src/hardware-sevsnp.test.ts | END-TO-END: ACCEPTS the genuine report |
| G-10 | packages/pca/src/hardware-sevsnp.test.ts | DEBUG policy bit is rejected unless explicitly opted in |
| G-10 | packages/pca/src/attest-multiroot.test.ts | DENIES when two roots DISAGREE on the measured identity |
| G-10 | packages/pca/src/attest-intel-collateral.test.ts | rejects expired collateral |
| G-10 | packages/pca/src/attest-nvidia-rim.test.ts | revocation "ocsp": RIM golden values |
| G-10 | packages/pca/src/attest-azure-maa.test.ts | ACCEPTS a real 3-cert chain anchored by the root SPKI fingerprint |
| G-10 | packages/pca/src/attest-gcp-confidential-space.test.ts | wrong eat_nonce binding denied |
| G-11 | packages/pca/src/attest-allowlist.test.ts | rejects rollback to an older version |
| G-11 | packages/pca/src/attest-allowlist.test.ts | rejects tampering anywhere in the body |
| G-11 | packages/pca/src/attest-maa-keys.test.ts | total replacement without overlap is rejected |
| G-11 | packages/pca/src/attest-maa-keys.test.ts | refuses trust-on-first-use by default |
| G-12 | packages/pca/src/ledger.test.ts | consistency proofs verify for all (old,new) pairs; forged fail |
| G-12 | packages/pca/src/ledger.test.ts | a rewritten history is not consistent with the old head |
| G-12 | packages/pca/src/adversarial.test.ts | two validly-witnessed heads at the same size with different roots prove EQUIVOCATION |
| G-12 | packages/pca/src/ledger.test.ts | k-of-n: threshold met |
| G-12 | packages/pca/src/ledger-store.test.ts | forged checkpoint: a bad signature, another log, or the wrong guardian pin |
| G-12 | tools/pca-witness/test/witness.test.ts | cosigns an extension only with a proof that connects it to the last cosigned head |
| G-12 | packages/pca/src/conformance-ext.test.ts | every vector reproduces, with accepts and rejects |
| G-13 | packages/pca/src/adversarial.test.ts | under-reporting caution gains the agent NOTHING |
| G-13 | packages/pca/src/taint.test.ts | is MONOTONE: adding a ref can only raise taint, never lower it |
| G-13 | packages/pca/src/taint.test.ts | a missing registry in the context fails closed |
| G-13 | packages/pca/src/agent-native.test.ts | under-report gains nothing; over-report escalates |
| G-14 | packages/pca/src/optimistic.test.ts | an out-of-policy optimistic claim yields a verifying fraud proof -> slash |
| G-14 | packages/pca/src/bond-store.test.ts | dispute slash and counter-bond slash use the same recomputed verdicts as the in-memory ledger |
| G-14 | packages/pca/src/conformance-ext.test.ts | every vector reproduces |
| G-14 | packages/pca/src/optimistic.test.ts | a fraud proof with a fabricated decision is rejected on recomputation |
| G-14 | packages/pca/src/optimistic.test.ts | does NOT slash an honest claim when current taint/budget/time have drifted |
| G-14 | packages/pca/src/optimistic.test.ts | refuses irreversible actions on the optimistic path |
| G-15 | packages/pca/src/adversarial.test.ts | a statement mis-bound to a DIFFERENT action is rejected |
| G-15 | packages/pca/src/zk.test.ts | REPLAY DENIED |
| G-15 | packages/pca/src/pcactn.test.ts | present zk_compliance + NO hook => FAIL CLOSED |
| G-16 | packages/pca/src/strict.test.ts | rejects lone surrogates in values and keys, and over-deep nesting |
| G-16 | packages/pca/src/capability.test.ts | rejects chains deeper than MAX_CHAIN_DEPTH before any signature work |
| G-16 | packages/pca/src/agent-native.test.ts | DoS bounds: deep / huge / cyclic args fail closed |
| G-16 | packages/pca/src/predicates.test.ts | rejects backreferences, lookaround, too many unbounded quantifiers |
| G-17 | packages/pca/src/pq-threshold.test.ts | exactly t passes, more than t passes, t-1 fails |
| G-17 | packages/pca/src/pq-threshold.test.ts | set id binds keys, suites, t, diversity |
| G-17 | packages/pca/src/pq-threshold.test.ts | forged signer (signature by a non-member key under a member index) rejected |
| G-17 | packages/pca/src/pq-threshold.test.ts | loadQuorumSet rejects forged id, tampered t, reordered signers |
| G-18 | packages/pca/src/prohibitions.test.ts | prohibitions are independent of the plan |
| G-18 | packages/pca/src/prohibitions.test.ts | forged all-clear evidence for a violating action is rejected |
| G-18 | packages/pca/src/prohibitions.test.ts | sign / verify / tamper |
| G-19 | packages/pca/src/passport-signed.test.ts | signed passport: reason codes |
| G-19 | packages/pca/src/passport-signed.test.ts | every signed field is covered: tampering any of them fails |
| G-19 | packages/pca/src/passport-signed.test.ts | passport conformance vectors |
| G-19 | packages/pca/src/server/authorize-passport.test.ts | a refused passport never consumes the PCActn: the same PCActn is then allowed with a valid passport |

## Security contract coverage (C-IDs)

The invariants of the [Security contract](./security-contract.md). The rows name tests of the surfaces where the invariant is enforced; the contract states, per surface, where it is not.

| ID | Test file | Test name (substring) |
|---|---|---|
| C-1 | packages/pca/src/server/verify.test.ts | denies an out-of-plan action |
| C-1 | packages/pca/src/server/verify.test.ts | denies a tampered body |
| C-1 | packages/pca/src/server/require-pca.test.ts | 401 on tampered signature |
| C-1 | packages/pca/src/adversarial.test.ts | an EXPIRED PCActn |
| C-1 | packages/pca/src/adversarial.test.ts | an audience MISMATCH is rejected |
| C-1 | packages/pca/src/adversarial.test.ts | a signature from the wrong key is rejected |
| C-2 | packages/pca/src/grant-ref-binding.test.ts | is part of the default-deny profile |
| C-2 | packages/pca/src/adversarial.test.ts | a child that DROPS a parent caveat is rejected |
| C-2 | packages/pca/src/adversarial.test.ts | a hop issued by a key that is NOT the parent holder |
| C-2 | packages/pca/src/threat-model-gaps.test.ts | only resolves grants IT enrolled |
| C-3 | packages/pca/src/r041-root-caveats.test.ts | verifyPCActn DENIES an action that exceeds a root max_spend |
| C-3 | packages/pca/src/r041-root-caveats.test.ts | a root caveat type the policy layer does not implement fails closed |
| C-3 | packages/pca/src/r041-root-caveats.test.ts | root and hop caveats both apply |
| C-3 | packages/pca/src/server/verify.test.ts | unknown delegated caveat types still fail closed |
| C-3 | packages/pca-mcp-rs/src/tool-call.test.ts | an over-limit amount |
| C-4 | packages/pca/src/server/verify.test.ts | denies params that do not open the digest |
| C-4 | packages/pca-mcp-rs/src/tool-call.test.ts | another tool, another resource or other arguments |
| C-4 | packages/pca-gateway/src/bind.test.ts | bindRequest denies a proof used on a different path |
| C-5 | packages/pca/src/server/verify.test.ts | the agent cannot lower risk through taint |
| C-5 | packages/pca/src/server/verify.test.ts | caution is MONOTONE |
| C-5 | packages/pca/src/server/verify.test.ts | the RS-authoritative reversibility class wins |
| C-5 | packages/pca/src/mutation-kill-agent-native.test.ts | never lowers |
| C-5 | packages/pca/src/pcactn.test.ts | an agent CANNOT forge low taint |
| C-6 | packages/pca/src/server/require-pca.test.ts | replay is denied with a store; budget drains |
| C-6 | packages/pca/src/server/require-pca.mutation-kill.test.ts | without a store the counter is reported not-enforced |
| C-6 | packages/pca/src/threat-model-gaps.test.ts | two independent guard instances over ONE store also admit exactly one |
| C-6 | packages/pca/src/threat-model-gaps.test.ts | its failure fails CLOSED |
| C-6 | packages/pca/src/replay.test.ts | exactly one accepted |
| C-6 | packages/pca-mcp-rs/src/tool-call.test.ts | a replayed proof |
| C-6 | packages/pca-gateway/src/index.test.ts | replayed-proof |
| C-7 | packages/pca/src/revocation.test.ts | rejects stale/expired/rollback epochs |
| C-7 | packages/pca/src/revocation.test.ts | fails closed on missing root, missing proof, or a forged proof |
| C-7 | packages/pca/src/server/verify.test.ts | denies when a RevocationChecker hook reports revoked |
| C-7 | packages/pca/src/server/require-pca.test.ts | allows only when counter, revocation and plan_root_authorized are all ENFORCED |
| C-8 | packages/pca/src/threshold-server-t.test.ts | refuses to be built without an explicit server-side t |
| C-8 | packages/pca/src/threshold-server-t.test.ts | a hook configured BELOW the server-derived t is rejected |
| C-8 | packages/pca/src/server/verify.test.ts | without an enforced threshold verifier is denied |
| C-8 | packages/pca/src/mutation-kill-threshold.test.ts | there is NO risk_claim-derived default |
| C-9 | packages/pca/src/server/require-pca.test.ts | allows only when counter, revocation and plan_root_authorized are all ENFORCED |
| C-9 | packages/pca/src/server/verify.test.ts | required-but-not-enforced check DENY |
| C-9 | packages/pca/src/server/verify.test.ts | omitted budget does NOT auto-admit |
| C-9 | packages/pca/src/pcactn.test.ts | present zk_compliance + NO hook |
| C-9 | packages/pca/src/server/require-pca.test.ts | require-when-bound |
| C-10 | NO AUTOMATED TEST | |
| C-11 | packages/pca/src/attest-fail-closed-table.test.ts | software attestation: missing or invalid X => exact denial |
| C-11 | packages/pca/src/attest-fail-closed-table.test.ts | hardware seam: missing or invalid X => exact denial, labels honest |
| C-11 | packages/pca/src/attest-allowlist-fail-closed-table.test.ts | verifyAllowlistManifest: missing or invalid X => exact result |
| C-11 | packages/pca/src/attest-allowlist-fail-closed-table.test.ts | verifyAllowlistDurable: missing or corrupt state => exact result |
| C-11 | packages/pca/src/attest-pq-software-fail-closed-table.test.ts | attest-pq-software: missing or invalid X => exact result |
| C-11 | packages/pca/src/attest-allowlist-anchor-vectors.test.ts | allowlist-anchor conformance vectors |
| C-11 | packages/pca/src/zk-attested-vm-hw.test.ts | attested-VM mode bound to hardware evidence |
| C-11 | packages/pca/src/zk-attested-vm-hw.test.ts | prover key revocation, rotation and statement freshness |
| C-11 | packages/pca/src/zk-attested-vm-hw.test.ts | assurance requirement { zk: attested_vm_hardware } |
| C-11 | packages/pca/src/x509-differential.test.ts | malformed and non-minimal encodings: exact rejection |
| C-11 | packages/pca/src/x509-differential.test.ts | mutation corpus: where we parse and another parser parses, the role facts are identical |
| C-11 | packages/pca/src/attest-parser-fuzz.test.ts | targeted strictness rules (each fails without its check) |
| C-11 | packages/pca/src/attest-canary.test.ts | the judge tells a fail-open verifier from a good one |
| C-11 | packages/pca/src/attest-canary.test.ts | recorded real-evidence canary |
| C-12 | packages/pca/src/passport-signed.test.ts | signed passport: reason codes |
| C-12 | packages/pca/src/passport-signed.test.ts | every signed field is covered: tampering any of them fails |
| C-12 | packages/pca/src/passport-signed.test.ts | rejects a forged flag (signed false->true by hand) and a flag with no evidence |
| C-12 | packages/pca/src/passport-signed.test.ts | hardware evidence age is re-checked at verify time (exact boundaries, default 24 h, skew for the future) |
| C-12 | packages/pca/src/passport-signed.test.ts | passport conformance vectors |
| C-12 | packages/pca/src/server/authorize-passport.test.ts | a refused passport never consumes the PCActn: the same PCActn is then allowed with a valid passport |
| C-13 | packages/pca/src/bond-store.test.ts | fail closed when a required component is missing |
| C-13 | packages/pca/src/bond-store.test.ts | the same call returns the original record and takes the collateral once |
| C-13 | packages/pca/src/bond-store.test.ts | two racing identical releases: one commits, one is a replay, funds move once |
| C-13 | packages/pca/src/bond-store.test.ts | a release racing a slash: exactly one wins and the books conserve |
| C-13 | packages/pca/src/bond-store.test.ts | a clock that steps backwards cannot reopen a closed window or release early |
| C-13 | packages/pca/src/bond-store.test.ts | a process that dies after the claim opened comes back with the bond open and escrow intact |
| C-13 | packages/pca/src/bond-store.test.ts | never half, and retrying finishes the job exactly once |
| C-13 | packages/pca/src/conformance-ext.test.ts | extension layer: optimistic vectors |
| C-13 | packages/pca/src/conformance-ext.test.ts | a fraud proof filed by the reference passes the wire check |
| C-13 | packages/pca-store-conformance/src/bond-conformance.test.ts | a store whose moves land before the phase check is caught |
| C-14 | packages/pca/src/ledger-store.test.ts | no store, a non-store or no guardian key refuses to open |
| C-14 | packages/pca/src/ledger-store.test.ts | inconsistent: a chain whose boundary proof does not connect the two checkpoints |
| C-14 | packages/pca/src/ledger-store.test.ts | checkpoint() refuses to sign over entries another writer rewrote since this handle loaded them |
| C-14 | packages/pca/src/ledger-store.test.ts | two writers on one store never assign an index twice and lose no entry |
| C-14 | packages/pca/src/ledger-store.test.ts | the log still verifies, and retrying finishes it |
| C-14 | packages/pca/src/ledger-checkpoints.test.ts | a forged or foreign head fails at its own index with reason head |
| C-14 | packages/pca/src/conformance-ext.test.ts | extension layer: ledger vectors |
| C-14 | packages/pca/src/conformance-ext.test.ts | the domains the natives must reproduce are the library constants |
| C-14 | packages/pca-store-conformance/src/ledger-conformance.test.ts | a store without compare-and-swap is caught |
| C-14 | tools/pca-witness/test/witness.test.ts | a log of heads cosigned in sequence forms a chain a client verifies end to end |
| T-053 | packages/pca/src/intent.test.ts | binding mismatches fail the intent check only |
| T-053 | packages/pca/src/intent.test.ts | policies fail closed |
| T-053 | packages/pca/src/intent-v2.test.ts | closed world: an undeclared parameter is a terminal schema deny |
| T-053 | packages/pca/src/intent-dod1-audit.test.ts | no intent under an active policy: denied |
| T-054 | packages/pca/src/intent-world.test.ts | refuses an unpinned oracle, a key that is not the pinned one, another subject, a duplicate oracle and an undeclared world |
| T-054 | packages/pca/src/intent-dod1-audit.test.ts | an expired fact (older than freshness_ms): not counted, so the quorum is missed: denied; a future fact likewise |
| T-054 | packages/pca/src/intent-dod1-audit.test.ts | a verdict from a judge not on the allowlist, for an undeclared classifier, with a label outside the set: denied |
| T-054 | packages/pca/src/intent-dod1-audit.test.ts | a receipt signed by a key that is not pinned, or bound to another session: denied |
| T-055 | packages/pca/src/intent-v2.test.ts | T11 (property): any split of any amounts, admitted concurrently, never pushes the counted sum over the cap |
| T-055 | packages/pca/src/intent-history-window.test.ts | a counted event (or a candidate) with a non-integer time throws instead of being dropped from the cap |
| T-055 | packages/pca/src/intent-v2.test.ts | receipt freshness: a leaked retired key, an old receipt, an old or superseded key set, an over-long lifetime are refused |
| T-055 | packages/pca/src/intent-dod1-audit.test.ts | requireDurable defaults to true and refuses a volatile store |
| T-056 | packages/pca/src/intent-v2.test.ts | append-only: an epoch that drops an id revoked in the tracked last epoch, or rolls back, or equivocates, is refused |
| T-056 | packages/pca/src/intent-v2.test.ts | refuses: no epoch, a stale epoch, a revoked session / map / delta, a co-principal or stranger signer, a list that is not the signed set |
| T-057 | packages/pca/src/intent-v2.test.ts | signs and verifies under the discovery keys; any edit fails; expiry is enforced |
| T-057 | packages/pca/src/intent-dod1-audit.test.ts | a clock that is present but not a safe integer: denied |
| T-110 | packages/pca-goal/test/goal.test.ts | G-T2: adding a constraint never grows the allow set |
| T-110 | packages/pca-goal/test/goal.test.ts | mutation sensitivity: the probe corpus tells apart every one-step mutant |
| T-110 | packages/pca-goal/test/goal.test.ts | W7b: co-sign tiers are not part of the goal |
| T-111 | packages/pca-goal/test/goal.test.ts | G-T6: mixed currencies and untyped comparisons are rejected |
| T-111 | packages/pca-goal/test/goal.test.ts | W6: a $ limit on a verb without an amount field is an error |
| T-112 | packages/pca-goal/test/goal.test.ts | the card prints every field |
| T-112 | packages/pca-goal/test/goal.test.ts | G-T10: renderTape is lossless on random goals |
| G-20 | packages/pca/src/intent.test.ts | policies fail closed |
| G-20 | packages/pca/src/intent-v2.test.ts | accumulators: the claim must equal the verifier post; unknown, unselected and wallet-held claims are refused |
| G-20 | packages/pca/src/intent-state-conformance.test.ts | pins the history rules a verifier would otherwise get wrong |
| G-21 | packages/pca/src/intent-world.test.ts | fails closed when fewer than min_oracles facts are fresh |
| G-21 | packages/pca/src/intent-dod1-audit.test.ts | no classifier verdicts while the policy declares a classifier: denied (no quorum) |
| C-15 | packages/pca/src/intent.test.ts | bound intent passes; absent intent without policy reports no check (back-compat) |
| C-15 | packages/pca/src/intent-v2.test.ts | an active policy fails closed on a PCActn without the member |
| C-15 | packages/pca/src/intent-dod1-audit.test.ts | no verifier context at all for a PCActn that carries intent_session: schema, session and accumulators all fail |
| C-16 | packages/pca/src/intent-v2.test.ts | sequenced accumulators: the claim carries a sequencer receipt bound to this action, audience and session |
| C-16 | packages/pca/src/intent-dod1-audit2.test.ts | only reserved and committed events count: released and reverted events leave the pre-state unchanged |
| C-16 | packages/pca/src/intent-state-conformance.test.ts | is the reference output |
| C-17 | packages/pca/src/intent-world.test.ts | fails closed when fewer than min_oracles facts are fresh (stale and future facts are not counted) |
| C-17 | packages/pca/src/intent-dod1-audit.test.ts | a policy with no params map: refused as misconfigured |
| C-18 | packages/pca/src/intent-dod1-audit.test.ts | no epoch evidence: denied |
| C-18 | packages/pca/src/intent-v2.test.ts | a policy age bound without a revocation authority in S fails closed |
| C-19 | packages/pca/src/intent-dod1-audit.test.ts | a malformed verifier context (null member, unknown policy member): every reported check fails with the reason |
| C-19 | packages/pca/src/intent-dod1-audit2.test.ts | no verdicts at all, or a non-array: denied with the count |
| C-19 | packages/pca/src/intent-v2.test.ts | absent means empty / default; present with null is malformed and fails closed |
| C-22 | packages/pca/src/nl-draft-approval.test.ts | every refusal row gives its exact reason |
| C-22 | packages/pca/src/nl-draft-approval.test.ts | valid approval loads exactly the drafted policy |
| C-22 | packages/pca/src/nl-draft-approval.test.ts | unknown verbs are reported and block approval |
| C-22 | packages/pca/src/nl-draft-approval.test.ts | oversize model output throws |
| C-23 | packages/pca/src/safety-certificate-checks.test.ts | scope is risk-budget-bound and the statement disclaims safety |
| C-23 | packages/pca/src/safety-certificate-checks.test.ts | checks are signed: removing or changing one breaks the signature |
| C-23 | packages/pca/src/safety-certificate-checks.test.ts | wrong scope is refused |
| C-23 | packages/pca/src/safety-certificate-checks.test.ts | requireChecks on a certificate with no checks is refused |
| C-24 | packages/pca/src/ha-lease.test.ts | epochs are strictly monotone over repeated takeovers |
| C-24 | packages/pca/src/ha-lease.test.ts | assertFence: current leader ok; stale epoch, expired window and no lease are refused |
| C-24 | packages/pca/src/ha-lease.test.ts | FencedSigner signs for the leader and refuses a stale ex-leader without running sign |
| C-24 | packages/pca/src/ha-lease.test.ts | cas refuses to lower the epoch |
| C-25 | packages/pca/src/contracts-enforcer.test.ts | a violation is refused, names the clause, and latches |
| C-25 | packages/pca/src/contracts-enforcer.test.ts | reset needs the principal signature at the latched seq |
| C-25 | packages/pca/src/contracts-enforcer.test.ts | two enforcers on one kv racing the same actions |
| C-25 | packages/pca/src/server/authorize-adaptive-contract.test.ts | a violated contract refuses with the exact reason and leaves the replay counter unconsumed |
| C-26 | packages/pca/src/immune-fail-closed-table.test.ts | a correctly signed but widening proposal is refused |
| C-26 | packages/pca/src/immune-fail-closed-table.test.ts | adapt never widens, never NaN, and reversal at score 0 is the base |
| C-26 | packages/pca/src/immune-fail-closed-table.test.ts | a higher score is never looser |
| C-26 | packages/pca/src/server/authorize-adaptive-contract.test.ts | a looser policy cannot widen: it is ignored |
| C-27 | packages/pca/src/reputation-fail-closed-table.test.ts | forged, wrong-key, and unknown-subject records are rejected, not counted |
| C-27 | packages/pca/src/reputation-fail-closed-table.test.ts | a repeated dispute id counts once |
| C-27 | packages/pca/src/reputation-fail-closed-table.test.ts | a correctly signed but mispriced quote is refused (recomputation) |
| C-28 | packages/pca/src/entropy-fail-closed-table.test.ts | fails closed: constant, run, skewed, empty and bad parameters |
| C-28 | packages/pca/src/entropy-fail-closed-table.test.ts | never follows redirects |
| C-28 | packages/pca/src/entropy-fail-closed-table.test.ts | http is refused, https allowed, loopback http only with the opt-in |
| C-29 | packages/pca/src/attest-puf-fail-closed-table.test.ts | a PUF root is never hardware assurance: verifier, gate and multi-root all report software |
| C-29 | packages/pca/src/attest-puf-fail-closed-table.test.ts | the registry revokes for good: re-registering does not un-revoke |
| C-29 | packages/pca/src/attest-puf-fail-closed-table.test.ts | an empty or missing measurement allowlist is refused at construction (no accept-all) |
| C-60 | packages/pca-goal/src/review.test.ts | a pinned reviewer approval over the exact goal loads, re-derived |
| C-60 | packages/pca-goal/src/review.test.ts | approval field %s changed: %s |
| C-60 | packages/pca-goal/src/review.test.ts | goal field %s tampered after approval: %s |
| C-60 | packages/pca-goal/src/review.test.ts | every top-level Goal member is exercised above |
| C-60 | packages/pca-goal/src/review.test.ts | a recompile that drifts (another compiler or ontology version) is refused: the policy digest is re-derived |
| C-60 | packages/pca-goal/src/review.test.ts | holes: not signable, not loadable |
| C-60 | packages/pca-goal/src/review.test.ts | tests with a kernel that cannot decide are refused (never silently skipped) |
| C-61 | packages/pca/src/goal-binding-v3.test.ts | a v3 grant opens under the matching approved_goal and nothing else |
| C-61 | packages/pca/src/goal-binding-v3.test.ts | v1 and v2 grants still verify without approved_goal, and are refused under it |
| C-61 | packages/pca/src/goal-binding-v3.test.ts | a misconfigured approved_goal fails closed |
| C-61 | packages/pca/src/goal-binding-v3.test.ts | binding %s |
| C-61 | packages/pca-goal/src/review.test.ts | the grant minted for the approved goal opens under the v3 verifier policy, and only for it (W1) |
| C-62 | packages/pca-goal/src/review.test.ts | the cap is exact: at the cap renders, one over is refused with card_too_large |
| C-62 | packages/pca-goal/src/review.test.ts | limit overrides can only tighten |
| C-62 | packages/pca-goal/src/review.test.ts | fatigue: too many widenings or changes refuse the diff |
| C-62 | packages/pca-goal/src/review.test.ts | an unknown clause shape is rendered as its canonical JSON, never dropped |
| C-63 | packages/pca/src/nl-draft-approval.test.ts | a reviewer-signed draft cannot be re-pointed at another instruction |
| C-63 | packages/pca/src/nl-draft-approval.test.ts | agentFromApprovedNL refuses a goal text other than the approved instruction |
| C-63 | packages/pca/src/nl-draft-approval.test.ts | a v1 approval of a current draft loads with legacy_unbound_instruction and any goal text |
| C-63 | packages/pca/src/nl-draft-approval.test.ts | the model id is pinned: another model is another digest, and a tampered model id is refused |
| T-130 | packages/pca-goal/src/review.test.ts | a pinned reviewer approval over the exact goal loads, re-derived |
| T-130 | packages/pca/src/goal-binding-v3.test.ts | a v3 grant opens under the matching approved_goal and nothing else |
| T-130 | packages/pca/src/nl-draft-approval.test.ts | a reviewer-signed draft cannot be re-pointed at another instruction |
| T-131 | packages/pca-goal/src/review.test.ts | widenings are listed first and counted |
| T-131 | packages/pca-goal/src/review.test.ts | the cap is exact: at the cap renders, one over is refused with card_too_large |
| T-131 | packages/pca-goal/src/review.test.ts | fatigue: too many widenings or changes refuse the diff |
| T-160 | packages/pca-goal/src/__tests__/benchmarks.test.ts | hostile corpus: widening-rate gates |
| T-161 | packages/pca-goal/src/__tests__/core.test.ts | human amounts: ambiguity is a hole, not a guess |
| T-161 | packages/pca-goal/src/__tests__/core.test.ts | homoglyph ids never match |
| T-162 | packages/pca-goal/src/__tests__/core.test.ts | panel needs k>=3, a deterministic reader, two families |
| T-163 | packages/pca-goal/src/__tests__/core.test.ts | forged, wrong-signer and mismatched answers are refused |
| T-164 | packages/pca-goal/src/__tests__/core.test.ts | off-profile, rate, magnitude and novelty raise friction; strikes never decrease |
| T-165 | packages/pca-goal/src/__tests__/benchmarks.test.ts | labelled benchmarks per domain (offline, recorded outputs) |
| C-90 | packages/pca-goal/src/__tests__/core.test.ts | meet is within every reading, on every cell and cap sequence |
| C-90 | packages/pca-goal/src/__tests__/core.test.ts | a wildcard reading cannot widen the meet |
| C-91 | packages/pca-goal/src/__tests__/core.test.ts | rejects defects |
| C-91 | packages/pca-goal/src/__tests__/core.test.ts | template goals have holes limited to declared slots |
| C-92 | packages/pca-goal/src/__tests__/core.test.ts | ambiguous literal and missing slot become holes |
| C-92 | packages/pca-goal/src/__tests__/core.test.ts | homoglyph ids never match |
| C-93 | packages/pca-goal/src/__tests__/core.test.ts | coverage theorem: any policy over the same literals that differs on a cell differs on an example |
| C-93 | packages/pca-goal/src/__tests__/core.test.ts | the pin refuses a silent policy, goal, test or ontology change |
| C-94 | packages/pca-goal/src/__tests__/core.test.ts | widens only with a signature bound to policy, cell and ceiling |
| C-94 | packages/pca-goal/src/__tests__/core.test.ts | deny is never widened; flipping needs a signed revocation; tamper locks |
| C-95 | packages/pca-goal/src/__tests__/core.test.ts | applyDrift is pointwise <= (property) |
| C-95 | packages/pca-goal/src/__tests__/core.test.ts | magnitude spike and sealed state |
| C-96 | packages/pca-goal/src/__tests__/core.test.ts | the card tape is lossless on every template example, meet and hole goal (decode . encode = id) |
| C-96 | packages/pca-goal/src/__tests__/core.test.ts | distinct goals have distinct cards |
| C-97 | packages/pca-goal/src/__tests__/core.test.ts | picks the least conservative feasible level and falls back to the top |
| C-97 | packages/pca-goal/src/__tests__/core.test.ts | too few calibration samples are infeasible and fall back to escalate-all |
| C-97 | packages/pca-goal/test/fail-closed-table.test.ts | non-binary or non-monotone losses throw with the case and level |
| C-97 | packages/pca-goal/test/fail-closed-table.test.ts | with too few cases the top (escalate-all) level is chosen and reported infeasible |
| C-97 | packages/pca-goal/test/fail-closed-table.test.ts | a gate can only make the choice more conservative |
| C-93 | packages/pca-goal/test/fail-closed-table.test.ts | the pinned signer verifies; no pin, a wrong pin, another kind, a tampered body and a non-object do not |
| C-93 | packages/pca-goal/test/fail-closed-table.test.ts | a payload envelope verifies only for its own kind and version |
| C-180 | packages/pca-goal/test/fail-closed-table.test.ts | a larger, negative, fractional or non-numeric override is ignored; a smaller one applies; the defaults are pinned |
| C-200 | packages/pca-actions/test/algebra.test.ts | S subset S2 implies F(S) <= F(S2) |
| C-200 | packages/pca-actions/test/algebra.test.ts | eff(d + t) >= eff(d) for every def d and every trait t |
| C-200 | packages/pca-actions/test/algebra.test.ts | eff(d) >= floor(t) for every t in T(d) and in its closure |
| C-200 | packages/pca-actions/test/def.test.ts | a declared value below its floor is clamped and flagged |
| C-201 | packages/pca-actions/test/algebra.test.ts | rho <= rho2 implies FloorDecision(rho2) <= FloorDecision(rho) |
| C-201 | packages/pca-actions/test/algebra.test.ts | adding a trait or tightening a declared field never raises Dec |
| C-202 | packages/pca-actions/test/algebra.test.ts | well formed custom traits are accepted and never reduce a core floor |
| C-202 | packages/pca-actions/test/algebra.test.ts | rejects the reserved namespace, cycles, unknown implies and depth > 8 |
| C-203 | packages/pca-actions/test/algebra.test.ts | an action outside the pinned pack is never allowed |
| C-203 | packages/pca-actions/test/algebra.test.ts | rejects not and unpinned any_of in an allow |
| C-204 | packages/pca-actions/test/derive.test.ts | rejects lowered floors, dropped implied traits, unknown traits and a lowered reversibility floor |
| C-204 | packages/pca-actions/test/vectors.test.ts | the reference replay reproduces every expected result |
| C-205 | packages/pca-actions/test/def.test.ts | two authoring forms of one action have one digest |
| C-205 | packages/pca-actions/test/def.test.ts | digests are stable under normalization for generated defs |
| C-205 | packages/pca-actions/test/vectors.test.ts | the committed vectors are byte-identical to a fresh generation |
| T-300 | packages/pca-actions/test/derive.test.ts | rejects lowered floors, dropped implied traits, unknown traits and a lowered reversibility floor |
| T-300 | packages/pca-actions/test/derive.test.ts | accepts every derived verb (builtins and generated defs) |
| T-301 | packages/pca-actions/test/def.test.ts | without a valid signed confirmation the effective traits are the TOP of the registry, whatever the def says |
| T-301 | packages/pca-actions/test/def.test.ts | a declared value below its floor is clamped and flagged |
| T-301 | packages/pca-actions/test/def.test.ts | send + pii + irreversible default => external_communication |
| T-302 | packages/pca-actions/test/algebra.test.ts | rejects the reserved namespace, cycles, unknown implies and depth > 8 |
| T-302 | packages/pca-actions/test/algebra.test.ts | well formed custom traits are accepted and never reduce a core floor |
| T-303 | packages/pca-actions/test/algebra.test.ts | rejects not and unpinned any_of in an allow |
| T-304 | packages/pca-actions/test/algebra.test.ts | an action outside the pinned pack is never allowed |
| T-305 | packages/pca-actions/test/def.test.ts | two authoring forms of one action have one digest |
| T-305 | packages/pca-actions/test/def.test.ts | the digest changes for every semantic change and ignores review, examples, source and since |
| T-306 | packages/pca-actions/test/def.test.ts | float in default |
| T-306 | packages/pca-actions/test/def.test.ts | lone surrogate |
| T-306 | packages/pca-actions/test/def.test.ts | non-NFC |
| C-320 | packages/pca-actions/test/author.test.ts | refuses aliases and anchors (no entity expansion), merge keys, duplicate keys and unknown tags |
| C-320 | packages/pca-actions/test/author.test.ts | a billion-laughs document is refused quickly |
| C-320 | packages/pca-actions/test/author.test.ts | refuses a '__proto__' member anywhere, in YAML and in JSON |
| C-320 | packages/pca-actions/test/author.test.ts | refuses floats, non-NFC and lone surrogates (strict JSON profile) |
| C-320 | packages/pca-actions/test/author.test.ts | refuses a file above the size limit |
| C-320 | packages/pca-actions/test/author.test.ts | builder == YAML == JSON == full def for generated actions |
| C-320 | packages/pca-actions/test/author.test.ts | every shorthand form |
| C-321 | packages/pca-cli/src/actions.test.ts | build refuses a project with lint errors and writes nothing |
| C-321 | packages/pca-cli/src/actions.test.ts | a changed schema floor |
| C-321 | packages/pca-cli/src/actions.test.ts | a changed pack def |
| C-321 | packages/pca-cli/src/actions.test.ts | a pack with an invalid def, a missing build, and a bad key |
| C-321 | packages/pca-cli/src/actions.test.ts | a stable pack must be lint-clean even of warnings |
| C-322 | packages/pca-actions/test/tooling.test.ts | a tampered def, root, version, key id, key and signature are refused |
| C-322 | packages/pca-actions/test/tooling.test.ts | a schema signature is not a pack signature, and the other way round |
| C-322 | packages/pca-actions/test/tooling.test.ts | an inconsistent pack is not signed |
| C-322 | packages/pca-cli/src/actions.test.ts | publish refuses a tampered signed file and a pack signed by an unlisted key |
| C-323 | packages/pca-actions/test/lint.test.ts | has 24 stable rules: 14 errors LD-001..014 and 10 warnings LW-001..010 |
| C-323 | packages/pca-actions/test/lint.test.ts | the rule list digest is pinned (changing a rule is a versioned change) |
| C-323 | packages/pca-actions/test/lint.test.ts | lint rules: every rule has a fixture that triggers it and one that does not |
| C-323 | packages/pca-actions/test/lint.test.ts | findings are sorted and stable across runs and input order |
| C-324 | packages/pca-cli/src/actions.test.ts | MCP tools become unreviewed draft defs that lint, build and escalate |
| C-325 | packages/pca-actions/test/tooling.test.ts | soundness against a brute-force oracle: an equal or narrow diff never accepts a call the old def refused |
| C-325 | packages/pca-actions/test/tooling.test.ts | reflexive on generated defs; a narrowing mutation is never a widening, and its inverse never narrows |
| C-325 | packages/pca-actions/test/tooling.test.ts | range changes |
| C-325 | packages/pca-actions/test/tooling.test.ts | params added and removed; breaking changes are flagged |
| C-340 | packages/pca-actions/test/import-fuzz.test.ts | tool lists with fuzzed schemas validate and are unreviewed |
| C-340 | packages/pca-actions/test/import-fuzz.test.ts | grpc: random token soup, mutated proto and random bytes |
| C-340 | packages/pca-actions/test/import.test.ts | covers every source kind, returns string todos, and its defs are unreviewed |
| C-341 | packages/pca-actions/test/import-limits.test.ts | an allOf fan-out bomb is bounded by the node budget |
| C-341 | packages/pca-actions/test/import-limits.test.ts | refuses a parsed source over the byte, node or depth limit |
| C-341 | packages/pca-actions/test/import-limits.test.ts | terminates on a cyclic object without a stack overflow |
| C-341 | packages/pca-actions/test/import-limits.test.ts | a recursive GraphQL input type and a recursive proto message terminate and note it |
| C-341 | packages/pca-actions/test/import-limits.test.ts | a deeply nested GraphQL list type or value does not overflow the stack |
| C-341 | packages/pca-actions/test/import-limits.test.ts | a binary descriptor with a length beyond the buffer, a bad varint or a wire type 7 is refused |
| C-342 | packages/pca-actions/test/suggest.test.ts | for any def and any rule subset: traits grow, params keep their roles, no state becomes confirmed, floors never fall |
| C-342 | packages/pca-actions/test/suggest.test.ts | a suggested def is still unreviewed for floor purposes: the unreviewed floor is never lost |
| C-342 | packages/pca-actions/test/suggest.test.ts | the closed vocabulary: a rule naming a trait outside the registry cannot add it |
| C-342 | packages/pca-actions/test/suggest.test.ts | an injection in the description cannot widen the vocabulary or confirm anything |
| C-342 | packages/pca-actions/test/suggest.test.ts | sign, verify, and detect a changed rule, a changed digest, a wrong key and an unsigned set |
| C-342 | packages/pca-actions/test/suggest.test.ts | rejects regular expressions outside the bounded subset |
| C-342 | packages/pca-actions/test/providers.test.ts | adds only vocabulary traits, records the model, never confirms, and the request holds no values |
| C-342 | packages/pca-actions/test/providers.test.ts | errors carry the status only, never the key, request or body |
| C-343 | packages/pca-actions/test/review-exact.test.ts | each failure has its reason and detail |
| C-343 | packages/pca-actions/test/review-exact.test.ts | each refusal has its code and message |
| C-343 | packages/pca-actions/test/review.test.ts | for any def claiming to be confirmed, with any garbage attestation, the review marker stays |
| C-343 | packages/pca-actions/test/review.test.ts | any change to the def after the review: the def reverts to unreviewed |
| C-343 | packages/pca-actions/test/review.test.ts | the attestation does not move to another def (replay) |
| C-343 | packages/pca-actions/test/review.test.ts | a forged signature, a tampered body, an unsigned attestation and a signature by a different key |
| C-343 | packages/pca-actions/test/review.test.ts | a machine key, an unknown key and a key outside its validity cannot confirm |
| C-343 | packages/pca-actions/test/review.test.ts | a changed trait registry (a raised floor) makes the attestation stale unless the pins accept the old digest |
| C-343 | packages/pca-actions/test/review.test.ts | a key cannot be both a reviewer and an importer or model |
| C-343 | packages/pca-actions/test/review.test.ts | a suggested trait left out must be dismissed with a reason |
| T-440 | packages/pca-actions/test/import-limits.test.ts | an allOf fan-out bomb is bounded by the node budget |
| T-440 | packages/pca-actions/test/import-limits.test.ts | refuses a parsed source over the byte, node or depth limit |
| T-440 | packages/pca-actions/test/import-limits.test.ts | terminates on a cyclic object without a stack overflow |
| T-440 | packages/pca-actions/test/import-limits.test.ts | a recursive GraphQL input type and a recursive proto message terminate and note it |
| T-440 | packages/pca-actions/test/import-limits.test.ts | a deeply nested GraphQL list type or value does not overflow the stack |
| T-440 | packages/pca-actions/test/import-limits.test.ts | a binary descriptor with a length beyond the buffer, a bad varint or a wire type 7 is refused |
| T-441 | packages/pca-actions/test/suggest.test.ts | for any def and any rule subset: traits grow, params keep their roles, no state becomes confirmed, floors never fall |
| T-441 | packages/pca-actions/test/suggest.test.ts | a suggested def is still unreviewed for floor purposes: the unreviewed floor is never lost |
| T-441 | packages/pca-actions/test/suggest.test.ts | the closed vocabulary: a rule naming a trait outside the registry cannot add it |
| T-441 | packages/pca-actions/test/suggest.test.ts | an injection in the description cannot widen the vocabulary or confirm anything |
| T-441 | packages/pca-actions/test/suggest.test.ts | sign, verify, and detect a changed rule, a changed digest, a wrong key and an unsigned set |
| T-441 | packages/pca-actions/test/suggest.test.ts | rejects regular expressions outside the bounded subset |
| T-442 | packages/pca-actions/test/review.test.ts | the attestation does not move to another def (replay) |
| T-442 | packages/pca-actions/test/review.test.ts | a forged signature, a tampered body, an unsigned attestation and a signature by a different key |
| T-442 | packages/pca-actions/test/review.test.ts | a machine key, an unknown key and a key outside its validity cannot confirm |
| T-442 | packages/pca-actions/test/review.test.ts | a key cannot be both a reviewer and an importer or model |
| T-443 | packages/pca-actions/test/review.test.ts | for any def claiming to be confirmed, with any garbage attestation, the review marker stays |
| T-443 | packages/pca-actions/test/review.test.ts | any change to the def after the review: the def reverts to unreviewed |
| T-443 | packages/pca-actions/test/review.test.ts | a changed trait registry (a raised floor) makes the attestation stale unless the pins accept the old digest |
| T-443 | packages/pca-actions/test/review.test.ts | a suggested trait left out must be dismissed with a reason |
| T-420 | packages/pca-actions/test/author.test.ts | refuses aliases and anchors (no entity expansion), merge keys, duplicate keys and unknown tags |
| T-420 | packages/pca-actions/test/author.test.ts | a billion-laughs document is refused quickly |
| T-420 | packages/pca-actions/test/author.test.ts | refuses a '__proto__' member anywhere, in YAML and in JSON |
| T-420 | packages/pca-actions/test/author.test.ts | refuses a file above the size limit |
| T-421 | packages/pca-actions/test/lint.test.ts | lint rules: every rule has a fixture that triggers it and one that does not |
| T-421 | packages/pca-actions/test/import-fuzz.test.ts | tool lists with fuzzed schemas validate and are unreviewed |
| T-422 | packages/pca-cli/src/actions.test.ts | a changed schema floor |
| T-422 | packages/pca-cli/src/actions.test.ts | a changed pack def |
| T-423 | packages/pca-actions/test/tooling.test.ts | a schema signature is not a pack signature, and the other way round |
| T-423 | packages/pca-actions/test/tooling.test.ts | a tampered def, root, version, key id, key and signature are refused |
| T-421 | packages/pca-actions/test/fail-closed-table.test.ts | an unconfirmed action is matched by every prohibit selector, even one that does not match its closure, and by no allow selector |
| T-421 | packages/pca-actions/test/fail-closed-table.test.ts | a verb outside the pinned set is denied (default) or escalated, never allowed; an unconfirmed pinned verb is denied |
| T-421 | packages/pca-actions/test/fail-closed-table.test.ts | an allow selector with negation, or an unpinned any_of, is refused with its reason |
| T-421 | packages/pca-actions/test/fail-closed-table.test.ts | a malformed pattern is refused with its reason |
| T-421 | packages/pca-actions/test/fail-closed-table.test.ts | a verb absent from the schema, floors that are not a profile, or a garbage document is denied |
| T-423 | packages/pca-actions/test/fail-closed-table.test.ts | verifyPackLogEntry returns false (never throws) for garbage bytes |
| T-424 | packages/pca-actions/test/import.test.ts | treats hints as untrusted lower bounds |
| T-424 | packages/pca-actions/test/import-limits.test.ts | refuses more operations than the limit |
| T-425 | packages/pca-actions/test/tooling.test.ts | soundness against a brute-force oracle: an equal or narrow diff never accepts a call the old def refused |
| T-425 | packages/pca-cli/src/actions.test.ts | equal, narrow, widen and incomparable are told apart; added and removed are listed |
| C-360 | packages/pca-actions/test/verifier.test.ts | a site-signed schema whose floors were lowered is refused (schema_floor_forged), by the schema check and by the pin |
| C-360 | packages/pca-actions/test/verifier.test.ts | a dropped implied trait is refused (schema_traits_forged) |
| C-360 | packages/pca-actions/test/verifier.test.ts | a lowered reversibility floor is refused |
| C-360 | packages/pca-actions/test/verifier.test.ts | a custom trait document that weakens a core trait is refused |
| C-360 | packages/pca-actions/test/verifier.test.ts | without the trait engine a v2 schema is refused: a verifier that cannot recompute the floors does not trust them |
| C-360 | packages/pca-actions/test/verifier.test.ts | a grant missing a required caveat escalates (never allows) |
| C-360 | packages/pca-actions/test/verifier.test.ts | a tier above preauth_esc escalates; above max_esc denies |
| C-360 | packages/pca-actions/test/verifier.test.ts | a required context key the verifier did not observe escalates |
| C-360 | packages/pca-actions/test/verifier.test.ts | an unknown verb or a malformed floors object is a deny |
| C-360 | packages/pca-actions/test/verifier.test.ts | control: a consistent v2 schema, an exact pin and a grant that provides the floors admit the action |
| C-360 | packages/pca-actions/test/verifier.test.ts | a grant without a pin and a v1 schema verifies byte-identically |
| C-360 | packages/pca/src/action-pin.test.ts | rejects a malformed rule22 engine, call_context and actions evidence |
| C-360 | packages/pca-actions/test/vectors.test.ts | the reference replay reproduces every expected result |
| C-361 | packages/pca-actions/test/verifier.test.ts | a changed definition with no evolution chain is def_changed |
| C-361 | packages/pca-actions/test/verifier.test.ts | a registry-signed narrowing chains and is admitted |
| C-361 | packages/pca-actions/test/verifier.test.ts | a widening is blocked without the principal even with a signed record, and names the diff to approve |
| C-361 | packages/pca-actions/test/verifier.test.ts | the principal re-approving that exact step for this grant admits it |
| C-361 | packages/pca-actions/test/verifier.test.ts | an unsigned/forged record, a record for another verb, and a record from another namespace never move the pin |
| C-361 | packages/pca-actions/test/verifier.test.ts | a schema from another pack namespace is refused (pack_mismatch) |
| C-361 | packages/pca-actions/test/verifier.test.ts | a pack-only pin (no defs) needs the exact pack root |
| C-361 | packages/pca-actions/test/verifier.test.ts | a schema that is not v2 carries no definition digests, so a pinned grant refuses it |
| C-361 | packages/pca-actions/test/verifier.test.ts | a malformed pin block cannot be minted and, if present in a stored grant, fails closed |
| C-361 | packages/pca-actions/test/pin.test.ts | for random definitions and mutations (property, signed records, 3x10^4 cases in CI) |
| C-361 | packages/pca/src/action-pin.test.ts | follows equal/narrow steps across several hops; a missing hop breaks the chain |
| C-361 | packages/pca/src/action-pin.test.ts | a widen/incomparable step blocks the chain and names the diff to approve; the principal unblocks exactly that step |
| C-361 | packages/pca/src/action-pin.test.ts | an unblocked path is preferred over a blocked shortcut |
| C-361 | packages/pca/src/action-pin.test.ts | records that are unsigned, from another key, for another verb or namespace, or backwards never move the pin |
| C-361 | packages/pca/src/action-pin.test.ts | the chain is bounded and cycles terminate |
| C-361 | packages/pca/src/action-pin.test.ts | accepts a well formed pin and rejects every malformed member |
| C-362 | packages/pca-actions/test/registry.test.ts | a built pack verifies and returns its defs and digest |
| C-362 | packages/pca-actions/test/registry.test.ts | rejects a changed def, a changed root, a swapped key and an unknown kid |
| C-362 | packages/pca-actions/test/registry.test.ts | rejects a downgraded suite claim, unknown members, unsorted or duplicate defs, and bad vocabulary digests |
| C-362 | packages/pca-actions/test/registry.test.ts | a pack signed over valid content but re-signed by another key is refused |
| C-362 | packages/pca-actions/test/registry.test.ts | a pack above the inline limit is sharded automatically and verifies with its shards only |
| C-362 | packages/pca-actions/test/registry.test.ts | verifies across shards; a missing, altered or foreign shard is refused |
| C-362 | packages/pca-actions/test/registry.test.ts | one inclusion proof shows a def belongs to the pack root, whatever the shard |
| C-362 | packages/pca-actions/test/registry.test.ts | appends a pack statement and verifies the receipt against the pinned keys and tree root |
| C-362 | packages/pca-actions/test/registry.test.ts | refuses a receipt for another pack, a wrong log key, a wrong registry key and a wrong tree root |
| C-362 | packages/pca-actions/test/vectors.test.ts | the committed vectors are byte-identical to a fresh generation |
| C-363 | packages/pca-actions/test/registry.test.ts | refuses a rollback to an older signed pack |
| C-363 | packages/pca-actions/test/registry.test.ts | refuses a fork: a second pack at an accepted version |
| C-363 | packages/pca-actions/test/registry.test.ts | refuses a chain gap: a newer pack that skips a version |
| C-363 | packages/pca-actions/test/registry.test.ts | refuses a forged pack and one with a lying evolution |
| C-363 | packages/pca-actions/test/registry.test.ts | survives a restart through snapshot and restore |
| C-363 | packages/pca-actions/test/registry.test.ts | rejects a chain gap, a non-increasing version and a different namespace |
| C-363 | packages/pca-actions/test/registry.test.ts | accepts first, same and upgrade in order |
| C-364 | packages/pca-actions/test/diff.test.ts | equal/narrow implies the new definition accepts only calls the old one accepts and never lowers the floors |
| C-364 | packages/pca-actions/test/diff.test.ts | negative control: a classifier that ignores parameters is caught |
| C-364 | packages/pca-actions/test/diff.test.ts | negative control: a classifier that calls every change narrow is caught |
| C-364 | packages/pca-actions/test/diff.test.ts | negative control: a classifier that ignores the effective profile is caught |
| C-364 | packages/pca-actions/test/diff.test.ts | tightening a bound is narrow, loosening it is widen |
| C-364 | packages/pca-actions/test/diff.test.ts | a new optional parameter is widen; a new required one and a removed required one are incomparable |
| C-364 | packages/pca-actions/test/diff.test.ts | one dimension widening while another narrows is incomparable |
| C-364 | packages/pca-actions/test/registry.test.ts | a registry cannot sign narrow for a widening, drop a record, or add an extra one |
| C-364 | packages/pca-actions/test/registry.test.ts | a pack whose evolution lies about a widening fails verifyUpgrade |
| C-364 | packages/pca-actions/test/registry.test.ts | an upgrade chains prev, increases the version and signs exactly the computed change |
| C-365 | packages/pca-actions/test/pin.test.ts | registry growth never grants: any verb a pack gains is new_action to every pinned grant |
| C-365 | packages/pca-actions/test/verifier.test.ts | a verb the grant does not name is denied or escalated by on_new_action |
| C-365 | packages/pca/src/action-pin.test.ts | a verb the pin does not name follows on_new_action; pack-level pin needs the exact root |
| C-366 | packages/pca/src/action-pin.test.ts | is bound to the grant, the verb and the diff |
| C-366 | packages/pca-actions/test/verifier.test.ts | a re-approval for another grant, another diff, or by another key does not admit it |
| T-460 | packages/pca-actions/test/verifier.test.ts | a site-signed schema whose floors were lowered is refused (schema_floor_forged), by the schema check and by the pin |
| T-460 | packages/pca-actions/test/verifier.test.ts | a dropped implied trait is refused (schema_traits_forged) |
| T-461 | packages/pca-actions/test/verifier.test.ts | a widening is blocked without the principal even with a signed record, and names the diff to approve |
| T-461 | packages/pca-actions/test/pin.test.ts | for random definitions and mutations (property, signed records, 3x10^4 cases in CI) |
| T-461 | packages/pca-actions/test/diff.test.ts | equal/narrow implies the new definition accepts only calls the old one accepts and never lowers the floors |
| T-462 | packages/pca-actions/test/registry.test.ts | refuses a rollback to an older signed pack |
| T-462 | packages/pca-actions/test/registry.test.ts | refuses a fork: a second pack at an accepted version |
| T-462 | packages/pca-actions/test/registry.test.ts | refuses a chain gap: a newer pack that skips a version |
| T-462 | packages/pca-actions/test/registry.test.ts | appends a pack statement and verifies the receipt against the pinned keys and tree root |
| T-463 | packages/pca-actions/test/registry.test.ts | a registry cannot sign narrow for a widening, drop a record, or add an extra one |
| T-463 | packages/pca-actions/test/registry.test.ts | a pack whose evolution lies about a widening fails verifyUpgrade |
| T-464 | packages/pca/src/action-pin.test.ts | is bound to the grant, the verb and the diff |
| T-464 | packages/pca-actions/test/verifier.test.ts | a re-approval for another grant, another diff, or by another key does not admit it |
| T-465 | packages/pca-actions/test/registry.test.ts | verifies across shards; a missing, altered or foreign shard is refused |
| T-466 | packages/pca-actions/test/pin.test.ts | registry growth never grants: any verb a pack gains is new_action to every pinned grant |
| T-466 | packages/pca-actions/test/verifier.test.ts | a pack-only pin (no defs) needs the exact pack root |
| C-420 | sdks/python-pca/test_actions_vectors.py | test_every_vector_replays |
| C-420 | sdks/python-pca/test_actions_vectors.py | test_pack_proof_verifies_and_tamper_fails |
| C-420 | sdks/go-pca/actions_vectors_test.go | TestActionsVectorsReplay |
| C-420 | sdks/go-pca/actions_vectors_test.go | TestActionsWholeDocumentRule22 |
| C-420 | sdks/rust-pca/tests/actions_vectors.rs | fn every_vector_replays |
| C-420 | sdks/rust-pca/tests/actions_vectors.rs | fn expand_oracle_matches_one_step_rounds |
| C-420 | sdks/ruby-pca/test/test_actions_vectors.rb | test_every_vector_replays |
| C-420 | sdks/ruby-pca/test/test_actions_vectors.rb | test_expand_matches_one_step_oracle |
| C-420 | sdks/php-pca/tests/ActionVectorsTest.php | testEveryVectorReplays |
| C-420 | sdks/java-pca/test/net/atlasauth/pca/ActionVectorsTest.java | void everyVectorReplays |
| C-420 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ActionVectorsTest.kt | everyVectorReplays |
| C-420 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ActionVectorsTest.kt | closureEqualsEightRoundsOfOneStepImplication |
| C-420 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ActionsVectorTests.cs | EveryVectorReplays |
| C-420 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ActionsVectorTests.cs | ExpandAndFloorMatchIndependentOracles |
| C-420 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ActionsVectorTests.swift | testEveryVectorReplays |
| C-420 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ActionsVectorTests.swift | testClosureOracleAndFloorAntitone |
| T-520 | sdks/python-pca/test_actions_vectors.py | test_pinned_values |
| T-520 | sdks/go-pca/actions_vectors_test.go | TestActionsPinnedDigests |
| T-520 | sdks/rust-pca/tests/actions_vectors.rs | fn pinned_digests |
| T-520 | sdks/ruby-pca/test/test_actions_vectors.rb | test_pinned_values |
| T-520 | sdks/php-pca/tests/ActionVectorsTest.php | testPinnedDigests |
| T-520 | sdks/java-pca/test/net/atlasauth/pca/ActionVectorsTest.java | void pinnedDigests |
| T-520 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ActionVectorsTest.kt | pinnedDigests |
| T-520 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ActionsVectorTests.cs | PinnedDigests |
| T-520 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ActionsVectorTests.swift | testPinnedDigests |
| C-20 | packages/pca-harness/src/harness.test.ts | an input with a typo or null provenance counts as UNTRUSTED |
| C-20 | packages/pca-harness/src/harness.test.ts | constructor refuses %s |
| C-20 | packages/pca-harness/src/harness.test.ts | blocks an injected OUT-OF-PLAN action |
| C-21 | packages/pca-control-evals/src/index.test.ts | refuses a vacuous run |
| C-21 | packages/pca-control-evals/src/index.test.ts | gate passes the example suite at a modest bar and fails on every violation |
| C-21 | packages/pca-control-evals/src/index.test.ts | the gate FAILS against a hazard no control encodes |
| C-21 | packages/pca-control-evals/src/index.test.ts | a NaN report value fails the gate |
| C-81 | packages/pca-abe/src/fame.test.ts | decrypts for every satisfying set and refuses every other, matching the boolean oracle |
| C-81 | packages/pca-abe/src/fame.test.ts | collusion: attribute components of two keys do not combine, whole or by component |
| C-81 | packages/pca-abe/src/fame.test.ts | encrypt: an attribute named by two leaves -> PcaEncryptionError (single-use attributes) |
| C-81 | packages/pca-abe/src/fame.test.ts | ciphertext with a tampered tree |
| C-81 | packages/pca-abe/src/audit/fame-differential.test.ts | master, user key and ciphertext points are byte-identical |
| C-82 | packages/pca-fhe/src/origin.test.ts | ATTACK: anyone with the PUBLIC key can mint a ciphertext of any slack - unsigned claims are refused |
| C-82 | packages/pca-fhe/src/origin.test.ts | REPLAY: the same signed claim is accepted once per guard; a refused claim does not burn its nonce |
| C-82 | packages/pca-fhe/src/audit.test.ts | a gate output decrypted with a DIFFERENT secret key throws |
| C-83 | packages/pca-vdf/src/production.test.ts | vdfVerify / verifyTimelock refuse y = pi = 0, y = pi = N and other non-canonical encodings |
| C-83 | packages/pca-vdf/src/primality.test.ts | the combined test refuses the strong Lucas pseudoprimes and the base-2 strong pseudoprimes |
| C-83 | packages/pca-vdf/src/reference.test.ts | TypeScript eval reproduces the reference y, pi and challenge prime l exactly |
| C-84 | packages/pca-mpc/src/default-offline.test.ts | composeSecureMalicious with no offline option runs the dealer-free phase |
| C-84 | packages/pca-mpc/src/default-offline.test.ts | runParty with offline trusted-dealer and no opt-in aborts before any network use |
| C-84 | packages/pca-mpc/src/fips203-kat.test.ts | reproduces the official ek and dk_pke for every ACVP keyGen case |
| C-84 | packages/pca-mpc/src/selective-failure.test.ts | RT-04 |
| C-40 | packages/pca-goal/test/goal.test.ts | G-T1: compiled decision == reference semantics |
| C-41 | packages/pca-goal/test/goal.test.ts | G-T2: adding a constraint never grows the allow set |
| C-41 | packages/pca-goal/test/goal.test.ts | mutation sensitivity: the probe corpus tells apart every one-step mutant |
| C-42 | packages/pca-goal/test/goal.test.ts | G-T1: compiled decision == reference semantics |
| C-42 | packages/pca-goal/test/goal.test.ts | G-T4: Unknown never yields Allow |
| C-43 | packages/pca-goal/test/goal.test.ts | G-T6: mixed currencies and untyped comparisons are rejected |
| C-43 | packages/pca-goal/test/goal.test.ts | typing: wildcard needs acknowledgement |
| C-44 | packages/pca-goal/test/goal.test.ts | G-T7: a goal with holes compiles |
| C-45 | packages/pca-goal/test/goal.test.ts | G-T10: renderTape is lossless on random goals |
| C-45 | packages/pca-goal/test/goal.test.ts | the card prints every field |
| C-46 | packages/pca-goal/test/goal.test.ts | G-T5: equal goals give byte-identical policies |
| C-41 | packages/pca/src/facade.test.ts | W7a: adding a second count limit never drops the first rate caveat |
| C-41 | packages/pca/src/facade.test.ts | W7b: a $ limit keeps the default co-sign tiers |
| C-43 | packages/pca/src/facade.test.ts | W6: a $ limit on a verb with no amount field is an error |
| T-140 | packages/pca/src/budget-ledger.test.ts | 100 x $19 from 100 different sessions under a $200 principal cap |
| T-140 | packages/pca/src/budget-ledger.test.ts | sessions, grants and agents do not appear in the key: only the principal does |
| T-140 | packages/pca/src/budget-ledger.test.ts | org and principal caps hold together |
| T-140 | packages/pca-store-conformance/src/budget-conformance.test.ts | no cap check |
| T-140 | packages/pca-store-conformance/src/budget-conformance.test.ts | shared keys |
| T-141 | packages/pca/src/budget-ledger.test.ts | a started reservation is never expired by any clock |
| T-141 | packages/pca/src/budget-ledger.test.ts | a tampered, re-keyed or wrong-signer release does not verify |
| T-141 | packages/pca/src/budget-ledger.test.ts | a release of something never reserved credits nothing |
| T-141 | packages/pca-store-conformance/src/budget-conformance.test.ts | late commit |
| T-141 | packages/pca-store-conformance/src/budget-conformance.test.ts | expire started |
| T-142 | packages/pca/src/budget-ledger.test.ts | refuses a volatile ledger for any non-session scope |
| T-142 | packages/pca-store-conformance/src/budget-conformance.test.ts | amnesia |
| T-142 | packages/pca-store-conformance/src/budget-conformance.test.ts | volatile ledger claiming durability |
| G-70 | packages/pca/src/budget-ledger.test.ts | one principal, N sessions and N delegated agents share one cap |
| G-70 | packages/pca-store-conformance/src/budget-conformance.test.ts | durable-state files: every check passes |
| G-71 | packages/pca/src/budget-ledger.test.ts | an expired reservation frees its budget, and a late commit of it is refused |
| G-71 | packages/pca-store-conformance/src/budget-conformance.test.ts | release of a committed event |
| G-72 | packages/pca/src/budget-ledger.test.ts | a session-only root needs no aggregate ledger |
| G-72 | packages/pca-store-conformance/src/budget-conformance.test.ts | every registered bad adapter fails at least one check |
| C-70 | packages/pca/src/budget-ledger.test.ts | 100 x $19 from 100 different sessions under a $200 principal cap |
| C-70 | packages/pca-store-conformance/src/budget-conformance.test.ts | no compare-and-swap |
| C-71 | packages/pca/src/budget-ledger.test.ts | a started reservation is never expired by any clock |
| C-71 | packages/pca-store-conformance/src/budget-conformance.test.ts | expire started |
| C-72 | packages/pca/src/budget-ledger.test.ts | refuses a volatile ledger for any non-session scope |
| C-72 | packages/pca-store-conformance/src/budget-conformance.test.ts | amnesia |
| C-85 | packages/pca-goal/adversarial/test/corpus.test.ts | generator is deterministic (same seeds, byte-identical corpus) |
| C-85 | packages/pca-goal/adversarial/test/corpus.test.ts | committed vectors equal a fresh generation (no drift, no stale files) |
| C-86 | packages/pca-goal/adversarial/test/vectors.test.ts | vectors replay through the reference subject with zero disagreements |
| C-87 | packages/pca-goal/adversarial/test/weaknesses.test.ts | W1 a grant minted for another goal text fails goal_commit opening |
| C-87 | packages/pca-goal/adversarial/test/weaknesses.test.ts | W21 escalate with no valid bound answer is refused by the PEP |
| C-88 | packages/pca-goal/adversarial/test/corpus.test.ts | the corpus kills every mutant not recorded as search-equivalent |
| C-89 | packages/pca-goal/adversarial/test/corpus.test.ts | W7 monotonicity: for random G and constraint c |
| T-150 | packages/pca-goal/adversarial/test/harness.ts | GOAL_REQUIRE_SUBJECT=1 but @atlasauth/pca-goal could not be imported |
| T-151 | packages/pca-goal/adversarial/test/corpus.test.ts | committed vectors equal a fresh generation (no drift, no stale files) |
| T-152 | packages/pca-goal/adversarial/test/corpus.test.ts | every generated goal compiles; every ill-typed variant is rejected with a code |

| C-50 | packages/pca/src/server/decision-escalation.test.ts | escalate is absorbing against allow |
| C-50 | packages/pca/src/server/decision-escalation.test.ts | escalate -> not admitted |
| C-50 | packages/pca/src/server/decision-escalation.test.ts | below the tighten threshold: allow; above: escalate |
| C-50 | packages/pca/src/decision-vectors.test.ts | decision_of |
| C-51 | packages/pca/src/server/decision-escalation.test.ts | no answer, a wrong-action answer |
| C-51 | packages/pca/src/server/decision-escalation.test.ts | a valid answer bound to this policy |
| C-51 | packages/pca/src/server/decision-escalation.test.ts | an answer can never upgrade a deny |
| C-51 | packages/pca/src/server/decision-escalation.test.ts | verifyEscalationAnswer |
| C-52 | packages/pca/src/server/decision-escalation.test.ts | matching tag passes; cents vs dollars |
| C-52 | packages/pca/src/server/decision-escalation.test.ts | a where term that reads a unit-bearing parameter without a tag is refused |
| C-52 | packages/pca/src/decision-vectors.test.ts | units: |
| C-53 | packages/pca/src/server/decision-escalation.test.ts | a model signal can only tighten |
| C-53 | packages/pca/src/server/decision-escalation.test.ts | an adversarial oracle |
| C-53 | packages/pca/src/server/decision-escalation.test.ts | a model-derived path in a grant where is refused |
| C-53 | packages/pca/src/server/decision-escalation.test.ts | a grant whose where reads env.class.* is refused |
| C-54 | packages/pca/src/server/decision-escalation.test.ts | rules: true -> signal, unknown -> escalate |
| C-55 | packages/pca/src/server/decision-escalation.test.ts | the answer can come from the request (header) |
| C-55 | packages/pca/src/server/decision-escalation.test.ts | no answer, a wrong-action answer |
| C-50 | packages/pca/src/decision-vectors.test.ts | fold: |
| C-51 | packages/pca/src/decision-vectors.test.ts | escalation_answer: |
| C-53 | packages/pca/src/model-rules-vectors.test.ts | model-rules-vectors.json |
| C-54 | packages/pca/src/model-rules-vectors.test.ts | model-rules-vectors.json |
| T-120 | packages/pca/src/server/decision-escalation.test.ts | escalate -> not admitted |
| T-120 | packages/pca/src/server/decision-escalation.test.ts | every escalate-class result carries allow:false |
| T-121 | packages/pca/src/server/decision-escalation.test.ts | no answer, a wrong-action answer |
| T-121 | packages/pca/src/server/decision-escalation.test.ts | verifyEscalationAnswer |
| T-122 | packages/pca/src/server/decision-escalation.test.ts | matching tag passes; cents vs dollars |
| T-122 | packages/pca/src/decision-vectors.test.ts | units: |
| T-123 | packages/pca/src/server/decision-escalation.test.ts | a model signal can only tighten |
| T-123 | packages/pca/src/server/decision-escalation.test.ts | a model-derived path in a grant where is refused |

| G-22 | packages/pca/src/server/decision-escalation.test.ts | an answer can never upgrade a deny |
| G-23 | packages/pca/src/server/decision-escalation.test.ts | matching tag passes; cents vs dollars |
| G-24 | packages/pca/src/server/decision-escalation.test.ts | a model signal can only tighten |
| C-100 | packages/pca-oidc/src/hardening-05.test.ts | jwksUri over http is a config error unless requireHttps: false |
| C-100 | packages/pca-oidc/src/hardening-05.test.ts | a key-set request that never answers is aborted and the token refused |
| C-100 | packages/pca-oidc/src/fail-closed.test.ts | stale + unreachable: refused, the old key is NOT reused |
| C-101 | packages/pca-oidc/src/fail-closed.test.ts | alg confusion: HS256 token keyed with the public JWK bytes is refused |
| C-101 | packages/pca-oidc/src/mutation-kill-verify.test.ts | nonce binding |
| C-101 | packages/pca-oidc/src/strict-jws.test.ts | rejects every alias with code invalid_token |
| C-102 | packages/pca-oauth/src/fail-closed.test.ts | parse: the document must be the one asked for |
| C-102 | packages/pca-oauth/src/defaults-05.test.ts | parse without expectedResource is refused unless strict: false |
| C-102 | packages/pca-oauth/src/fail-closed.test.ts | an upstream PCA challenge with a newline cannot be smuggled into the header |
| C-103 | packages/pca-authzen/src/fail-closed.test.ts | a request without a proof is denied by default; requireProof: false opts into static admission |
| C-103 | packages/pca-authzen/src/fail-closed.test.ts | a replayed PCActn is permitted once and then denied |
| C-103 | packages/pca-authzen/src/readme.test.ts | permits the signed action once, then denies the replay |
| C-104 | packages/pca-authzen/src/fail-closed.test.ts | the default bound is 100 items: 100 are evaluated, 101 are refused |
| C-104 | packages/pca-authzen/src/fail-closed.test.ts | an unsupported semantic denies every item |
| T-200 | packages/pca-oidc/src/hardening-05.test.ts | a clock that returns a non-finite time refuses |
| T-200 | packages/pca-oidc/src/fail-closed.test.ts | non-2xx, non-JWKS and oversize key sets are refused |
| T-201 | packages/pca-oidc/src/fail-closed.test.ts | reproduces the OpenID Connect Core example pair |
| T-201 | packages/pca-oidc/src/fail-closed.test.ts | alg "none" is refused |
| T-202 | packages/pca-oauth/src/fail-closed.test.ts | header injection |
| T-202 | packages/pca-oauth/src/fail-closed.test.ts | token-audience binding |
| T-203 | packages/pca-authzen/src/fail-closed.test.ts | without the hook a proof is denied by default (0.5) |
| T-203 | packages/pca-authzen/src/fail-closed.test.ts | a thrown authorizer fails closed |
| T-204 | packages/pca-authzen/src/fail-closed.test.ts | rows that deny |
| T-204 | packages/pca-authzen/src/fail-closed.test.ts | maxEvaluations refuses an oversize boxcar |
| C-105 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | no seenTxn and no explicit opt-out throws the typed error before anything else is read |
| C-105 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | only the literal opt-out value disables the requirement |
| C-105 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | the identifier is consumed last |
| T-205 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | no seenTxn and no explicit opt-out throws the typed error before anything else is read |
| T-205 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | the identifier is consumed last |
| T-205 | packages/pca-txn-tokens/src/fail-closed.test.ts | replay hook: first sight passes, a repeat is refused |
| C-106 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | a free-form tctx is returned verbatim |
| C-106 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | the PCA keys are reserved |
| C-106 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | a tctx that is not a JSON object is refused |
| C-106 | packages/pca-txn-tokens/src/crosscheck.test.ts | python vector: |
| T-206 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | the PCA keys are reserved |
| T-206 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | an rctx that is not a JSON object is refused |
| C-107 | packages/pca-idjag/src/strict-default.test.ts | no consumeJti is a config error |
| C-107 | packages/pca-idjag/src/strict-default.test.ts | a loose-shaped grant |
| C-107 | packages/pca-idjag/src/strict-default.test.ts | the jti is consumed last |
| C-107 | packages/pca-idjag/src/crosscheck.test.ts | python vector: |
| T-207 | packages/pca-idjag/src/strict-default.test.ts | a jti is consumed once |
| T-207 | packages/pca-idjag/src/strict-default.test.ts | only the literal false opts out |
| T-207 | packages/pca-idjag/src/index.test.ts | refuses missing or mismatched client_id |
| C-108 | packages/pca-gnap/src/draft-replay.test.ts | no seenProof and no opt-out throws GnapError |
| C-108 | packages/pca-gnap/src/draft-replay.test.ts | the proof is consumed last |
| C-108 | packages/pca-gnap/src/crosscheck.test.ts | python vector: |
| C-108 | packages/pca-gnap/src/mutation-kill-r2.test.ts | refuses httpsig, mtls, jwsd-vc, unknown, missing and malformed methods |
| T-208 | packages/pca-gnap/src/draft-replay.test.ts | first sight passes, a repeat is refused |
| T-208 | packages/pca-gnap/src/draft-replay.test.ts | a store that throws, or returns anything but false, fails closed |
| T-208 | packages/pca-gnap/src/mutation-kill-r2.test.ts | grantRequestToCapability refuses an httpsig-declared client |
| C-109 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | a token string over MAX_TOKEN_CHARS is refused before any parsing |
| C-109 | packages/pca-idjag/src/strict-default.test.ts | an oversize token is refused before parsing |
| C-109 | packages/pca-gnap/src/draft-replay.test.ts | an oversize detached JWS is refused |
| T-209 | packages/pca-txn-tokens/src/draft-tctx-replay.test.ts | a validly signed oversize token is refused |
| T-209 | packages/pca-idjag/src/strict-default.test.ts | an oversize token is refused before parsing |
| T-209 | packages/pca-gnap/src/draft-replay.test.ts | an oversize detached JWS is refused |
| C-110 | packages/pca-dpop/src/production.test.ts | no store and no flag: refused with the exact code and message |
| C-110 | packages/pca-dpop/src/production.test.ts | is refused as alg_jwk_mismatch |
| C-110 | packages/pca-dpop/src/production.test.ts | refuses to evict a live entry |
| C-111 | packages/pca-dpop/src/production.test.ts | a bound certificate passes and returns the confirmation |
| C-111 | packages/pca-dpop/src/production.test.ts | a different certificate is refused as x5t |
| C-112 | packages/pca-webauthn/src/failure-modes.test.ts | absent storedSignCount is refused |
| C-112 | packages/pca-webauthn/src/failure-modes.test.ts | crossOrigin true is refused by default |
| C-112 | packages/pca-webauthn/src/authenticator-formats.test.ts | synced platform passkey (attestation none) |
| C-113 | packages/pca-signals/src/receive.test.ts | replay: the second delivery of the same SET is refused |
| C-113 | packages/pca-signals/src/revocation-adapters.test.ts | receiveSET refuses with replay_store_error when the store is full |
| C-114 | packages/pca-signals/src/revocation-adapters.test.ts | fails closed on undeterminable input |
| C-114 | packages/pca-signals/src/revocation-adapters.test.ts | a revoked grant_ref, a revoked root capability id and a killed leaf holder each deny |
| T-210 | packages/pca-dpop/src/production.test.ts | no store and no flag: refused with the exact code and message |
| T-210 | packages/pca-dpop/src/production.test.ts | is refused as alg_jwk_mismatch |
| T-211 | packages/pca-dpop/src/production.test.ts | a different certificate is refused as x5t |
| T-212 | packages/pca-webauthn/src/failure-modes.test.ts | absent storedSignCount is refused |
| T-212 | packages/pca-webauthn/src/failure-modes.test.ts | crossOrigin true is refused by default |
| T-213 | packages/pca-signals/src/receive.test.ts | replay: the second delivery of the same SET is refused |
| T-214 | packages/pca-signals/src/revocation-adapters.test.ts | a revoked grant_ref, a revoked root capability id and a killed leaf holder each deny |
| C-115 | packages/pca-spiffe/src/revocation.test.ts | refuses a revoked leaf with svid_revoked |
| C-115 | packages/pca-spiffe/src/revocation.test.ts | refuses when the check throws |
| C-115 | packages/pca-spiffe/src/revocation.test.ts | refuses any answer that is not exactly a boolean |
| C-115 | packages/pca-spiffe/src/revocation.test.ts | keeps the last good snapshot through a failed refresh |
| C-115 | packages/pca-spiffe/src/go-spiffe.crosscheck.test.ts | X.509-SVID chains: same accept/reject as go-spiffe |
| T-215 | packages/pca-spiffe/src/revocation.test.ts | refuses a revoked signing certificate with chain_revoked |
| T-215 | packages/pca-spiffe/src/revocation.test.ts | refuses a revocation option that is not a function |
| T-215 | packages/pca-spiffe/src/go-spiffe.crosscheck.test.ts | JWT-SVIDs: same accept/reject as go-spiffe |
| C-116 | packages/pca-ciba/src/store-conformance.test.ts | the reference stores pass the conformance suite |
| C-116 | packages/pca-ciba/src/store-conformance.test.ts | a non-atomic check-then-write |
| C-116 | packages/pca-ciba/src/approval.test.ts | a decision cannot be replayed |
| T-216 | packages/pca-ciba/src/store-conformance.test.ts | a store that does not bump the version |
| T-216 | packages/pca-ciba/src/store-conformance.test.ts | a store that forgets everything on restart |
| C-117 | packages/pca-ciba/src/approval.test.ts | requires a store and a positive ttl |
| C-117 | packages/pca-ciba/src/store-conformance.test.ts | refuses a stored record that is not valid JSON |
| T-217 | packages/pca-ciba/src/store-conformance.test.ts | fails closed with lock_timeout when a stale lock is present |
| T-217 | packages/pca-ciba/src/store-conformance.test.ts | keys cannot escape the directory |
| C-118 | packages/pca-scim/src/rfc-vectors.test.ts | unsupported RFC filter is 400 invalidFilter with the exact body |
| C-118 | packages/pca-scim/src/index.test.ts | unsupported filters are rejected, never ignored |
| T-218 | packages/pca-scim/src/rfc-vectors.test.ts | every other RFC operator form is refused by the parser |
| C-119 | packages/pca-scim/src/index.test.ts | required authentication hook (fail closed) |
| C-119 | packages/pca-scim/src/rfc-vectors.test.ts | RFC "add" of an attribute the resource does not define |
| T-219 | packages/pca-scim/src/index.test.ts | does not touch the store when denied |
| T-219 | packages/pca-scim/src/rfc-vectors.test.ts | RFC "remove" of a member by value path is refused |
| C-120 | packages/pca-agent/src/agent.test.ts | 200 with a receipt whose inclusion proof does not verify: error bad_response, not allowed |
| C-120 | packages/pca-agent/src/agent.test.ts | allow:true at top level but verdict.allow false: denied |
| C-120 | packages/pca-agent/src/agent.test.ts | a truthy non-boolean allow ("true", 1): denied |
| C-121 | packages/pca-agent/src/agent.test.ts | missing plan_root in the commit response: commitPlan throws bad_response and no plan is kept |
| C-121 | packages/pca-agent/src/agent.test.ts | mutating the node array after commit does not change the plan the agent acts on |
| C-122 | packages/pca-agent/src/agent.test.ts | awaitStepUp: 404 stops polling and is denied with the status |
| C-122 | packages/pca-agent/src/agent.test.ts | awaitStepUp: denied and expired are passed through; a network failure throws network |
| C-123 | packages/pca-payments/src/properties.test.ts | concurrent atomic charges commit exactly what the store debited, never more than the cap |
| C-123 | packages/pca-payments/src/minor-units.test.ts | mandate terms must be integer minor units by default |
| C-123 | packages/pca-payments/src/minor-units.test.ts | a merchant id containing a star on the charge side matches no allowlist entry |
| C-123 | packages/pca-payments/src/minor-units.test.ts | a stored balance above bMax is clamped to the signed bMax |
| C-124 | packages/pca-acp/src/strict-default.test.ts | no single-use store: refused with the exact reason |
| C-124 | packages/pca-acp/src/strict-default.test.ts | with both, the token redeems exactly once |
| C-124 | packages/pca-acp/src/strict-default.test.ts | a grant without the pcActn to re-verify is refused, not silently skipped |
| C-125 | packages/pca-acp/src/strict-default.test.ts | carries maxTimeoutSeconds and a body error, and refuses a missing payee or asset |
| C-125 | packages/pca-acp/src/strict-default.test.ts | maps to the ACP delegate_payment allowance exactly |
| C-126 | packages/pca-invariants/src/teeth.test.ts | every registered invariant has a negative control above (a new invariant without one fails here) |
| T-220 | packages/pca-agent/src/agent.test.ts | 200 with a receipt whose inclusion proof does not verify |
| T-221 | packages/pca-agent/src/agent.test.ts | awaitStepUp: 404 stops polling |
| T-222 | packages/pca-payments/src/minor-units.test.ts | mandate terms must be integer minor units by default |
| T-223 | packages/pca-acp/src/strict-default.test.ts | with both, the token redeems exactly once |
| C-127 | packages/pca-notary/src/index.test.ts | a LIE about the disclosed value fails inclusion |
| C-127 | packages/pca-notary/src/index.test.ts | a proof whose size differs from the committed leaf count is refused even when its path has the right length |
| C-127 | packages/pca-notary/src/track6.test.ts | an unlisted key is refused with the exact reason |
| C-127 | packages/pca-notary/src/track6.test.ts | a revoked key is refused for any observation time, including backdated ones |
| C-127 | packages/pca-notary/src/track6.test.ts | an admitted fact is labelled notary-trusted; a refusal carries no trust label |
| T-224 | packages/pca-notary/src/index.test.ts | a LIE about the disclosed value fails inclusion |
| T-224 | packages/pca-notary/src/track6.test.ts | a disclosure from another attestation of the same body does not verify under this one |
| C-128 | packages/pca-sdjwt/src/fail-closed-table.test.ts | requireKeyBinding without a KB-JWT: the exact reason |
| C-128 | packages/pca-sdjwt/src/fail-closed-table.test.ts | a required disclosure that was withheld: the exact reason |
| C-128 | packages/pca-sdjwt/src/fail-closed-table.test.ts | key binding: wrong nonce, wrong key, stale iat |
| C-128 | packages/pca-sdjwt/src/fail-closed-table.test.ts | a withheld %s is denied with the exact reason |
| T-225 | packages/pca-sdjwt/src/fail-closed-table.test.ts | requireKeyBinding without a KB-JWT: the exact reason |
| T-225 | packages/pca-sdjwt/src/fail-closed-table.test.ts | a duplicated disclosure and an empty disclosure segment are refused |
| C-129 | packages/pca-vc/src/mutation-kill.test.ts | vc claim checks |
| C-129 | packages/pca-vc/src/mutation-kill.test.ts | disclosures: digest membership, duplicates, shape, names and values |
| C-129 | packages/pca-vc/src/binding.test.ts | a JWT sub that differs from credentialSubject.id is refused |
| C-129 | packages/pca-vc/src/binding.test.ts | expectedIssuerDid: matching passes, any other issuer is refused |
| C-129 | packages/pca-vc/src/context.test.ts | accepts the emitted pair; the issuer emits exactly it |
| C-129 | packages/pca-vc/src/context.test.ts | defines every term the issuer emits in credentialSubject |
| C-130 | packages/pca-vc/src/mutation-kill.test.ts | verifies an honest signature and rejects any tamper |
| C-130 | packages/pca-vc/src/mutation-kill.test.ts | requiredComponents |
| C-130 | packages/pca-vc/src/mutation-kill.test.ts | freshness window: maxAgeSec and 5 s of allowed clock lead, inclusive at the edges |
| C-130 | packages/pca-vc/src/mutation-kill.test.ts | a malformed URL or header set never throws |
| T-226 | packages/pca-vc/src/mutation-kill.test.ts | vc claim checks |
| C-131 | packages/pca-webbotauth/src/signed-directory.test.ts | a different authority (replay at another host) is refused |
| C-131 | packages/pca-webbotauth/src/signed-directory.test.ts | only keys with a valid signature are returned (an unsigned key is ignored) |
| C-131 | packages/pca-webbotauth/src/signed-directory.test.ts | a signature that covers anything other than @authority;req is refused |
| C-131 | packages/pca-webbotauth/src/signed-directory.test.ts | throws when the response is unsigned, or signed for another host |
| T-227 | packages/pca-webbotauth/src/signed-directory.test.ts | a changed body (a swapped key) does not change what the signature vouches for: the extra key is dropped |
| C-132 | packages/pca-scitt/src/durable.test.ts | roots, inclusion receipts and consistency proofs for 1..70 entries |
| C-132 | packages/pca-scitt/src/durable.test.ts | a new service over the same store continues the same log (restart) |
| C-132 | packages/pca-scitt/src/durable.test.ts | a missing subtree hash is store_corrupt, never a wrong root |
| C-132 | packages/pca-scitt/src/durable.test.ts | a store is required, with the right shape |
| C-132 | packages/pca-scitt/src/durable.test.ts | appends and proofs do not read the whole log: store reads stay logarithmic at 1024 entries |
| C-132 | packages/pca-scitt/src/file-store.test.ts | a torn final record (crash mid-append) is discarded and the log stays consistent |
| C-132 | packages/pca-scitt/src/file-store.test.ts | corruption before the end of the file is store_corrupt, never silently dropped |
| C-132 | packages/pca-scitt/src/testing.test.ts | the in-memory reference log and store are only on /testing, never on the main entry |
| C-133 | packages/pca-scitt/src/index.test.ts | requires at least one anchor (no treeRoot and no verificationKey => false) |
| C-133 | packages/pca-scitt/src/index.test.ts | a tampered statement fails (inclusion binding + signature both break) |
| C-133 | packages/pca-scitt/src/index.test.ts | a forged receipt fails (bad TS signature, and a tampered inclusion proof) |
| C-133 | packages/pca-scitt/src/index.test.ts | a wrong root fails |
| T-228 | packages/pca-scitt/src/durable.test.ts | roots, inclusion receipts and consistency proofs for 1..70 entries |
| T-228 | packages/pca-scitt/src/durable.test.ts | a new service over the same store continues the same log (restart) |
| C-134 | packages/pca-a2a/src/a2a-card.test.ts | section 3.2.2: the published example |
| C-134 | packages/pca-a2a/src/a2a-card.test.ts | section 3.2.3: members sort by UTF-16 code units (the emoji sorts before U+FB33) |
| C-134 | packages/pca-a2a/src/a2a-card.test.ts | agrees with an independent reference on a generated corpus |
| C-134 | packages/pca-a2a/src/a2a-card.test.ts | issue refuses an invalid card under schema a2a-1.0 and signs a valid one; verify enforces it too |
| C-134 | packages/pca-a2a/src/a2a-card.test.ts | a card whose keys differ in UTF-16 vs UTF-8 order signs over the JCS bytes (a JCS verifier would accept it) |
| C-134 | packages/pca-a2a/src/a2a-card.test.ts | reports each wrong type with its exact path |
| C-135 | packages/pca-a2a/src/mandate-binding.test.ts | another amount or currency around the same valid PCActn is refused |
| C-135 | packages/pca-a2a/src/mandate-binding.test.ts | the params plaintext is required, and must open the committed params_digest (even when requireChecks omits it) |
| C-135 | packages/pca-a2a/src/mandate-binding.test.ts | every x_pca field must be the PCActn |
| C-135 | packages/pca-a2a/src/mandate-binding.test.ts | human_present: a boolean, and true only with a verified t=3 principal co-signature |
| C-135 | packages/pca-a2a/src/a2a-full-verifier.test.ts | a self-minted chain naming the victim as issuer is refused (signed by the attacker key) |
| C-135 | packages/pca-a2a/src/a2a-full-verifier.test.ts | verifyA2ATask / verifyA2APaymentMandate / pcaA2AMiddleware refuse a config with neither grant nor expectedRootIssuer |
| C-136 | packages/pca-agentcard/src/index.test.ts | rejects a forged card (body mutated after signing) |
| C-136 | packages/pca-agentcard/src/index.test.ts | rejects a mutated passport pointer (the whole card body is signed) |
| C-136 | packages/pca-agentcard/src/index.test.ts | rejects an unsigned card (fail closed) |
| C-136 | packages/pca-agentcard/src/index.test.ts | fails closed on an attestation about a DIFFERENT subject |
| C-136 | packages/pca-agentcard/src/index.test.ts | fails closed on an EXPIRED attestation |
| T-229 | packages/pca-a2a/src/a2a-card.test.ts | PCA canonical JSON orders those keys by UTF-8 bytes instead, so it is NOT JCS for such keys (why cards use JCS) |
| T-229 | packages/pca-a2a/src/a2a-card.test.ts | section 3.2.2: the published example |
| T-230 | packages/pca-a2a/src/mandate-binding.test.ts | another amount or currency around the same valid PCActn is refused |
| C-137 | packages/pca-ap2/src/pca.test.ts | refuses a grant not signed by the expected principal, and a wrong PCA audience |
| C-137 | packages/pca-ap2/src/pca.test.ts | refuses x_pca terms that do not match the grant envelope or risk policy |
| C-137 | packages/pca-ap2/src/pca.test.ts | refuses an open mandate whose AP2 constraints are wider than the PCA terms |
| C-137 | packages/pca-ap2/src/pca.test.ts | refuses a PCActn that does not commit to this AP2 charge |
| C-137 | packages/pca-ap2/src/pca.test.ts | refuses when the AP2 amount, payee or instrument no longer matches what the PCActn committed |
| C-137 | packages/pca-ap2/src/pca.test.ts | an agent that understates its own risk is refused |
| C-137 | packages/pca-ap2/src/minor-unit-terms.test.ts | a legacy fractional major-unit mandate is refused with the exact reason |
| C-137 | packages/pca-ap2/src/minor-unit-terms.test.ts | JPY (0): budget is cap / 100, so the SDK x100 read is exactly the cap (a major-unit reader reads less); amount_range stays in yen |
| C-137 | packages/pca-ap2/src/minor-unit-terms.test.ts | 27999 minor (USD 279.99) with a human co-sign verifies |
| T-231 | packages/pca-ap2/src/minor-unit-terms.test.ts | JPY (0): budget is cap / 100, so the SDK x100 read is exactly the cap (a major-unit reader reads less); amount_range stays in yen |
| T-231 | packages/pca-ap2/src/minor-unit-terms.test.ts | USD (2): exact for both readers, including caps whose x100 product is inexact in floating point (29, 57, 58, 115) |
| C-138 | packages/pca-acp/src/x402-v2-spt.test.ts | the specification PaymentRequired example is valid, and its header round-trips |
| C-138 | packages/pca-acp/src/x402-v2-spt.test.ts | picks the highest common version; a client that says nothing gets v1; no overlap is undefined |
| C-138 | packages/pca-acp/src/x402-v2-spt.test.ts | a v2 payload that accepted something the server did not offer is refused |
| C-138 | packages/pca-acp/src/x402-v2-spt.test.ts | a v2 payload settles under a strict verifier; the client merchant is never read |
| C-138 | packages/pca-acp/src/x402-v2-spt.test.ts | v1 still settles exactly as before |
| C-138 | packages/pca-acp/src/x402-http.test.ts | a missing header is 402; an undecodable or invalid one is 400 with the reason; it never throws |
| C-138 | packages/pca-acp/src/x402-http.test.ts | the specification SettlementResponse example round-trips |
| C-138 | packages/pca-acp/src/x402-http.test.ts | a settled outcome is 200 with success true; a failure is 402 with success false, the reason and an empty transaction |
| C-139 | packages/pca-acp/src/x402-v2-spt.test.ts | the published example object is well formed |
| C-139 | packages/pca-acp/src/x402-v2-spt.test.ts | usability: exact boundary of the amount, expiry, currency, mode and deactivation |
| C-139 | packages/pca-acp/src/x402-v2-spt.test.ts | a token may be no wider than the delegated payment token it serves |
| C-139 | packages/pca-payments/src/minor-units.test.ts | is the auto-approve threshold, in lowercase minor units, expiring with the period |
| C-139 | packages/pca-payments/src/minor-units.test.ts | refuses when no autonomous capacity is left, after the period ended, and for a bad clock |
| T-232 | packages/pca-acp/src/x402-v2-spt.test.ts | a v2 payload that accepted something the server did not offer is refused |
| T-232 | packages/pca-acp/src/x402-v2-spt.test.ts | a token may be no wider than the delegated payment token it serves |
| T-240 | packages/pca/src/frontier-signals.test.ts | G-T9 over the frontier signals |
| C-140 | packages/pca/src/frontier-signals.test.ts | G-T9 over the frontier signals |
| C-141 | packages/pca/src/frontier-signals.test.ts | tightenRiskInputs: the objective path can only raise risk |
| T-241 | packages/pca/src/x509-chain-unification.test.ts | strictChainError: the shared profile |
| C-142 | packages/pca/src/x509-chain-unification.test.ts | strictChainError: the shared profile |
| T-242 | packages/pca/src/intent-dod1-audit2.test.ts | B16: the library default refuses self-reported state |
| C-143 | packages/pca/src/intent-dod1-audit.test.ts | B16: requireDurable defaults to true and refuses a volatile store |
| C-144 | packages/pca/src/optimistic-no-memory-default.test.ts | B17: no in-memory default in ext/optimistic |

| C-160 | packages/pca/src/frost-nonce-clone.test.ts | a byte-clone of spent nonces is refused for a second message |
| C-160 | packages/pca/src/frost-nonce-recovery.test.ts | a crash after the spent marker and before the share leaves the session unusable, not reusable |
| C-160 | packages/pca/src/frost-nonce-recovery.test.ts | a store that fails on spend means no signature share is released, and the nonces were not consumed |
| C-160 | packages/pca/src/frost.test.ts | trusted-dealer key split reproduces the RFC shares + group public key |
| C-160 | packages/pca/src/ct-scalar.test.ts | add, sub, mul agree on edge values and 300 random pairs |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | run produces one group key that signs |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | claims another identifier than its authenticated sender is refused with `identity` |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | stamped with another session is refused with `wrong-session` |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | a broadcast echo that differs per recipient aborts with `equivocation` |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | a missing message at the timeout aborts the run with `timeout` and no key |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | a peer with an unpinned certificate gets no link |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | a plaintext client is dropped and never becomes a link |
| C-161 | packages/pca/src/frost-dkg-channel.test.ts | a TLS 1.2 client is refused |
| C-162 | packages/pca/src/frost-net-decoders.test.ts | decodeCommitments refuses a non-list and a list above the maximum signing set |
| C-162 | packages/pca/src/frost-dkg-channel.test.ts | an oversize message is refused with `oversize` before it is parsed |
| C-162 | packages/pca/src/frost-dkg-channel.test.ts | reject %j with a typed error |
| C-171 | packages/pca-pq-threshold/src/consolidation.test.ts | an aggregate produced by core signHybridFrostCosign is accepted as the classical half |
| C-171 | packages/pca-pq-threshold/src/consolidation.test.ts | both verifiers agree on valid, flipped, truncated, non-canonical and wrong-key aggregates |
| T-260 | packages/pca/src/frost-dkg-channel.test.ts | claims another identifier than its authenticated sender is refused with `identity` |
| T-260 | packages/pca/src/frost-dkg-channel.test.ts | a peer with an unpinned certificate gets no link |
| T-261 | packages/pca/src/frost-dkg-channel.test.ts | is `duplicate`; a different second message is `equivocation` |
| T-261 | packages/pca/src/frost-dkg-channel.test.ts | a broadcast echo that differs per recipient aborts with `equivocation` |
| T-262 | packages/pca/src/frost-net-decoders.test.ts | decodeCommitments refuses a non-list and a list above the maximum signing set |
| T-262 | packages/pca/src/frost-dkg-channel.test.ts | an oversize message is refused with `oversize` before it is parsed |
| T-263 | packages/pca/src/frost-nonce-recovery.test.ts | a crash after the spent marker and before the share leaves the session unusable, not reusable |
| C-171 | packages/pca-pq-threshold/src/pq-quorum-v2.test.ts | a version 1 artifact (no pq version, bare-message co-signatures) is refused with the version 1 reason |
| C-171 | packages/pca-pq-threshold/src/pq-quorum-v2.test.ts | relabelling a version 1 artifact as version 2 fails |
| C-171 | packages/pca-pq-threshold/src/pq-quorum-v2.test.ts | under-threshold, duplicate and wrong-set quorums are refused with exact counts |
| C-171 | packages/pca-pq-threshold/src/pq-quorum-v2.test.ts | an artifact without a version, or with an unknown one, is refused |
| T-264 | packages/pca-pq-threshold/src/pq-quorum-v2.test.ts | the pq block version is checked on its own |
| T-264 | packages/pca-pq-threshold/src/pq-quorum-v2.test.ts | relabelling a version 1 artifact as version 2 fails |
| T-264 | packages/pca-pq-threshold/src/consolidation.test.ts | both verifiers agree on valid, flipped, truncated, non-canonical and wrong-key aggregates |
| C-163 | packages/pca/src/zk-bound.test.ts | enforces the risk pin: equal halves pass |
| C-163 | packages/pca/src/zk-bound.test.ts | is labelled policyvm_snark only when action, policy, plan and risk are all pinned |
| C-163 | packages/pca/src/zk-circuits-ci.test.ts | perturbing private input %s: the witness is refused or a public signal changes |
| C-163 | packages/pca/src/zk-circuits-ci.test.ts | a deny witness is refused |
| C-163 | packages/pca/src/zk-circuit-version.test.ts | the committed versions equal the ones recomputed |
| C-163 | packages/pca/src/zk-bound-e2e.test.ts | refuses a tampered signal, a wrong risk pin |
| C-164 | packages/pca/src/zk-arkworks-xcheck.test.ts | arkworks agrees with the package verifier |
| C-164 | packages/pca/src/zk-arkworks-xcheck.test.ts | has the exact case count |
| T-265 | packages/pca/src/zk-circuits-ci.test.ts | perturbing private input %s: the witness is refused or a public signal changes |
| T-266 | packages/pca/src/zk-bound.test.ts | enforces the risk pin: equal halves pass |
| T-266 | packages/pca/src/zk-circuits-ci.test.ts | v2: changing a risk magnitude to another valid value |
| T-267 | packages/pca/src/zk-bound.test.ts | the v1 backend refuses a v2 envelope and the v2 backend refuses a v1 envelope |
| T-267 | packages/pca/src/zk-circuit-version.test.ts | refuses every mismatch: circuit, sources, constraint system, key, shape |
| T-268 | packages/pca/src/zk-arkworks-xcheck.test.ts | arkworks agrees with the package verifier |
| T-268 | packages/pca/src/zk-bound.test.ts | refuses a field-negative (non-canonical, >= 2^64) context signal |
| T-269 | packages/pca/src/zk-ceremony.test.ts | backends report single-party by default and multi-party only with evidence for their circuit |
| C-165 | packages/pca/src/kem-acvp.test.ts | key generation: (d, z) reproduces |
| T-270 | packages/pca/src/kem-acvp.test.ts | key generation: (d, z) reproduces |
| C-165 | packages/pca/src/kem-acvp.test.ts | encapsulation: the primitive PCA wraps |
| T-270 | packages/pca/src/kem-acvp.test.ts | encapsulation: the primitive PCA wraps |
| C-165 | packages/pca/src/kem-acvp.test.ts | hybrid decapsulation: a valid NIST ciphertext |
| T-270 | packages/pca/src/kem-acvp.test.ts | hybrid decapsulation: a valid NIST ciphertext |
| C-165 | packages/pca/src/kem-acvp.test.ts | the implicit-rejection secret differs |
| T-270 | packages/pca/src/kem-acvp.test.ts | the implicit-rejection secret differs |
| C-165 | packages/pca/src/kem-acvp.test.ts | decapsulation-key check (FIPS 203 |
| T-270 | packages/pca/src/kem-acvp.test.ts | decapsulation-key check (FIPS 203 |
| C-165 | packages/pca/src/kem-acvp.test.ts | encapsulation-key check (FIPS 203 |
| T-270 | packages/pca/src/kem-acvp.test.ts | encapsulation-key check (FIPS 203 |
| C-165 | packages/pca/src/kem-acvp.test.ts | the key checks reject wrong lengths |
| T-270 | packages/pca/src/kem-acvp.test.ts | the key checks reject wrong lengths |
| C-165 | packages/pca/src/kem-acvp.test.ts | the derandomized X-Wing encapsulation carries |
| T-270 | packages/pca/src/kem-acvp.test.ts | the derandomized X-Wing encapsulation carries |
| C-166 | packages/pca-aggsig/src/rogue-subgroup.test.ts | a key built as a*G - pk_victim is refused |
| T-271 | packages/pca-aggsig/src/rogue-subgroup.test.ts | a key built as a*G - pk_victim is refused |
| C-166 | packages/pca-aggsig/src/rogue-subgroup.test.ts | a proof of possession is bound to its key |
| T-271 | packages/pca-aggsig/src/rogue-subgroup.test.ts | a proof of possession is bound to its key |
| C-166 | packages/pca-aggsig/src/rogue-subgroup.test.ts | a message signature is not a proof of possession |
| T-271 | packages/pca-aggsig/src/rogue-subgroup.test.ts | a message signature is not a proof of possession |
| C-166 | packages/pca-aggsig/src/rogue-subgroup.test.ts | identity, off-subgroup and wrong-length keys are refused |
| T-271 | packages/pca-aggsig/src/rogue-subgroup.test.ts | identity, off-subgroup and wrong-length keys are refused |
| C-166 | packages/pca-aggsig/src/rogue-subgroup.test.ts | fast aggregation refuses one signer counted twice |
| T-271 | packages/pca-aggsig/src/rogue-subgroup.test.ts | fast aggregation refuses one signer counted twice |
| C-166 | packages/pca-aggsig/src/rogue-subgroup.test.ts | an empty signer set is refused |
| T-271 | packages/pca-aggsig/src/rogue-subgroup.test.ts | an empty signer set is refused |
| T-272 | packages/pca-aggsig/src/rogue-subgroup.test.ts | the identity signature never verifies |
| T-272 | packages/pca-aggsig/src/rogue-subgroup.test.ts | 96-byte values that are off the curve |
| T-272 | packages/pca-aggsig/src/rogue-subgroup.test.ts | keys that cancel to the identity |
| C-167 | packages/pca-bbs/src/audit.test.ts | signature: wrong lengths, identity A, e = 0, e >= r are all rejected |
| T-273 | packages/pca-bbs/src/audit.test.ts | signature: wrong lengths, identity A, e = 0, e >= r are all rejected |
| C-167 | packages/pca-bbs/src/audit.test.ts | public key: identity, wrong length, garbage |
| T-273 | packages/pca-bbs/src/audit.test.ts | public key: identity, wrong length, garbage |
| C-167 | packages/pca-bbs/src/audit.test.ts | a G1 point that is on the curve but outside the prime-order subgroup |
| T-273 | packages/pca-bbs/src/audit.test.ts | a G1 point that is on the curve but outside the prime-order subgroup |
| C-167 | packages/pca-bbs/src/audit.test.ts | proof: identity points (Abar, Bbar, D) |
| T-273 | packages/pca-bbs/src/audit.test.ts | proof: identity points (Abar, Bbar, D) |
| C-167 | packages/pca-bbs/src/audit.test.ts | proof indexes: duplicate, negative, fractional, NaN, out-of-range |
| T-273 | packages/pca-bbs/src/audit.test.ts | proof indexes: duplicate, negative, fractional, NaN, out-of-range |
| C-167 | packages/pca-bbs/src/audit.test.ts | header, presentation header, issuer key, disclosed values and disclosed indexes are each bound |
| T-273 | packages/pca-bbs/src/audit.test.ts | header, presentation header, issuer key, disclosed values and disclosed indexes are each bound |
| C-167 | packages/pca-bbs/src/audit.test.ts | a proof cannot be re-targeted to a credential with extra undisclosed messages |
| T-273 | packages/pca-bbs/src/audit.test.ts | a proof cannot be re-targeted to a credential with extra undisclosed messages |
| C-167 | packages/pca-bbs/src/audit.test.ts | proof malleability: sampled single-bit flips |
| T-273 | packages/pca-bbs/src/audit.test.ts | proof malleability: sampled single-bit flips |
| C-167 | packages/pca-bbs/src/audit.test.ts | replay: a presentation bound to action A fails for action B |
| T-273 | packages/pca-bbs/src/audit.test.ts | replay: a presentation bound to action A fails for action B |
| C-168 | packages/pca-oprf/src/audit.test.ts | rejects the identity element and every wrong length |
| T-274 | packages/pca-oprf/src/audit.test.ts | rejects the identity element and every wrong length |
| C-168 | packages/pca-oprf/src/audit.test.ts | rejects non-canonical field encodings (y >= p) |
| T-274 | packages/pca-oprf/src/audit.test.ts | rejects non-canonical field encodings (y >= p) |
| C-168 | packages/pca-oprf/src/audit.test.ts | scalar boundary: L-1 accepted |
| T-274 | packages/pca-oprf/src/audit.test.ts | scalar boundary: L-1 accepted |
| C-168 | packages/pca-oprf/src/audit.test.ts | server refuses an identity blinded element |
| T-274 | packages/pca-oprf/src/audit.test.ts | server refuses an identity blinded element |
| C-168 | packages/pca-oprf/src/audit.test.ts | a zero or order-L blind is rejected |
| T-274 | packages/pca-oprf/src/audit.test.ts | a zero or order-L blind is rejected |
| C-168 | packages/pca-oprf/src/audit.test.ts | a proof made under another server key never verifies |
| T-274 | packages/pca-oprf/src/audit.test.ts | a proof made under another server key never verifies |
| C-168 | packages/pca-oprf/src/audit.test.ts | proof malleability: non-canonical s or c |
| T-274 | packages/pca-oprf/src/audit.test.ts | proof malleability: non-canonical s or c |
| C-168 | packages/pca-oprf/src/audit.test.ts | exhaustive: every single-bit flip of the proof |
| T-274 | packages/pca-oprf/src/audit.test.ts | exhaustive: every single-bit flip of the proof |
| C-168 | packages/pca-oprf/src/audit.test.ts | cross-mode: a VOPRF-domain proof is not accepted |
| T-274 | packages/pca-oprf/src/audit.test.ts | cross-mode: a VOPRF-domain proof is not accepted |
| C-168 | packages/pca-oprf/src/audit.test.ts | revocation flow: a service that omits the proof in VOPRF mode |
| T-274 | packages/pca-oprf/src/audit.test.ts | revocation flow: a service that omits the proof in VOPRF mode |
| C-168 | packages/pca-oprf/src/audit.test.ts | privateRateToken: a server that omits the proof is refused |
| T-274 | packages/pca-oprf/src/audit.test.ts | privateRateToken: a server that omits the proof is refused |
| T-272 | packages/pca-bbs/src/audit.test.ts | a G1 point that is on the curve but outside the prime-order subgroup |
| T-272 | packages/pca-oprf/src/audit.test.ts | rejects non-canonical field encodings (y >= p) |
| C-166 | packages/pca-aggsig/src/audit.test.ts | keyValidate rejects identity, off-subgroup |
| C-169 | packages/pca-ratchet/src/audit-readiness.test.ts | depth outside [1, max] or fractional -> invalid_depth |
| C-169 | packages/pca-ratchet/src/audit-readiness.test.ts | a state rolled back to a backup signs the same leaf again |
| C-169 | packages/pca-ratchet/src/audit-readiness.test.ts | a spent-leaf store that throws or rejects -> store-error (deny) |
| C-169 | packages/pca-ratchet/src/audit-readiness.test.ts | over-budget, wrong ceiling, malformed commitment and a truncated proof all verify false |
| T-275 | packages/pca-ratchet/src/audit-readiness.test.ts | a state rolled back to a backup signs the same leaf again |
| T-275 | packages/pca-ratchet/src/audit-readiness.test.ts | a nullifier from another root, a missing nullifier or a non-object signature -> invalid |
| C-170 | packages/pca-fndsa/src/index.test.ts | non-canonical base64url (padding, standard alphabet, whitespace, trailing junk) in pq_pk or sig -> false |
| C-170 | packages/pca-fndsa/src/index.test.ts | no backend registered -> verification and signing throw |
| C-170 | packages/pca-fndsa-wasm/src/audit-readiness.test.ts | wrong-size inputs name the field and both sizes |
| C-170 | packages/pca-fndsa-wasm/src/audit-readiness.test.ts | wasm file missing -> importing the binding rejects with the read error |
| T-276 | packages/pca-fndsa/src/index.test.ts | hybrid with a short Ed25519 half or a short FN-DSA half -> false, backend not reached |
| T-276 | packages/pca-fndsa/src/index.test.ts | verify-only backend -> signing throws |
| T-276 | packages/pca-fndsa-wasm/src/audit-readiness.test.ts | wasm file corrupt (not a module) -> importing the binding rejects with a compile error |
| C-172 | packages/pca-attest-eat/src/audit-readiness.test.ts | missing issuer, nonce or channel binding, or an unknown alg -> buildEAT throws the named reason |
| C-172 | packages/pca-attest-eat/src/audit-readiness.test.ts | wrong signer, alg none, HS256 downgrade, missing parts, bad typ |
| C-172 | packages/pca-attest-eat/src/audit-readiness.test.ts | freshness: each missing or wrong input -> its own reason |
| C-172 | packages/pca-attest-eat/src/audit-readiness.test.ts | an AMD hardware check that cannot pass (garbage report and chain) -> contraindicated, never affirming |
| T-277 | packages/pca-attest-eat/src/audit-readiness.test.ts | each failing gate stops the pipeline with ok:false and no tier |
| T-277 | packages/pca-attest-eat/src/audit-readiness.test.ts | channel: no expectation, no cnf, other channel, other key thumbprint -> own reason |
| C-174 | packages/pca-mpc-wasm/src/audit-readiness.test.ts | wrong length -> "expected a 32-byte compressed point, got N" naming the operand |
| C-174 | packages/pca-mpc-wasm/src/audit-readiness.test.ts | wasm file missing -> importing the binding rejects with the read error |
| C-174 | packages/pca-mpc-lwe-ot-wasm/src/audit-readiness.test.ts | wrong length -> "<op>: <argument>: expected N bytes, got M" |
| C-174 | packages/pca-mpc-lwe-ot-wasm/src/audit-readiness.test.ts | hashToRing input: exactly the cap is accepted |
| C-171 | packages/pca/src/pq-quorum-vectors.test.ts | exactly one case is accepted: the v2 block, and every pre-0.5 shape is refused |
| T-280 | packages/pca/src/goal-binding-v3.test.ts | a v3 grant opens under the matching approved_goal and nothing else |
| C-180 | packages/pca/src/goal-binding-v3.test.ts | a v3 grant opens under the matching approved_goal and nothing else |
| T-281 | packages/pca/src/revocation-staleness.test.ts | an epoch older than the cap is denied even before its signed not_after |
| C-181 | packages/pca/src/revocation-staleness.test.ts | an epoch older than the cap is denied even before its signed not_after |
| T-282 | packages/pca/src/server/operations.test.ts | runs fn once with the operation id as idempotency key, records committ |
| C-182 | packages/pca/src/server/operations.test.ts | runs fn once with the operation id as idempotency key, records committ |
| T-283 | packages/pca/src/server/plan-lifecycle.test.ts | executable only when authorized, unexpired, and the nodes still hash t |
| C-183 | packages/pca/src/server/plan-lifecycle.test.ts | executable only when authorized, unexpired, and the nodes still hash t |
| T-284 | packages/pca/src/assurance.test.ts | software, hardware, multi-root and unlabelled verifiers are labelled f |
| C-184 | packages/pca/src/assurance.test.ts | software, hardware, multi-root and unlabelled verifiers are labelled f |
| T-340 | packages/pca/src/forbid-certificate.test.ts | refuses a certificate whose table does not entail its decision |
| T-340 | packages/pca/src/forbid-certificate.test.ts | refuses a self-consistent forgery that does not match the recomputed decision |
| T-340 | packages/pca/src/forbid-certificate.test.ts | refuses a certificate for another action or another policy |
| T-341 | packages/pca/src/forbid-certificate.test.ts | forbid beats permit, whoever signed either |
| T-341 | packages/pca/src/forbid-certificate.test.ts | an order-independent decision |
| T-342 | packages/pca/src/policy-link.test.ts | a slot used for a verb or resource cannot carry a wildcard or regex |
| T-342 | packages/pca/src/policy-link.test.ts | instantiate: $name |
| T-343 | packages/pca/src/policy-link.test.ts | a new template version does not touch an existing link; a tighten overlay narrows it |
| T-343 | packages/pca/src/policy-link.test.ts | a grant whose policy was edited after linking is refused |
| T-344 | packages/pca-analyzer/src/exposure.test.ts | rejects a witness the evaluator refuses |
| T-344 | packages/pca-analyzer/src/exposure.test.ts | labels an unsat claim as unchecked |
| T-344 | packages/pca-analyzer/src/exposure.test.ts | is inconclusive, never equivalent, when the grid overflows |
| T-345 | packages/pca-analyzer/src/narrowing.test.ts | counts, and never uses, observations the agent merely claims |
| T-345 | packages/pca-analyzer/src/narrowing.test.ts | a refused attempt becomes an access request for a human, and never loosens the grant |
| T-345 | packages/pca-analyzer/src/narrowing.test.ts | an observation the policy does not admit cannot widen it |
| T-346 | packages/pca-analyzer/src/residual.test.ts | an unknown that reaches a veto keeps the veto (never prunes it) |
| T-346 | packages/pca-analyzer/src/residual.test.ts | refuses what it cannot express exactly, instead of widening |
| T-346 | packages/pca-analyzer/src/residual.test.ts | the filter selects exactly the rows the evaluator allows (Kleene logic, nulls, vetoes, nested not) |
| T-347 | packages/pca-analyzer/src/flip.test.ts | refuses anyone but the authenticated holder, and rate-limits probing |
| T-347 | packages/pca-analyzer/src/flip.test.ts | redacts the value of a critical parameter to "a repair exists" |
| T-348 | packages/pca-analyzer/src/validate.test.ts | type mismatches |
| T-348 | packages/pca-analyzer/src/validate.test.ts | bounds the schema makes impossible or redundant |
| T-348 | packages/pca-analyzer/src/validate.test.ts | rule 20: a unit-bearing parameter needs the matching unit tag |
| T-349 | packages/pca-analyzer/src/testrunner.test.ts | a policy that drifts but passes every case still fails when the digest is required |
| T-349 | packages/pca-analyzer/src/coverage.test.ts | reports clauses, boundaries and surviving mutants, with the action that kills each |
| C-240 | packages/pca/src/forbid-certificate.test.ts | forbid beats permit, whoever signed either |
| C-240 | packages/pca/src/forbid-certificate.test.ts | an order-independent decision |
| C-240 | packages/pca-invariants/src/teeth.test.ts | forbid-monotone: a decision procedure that lets a permit beat a forbid |
| C-240 | packages/pca-invariants/src/properties.ts | forbidMonotoneProperty |
| C-241 | packages/pca/src/forbid-certificate.test.ts | refuses a certificate whose table does not entail its decision |
| C-241 | packages/pca/src/forbid-certificate.test.ts | refuses a self-consistent forgery that does not match the recomputed decision |
| C-241 | packages/pca/src/forbid-certificate.test.ts | refuses a certificate for another action or another policy |
| C-241 | packages/pca/src/forbid-certificate.test.ts | table: $name |
| C-241 | sdks/python-pca/test_forbid_certificate.py | test_table |
| C-241 | sdks/go-pca/forbid_certificate_test.go | TestForbidCertificateTableVectors |
| C-241 | sdks/ruby-pca/test/test_forbid_certificate.rb | test_table |
| C-242 | packages/pca/src/policy-link.test.ts | the grant carries the reference, covered by the grant signature, and verifies against the registry |
| C-242 | packages/pca/src/policy-link.test.ts | a grant whose policy was edited after linking is refused |
| C-242 | packages/pca/src/policy-link.test.ts | resolve: $name |
| C-242 | sdks/python-pca/test_policy_link.py | test_resolve |
| C-242 | sdks/go-pca/policy_link_test.go | TestPolicyLinkVectors |
| C-242 | sdks/ruby-pca/test/test_policy_link.rb | test_resolve |
| C-243 | packages/pca/src/policy-link.test.ts | a new template version does not touch an existing link; a tighten overlay narrows it |
| C-243 | packages/pca/src/policy-link.test.ts | overlays can only add conditions and caveats |
| C-243 | packages/pca/src/policy-link.test.ts | a slot used for a verb or resource cannot carry a wildcard or regex |
| C-243 | packages/pca/src/policy-link.test.ts | instantiate: $name |
| C-244 | packages/pca-analyzer/src/exposure.test.ts | accepts a witness the evaluator confirms |
| C-244 | packages/pca-analyzer/src/exposure.test.ts | rejects a witness the evaluator refuses |
| C-244 | packages/pca-analyzer/src/exposure.test.ts | labels an unsat claim as unchecked |
| C-244 | packages/pca-analyzer/src/exposure.test.ts | widens: names the actions that moved from deny to allow |
| C-245 | packages/pca-analyzer/src/exposure.test.ts | composes the per-action ceiling with a rate limit over a window |
| C-245 | packages/pca-analyzer/src/exposure.test.ts | applies a universal cap invariant, and leaves out one that does not provably apply |
| C-245 | packages/pca-analyzer/src/exposure.test.ts | an exclusive bound is a supremum for a real, and the largest integer below it for an integer |
| C-245 | packages/pca-analyzer/src/exposure.test.ts | separates the autonomous ceiling from the one with a human |
| C-246 | packages/pca-analyzer/src/exposure.test.ts | is ternary: a drop from allow to escalate is a tightening, escalate to allow a widening |
| C-246 | packages/pca-analyzer/src/exposure.test.ts | is inconclusive, never equivalent, when the grid overflows |
| C-246 | packages/pca-analyzer/src/exposure.test.ts | reports the exposure delta and gates on it |
| C-246 | packages/pca-analyzer/src/exposure.test.ts | flags a child that is wider than its parent |
| C-246 | packages/pca-policy-ci/src/authoring.test.ts | passes a narrowing and an identical policy, fails a widening with a witness line |
| C-247 | packages/pca-analyzer/src/residual.test.ts | the residual decides exactly what the original decides, for every completion of the unknown parameters |
| C-247 | packages/pca-analyzer/src/residual.test.ts | an unknown that reaches a veto keeps the veto (never prunes it) |
| C-247 | packages/pca-analyzer/src/residual.test.ts | a delegation chain keeps every ancestor |
| C-248 | packages/pca-analyzer/src/residual.test.ts | returns the allowed parameter domains and the policy digest |
| C-248 | packages/pca-analyzer/src/residual.test.ts | shows the approval threshold and the enum values |
| C-248 | packages/pca-analyzer/src/residual.test.ts | a regex resource makes the answer approximate rather than wrong |
| C-248 | packages/pca-analyzer/src/residual.test.ts | denied for a verb the policy does not grant, with the reason; passes through budget and discharges |
| C-249 | packages/pca-analyzer/src/residual.test.ts | refuses what it cannot express exactly, instead of widening |
| C-249 | packages/pca-analyzer/src/residual.test.ts | the filter selects exactly the rows the evaluator allows (Kleene logic, nulls, vetoes, nested not) |
| C-249 | packages/pca-analyzer/src/residual.test.ts | escapes LIKE metacharacters and supports ? placeholders |
| C-250 | packages/pca-analyzer/src/narrowing.test.ts | proposes a narrower grant, proven subsumed by the original, and lists what was never used |
| C-250 | packages/pca-analyzer/src/narrowing.test.ts | property: a proposal is never wider than the original, whatever was observed |
| C-250 | packages/pca-analyzer/src/narrowing.test.ts | an observation the policy does not admit cannot widen it |
| C-250 | packages/pca-analyzer/src/narrowing.test.ts | says why there is no proposal when nothing observed matches |
| C-251 | packages/pca-analyzer/src/narrowing.test.ts | counts, and never uses, observations the agent merely claims |
| C-251 | packages/pca-analyzer/src/narrowing.test.ts | a refused attempt becomes an access request for a human, and never loosens the grant |
| C-251 | packages/pca-analyzer/src/narrowing.test.ts | decay: the re-minted grant lapses |
| C-252 | packages/pca-analyzer/src/coverage.test.ts | reports clauses, boundaries and surviving mutants, with the action that kills each |
| C-252 | packages/pca-analyzer/src/coverage.test.ts | boundary traffic and a trigger for each prohibition kill the mutants |
| C-252 | packages/pca-analyzer/src/coverage.test.ts | a mutant the analyzer proves equivalent is not counted against the score |
| C-252 | packages/pca-analyzer/src/coverage.test.ts | a gate fails on missing coverage, and on an unreachable clause |
| C-253 | packages/pca-analyzer/src/validate.test.ts | type mismatches |
| C-253 | packages/pca-analyzer/src/validate.test.ts | bounds the schema makes impossible or redundant |
| C-253 | packages/pca-analyzer/src/validate.test.ts | rule 20: a unit-bearing parameter needs the matching unit tag |
| C-253 | packages/pca-policy-ci/src/authoring.test.ts | --schema checks each linted policy against an action schema file |
| C-254 | packages/pca-analyzer/src/flip.test.ts | lowers the amount to the largest admissible value and verifies it with the real decision |
| C-254 | packages/pca-analyzer/src/flip.test.ts | a hard deny with no repair becomes an access request, not an invented fix |
| C-254 | packages/pca-analyzer/src/flip.test.ts | splitting is opt-in and only when nothing meters the total |
| C-254 | packages/pca-analyzer/src/flip.test.ts | waits for a time caveat to open, verified by the caveat evaluator |
| C-255 | packages/pca-analyzer/src/flip.test.ts | refuses anyone but the authenticated holder, and rate-limits probing |
| C-255 | packages/pca-analyzer/src/flip.test.ts | redacts the value of a critical parameter to "a repair exists" |
| C-256 | packages/pca-analyzer/src/testrunner.test.ts | a policy that drifts but passes every case still fails when the digest is required |
| C-256 | packages/pca-analyzer/src/testrunner.test.ts | signed examples verify, and any edit breaks the signature |
| C-256 | packages/pca-analyzer/src/testrunner.test.ts | the generated examples pass the policy they came from, and catch a widened cap |
| C-260 | packages/pca-grants/src/fresh-at.test.ts | NEW ENEMY: a verifier at an older revocation epoch escalates stale_state, naming the field |
| C-260 | packages/pca-grants/src/fresh-at.test.ts | wrong scope, forgery, future and over-age tokens are denied |
| C-260 | packages/pca-grants/src/fresh-at.test.ts | gateDecision only tightens |
| C-261 | packages/pca-grants/src/fresh-at.test.ts | a token verifies for its signer and for nobody else |
| C-261 | packages/pca-grants/src/fresh-at.test.ts | mergeFreshAt is the field-wise max and never lowers |
| C-261 | packages/pca-grants/src/fresh-at.test.ts | the issuer advances monotonically and its own tokens check ok at once; an old token still passes, a revoke token makes a lagging peer stale |
| C-262 | packages/pca-grants/src/list-authorized.test.ts | returns exactly the capability-permitted objects across pages, each once and in order |
| C-262 | packages/pca-grants/src/list-authorized.test.ts | the relationship can only narrow the capability |
| C-262 | packages/pca-grants/src/list-authorized.test.ts | a cursor cannot be reused with a different subject, filter, policy or limit, or forged |
| C-263 | packages/pca-grants/src/list-authorized.test.ts | the receipt binds policy, freshness, filter and the exact objects |
| C-263 | packages/pca-grants/src/list-authorized.test.ts | enumeration by scraping is stopped by the read accumulator, counting scanned objects not returned ones |
| C-264 | packages/pca-grants/src/bundle.test.ts | accepts k-of-n distinct pinned signatures and reports who signed |
| C-264 | packages/pca-grants/src/bundle.test.ts | one signer twice, an unpinned signer, or a signature over other content do not count |
| C-264 | packages/pca-grants/src/bundle.test.ts | rollback, broken chain, an old verifier and malformed bundles are refused |
| C-265 | packages/pca-grants/src/bundle.test.ts | records are hash-chained and inclusion-provable against a signed head, offline |
| C-265 | packages/pca-grants/src/bundle.test.ts | the stream is gap-free, replay-proof and tamper-evident |
| C-265 | packages/pca-grants/src/bundle.test.ts | masks by data class, not by path |
| C-266 | packages/pca-grants/src/grant-resource.test.ts | narrow by the HOLDER revises in place; the same signature cannot be replayed on the next revision |
| C-266 | packages/pca-grants/src/grant-resource.test.ts | widening needs the PRINCIPAL signature AND a step-up, and makes a new grant id with supersedes (nothing widens in place) |
| C-266 | packages/pca-grants/src/grant-resource.test.ts | orders verbs, resources, ceilings and expiry; incomparable and unbounded-to-bounded are classified |
| C-267 | packages/pca-grants/src/grant-resource.test.ts | revoke: signed by the principal or admin; agent and subtree scopes reach the right grants; the host hook fires |
| C-267 | packages/pca-grants/src/grant-resource.test.ts | a principal only sees its own grants; an admin sees all; routes map to statuses |
| C-268 | packages/pca-grants/src/grant-resource.test.ts | the agent files typed needs; the principal approves a LOWERED amount of an adjustable need and gets a new grant |
| C-268 | packages/pca-grants/src/grant-resource.test.ts | an approval cannot raise an amount, change the target, lower a non-adjustable need, or come from anyone but the principal |
| C-269 | packages/pca-signals/src/ssf-stream.test.ts | unverified -> healthy on a matching single-use state -> degraded after the window |
| C-269 | packages/pca-signals/src/ssf-stream.test.ts | refuses unknown, expired and non-string states; expiry counts toward failing |
| C-269 | packages/pca-signals/src/ssf-stream.test.ts | honours min_verification_interval, the pending cap and the status; paused and disabled never claim revocation freshness |
| C-270 | packages/pca-gnap/src/interaction.test.ts | matches the RFC example for sha-256 and sha3-512 |
| C-270 | packages/pca-gnap/src/interaction.test.ts | REDIRECT finish end to end: user code lookup is case-insensitive, the callback hash validates at the client, the ref is single use |
| C-270 | packages/pca-gnap/src/interaction.test.ts | PUSH finish carries {hash, interact_ref}; a forged hash or foreign nonce does not validate and the ref must not be sent |
| C-271 | packages/pca-authzen/src/search.test.ts | the queried entity id is ignored (stripped before the provider sees it) |
| C-271 | packages/pca-authzen/src/search.test.ts | results are only entities of the searched type, de-duplicated |
| C-271 | packages/pca-authzen/src/search.test.ts | the member table per search type is enforced (400) |
| C-271 | packages/pca-authzen/src/search.test.ts | an unsupported search is 404, a non-search path falls through, a provider that ignores the limit fails closed |
| C-272 | packages/pca/src/fresh-at-member.test.ts | is signed by the leaf signature: swapping the token breaks leaf_signature |
| C-272 | packages/pca/src/fresh-at-member.test.ts | a lagging verifier fails fresh_at with an ESCALATE-class reason (decision escalate, never allow) |
| C-272 | packages/pca/src/fresh-at-member.test.ts | a PCActn that carries the member with no policy is refused; no member and no policy is byte-identical (check absent) |
| C-272 | packages/pca/src/fresh-at-member.test.ts | require: no token escalates; the side-carried form is still read for one release, but the member wins |
| C-273 | apps/api/src/routes/pca.test.ts | enrolment needs the principal signature at revision 0, is once, and is enforced at admission as a tighten-only ceiling |
| C-273 | apps/api/src/routes/pca.test.ts | widening: principal signature + a spent step-up + a registered successor; the old grant is superseded and killed, the new one carries the wider authority |
| C-273 | apps/api/src/routes/pca.test.ts | step-up challenges: unknown, foreign-grant, wrongly signed and replayed approvals are refused |
| C-274 | packages/pca-signals/src/ssf-manage.test.ts | read: one stream, all streams, none; another receiver sees 404, unauthenticated is 401 |
| C-274 | packages/pca-signals/src/ssf-manage.test.ts | PATCH changes only what is present; transmitter-supplied members must match; push delivery is receiver-set; method cannot change |
| C-274 | packages/pca-signals/src/ssf-manage.test.ts | create refuses transmitter-supplied members, unsupported or insecure delivery, unsupported-only events; a second stream is 409 |
| C-272 | packages/pca/src/fresh-at-vectors.test.ts | the committed file is what the reference produces and every case matches its stated intent |
| C-275 | apps/api/src/routes/pca.test.ts | keys outside the closed grammar are refused when written, so nothing is silently unenforced |
| C-275 | apps/api/src/routes/pca.test.ts | max.<param> is a per-action ceiling and needs the parameter plaintext |
| C-275 | apps/api/src/routes/pca.test.ts | sum.<param> is a lifetime total: the action that would cross it is refused and costs nothing |
| C-275 | apps/api/src/routes/pca.test.ts | count caps the number of admitted actions, and concurrent admissions cannot overshoot |
| C-145 | packages/pca-express/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| C-145 | packages/pca-express/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| C-145 | packages/pca-express/src/index.test.ts | is refused at construction without `operation` |
| C-145 | packages/pca-express/src/index.test.ts | 401s an unknown grant_ref |
| C-145 | packages/pca-express/src/index.test.ts | answers 401 with a WWW-Authenticate challenge when no PCActn is presented |
| C-145 | packages/pca-fastify/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| C-145 | packages/pca-fastify/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| C-145 | packages/pca-fastify/src/index.test.ts | is refused at construction without `operation` |
| C-145 | packages/pca-fastify/src/index.test.ts | 401s an unknown grant_ref |
| C-145 | packages/pca-fastify/src/index.test.ts | answers 401 with a WWW-Authenticate challenge when no PCActn is presented |
| C-145 | packages/pca-hono/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| C-145 | packages/pca-hono/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| C-145 | packages/pca-hono/src/index.test.ts | is refused at construction without `operation` |
| C-145 | packages/pca-hono/src/index.test.ts | 401s an unknown grant_ref |
| C-145 | packages/pca-hono/src/index.test.ts | answers 401 with a WWW-Authenticate challenge when no PCActn is presented |
| C-145 | packages/pca-next/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| C-145 | packages/pca-next/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| C-145 | packages/pca-next/src/index.test.ts | is refused at construction without `operation` |
| C-145 | packages/pca-next/src/index.test.ts | 401s an unknown grant_ref |
| C-145 | packages/pca-next/src/index.test.ts | answers 401 with a WWW-Authenticate challenge when no PCActn is presented |
| C-145 | packages/pca-fetch/src/acceptance.test.ts | refuses over-limit, rebound, replayed and misconfigured requests before the handler |
| C-145 | packages/pca-fetch/src/readme-operation.test.ts | runs the refund once with the operation id as idempotency key |
| C-145 | packages/pca-fetch/src/index.test.ts | is refused at construction without `operation` |
| C-145 | packages/pca-fetch/src/index.test.ts | 401s an unknown grant |
| C-145 | packages/pca-fetch/src/index.test.ts | returns 401 + WWW-Authenticate when no PCActn is presented |
| C-146 | packages/pca-mcp/src/fetch.test.ts | adds a fresh PCA-Action for each tools/call, bound to the call |
| C-146 | packages/pca-mcp/src/fetch.test.ts | passes other requests, unmapped tools and non-JSON bodies through unchanged |
| C-146 | packages/pca-mcp/src/fetch.test.ts | honours an audience override |
| C-146 | packages/pca-mcp/src/index.test.ts | returns an MCP error result (not a throw) on an over-cap call and does NOT run the handler |
| C-146 | packages/pca-mcp/src/schema.test.ts | drafts from tools/list |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | a valid proof presented for another tool, another resource or other arguments |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | a replayed proof |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | the challenge never carries request-derived text |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | a verb the grant does not permit (stripe.delete_customer on a refund-only grant) |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | an over-limit amount ($5000 under a $500 limit) |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | no proof, an unregistered grant, a revoked grant, another audience |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | fails closed when a callback throws |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | a call that omits what the full check needs |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | refuses what only admission admits |
| C-147 | packages/pca-mcp-rs/src/tool-call.test.ts | multiInstance: a process-local store is refused |
| C-148 | packages/pca-gateway/src/breaking-05.test.ts | createGateway throws and authorize denies a genuine proof |
| C-148 | packages/pca-gateway/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused |
| C-148 | packages/pca-gateway/src/index.test.ts | denies an unmapped dangerous route by default, even with a valid proof |
| C-148 | packages/pca-gateway/src/index.test.ts | overwrites every x-pca-* header on a pass-through allow so a forged one cannot reach the upstream |
| C-148 | packages/pca-gateway/src/index.test.ts | percent-encoded ; is also ambiguous |
| C-148 | packages/pca-gateway/src/full-policy.test.ts | a $50 refund is allowed once; the replayed proof is refused |
| C-148 | packages/pca-gateway/src/index.test.ts | denies with 403 (wrong-audience) for a proof minted for another resource |
| C-148 | packages/pca-gateway/src/index.test.ts | fails closed (400) when a forged header is present and the request cannot be rewritten |
| C-149 | packages/pca-gateway/src/breaking-05.test.ts | without a replayGuard it throws |
| C-149 | packages/pca-gateway/src/breaking-05.test.ts | requireChecks defaults to [revocation] |
| C-149 | packages/pca-gateway/src/full-policy.test.ts | signature-only mode (explicit since 0.5) admits a $400 body |
| C-149 | packages/pca-gateway/src/breaking-05.test.ts | a revoked grant is refused by the default required check, and a proof is single-use |
| C-149 | packages/pca-gateway/src/index.test.ts | fails closed (503) when the guard throws or is full |
| C-150 | packages/pca-testing/src/index.test.ts | changing the action verb makes expectVerifies throw and expectDenied pass |
| C-150 | packages/pca-store-conformance/src/reference.test.ts | read-then-write: two clients both read "absent" -> two TRUEs for one key (burst and concurrent) |
| C-150 | packages/pca-store-conformance/src/reference.test.ts | volatile store: the durability test sees a consumed nonce / counter come back after restart |
| C-150 | packages/pca-store-conformance/src/reference.test.ts | evicting cache: the retention test sees evicted live records accepted again |
| C-150 | packages/pca-store-conformance/src/runner.test.ts | fail on a violation, unresolved when nothing definite was observed or a key was over budget |
| C-150 | packages/pca-store-conformance/src/cli.test.ts | exit 3 when nothing definite was observed |
| C-150 | packages/pca-testing/src/index.test.ts | defaults to the PCActn aud, fails on a mismatch, opts out on null |
| C-150 | packages/pca-store-conformance/src/runner.test.ts | durability is skipped only when declared non-durable, and the note says why |
| C-151 | packages/pca-ai-sdk/src/index.test.ts | emits a verifiable PCActn |
| C-151 | packages/pca-ai-sdk/src/index.test.ts | fast-fails an over-cap call without running execute |
| C-151 | packages/pca-anthropic/src/index.test.ts | returns an error tool_result for an unmapped tool, without running a handler |
| C-151 | packages/pca-anthropic/src/index.test.ts | returns an error tool_result when the handler throws |
| C-151 | packages/pca-langchain/src/index.test.ts | fast-fails an over-cap call without running the original func |
| C-151 | packages/pca-langchain/src/index.test.ts | guards a tool exposing only invoke() |
| C-151 | packages/pca-llamaindex/src/index.test.ts | fast-fails an over-cap call without running the original call |
| C-151 | packages/pca-openai/src/index.test.ts | does NOT fast-fail an over-cap call |
| C-151 | packages/pca-openai/src/index.test.ts | throws on an unmapped tool name (no PCActn without a mapping) |
| C-152 | packages/pca-mastra/src/full-policy.test.ts | `operation` binds the resource: a proof for another charge is refused |
| C-152 | packages/pca-mastra/src/full-policy.test.ts | a $50 refund runs once; the replayed proof is refused before execute runs |
| C-152 | packages/pca-mastra/src/full-policy.test.ts | a revoked grant is refused before execute runs |
| C-152 | packages/pca-mastra/src/full-policy.test.ts | a tool input that differs from the signed params is refused |
| C-152 | packages/pca-mastra/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused before execute runs |
| C-152 | packages/pca-mastra/src/index.test.ts | blocks a call with NO proof (typed PcaToolDenied/missing), original not called |
| C-152 | packages/pca-mastra/src/index.test.ts | blocks a proof whose verb does not bind to this tool (binding) |
| C-152 | packages/pca-mastra/src/index.test.ts | blocks an INVALID proof (wrong audience → verify fail), original not called |
| C-152 | packages/pca-openai-agents/src/full-policy.test.ts | `operation` binds the resource: a proof for another charge is refused |
| C-152 | packages/pca-openai-agents/src/full-policy.test.ts | a $50 refund runs once; the replayed proof is refused before execute runs |
| C-152 | packages/pca-openai-agents/src/full-policy.test.ts | a revoked grant is refused before execute runs |
| C-152 | packages/pca-openai-agents/src/full-policy.test.ts | a tool input that differs from the signed params is refused |
| C-152 | packages/pca-openai-agents/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused before execute runs |
| C-152 | packages/pca-openai-agents/src/index.test.ts | blocks a call with NO proof (typed PcaToolDenied/missing), original not called |
| C-152 | packages/pca-openai-agents/src/index.test.ts | blocks a proof whose verb does not bind to this tool (binding) |
| C-152 | packages/pca-openai-agents/src/index.test.ts | blocks an INVALID proof (wrong audience → verify fail), original not called |
| C-152 | packages/pca-vercel-ai/src/full-policy.test.ts | `operation` binds the resource: a proof for another charge is refused |
| C-152 | packages/pca-vercel-ai/src/full-policy.test.ts | a $50 refund runs once; the replayed proof is refused before execute runs |
| C-152 | packages/pca-vercel-ai/src/full-policy.test.ts | a revoked grant is refused before execute runs |
| C-152 | packages/pca-vercel-ai/src/full-policy.test.ts | a tool input that differs from the signed params is refused |
| C-152 | packages/pca-vercel-ai/src/full-policy.test.ts | a validly signed $400 refund under a $100 grant is refused before execute runs |
| C-152 | packages/pca-vercel-ai/src/index.test.ts | blocks a call with NO proof (typed PcaToolDenied/missing), original not called |
| C-152 | packages/pca-vercel-ai/src/index.test.ts | blocks a proof whose verb does not bind to this tool (binding) |
| C-152 | packages/pca-vercel-ai/src/index.test.ts | blocks an INVALID proof (wrong audience → verify fail), original not called |
| C-153 | packages/pca-mastra/src/full-policy.test.ts | a missing component throws at construction (fail closed, never a downgrade to signature-only) |
| C-153 | packages/pca-mastra/src/full-policy.test.ts | pcaTools forwards `authorize`, and a per-tool `verify` replaces it for that tool |
| C-153 | packages/pca-openai-agents/src/full-policy.test.ts | a missing component throws at construction (fail closed, never a downgrade to signature-only) |
| C-153 | packages/pca-openai-agents/src/full-policy.test.ts | pcaTools forwards `authorize`, and a per-tool `verify` replaces it for that tool |
| C-153 | packages/pca-openai-agents/src/index.test.ts | pcaInputGuardrail trips on a run with no proof and passes with a valid one |
| C-153 | packages/pca-openai-agents/src/index.test.ts | pcaToolGuard trips on a wrong-audience proof |
| C-153 | packages/pca-vercel-ai/src/full-policy.test.ts | a missing component throws at construction (fail closed, never a downgrade to signature-only) |
| C-153 | packages/pca-vercel-ai/src/full-policy.test.ts | pcaTools forwards `authorize`, and a per-tool `verify` replaces it for that tool |
| C-154 | packages/pca-mastra/src/index.test.ts | guardStep runs a safe step through, and lets an approved step-up through |
| C-154 | packages/pca-mastra/src/index.test.ts | guardStep throws PcaStepDenied when the grant forbids the step |
| C-154 | packages/pca-mastra/src/index.test.ts | guardStep throws PcaStepUpRequired on a risky step and routes it to onStepUp (original not run) |
| C-154 | packages/pca-openai-agents/src/index.test.ts | pcaNeedsApproval returns true for a risky tool and routes a step-up, false for a safe one |
| C-154 | packages/pca-openai-agents/src/index.test.ts | withApproval sets needsApproval on the tool; an already-approved step-up is let through |
| C-154 | packages/pca-vercel-ai/src/index.test.ts | prepareStep lets an already-approved step-up through (no change) |
| C-154 | packages/pca-vercel-ai/src/index.test.ts | prepareStep removes a risky tool from the next step and routes it to step-up |
| C-155 | sdks/agent-framework-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| C-155 | sdks/agent-framework-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| C-155 | sdks/agent-framework-pca/test_authorize.py | test_missing_store_refused |
| C-155 | sdks/agent-framework-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| C-155 | sdks/agent-framework-pca/test_authorize.py | test_replay_refused |
| C-155 | sdks/agent-framework-pca/test_authorize.py | test_revoked_refused |
| C-155 | sdks/agent-framework-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| C-155 | sdks/agent-framework-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| C-155 | sdks/agent-framework-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| C-155 | sdks/agent-framework-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| C-155 | sdks/crewai-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| C-155 | sdks/crewai-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| C-155 | sdks/crewai-pca/test_authorize.py | test_missing_store_refused |
| C-155 | sdks/crewai-pca/test_authorize.py | test_positional_arguments_cannot_be_bound |
| C-155 | sdks/crewai-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| C-155 | sdks/crewai-pca/test_authorize.py | test_replay_refused |
| C-155 | sdks/crewai-pca/test_authorize.py | test_revoked_refused |
| C-155 | sdks/crewai-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| C-155 | sdks/crewai-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| C-155 | sdks/crewai-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| C-155 | sdks/crewai-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_missing_store_refused |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_replay_refused |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_revoked_refused |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| C-155 | sdks/fastmcp-pca/test_authorize.py | test_wildcard_capability_refused |
| C-155 | sdks/fastmcp-pca/test_fastmcp_pca.py | test_missing_proof_is_rejected |
| C-155 | sdks/fastmcp-pca/test_fastmcp_pca.py | test_tampered_proof_fails_signature |
| C-155 | sdks/fastmcp-pca/test_fastmcp_pca.py | test_wrong_audience_is_rejected |
| C-155 | sdks/google-adk-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| C-155 | sdks/google-adk-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| C-155 | sdks/google-adk-pca/test_authorize.py | test_missing_store_refused |
| C-155 | sdks/google-adk-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| C-155 | sdks/google-adk-pca/test_authorize.py | test_replay_refused |
| C-155 | sdks/google-adk-pca/test_authorize.py | test_revoked_refused |
| C-155 | sdks/google-adk-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| C-155 | sdks/google-adk-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| C-155 | sdks/google-adk-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| C-155 | sdks/google-adk-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| C-155 | sdks/haystack-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| C-155 | sdks/haystack-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| C-155 | sdks/haystack-pca/test_authorize.py | test_missing_store_refused |
| C-155 | sdks/haystack-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| C-155 | sdks/haystack-pca/test_authorize.py | test_replay_refused |
| C-155 | sdks/haystack-pca/test_authorize.py | test_revoked_refused |
| C-155 | sdks/haystack-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| C-155 | sdks/haystack-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| C-155 | sdks/haystack-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| C-155 | sdks/haystack-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| C-155 | sdks/langgraph-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| C-155 | sdks/langgraph-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| C-155 | sdks/langgraph-pca/test_authorize.py | test_missing_store_refused |
| C-155 | sdks/langgraph-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| C-155 | sdks/langgraph-pca/test_authorize.py | test_replay_refused |
| C-155 | sdks/langgraph-pca/test_authorize.py | test_revoked_refused |
| C-155 | sdks/langgraph-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| C-155 | sdks/langgraph-pca/test_tool.py | test_missing_proof_is_rejected_and_tool_not_run |
| C-155 | sdks/langgraph-pca/test_tool.py | test_undecodable_inline_proof_fails_closed |
| C-155 | sdks/langgraph-pca/test_tool.py | test_wrong_audience_is_rejected_and_tool_not_run |
| C-155 | sdks/pydantic-ai-pca/test_authorize.py | test_400_under_100_refused_before_the_tool_runs |
| C-155 | sdks/pydantic-ai-pca/test_authorize.py | test_default_without_authorize_options_refuses_with_authorize_config |
| C-155 | sdks/pydantic-ai-pca/test_authorize.py | test_missing_store_refused |
| C-155 | sdks/pydantic-ai-pca/test_authorize.py | test_proof_for_x_used_for_y_refused |
| C-155 | sdks/pydantic-ai-pca/test_authorize.py | test_replay_refused |
| C-155 | sdks/pydantic-ai-pca/test_authorize.py | test_revoked_refused |
| C-155 | sdks/pydantic-ai-pca/test_authorize.py | test_signature_only_and_authorize_together_is_a_construction_error |
| C-155 | sdks/pydantic-ai-pca/test_pydantic_ai_pca.py | test_missing_proof_is_rejected_fail_closed |
| C-155 | sdks/pydantic-ai-pca/test_pydantic_ai_pca.py | test_tampered_proof_fails_signature |
| C-155 | sdks/pydantic-ai-pca/test_pydantic_ai_pca.py | test_wrong_audience_is_rejected |
| C-157 | packages/pca-rotate/src/index.test.ts | preserves the leaf caveats exactly (no widening) |
| C-157 | packages/pca-rotate/src/index.test.ts | throws when the secret is not the leaf issuer |
| C-157 | packages/pca-rotate/src/index.test.ts | re-roots a deep chain preserving monotone budget allocations |
| C-157 | packages/pca-rotate/src/index.test.ts | throws on a bad principal secret or wrong holderSecret count |
| C-158 | packages/pca-rotate/src/atomic.test.ts | a failure part-way rolls back what this call added |
| C-158 | packages/pca-rotate/src/atomic.test.ts | a record that names nothing is an error and touches nothing |
| C-159 | packages/pca-events/src/hardening.test.ts | accepts a genuine delivery once and refuses the replay |
| C-159 | packages/pca-events/src/hardening.test.ts | without a replay store, or with one that throws, nothing is accepted |
| C-159 | packages/pca-events/src/hardening.test.ts | a forged id is refused and a genuine one is accepted |
| C-175 | packages/pca-otel/src/hardening.test.ts | a tracer that throws on every call still returns the guard result |
| C-175 | packages/pca-otel/src/hardening.test.ts | a recorded exception is a clean copy: no secret in message, stack or cause |
| C-175 | packages/pca-otel/src/hardening.test.ts | the span is ended exactly once on every path |
| C-176 | packages/pca-connect/src/hardening.test.ts | a captured action releases a token once, then is refused |
| C-176 | packages/pca-connect/src/hardening.test.ts | a revoked chain is refused, with the exact reason |
| C-176 | packages/pca-connect/src/hardening.test.ts | a NaN clock never releases a token as fresh |
| C-176 | packages/pca-connect/src/vault.test.ts | rejects requested scopes that exceed the grant (scope_exceeded) |
| C-176 | packages/pca-connect/src/vault.test.ts | denies a forged leaf signature (real PCActn verification, not a stub) |
| C-176 | packages/pca-connect/src/hardening.test.ts | refuses a ciphertext moved to another connection or field |
| C-176 | packages/pca-connect/src/r4-01-pq-root.test.ts | refuses a forged pure-PQ root |
| C-177 | packages/pca-connectors/src/hardening.test.ts | extraParams cannot override what the builder owns |
| C-177 | packages/pca-connectors/src/hardening.test.ts | the authorize URL and the token exchange both apply the rule |
| C-177 | packages/pca-connectors/src/hardening.test.ts | the registry refuses to swap a registered provider silently |
| C-178 | packages/pca-explain/src/hardening.test.ts | an allow that a failing check contradicts is explained as a denial, naming the check |
| C-178 | packages/pca-compliance/src/index.test.ts | shares that no threshold verifier checked are not reported as a signed human approval |
| C-178 | packages/pca-compliance/src/index.test.ts | empty event set: every control is not-evidenced |
| C-178 | packages/pca-doctor/src/hardening.test.ts | no results, or only skips, is a fail |
| C-179 | packages/pca/src/dataflow-hardening.test.ts | a hand-built look-alike (or one revived from JSON) is not tagged and flows nowhere |
| C-179 | packages/pca/src/dataflow.test.ts | tool-output (untrusted) → external-send sink → DENY with the provenance reason |
| C-185 | packages/pca-policy-bridge/src/cedar.test.ts | still fails closed on genuinely unmodeled constructs |
| C-185 | packages/pca-policy-bridge/src/rego.test.ts | drops an entire rule containing an unmodeled construct (fail closed) |
| C-185 | packages/pca-policy-bridge/src/openfga.test.ts | fails closed on a malformed model |
| C-185 | packages/pca-policy-bridge/src/openfga.test.ts | terminates and fails closed on a cyclic model |
| C-185 | packages/pca-policy-bridge/src/mutation-kill-types.test.ts | translation incomplete (fail closed) |
| C-186 | packages/pca-policy-bridge/src/differential.test.ts | replays every generated request |
| C-186 | packages/pca-policy-bridge/src/differential.test.ts | the corpus is large and mixed enough to mean something |
| C-187 | packages/pca-rag/src/hardening.test.ts | no ACL, an empty ACL list |
| C-187 | packages/pca-rag/src/hardening.test.ts | a matching deny wins |
| C-187 | packages/pca-rag/src/hardening.test.ts | duplicate ids are told apart by position |
| C-187 | packages/pca-rag/src/index.test.ts | fails closed on an incomplete policy translation |
| C-188 | packages/pca-revoke/src/hardening.test.ts | denies a missing or empty chain |
| C-188 | packages/pca-revoke/src/hardening.test.ts | denies when the store throws, and does not leak the store error text |
| C-188 | packages/pca-revoke/src/index.test.ts | denies the action whose chain contains the revoked leaf |
| C-188 | packages/pca-revoke/src/hardening.test.ts | a prefix revoke is one store write |
| C-188 | packages/pca-revoke/src/hardening.test.ts | refuses to start on a corrupt file instead of starting empty |
| C-189 | packages/pca-siem/src/index.test.ts | swallows a thrown fetch error, reports via onError, returns ok:false |
| C-189 | packages/pca-siem/src/index.test.ts | an onError callback that itself throws cannot escape |
| C-189 | packages/pca-siem/src/hardening.test.ts | the good records are delivered, the bad one is counted and reported |
| C-189 | packages/pca-siem/src/hardening.test.ts | when nothing can be serialized nothing is delivered |
| C-190 | packages/pca-siem/src/mutation-kill.test.ts | missing verify record is a deny |
| C-190 | packages/pca-siem/src/hardening.test.ts | a newline or a CEF delimiter in attacker-controlled fields cannot forge a second line or a field |
| C-190 | packages/pca-siem/src/hardening.test.ts | is a 16-character prefix by default, in every format |
| C-191 | packages/pca-less-wasm/src/robustness.test.ts | truncated / oversized / empty / garbage inputs: always false, never throws |
| C-191 | packages/pca-less-wasm/src/robustness.test.ts | padding-bit rows |
| C-191 | packages/pca-less-wasm/src/robustness.test.ts | refuses a seed-padded signature |
| C-191 | packages/pca-less-wasm/src/kat.test.ts | matches all 100 entries byte-for-byte |
| C-192 | packages/pca-less-wasm/src/portable.test.ts | fails closed when Web Crypto is unavailable |
| C-192 | packages/pca-less-wasm/src/portable.test.ts | embedded wasm equals the shipped file |
| C-193 | packages/pca-schema/src/index.test.ts | rejects a PCActn with a required field removed, naming it |
| C-193 | packages/pca-schema/src/index.test.ts | catches a wrong JSON type on a nested field |
| C-193 | packages/pca-schema/src/index.test.ts | rejects a non-object top-level value |
| C-194 | packages/pca-conformance/src/conformance.test.ts | runConformance detects divergence from a non-conformant verifier |
| C-194 | packages/pca-conformance/src/conformance.test.ts | is deterministic: regenerating yields byte-identical content |
| C-194 | packages/pca-conformance/src/conformance.test.ts | has one canonical valid vector + exactly one per documented failure mode |
| C-195 | packages/pca-verified-core/test/finding-clock.test.ts | NaN / non-integer / infinite clocks fail closed |
| C-195 | packages/pca-verified-core/test/diff-chain.test.ts | agrees on 6000 random mutations (verdict AND exact reason) |
| C-195 | packages/pca-verified-core/test/constants.test.ts | the window boundaries sit exactly on those limits |
| C-195 | packages/pca-verified-core/test/ext-regex-budget.test.ts | cannot be called without a budget |
| C-195 | packages/pca-verified-core/test/mutation-kill-ext-policyvm.test.ts | a throwing oracle fails closed |
| C-196 | packages/pca-harness/src/attestation.test.ts | DENIES when configured with an empty allowlist (fail closed) |
| C-196 | packages/pca-harness/src/attestation.test.ts | DENIES when the harness attestation is ABSENT but required |
| C-196 | packages/pca-harness/src/attestation.test.ts | pins model_id when expectedModelId is set |
| C-196 | packages/pca-harness/src/attestation.test.ts | end-to-end: a harness with stamping emits a PCActn the allowlist verifier accepts |
| C-440 | packages/pca-actions/test/def.test.ts | without a valid signed confirmation the effective traits are the TOP of the registry, whatever the def says |
| C-440 | packages/pca-actions/test/def.test.ts | only a signed confirmation sets the traits, to exactly the declared set plus what the signed facts imply |
| C-440 | packages/pca-actions/test/algebra.test.ts | an unconfirmed def has the TOP trait set whatever its machine traits |
| C-440 | packages/pca-actions/test/algebra.test.ts | no machine-authored input (declared traits, provenance, suggestion records, review state) lowers the effective set |
| C-440 | packages/pca-actions/test/algebra.test.ts | the final decision for an unconfirmed def is at most the decision for any confirmed version (antitone) |
| C-440 | packages/pca-actions/test/review.test.ts | a suggested def stays unreviewed; a confirmed one with a valid attestation counts |
| C-440 | packages/pca-actions/test/vectors.test.ts | the reference replay reproduces every expected result |
| C-441 | packages/pca-actions/test/confirmation.test.ts | the same document is refused when no reviewer is pinned (nothing is confirmed) |
| C-441 | packages/pca-actions/test/confirmation.test.ts | dropping the confirmation from a document that claims the reviewed traits is refused |
| C-441 | packages/pca-actions/test/confirmation.test.ts | an unconfirmed def whose schema claims low machine traits and floors is refused |
| C-441 | packages/pca-actions/test/confirmation.test.ts | an unconfirmed verb missing a single trait is refused, naming it |
| C-441 | packages/pca-actions/test/confirmation.test.ts | a forged signature, a stale def digest, a stale registry digest and an altered trait list are all unconfirmed |
| C-441 | packages/pca-actions/test/confirmation.test.ts | a confirmation by an unpinned key, a machine key or a key outside its validity window is unconfirmed |
| C-441 | packages/pca-actions/test/confirmation.test.ts | a confirmation lifted from another action does not transfer |
| C-441 | packages/pca-actions/test/confirmation.test.ts | custom traits are part of the top |
| C-441 | packages/pca-actions/test/verifier.test.ts | the same confirmed schema is refused when the verifier pins no reviewer |
| C-441 | packages/pca-actions/test/verifier.test.ts | an unconfirmed def whose schema claims the reviewed traits is refused |
| C-441 | packages/pca-actions/test/verifier.test.ts | a confirmation signed by a key the verifier did not pin is refused |
| C-442 | packages/pca-actions/test/algebra.test.ts | a trait policy: forbid and cap selectors match an unconfirmed def, allow selectors never do |
| C-442 | packages/pca-goal/test/selectors.test.ts | a class ALLOW never covers an unreviewed verb, even one that matches its traits |
| C-442 | packages/pca-goal/test/selectors.test.ts | a class PROHIBITION and a bound cover an unreviewed verb whatever their all_of and none_of say |
| C-442 | packages/pca-goal/test/selectors.test.ts | a classifier miss changes nothing |
| C-442 | packages/pca-actions/test/diff.test.ts | confirmed -> unconfirmed only tightens; unconfirmed -> confirmed (fewer traits) is a widening |
| T-540 | packages/pca-actions/test/algebra.test.ts | no machine-authored input (declared traits, provenance, suggestion records, review state) lowers the effective set |
| T-541 | packages/pca-actions/test/confirmation.test.ts | a forged signature, a stale def digest, a stale registry digest and an altered trait list are all unconfirmed |
| T-542 | packages/pca-goal/test/selectors.test.ts | a class PROHIBITION and a bound cover an unreviewed verb whatever their all_of and none_of say |
| C-441 | packages/pca-actions/test/confirmation.test.ts | editing any fact after confirmation, or claiming another definition digest, makes the verb unconfirmed |
| T-541 | packages/pca-actions/test/confirmation.test.ts | editing any fact after confirmation, or claiming another definition digest, makes the verb unconfirmed |
| C-780 | packages/pca/src/product-layer-fail-closed-table.test.ts | NaN taint against a hard ceiling is a hard deny |
| C-780 | packages/pca/src/product-layer-fail-closed-table.test.ts | class ceiling is a string |
| C-780 | packages/pca/src/product-layer-fail-closed-table.test.ts | default ceiling is NaN |
| C-780 | packages/pca/src/product-layer-fail-closed-table.test.ts | a taint smuggled in as a string is treated as maximally tainted |
| C-781 | packages/pca/src/product-layer-fail-closed-table.test.ts | an unknown verb resolves to the most dangerous spec and says it is not catalogued |
| C-781 | packages/pca/src/product-layer-fail-closed-table.test.ts | extending cannot relabel an existing verb as less cautious |
| C-781 | packages/pca/src/product-layer-fail-closed-table.test.ts | a pin mismatch throws; the matching digest passes |
| C-781 | packages/pca/src/product-layer-fail-closed-table.test.ts | an ambiguous alias resolves to nothing |
| C-782 | packages/pca/src/product-layer-fail-closed-table.test.ts | frozen not an array |
| C-782 | packages/pca/src/product-layer-fail-closed-table.test.ts | freezing needs a non-empty agent, is idempotent and sorted |
| C-783 | packages/pca/src/product-layer-fail-closed-table.test.ts | digest does not match |
| C-783 | packages/pca/src/product-layer-fail-closed-table.test.ts | a saved state loads back exactly and leaves no temporary file |
| C-783 | packages/pca/src/mesh.test.ts | persists and restores witness memory; refuses corrupt state |
| C-784 | packages/pca/src/mesh.test.ts | rejects when the source domain head lacks enough trusted witness cosignatures |
| C-784 | packages/pca/src/mesh.test.ts | R2-04: allowedDomains and rootDomain are required |
| C-784 | packages/pca/src/mesh.test.ts | refuses equivocation (same size, different log) and rollback |
| C-784 | packages/pca/src/mesh.test.ts | never throws under deterministic structural fuzzing |
| C-326 | packages/pca-grants/src/client-http.test.ts | a principal-scoped caller cannot learn that another principal grant exists |
| C-326 | packages/pca-grants/src/client-http.test.ts | needs: file, approve (principal only, with a signature and an array), deny; another principal cannot touch the need request |
| C-326 | packages/pca-grants/src/client-http.test.ts | no caller, or a caller with neither principal nor admin, is 401; an authenticator that throws is 500 without detail |
| C-326 | packages/pca-grants/src/lease-http.test.ts | no caller, a caller without principal or admin, and a throwing authenticator are 401 / 401 / 500 |
| C-326 | packages/pca-grants/src/lease-http.test.ts | read and check: only the holder or an admin |
| C-327 | packages/pca-grants/src/registry-store.test.ts | a registry without a store is refused at construction |
| C-327 | packages/pca-grants/src/lease.test.ts | a throwing store fails closed |
| C-327 | packages/pca-grants/src/breakglass.test.ts | a store opened with another shard count is refused |
| C-328 | packages/pca-harness/src/harness-failclosed.test.ts | createHarnessAttestationVerifier: exact results |
| C-328 | packages/pca-harness/src/harness-failclosed.test.ts | the allowlist is copied at construction |
| T-448 | packages/pca-grants/src/client-http.test.ts | another principal cannot touch the need request |
| T-448 | packages/pca-grants/src/client-http.test.ts | a principal-scoped caller cannot learn that another principal grant exists |
| T-449 | packages/pca-grants/src/registry-store.test.ts | a registry without a store is refused at construction |
| T-449 | packages/pca-grants/src/lease-http.test.ts | an unreachable store is 503 on issue and revoke, 500 on read, and never an allow |
| T-450 | packages/pca-harness/src/harness-failclosed.test.ts | a present measurement that is not allowlisted always fails |
| T-450 | packages/pca-harness/src/harness-failclosed.test.ts | the measurement changes with the version, the manifest order and every gating parameter |
| C-600 | packages/pca/src/producer-vectors.test.ts | producer vectors (fixed keys, exact outputs) |
| C-600 | sdks/python-pca/test_agent_producer.py | test_vectors |
| C-600 | sdks/go-pca/agent_test.go | TestProducerVectors |
| C-600 | sdks/rust-pca/tests/agent_producer.rs | producer_vectors |
| C-600 | sdks/ruby-pca/test/test_agent_producer.rb | test_vectors |
| C-600 | sdks/php-pca/tests/AgentProducerTest.php | testVectors |
| C-601 | sdks/python-pca/test_agent_producer.py | test_refuses_bad_input |
| C-601 | sdks/go-pca/agent_test.go | TestProducerRefusesBadInput |
| C-601 | sdks/rust-pca/tests/agent_producer.rs | refuses_bad_input |
| C-601 | sdks/ruby-pca/test/test_agent_producer.rb | test_refuses_bad_input |
| C-601 | sdks/php-pca/tests/AgentProducerTest.php | testRefusesBadInput |
| C-602 | sdks/python-pca/test_agent_producer.py | test_hybrid_and_pure_chain_and_leaf |
| C-602 | sdks/go-pca/agent_test.go | TestPostQuantumSuites |
| C-602 | sdks/rust-pca/tests/agent_producer.rs | ml_dsa_hybrids_cross_verify |
| C-602 | sdks/ruby-pca/test/test_agent_producer.rb | test_post_quantum_hybrids |
| C-620 | sdks/java-pca/test/net/atlasauth/pca/ProducerVectorsTest.java | everyCaseIsReproducedByteForByte |
| C-620 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ProducerVectorsTest.kt | everyCaseIsReproducedByteForByte |
| C-620 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ProducerVectorTests.cs | EveryCaseIsReproducedByteForByte |
| C-620 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ProducerVectorsTests.swift | testEveryCaseIsReproducedByteForByte |
| C-620 | sdks/java-pca/test/net/atlasauth/pca/ProducerTest.java | suiteKeysFailClosed |
| C-620 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ProducerTest.kt | suiteKeysFailClosed |
| C-620 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ProducerTests.cs | SuiteKeysFailClosed |
| C-620 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ProducerVectorsTests.swift | testSuiteKeysFailClosed |
| C-620 | sdks/java-pca/test/net/atlasauth/pca/ProducerVectorsTest.java | referenceActionsVerify |
| C-620 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ProducerVectorsTest.kt | referenceActionsVerify |
| C-620 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ProducerVectorTests.cs | ReferenceActionsVerify |
| C-620 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ProducerVectorsTests.swift | testReferenceActionsVerify |
| C-621 | sdks/java-pca/test/net/atlasauth/pca/ProducerTest.java | delegationNarrows |
| C-621 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ProducerTest.kt | delegationNarrows |
| C-621 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ProducerTests.cs | DelegationNarrows |
| C-621 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ProducerVectorsTests.swift | testNativeRoundTripEd25519AndDelegation |

## Gaps

Entries marked `NO AUTOMATED TEST` above, with the reason. Other entries listed under "Partial coverage" have tests, but the tests do not cover the whole stated residual.

### No automated test

- **C-10** (every success bound to its execution): there is nothing to test yet. The verdict carries no operation id or digest, and no API ties the authorization to the side effect it admits; see the [Security contract](./security-contract.md). Operation records are planned for 0.5.

Otherwise none. The four IDs that previously had no test now have one each (T-008 concurrent counter and budget races, T-015, T-019, T-041). T-015 and T-019 are documented non-goals: their tests pin the stated residual (the wire form is readable, a compromised principal key is total within the grant, detection is after the fact) and the mitigations that do exist, rather than claiming prevention.

### Partial coverage

These IDs have tests for the mitigation but not for the whole claim:

- **T-001 / G-5**: counter monotonicity is tested against the in-memory single-node store in the resource-server middleware. The core verifier only checks that the counter is well-formed. Concurrent verifiers sharing one store are tested (T-008); a real multi-node store (Redis, Postgres) supplying `withKeyLock` is the integrator's, and is modelled but not run here.
- **T-009**: freshness and pre-revocation rejection are tested; there is no test that re-checks authority at effect time, which is the resource server's job.
- **T-016**: sub-threshold failure is tested for FROST, the multi-signature, and PQ quorums. Separate-trust-domain custody cannot be tested in a single process.
- **T-028 / T-029**: failure of one root among several is tested with synthetic and real-fixture roots, and a compromised vendor root (a forged quote that validates under it) is tested against a genuine second root. A policy that needs only the compromised root accepts the forgery; that residual risk is pinned by a test, not removed.
- **T-035**: audience reuse and proof replay are tested; a malicious server misreporting effects is out of what the library can test.
- **T-040**: equivocation proofs are tested with in-process witnesses. No independent third-party witness is operated or tested.
- **T-044**: the TypeScript implementation is tested against the frozen conformance vectors. Differential results for the other language SDKs are produced by the separate cross-language conformance run and are not asserted here.
- **T-045**: tests show byte-exact handling (astral key order, lone surrogates) and that NFC/NFD, homoglyph, zero-width, bidi, fullwidth and case variants of an identifier are never treated as equal in verb, resource, condition, caveat-type, audience and digest decisions, in both the allow and deny directions. The library still does not normalize (by design), so there is no helper test for integrators who normalize before authorizing.
- **T-046**: the nesting-depth, chain-depth, tool-argument and regex bounds are tested, and oversized and deeply nested inputs are submitted to the strict parser entry points (`strictParse`, `strictParseBytes`, `decodePCActn`) and the other decoders under a per-test time budget. `decodePcaHeader` itself has no size cap (HTTP servers bound header size); the oversize is refused one step later by `decodePCActn`. Volumetric flooding and signature-verification cost are not tested.
- **T-048**: known-answer vectors catch wrong output only. There is no test for dependency provenance or lockfile integrity.
- **T-049**: the receipt-integrity comparison is tested, and a dudect-style statistical timing harness measures Ed25519 and ML-DSA signing, the hybrid KEM decapsulation and FROST signing (with a leaky positive control and a constant-time negative control). A black-box timing test in a JIT runtime cannot prove constant time; the FROST scalar arithmetic is documented as not constant-time and the harness reports it as such. The DKG is not measured.
- **T-047**: PQ and hybrid suites are tested for correctness and downgrade resistance. No test asserts that a classical-only artifact is rejected after a given date, because that is a policy decision.

| C-324 | packages/pca-actions/test/import.test.ts | an unreviewed def is held at the most restrictive floor |
| C-324 | packages/pca-actions/test/import.test.ts | every def is well formed and unreviewed, with its source recorded |
| C-324 | packages/pca-actions/test/import-fuzz.test.ts | arbitrary JSON never throws anything but ActionKitError |
| C-324 | packages/pca-actions/test/import-fuzz.test.ts | documents with fuzzed schemas validate, are unreviewed, and stay within bounds |
| C-324 | packages/pca-actions/test/import-limits.test.ts | a binary reference bomb costs a bounded amount of work and fails closed |
| C-324 | packages/pca-actions/test/import-limits.test.ts | a remote reference is never fetched: it is noted and fails closed |
| C-324 | packages/pca-actions/test/import.test.ts | treats hints as untrusted lower bounds |

### Gaps worth filling

Highest value first:

1. ~~Concurrent counter/budget race (T-008).~~ Done.
2. **Normalization helper (T-045).** The byte-exact behaviour is tested; what remains is a helper test for integrators who normalize before authorizing.
3. ~~Resource-server inclusion-proof requirement (T-041).~~ Done.
4. **Effect-time re-check (T-009).** A test of a verify-then-revoke-then-execute sequence with the documented re-check hook.
5. **Cross-SDK differential fuzzing (T-044).** An automated differential fuzzer across the language SDKs on the strict parser.
6. **Side-channel evidence (T-049).** A timing-distribution harness now exists; a documented constant-time review of signer arithmetic by an independent reviewer does not.
7. ~~Compromised vendor key simulation (T-028).~~ Done.

### Not applicable to automated testing

- **T-015** (passive eavesdropping) and **T-019** (compromised principal) are non-goals; they are listed so the matrix is complete.

| C-220 | packages/pca/src/caveat-lang.test.ts | discharge_verify |
| C-220 | packages/pca/src/k1-integration.test.ts | K1 through requirePCA |
| C-221 | packages/pca/src/caveat-lang.test.ts | k1_eval |
| C-221 | packages/pca/src/k1-integration.test.ts | K1 through requirePCA |
| C-222 | packages/pca/src/caveat-lang.test.ts | offline attenuation hardening |
| C-222 | packages/pca/src/k1-integration.test.ts | K1 through requirePCA |
| C-223 | packages/pca/src/caveat-lang.test.ts | narrow |
| C-223 | packages/pca/src/k1-integration.test.ts | K1 through requirePCA |
| C-224 | packages/pca/src/caveat-lang.test.ts | max_uses |
| C-224 | packages/pca/src/k1-integration.test.ts | K1 through requirePCA |
| C-225 | packages/pca/src/caveat-lang.test.ts | caveat_shape |
| C-225 | packages/pca/src/k1-integration.test.ts | K1 through requirePCA |
| C-226 | packages/pca/src/caveat-lang.test.ts | spiffe_id |
| C-226 | packages/pca/src/k1-integration.test.ts | K1 through requirePCA |
| T-320 | packages/pca/src/caveat-lang.test.ts | caveat-lang-vectors.json |
| T-321 | packages/pca/src/caveat-lang.test.ts | caveat-lang-vectors.json |
| T-322 | packages/pca/src/caveat-lang.test.ts | caveat-lang-vectors.json |
| T-323 | packages/pca/src/caveat-lang.test.ts | caveat-lang-vectors.json |
| T-324 | packages/pca/src/caveat-lang.test.ts | caveat-lang-vectors.json |
| T-325 | packages/pca/src/caveat-lang.test.ts | caveat-lang-vectors.json |
| T-326 | packages/pca/src/caveat-lang.test.ts | caveat-lang-vectors.json |
| C-480 | packages/pca/src/pca-need.test.ts | pca_need challenge parameter |
| C-481 | packages/pca/src/pca-grant-details.test.ts | pca_grant authorization details (RFC 9396 profile) |
| C-482 | packages/pca-mcp-rs/src/spec-conformance.test.ts | MCP authorization conformance matrix (resource-server rows) |
| C-482 | packages/pca-mcp/src/auth-client-conformance.test.ts | MCP authorization conformance matrix (client rows) |
| C-483 | packages/pca-mcp-rs/src/spec-conformance.test.ts | scope-hierarchy |
| C-484 | packages/pca-mcp/src/auth-client.test.ts | planStepUp: a stock client falls back cleanly, a PCA client completes an argument-aware step-up |
| C-484 | packages/pca-mcp/src/auth-client.test.ts | checkAuthorizationResponseIss: the RFC 9207 table of the MCP specification |
| C-485 | packages/pca-oauth/src/pca-grant.test.ts | end to end: an OAuth server carries the grant, the resource server still verifies the proof |
| C-486 | packages/pca-a2a/src/a2a-auth.test.ts | AUTH_REQUIRED mapping (A2A 7.6) |
| C-487 | packages/pca-a2a/src/a2a-auth.test.ts | per-hop delegation |
| C-488 | packages/pca-a2a/src/a2a-auth.test.ts | push notifications (A2A 13.2) |
| C-489 | packages/pca-grants/src/blueprint.test.ts | the ceiling is tighten-only |
| C-490 | packages/pca-grants/src/blueprint.test.ts | GROUP KILL: one signed record refuses every instance |
| C-491 | packages/pca-grants/src/blueprint.test.ts | staleness: a registry behind the epoch the caller proved it has seen escalates, never allows |
| T-580 | packages/pca/src/pca-grant-details.test.ts | pca-grant-vectors.json |
| T-581 | packages/pca/src/pca-need.test.ts | pca_need challenge parameter |
| T-582 | packages/pca-mcp/src/auth-client.test.ts | planStepUp: a stock client falls back cleanly, a PCA client completes an argument-aware step-up |
| T-583 | packages/pca-mcp/src/auth-client.test.ts | checkAuthorizationResponseIss: the RFC 9207 table of the MCP specification |
| T-584 | packages/pca-mcp-rs/src/spec-conformance.test.ts | MCP authorization conformance matrix (resource-server rows) |
| T-585 | packages/pca-mcp/src/auth-client-conformance.test.ts | MCP authorization conformance matrix (client rows) |
| T-586 | packages/pca-oauth/src/pca-grant.test.ts | pca_grant for authorization servers and resource servers |
| T-587 | packages/pca-a2a/src/a2a-auth.test.ts | A2A PCA binding |
| T-588 | packages/pca-grants/src/blueprint.test.ts | agent blueprints: ceiling and group kill |
| T-588 | packages/pca-grants/src/blueprint-vectors.test.ts | blueprint-vectors.json |
| C-492 | packages/pca-grants/src/blueprint-admission.test.ts | attestation-gated blueprint admission |
| C-493 | packages/pca-a2a/src/a2a-receipt.test.ts | signed task-update receipts |
| C-494 | packages/pca-a2a/src/a2a-extended-card.test.ts | extended Agent Card from a residual policy |
| C-495 | packages/pca-oauth/src/pca-grant.test.ts | OAuth scopes derived from the confirmed action |
| C-495 | packages/pca-mcp-rs/src/spec-conformance.test.ts | MCP scopes derived from the confirmed action |
| T-589 | packages/pca-grants/src/blueprint-admission.test.ts | attestation-gated blueprint admission |
| T-590 | packages/pca-a2a/src/a2a-receipt.test.ts | signed task-update receipts |
| T-591 | packages/pca-a2a/src/a2a-extended-card.test.ts | extended Agent Card from a residual policy |
| T-592 | packages/pca-oauth/src/pca-grant.test.ts | OAuth scopes derived from the confirmed action |
| T-592 | packages/pca-mcp-rs/src/spec-conformance.test.ts | MCP scopes derived from the confirmed action |
| C-496 | packages/pca-attest-eat/src/admission.test.ts | EAT evidence for blueprint admission |
| C-496 | packages/pca-spiffe/src/admission.test.ts | SPIFFE evidence for blueprint admission |
| C-497 | packages/pca-a2a/src/a2a-vectors.test.ts | A2A binding shared vectors |
| T-593 | packages/pca-attest-eat/src/admission.test.ts | EAT evidence for blueprint admission |
| T-593 | packages/pca-spiffe/src/admission.test.ts | SPIFFE evidence for blueprint admission |
| T-594 | packages/pca-a2a/src/a2a-vectors.test.ts | A2A binding shared vectors |
| C-520 | packages/pca/src/provenance-gate.test.ts | a workload key cannot stand in for the artifact verifier |
| C-520 | sdks/python-pca/test_caveat_lang.py | discharge_verify |
| C-521 | packages/pca/src/provenance-gate.test.ts | provenance vectors (shared with the natives) |
| C-521 | packages/pca/src/provenance-gate.test.ts | a level below the caveat floor is refused at the verifier |
| C-522 | packages/pca/src/provenance-gate.test.ts | a swapped tool image gets no discharge, and the action is refused |
| C-522 | packages/pca-attest-eat/src/sigstore.test.ts | a swapped image gets no discharge |
| C-522 | packages/pca-attest-eat/src/sigstore.test.ts | an EAT that failed, or names no image, is no join |
| C-523 | packages/pca-attest-eat/src/sigstore.test.ts | establishes identity, issuer, source and subject |
| C-523 | packages/pca-attest-eat/src/sigstore.test.ts | refuses a forged SET, a moved integrated time |
| C-523 | packages/pca-attest-eat/src/sigstore.test.ts | refuses a broken inclusion proof and a checkpoint not signed by the pinned log |
| C-523 | packages/pca-attest-eat/src/sigstore.test.ts | refuses when no pinned CT log signed the embedded SCT |
| C-523 | packages/pca-attest-eat/src/sigstore.test.ts | refuses a certificate no pinned CA issued |
| C-524 | packages/pca/src/provenance-gate.test.ts | inclusion refuses non-integer or out-of-range positions |
| C-524 | packages/pca/src/provenance-gate.test.ts | merkle |
| C-525 | sdks/python-pca/test_provenance_vectors.py | test_gate |
| C-525 | sdks/go-pca/provenance_test.go | TestProvenanceVectors |
| C-525 | sdks/rust-pca/tests/provenance_vectors.rs | provenance_vectors |
| C-525 | sdks/ruby-pca/test/test_provenance.rb | test_gate |
| C-525 | sdks/php-pca/tests/VectorsTest.php | testProvenanceVectors |
| C-525 | sdks/java-pca/test/net/atlasauth/pca/ProvenanceVectorsTest.java | gate |
| C-525 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/ProvenanceVectorsTest.kt | gate |
| C-525 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/ProvenanceVectorTests.cs | GateMatchesTheReference |
| C-525 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/ProvenanceVectorTests.swift | testGate |
| C-526 | packages/pca-cli/src/actions.test.ts | LP-001: a beta or stable pack without a pinned builder identity |
| C-527 | packages/pca-dataflow/src/trace-rules.test.ts | refuses a send after a fetch inside the window, and nothing else |
| C-527 | packages/pca-dataflow/src/trace-rules.test.ts | fails closed: a send with no history |
| C-528 | packages/pca-dataflow/src/trace-rules.test.ts | compile errors are errors, never skipped |
| C-528 | packages/pca-dataflow/src/trace-rules.test.ts | the canonical example has a detector condition |
| C-528 | packages/pca-cli/src/actions.test.ts | LT-000: a rule that does not compile is an error |
| C-529 | packages/pca-dataflow/src/trace-rules.test.ts | flags every send that both untrusted and private reads can reach |
| C-529 | packages/pca-cli/src/actions.test.ts | LT-001: untrusted content, private data and a send with no trace rule |
| C-530 | packages/pca/src/detector-receipt.test.ts | for every base decision and receipt set |
| C-530 | packages/pca/src/detector-receipt.test.ts | adding valid no_finding receipts changes nothing |
| C-530 | packages/pca/src/detector-receipt.test.ts | an invalid receipt (%s) escalates, never ok |
| C-531 | packages/pca/src/detector-receipt.test.ts | a grant whose where reads env.detect is refused |
| C-531 | sdks/go-pca/provenance_test.go | TestProvenanceVectors |
| C-532 | packages/pca-dataflow/src/trace-rules.test.ts | detector adapters are one-sided |
| T-620 | packages/pca/src/provenance-gate.test.ts | a swapped tool image gets no discharge, and the action is refused |
| T-620 | packages/pca-attest-eat/src/sigstore.test.ts | a swapped image gets no discharge |
| T-621 | packages/pca/src/provenance-gate.test.ts | a level below the caveat floor is refused at the verifier |
| T-621 | packages/pca-attest-eat/src/sigstore.test.ts | the GitHub-hosted runner pinned at level 2 does not meet a level 3 policy |
| T-622 | packages/pca-attest-eat/src/sigstore.test.ts | refuses a payload changed after logging |
| T-622 | packages/pca-attest-eat/src/sigstore.test.ts | refuses a forged SET, a moved integrated time |
| T-622 | packages/pca-attest-eat/src/sigstore.test.ts | refuses a broken inclusion proof and a checkpoint not signed by the pinned log |
| T-623 | packages/pca/src/provenance-gate.test.ts | provenance vectors (shared with the natives) |
| T-623 | packages/pca-attest-eat/src/sigstore.test.ts | an unpinned identity meets nothing |
| T-624 | packages/pca-dataflow/src/trace-rules.test.ts | compile errors are errors, never skipped |
| T-624 | packages/pca-dataflow/src/trace-rules.test.ts | fails closed: a send with no history |
| T-625 | packages/pca-dataflow/src/trace-rules.test.ts | flags every send that both untrusted and private reads can reach |
| T-625 | packages/pca-cli/src/actions.test.ts | LT-001: untrusted content, private data and a send with no trace rule |
| T-626 | packages/pca/src/detector-receipt.test.ts | adding valid no_finding receipts changes nothing |
| T-626 | packages/pca/src/detector-receipt.test.ts | a grant whose where reads env.detect is refused |
| T-627 | packages/pca/src/detector-receipt.test.ts | an invalid receipt (%s) escalates, never ok |
| T-628 | packages/pca-dataflow/src/trace-rules.test.ts | detector adapters are one-sided |
| T-629 | sdks/python-pca/test_provenance_vectors.py | test_gate |
| T-629 | sdks/go-pca/provenance_test.go | TestProvenanceVectors |
| C-533 | packages/pca-gateway/src/k1-discharges.test.ts | admits with a discharge in PCA-Discharges |
| C-533 | packages/pca-gateway/src/k1-discharges.test.ts | without a k1 configuration the caveat refuses |
| T-630 | packages/pca-gateway/src/k1-discharges.test.ts | refuses without a discharge, with a rogue or under-claimed one |
| C-523 | packages/pca-attest-eat/src/sigstore-vectors.test.ts | covers Rekor v1 and v2, SET and RFC 3161 time |
| C-460 | packages/pca-actions/test/approval-render.test.ts | renders every supplied parameter |
| C-460 | packages/pca-actions/test/approval-render.test.ts | an unconfirmed definition renders UNREVIEWED |
| C-460 | packages/pca-actions/test/approval-render.test.ts | refuses anything it cannot show completely |
| C-460 | packages/pca/src/approval-render.test.ts | digest and challenge are pinned |
| C-460 | packages/pca-webauthn/src/spc.test.ts | commits to the action and the render |
| C-460 | sdks/go-pca/approval_test.go | TestApprovalPrimitivesPinned |
| C-460 | sdks/python-pca/test_actions_vectors.py | test_every_vector_replays |
| C-461 | packages/pca/src/server/decision-escalation.test.ts | an answer for another render, or none |
| C-461 | packages/pca/src/server/decision-escalation.test.ts | by default every answer is refused when the render cannot be recomputed |
| C-461 | packages/pca/src/server/decision-escalation.test.ts | an answer with no render check is refused unless insecureUnboundApproval is set |
| C-461 | sdks/go-pca/escalation_test.go | TestUnboundApprovalIsRefusedByDefault |
| C-461 | sdks/java-pca/test/net/atlasauth/pca/EscalationTest.java | unboundApprovalIsRefusedByDefault |
| C-461 | sdks/rust-pca/tests/escalation.rs | unbound_approval_is_refused_by_default |
| C-461 | packages/pca/src/server/decision-escalation.test.ts | an answer that carries a render the verifier did not recompute |
| C-461 | sdks/python-pca/test_escalation_guard.py | test_render_mismatch_missing_unchecked_and_required |
| C-461 | sdks/go-pca/actions_vectors_test.go | TestActionsVectorsReplay |
| C-461 | sdks/ruby-pca/test/test_actions_vectors.rb | test_every_vector_replays |
| C-462 | packages/pca-actions/test/approval-render.test.ts | extracts the amount and the payee |
| C-462 | packages/pca-actions/test/approval-render.test.ts | a batch commits to per-currency totals |
| C-462 | packages/pca-webauthn/src/spc.test.ts | refuses any change to the amount |
| C-462 | sdks/go-pca/actions_vectors_test.go | TestApprovalProfileVectors |
| C-463 | packages/pca-connect/src/proxy.test.ts | refuses any request that does not re-derive the signed params digest |
| C-463 | packages/pca-connect/src/proxy.test.ts | refuses headers the agent must not set |
| C-463 | packages/pca-connect/src/proxy.test.ts | is disabled by default |
| C-464 | packages/pca-connect/src/proxy.test.ts | an unknown verb and an unconfirmed definition release nothing |
| C-464 | packages/pca-connect/src/proxy.test.ts | scopes_min must be inside the grant and inside the stored connection |
| C-465 | packages/pca-connect/src/proxy.test.ts | makes the call itself with the token attached |
| C-465 | packages/pca-connect/src/proxy.test.ts | transport failure is a typed refusal with a failed receipt |
| C-466 | packages/pca-payments/src/rails.test.ts | declines at the latency budget |
| C-466 | packages/pca-payments/src/rails.test.ts | a bad, missing, stale or tampered signature decides nothing |
| C-466 | packages/pca-payments/src/rails.test.ts | more charged, another merchant, a second capture |
| C-460 | packages/pca/src/approvals.test.ts | without a renderer the review is a deny |
| C-460 | packages/pca-actions/test/approval-render.test.ts | reviewAction binds the render with no hand-written renderer |
| C-280 | packages/pca-payments/src/network-token.test.ts | a binding signed by the holder over token_ref, grant digest and nonce verifies |
| C-280 | packages/pca-payments/src/network-token.test.ts | every field is bound: token_ref, grant, holder, nonce, provider |
| C-280 | packages/pca-payments/src/network-token.test.ts | a PAN-shaped or malformed token_ref is refused |
| C-281 | packages/pca-payments/src/network-token.test.ts | controls sent to the network equal the rail limits and carry the grant digest |
| C-281 | packages/pca-payments/src/network-token.test.ts | the Mastercard mapping uses its own scope key; a PAN-shaped provider response is refused |
| C-281 | packages/pca-payments/src/network-token.test.ts | revoking the grant suspends the token; a failing suspend propagates |
| C-282 | packages/pca-payments/src/network-token.test.ts | joins only on an exact echo of grant digest, PCActn digest and token_ref |
| C-284 | packages/pca-wallet/src/escalation-pricing.test.ts | asks exactly when p * loss > cost (boundary exact, integer math) |
| C-284 | packages/pca-wallet/src/escalation-pricing.test.ts | fails strict: bad signature, tampered cost, currency, out-of-range inputs, ceiling |
| C-284 | packages/pca-wallet/src/escalation-pricing.test.ts | is deterministic |
| C-284 | packages/pca-wallet/src/escalation-pricing.test.ts | replays conformance/k4-vectors.json (decisions, config cases, calibration) |
| C-285 | packages/pca-wallet/src/escalation-pricing.test.ts | a signed deny of an auto-approved action raises the multiplier; approve / replay / forged / unknown change nothing |
| C-286 | packages/pca-wallet/src/escalation-pricing.test.ts | PROPERTY: no sequence of answers ever makes any action go from ask to no-ask |
| C-286 | packages/pca-wallet/src/escalation-pricing.test.ts | a corrupt config makes the learner a no-op |
| C-287 | packages/pca-wallet/src/escalation-pricing.test.ts | a signed raise within the maximum lowers the ask rate; above the max, wrong key, stale epoch are refused |
| C-288 | packages/pca-erc7715/src/index.test.ts | maps cap, expiry and addresses; exact integer unit conversion |
| C-288 | packages/pca-erc7715/src/index.test.ts | refuses bad inputs: fractional ratio, zero, bad address, bad envelope |
| C-288 | packages/pca-erc7715/src/index.test.ts | supports discovery, either spelling of ruleTypes, and revoke params |
| C-289 | packages/pca-erc7715/src/index.test.ts | accepts the permission as requested and a narrowed one |
| C-289 | packages/pca-erc7715/src/index.test.ts | refuses: ${name} |
| C-290 | packages/pca-erc7715/src/index.test.ts | refuses a context already bound to another grant, and garbage |
| C-283 | packages/pca-payments/src/network-token.test.ts | chargeWithNetworkToken derives the metadata from the PCActn it built, and a settlement with that metadata joins |
| C-283 | packages/pca-payments/src/network-token.test.ts | a settlement without the PCActn digest is refused, including when the expectation is empty too |
| C-283 | packages/pca-payments/src/network-token.test.ts | a binding for another grant cannot start a charge |
| T-700 | packages/pca-payments/src/network-token.test.ts | every field is bound: token_ref, grant, holder, nonce, provider |
| T-701 | packages/pca-payments/src/network-token.test.ts | a PAN-shaped or malformed token_ref is refused |
| T-702 | packages/pca-payments/src/network-token.test.ts | a settlement without the PCActn digest is refused, including when the expectation is empty too |
| T-703 | packages/pca-wallet/src/escalation-pricing.test.ts | PROPERTY: no sequence of answers ever makes any action go from ask to no-ask |
| T-704 | packages/pca-erc7715/src/index.test.ts | refuses: ${name} |
| C-284 | sdks/python-pca/test_k4_vectors.py | test_decisions |
| C-284 | sdks/go-pca/k4_test.go | TestK4Vectors |
| C-284 | sdks/rust-pca/tests/k4_vectors.rs | k4_vectors |
| C-284 | sdks/ruby-pca/test/test_k4.rb | test_decisions |
| C-284 | sdks/php-pca/tests/Vectors.php | k4-vectors.json |
| C-284 | sdks/java-pca/test/net/atlasauth/pca/K4VectorsTest.java | escalation |
| C-284 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/K4VectorsTest.kt | escalation |
| C-284 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/K4VectorTests.cs | Escalation |
| C-284 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/K4VectorTests.swift | testK4Vectors |

| C-300 | packages/pca/src/k5-vectors.test.ts | every denial code of the contract is exercised |
| C-300 | packages/pca/src/workflow-mutation-kill.test.ts | a step with a committed params digest admits exactly those params |
| C-301 | packages/pca/src/workflow-mutation-kill.test.ts | fresh_ms: exactly fresh_ms old is fresh, one ms more is stale |
| C-301 | packages/pca/src/workflow-mutation-kill.test.ts | a receipt may precede its dependency only through a declared promise |
| C-302 | packages/pca/src/k5-vectors.test.ts | digests |
| C-302 | packages/pca/src/workflow-mutation-kill.test.ts | the unit must match on both the receipt and the edge |
| C-303 | packages/pca/src/k5-vectors.test.ts | receipt refs |
| C-303 | packages/pca/src/workflow-mutation-kill.test.ts | a receipt must be from this workflow, in sequence, linked, and not future-dated |
| C-304 | packages/pca/src/workflow-mutation-kill.test.ts | step-level taint: deny and escalate come from labels of any executed ancestor |
| C-305 | packages/pca/src/workflow-mutation-kill.test.ts | a failed dependency denies; max_steps and cost caps are inclusive |
| C-306 | packages/pca/src/e2e.test.ts | runs all 8 steps |
| C-306 | packages/pca/src/workflow-mutation-kill.test.ts | planRootAuthorized needs the exact root, the pinned principal and the time window |
| C-307 | packages/pca/src/workflow-mutation-kill.test.ts | an edge with a promise admits ahead of the source and reports it pending |
| C-307 | packages/pca/src/workflow-mutation-kill.test.ts | bindPromises needs the step receipt |
| C-310 | packages/pca/src/k5-vectors.test.ts | redact:  |
| C-311 | packages/pca/src/k5-vectors.test.ts | digests and chain labels |
| C-312 | packages/pca/src/k5-vectors.test.ts | sink:  |
| C-313 | packages/pca/src/workflow-mutation-kill.test.ts | cap: reaching the cap allows, one over denies and reports the prior counts |
| C-300 | packages/pca/src/k5-vectors.test.ts | admit:  |
| C-301 | packages/pca/src/k5-vectors.test.ts | every denial code of the contract is exercised |
| C-302 | packages/pca/src/k5-vectors.test.ts | digests |
| C-303 | packages/pca/src/k5-vectors.test.ts | receipt refs |
| C-304 | packages/pca/src/k5-vectors.test.ts | never throws on hostile input |
| C-305 | packages/pca/src/k5-vectors.test.ts | bind:  |
| C-306 | packages/pca/src/k5-vectors.test.ts | plan_root_authorized:  |
| C-307 | packages/pca/src/k5-vectors.test.ts | bind:  |
| C-310 | packages/pca/src/k5-vectors.test.ts | redact:  |
| C-311 | packages/pca/src/k5-vectors.test.ts | digests and chain labels |
| C-312 | packages/pca/src/k5-vectors.test.ts | sink:  |
| C-313 | packages/pca/src/k5-vectors.test.ts | redact:  |
| C-313 | packages/pca/src/k5-vectors.test.ts | the masked view never contains a dropped value |
| C-314 | packages/pca/src/k5-vectors.test.ts | the committed files are exactly what the generator writes |
| C-300 | formal/dafny/WorkflowAdmit.dfy | AdmittedIsPlanned |
| C-300 | formal/dafny/WorkflowAdmit.dfy | UnplannedDenied |
| C-301 | formal/dafny/WorkflowAdmit.dfy | AdmittedDepsMet |
| C-301 | formal/dafny/WorkflowAdmit.dfy | ReorderDenied |
| C-301 | formal/dafny/WorkflowAdmit.dfy | AdmittedNotDone |
| C-302 | formal/dafny/WorkflowAdmit.dfy | AdmittedEdgesHold |
| C-303 | formal/dafny/WorkflowAdmit.dfy | ChainAppend |
| C-303 | formal/dafny/WorkflowAdmit.dfy | ChainPrefix |
| C-303 | formal/dafny/WorkflowAdmit.dfy | ChainDistinct |
| C-310 | formal/dafny/ReadSide.dfy | EffectiveNeverWeaker |
| C-310 | formal/dafny/ReadSide.dfy | EffectiveIsOneOf |
| C-311 | formal/dafny/ReadSide.dfy | LabelsSound |
| C-311 | formal/dafny/ReadSide.dfy | LabelsExact |
| C-311 | formal/dafny/ReadSide.dfy | ChainLabelsUnion |
| C-312 | formal/dafny/ReadSide.dfy | SinkAllowIsSubset |
| C-312 | formal/dafny/ReadSide.dfy | SinkEscalateNeedsAsk |
| C-312 | formal/dafny/ReadSide.dfy | SinkDenyOnForeignLabel |

| C-308 | packages/pca/src/server/authorize-workflow.test.ts | a step inside a committed workflow is checked automatically |
| C-309 | packages/pca/src/e2e.test.ts | runs all 8 steps |
| C-309 | packages/pca/src/server/require-pca.test.ts | an UNauthorized plan root (planAuthorized: false) is denied outright |
| C-315 | packages/pca/src/read-vault.test.ts | detokenises only for a sink the grant allows the class to reach |
| C-316 | packages/pca/src/read-vault.test.ts | a group below k is refused |
| C-309 | packages/pca/src/server/require-pca.test.ts | allows only when counter, revocation and plan_root_authorized are all ENFORCED |
| C-315 | packages/pca/src/read-vault.test.ts | detokenises only for a sink the grant allows the class to reach |
| C-316 | packages/pca/src/read-vault.test.ts | a group below k is refused; clamping bounds the exact sum |
| C-316 | packages/pca/src/read-vault.test.ts | the query count is capped even when no epsilon is spent |
| C-317 | packages/pca/src/read-vault.test.ts | charges epsilon, clamps each value, and refuses once the budget would be exceeded |
| C-318 | packages/pca/src/read-vault.test.ts | a repeated identical query returns the same answer and is not charged again |
| C-319 | packages/pca-analyzer/src/dag-exposure.test.ts | a diamond: depth, width, paths, lineage and the unprotected sink |
| C-300 | packages/pca/src/workflow-mutation-kill.test.ts | workflow: limits and shape (exact boundaries) |
| C-310 | packages/pca/src/workflow-mutation-kill.test.ts | readside: mask modes and boundaries |
| C-300 | packages/pca/src/workflow-mutation-kill.test.ts | 64 steps are valid, 65 are not |
| C-303 | formal/pca-lean/PcaProof/WorkflowAdmit.lean | chain_append |
| C-303 | formal/pca-lean/PcaProof/WorkflowAdmit.lean | chain_nodup |
| C-303 | formal/pca-lean/PcaProof/WorkflowAdmit.lean | admit_run_invariant |
| C-305 | formal/dafny/WorkflowAdmit.dfy | AdmittedWithinCap |
| C-305 | formal/dafny/WorkflowAdmit.dfy | SpentAppend |
| C-305 | formal/dafny/WorkflowAdmit.dfy | RunInvariant |
| T-410 | packages/pca/src/k5-vectors.test.ts | redact:  |
| T-410 | formal/dafny/ReadSide.dfy | EffectiveNeverWeaker |
| T-411 | packages/pca/src/k5-vectors.test.ts | digests and chain labels |
| T-411 | formal/dafny/ReadSide.dfy | LabelsSound |
| T-412 | packages/pca/src/k5-vectors.test.ts | sink:  |
| T-412 | formal/dafny/ReadSide.dfy | SinkDenyOnForeignLabel |
| T-413 | packages/pca/src/workflow-mutation-kill.test.ts | cap: reaching the cap allows, one over denies and reports the prior counts |
| T-414 | packages/pca/src/k5-vectors.test.ts | the committed files are exactly what the generator writes |
| T-415 | packages/pca/src/read-vault.test.ts | detokenises only for a sink the grant allows the class to reach |
| T-416 | packages/pca/src/read-vault.test.ts | a group below k is refused |
| T-416 | packages/pca/src/read-vault.test.ts | charges epsilon, clamps each value, and refuses once the budget would be exceeded |
| T-417 | packages/pca/src/read-vault.test.ts | a repeated identical query returns the same answer and is not charged again |
| C-500 | packages/pca-grants/src/lease.test.ts | lease vectors |
| C-500 | packages/pca-grants/src/lease.test.ts | renewLease extends from now, caps at max_ttl, and a veto stops it (signals never lengthen) |
| C-500 | packages/pca-grants/src/lease.test.ts | signLease refuses a lease past its cap |
| C-500 | packages/pca-grants/src/lease.test.ts | a throwing store fails closed |
| C-501 | packages/pca-grants/src/lease.test.ts | sodError returns the exact reason |
| C-502 | packages/pca-grants/src/lease.test.ts | pathUnder is segment bounded |
| C-502 | packages/pca-grants/src/lease.test.ts | issue, read, check, revoke |
| C-503 | packages/pca-grants/src/shadow.test.ts | returns the enforced decision whatever the candidate does |
| C-503 | packages/pca-grants/src/shadow.test.ts | a candidate mutating its input cannot change what the enforced policy sees later |
| C-503 | packages/pca-grants/src/shadow.test.ts | counts every observation and keeps a signed diff per divergence |
| C-504 | packages/pca-grants/src/shadow.test.ts | an unexplained widening blocks promotion and names the action |
| C-504 | packages/pca-grants/src/shadow.test.ts | a principal explanation for exactly that action unblocks it; others do not |
| C-504 | packages/pca-grants/src/shadow.test.ts | a wider or unprovable surface needs a principal approval for this pair |
| C-504 | packages/pca-grants/src/shadow.test.ts | promoteShadow builds the next revision only behind a passing gate for a listed candidate |
| C-505 | packages/pca-policy-bridge/src/cel.test.ts | celToCondition: exact translation (differential against a reference CEL evaluator) |
| C-505 | packages/pca-policy-bridge/src/cel.test.ts | celToCondition: anything it cannot translate exactly is rejected, by name |
| C-505 | packages/pca-policy-bridge/src/cel.test.ts | one rejection makes the whole import deny everything |
| C-506 | packages/pca/src/obligations.test.ts | an allow with an unsupported obligation carries the reason |
| C-506 | packages/pca/src/obligations.test.ts | discovery carries obligations_supported |
| C-506 | packages/pca/src/obligations-vectors.test.ts | is current (OBLIGATIONS_VECTORS_WRITE=1 regenerates it) |
| C-507 | packages/pca/src/obligations.test.ts | an overdue obligation escalates and never allows |
| C-508 | sdks/python-pca/test_lease_vectors.py | test_scenarios |
| C-508 | sdks/python-pca/test_obligations_vectors.py | test_gate |
| T-600 | packages/pca-grants/src/lease.test.ts | signLease refuses a lease past its cap |
| T-600 | packages/pca-grants/src/lease.test.ts | lease vectors |
| T-601 | packages/pca-grants/src/lease.test.ts | sodError returns the exact reason |
| T-602 | packages/pca-grants/src/lease.test.ts | issue, read, check, revoke |
| T-603 | packages/pca-grants/src/shadow.test.ts | returns the enforced decision whatever the candidate does |
| T-603 | packages/pca-grants/src/shadow.test.ts | an unexplained widening blocks promotion and names the action |
| T-604 | packages/pca-policy-bridge/src/cel.test.ts | celToCondition: anything it cannot translate exactly is rejected, by name |
| T-605 | packages/pca/src/obligations.test.ts | an allow with an unsupported obligation carries the reason |
| T-606 | packages/pca/src/obligations.test.ts | an overdue obligation escalates and never allows |
| T-607 | sdks/python-pca/test_lease_vectors.py | test_scenarios |
| C-509 | packages/pca-grants/src/breakglass.test.ts | refuse a window over 24 hours, a budget outside 1..16 and a bad review clock when signing |
| C-509 | packages/pca-grants/src/breakglass.test.ts | keeps a numbered use log and the exact review deadline |
| C-510 | packages/pca-grants/src/breakglass.test.ts | are current (BREAK_GLASS_VECTORS_WRITE=1 regenerates them) and the reference agrees with every expectation |
| C-510 | packages/pca-grants/src/breakglass.test.ts | fails closed: a bad frozen query is frozen, a failing store refuses |
| C-511 | packages/pca/src/mutation-kill-k8.test.ts | typed decisions: exact result objects |
| C-511 | packages/pca/src/k8-ops-vectors.test.ts | is current and the reference agrees with every hand-written expectation (K8_VECTORS_WRITE=1 regenerates it) |
| C-512 | packages/pca/src/mutation-kill-k8.test.ts | bind never writes into prototypes and never takes verb or resource |
| C-513 | packages/pca/src/mutation-kill-k8.test.ts | decide is deterministic and names who said no |
| C-513 | packages/pca/src/mutation-kill-k8.test.ts | limits |
| C-514 | packages/pca/src/mutation-kill-k8.test.ts | createLink binds, resolves and verifies |
| C-514 | packages/pca/src/mutation-kill-k8.test.ts | template_ref shape: exact messages |
| C-515 | packages/pca-grants/src/lease.test.ts | the in-memory store passes |
| C-515 | packages/pca-grants/src/lease.test.ts | the crash-safe durable state passes |
| C-515 | packages/pca-grants/src/lease.test.ts | bad shard counts and ceilings are refused at construction |
| T-608 | packages/pca-grants/src/breakglass.test.ts | refuse a window over 24 hours, a budget outside 1..16 and a bad review clock when signing |
| T-609 | packages/pca-grants/src/breakglass.test.ts | fails closed: a bad frozen query is frozen, a failing store refuses |
| T-610 | packages/pca/src/mutation-kill-k8.test.ts | typed decisions: exact result objects |
| T-611 | packages/pca/src/mutation-kill-k8.test.ts | bind never writes into prototypes and never takes verb or resource |
| T-612 | packages/pca/src/mutation-kill-k8.test.ts | decide is deterministic and names who said no |
| T-613 | packages/pca-grants/src/lease.test.ts | the in-memory store passes |
| T-614 | packages/pca/src/mutation-kill-k8.test.ts | createLink binds, resolves and verifies |
| C-540 | packages/pca-sandbox/src/sandbox.test.ts | mints only for exactly the operation the verifier allowed |
| C-540 | packages/pca-sandbox/src/sandbox.test.ts | refuses a result the verifier denied |
| C-540 | packages/pca-sandbox/src/sandbox.test.ts | refuses a table below the class the grant requires |
| C-540 | packages/pca-sandbox/src/sandbox.test.ts | validates uses |
| C-541 | packages/pca-sandbox/src/sandbox.test.ts | a child takes uses from its parent and can never widen |
| C-541 | packages/pca-sandbox/src/sandbox.test.ts | revoking a parent revokes the whole subtree |
| C-542 | packages/pca-sandbox/src/sandbox.test.ts | refuses a tool that imports anything else |
| C-542 | packages/pca-sandbox/src/sandbox.test.ts | refuses memory without a declared maximum |
| C-542 | packages/pca-sandbox/src/sandbox.test.ts | refuses malformed, empty and oversized modules |
| C-542 | packages/pca-sandbox/src/sandbox.test.ts | two sandboxes are separate capability spaces |
| C-542 | packages/pca-sandbox/src/sandbox.test.ts | refuses ambient imports, traps and a missing entry without running |
| C-542 | packages/pca-sandbox/src/sandbox.test.ts | kills a tool that never returns at the timeout |
| C-542 | packages/pca-sandbox/src/demo.test.ts | a sandboxed tool cannot reach an unlisted host |
| C-543 | packages/pca-sandbox/src/sandbox.test.ts | runs the executor on the signed params, once, and receipts it |
| C-543 | packages/pca-sandbox/src/sandbox.test.ts | a failing executor still spends the use |
| C-543 | packages/pca-sandbox/src/sandbox.test.ts | refuses when no executor exists for the verb |
| C-543 | packages/pca-sandbox/src/sandbox.test.ts | expires |
| C-543 | packages/pca-sandbox/src/sandbox.test.ts | verifies, and fails on every tamper |
| C-544 | packages/pca-sandbox/src/egress.test.ts | denies everything when nothing is admitted |
| C-544 | packages/pca-sandbox/src/egress.test.ts | each deviation is refused |
| C-544 | packages/pca-sandbox/src/egress.test.ts | path prefix admits children only on a segment boundary |
| C-544 | packages/pca-sandbox/src/egress.test.ts | a body is allowed only with a matching body hash |
| C-544 | packages/pca-sandbox/src/egress.test.ts | admit refuses an unauthorized operation |
| C-544 | packages/pca-sandbox/src/egress.test.ts | forwards the admitted request once and receipts both outcomes |
| C-544 | packages/pca-sandbox/src/egress.test.ts | CONNECT: tunnels only to an admitted host:port |
| C-545 | packages/pca-sandbox/src/egress.test.ts | flags private, loopback, link-local |
| C-545 | packages/pca-sandbox/src/egress.test.ts | SSRF guard: with allowPrivate off |
| C-546 | packages/pca-sandbox/src/profiles.test.ts | sandbox-vectors.json is a fresh generation |
| C-546 | packages/pca-sandbox/src/profiles.test.ts | refuses every unsafe path rather than escaping it |
| C-546 | packages/pca-sandbox/src/profiles.test.ts | compiles authorized operations and refuses an unauthorized one |
| C-546 | packages/pca-sandbox/src/profiles.test.ts | seccomp: default deny |
| C-546 | packages/pca-sandbox/src/profiles.test.ts | landlock: handles every right |
| C-546 | packages/pca-sandbox/src/profiles.test.ts | macOS: deny default |
| C-546 | packages/pca-sandbox/src/profiles.test.ts | a tool in the sandbox can reach the egress proxy |
| C-547 | packages/pca-sandbox/src/sandbox.test.ts | orders the classes and refuses unknown names |
| T-640 | packages/pca-sandbox/src/sandbox.test.ts | revoking a parent revokes the whole subtree |
| T-640 | packages/pca-sandbox/src/sandbox.test.ts | refuses when no executor exists for the verb |
| T-641 | packages/pca-sandbox/src/sandbox.test.ts | refuses a tool that imports anything else |
| T-641 | packages/pca-sandbox/src/sandbox.test.ts | refuses memory without a declared maximum |
| T-642 | packages/pca-sandbox/src/egress.test.ts | each deviation is refused |
| T-642 | packages/pca-sandbox/src/egress.test.ts | path prefix admits children only on a segment boundary |
| T-643 | packages/pca-sandbox/src/egress.test.ts | SSRF guard: with allowPrivate off |
| T-644 | packages/pca-sandbox/src/profiles.test.ts | refuses every unsafe path rather than escaping it |
| T-645 | packages/pca-sandbox/src/sandbox.test.ts | verifies, and fails on every tamper |
| T-646 | packages/pca-sandbox/src/sandbox.test.ts | a failing executor still spends the use |
| T-646 | packages/pca-sandbox/src/sandbox.test.ts | runs the executor on the signed params, once, and receipts it |
| C-547 | packages/pca-sandbox/src/runtime-claim.test.ts | everything that does not verify is none |
| C-547 | packages/pca-sandbox/src/runtime-claim.test.ts | a sandbox without verifiable evidence is class none |
| C-547 | packages/pca-sandbox/src/runtime-claim.test.ts | a valid claim proves its class |
| C-547 | packages/pca-sandbox/src/runtime-claim.test.ts | are a fresh generation |
| C-542 | packages/pca-sandbox/src/component.test.ts | a component built for the world calls invoke through the canonical ABI |
| C-542 | packages/pca-sandbox/src/component.test.ts | the host codes come back through result |
| C-542 | packages/pca-sandbox/src/component.test.ts | refuses any other import before it runs |
| C-542 | packages/pca-sandbox/src/component.test.ts | fuel: a tool that never returns |
| C-542 | packages/pca-sandbox/src/component-protocol.test.ts | answers count, verb and invoke from the table |
| C-542 | packages/pca-sandbox/src/kill.test.ts | module size: exactly the cap runs |
| C-542 | packages/pca-sandbox/src/kill.test.ts | memory pages |
| C-542 | packages/pca-sandbox/src/kill.test.ts | handle_verb: writes the verb into guest memory |
| C-543 | packages/pca-sandbox/src/kill.test.ts | pins every field of a receipt and its digest |
| C-543 | packages/pca-sandbox/src/kill.test.ts | a use is spent before the executor runs |
| C-540 | packages/pca-sandbox/src/kill.test.ts | uses: 1 and 1_000_000 mint |
| C-541 | packages/pca-sandbox/src/kill.test.ts | attenuate: exactly the parent uses |
| C-544 | packages/pca-sandbox/src/kill.test.ts | port 1 and 65535 are admitted |
| C-545 | packages/pca-sandbox/src/kill.test.ts | private ranges: the exact edges |
| C-546 | packages/pca-sandbox/src/kill.test.ts | flattens the generated profiles with nothing added |
| C-546 | packages/pca-sandbox/src/kill.test.ts | pins the whole profile for a known policy |
| C-546 | packages/pca-sandbox/src/linux.test.ts | Landlock: the granted path reads |
| C-546 | packages/pca-sandbox/src/linux.test.ts | seccomp: syscalls outside the allowlist fail with EPERM |
| C-546 | packages/pca-sandbox/src/linux.test.ts | egress only via the proxy |
| C-546 | packages/pca-sandbox/src/linux.test.ts | the helper fails closed |
| C-547 | packages/pca-sandbox/src/runtime-claim.test.ts | admits the digest only for ok and bound evidence |
| C-547 | packages/pca-sandbox/src/runtime-claim.test.ts | end to end: a claim over verified evidence |
| C-547 | packages/pca-sandbox/src/kill.test.ts | valid at iat, valid at exp-1 |
| T-641 | packages/pca-sandbox/src/component.test.ts | refuses any other import before it runs |
| T-641 | packages/pca-sandbox/src/component.test.ts | fuel: a tool that never returns |
| T-644 | packages/pca-sandbox/src/linux.test.ts | the helper fails closed |
| T-642 | packages/pca-sandbox/src/linux.test.ts | egress only via the proxy |
| C-547 | sdks/python-pca/test_runtime_claim_vectors.py | test_cases |
| C-547 | sdks/go-pca/runtime_claim_test.go | TestRuntimeClaimVectors |
| C-547 | sdks/rust-pca/tests/runtime_claim_vectors.rs | runtime_claim_vectors |
| C-547 | sdks/ruby-pca/test/test_runtime_claim.rb | test_cases |
| C-547 | sdks/php-pca/tests/VectorsTest.php | testRuntimeClaimVectors |
| C-547 | sdks/swift-pca/Tests/AtlasPCAVerifyTests/RuntimeClaimVectorTests.swift | testRuntimeClaimVectors |
| C-547 | sdks/java-pca/test/net/atlasauth/pca/RuntimeClaimVectorsTest.java | cases |
| C-547 | sdks/kotlin-pca/src/test/kotlin/net/atlasauth/pca/verifier/RuntimeClaimVectorsTest.kt | cases |
| C-547 | sdks/dotnet-pca/AtlasPca.Corpus.Tests/RuntimeClaimVectorTests.cs | EveryCaseDecidesLikeTheReference |
| C-380 | packages/pca-intent/src/fail-closed-table.test.ts | is refused |
| C-380 | packages/pca-intent/src/fail-closed-table.test.ts | no trials, or every trial failed, is the widest bound |
| C-380 | packages/pca-intent/src/fail-closed-table.test.ts | a dropped cell |
| C-380 | packages/pca-intent/src/fail-closed-table.test.ts | once raised, the alarm stays raised |
| C-380 | packages/pca-intent/src/fail-closed-table.test.ts | verifyOutcome for a verb not in the outcome space throws |
| T-480 | packages/pca-intent/src/fail-closed-table.test.ts | no trials, or every trial failed, is the widest bound |
| T-480 | packages/pca-intent/src/fail-closed-table.test.ts | a dropped cell |

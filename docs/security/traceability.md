---
title: Traceability
order: 32
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
| T-008 | NO AUTOMATED TEST | - |
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
| T-015 | NO AUTOMATED TEST | - |
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
| T-019 | NO AUTOMATED TEST | - |
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
| T-040 | packages/pca/src/adversarial.test.ts | two validly-witnessed heads at the same size with different roots prove EQUIVOCATION |
| T-040 | packages/pca/src/adversarial.test.ts | the witness-threshold is FAIL-CLOSED |
| T-040 | packages/pca/src/adversarial.test.ts | a FORGED prev_root on adjacent heads breaks verifyHeadConsistency |
| T-040 | packages/pca/src/ledger.test.ts | a rewritten history is not consistent with the old head |
| T-040 | packages/pca/src/ledger.test.ts | split view: two conflicting roots at the same size cannot both gather an honest-witness threshold |
| T-040 | packages/pca/src/mesh.test.ts | refuses equivocation (same size, different log) and rollback |
| T-040 | packages/pca/src/mesh.test.ts | rejects a head cosigned only by unpinned (attacker) witnesses |
| T-041 | NO AUTOMATED TEST | - |
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
| T-050 | packages/pca/src/prohibitions.test.ts | an unresolvable trigger condition counts as MATCHED |
| T-050 | packages/pca/src/prohibitions.test.ts | forged all-clear evidence for a violating action is rejected |
| T-050 | packages/pca/src/prohibitions.test.ts | prohibitions are independent of the plan |
| T-050 | packages/pca/src/prohibitions.test.ts | daily spend cap triggers across a sequence and the window rolls |
| T-051 | packages/pca/src/grant-ref-binding.test.ts | grant_ref_bound closes the replay-namespace bypass |
| T-051 | packages/pca/src/grant-ref-binding.test.ts | grant_ref_bound: the check |
| T-051 | packages/pca-conformance/adversarial/gen-adversarial.ts | grant-ref-bound |

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
| G-13 | packages/pca/src/adversarial.test.ts | under-reporting caution gains the agent NOTHING |
| G-13 | packages/pca/src/taint.test.ts | is MONOTONE: adding a ref can only raise taint, never lower it |
| G-13 | packages/pca/src/taint.test.ts | a missing registry in the context fails closed |
| G-13 | packages/pca/src/agent-native.test.ts | under-report gains nothing; over-report escalates |
| G-14 | packages/pca/src/optimistic.test.ts | an out-of-policy optimistic claim yields a verifying fraud proof -> slash |
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

## Gaps

Entries marked `NO AUTOMATED TEST` above, with the reason. Other entries listed under "Partial coverage" have tests, but the tests do not cover the whole stated residual.

### No automated test

- **T-008**: No concurrent / multi-node test of the counter and budget store; only a single-node store is exercised.
- **T-015**: By design: PCA provides no confidentiality. Nothing to test.
- **T-019**: By design (non-goal N-1): a compromised principal cannot be detected or stopped by PCA.
- **T-041**: No test demonstrates that a resource server rejects an action lacking a witnessed inclusion proof, and omission is undetectable from the log alone.

### Partial coverage

These IDs have tests for the mitigation but not for the whole claim:

- **T-001 / G-5**: counter monotonicity is tested against the in-memory single-node store in the resource-server middleware. The core verifier only checks that the counter is well-formed. Multi-node behaviour is untested (see T-008).
- **T-009**: freshness and pre-revocation rejection are tested; there is no test that re-checks authority at effect time, which is the resource server's job.
- **T-016**: sub-threshold failure is tested for FROST, the multi-signature, and PQ quorums. Separate-trust-domain custody cannot be tested in a single process.
- **T-028 / T-029**: failure of one root among several is tested with synthetic and real-fixture roots. No test simulates a compromised vendor signing key.
- **T-035**: audience reuse and proof replay are tested; a malicious server misreporting effects is out of what the library can test.
- **T-040**: equivocation proofs are tested with in-process witnesses. No independent third-party witness is operated or tested.
- **T-044**: the TypeScript implementation is tested against the frozen conformance vectors. Differential results for the other language SDKs are produced by the separate cross-language conformance run and are not asserted here.
- **T-045**: tests show byte-exact handling (astral key order, lone surrogates) and that NFC/NFD, homoglyph, zero-width, bidi, fullwidth and case variants of an identifier are never treated as equal in verb, resource, condition, caveat-type, audience and digest decisions, in both the allow and deny directions. The library still does not normalize (by design), so there is no helper test for integrators who normalize before authorizing.
- **T-046**: the nesting-depth, chain-depth, tool-argument and regex bounds are tested, and oversized and deeply nested inputs are submitted to the strict parser entry points (`strictParse`, `strictParseBytes`, `decodePCActn`) and the other decoders under a per-test time budget. `decodePcaHeader` itself has no size cap (HTTP servers bound header size); the oversize is refused one step later by `decodePCActn`. Volumetric flooding and signature-verification cost are not tested.
- **T-048**: known-answer vectors catch wrong output only. There is no test for dependency provenance or lockfile integrity.
- **T-049**: only the receipt-integrity comparison on the verifier surface is tested. No constant-time or timing measurement exists for the signer, the FROST scalar arithmetic or the DKG.
- **T-047**: PQ and hybrid suites are tested for correctness and downgrade resistance. No test asserts that a classical-only artifact is rejected after a given date, because that is a policy decision.

### Gaps worth filling

Highest value first:

1. **Concurrent counter/budget race (T-008).** A test that runs N parallel `requirePCA` calls with the same counter against a shared store and asserts exactly one wins, and parallel spends never exceed the budget.
2. **Normalization helper (T-045).** The byte-exact behaviour is tested; what remains is a helper test for integrators who normalize before authorizing.
3. **Resource-server inclusion-proof requirement (T-041).** A test that an action without a witnessed inclusion proof is refused when the resource server requires one.
4. **Effect-time re-check (T-009).** A test of a verify-then-revoke-then-execute sequence with the documented re-check hook.
5. **Cross-SDK differential fuzzing (T-044).** An automated differential fuzzer across the language SDKs on the strict parser.
6. **Side-channel evidence (T-049).** A timing-distribution test for the verifier and a documented constant-time review of signer arithmetic.
7. **Compromised vendor key simulation (T-028).** A test where one of several roots signs a forged token with a valid-looking chain and the N-of-M policy denies.

### Not applicable to automated testing

- **T-015** (passive eavesdropping) and **T-019** (compromised principal) are non-goals; they are listed so the matrix is complete.

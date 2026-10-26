---
title: Audit package
order: 41
---

# PCA audit package for the cryptographic units

This page lists what an independent reviewer receives for each cryptographic unit that is waiting for review, a trusted-setup ceremony or real hardware. It extends the [audit scope](./audit-scope.md), which describes the whole system. It is the evidence side of the label **experimental: hardened, awaiting audit** (tier `hardened` in [Maturity tiers](../maturity.md)).

**What the label means.** The engineering that can be done before an outside review has been done and is evidenced below: constant-time arithmetic where the runtime allows it, known-answer tests, a second implementation cross-checking the output, parser fuzzing, and fail-closed handling of every error. **None of these units has been independently audited, and none is called production-ready.** A unit leaves this label only when the review (or ceremony, or hardware programme) named in its row has happened and its findings are fixed.

## What every unit comes with

| Item | Where it comes from |
|---|---|
| Source at a fixed release candidate | the tag the auditor is given; the package builds from a clean checkout with the lockfile |
| Specification | the standard it implements (RFC, FIPS or draft, with the version), or, for a PCA-specific construction, the design text in the unit's source header |
| Test vectors | official vectors where they exist; otherwise vectors from a second implementation, with the tool that produced them |
| Fuzz corpora | seeds and regression inputs for every binary, ASN.1, CBOR and JWT parser; the harness runs for a bounded time in CI |
| Mutation results | the surviving-mutant ledger, every survivor reviewed |
| Known limitations | in each row below, stated plainly |
| Timing report | for units that handle secret scalars: a dudect-style report with a positive control that must be flagged |

## FROST threshold signing and the DKG

**Scope.** Threshold Schnorr signing over Ed25519 (RFC 9591), the dealer-less key generation (a PedPoP variant with proofs of possession, a blame round and an echo round), the networked signer and coordinator, the durable nonce store, and the hybrid with an ML-DSA co-signature. The default step-up in PCA stays the independent-share multi-signature; use FROST only if you need one signature out of `t` of `n` shares.

**Evidence.**

- *Constant-time scalar arithmetic.* Every secret-dependent scalar operation (nonce derivation, signature shares, polynomial evaluation, DKG share sums, proofs of possession) runs on the fixed-width, branch-free module `ct-scalar`: 16-bit limbs, fixed loop bounds, mask selects, no secret-indexed access. It is checked against BigInt arithmetic on edge values and random pairs. The timing report uses a replaced-BigInt control that is flagged as leaking (|t| about 18) and shows no leak for the new path (|t| below 3). Limits: a JIT runtime cannot be proved constant-time; building the BigInt that @noble/curves expects from secret bytes is not constant-time; point multiplication is the library's.
- *Known-answer tests.* The RFC 9591 Appendix vectors reproduce byte for byte (hiding and binding nonces, commitments, binding factors, group commitment, signature shares, aggregate).
- *Independent implementation.* A small Rust tool (`pca-frost-xcheck`) uses the Zcash Foundation `frost-ed25519` crate and `curve25519-dalek`. Two directions. (1) The foundation crate runs its own DKG and a signing round with recorded nonces; PCA reproduces every key relation, signature share and the aggregate signature byte for byte, for 2-of-3 and 3-of-5. (2) PCA runs its DKG with fixed seeds; the tool re-derives the group key, the group commitment and every verifying share with dalek, and signs with the foundation crate using PCA's key shares and nonces: its shares and aggregate equal PCA's. A tampered vector is rejected (negative control). The PCA DKG itself has no standard to take vectors from, so these cross-checks cover its output, not its message flow.
- *Nonce handling and recovery.* Nonces are one-shot (re-use throws, a byte-clone of a spent nonce is refused by commitment). A pluggable durable store marks a session spent *before* the share is computed: a crash loses the session and never reuses a nonce. Tests cover a restart between rounds, a restart after the share, a crash between the marker and the share, a store that fails on create (no commitment released) and on spend (no share released), and a store contract checker with a negative control.
- *Fail closed.* Malformed identifiers, points (small-order, torsion, non-canonical), scalars, commitment lists and verification shares are rejected. A bad signature share is named and refused before aggregation.
- *Mutation testing.* The `mutation-kill` suites over frost, frost-dkg, frost-net, frost-pq and pq-threshold (the surviving-mutant ledger lists every reviewed survivor).

**Known limitations.** The DKG assumes an authenticated broadcast channel and private point-to-point channels that the caller provides; there is no reference channel implementation yet. The DKG is a custom construction, not a standard. In-process coordinators hold every share in one address space. Signing and DKG exist only in TypeScript; the native verifiers check the aggregate as ordinary Ed25519. Two copies of the hybrid FROST + ML-DSA code exist (in the core package and in `pca-pq-threshold`) and should be merged before review.

**Awaiting.** Independent cryptographic review of the signing implementation (nonce lifecycle, binding factors, timing) and of the DKG design.

## Zero-knowledge compliance (Groth16 and Policy-VM SNARK)

**Scope.** The verifier and prover glue for the Groth16 compliance circuit (BN254) and the Policy-VM circuit (BN254 and BLS12-381), the circuits themselves, and the trusted-setup tooling. The attested-VM mode is a trusted signer, not a proof, and is outside this row.

**Evidence.**

- *Ceremony tooling.* A command-line tool runs a multi-party Phase 2 setup per circuit: initialise from a pinned Phase 1 file (hash checked), one contribution per participant, per-contribution verification, a public random beacon, finalisation with verifying-key export, and publication of the transcript with hashes. A transcript verifier fails closed on a missing file, a flipped key byte, a swapped circuit, a wrong pinned circuit or transcript hash, a removed beacon, a dropped contribution, too few contributions and a replaced verifying key. A participant guide and a coordinator runbook accompany it. It has been run end to end only on a small toy circuit with a development Phase 1 file; the real circuits have not been through it.
- *Honest label.* The bundled keys come from single-party development scripts, which now refuse to run unless `PCA_DEV_SETUP=1` is set and which write a `ceremony: single-party` marker. The assurance report of both SNARK backends carries a `ceremony` field: `single-party` unless a transcript hash pinned out of band names the verifying key in use, in which case `multi-party`. This states how the key was made, not that the circuit is correct.
- *Circuit constraint tests.* For both curves' committed Policy-VM fixtures, each of the 15 public signals fails verification when changed and when pushed to a non-canonical value. Witness-perturbation tests exist for both circuits but need the circom toolchain to build the circuits; they are skipped where it is absent and have not been shown to pass.
- *Verifying-key identity.* A verifying-key id is the hash of the verifying key, so a new setup is a new id.
- Existing: tests for pinning, canonical encoding, binding tag and BLS12-381, and a fake-snarkjs mutation suite.

**Known limitations.** The Policy-VM circuit takes its risk inputs from the prover (not yet bound in the statement); its commitments are SHA-256 over a fixed layout, not canonical JSON; it covers a quantised subset of the predicate language; the six-to-one binding change needs a new setup; no widely contributed Phase 1 file exists for BLS12-381; the circuit has about 151,585 constraints and needs a 2^18 Phase 1 file. There is no committed proof for the compliance circuit and no second (Rust) verifier.

**Awaiting.** A real multi-party Phase 2 ceremony per circuit, and an independent circuit audit (under-constrained signals are the classic failure).

## Hybrid KEM, post-quantum signature verifiers, FN-DSA

**Scope.** The hybrid KEM (ML-KEM-768 and 1024 with X25519, and X-Wing), the ML-DSA and SLH-DSA verifiers and hybrids, and the FN-DSA suite and its WebAssembly backend.

**Evidence.** X-Wing draft Appendix C vectors; hybrid vectors produced by OpenSSL through a separate code path, with abuse tests (wrong lengths, implicit rejection on a mutated ciphertext, zero ephemeral key); ML-DSA-65 ACVP vectors; ML-DSA-65 and -87 and SLH-DSA-SHA2-128f and -256s cross-checked in both directions against OpenSSL; decapsulation and verifier fuzz targets that must never throw an untyped error nor accept a mutation; a timing target for decapsulation.

**Known limitations.** The hybrid combiner is a bespoke HKDF construction, not a standard. FN-DSA (FIPS 206) is still a draft: tests use the mock backend and Falcon round-3 vectors. ML-DSA signing uses rejection sampling, so its timing depends on values by design.

**Awaiting.** Review of the combiner and of the WebAssembly binding; the final FIPS 206 and its vectors.

## Aggregate signatures, BBS, OPRF, ratchet

| Unit | Parsers fuzzed | Known-answer sources | Known limitations |
|---|---|---|---|
| `pca-aggsig` (BLS aggregation) | key registration with a mutated key and proof | Ethereum BLS12-381 test vectors (v0.1.2) and a py_ecc corpus; rogue-key and subgroup-check tests | BLS12-381 is not post-quantum; aggregation and proof-of-possession usage need review |
| `pca-bbs` | secret-key decoding | CFRG draft vectors and an independent implementation's corpus | one ciphersuite; the draft is not final |
| `pca-oprf` (RFC 9497, PSI) | element and scalar deserialisation | all RFC 9497 vectors and a second-implementation corpus; identity-element and malformed-element tests | the PSI composition and the private-revocation protocol need review |
| `pca-ratchet` | leaf-signature verification | ristretto oracle vectors and a Rust oracle | bespoke construction; a Merkle path's `size` is not authenticated by the root (it proves leaf-under-root for any size consistent with the path length) |

## Hardware attestation verifiers, x509, EAT

**Scope.** Quote, report and certificate parsing and chain logic for AMD SEV-SNP, Intel TDX and DCAP, NVIDIA SPDM, RIM and OCSP, Azure Attestation, Google Confidential Space, the strict x509 helpers, and EAT.

**Evidence.** Real captured evidence from each vendor as test fixtures; fuzz targets for every parser (DER and x509 readers, chain role checks, validity, time strings, PEM splitting, TBS extraction, report-to-certificate binding, quote and report parsers, JWT-based evidence, EAT) seeded from those fixtures; the fuzz harness fails on a crash, an untyped error, a hang or a single input that allocates more than 512 MiB.

**Known limitations.** No fuzzing of live collateral fetch. A live canary against current vendor collateral (SNP, TDX, H100) is not in place, so collateral rotation and TCB recovery are untested against real services. The vendor roots are a fixed trust assumption. CWT/COSE evidence is not implemented.

**Awaiting.** Independent review of the parsers and chain logic, and the hardware programme (scheduled verification of fresh quotes).

## Reproducing the evidence

- Unit tests: `vitest` in `@atlasauth/pca` (FROST and DKG, KEM, PQ, ZK, ceremony).
- Independent FROST cross-check: `pca-frost-xcheck` (`run.sh check`, `run.sh selftest`).
- Timing: the dudect-style harness with its positive and negative controls.
- Fuzzing: the fuzz harness with `--regress` for the committed corpus and `--budget-seconds N` for a bounded run; the scheduled workflow runs both.
- Maturity: the maturity check confirms every module has a tier and that Core imports nothing below production.

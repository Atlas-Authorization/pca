# PCA security analysis: theorems, proofs, concrete bounds, and gaps

This directory is the cryptographic appendix for Proof-Carrying Authority (PCA). It is written the way a paper appendix would be: for each area it gives the assumptions, the theorem, the proof, the concrete security, and the gaps.
It was written by reading the code first; every statement matches what is implemented, and every deviation from a cited paper is listed. It is **a self-analysis, not an independent audit**, and it is not machine-checked.

| File | Area |
|---|---|
| [`01-core.md`](01-core.md) | canonical encoding, domain separation, Merkle binding, action-authorization unforgeability, capability attenuation, freshness, replay-freedom |
| [`02-threshold-hybrid.md`](02-threshold-hybrid.md) | role-bound $t$-of-$n$ multisig, FROST aggregate and descriptor binding, hybrid PQ combiner (AND and nested), Falcon/LESS notes |
| [`03-attestation.md`](03-attestation.md) | `report_data = H(binding)`, relay resistance, the named hardware-root assumption list |
| [`04-ratchet.md`](04-ratchet.md) | Pedersen binding/hiding, OR/range proofs, special soundness, HVZK, Fiat-Shamir domain separation, GGM forward security |
| [`05-abe.md`](05-abe.md) | BSW07 versus the type-3 adaptation, algebraic independence proof, KEM-DEM composition |
| [`06-mpc.md`](06-mpc.md) | SPDZ-style malicious-with-abort model, soundness errors with exact numbers, input monotonicity, what a UC proof needs |
| [`07-stark-fri.md`](07-stark-fri.md) | proven versus conjectured bits for the pinned Winterfell and Plonky3 options, assumptions, absence of zero knowledge |
| [`bounds.py`](bounds.py) | reproduces every number (standard library only) |
| [`repro/`](repro) | proof-of-concept programs for each discrepancy and library cross-checks |

## Status legend

* **P**: proved, the full argument is in the file.
* **PM**: proved in a stated idealised model (random oracle, generic group); the model is named at the theorem.
* **R**: reduced to a stated assumption; the reduction is given, the assumption (a cited theorem or hardness hypothesis) is not re-proved here.
* **O**: open; not proved, or proved only partially. Where only a shape is established, the text says which part.

I did not mark anything P that depends on an unproved assumption, and I did not substitute a heuristic for a proof; where a constant of a cited theorem was not re-derived the theorem is tagged PM or R and the constant is marked O.

## Theorem list

| ID | Statement | Status |
|---|---|---|
| Lemma 1.1 | strict Ed25519 verification = cofactorless equation on canonical torsion-free inputs | P |
| Lemma 2.1, Cor. 2.2 | canonical JSON encoding injective; digest binding | P |
| Lemma 3.1 | domain separation of capability, PCActn and share messages | P |
| Lemma 4.1 | Merkle plan-commitment binding | P |
| **C-1** | action-authorization soundness: $\Pr\le\mathrm{Adv}^{\mathrm{cr}}+\mu\,\varepsilon_{\mathrm{Ed}}$ | R |
| C-1b | uniqueness of the accepted byte string | R |
| **C-2, C-3** | structural attenuation; attenuation monotonicity of accepted actions | P |
| C-4 | combination: accepted action lies in the last honest hop's permission set | R |
| 5.3 | "authorised" equals what the principal meant (specification gap) | O |
| **C-5, C-6** | replay-freedom under the store contract and clock-skew assumption | P |
| **TH-1** | role-bound $t$-of-$n$ multisig unforgeable, loss factor 3 | R |
| TH-2, TH-3 | no role / signer-set / threshold / suite confusion; counted keys = distinct roles | P |
| TH-4 | corrected composition (integrator must supply the server's $t$) | R |
| FR-1 | a FROST aggregate passes the strict Ed25519 predicate | P |
| FR-2 | FROST threshold unforgeability (static corruption, OMDL/AOMDL, ROM) | R |
| FR-3 | PedPoP DKG and the blame/signed-share extensions | O |
| FR-4 | the threshold of a bare FROST key is unverifiable | P |
| **FR-5** | descriptor binds $(X_g,t,n,\kappa)$ under a pinned authority | R |
| **H-1** | AND-combiner EUF-CMA if either component is, pinned keys | P |
| H-2, H-3 | SUF-CMA of the plain and nested combiners | P |
| **H-4** | the implemented leaf/hop hybrid has exactly Ed25519's security (PQ key unpinned) | P (negative) |
| AT-1, AT-2, AT-3 | binding injectivity and collision bound; nonce freshness | P / R / P |
| **AT-4** | relay resistance, conditional on assumptions H1-H9 | R |
| PD-1, PD-2 | Pedersen binding (DL) and hiding (SD $<2^{-251}$) | R / P |
| RP-1, RP-2 | range/budget proof perfect completeness; special soundness | P |
| RP-3, **RP-4** | knowledge soundness (ROM) and bounded-budget soundness | PM (loss O) / R+PM |
| RP-5, RP-6, RP-7 | necessity of per-commitment proofs; special HVZK; NIZK in programmable ROM | P / P / PM |
| GG-1, **GG-2** | HMAC PRG; forward-secure unforgeability with loss $2^d(d+2)$ | P / R |
| GG-3 | no double-spend resistance against the state holder | P (negative) |
| ABE-A, ABE-B | Shamir-tree span property; algebraic independence in the type-3 model | P |
| **ABE-1, ABE-2, ABE-3** | KEM CPA security (type-3 GGM+ROM), collusion resistance, full-scheme CPA | PM (constant O) |
| ABE-4 | policy equals decryptability | P |
| ABE adaptive / CCA | | O |
| **MPC-1** | MAC-check soundness $(2/(p-1))^2\approx2^{-120}$, sequentially composable | P |
| **MPC-2** | sacrifice $(1/(p-1))^2\approx2^{-122}$ (network), $(2/p)^2$ (in-process) | P |
| MPC §4 | total online error $\approx2^{-114.3}$ ($Q{=}100,n{=}3$) | P (given MPC-A) |
| **MPC-3** | corrupted inputs cannot loosen allow / $t$ / $r$ | P |
| MPC-4 | share privacy and masked openings | P |
| MPC-A, UC | MAC-key secrecy in dealer-free mode; UC proof | O |
| ST-1, ST-2, ST-3 | Winterfell 110 / 54 / 30 (HEAD 95 / 47 / 26); Plonky3 proven 70 / 50, conjectured 112-113; query phase binds | P over R |
| ST-4, ST-7 | capacity conjecture; post-quantum (QROM) soundness | O |
| **ST-6** | the STARK proofs reveal the witness (no zero knowledge) | P (with PoC) |

## Assumption index

SHA-256 collision resistance (generic birthday); Ed25519 SUF-CMA under the strict predicate (cited: RFC 8032, Bernstein et al. 2012, Brendel et al. S&P 2021); discrete logarithm in ristretto255 for the specific second generator (`DL-H`); HMAC-SHA256 as a PRF; AES-256-GCM; HKDF-SHA256 and SHA-512 as random oracles where stated; generic bilinear group model with hash-to-curve as a random oracle (ABE); FROST/OMDL in the ROM (cited); proximity gaps (BCIKS20 and successors) and, for the conjectured rows, the ethSTARK capacity conjecture; hardware assumptions H1-H9 of `03-attestation.md`; the replay-store contract and bounded clock skew of `01-core.md` section 7.

## Deviations from repository claims discovered while writing the proofs

Details, line numbers and reproductions are in the area files; the same list is in the report that accompanied this work. Severity is my judgement. **No file outside this directory was changed.**

| # | Severity | Claim | Reality | Where |
|---|---|---|---|---|
| F-1 | High (integrator-visible) | an agent is "t-1 short" at higher thresholds (`threshold.ts` header); `verifyPCActn` demands the hook pass when the server's $t>1$ (`server/verify.ts:294`) | default `createThresholdVerifier` takes $t$ from the agent-signed `risk_claim.r` (`threshold.ts:368-373, 387`); the gate checks only "pass": allow with $t_{\mathrm{srv}}=3$ and $t_{\mathrm{claimed}}=1$ | `02` section A.3 |
| F-2 | High (PQ claim) | hybrid "a forger must break BOTH" (`pq.ts:30, 921, 924`); G-9 (`threat-model.md:583`) | the PQ key comes from the artifact (`pcactn.ts:566`, `capability.ts:364-376`, `threshold.ts:342`); an Ed25519 forger supplies its own ML-DSA key | `02` section C.2 |
| F-3 | High | "zk-STARK", "private witnesses" (`sdks/stark-pca/README.md:5,36`, `lib.rs:3`; plonky3 `lib.rs:3`) | witness columns are constant, no blinding: one FRI query reveals the full witness (shown on both committed proofs) | `07` section 6 |
| F-4 | Medium/High | "verifiers do not accept a suite weaker than policy" (`threat-model.md:583`) | there is no suite policy; a pure-PQ leaf is verified under its own key and ignores the holder (PoC) | `02` section C.2 |
| F-5 | Medium | nonce "consumed once" (`attestation.ts:73-74`) | the library only checks age; consumption and entropy are the integrator's | `03` H4 |
| F-6 | Low/Medium | plonky3: 127 conjectured, 72 / 51 proven (README:37, `tests/security_bits.rs`) | `p3-security 0.8.0`: 112-113 conjectured, 70 / 50 proven | `07` section 3.2 |
| F-7 | Low | ratchet "a spent action can never be re-signed" (README:5) | true only after erasure; a state copy re-signs (GG-3); adapters round risk down | `04` section 3.4 |
| F-8 | Low | sacrifice "about $2^{-122}$" (`pca-mpc-spdz-soundness.md:87`, README:125) | $2^{-120}$ in-process (`spdz.ts:285`); union bound over triples absent (about 8 bits) | `06` sections 3-4 |
| F-9 | Unverified | KOS check fails with probability $\le2^{-128}$ (`ot.ts`, README table) | KOS is stated with statistical parameter $s=64$; effective dealer-free error may be $2^{-64}$ | `06` section 6 |
| F-10 | Low | | sparse arrays canonicalise to non-JSON (`hash.ts:174`); stale "BF-IBE" comment (`attributes.ts:3-8`); unbounded Goldilocks policy parameters (`plonky3 lib.rs:182-184`); several checks `not-enforced` by default | `01`, `05`, `07` |

## Status of the findings

F-1, F-2, F-4, F-5 are fixed in code (regressions in `packages/pca/src/{threshold-server-t,pq-binding,attestation-nonce}.test.ts`, breaking changes in `docs/pca/CHANGELOG.md`); F-6, F-7, F-8, F-9 are corrected in the documentation and comments; F-10: the stale BF-IBE comment is corrected and the `not-enforced` defaults are documented in the package README (the default was not flipped: `requirePCA` already demands them). F-3 belongs to the STARK crates.

## How to reproduce

```
python3 docs/pca/security/proofs/bounds.py          # every number quoted in the files
cd packages/pca && ./node_modules/.bin/tsx ../../docs/pca/security/proofs/repro/poc_threshold_downgrade_and_hybrid_unpinned.mts
cd packages/pca && ./node_modules/.bin/tsx ../../docs/pca/security/proofs/repro/poc_pure_pq_leaf_unbound.mts
cd packages/pca && ./node_modules/.bin/tsx ../../docs/pca/security/proofs/repro/poc_canonical.mts
# Rust programs in repro/*.rs: scratch cargo projects (path dependency on the SDK, serde_json / p3-security as noted in the file header),
# built with `cargo run --offline --release` and a private CARGO_TARGET_DIR.
```
The Rust cross-checks print: Winterfell `conjectured 110 proven LDR 54 proven UDR 30`; Plonky3 (`p3-security 0.8.0`) `proven UDR=50 LDR=70 conjectured=112/113`; and the leaked witness `[100000, 900000, 50000, 0, 950000, 100000, 1000000, ...]` from both committed proofs.

## What this is not

* Not an independent review. The code was read by the author of the proofs; the proofs have not been checked by a second cryptographer.
* Not a proof that the implementations match the mathematics beyond the code paths read (listed at the head of each file); constant-time behaviour, side channels, memory safety and the hosted server are out of scope.
* Not a UC proof for any protocol; section 7 of `06-mpc.md` lists what that would require.
* Not a statement about the eight non-TypeScript verifiers.

## Appendix: NUL-terminated `atlas-pca/` signing/hash domains in `packages/pca/src` (non-test)

`zk-compliance/v1`, `sth/v1`, `sth-witness/v2`, `signerset/v1`, `semantic-judge/v1`, `safety-evidence/v1`, `safety-cert/v1`, `revoke/v1`, `revepoch/v1`, `progress-state-attestation/v1`, `pq-quorum-msg/v1`, `optimistic/v1`, `mesh-xref/v1`, `mesh-xcap/v1`, `mesh-xanchor/v1`, `mesh-head/v1`, `mesh-cosig/v1`, `mesh-binding/v1`, `mesh-action/v1`, `mesh-action-digest/v1`, `ledger-head/v1`, `kem/x25519-ml-kem-768/v1`, `kem/x25519-ml-kem-1024/v1`, `goal/v1`, `frost-signer-set/v1`, `frost-pq-cosign/v1`, `contract/v1`, `constitution/v1`, `cap/v1`, `bond-settlement/v1`, `beacon/v2`, `actn/v2`; each followed by `\0`.
Non-NUL variants such as `mesh-xcap/v1` and `mesh-xref/v1` are the `v` field inside canonical JSON (`mesh.ts:1184, 1521`), not raw prefixes. By the argument of Lemma 3.1 the NUL-terminated set is pairwise prefix-free; verifying that each is used as a raw message prefix at every call site is **open**.

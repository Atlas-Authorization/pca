# Security audit in tests: the cryptographic building blocks

This is a self-audit written as executable tests, in the way an external cryptographic review would proceed:
read each construction against its specification or paper, try to misuse every entry point, try to break each
security property, and record what happened. It covers these packages:

| Package | What it is |
|---|---|
| `@atlasauth/pca-oprf` | RFC 9497 OPRF / VOPRF / POPRF on ristretto255, private revocation checks and private rate limiting |
| `@atlasauth/pca-bbs` | BBS signatures and selective-disclosure proofs on BLS12-381 (draft-irtf-cfrg-bbs-signatures) |
| `@atlasauth/pca-aggsig` | BLS aggregate signatures (proof-of-possession scheme) for delegation chains and witness quorums |
| `@atlasauth/pca-vdf` | Wesolowski verifiable delay function over an RSA group, and the timelock built on it |
| `@atlasauth/pca-fhe` | Homomorphic evaluation of the risk gate (BFV, Microsoft SEAL via node-seal) |
| `@atlasauth/pca-pq-threshold` | Hybrid post-quantum step-up: FROST(Ed25519) threshold plus an ML-DSA-65 co-signature quorum |
| `@atlasauth/pca-mpc` | Secret-shared policy composition, SPDZ MAC check, Chou-Orlandi / KEM / LWE / hybrid base OT, KOS OT extension |
| `@atlasauth/pca-mpc-wasm` | WebAssembly Ed25519 group core used by the OT |
| `@atlasauth/pca-mpc-lwe-ot-wasm` | WebAssembly K-PKE (Kyber-768) and ring core used by the LWE OT |

It is **not** an independent audit. Section 7 lists what only a human cryptographer can still judge.
The official test vectors and the cross-implementation checks for these packages already existed; this work adds
to them and does not repeat them.

Run it: `pnpm --filter <package> test`. Each package has one `audit.test.ts`. The fuzzing groups run for
`AUDIT_FUZZ_SECONDS` seconds each (default 3); the results below used 45 seconds per group.

## 1. Summary

| | Result |
|---|---|
| Real defects found and fixed | 31, each with a regression test (section 2); one more, the unbound high bits of the KOS challenge, found while closing the residual limits (section 2b, item 38) |
| Properties that do not hold, by design | Section 3 |
| Behaviours that depend on the caller, documented | Section 4 |
| Constant-time | Not provable in JavaScript. Secret-scalar point multiplications in `pca-bbs` and `pca-oprf` use the library's constant-time-style multiply and Fermat inversion, with dudect-style tests that fail on a Hamming-weight dependence (section 2b). The WebAssembly curve core was measured and showed no dependence on the scalar (section 6) |
| Fuzzing | Every public parse and verify entry, bounded time, with a check for non-typed exceptions, calls over 1 second, and false accepts. No remaining finding |

## 2. Defects found and fixed

### `pca-oprf`

1. **A stuck-at-zero random source hung the process.** `randomScalar` retried forever on a zero scalar. It now
   gives up after 8 attempts and throws, so `blind`, `randomKeyPair` and every caller fail closed.
2. **The server's secret key went through a variable-time scalar multiply** while building the DLEQ proof. It now
   uses the ladder multiply.
3. **`deriveKeyPair` accepted any seed length**, including empty. RFC 9497 requires exactly 32 bytes.
4. **Oversized or mistyped inputs were not rejected.** An input over 65535 bytes (the RFC's two-byte length
   framing) and a non-`Uint8Array` argument (`null`, a string) now fail with a typed error.
5. **Different identifiers could share one counter.** `TextEncoder` turns each unpaired UTF-16 surrogate into
   U+FFFD, so two different capability ids or rate-limit identifiers produced the same OPRF input. Ill-formed
   strings are rejected.

### `pca-bbs`

6. **The message count was unbounded, and a verifier derives it from the length of an attacker-supplied proof.**
   A proof a few megabytes long forced hundreds of thousands of hash-to-curve operations. The count is now
   capped at `MAX_MESSAGES` (1024) before any curve work.
7. **Attribute names containing NUL were ambiguous.** `{name:"a\0b", value:"c"}` and `{name:"a", value:"b\0c"}`
   encode to the same signed octets. NUL in a name is now refused.
8. **`verifyCredential` and `verifyPresentation` threw on malformed structure** instead of returning `false`.
9. **Degenerate randomness was accepted.** A zero blinding scalar `r1` or `r2` collapses the proof; an all-zero key
   seed gave one fixed key. Both are refused.

### `pca-aggsig`

10. **A duplicated witness key was counted twice.** One witness's cosignature, aggregated with itself, verified
    for the key list `[k, k]`. Duplicates are rejected.
11. **The aggregate key was not validated.** Keys `P` and `-P` each pass key validation and sum to the identity.
    The pinned `@noble/curves` already refuses that pairing, so this was not exploitable today; the aggregate is
    now validated explicitly so the rejection does not depend on a library version.
12. **`keyGen` under a stuck-at-zero random source returned the public key of the secret `1`.** It now throws.
13. **BLS signatures were malleable.** Clearing the compression bit of a valid 96-byte signature still verified
    (found by the 45-second fuzz run), so every signature had two accepted encodings and a hop's `capHash`
    could be changed without invalidating it. Signatures, proofs of possession and aggregates must now carry the
    compression bit, in single, aggregate, fast-aggregate and PoP verification.

### `pca-vdf`

14. **`insecureDevSetup` looped forever with a constant random source** (also when both primes came out equal).
    Both loops are bounded.
15. **`hashToPrime` accepted any bit width**, including values that allocate gigabytes. The width is limited to
    8 to 8192.

### `pca-fhe`

16. **Policy coefficients were not validated.** The policy reaches the evaluator as JSON and was packed into
    32-bit slots, so `NaN` became 0 and `2^32 + 5` became 5: a different circuit, silently. Every coefficient
    must now be an integer below the signed bound, and the scale a positive integer.
17. **A wrong-key or garbage ciphertext decrypted to a random value, and its sign "admitted" about half the
    time.** `decryptVerdict` now measures the invariant noise budget and refuses anything under 16 bits (random
    ciphertexts measure about 1 bit; a genuine gate output keeps about 90). Four existing tests that expected a
    wrong value now expect either a refusal or a wrong value.
18. `null` arguments produced internal `TypeError`s; they are now ordinary errors.

### `pca-pq-threshold`

19. **`verifyHybridThreshold` threw** (`TypeError`) on malformed verifier options. It now returns a refusal.
20. **A presented block with thousands of invalid co-signatures cost one ML-DSA verification each.** At most 256
    entries are examined.
21. The experimental additive-sharing toy accepted a repeated share index and `n` up to 2^31; both are refused.

### `pca-mpc`

22. **`schnorrProve` replaced a zero nonce with the public value 1.** With nonce 1, the secret follows from the
    proof as `y = (z - 1) / e`. A stuck random source therefore leaked the sender's base-OT secret from a single
    proof. A zero nonce is now refused.
23. **`composeSecure` and `composeSecureMalicious` defaulted to a fixed seed.** Every share was predictable to
    anyone reading the source. They now default to the secure source; a seed is for reproducible tests only.
24. **Out-of-domain decision vectors were accepted.** Two parties sending `allow = -1` multiply to `+1` under the
    shared AND, so an invalid pair allowed; the cleartext reference treated any non-zero `allow` as allow. `allow`,
    `t` and `rQuant` are now checked in all three entry points.
25. **`baseOT` sent the tail of a long message in the clear.** The pad is 16 bytes; a longer message was XORed
    only over its first 16 bytes. Messages must now be equal length and at most 16 bytes.
26. **`otRandom(() => 0n).scalar()` hung.** Bounded, throws.
27. **A malformed `u` column in the KOS check crashed with an untyped error** (bits beyond the row count have no
    challenge weight). It now aborts with `MalOtAbort`. Choice bits must be exactly 0 or 1 and messages 64-bit
    non-negative integers; the extension pad is 64 bits wide and a wider message would have its high bits
    unmasked.
28. **The endemic LWE OT crashed with an untyped error** on a short ciphertext array or malformed points. Shapes
    and lengths are checked before any arithmetic.
29. **Unbounded allocations.** The sender-chosen pad length in the KEM and hybrid OTs (limit 1 MiB) and the party
    count in secret sharing (limit 1024). Operand and triple party counts are checked in Beaver and SPDZ.

### `pca-mpc-wasm`, `pca-mpc-lwe-ot-wasm`

30. **A 32-character string was accepted as a point or a seed** and silently coerced to 32 zero bytes (the
    order-4 point with y = 0, and the all-zero seed). Anything that is not a `Uint8Array` is refused.
31. (`pca-mpc-wasm`) The same check on the length-only predicates (`isOnCurve`, `isIdentity`, `isInSubgroup`,
    `equal`), which previously coerced array-likes.

## 2b. Residual limits closed (2026-10-09)

Each has a test that fails on the previous behaviour. These are breaking API changes (day-0: the unsafe form is
removed, not deprecated).

32. **`pca-aggsig`: same-message aggregation was only safe if the caller remembered the proof of possession.**
    `RegisteredKey` is an opaque class, constructible only through `registerKey` / `KeyRegistry.register`, which run
    KeyValidate and verify the PoP (token-guarded constructor plus a module-private `WeakSet`, so a cast object,
    a prototype-forged object or a clone is refused). `aggregateVerify` and `fastAggregateVerify` take only
    `RegisteredKey`s; `verifyAggregatedChain` takes a `KeyRegistry`; `verifyAggregatedWitnessCosignatures` takes
    `RegisteredKey[]`; `aggregatePublicKeys` and `popVerify` are no longer exported and the raw verifiers live in an
    internal module blocked by `package.json` `exports`. Tests run the classic attack (`g^x - sum(honest)`): the
    rogue key cannot be registered (every PoP candidate the attacker can build fails), a forged `RegisteredKey` is
    refused, and the raw verifier is shown to accept the forgery, which is the control. Residual: the application
    still decides who may register, and a PoP proves possession at registration time only.
33. **`pca-fhe`: any holder of the public key could mint a ciphertext of any slack.** The claim path
    (`encryptedRiskClaim`, `evalSignedRiskClaim`) now carries an Ed25519 signature (strict RFC 8032 verification)
    over a domain tag, the grant context, the action binding, a hash of the gate policy, a hash of the ciphertext,
    a random nonce and the signer key. The evaluator refuses an unsigned claim, an unpinned signer, a changed
    ciphertext / context / binding / policy, and a replayed nonce (consumed only after every other check passes;
    the in-memory guard fails closed when full), before the ciphertext reaches SEAL. The key holder can sign the
    admit decision back (`attestVerdict`), bound to the claim and the exact gate ciphertexts, revealing only
    `admit`. This buys integrity and origin of the input; it hides nothing. A malicious evaluator can still refuse
    service, run a different circuit, see the signed metadata, and replay to an evaluator with its own nonce
    guard; a lying or compromised signer can sign false or out-of-range inputs. `evalEncryptedRiskClaim` is
    removed; the unsigned `encryptRiskInputs` / `evalRiskGate` primitives remain.
34. **`pca-pq-threshold`: `t` was a label.** `issueGroupDescriptor` makes a setup authority sign
    `{ suite, groupPublicKey, t, n, signerSetCommitment }`; `verifyHybridThreshold`, `createHybridThresholdVerifier`
    and `verifyHybridStepUp` require the descriptor and the pinned authority keys and refuse unless it verifies, is
    for the pinned group key and has `t` equal to the required `t`. A 1-of-n key presented as 3-of-n, a descriptor
    from an untrusted authority, an edited `t`, a descriptor for another group and a missing descriptor are all
    refused. The group cannot attest its own `t` (a 1-of-n group can sign a claim of 3-of-n). Residual: a
    compromised authority can certify a false `t`, and the descriptor does not show the dealer behaved.
35. **`pca-bbs` and `pca-oprf`: secret scalars went through variable-time paths.** BBS: the signing key, `1/(SK+e)`,
    the signed messages and the prover's blinding scalars used `multiplyUnsafe`, and inversions used extended
    Euclid. They now use `Point.multiply` (fixed-window with a fake point) and Fermat exponentiation; the remaining
    `multiplyUnsafe` calls are on public verifier scalars only (a static test pins this). OPRF: the server key
    multiply was already on the library multiply; the inversions of the client blind and of the POPRF `skS + m`
    used extended Euclid and now use Fermat. New dudect-style tests (Welch t on randomly interleaved sparse
    (weight 1) and dense (weight 252/253) scalars, top 20% cropped) fail when `|t| >= 10` and the class medians
    differ by more than 5%; a positive control (`multiplyUnsafe`) is detected every time (`|t|` about 23, median ratio
    about 3), and reverting the BBS change makes the `skToPk` and `proofGen` tests fail (`|t|` 23 and 12).
    **What is not guaranteed:** JavaScript gives no constant-time guarantee. BigInt multiplication and reduction
    have value-dependent timing, the JIT and GC add noise, and the library's window method indexes a precomputed
    table by secret digits (a cache-timing channel). The tests show no first-order Hamming-weight dependence at
    the stated threshold on one machine; they do not show constant time. Long-lived issuer or server keys facing a
    co-resident attacker need a native or WebAssembly constant-time implementation or an HSM.

### `pca-mpc` (closed 2026-10-09; the tests named here fail on the previous behaviour)

36. **Base-OT Schnorr proofs were not session-bound.** The challenge is now
    `H(tag, len(ctx), ctx, B, S, U)` where `ctx` is a canonical encoding of session id (8-64 bytes), the two party
    indices, a round label, and `schnorrProve`/`schnorrVerify` refuse an empty context. A valid `(S, proof)` pair
    replayed into another session, another sender or receiver index, swapped roles or another round fails
    (`ot-binding.test.ts`, one case per element); the network runner binds the mesh session id hashed to 32 bytes,
    the two node ids and the round. A proof for `S` also fails for `S + B` and with a moved commitment.
37. **Base-OT keys did not hash the transcript.** Pads are `H("ot-kdf", H(binding, S, R_0..R_{m-1}), i, R_i, P)`
    (Chou-Orlandi/Simplest-OT style over the whole transcript, domain separated). Tests change the session id,
    each index, the round, `S`, and each single `R_j` in turn: the transcript hash and EVERY derived key (including
    those at indices that were not touched) change. The post-quantum KEM and LWE base OTs already carried their own
    session/commitment binding and were not changed.
38. **KOS row weights: SplitMix64, and only the low 128 bits of each `u` column were hashed.** Two problems, both
    fixed. The weights are now the output of SHAKE256 (`node:crypto`) over
    `tag, channel binding, round, row count, every bit of every column of u`, 16 bytes per row. The second defect
    was a real flaw found while doing this: the old code serialised each column into 16 bytes, so every bit of `u`
    above position 127 was not bound into the Fiat-Shamir challenge and a receiver could vary those bits after
    seeing the weights (each column has `m + 192` bits, so this affected every round). The known-answer
    vector in `ot-binding.test.ts` was produced independently with Python `hashlib.shake_256`; a test flips single
    bits at positions 0, 1, 127, 128, 129 and 199 and requires every weight to change.
39. **SPDZ over a 61-bit field had MAC soundness about 2^-61.** Every authenticated value now carries a MAC under
    each of `MAC_KEYS = 2` independent global keys, each with its own challenge vector, checked in the same batched
    check (`macResiduals`); soundness is `k * (log2 p - 1)` = 120 bits (derivation and caveats:
    `pca-mpc-spdz-soundness.md`). `SpdzEngine` refuses a context below 100 bits. The same residual arithmetic is run
    on 16-bit and 8-bit primes against a cheating-share attack: 61 successes in 2,000,000 trials where 61.0 +- 7.8
    are predicted (one key, p = 65521), 66 in 1,000,000 where 63.2 +- 8.0 are predicted (two keys, p = 251). The
    commit-then-open and the coin flip are still modelled (SHA-256 commitments, hash-based public coins), not
    proven.
40. **A trusted dealer's wrong triple was not detected, and the dealer-free phase was not distributed.** (a) Dealt
    triples are certified by the sacrifice with `SACRIFICE_PARTNERS = 2` independent partners sharing `b`
    (failure probability at most p^-2, about 2^-122), in process (`sacrificeVerify`, `composeSecureMalicious`) and
    over the network (`sac-rho`/`sac-tau` rounds). A dealer authenticating `c = ab + d` (consistent MACs, so MACs
    alone cannot catch it) aborts the run, in either partner too, in a batch of 20 with one bad triple, and over
    real processes where the DEALER is named. Without the verification the same lie turns `allow 1 AND 0` into
    allow (the test shows it). The result and the API label the mode (`offlineMode: 'trusted-dealer' | 'no-dealer'`,
    `triplesVerified`). (b) `net/offline-net.ts` runs the OT-based offline phase between 2-4 real processes over the
    mutual-TLS mesh with no dealer process: session-bound base OTs, the KOS-checked OT extension split into sender
    and receiver roles, Gilboa multiplication for the triple products and the MACs of two keys, the input
    sharings, the input-consistency opening and the sacrifice. Evidence: `docs/evidence/pca-mpc-nodealer-local-2026-10-09.json`.
41. **A MAC-check failure could not say who cheated.** Every share now carries BDOZ-style pairwise
    information-theoretic tags (`net/pa.ts`: `T_ij = K_ij + Delta_j * x_i`), dealt by the dealer or generated from
    OT in the dealer-free mode. Every opened share is verified by every receiver at once, so a party that lies about
    a share, sends a wrong tag or equivocates is named by the honest verifiers with first-hand evidence; after a
    failed MAC-check a blame round makes each party open its combined MAC shares and key shares with their tags,
    which names a party that forged a MAC share or opened a residual that is not what its shares give, and names the
    dealer when every party verifies. Tested over real processes with each of the three parties as the cheater for
    seven kinds of lie in dealer mode and for open/MAC/residual lies in dealer-free mode (`net/identify.test.ts`,
    `net/offline-net.test.ts`). **Residual:** (i) the tags have soundness 1/p per verified tag, so identification
    can fail with probability about n/p while the MAC-check (section 3, 2^-120) still aborts; (ii) an accusation is
    evidence for the accuser only, never proof a third party can check; (iii) in the dealer-free mode a wrong OT
    operand in the offline triple products is DETECTED (sacrifice) but not attributable, because the tags are
    computed on the already-wrong value (named only for two parties); (iv) the opened MAC combinations of the
    blame round reveal the MAC key shares of the aborted run, which is acceptable only because those keys die with
    the run.

## 3. Properties that do not hold, by design

- **Rogue-key resistance of the raw BLS verifier (closed, section 2b).** A key `A·G - V` aggregates with a victim
  key `V` to a key the attacker controls. The public aggregate verifiers now accept only `RegisteredKey`s, which
  exist only after a proof of possession verified; the raw verifier is internal and the test still shows the attack
  against it.
- **Origin of the FHE ciphertext (closed for the claim path, section 2b).** BFV itself is confidentiality only:
  anyone holding the public key can mint a ciphertext that decrypts to any slack, and `decryptVerdict` accepts it
  (the test shows this). The PCA claim path now requires an Ed25519 signature by a pinned encryptor, bound to the
  grant context, the action, the policy and a nonce. What remains: a malicious evaluator can still run a different
  circuit, and a lying signer can sign false or out-of-range inputs.
- **Base OPRF (non-verifiable) revocation sets.** A service answering with a different key makes every
  capability look "not revoked", undetectably. Use the verifiable mode.
- **The threshold `t` in `verifyHybridThreshold` (closed, section 2b).** A FROST aggregate is a plain Ed25519
  signature, so `t` cannot be read off the key. The verifier now requires a signed group descriptor from a pinned
  setup authority whose `t` equals the required `t`. The authority is the remaining trust assumption.
- **Without a hidden group order the VDF has no soundness at all.** For a toy modulus, exactly one `pi` is accepted
  for every claimed `y`, and with the factors the delay collapses to one exponentiation (both are tested).
  Production use needs a modulus nobody can factor; the code refuses its own development moduli.
- **Schnorr proofs in the base OT, base-OT key derivation, KOS weights (closed, section 2b items 36-38).** Proofs
  are bound to session, parties, round and both points; pads hash the whole transcript; the KOS weights are a
  SHAKE256 output over every bit of `u`.
- **SPDZ over a 61-bit field (closed, section 2b item 39).** Two independent keys give about 2^-120 MAC soundness.
  The commit-then-open and the public coin flip are still SHA-256 commitments and a hash-based coin, not a proven
  multiparty protocol, and the in-process engine simulates all parties in one process.
- **Trusted dealer (closed as to integrity, not as to privacy; section 2b item 40).** A dealer that hands out a
  wrong triple is detected. In `trusted-dealer` mode the dealer still knows every share and key, so it can break
  privacy and, colluding with a party, forge. The dealer-free mode removes that assumption, at about 4x the
  offline cost, and has no proof.
- **Identifiable abort (closed for online lies in both modes, section 2b item 41).** Not closed for a wrong OT
  operand in the dealer-free offline products (detected, not attributed, except for two parties); accusations are
  not publicly verifiable; no Byzantine agreement (the transcript echo is a hash exchange).
- **`kpkeKeygen` is not FIPS 203 `ML-KEM.KeyGen`** (documented in the package; keys are derived from `G(d)`, not
  `G(d || k)`). K-PKE has no ciphertext integrity; the OT adds its own commitments.

## 4. Behaviour that depends on the caller

- `finalizePoprf` trusts the `tweakedKey` it is given. A key made for a different `info` is accepted and yields a
  wrong (not forged) output; always use the key returned by `blindPoprf` for the same `info`.
- Pinning a blind (`fixedBlind`), a DLEQ nonce (`fixedProofRandomness`) or BBS random scalars is for test vectors.
  Reusing a DLEQ nonce across two proofs reveals the server key (the test recovers it).
- `verifyPresentation` binds to the presentation header only if the verifier passes its own.
- BBS and OPRF accept any `Uint8Array`; message count in BBS is limited to 1024.
- A constant non-zero random source is indistinguishable from a good one and cannot be detected by the libraries
  (blinds then repeat). Only all-zero output is rejected.
- SEAL draws its own entropy inside WebAssembly; the JavaScript random source cannot be substituted, so RNG-failure
  behaviour for key generation in `pca-fhe` is not testable from outside.

## 5. What was tried

| Technique | Where |
|---|---|
| Wrong type, empty, oversized and aliased buffers on every public function; inputs not mutated, outputs not aliased | all |
| Identity, zero, low-order, mixed-order, off-subgroup, non-canonical encodings on every deserializer | oprf, bbs, aggsig, mpc, mpc-wasm, lwe-wasm |
| Challenge binding: every public input, the header, the presentation header, the ciphersuite domain; cross-mode and cross-protocol replay | oprf, bbs, aggsig, vdf, pq-threshold, mpc |
| Domain separation between protocols sharing a hash (OPRF modes, revocation vs rate token, signature vs PoP, hop vs cosignature) | oprf, aggsig |
| Nonce, blind and key reuse; call-order and replay abuse | oprf, bbs, mpc, aggsig |
| Stuck-at-zero and constant random sources | oprf, bbs, aggsig, vdf, mpc |
| Exhaustive small-parameter checks: all single-bit flips of a proof; every unit and step count in toy RSA groups; every `(y, pi)` pair; all 64 choice vectors in OT extension; every open, party and deviation kind in the SPDZ MAC check | oprf, vdf, mpc |
| Property tests (round trips, group, field, ring and GF(2^128) laws, equality with a cleartext reference) | all |
| Bounded fuzzing of every parse and verify entry | all |
| Timing, dudect-style (positive control that the harness detects an early-exit comparator) | oprf, mpc |

## 6. Review against the specifications

- RFC 9497: context strings, DSTs, the framing of the composite and challenge transcripts, `DeriveKeyPair` and
  proof verification match; the code differs only in the hardening in section 2. Batching of multiple elements
  into one proof is not implemented (one element per proof).
- draft-irtf-cfrg-bbs-signatures: octet formats, domain calculation, generator creation and the challenge match
  the BLS12-381-SHA-256 suite. Only that suite exists. The message count is capped (section 2, item 6), which the
  draft does not do.
- draft-irtf-cfrg-bls-signature (proof-of-possession scheme): the signature and PoP domain tags are distinct;
  subgroup and identity checks run on every key; aggregation requires distinct messages for the distinct-message
  verifier; the public aggregate verifiers accept only keys with a verified PoP (section 2b).
- Wesolowski VDF: the challenge prime binds `x`, `y`, `T`, `N` and its own width; `y` and `pi` must be canonical
  units, so `y + N`, `-pi` and `-y` are all rejected.
- BFV risk gate: parameters are the 128-bit set from the Homomorphic Encryption Standard (checked in the existing
  suite).
- Chou-Orlandi with a Schnorr proof, Beaver multiplication, SPDZ MAC check, KOS check: matched to the
  descriptions in the package headers; deviations are in section 3.
- Timing: the pure-BigInt elliptic-curve fallback is variable-time and documented as such; with the WebAssembly
  core active, `mulBase` of a sparse and a dense 252-bit scalar differed by under 40% in the minimum of interleaved
  runs (the test bounds it at that). `bytesEqual` showed no first-mismatch dependence. BBS signing and proof
  generation, and the OPRF server/client secret paths, now use the library's fake-point fixed-window multiply and
  Fermat inversion (section 2b); JavaScript `BigInt` is not constant-time anywhere.

## 7. What only an independent human audit can establish

- That the security reductions hold for the exact parameters, encodings and hash-to-curve / hash-to-scalar choices
  used here, and that no deviation from the papers was missed by reading. These tests find what they were written
  to look for.
- Side channels on real hardware: cache, branch-predictor, power and electromagnetic behaviour of the JavaScript
  and WebAssembly code, and the effect of JIT compilation and the host runtime. A statistical timing check in a test
  process on a shared machine cannot rule these out.
- The correctness of the third-party code underneath (`@noble/curves`, `@noble/hashes`, curve25519-dalek compiled to
  WebAssembly, pqc_kyber, SEAL), the WebAssembly build pipeline, and supply-chain integrity.
- The quality of the platform's entropy source and how keys and shares are stored, zeroised and rotated.
- Whether the composition of these primitives into the full protocols meets the stated security goals against an
  active network adversary (the tests exercise malformed and replayed messages, not a formal security proof).
- Formal verification, and a review of the choices in section 3 (61-bit SPDZ field, SplitMix challenge expansion,
  unbound Schnorr proof, the trusted threshold authority) against the risk the deployment accepts.
- A look at the public parameters and fixtures (RSA-2048 challenge modulus, test vectors) by someone who can
  check their provenance independently.

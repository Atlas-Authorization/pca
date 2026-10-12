# Security audit in tests: `@atlasauth/pca-abe` and `@atlasauth/pca-ratchet`

This is a self-audit written as executable tests, in the way an external cryptographic review would proceed:
read each construction against its source paper, list every deviation, then try to break each security property
and record what happened. It is **not** an independent audit. Section 6 lists what only a human cryptographer
can still judge.

Run it: `pnpm --filter @atlasauth/pca-abe test` and `pnpm --filter @atlasauth/pca-ratchet test`.
The timing runs are opt-in: `PCA_AUDIT_TIMING=1`.

## 1. Summary

| | Result |
|---|---|
| Real defects found and fixed | 13 (9 in ABE, 4 in the ratchet, plus one hardening), each with a regression test |
| Former gap, now closed | Collusion resistance between separately issued ABE keys (finding F1, fixed by the BSW07 redesign, item 9 in section 2) |
| Not available in this design | Post-compromise security for the ratchet; zeroisation of spent state in JavaScript |
| Independent implementations used | py_ecc (pure Python) for BLS12-381 hash-to-curve, ABE key and ciphertext components, the pairing equations and Shamir; curve25519-dalek 4.1.3 (Rust) for ristretto255, Pedersen commitments and a second budget-proof verifier |
| Constant-time | Not provable in JavaScript. dudect-style measurements found no detected leakage (section 5) |

## 2. Findings that were fixed

### ABE

1. **Different attribute names could share one identity.** `TextEncoder` turns every unpaired UTF-16
   surrogate into U+FFFD, so `"a\ud800"` and `"a\udfff"` hashed to the same curve point; a key issued for one
   opened ciphertexts for the other. Ill-formed UTF-16 is now rejected in policies and skipped at key issue.
2. **Master secret had two encodings.** A scalar `s` and `s + r` were both accepted. Only canonical values
   below the group order are accepted now.
3. **Shamir evaluation points `x` and `x + r`** were treated as different points while being the same field
   element (a zero Lagrange denominator). They are compared as field elements and refused.
4. **The point at infinity was accepted** as a key, ephemeral or public element. Pairing with it is undefined.
   It is refused on parse (G1 and G2).
5. **Ciphertext branch indices were free-form.** Branch `k` must now carry evaluation point `k + 1`, exactly as
   the encryptor emits. Duplicate, zero, huge and reordered indices are refused, and parsing has a node budget.
6. **Silent data loss on deep policies.** A policy could be encrypted that could never be decrypted, because the
   authenticated header is canonical JSON with a nesting cap of 32. Gate nesting is now capped at 10, so
   "encryptable" implies "decryptable"; a header outside the canonical profile is refused at encrypt time.
7. **Ambiguous policy nodes** (for example both `allOf` and `anyOf`) are refused instead of one silently winning.
8. **An attribute named `__proto__`** was dropped at key issue (plain property assignment hit the prototype
   setter), so such a key could not decrypt. Keys are now built with own data properties.
9. **F1: separately issued keys could pool** (this was finding F1 in the earlier revision of this document).
   The key for an attribute was `s * H1(attribute)`, the same group element for every holder, so a holder of
   `verb:read` and a holder of `scope:finance` could merge their keys and decrypt an AND policy neither
   satisfies. The scheme is replaced by Bethencourt-Sahai-Waters CP-ABE (section 4): every issued key carries a
   fresh randomiser `r`, every attribute component a fresh `r_j`, and a decryption recovers `e(g1,g2)^(r*q)` per
   leaf, so the root recovery only succeeds when every component came from one key. The test that demonstrated the
   attack now asserts the opposite (`src/audit/collusion.test.ts`): pooled keys fail in both orders, for AND,
   threshold and nested policies, for every pair of single-attribute keys of a 2-of-4 policy, and for every single
   component (`D`, `D_j`, `D'_j`) swapped in from another key. A one-key control decrypts the same ciphertexts.

### Ratchet accumulator

1. **Proofs were malleable.** Scalars were reduced instead of rejected, so `s` and `s + l` (about 16 encodings
   each) all verified. Scalar and point decoding is now strict and canonical. The Rust verifier agrees.
2. **Negative-risk cancellation.** The budget proof constrains only the *sum*. A prover could include a
   commitment to `l - 50` (a "negative" risk) to cancel real risk, and the budget proof alone still verified
   (the test shows this). Added `proveRiskRange` / `verifyRiskRange` (per-commitment range proof,
   domain-separated) and `verifyBoundedBudget`, the sound end-to-end check. `verifyBudget` alone is documented as
   insufficient.
3. **Ceilings of 2^32 or more made every small total unprovable** (the slack no longer fit the range), a false
   reject. The ceiling is clamped to 2^32 - 1, which is a strictly stronger statement.
4. **Zero-scalar timing.** `mul()` skipped the work when the scalar was zero. It now always multiplies and
   selects the identity afterwards.
5. **Hardening: proof replay across statements.** Per-commitment range proofs use their own transcript domain, and a test
   checks that a range proof cannot be replayed as a budget proof (or the reverse) even when the slack point is
   engineered to be equal.

## 3. Findings that were NOT fixed

**F1 (closed, see item 9 in section 2).** Pooling of separately issued ABE keys. Kept here so the old finding
number still resolves. What remains of it: the design is only as collusion-resistant as BSW07 is (section 4),
which is proved in the paper's generic-group model and not for this type-3 adaptation, and the holder of the
master secret can decrypt everything.

**F2. The ratchet's guarantees depend on state discipline.** Stealing the
current state lets the thief sign every unspent leaf (no post-compromise security). A copied or restored old
state can sign a spent leaf again. JavaScript cannot zeroise memory.

**F3. A Pedersen commitment reused with the same blinding** leaks the difference of the values to any observer
(asserted in a test). Blindings must be fresh per action; the library draws them that way.

## 4. Construction checks and deviations

### ABE (`pca-abe`)

* Source: Bethencourt, Sahai, Waters, "Ciphertext-Policy Attribute-Based Encryption", IEEE S&P 2007 (ePrint
  2006/309), Section 4 construction with access tree (Shamir at each gate, `DecryptNode` with Lagrange
  interpolation in the exponent), AES-256-GCM sealing with the whole header (`C_0`, tree, salt) as associated data.
* Equations (`g1`, `g2` the generators, `H` hash-to-G1): `MPK = (h = beta*g2, f = beta^-1*g1, Y = e(g1,g2)^alpha)`;
  key `D = ((alpha+r)/beta)*g1`, `D_j = r*g1 + r_j*H(j)`, `D'_j = r_j*g2`; ciphertext `C_0 = s*h`, per leaf
  `C_x = q_x(0)*g2`, `C'_x = q_x(0)*H(attr)`; leaf `F_x = e(D_j,C_x) / e(C'_x,D'_j) = e(g1,g2)^(r*q_x(0))`;
  root `K = e(D,C_0) / e(g1,g2)^(r*s) = Y^s`, which keys the AEAD. The Lagrange coefficients are folded into the
  group points so one multi-pairing with a single final exponentiation evaluates the tree.
* Deviation 1, type-3 adaptation. BSW07 is written for a symmetric pairing with one generator `g`. Here each
  element has a fixed side so every pairing has one G1 and one G2 argument: `D, D_j, C'_x, f, H(.)` in G1 and
  `h, D'_j, C_x, C_0` in G2. This is the package's own adaptation; the paper does not prove it.
* Deviation 2. `msk = (alpha, beta)` as scalars (the paper keeps `g^alpha`); equivalent for issuance.
* Deviation 3. `rerandomizeKey` is BSW07's `Delegate` (needs `f`): it re-randomises a key, optionally to a subset
  of its attributes, and needs no master secret.
* Deviation 4. Leaf-level threshold semantics (an attribute repeated in two leaves counts twice, as in the BSW
  tree), a hash-to-curve domain tag of our own (`...BSW07:H-G1...:v2`), and the policy language (AND, OR,
  threshold, depth and node budgets) of the package.
* Security notion. BSW07 proves selective (the adversary names the challenge access structure first) chosen-plaintext
  security against colluding key holders in the generic bilinear group model with `H` a random oracle. Not
  established here: a reduction to a standard assumption, adaptive security, CCA security of the ABE layer (the GCM
  tag over the header gives integrity, not a CCA proof), security of the type-3 adaptation, hiding of the policy
  (it is public in the ciphertext), key revocation. The master-key holder reads everything.
* Tested: the pooling attack and every single-component mix; re-randomisation and delegation; keys differ per
  issuance; wrong-curve, off-curve, wrong-subgroup, identity and truncated points in keys, ciphertexts and the
  public key (including `e(f,h) != e(g1,g2)`); every single-bit change in salt, IV, ciphertext, tag, `C_0`, every
  leaf `C` and `C'`; threshold downgrade; branch reorder; splicing between ciphertexts; non-canonical base64url;
  cross-master and cross-ciphertext key use; satisfaction equals decryptability for random policies (fast-check);
  NFC/NFD, case and homoglyph attributes are all distinct; key issue, public key, ciphertext points and both pairing
  equations cross-checked against py_ecc, plus a key built only from py_ecc components decrypting a library ciphertext.

### Ratchet (`pca-ratchet`)

* **GGM puncturable tree** (Goldreich-Goldwasser-Micali 1986; Bellare-Miner style forward-secure signatures).
  Deviation: HMAC-SHA256 under the seed with a domain suffix stands in for the PRG; the state is an immutable
  value, so forward security depends on the caller discarding the old one.
* **Pedersen commitments** over ristretto255 (RFC 9496). The second generator is the RFC 9496 hash-to-group of
  the SHA-512 of a published label. It was re-derived here, and independently in Rust, and matches byte for
  byte; it is not the identity, not a small multiple of G (checked to 20,000), and a different label gives a
  different point.
* **Range proof**: bit decomposition with a Cramer-Damgard-Schoenmakers OR proof per bit and a Schnorr proof
  that the bits aggregate to the committed value, made non-interactive with Fiat-Shamir. Deviations from the
  literature: not Bulletproofs (linear size, 32 bits); challenges are SHA-512 reduced mod l with length-prefixed
  parts; the statement (n, ceiling, sum, every bit commitment) is hashed into every challenge; there is no
  batching or aggregation.

## 5. Evidence

* **Differential testing.** ABE: hash-to-G1, public key, key and ciphertext components and Shamir shares match py_ecc on a fixed corpus; both BSW07 pairing equations hold in noble on the py_ecc points
 . Ratchet: 16 base-point multiples, `H`, 12 Pedersen commitments and the
  verdicts on 15 budget cases (valid, boundary, over budget, wrong ceiling, mutated and non-canonical
  fields, swapped proofs) agree with the Rust oracle.
* **Exhaustive toy-group check.** Over Z_13 x Z_13 with unrelated generators, for every commitment whose value
  is not 0 or 1, every announcement admits exactly one challenge (special soundness of the OR proof, so
  soundness error 1/q per bit), while honest bits admit two (positive control). This checks the protocol
  algebra, not the computational binding assumption. A second check shows the bit aggregation wraps when
  `2^n >= q` and does not otherwise; for the real parameters, 2^64 addends of 2^32 each stay far below l.
* **Properties (fast-check).** ABE: round trip under arbitrary payloads and attributes, decryptability equals
  the boolean satisfaction oracle. Ratchet: after any spend sequence the covering set is a disjoint exact
  cover of the unspent leaves; commitments are homomorphic; an honest budget proof verifies exactly when the
  total is within the (clamped) ceiling.
* **Forward secrecy attack search.** Every function the library defines (PRG both directions, leaf-key
  derivation, root KDF, domain HMACs) is applied to every retained seed up to three deep; none reaches a
  punctured secret, and no retained byte string equals one.
* **Timing (dudect-style, Welch t-test with percentile cropping).** Node 24, Apple silicon, shared machine.
  Threshold for concern is |t| > 10; ours must stay under 30 (looser, because of scheduler noise). A leaky
  comparison is flagged (positive control) and identical work is not (negative control).

  | Operation | classes | samples | max abs t (cropped) | raw abs t |
  |---|---|---|---|---|
  | ABE key issue (superseded construction) `s*H1(A)` | low-weight s vs random s | 1500 | 4.9 | 0.3 |
  | ABE decapsulation (superseded construction) `e(d,U)` | fixed vs random key | 1500 | 1.7 | 1.1 |
  | Ratchet `mul` | zero vs random scalar | 2000 | 18.7 | 1.8 |
  | Ratchet `commitRisk` | risk 0 vs random | 2000 | 4.7 | 1.6 |
  | Ratchet range proof | value 0 vs 2^32 - 1 | 400 | 1.0 | 0.8 |

  The two ABE rows were measured on the construction before the BSW07 redesign. The harness is retargeted (`r_j*H(j)`, `r_j*g2`
  scalar multiplications and the decryption multi-pairing) but the opt-in run has NOT been repeated since; do not read
  those two rows as evidence about the new code.

  The one cropped value above 10 (`mul`, 18.7) has an uncropped t of 1.8 and appears in only one crop of 41,
  which is the signature of scheduler noise; it is reported rather than hidden. BigInt arithmetic, JIT
  tiering and garbage collection make JavaScript constant-time claims impossible; the measurement shows no
  leakage at these sample sizes and nothing more. The hash-to-curve of the attribute (a public input) reached
  30.6 and is expected to vary, since attributes are not secret.

## 6. What only a human cryptographer can still judge

* The security of the type-3 adaptation of BSW07 (the paper's proof is for the symmetric setting in the generic
  group model): a reduction to a standard assumption, adaptive key queries, and CCA security of the ABE layer.
* Whether the hash-to-curve domain tags and the leaf-level threshold semantics suit your threat model.
* The Fiat-Shamir transcript of the range proof under a formal simulation-extractability argument, and the
  choice to hash SHA-512 modulo l.
* The PRG instantiation of the GGM tree and the composition of HMAC-derived leaf seeds with Ed25519 signing.
* Side channels below the level JavaScript exposes: cache, branch and memory behaviour of the underlying
  BigInt and curve libraries.
* Whether the deployment can meet the state-discipline assumption (single holder, atomic persistence, no
  restored backups) that one-time use depends on.

Until that review exists, treat both packages as experimental and do not use them as the sole control for
high-value actions.

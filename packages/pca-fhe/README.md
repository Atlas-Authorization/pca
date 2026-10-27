# @atlasauth/pca-fhe

> Maturity: **hardened** (experimental: hardened, awaiting audit). The engineering is done and evidenced by tests, differential checks and a mutation gate; it awaits an independent review of the BFV parameter choices, the fixed-point encoding and the signed-claim layer. It is never production until that review is done, and its API may still change. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Homomorphic evaluation of PCA's risk gate. PCA admits a machine-only action while the trust budget covers its cost (`kappa * r <= B`, where `r` is a weighted sum of six normalized risk inputs). This package runs that exact functional over encrypted risk inputs using BFV from Microsoft SEAL (via `node-seal`): the evaluator computes the weighted risk and the admission slack without ever seeing the plaintext inputs, and only the key holder decrypts the verdict.

## Install

```sh
npm i @atlasauth/pca-fhe
```

Depends on `@atlasauth/pca` and `node-seal`. Three roles share only strings: the key holder, the agent, and the evaluator.

## Usage

```ts
import { DEFAULT_RISK_POLICY } from '@atlasauth/pca';
import {
  keygen, fheRiskPolicy, quantizeRiskInputs, encryptRiskInputs, evalRiskGate, decryptVerdict,
} from '@atlasauth/pca-fhe';

// Key holder (policy owner): generate keys, keep secretKey, publish the rest.
const keys = await keygen();
const evalKeys = { publicKey: keys.publicKey, relinKeys: keys.relinKeys, galoisKeys: keys.galoisKeys };

// Public policy: risk weights and kappa from the core policy, plus the current trust budget.
const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);

// Agent: encrypt the quantized risk inputs under the public key.
const inputs = { semanticDistance: 0.1, reversibility: 0.9, blastRadius: 0.1, taint: 0.1, confidence: 0.9, age: 0.1 };
const encInputs = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs(inputs));

// Evaluator: compute encrypted risk and slack blind (no secret key).
const gate = await evalRiskGate(evalKeys, encInputs, policy);

// Key holder: decrypt and read the verdict.
const verdict = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
// { rScaled: 100000, slack: 500000, admit: true }   (values are at scale S^2 = 1e6)
```

For a signed action, use the signed claim path (below). `plaintextVerdict(inputs, policy, budget)` gives the plaintext reference result for cross-checking.

## Origin authentication (signed claims)

The BFV public key is public, so on its own anyone can mint a ciphertext that decrypts to any slack. The PCA claim path therefore requires the encryptor to sign:

```ts
import { generateKeyPair, b64u } from '@atlasauth/pca';
import { encryptedRiskClaim, evalSignedRiskClaim, memoryNonceGuard, decryptVerdict, attestVerdict, verifyVerdictAttestation, signedClaimDigest } from '@atlasauth/pca-fhe';

const encryptor = generateKeyPair();           // the principal / guardian; the evaluator pins its public key
const signed = await encryptedRiskClaim({ actn, publicKey: keys.publicKey, policy, signerSecretKey: encryptor.secretKey, context: 'grant-123' });

const nonces = memoryNonceGuard();             // evaluator: single-use nonces (fails closed when full)
const ev = await evalSignedRiskClaim(evalKeys, signed, {
  trustedSigners: [b64u(encryptor.publicKey)], context: 'grant-123', binding, policy, nonces,
});                                            // { ok: false, reason } for unsigned / wrong signer / wrong context, binding or policy / altered ciphertext / replay

// Optional: the key holder signs the admit decision back (only `admit`, never slack or r).
const verdict = await decryptVerdict(keys.secretKey, ev.gate.encRiskRaw, ev.gate.encSlack, policy);
const att = attestVerdict({ holderSecretKey: holder.secretKey, signed, gate: ev.gate, verdict });
verifyVerdictAttestation(att, { trustedHolders: [b64u(holder.publicKey)], claimDigest: signedClaimDigest(signed), gate: ev.gate });
```

The Ed25519 signature (strict RFC 8032 verification, from `@atlasauth/pca`) covers a domain tag, the grant context, the action binding, a hash of the public gate policy, a hash of the ciphertext, a random nonce and the signer key. The evaluator checks the signature, the pinned signer, and that context, binding and policy equal its own expectations before the ciphertext is loaded; the nonce is consumed only after all of that passes.

What this buys: integrity and origin of the input ciphertext. It does not hide anything, and it does not stop: a malicious evaluator refusing service, running a different circuit (BFV is not verifiable computation), seeing the signed metadata, or replaying to a second evaluator that does not share the nonce guard; a lying or compromised signer (it authenticates origin, not truth, and out-of-range values wrap modulo the plaintext modulus); or a leaked signer key until it is unpinned.

Breaking (unreleased): `evalEncryptedRiskClaim` is removed and `encryptedRiskClaim` now requires `signerSecretKey` and `context` and returns a `SignedRiskClaim`. The low-level `encryptRiskInputs` / `evalRiskGate` primitives remain unsigned.

## Where it fits, and what happens when something is missing

Use it when the party that evaluates the risk gate must not see the agent's risk inputs, for example a shared or third-party gate service in front of several tenants. The principal (key holder) generates keys and pins its signer; the agent encrypts and signs the claim; the gate service calls `evalSignedRiskClaim` and returns the encrypted verdict; the key holder decrypts it and feeds the admit decision into its own authorisation step (a PCA verifier or `requirePCA`) as one input. If the verifier is local and the inputs are not sensitive, evaluate the gate in the clear instead.

| Missing or wrong | Result |
|---|---|
| Signature absent, not by a pinned signer, or over another context, binding or policy | `{ ok: false, reason }`, nothing evaluated |
| Nonce already seen, or the guard is full | `{ ok: false, reason }`, nonce not burned by a refused claim |
| Ciphertext altered after signing | signature refusal |
| Malformed or truncated key or ciphertext blob, wrong blob kind | typed error before it reaches the WASM module |
| Out-of-range, NaN, fractional or mistyped input or policy value | refused before any key is parsed |
| Secret key for a different public key | decryption throws rather than returning a verdict |
| Policy with all-zero scaled weights | evaluates to an encryption of zero |

## Status

Hardened, awaiting audit; unaudited. What the test suite now establishes, and what it does not:

**Validated**

- Property-based tests (fast-check 3.23) compare the fixed-point pipeline with the plaintext `riskScore` / `cost` over random inputs, including out-of-range, negative, NaN and infinite values, and random policies. The integer circuit stays within a derived rounding bound of the plaintext score, and the admit decision matches the plaintext decision everywhere outside that bound. Boundary cases (all-zero, all-worst, exact `slack == 0`, one unit short) are checked explicitly.
- The encrypted evaluation is checked against an exact integer oracle: decrypted `riskRaw`, `slack` and `admit` equal the oracle for random vectors and policies, with no tolerance.
- Cross-implementation check against an independently built Microsoft SEAL (TenSEAL 0.3.18, driven through its raw `sealapi`; this package uses node-seal 5.1.7, SEAL 4.1.2). Both parameter sets match. In both directions the keys, ciphertexts and evaluations interoperate: TenSEAL encrypts and node-seal evaluates, node-seal encrypts and TenSEAL evaluates the same circuit with its own slot-sum, and both evaluations of one ciphertext decrypt to the same integers. A committed TenSEAL-produced fixture is decrypted in the default test run; the live two-way run needs a Python with TenSEAL and is skipped otherwise. The two SEAL builds stamp different version bytes into their serialization header, so blobs are re-stamped when crossing between them; the coefficients are untouched and the exact decrypted values confirm the result.
- Parameter security: degree 8192 with a 218-bit coefficient modulus (43+43+44+44+44 bits), which is the maximum the Homomorphic Encryption Security Standard (Albrecht et al., 2018, Table 1; ternary secret, classical 128-bit) allows for n = 8192. SEAL's own 128-bit table agrees, and a 240-bit modulus at the same degree is rejected at that level.
- Serialization: ciphertext and key blobs round-trip, re-saving is byte-stable, and results survive an extra serialize/deserialize hop.
- Negative cases: a wrong secret key, a ciphertext under a different public key, a key blob passed in the wrong role, bit-flipped ciphertexts, and empty, non-base64, wrong-magic, truncated or padded blobs are all refused or fail to yield the true verdict, with the specific refusal reason asserted.

**Defects found by these tests and fixed**

- A policy whose scaled weights (or scaled kappa-weights) were all zero crashed evaluation, because SEAL refuses to multiply by an all-zero plaintext. Such a policy is valid and now evaluates to an encryption of zero.
- A malformed or truncated blob sent to the evaluator aborted inside the WASM module and stranded roughly 80 MB per call, so repeated bad input could exhaust memory. Blobs are now checked against the SEAL stream envelope before they reach WASM, and every SEAL object is released on every exit path.

**Not validated**

- There are no official known-answer vectors for BFV evaluation (the HE Standard publishes parameter tables, not test vectors), so the cross-check fixture is self-generated by TenSEAL and labelled as such.
- The 128-bit estimate relies on the standard's table as implemented by SEAL, not on a fresh lattice-estimator run.
- BFV itself provides confidentiality, not integrity. Origin and integrity of the input ciphertext now come from the signed claim (above); BFV still does not prove the evaluator ran the agreed circuit or that the ciphertext encrypts the signer's true inputs. A ciphertext holding values outside `[0, scale]` can wrap modulo the plaintext modulus and distort the verdict; the evaluator cannot range-check it, so the signer must be trusted for that. A range proof and an attested evaluator remain open.
- The verdict is the sign of an encrypted slack, decrypted by the key holder. The key holder learns `r` and the verdict; there is no fully blind comparison. A wrong key decrypts to garbage rather than an error.
- The circuit is linear. For policies whose weights sum to at most 1 (the default sums to exactly 1) it matches the plaintext gate; for larger sums the slack is a lower bound.
- Inputs are quantized to fixed point (default scale 1000), which is the only source of divergence from the plaintext score.
- No side-channel review and no independent audit.

## License

MIT - see LICENSE

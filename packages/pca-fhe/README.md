# @atlasauth/pca-fhe

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

For a signed action, `encryptedRiskClaim({ actn, publicKey, policy })` builds an encrypted claim bound to the PCActn's audience, params digest and counter, and `evalEncryptedRiskClaim(evalKeys, claim)` evaluates it. `plaintextVerdict(inputs, policy, budget)` gives the plaintext reference result for cross-checking.

## Status

Experimental and unaudited. What the test suite now establishes, and what it does not:

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
- It provides confidentiality, not integrity. BFV hides the inputs from the evaluator, but does not prove the evaluator ran the agreed circuit or that the ciphertext encrypts the agent's true inputs. A ciphertext holding values outside `[0, scale]` can wrap modulo the plaintext modulus and distort the verdict; the evaluator cannot range-check it. Those need a signed PCActn binding, a range proof and an attested evaluator.
- The verdict is the sign of an encrypted slack, decrypted by the key holder. The key holder learns `r` and the verdict; there is no fully blind comparison. A wrong key decrypts to garbage rather than an error.
- The circuit is linear. For policies whose weights sum to at most 1 (the default sums to exactly 1) it matches the plaintext gate; for larger sums the slack is a lower bound.
- Inputs are quantized to fixed point (default scale 1000), which is the only source of divergence from the plaintext score.
- No side-channel review and no independent audit.

## License

MIT - see LICENSE

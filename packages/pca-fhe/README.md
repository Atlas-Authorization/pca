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

Experimental and unaudited. Read the limits before relying on it:

- It provides confidentiality, not integrity. BFV hides the inputs from the evaluator, but does not prove the evaluator ran the agreed circuit or that the ciphertext encrypts the agent's true inputs. Those need a signed PCActn binding and an attested evaluator.
- The verdict is the sign of an encrypted slack, decrypted by the key holder. The key holder learns `r` and the verdict; there is no fully blind comparison.
- The circuit is linear. For policies whose weights sum to at most 1 (the default sums to exactly 1) it matches the plaintext gate; for larger sums the slack is a lower bound.
- Inputs are quantized to fixed point (default scale 1000), which is the only source of divergence from the plaintext score.

## License

MIT - see LICENSE

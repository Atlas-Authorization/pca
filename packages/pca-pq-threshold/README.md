# @atlasauth/pca-pq-threshold

Post-quantum hybrid threshold step-up for Proof-Carrying Authority (PCA). A step-up is authorized only when **both** of these hold over the same action:

- a classical FROST (Ed25519) t-of-n threshold signature, and
- a pqT-of-m quorum of ML-DSA-65 (FIPS 204) co-signatures.

A verifier fails closed if either quorum is short. A future break of the classical threshold alone does not forge the step-up, and a classical-only attacker is still stopped by the FROST threshold. The ML-DSA keys are ordinary single-party keys held by m distinct signers, so the post-quantum layer is a multi-signature quorum, not a true threshold scheme.

All cryptographic primitives come from `@atlasauth/pca`; this package composes the two quorums and binds them to a PCActn step-up.

## Install

```sh
npm i @atlasauth/pca-pq-threshold
```

Depends on `@atlasauth/pca`.

## Usage

```ts
import { frostTrustedDealerKeygen, mlDsa65Keygen } from '@atlasauth/pca';
import { hybridThresholdSign, verifyHybridThreshold } from '@atlasauth/pca-pq-threshold';

// Classical: 2-of-3 FROST group. Post-quantum: three ML-DSA-65 co-signer keys.
const frost = frostTrustedDealerKeygen(2, 3);
const pqKeys = [1, 2, 3].map((i) => mlDsa65Keygen(new Uint8Array(32).fill(i))); // use random seeds in practice

// `pcactn` is the PCActn (or body) being stepped up.
const artifact = hybridThresholdSign(pcactn, {
  frost: { groupPublicKey: frost.groupPublicKey, quorum: frost.participantShares.slice(0, 2), t: 2 },
  pqSigners: pqKeys.slice(0, 2).map((keyPair) => ({ keyPair })),
});

// Verify against YOUR trusted keys, never the keys the artifact declares.
const verdict = verifyHybridThreshold(pcactn, artifact, {
  groupKey: frost.groupPublicKey,
  pqPublicKeys: pqKeys.map((k) => k.publicKey),
  t: 2,
  pqT: 2,
});
verdict.ok; // true only if the FROST quorum AND the ML-DSA quorum both hold
```

To carry the result on a PCActn, `foldHybridStepUp(pcactn, artifact)` folds the FROST aggregate into the action's threshold field, and `verifyHybridStepUp(stepUp, { grant, groupKey, pqPublicKeys, t, pqT })` runs full PCActn verification with the hybrid check as the threshold hook. `createHybridThresholdVerifier(...)` exposes that hook directly.

## API

`hybridThresholdSign`, `verifyHybridThreshold`, `foldHybridStepUp`, `createHybridThresholdVerifier`, `verifyHybridStepUp`, and the types `HybridThresholdArtifact`, `HybridVerdict`, `HybridStepUp`.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). Cryptography is unaudited.

**ML-DSA-65 (the hybrid path).** The ML-DSA-65 used for the post-quantum co-signatures is validated against NIST's official ACVP vectors for FIPS 204 (key generation from seed, deterministic and hedged signature generation, and signature verification including the official negative classes: modified message, modified commitment hash, modified z and modified hint), and cross-checked in both directions against two independent implementations (dilithium-py 1.4.0 and liboqs 0.16.0). The wrappers this package calls expose the pure external interface with an empty context only; vectors that need a context or the internal interfaces are exercised on the same underlying library instance. Not covered: HashML-DSA (pre-hash) mode, which PCA does not use, constant-time behavior, and the FROST half of the hybrid, whose own validation lives in `@atlasauth/pca`. A passing test run does not replace an independent audit.

The package also exports an `experimental` namespace containing a toy sketch of a Raccoon/Ringtail-style lattice threshold. It is **not production**: no security proof, variable-time arithmetic, n-of-n additive sharing only, and it refuses to run without an explicit opt-in flag. No audited lattice-threshold signature library exists today; use the hybrid above.

## License

MIT - see LICENSE

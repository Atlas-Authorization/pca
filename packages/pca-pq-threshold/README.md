# @atlasauth/pca-pq-threshold

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
import { mlDsa65Keygen } from '@atlasauth/pca';
import { frostTrustedDealerKeygen } from '@atlasauth/pca/ext/frost';
import { generateKeyPair } from '@atlasauth/pca';
import { hybridThresholdSign, issueGroupDescriptor, verifyHybridThreshold } from '@atlasauth/pca-pq-threshold';

// Classical: 2-of-3 FROST group. Post-quantum: three ML-DSA-65 co-signer keys.
const frost = frostTrustedDealerKeygen(2, 3);
const pqKeys = [1, 2, 3].map((i) => mlDsa65Keygen(new Uint8Array(32).fill(i))); // use random seeds in practice

// At setup, an AUTHORITY key (a root of trust you pin; not part of the group) attests how the group was dealt.
const authority = generateKeyPair();
const groupDescriptor = issueGroupDescriptor({
  authoritySecretKey: authority.secretKey, groupPublicKey: frost.groupPublicKey, t: 2, participants: frost.participantShares,
});

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
  groupDescriptor,                          // required: binds t to the group key
  trustedAuthorities: [authority.publicKey], // pinned
});
verdict.ok; // true only if the FROST quorum AND the ML-DSA quorum both hold
```

To carry the result on a PCActn, `foldHybridStepUp(pcactn, artifact)` folds the FROST aggregate into the action's threshold field, and `verifyHybridStepUp(stepUp, { grant, groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities })` runs full PCActn verification with the hybrid check as the threshold hook. `createHybridThresholdVerifier(...)` exposes that hook directly.

## The threshold is bound to the group key

A FROST aggregate is a plain Ed25519 signature: from (group key, signature) a verifier cannot tell a 1-of-5 key from a 3-of-5 key, so a `t` supplied by the caller or declared in the artifact is only a label. The verifier therefore requires a signed group descriptor `{ suite, groupPublicKey, t, n, signerSetCommitment }` issued at DKG / dealing time by a setup authority whose key the verifier pins, and refuses the aggregate unless the descriptor verifies, is for the pinned group key, and has `t` equal to the required `t`. `signerSetCommitment` commits to the participants' verification shares and can be pinned too. A 1-of-n group key presented as 3-of-n is rejected (tested), as are a descriptor from an untrusted authority, an edited `t`, a descriptor for another group, and a missing descriptor.

An authority rather than "the group signs its own descriptor" because a 1-of-n group can sign a descriptor claiming 3-of-n by itself. The remaining trust assumption is the authority: a compromised authority key can certify a false `t`, and the descriptor says nothing about whether the dealer (or DKG) that formed the group behaved. Breaking change (unreleased): `groupDescriptor` and `trustedAuthorities` are now required by `verifyHybridThreshold`, `createHybridThresholdVerifier` and `verifyHybridStepUp`.

## API

`issueGroupDescriptor`, `verifyGroupDescriptor`, `signerSetCommitment`, `hybridThresholdSign`, `verifyHybridThreshold`, `foldHybridStepUp`, `createHybridThresholdVerifier`, `verifyHybridStepUp`, and the types `HybridThresholdArtifact`, `HybridVerdict`, `HybridStepUp`.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). Cryptography is unaudited.

**ML-DSA-65 (the hybrid path).** The ML-DSA-65 used for the post-quantum co-signatures is validated against NIST's official ACVP vectors for FIPS 204 (key generation from seed, deterministic and hedged signature generation, and signature verification including the official negative classes: modified message, modified commitment hash, modified z and modified hint), and cross-checked in both directions against two independent implementations (dilithium-py 1.4.0 and liboqs 0.16.0). The wrappers this package calls expose the pure external interface with an empty context only; vectors that need a context or the internal interfaces are exercised on the same underlying library instance. Not covered: HashML-DSA (pre-hash) mode, which PCA does not use, constant-time behavior, and the FROST half of the hybrid, whose own validation lives in `@atlasauth/pca`. A passing test run does not replace an independent audit.

The package also exports an `experimental` namespace containing a toy sketch of a Raccoon/Ringtail-style lattice threshold. It is **not production**: no security proof, variable-time arithmetic, n-of-n additive sharing only, and it refuses to run without an explicit opt-in flag. No audited lattice-threshold signature library exists today; use the hybrid above.

## License

MIT - see LICENSE

# @atlasauth/pca-oprf

RFC 9497 oblivious pseudorandom functions (OPRF, VOPRF, POPRF on `ristretto255-SHA512`) plus two Proof-Carrying Authority use cases built on them:

- **Private revocation checks**: ask whether a capability id is revoked without telling the revocation service which capability you mean.
- **Private rate limiting**: count and cap usage per `(identifier, window)` without the server ever seeing the identifier.

## Install

```sh
npm i @atlasauth/pca-oprf
```

## Usage

Private revocation check:

```ts
import { randomKeyPair, buildRevocationSet, makeRevocationEvaluator, isRevokedPrivate } from '@atlasauth/pca-oprf';

// Service side: key + published set of OPRF outputs of revoked capability ids.
const { secretKey } = randomKeyPair();
const revokedSet = buildRevocationSet(secretKey, ['cap_revoked_1'], 'voprf'); // 'oprf' or verifiable 'voprf'
const blindEval = makeRevocationEvaluator(secretKey, 'voprf');                 // answers blinded queries

// Client side: the service only sees a blinded element.
isRevokedPrivate('cap_revoked_1', { blindEval, revokedSet }); // true
isRevokedPrivate('cap_ok', { blindEval, revokedSet });        // false
```

Private rate limiting (the window is public, the identifier stays hidden):

```ts
import { randomKeyPair, makeRateEvaluator, privateRateToken, RateWindowCounter, publicKeyFor } from '@atlasauth/pca-oprf';

const { secretKey } = randomKeyPair();
const counter = new RateWindowCounter(100); // 100 hits per window token

const token = privateRateToken('agent-key-1', '2026-10-08T12', {
  blindEval: makeRateEvaluator(secretKey),
  publicKey: publicKeyFor(secretKey),
});
counter.hit(token); // { count: 1, allowed: true }
```

The same `(identifier, window)` always yields the same token (counts aggregate); a new window yields an unlinkable one (the count resets).

## API

- Ciphersuite: `blind`, `blindEvaluate`, `finalize`, `evaluate`, `blindPoprf`, `blindEvaluatePoprf`, `finalizePoprf`, `evaluatePoprf`, `deriveKeyPair`, `randomKeyPair`, `publicKeyFor`, `toHex`
- Revocation: `buildRevocationSet`, `makeRevocationEvaluator`, `isRevokedPrivate`
- Rate limiting: `rateToken`, `rateTokenHex`, `makeRateEvaluator`, `privateRateToken`, `RateWindowCounter`

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). **Experimental and unaudited.**

What is validated:

- **RFC 9497 Appendix A.1 (ristretto255-SHA512)**: all 8 official test vectors (OPRF 2, VOPRF 3, POPRF 3) and the three `DeriveKeyPair` results reproduce byte-for-byte: blinded elements, evaluated elements, outputs, and, for single-element batches, the DLEQ proofs (re-generated with the published proof nonce, and the published proofs verify). Fixtures live in `test-vectors/` with source URL, retrieval date and source SHA-256.
- **Independent implementation**: a 21-case corpus produced by the Rust `voprf` crate 0.5.0 (curve25519-dalek) is reproduced exactly, and messages produced by this package (random blinds and proof nonces) are accepted, re-evaluated and finalized to the same output by that crate. The crate itself reproduces the RFC vector-1 outputs. The runner source is in `test-vectors/xcheck-voprf-crate`.
- **Negative cases** assert the failure reason: tampered or cross-vector proofs, wrong public key, tampered evaluation, truncated proof, different public `info`, the identity element, non-canonical element and scalar encodings.

What is not validated:

- Only the ristretto255-SHA512 ciphersuite is implemented; the decaf448 and NIST P-curve suites of RFC 9497 are not supported.
- Batched evaluation (more than one element per proof) is not supported, so the batch-of-2 proof vectors are checked element by element only.
- No constant-time guarantee and no independent security audit.

## License

MIT - see LICENSE

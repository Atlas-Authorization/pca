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

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). Cryptography is unaudited and built on `@noble/curves`; do not rely on it for high-stakes privacy without your own review.

## License

MIT - see LICENSE

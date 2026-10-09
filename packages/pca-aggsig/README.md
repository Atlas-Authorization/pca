# @atlasauth/pca-aggsig

BLS12-381 signature aggregation for Proof-Carrying Authority (PCA). A whole delegation chain's per-hop signatures, or a transparency-ledger witness quorum's cosignatures, collapse into one 96-byte aggregate that is checked with a single pairing-product verification. The scheme is BLS with proof-of-possession (`draft-irtf-cfrg-bls-signature`), minimal-pubkey-size variant (48-byte G1 keys, 96-byte G2 signatures).

## Install

```sh
npm i @atlasauth/pca-aggsig
```

Depends on `@atlasauth/pca`, `@noble/curves` and `@noble/hashes` (installed transitively).

## Usage

```ts
import {
  keyGen, blsPublicKey, mintBlsRoot, blsDelegate,
  aggregateChainSignatures, verifyAggregatedChain,
  cosignTreeHead, aggregateWitnessCosignatures, verifyAggregatedWitnessCosignatures,
} from '@atlasauth/pca-aggsig';

// A two-hop delegation chain: principal -> alice -> bob.
const principal = keyGen(), alice = keyGen(), bob = keyGen();
const principalPub = blsPublicKey(principal.secretKey);

const root = mintBlsRoot({
  principalSecret: principal.secretKey,
  principalPublic: principalPub,
  holder: blsPublicKey(alice.secretKey),
  caveats: [{ type: 'scope', value: 'payments:write' }],
});
const hop1 = blsDelegate(root, blsPublicKey(bob.secretKey), [{ type: 'max_amount', limit: 100 }], alice.secretKey);

const chain = [root, hop1];
const aggSig = aggregateChainSignatures(chain);              // one 96-byte signature
verifyAggregatedChain(chain, aggSig, principalPub);          // { ok: true }

// A witness quorum cosigning one signed tree head.
const statement = { size: 1024, root: 'cm9vdEA=', prev_root: 'cHJldg==', guardian_epoch: 3 };
const cosigs = [keyGen(), keyGen(), keyGen()].map((w) => cosignTreeHead(statement, w.secretKey));
const agg = aggregateWitnessCosignatures(cosigs);
verifyAggregatedWitnessCosignatures(statement, cosigs.map((c) => c.key), agg); // true
```

`verifyAggregatedChain` also checks structure: depth bound, parent hash-links, holder-to-issuer continuity and append-only caveats. It never throws and returns `{ ok: false, reason }` on failure.

## API

- Core BLS: `keyGen`, `publicKeyOf`, `keyValidate`, `sign`, `verify`, `aggregate`, `aggregatePublicKeys`, `aggregateVerify`, `fastAggregateVerify`, `popProve`, `popVerify`.
- Capability chain (suite `bls12-381-pop`): `mintBlsRoot`, `blsAttenuate`, `blsDelegate`, `blsPublicKey`, `capHash`, `aggregateChainSignatures`, `verifyAggregatedChain`.
- Witness cosignatures: `cosignTreeHead`, `verifyWitnessCosignature`, `aggregateWitnessCosignatures`, `verifyAggregatedWitnessCosignatures`.

## Status

Experimental. The cryptography is built on `@noble/curves` but this package has not been independently audited, and BLS12-381 is not post-quantum. Aggregate signatures over distinct messages rely on every signer's key being proven (proof-of-possession) before it is trusted; use `popProve` / `popVerify` when accepting keys from third parties.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

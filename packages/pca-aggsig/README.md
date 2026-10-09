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

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). **Experimental and unaudited.** BLS12-381 is not post-quantum.

What is validated (proof-of-possession scheme, public keys in G1, signatures in G2):

- **Reference vectors**: the 90 community-standard vectors of `ethereum/bls12-381-tests` v0.1.2 for this exact ciphersuite (sign, verify, aggregate, fast-aggregate-verify, aggregate-verify, and G1/G2 point deserialization), vendored in `test-vectors/` with source, release hash and per-file SHA-256. All pass, including infinity-key, infinity-signature, tampered-signature, wrong-key, extra-key and malformed-encoding cases. The IETF draft itself publishes no test vectors (its test-vector appendix is still to be written), so these are the reference vectors for the scheme, not vectors from the draft text.
- **Independent implementation**: `py_ecc` 8.0.0. Its public keys, proofs of possession, signatures and aggregates are reproduced byte-for-byte, and artifacts produced here verify there (and tampered ones are rejected there).
- **Rogue-key behavior** is exercised: a key chosen as `a*G - pk_victim` lets an adversary forge a same-message aggregate, which is why `fastAggregateVerify` must only be given keys admitted with `popVerify`; the adversary cannot produce a valid proof of possession for such a key. Proofs of possession and message signatures are domain-separated.

What is not validated:

- Only the minimal-pubkey-size, proof-of-possession variant is implemented. The basic and message-augmentation schemes and the signatures-in-G1 variant are not.
- `aggregateVerify` additionally refuses repeated messages (stricter than the proof-of-possession scheme requires).
- The delegation-chain and witness-cosignature layers are PCA-specific and have no external standard; they are covered by this package's own tests only.
- Not constant-time, and no independent security audit.

## License

MIT - see LICENSE

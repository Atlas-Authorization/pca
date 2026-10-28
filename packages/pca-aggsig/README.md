# @atlasauth/pca-aggsig

> Maturity: **hardened** (hardened, awaiting independent audit). The engineering is done and evidenced by the community reference vectors, an independent implementation, abuse tests and a mutation gate; it awaits an independent review of the aggregation and proof-of-possession layers (O-1). It is never production until that review is done, and its API may still change. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

BLS12-381 signature aggregation for Proof-Carrying Authority (PCA). A whole delegation chain's per-hop signatures, or a transparency-ledger witness quorum's cosignatures, collapse into one 96-byte aggregate that is checked with a single pairing-product verification. The scheme is BLS with proof-of-possession (`draft-irtf-cfrg-bls-signature`), minimal-pubkey-size variant (48-byte G1 keys, 96-byte G2 signatures).

## Install

```sh
npm i @atlasauth/pca-aggsig
```

Depends on `@atlasauth/pca`, `@noble/curves` and `@noble/hashes` (installed transitively).

## Usage

```ts
import {
  keyGen, blsPublicKey, popProve, KeyRegistry, registerKey, mintBlsRoot, blsDelegate,
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

// Every signing key must be admitted with a proof of possession before it can count in an aggregate.
const registry = new KeyRegistry();
for (const k of [principal, alice]) registry.register(k.publicKey, popProve(k.secretKey)); // { ok: true, key }

const chain = [root, hop1];
const aggSig = aggregateChainSignatures(chain);              // one 96-byte signature
verifyAggregatedChain(chain, aggSig, registry, principalPub); // { ok: true }

// A witness quorum cosigning one signed tree head.
const statement = { size: 1024, root: 'cm9vdEA=', prev_root: 'cHJldg==', guardian_epoch: 3 };
const witnesses = [keyGen(), keyGen(), keyGen()];
const quorum = witnesses.map((w) => {
  const r = registerKey(w.publicKey, popProve(w.secretKey));
  if (!r.ok) throw new Error(r.reason);
  return r.key; // a RegisteredKey
});
const agg = aggregateWitnessCosignatures(witnesses.map((w) => cosignTreeHead(statement, w.secretKey)));
verifyAggregatedWitnessCosignatures(statement, quorum, agg); // true
```

`verifyAggregatedChain` also checks structure: depth bound, parent hash-links, holder-to-issuer continuity and append-only caveats. It never throws and returns `{ ok: false, reason }` on failure.

## API

- Core BLS: `keyGen`, `publicKeyOf`, `keyValidate`, `sign`, `verify`, `aggregate`, `popProve`.
- Rogue-key-safe aggregation: `registerKey(publicKey, pop)` -> `{ ok, key: RegisteredKey } | { ok: false, reason }`, `KeyRegistry`, `isRegisteredKey`, and `aggregateVerify` / `fastAggregateVerify`, which accept only `RegisteredKey`s.
- Capability chain (suite `bls12-381-pop`): `mintBlsRoot`, `blsAttenuate`, `blsDelegate`, `blsPublicKey`, `capHash`, `aggregateChainSignatures`, `verifyAggregatedChain`. `capHash` hashes everything EXCEPT `sig` (per-hop signatures are only checked in aggregate, so they must not feed identity); `verifyAggregatedChain` additionally requires every hop `sig` to be a canonical encoding and the hop sigs to sum to the verified aggregate, so a junk `sig` is refused rather than ignored (red-team RT-13; breaking: parent links computed by earlier versions do not match). Individual hop signatures are not separately verified, only their sum. `fastAggregateVerify` refuses a repeated key (one signer cannot count as N).
- Witness cosignatures: `cosignTreeHead`, `verifyWitnessCosignature`, `aggregateWitnessCosignatures`, `verifyAggregatedWitnessCosignatures`.

## Rogue-key safety is structural

Same-message aggregation is forgeable unless every key proved possession of its secret (a rogue key `g^x - sum(honest keys)` makes `sign_x(m)` a valid aggregate for the whole honest set). Here the safe path is the only path:

- `RegisteredKey` is an opaque class. The only producers are `registerKey` and `KeyRegistry.register`, which run KeyValidate and verify the key's proof of possession (a PoP-DST signature over the key). The constructor is token-guarded and instances are tracked in a module-private `WeakSet`, so a cast object, a prototype-forged object or a `structuredClone` is refused at runtime.
- `aggregateVerify` and `fastAggregateVerify` take `RegisteredKey[]`; there is no raw-key overload and no exported `aggregatePublicKeys` or `popVerify`. `verifyAggregatedChain` takes a `KeyRegistry` and refuses a chain whose issuer is not in it; `verifyAggregatedWitnessCosignatures` takes `RegisteredKey[]`.
- The raw verifiers exist only in the internal `core` module (used by the reference-vector tests), which is not exported from the index and blocked by `package.json` `exports`.

Residual: this proves possession at registration time. The application still decides which keys deserve a registry slot (who may register), and a `RegisteredKey` is only as trustworthy as the channel that carried the PoP. Breaking change (unreleased): `aggregatePublicKeys` and `popVerify` removed; `aggregateVerify`, `fastAggregateVerify`, `verifyAggregatedChain` (new `registry` argument before `expectedRootPrincipal`) and `verifyAggregatedWitnessCosignatures` (takes `RegisteredKey[]`) changed signature.

## Fail-closed behavior

Every row is pinned by a test that asserts the exact outcome.

| Missing or malformed input | Result |
|---|---|
| Public key is the identity, off the prime-order subgroup, not canonical or not 48 bytes | `keyValidate` false; `registerKey` returns `{ ok: false, reason }`; never admitted |
| Proof of possession missing, wrong length, for another key, or a message signature | `registerKey` returns `{ ok: false, reason }` |
| Key built from another key (`a*G - pk_victim`) | no valid proof exists; refused at registration |
| Signature is the identity, off the curve, off the subgroup, flag-cleared or not canonical | `verify`, `fastAggregateVerify`, `aggregateVerify` false; `aggregate` throws `RangeError` |
| Signer set is empty | verifiers return false; `aggregate` and `aggregatePublicKeys` throw `RangeError` |
| Same key listed twice in a same-message aggregate | `fastAggregateVerify` false |
| Same message twice in a distinct-message aggregate | `aggregateVerify` false |
| Key is not a `RegisteredKey` (raw bytes, plain object, null) | public verifiers return false; no throw |
| Chain issuer not in the registry, bad structure, depth over the bound, junk hop signature | `verifyAggregatedChain` returns `{ ok: false, reason }` |
| Witness quorum member missing, substituted, extra or duplicated | `verifyAggregatedWitnessCosignatures` false |
| Entropy source returns the degenerate key | `keyGen` throws |

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). **Hardened, awaiting independent audit.** BLS12-381 is not post-quantum.

What is validated (proof-of-possession scheme, public keys in G1, signatures in G2):

- **Reference vectors**: the 90 community-standard vectors of `ethereum/bls12-381-tests` v0.1.2 for this exact ciphersuite (sign, verify, aggregate, fast-aggregate-verify, aggregate-verify, and G1/G2 point deserialization), vendored in `test-vectors/` with source, release hash and per-file SHA-256. All pass, including infinity-key, infinity-signature, tampered-signature, wrong-key, extra-key and malformed-encoding cases. The IETF draft itself publishes no test vectors (its test-vector appendix is still to be written), so these are the reference vectors for the scheme, not vectors from the draft text.
- **Independent implementation**: `py_ecc` 8.0.0. Its public keys, proofs of possession, signatures and aggregates are reproduced byte-for-byte, and artifacts produced here verify there (and tampered ones are rejected there).
- **Rogue-key behavior** is exercised: a key chosen as `a*G - pk_victim` lets an adversary forge a same-message aggregate, which is why the public `fastAggregateVerify` accepts only keys admitted through `registerKey` (proof of possession); the adversary cannot produce a valid proof of possession for such a key. Proofs of possession and message signatures are domain-separated.

What is not validated:

- Only the minimal-pubkey-size, proof-of-possession variant is implemented. The basic and message-augmentation schemes and the signatures-in-G1 variant are not.
- `aggregateVerify` additionally refuses repeated messages (stricter than the proof-of-possession scheme requires).
- The delegation-chain and witness-cosignature layers are PCA-specific and have no external standard; they are covered by this package's own tests only.
- Not constant-time, and no independent security audit (this is what the hardened label awaits).

## License

MIT - see LICENSE

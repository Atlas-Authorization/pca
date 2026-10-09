# @atlasauth/pca-dpop

Sender-constrained proof-of-possession for Proof-Carrying Authority. It ties a PCActn to the holder key (or TLS channel) that is allowed to use it, and interoperates with OAuth proof-of-possession:

- RFC 9449 DPoP: a holder-key-signed `dpop+jwt` proof over the HTTP method and target URI.
- RFC 8705 mutual TLS: the `x5t#S256` certificate-thumbprint confirmation.

A PCActn's bound holder key is the last capability in its chain (`cap_chain[last].holder`, an Ed25519 public key). That key is exactly an OKP/Ed25519 JWK, so a DPoP proof signed by it has a `jkt` thumbprint equal to the PCActn's binding.

## Install

```sh
npm i @atlasauth/pca-dpop
```

Depends on `@atlasauth/pca` and `jose`.

## Usage

```ts
import { createDpopProof, assertPcaDpop, leafHolderJwk } from '@atlasauth/pca-dpop';

// Client: sign a DPoP proof with the same key that holds the PCActn's leaf capability.
const proof = await createDpopProof({
  method: 'POST',
  url: 'https://api.example.com/refunds',
  privateKey: holderPrivateJwk,          // { kty: 'OKP', crv: 'Ed25519', x, d }
  publicJwk: leafHolderJwk(pcactn),
});

// Resource server: confirm the proof is held by the PCActn's bound key and is for this request.
const seenJti = new Set<string>();       // use a shared store with expiry in production
const result = await assertPcaDpop(pcactn, proof, {
  method: 'POST',
  url: 'https://api.example.com/refunds', // query and fragment are ignored
  maxAgeSec: 300,                         // default 300
  seenJti,                                // rejects a repeated jti
});
result.jkt;                               // verified key thumbprint
```

`assertPcaDpop` throws a `DpopVerificationError` (with a `code` such as `typ`, `signature`, `htm`, `htu`, `iat_stale`, `jkt`, `jti_replay`) on any mismatch.

## API

- `createDpopProof`, `verifyDpopProof` (generic RFC 9449 proofs, with optional `expectedJkt`, `seenJti`, `nonce` and `ath`)
- `bindPcaToDpop(pcactn)` returns `{ jkt }`, the `cnf` binding for the PCActn's holder key
- `assertPcaDpop(pcactn, proof, opts)` verifies a proof against that binding
- `leafHolderJwk`, `jwkThumbprint`, `normalizeHtu`, `athFor`
- `mtlsCnf(certDerOrPem)` returns `{ 'x5t#S256': ... }`
- `DPOP_ALLOWED_ALGS`: asymmetric algorithms only (`none` and MACs are rejected)

## Status

Experimental. This package checks the proof only; it does not issue DPoP nonces, and replay protection is whatever `seenJti` store you supply. It does not verify the TLS client certificate itself, only computes its thumbprint for comparison. The cryptography is unaudited.

## License

MIT - see LICENSE

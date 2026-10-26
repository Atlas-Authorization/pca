# @atlasauth/pca-dpop

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
import { createDpopProof, assertPcaDpop, leafHolderJwk, createInMemoryDpopReplayStore } from '@atlasauth/pca-dpop';

// Client: sign a DPoP proof with the same key that holds the PCActn's leaf capability.
const proof = await createDpopProof({
  method: 'POST',
  url: 'https://api.example.com/refunds',
  privateKey: holderPrivateJwk,          // { kty: 'OKP', crv: 'Ed25519', x, d }
  publicJwk: leafHolderJwk(pcactn),
});

// Resource server: confirm the proof is held by the PCActn's bound key and is for this request.
const replayStore = createInMemoryDpopReplayStore(); // single process only; use a shared store in production
const result = await assertPcaDpop(pcactn, proof, {
  method: 'POST',
  url: 'https://api.example.com/refunds', // query and fragment are ignored
  maxAgeSec: 300,                         // default 300
  replayStore,                            // rejects a repeated jti
  requireReplayStore: true,               // refuse to run without a store
});
result.jkt;                               // verified key thumbprint
```

`assertPcaDpop` throws a `DpopVerificationError` (with a `code` such as `typ`, `signature`, `htm`, `htu`, `iat_stale`, `jkt`, `jti_replay`) on any mismatch.

## API

- `createDpopProof`, `verifyDpopProof` (generic RFC 9449 proofs, with optional `expectedJkt`, `replayStore`, `requireReplayStore`, `nonceIssuer`, `expectedNonce` and `accessToken`)
- `createDpopNonceIssuer`, `createInMemoryDpopReplayStore`, `runDpopReplayStoreConformance`
- `bindPcaToDpop(pcactn)` returns `{ jkt }`, the `cnf` binding for the PCActn's holder key
- `assertPcaDpop(pcactn, proof, opts)` verifies a proof against that binding
- `leafHolderJwk`, `jwkThumbprint`, `normalizeHtu`, `athFor`
- `mtlsCnf(certDerOrPem)` returns `{ 'x5t#S256': ... }`
- `DPOP_ALLOWED_ALGS`: asymmetric algorithms only (`none` and MACs are rejected)

## Replay protection, nonces and limits

DPoP only works if the server remembers the `jti` of every proof it accepted. This package cannot do that for you, so pass a `replayStore` and set `requireReplayStore: true` on every resource server: with that flag, a call with neither `replayStore` nor `seenJti` is refused (`replay_store_required`) instead of silently skipping replay detection. Without the flag the check is skipped when no store is given; that default is kept for compatibility and will be tightened in a future major release.

```ts
import { createDpopNonceIssuer, createInMemoryDpopReplayStore, verifyDpopProof } from '@atlasauth/pca-dpop';

const issuer = createDpopNonceIssuer({ secret, ttlSec: 300 }); // secret: >= 32 random bytes
const replayStore = createInMemoryDpopReplayStore();            // single process only; use a shared store in production

// Send `DPoP-Nonce: issuer.issue()` to clients; then:
const result = await verifyDpopProof(proof, {
  method: 'POST',
  url: 'https://api.example.com/refunds',
  maxAgeSec: 120,
  replayStore,
  requireReplayStore: true,
  nonceIssuer: issuer,
});
```

`DpopReplayStore.addIfAbsent(key, expiresAtSec, nowSec)` must be atomic (one winner among concurrent calls) and is keyed `<jkt>.<jti>`, so another key holder cannot burn your `jti`. Run `runDpopReplayStoreConformance(() => yourStore)` against your implementation; it returns the failed checks (empty means conformant). The in-memory store is a single-process test double: state is lost on restart and not shared between processes. `seenJti` (a synchronous `Set`) still works but is not atomic across processes.

The nonce issuer is stateless: a timestamp authenticated with your secret, valid for `ttlSec`. Reply `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh `DPoP-Nonce` header when a proof's nonce is refused.

Limits: a proof string longer than 8192 bytes is refused; allowed algorithms are `EdDSA`, `ES256`, `ES384`, `ES512`, `PS256`, `RS256`; accepted clock skew is 5 seconds.

## Failure modes

Every row has a test asserting the exact error `code` and message. Nothing is recorded in the replay store on a failure.

| Input | `code` |
| --- | --- |
| `requireReplayStore` set, no store given | `replay_store_required` |
| proof not a string, or over 8192 bytes | `oversize` |
| not canonical compact JWS | `malformed` |
| `typ` is not `dpop+jwt` | `typ` |
| no `jwk` in the header | `no_jwk` |
| header `jwk` carries private key material | `private_jwk` |
| bad signature, disallowed `alg` (`none`, `HS256`, others) | `signature` |
| `htm`, `htu`, `iat`, `jti` missing or wrong type | `htm`, `htu`, `iat`, `jti` |
| method or URL differs from the request | `htm`, `htu` |
| `iat` more than 5 s ahead | `iat_future` |
| `iat` older than `maxAgeSec` | `iat_stale` |
| key thumbprint differs from `expectedJkt` (or the PCActn's holder key) | `jkt` |
| nonce missing, wrong, forged or expired | `nonce` |
| `ath` missing or not the hash of the access token | `ath` |
| `jti` already seen | `jti_replay` |
| replay store throws | `replay_store_error` |
| PCActn has an empty capability chain | `no_leaf` |

## Status

Maturity is experimental. Pinned to RFC 9449 (DPoP) and RFC 8705 (mutual-TLS certificate-bound tokens). A mutation-testing run has not been made for this package, no independent DPoP server has been run against it, and the cryptography is unaudited. This package does not verify the TLS client certificate itself, only computes its thumbprint for comparison.

What is validated:

- The three example DPoP proofs published in RFC 9449 (token request, refresh request, and the resource request with `ath`) are accepted, with the RFC's own `jkt`, `ath` and thumbprint values reproduced. Their ES256 signatures are also checked with Node's built-in crypto, independent of `jose`.
- Proofs interoperate in both directions with PyJWT 2.10.1 (Ed25519 and ES256).
- `mtlsCnf` matches the SHA-256 fingerprint OpenSSL and Node's `X509Certificate` report for the same certificate. RFC 8705 publishes the example thumbprint but not the certificate it came from, so the RFC value itself cannot be reproduced.
- Each failure row above is rejected for its named reason.

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the DPoP proof (rejected with code `malformed`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

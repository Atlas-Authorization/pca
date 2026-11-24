# @atlasauth/pca-dpop

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
const replayStore = createInMemoryDpopReplayStore(); // bounded, single process only; use a shared store across processes
const result = await assertPcaDpop(pcactn, proof, {
  method: 'POST',
  url: 'https://api.example.com/refunds', // query and fragment are ignored
  maxAgeSec: 300,                         // default 300
  replayStore,                            // required: rejects a repeated jti
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
- `mtlsCnf(certDerOrPem)` returns `{ 'x5t#S256': ... }` (hash only, no parsing)
- `mtlsThumbprint(cert)` and `assertMtlsBound(cert, cnf)`: parse the certificate as X.509 and compare its SHA-256 thumbprint with a token's `cnf` (RFC 8705 section 3.1)
- `dpopAlgMatchesJwk(alg, jwk)`
- `DPOP_ALLOWED_ALGS`: asymmetric algorithms only (`none` and MACs are rejected)

## Replay protection, nonces and limits

DPoP only works if the server remembers the `jti` of every proof it accepted. This package cannot do that for you, so a `replayStore` (or `seenJti`) is required: a call with neither is refused (`replay_store_required`) before the proof is even parsed. Pass `requireReplayStore: false` only to opt out on purpose, for example a stateless pre-check whose replay is detected elsewhere.

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
  nonceIssuer: issuer,
});
```

`DpopReplayStore.addIfAbsent(key, expiresAtSec, nowSec)` must be atomic (one winner among concurrent calls) and is keyed `<jkt>.<jti>`, so another key holder cannot burn your `jti`. Run `runDpopReplayStoreConformance(() => yourStore)` against your implementation; it returns the failed checks (empty means conformant). The in-memory store is bounded (100000 live entries by default, `maxEntries` to change): it never evicts a live entry, so when full it throws and the verifier refuses with `replay_store_error`. Its state is lost on restart and not shared between processes, so use a shared store when more than one process verifies. `seenJti` (a synchronous `Set`) still works but is not atomic across processes.

The nonce issuer is stateless: a timestamp authenticated with your secret, valid for `ttlSec`. Reply `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh `DPoP-Nonce` header when a proof's nonce is refused.

Limits: a proof string longer than 8192 bytes is refused; allowed algorithms are `EdDSA`, `ES256`, `ES384`, `ES512`, `PS256`, `RS256`; accepted clock skew is 5 seconds.

## Failure modes

Every row has a test asserting the exact error `code` and message. Nothing is recorded in the replay store on a failure.

| Input | `code` |
| --- | --- |
| no `replayStore` and no `seenJti` (unless `requireReplayStore: false`) | `replay_store_required` |
| proof not a string, or over 8192 bytes | `oversize` |
| not canonical compact JWS | `malformed` |
| `typ` is not `dpop+jwt` | `typ` |
| no `jwk` in the header | `no_jwk` |
| header `jwk` carries private key material | `private_jwk` |
| header `alg` does not belong to the embedded key type (for example `EdDSA` over an RSA key) | `alg_jwk_mismatch` |
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
| in-memory store full | `replay_store_error` |

Certificate binding (`assertMtlsBound`):

| Input | `code` |
| --- | --- |
| `cnf` has no string `x5t#S256` | `x5t_missing` |
| certificate does not parse as X.509 | `cert` |
| certificate hash differs from `cnf` | `x5t` |

## Status

Production. Pinned to RFC 9449 (DPoP) and RFC 8705 (mutual-TLS certificate-bound tokens). Cross-language conformance does not apply: this is a server-side bridge for a standard OAuth mechanism, validated against independent implementations instead (below).

Limits:

- `assertMtlsBound` compares a certificate you already authenticated with a token's `cnf`. It does not run the TLS handshake or validate the chain; your TLS terminator does that.
- `assertPcaDpop` checks that the proof is held by the PCActn's bound holder key and is for this request. It does not verify the PCActn itself; do that with the PCA verifier.
- Only the algorithms listed above are accepted, and a proof over 8192 bytes is refused.
- The cryptography is `jose` and Node's built-in crypto; this package is not independently audited.

What is validated:

- The three example DPoP proofs published in RFC 9449 (token request, refresh request, and the resource request with `ath`) are accepted, with the RFC's own `jkt`, `ath` and thumbprint values reproduced. Their ES256 signatures are also checked with Node's built-in crypto, independent of `jose`.
- Proofs interoperate in both directions with PyJWT 2.10.1 (Ed25519 and ES256).
- A second, independent resource-server implementation (Python `cryptography`, no shared code) judges a generated matrix of proofs (EdDSA, ES256, ES384; good, wrong method, wrong URL, stale, future, wrong `ath`, wrong `jkt`, tampered) and agrees with this package on accept or reject and on the reason.
- `x5t#S256` is checked against certificates built and hashed by other tools (Python `cryptography` and OpenSSL), and against a certificate assembled byte by byte in the unit tests and hashed with Node's `X509Certificate`. RFC 8705 publishes an example thumbprint but not the certificate it came from, so the RFC value itself cannot be reproduced.
- Each failure row above is rejected for its named reason, with the exact message.

Breaking changes in 0.5: a replay store is required by default, the header `alg` must match the embedded key type, and the in-memory store is bounded.

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the DPoP proof (rejected with code `malformed`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

# @atlasauth/pca-spiffe

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Bridge Proof-Carrying Authority agent identity with SPIFFE / SPIRE workload identity. A SPIFFE workload is the kind of attested, non-human principal PCA calls an agent holder. This package validates SPIFFE IDs, verifies JWT-SVIDs, parses and verifies X.509-SVIDs, and maps a SPIFFE ID to and from a PCA holder (a base64url Ed25519 public key usable as `Capability.holder`).

## Install

```sh
npm i @atlasauth/pca-spiffe @atlasauth/pca jose
```

## Quick start

A complete, runnable verification of a JWT-SVID with revocation checking (Node 20+, ESM; install `@atlasauth/pca-spiffe`, `@atlasauth/pca` and `jose`). The key pair is generated here only so the example is self-contained: in production the key comes from your trust bundle.

```ts
import { generateKeyPair, SignJWT } from 'jose';
import { createRevocationSource, svidToHolder, verifyJwtSvid } from '@atlasauth/pca-spiffe';

const { privateKey, publicKey } = await generateKeyPair('ES256');
const token = await new SignJWT({ sub: 'spiffe://example.org/ns/prod/agent-7' })
  .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
  .setAudience('rs')
  .setExpirationTime('5m')
  .sign(privateKey);

const revocation = createRevocationSource({
  fetch: async () => ({ spiffeIds: [] }), // your revocation data; may reject
  refreshMs: 30_000,
  maxStaleMs: 120_000,
});

const svid = await verifyJwtSvid(token, { audience: 'rs', trustDomain: 'example.org', key: publicKey, revocation: revocation.jwt });
console.log(svid.spiffeId.path); // '/ns/prod/agent-7'

// A JWT-SVID has no key of its own: bind it to a PCA holder key you authenticated another way.
const holderKey = Buffer.alloc(32, 1).toString('base64url'); // stand-in 32-byte Ed25519 public key
console.log(svidToHolder(svid, holderKey, { acceptUnboundJwtHolder: true }).spiffeId);
```

## Usage

```ts
import { parseSpiffeId, verifyJwtSvid, parseX509Svid, verifyX509Svid, svidToHolder, holderToSpiffeId, SpiffeError } from '@atlasauth/pca-spiffe';

// Verify a JWT-SVID (audience is mandatory; `key` may also be a JWKS resolver from jose).
const svid = await verifyJwtSvid(token, { audience: 'rs', key: bundleKey, trustDomain: 'example.org' });
svid.spiffeId.path; // '/ns/prod/agent-7'

// Or parse an X.509-SVID leaf (PEM or DER): one URI SAN, CA:FALSE, digitalSignature, no keyCertSign/cRLSign.
const x509 = parseX509Svid(pem);

// Verify the leaf and its chain against the trust domain's bundle authorities (signatures, CA flags,
// keyCertSign, pathLenConstraint, validity, trust domain).
const verified = verifyX509Svid(chainPem, { trustDomain: 'example.org', roots: [bundleCaPem] });

// Bind the workload to a PCA holder key, then use `.holder` with mintRoot / delegate.
// svidToHolder takes only a VERIFIED SVID. X.509 with an Ed25519 key: the holder is the cert key.
const h = svidToHolder(verified);
// Any other holder key needs a signature by the SVID key over holderBindingMessage(spiffeId, holder):
//   svidToHolder(verified, agentPublicKeyB64u, { proof })
// A JWT-SVID is a bearer token: it needs a matching cnf.jwk, or { acceptUnboundJwtHolder: true } if you authenticated the key another way.
const hj = svidToHolder(svid, agentPublicKeyB64u, { acceptUnboundJwtHolder: true });
h.holder;               // use as Capability.holder
holderToSpiffeId(h);    // 'spiffe://example.org/ns/prod/agent-7'

try { parseSpiffeId('spiffe://Bad/x'); } catch (e) { (e as SpiffeError).code; } // 'invalid_trust_domain'
```

## API

- `parseSpiffeId`, `verifyJwtSvid`, `parseX509Svid`, `verifyX509Svid`, `svidToHolder`, `holderBindingMessage`, `holderToSpiffeId`, `JWT_SVID_ALGORITHMS`, `createTrustBundleSource`, `createRevocationSource`.
- Types: `SpiffeId`, `JwtSvid`, `X509Svid`, `SpiffeHolder`, `SpiffeError` (with a stable `code`), `X509RevocationCheck`, `JwtRevocationCheck`, `RevocationList`, `RevocationSource`.

## Status

Production. This package performs no cryptography of its own beyond Node's certificate signature checks and `jose`.

Since 0.4, `verifyJwtSvid` requires `trustDomain` (no unpinned mode), and `svidToHolder` accepts only the object returned by `verifyJwtSvid` / `verifyX509Svid` (strings, parsed IDs and parse-only SVIDs throw `unverified_svid`). An X.509-SVID binds its own Ed25519 key, or another holder key with a proof signed by the SVID key. A JWT-SVID has no key of its own, so a holder key is bound only through a `cnf.jwk` claim, or by your explicit `acceptUnboundJwtHolder` attestation that you authenticated the key by other means.

What is validated:

- SPIFFE IDs follow the SPIFFE-ID standard, checked with the character-by-character rules of go-spiffe v2 (every code point 0 to 255 in the trust domain and the path, empty and dot segments, scheme, percent-encoding, length limits), compared against py-spiffe 0.3.2 on 545 strings and against go-spiffe itself on the same strings. py-spiffe is more lenient than the standard (case-insensitive scheme and trust domain, no length limits, accepts a trailing newline); this package follows the standard.
- X.509-SVID leaves: the go-spiffe test certificates are checked, including each deliberately wrong leaf (CA flag set, `keyCertSign`, `cRLSign`, no `digitalSignature`, no URI SAN) and signing certificate (not a CA, no `keyCertSign`), each rejected with its own error code. The SPIFFE ID is read from the DER subjectAltName.
- `verifyX509Svid` builds the chain to a bundle authority using Node's certificate signature checks. Its accept and reject decisions on nine chains (valid, path-length violation, signer without `keyCertSign`, signer that is not a CA, expired, not yet valid, unrelated root, missing intermediate) match the OpenSSL command-line verifier, the Python `cryptography` verifier and go-spiffe's chain verifier; the ten wrong-leaf certificates also get the same verdict as go-spiffe, except where the specification is stricter than go-spiffe (a leaf whose SPIFFE ID has no path).
- JWT-SVIDs: tokens signed by PyJWT (ES256, RS256, PS256) are accepted, and the tampered variants (wrong audience, expired, missing `exp` or `aud`, bad `sub`, other signer, wrong `typ`, wrong trust domain) get the same verdict as py-spiffe, and as go-spiffe on tokens signed in Go (except the `typ` header, which the specification checks and go-spiffe does not). Only the algorithms the JWT-SVID specification allows (RS, ES, PS families) are accepted by default; `none` and HMAC are always refused.
- Revocation (below): a revoked SVID is refused, and an unavailable, stale, failing or malformed revocation source refuses.

The cross-implementation checks are a documented, repeatable comparison with independent verifiers (they run in the project's CI); this is not a cross-language port, because this package is a TypeScript bridge to the SPIFFE ecosystem and the wire formats it reads (X.509, JWT) are verified by independent implementations rather than re-implemented in other languages.

`parseX509Svid` rejects CA certificates and certificates without `digitalSignature`, and `verifyJwtSvid` refuses HMAC algorithms even when given raw key bytes.

## Revocation (fail closed when configured)

SVIDs are short-lived, and SPIFFE relies on expiry as its usual bound. When you also keep revocation data (a CRL you converted, an admin deny-list, an incident response list), pass it as `revocation`. It is checked last, only for an SVID that passed every other check, and for every presented certificate of an X.509 chain.

```ts
import { createRevocationSource, verifyX509Svid, verifyJwtSvid } from '@atlasauth/pca-spiffe';

const revocation = createRevocationSource({
  fetch: async () => ({ fingerprints: revokedFingerprints, spiffeIds: revokedIds, jtis: revokedJtis }), // your data; may reject
  refreshMs: 30_000,   // re-fetch when the snapshot is older than this
  maxStaleMs: 120_000, // never use a snapshot older than this since its last successful fetch
});
await revocation.ensureFresh();                                             // X.509 check is synchronous: refresh first
verifyX509Svid(chainPem, { trustDomain, roots, revocation: revocation.x509 });
await verifyJwtSvid(token, { audience, trustDomain, key, revocation: revocation.jwt }); // refreshes itself
```

You can also pass your own function: it receives `{ spiffeId, serialNumber, fingerprint256, position, isLeaf }` (X.509) or `{ spiffeId, jti?, expiresAt, tokenHash }` (JWT) and must return exactly `false` to admit. A revoked SVID is `svid_revoked` (a revoked signing certificate is `chain_revoked`); a function that throws, rejects or returns anything but a boolean, a missing or stale snapshot, and a revocation option that is not a function are all `revocation_unavailable`. When `revocation` is not set, nothing is checked. The bundle authority is not asked: remove a compromised authority from the bundle.

Serial numbers are unique per issuer only; a `serials` entry matches that serial under any issuer, so prefer `fingerprints` unless one CA issues all your SVIDs. Parsing a CRL file is out of scope: convert it to fingerprints or serials with your CA tooling.

## Trust bundle refresh (fail closed)

`createTrustBundleSource` wraps your own bundle fetch (Workload API, bundle endpoint, file) and hands out a JWT key resolver and the X.509 authorities. All three timing options are required.

```ts
import { createTrustBundleSource, verifyJwtSvid, verifyX509Svid } from '@atlasauth/pca-spiffe';

const bundle = createTrustBundleSource({
  fetch: async () => ({ jwks: await getJwks(), x509Authorities: await getRootPems() }), // may reject
  refreshMs: 60_000,   // re-fetch when the cached bundle is older than this
  maxStaleMs: 300_000, // never use a bundle older than this since its last successful fetch
});
await verifyJwtSvid(token, { audience: 'rs', trustDomain: 'example.org', key: bundle.jwtKey });
verifyX509Svid(chainPem, { trustDomain: 'example.org', roots: await bundle.x509Roots() });
```

A successful refresh replaces the bundle (nothing is merged), so a removed authority stops being trusted at the next refresh. Concurrent callers share one fetch.

## Failure modes

Every failure throws a `SpiffeError` (or a `jose` error for signature, expiry and key-selection failures); nothing returns a partial result.

| Missing or invalid | Result (`code`) |
|---|---|
| bundle never fetched successfully, fetch rejects | `trust_bundle_unavailable` |
| bundle fetched but has no authorities or is malformed | `trust_bundle_invalid` (a previous good bundle is kept until `maxStaleMs`) |
| last good fetch older than `maxStaleMs` | `trust_bundle_unavailable` (or `_invalid`), every call |
| JWT-SVID: no `trustDomain`, empty `audience` | `missing_trust_domain`, `missing_audience` |
| JWT-SVID: `none` / `HS*` / empty algorithm list | `forbidden_algorithm` |
| JWT-SVID: non-canonical token spelling | `malformed_token` |
| JWT-SVID: bad signature, unknown `kid`, wrong `aud`, expired, `nbf` in the future | `jose` error (`ERR_JWS_SIGNATURE_VERIFICATION_FAILED`, `ERR_JWKS_NO_MATCHING_KEY`, `ERR_JWT_CLAIM_VALIDATION_FAILED`, `ERR_JWT_EXPIRED`) |
| JWT-SVID: no `exp`, bad `typ`, bad or foreign `sub` | `missing_exp`, `invalid_typ`, `invalid_subject`, `trust_domain_mismatch` |
| X.509-SVID: not a certificate, unknown critical extension | `malformed_certificate`, `unsupported_critical_extension` |
| X.509-SVID leaf: no or several URI SANs, CA flag, wrong key usage, root path | `no_uri_san`, `multiple_uri_san`, `leaf_is_ca`, `leaf_no_digital_signature`, `leaf_cert_sign`, `leaf_crl_sign`, `leaf_root_path` |
| chain: empty, too long, wrong trust domain, expired, bad signature, signer not a CA, no `keyCertSign`, path length exceeded, no bundle authority | `chain_empty`, `chain_too_long`, `chain_trust_domain_mismatch`, `chain_expired`, `chain_signature`, `chain_not_ca`, `chain_no_key_cert_sign`, `chain_path_len`, `chain_untrusted_root` |
| `svidToHolder` given an unverified SVID, a wrong holder key, a missing proof or `cnf.jwk` | `unverified_svid`, `invalid_holder_key`, `holder_binding_failed` |
| revocation configured: SVID (or, for X.509, a signing certificate) is on the list | `svid_revoked` (`chain_revoked` for a signing certificate) |
| revocation configured: no snapshot yet, snapshot older than `maxStaleMs`, fetch rejects, malformed list, check throws or returns a non-boolean, option not a function | `revocation_unavailable` |
| revocation not configured | not checked: expiry is the only bound (by design, stated here) |

## Limits

- Revocation is opt-in. Without `revocation`, a stolen SVID is accepted until it expires; keep SVID lifetimes short, or configure revocation.
- No CRL or OCSP parsing, no name constraints, no SPIFFE federation or Workload API client: you fetch bundles and revocation data yourself.
- The "verified" marker that `svidToHolder` relies on is process-local; it does not survive serialization or a process boundary. Re-verify in each process.
- SPIFFE IDs are limited to 2048 bytes and trust domains to 255 bytes; chains to 8 certificates by default.
- A verified JWT-SVID is a bearer token until you bind it to a key.

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the JWT-SVID (rejected with code `malformed_token`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

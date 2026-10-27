# @atlasauth/pca-spiffe

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Bridge Proof-Carrying Authority agent identity with SPIFFE / SPIRE workload identity. A SPIFFE workload is the kind of attested, non-human principal PCA calls an agent holder. This package validates SPIFFE IDs, verifies JWT-SVIDs, parses and verifies X.509-SVIDs, and maps a SPIFFE ID to and from a PCA holder (a base64url Ed25519 public key usable as `Capability.holder`).

## Install

```sh
npm i @atlasauth/pca-spiffe @atlasauth/pca jose
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
// svidToHolder takes only a VERIFIED SVID (R3-18). X.509 with an Ed25519 key: the holder is the cert key.
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

- `parseSpiffeId`, `verifyJwtSvid`, `parseX509Svid`, `verifyX509Svid`, `svidToHolder`, `holderBindingMessage`, `holderToSpiffeId`, `JWT_SVID_ALGORITHMS`.
- Types: `SpiffeId`, `JwtSvid`, `X509Svid`, `SpiffeHolder`, `SpiffeError` (with a stable `code`).

## Status

Experimental and unaudited. Breaking in R3-18: `verifyJwtSvid` requires `trustDomain` (no unpinned mode), and `svidToHolder` accepts only the object returned by `verifyJwtSvid` / `verifyX509Svid` (strings, parsed IDs and parse-only SVIDs throw `unverified_svid`). An X.509-SVID binds its own Ed25519 key, or another holder key with a proof signed by the SVID key. A JWT-SVID has no key of its own, so a holder key is bound only through a `cnf.jwk` claim, or by your explicit `acceptUnboundJwtHolder` attestation that you authenticated the key by other means.

What is validated:

- SPIFFE IDs follow the SPIFFE-ID standard, checked with the character-by-character rules of go-spiffe v2 (every code point 0 to 255 in the trust domain and the path, empty and dot segments, scheme, percent-encoding, length limits), and compared against py-spiffe 0.3.2 on 545 strings. py-spiffe is more lenient than the standard (case-insensitive scheme and trust domain, no length limits, accepts a trailing newline); this package follows the standard.
- X.509-SVID leaves: the go-spiffe test certificates are checked, including each deliberately wrong leaf (CA flag set, `keyCertSign`, `cRLSign`, no `digitalSignature`, no URI SAN) and signing certificate (not a CA, no `keyCertSign`), each rejected with its own error code. The SPIFFE ID is read from the DER subjectAltName.
- `verifyX509Svid` builds the chain to a bundle authority using Node's certificate signature checks. Its accept and reject decisions on nine chains (valid, path-length violation, signer without `keyCertSign`, signer that is not a CA, expired, not yet valid, unrelated root, missing intermediate) match both the OpenSSL command-line verifier and the Python `cryptography` verifier.
- JWT-SVIDs: tokens signed by PyJWT (ES256, RS256, PS256) are accepted, and the tampered variants (wrong audience, expired, missing `exp` or `aud`, bad `sub`, other signer, wrong `typ`, wrong trust domain) get the same verdict as py-spiffe. Only the algorithms the JWT-SVID specification allows (RS, ES, PS families) are accepted by default; `none` and HMAC are always refused.

`parseX509Svid` rejects CA certificates and certificates without `digitalSignature` (releases before this one accepted any certificate with a single URI SAN), and `verifyJwtSvid` refuses HMAC algorithms even when given raw key bytes.

Not validated: certificate revocation and name constraints are not checked (a critical extension this package does not understand makes verification fail); `verifyX509Svid` has not been compared against go-spiffe's own chain verifier; the Workload API and SPIFFE federation are out of scope. Bundle refresh is yours to fetch; `createTrustBundleSource` (below) caches it and fails closed.

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

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the JWT-SVID (rejected with code `malformed_token`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

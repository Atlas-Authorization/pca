# @atlasauth/pca-spiffe

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
const h = svidToHolder(svid.spiffeId, agentPublicKeyB64u); // b64u string or 32 raw bytes
h.holder;               // use as Capability.holder
holderToSpiffeId(h);    // 'spiffe://example.org/ns/prod/agent-7'

try { parseSpiffeId('spiffe://Bad/x'); } catch (e) { (e as SpiffeError).code; } // 'invalid_trust_domain'
```

## API

- `parseSpiffeId`, `verifyJwtSvid`, `parseX509Svid`, `verifyX509Svid`, `svidToHolder`, `holderToSpiffeId`, `JWT_SVID_ALGORITHMS`.
- Types: `SpiffeId`, `JwtSvid`, `X509Svid`, `SpiffeHolder`, `SpiffeError` (with a stable `code`).

## Status

Experimental and unaudited. `svidToHolder` records an association between a SPIFFE ID and a holder key; it does not prove that the key belongs to that workload. Establish that yourself (for example by using the key in the X.509-SVID, or checking the attested workload controls it).

What is validated:

- SPIFFE IDs follow the SPIFFE-ID standard, checked with the character-by-character rules of go-spiffe v2 (every code point 0 to 255 in the trust domain and the path, empty and dot segments, scheme, percent-encoding, length limits), and compared against py-spiffe 0.3.2 on 545 strings. py-spiffe is more lenient than the standard (case-insensitive scheme and trust domain, no length limits, accepts a trailing newline); this package follows the standard.
- X.509-SVID leaves: the go-spiffe test certificates are checked, including each deliberately wrong leaf (CA flag set, `keyCertSign`, `cRLSign`, no `digitalSignature`, no URI SAN) and signing certificate (not a CA, no `keyCertSign`), each rejected with its own error code. The SPIFFE ID is read from the DER subjectAltName.
- `verifyX509Svid` builds the chain to a bundle authority using Node's certificate signature checks. Its accept and reject decisions on nine chains (valid, path-length violation, signer without `keyCertSign`, signer that is not a CA, expired, not yet valid, unrelated root, missing intermediate) match both the OpenSSL command-line verifier and the Python `cryptography` verifier.
- JWT-SVIDs: tokens signed by PyJWT (ES256, RS256, PS256) are accepted, and the tampered variants (wrong audience, expired, missing `exp` or `aud`, bad `sub`, other signer, wrong `typ`, wrong trust domain) get the same verdict as py-spiffe. Only the algorithms the JWT-SVID specification allows (RS, ES, PS families) are accepted by default; `none` and HMAC are always refused.

`parseX509Svid` rejects CA certificates and certificates without `digitalSignature` (releases before this one accepted any certificate with a single URI SAN), and `verifyJwtSvid` refuses HMAC algorithms even when given raw key bytes.

Not validated: certificate revocation and name constraints are not checked (a critical extension this package does not understand makes verification fail); `verifyX509Svid` has not been compared against go-spiffe's own chain verifier; trust bundle retrieval and rotation, the Workload API, and SPIFFE federation are out of scope.

## License

MIT - see LICENSE

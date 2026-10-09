# @atlasauth/pca-spiffe

Bridge Proof-Carrying Authority agent identity with SPIFFE / SPIRE workload identity. A SPIFFE workload is the kind of attested, non-human principal PCA calls an agent holder. This package validates SPIFFE IDs, verifies JWT-SVIDs, parses X.509-SVIDs, and maps a SPIFFE ID to and from a PCA holder (a base64url Ed25519 public key usable as `Capability.holder`).

## Install

```sh
npm i @atlasauth/pca-spiffe @atlasauth/pca jose
```

## Usage

```ts
import { parseSpiffeId, verifyJwtSvid, parseX509Svid, svidToHolder, holderToSpiffeId, SpiffeError } from '@atlasauth/pca-spiffe';

// Verify a JWT-SVID (audience is mandatory; `key` may also be a JWKS resolver from jose).
const svid = await verifyJwtSvid(token, { audience: 'rs', key: bundleKey, trustDomain: 'example.org' });
svid.spiffeId.path; // '/ns/prod/agent-7'

// Or parse an X.509-SVID (PEM or DER); it must carry exactly one URI SAN.
const x509 = parseX509Svid(pem);

// Bind the workload to a PCA holder key, then use `.holder` with mintRoot / delegate.
const h = svidToHolder(svid.spiffeId, agentPublicKeyB64u); // b64u string or 32 raw bytes
h.holder;               // use as Capability.holder
holderToSpiffeId(h);    // 'spiffe://example.org/ns/prod/agent-7'

try { parseSpiffeId('spiffe://Bad/x'); } catch (e) { (e as SpiffeError).code; } // 'invalid_trust_domain'
```

## API

- `parseSpiffeId`, `verifyJwtSvid`, `parseX509Svid`, `svidToHolder`, `holderToSpiffeId`.
- Types: `SpiffeId`, `JwtSvid`, `X509Svid`, `SpiffeHolder`, `SpiffeError` (with a stable `code`).

## Status

Experimental. `svidToHolder` records an association between a SPIFFE ID and a holder key; it does not prove that the key belongs to that workload. Establish that yourself (for example by using the key in the X.509-SVID, or checking the attested workload controls it). `parseX509Svid` extracts the SPIFFE ID from the certificate but does not validate the certificate chain against a trust bundle; do that separately. Unaudited.

## License

MIT - see LICENSE

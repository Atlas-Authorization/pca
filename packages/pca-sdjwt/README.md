# @atlasauth/pca-sdjwt

SD-JWT serialization of a Proof-Carrying Authority action proof (PCActn), so PCA proofs drop into existing JWT / SD-JWT tooling. The standard claims (`iss`, `sub`, `aud`, `iat`, `exp`, `ver`) stay in the clear; the capability claims (`action`, `plan`, `cap_chain`, `sig`, and so on) are selectively disclosable, with optional holder key binding (KB-JWT). It is a bridge, not a replacement: the PCActn's own canonical signature rides along as a disclosable `sig` claim and stays the source of truth.

## Install

```sh
npm i @atlasauth/pca-sdjwt @atlasauth/pca jose
```

## Usage

```ts
import { issuePcaSdJwt, present, verifyPcaSdJwt, importEd25519PrivateKey } from '@atlasauth/pca-sdjwt';

// Issuer: serialize a signed PCActn. `keyBinding: {}` embeds the leaf holder as the `cnf` key.
const sdjwt = await issuePcaSdJwt(pcactn, { issuerKey, keyBinding: {} });

// Holder: disclose only some claims and bind the presentation to the verifier (KB-JWT).
const presentation = await present(sdjwt, ['action', 'sig'], {
  keyBinding: {
    holderKey: importEd25519PrivateKey(agentSecretKey), // raw 32-byte PCA seed -> jose key
    audience: 'https://rs.example.com',
    nonce: 'n-123',
  },
});

// Verifier: fail-closed.
const res = await verifyPcaSdJwt(presentation, {
  issuerKey: issuerPublicKey,
  expectedAudience: 'https://rs.example.com',
  requireKeyBinding: true,
  expectedNonce: 'n-123',
  requiredDisclosures: ['action'],
});
if (res.ok) console.log(res.disclosed, res.keyBinding); // { action, sig }, { presented, verified, aud, nonce }
else console.error(res.reason);
```

`issuerKey` is a jose `KeyLike` (a Node `KeyObject` works); the default algorithm is EdDSA.

## API

- `issuePcaSdJwt(pcactn, options)`, `present(sdjwt, claimNames, options?)`, `verifyPcaSdJwt(sdjwt, options)`.
- Key helpers: `ed25519PublicJwk`, `importEd25519PrivateKey`, `importEd25519PublicKey` (bridge raw PCA Ed25519 keys to jose).
- Constants: `PCA_CAPABILITY_CLAIMS`, `SD_ALG`, `PCA_SD_JWT_TYP`, `KB_JWT_TYP`, `DEFAULT_SIGNING_ALG`.

## Status

Experimental. Verifying an SD-JWT checks the issuer's JWT signature, disclosure digests and key binding. It does not re-run the PCA verification of the embedded chain, plan and `sig`; do that with `@atlasauth/pca` on the recovered claims. The cryptography is unaudited.

What is validated:

- All eight SD-JWT and SD-JWT+KB strings printed in RFC 9901 (the main example with its Key Binding JWT, the structured and recursive examples, and the SD-JWT VC and W3C VC examples) verify under the RFC's published issuer key. The Processed SD-JWT Payload for the main presentation matches the RFC exactly.
- Verification follows RFC 9901 section 7.1: nested `_sd` digests and array-element disclosures are resolved recursively, decoy digests are ignored, and a presentation is rejected for a reused digest, an unreferenced disclosure, a reserved or colliding claim name, or a security-critical claim (`iss`, `aud`, `exp`, `nbf`, `cnf`, `status`) behind a disclosure. A missing `_sd_alg` is treated as `sha-256`.
- Key binding rejects a wrong `nonce`, wrong audience, a stale `iat` (with `kbMaxAgeSec`), a missing KB-JWT when required, and an `sd_hash` that does not cover the presented disclosures.
- Interoperates in both directions with `@sd-jwt/core` 0.22.0 and `@sd-jwt/crypto-nodejs` 0.19.0: credentials they issue (nested objects, arrays, KB-JWT) verify here, and presentations produced here verify there, including rejection of a wrong nonce.

`present()` accepts claim names; selecting a claim discloses it in full, including any disclosures nested inside it.

Not validated: only SHA-256 is supported for `_sd_alg`; the JWS JSON serialization (RFC 9901 section 8) is not implemented; the specification's SD-JWT VC type metadata and issuer-key discovery are out of scope.

## License

MIT - see LICENSE

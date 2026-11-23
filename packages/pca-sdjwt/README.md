# @atlasauth/pca-sdjwt

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
- `verifyRecovered(result, coreOptions)`: re-verifies a successful `verifyPcaSdJwt` result with PCA Core (chain, plan inclusion, leaf signature, audience, validity) by rebuilding the exact PCActn from the recovered claims. It denies when a required claim (`action`, `cap_chain`, `plan`, `sig`, `grant_ref`, `counter`) was withheld, when `iss`/`sub` disagree with the chain, or when the exact-millisecond `iat_ms`/`exp_ms` claims are missing or inconsistent. Pass your own stored `grant` and your `audience`.
- Key helpers: `ed25519PublicJwk`, `importEd25519PrivateKey`, `importEd25519PublicKey` (bridge raw PCA Ed25519 keys to jose).
- Constants: `PCA_CAPABILITY_CLAIMS`, `SD_ALG`, `PCA_SD_JWT_TYP`, `KB_JWT_TYP`, `DEFAULT_SIGNING_ALG`.

## Failure modes

| Missing or wrong | Result |
|---|---|
| Empty, non-string or malformed serialization, empty disclosure segment, non-canonical token spelling | `{ ok: false, reason }` |
| Wrong issuer key, disallowed algorithm, expired token, audience mismatch | `{ ok: false }` |
| Unsupported `_sd_alg`, duplicate disclosure, disclosure not referenced by a digest | `{ ok: false }` |
| Security-critical claim (`iss`, `aud`, `exp`, `nbf`, `cnf`, `status`) behind a disclosure | `{ ok: false }` |
| `requiredDisclosures` entry not presented | `required disclosure '<name>' was not presented` |
| Key binding required (`requireKeyBinding` or `keyBindingKey`) and no KB-JWT | `key binding required but no KB-JWT was presented` |
| KB-JWT with no `cnf` key, wrong `cnf` key, wrong audience, wrong nonce, stale or future `iat`, `sd_hash` not covering the presentation | `{ ok: false }` with the exact reason |
| `verifyRecovered`: any of `action`, `cap_chain`, `plan`, `sig`, `grant_ref`, `counter` withheld | `{ allow: false, reason: "pca-sdjwt: required claim '<name>' was not disclosed" }` |
| `verifyRecovered`: `iat_ms` or `exp_ms` missing or inconsistent, `iss` or `sub` disagreeing with the chain | `{ allow: false }` |
| `verifyRecovered`: no audience, wrong stored grant, tampered action | `{ allow: false }` from PCA Core |

## Limits

- Only `sha-256` for `_sd_alg`, EdDSA by default, and the compact serialization (no JWS JSON serialization).
- `verifyPcaSdJwt` proves the JWT layer only; run `verifyRecovered` with your own stored grant before acting.
- Replay of a KB-JWT is yours to prevent: give each verification a fresh `expectedNonce`.
- SD-JWT VC type metadata and issuer-key discovery are out of scope.

## Status

Production. Pinned to RFC 9901 (SD-JWT and SD-JWT+KB). Verifying an SD-JWT checks the issuer's JWT signature, disclosure digests and key binding. On its own it does not re-run the PCA verification of the embedded chain, plan and `sig`; call `verifyRecovered` for that.

What is validated:

- All eight SD-JWT and SD-JWT+KB strings printed in RFC 9901 (the main example with its Key Binding JWT, the structured and recursive examples, and the SD-JWT VC and W3C VC examples) verify under the RFC's published issuer key. The Processed SD-JWT Payload for the main presentation matches the RFC exactly.
- Verification follows RFC 9901 section 7.1: nested `_sd` digests and array-element disclosures are resolved recursively, decoy digests are ignored, and a presentation is rejected for a reused digest, an unreferenced disclosure, a reserved or colliding claim name, or a security-critical claim (`iss`, `aud`, `exp`, `nbf`, `cnf`, `status`) behind a disclosure. A missing `_sd_alg` is treated as `sha-256`.
- Key binding rejects a wrong `nonce`, wrong audience, a stale `iat` (with `kbMaxAgeSec`), a missing KB-JWT when required, and an `sd_hash` that does not cover the presented disclosures.
- Interoperates in both directions with `@sd-jwt/core` 0.22.0 and `@sd-jwt/crypto-nodejs` 0.19.0: credentials they issue (nested objects, arrays, KB-JWT) verify here, and presentations produced here verify there, including rejection of a wrong nonce.

`present()` accepts claim names; selecting a claim discloses it in full, including any disclosures nested inside it.

Not validated: only SHA-256 is supported for `_sd_alg`; the JWS JSON serialization (RFC 9901 section 8) is not implemented; the specification's SD-JWT VC type metadata and issuer-key discovery are out of scope.

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the issuer JWT, the KB-JWT and every Disclosure segment: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

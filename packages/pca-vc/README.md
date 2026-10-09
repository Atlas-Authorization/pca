# @atlasauth/pca-vc

Emit the PCA **agent passport** in the converging verifiable-identity formats: a **W3C Verifiable
Credential 2.0** (as an **SD-JWT VC**) bound to a **did:key**, and request signatures per **RFC 9421 HTTP
Message Signatures** using the **Web Bot Auth** `Signature-Agent` pattern.

## Honest framing

PCA's `AgentPassport` (from `@atlasauth/pca`) is the **source of truth** — a content-addressed,
attestation-rooted statement of *which* agent is acting (model / weights / system-prompt / tool-manifest /
operator / hardware root). This package is a **bridge, not a replacement**: it re-expresses that same
passport in the shapes the ecosystem (Microsoft **Entra Agent ID**, Google / **AP2** agent payments, the
**ATEP** transaction envelope, Cloudflare **Web Bot Auth**) is converging on, so a PCA agent can present a
credential those systems already understand. It mints no new authority and never supersedes the signed
PCActn proof. **Compose, don't replace.**

## Standards

- **W3C Verifiable Credentials Data Model 2.0** — `@context: https://www.w3.org/ns/credentials/v2`, subtype
  `AgentPassportCredential`, secured as an EdDSA JWT.
- **SD-JWT VC** — draft-ietf-oauth-sd-jwt-vc over draft-ietf-oauth-selective-disclosure-jwt. Each passport
  *digest* (weights / system-prompt / tool-manifest / runtime measurement) is a **selectively-disclosable**
  claim: its salted hash lives in `credentialSubject._sd`, the disclosure travels after the `~`, and the
  holder chooses which to release. The stable fields (model id, operator, `hardware_rooted`, passport id)
  stay in the clear.
- **did:key** — w3c-ccg, Ed25519 (`0xed01` multicodec + base58btc, `z…`).
- **RFC 9421 HTTP Message Signatures** + **Web Bot Auth** (draft-ietf-webbotauth-httpsig-protocol) — sign a
  covered-component set (`@method`, `@target-uri`, headers) with EdDSA and carry the `Signature-Agent`
  header pointing at the signer's key directory (`tag="web-bot-auth"`).

## Install

```sh
npm i @atlasauth/pca-vc @atlasauth/pca
```

## Usage

```ts
import {
  didKeyFromEd25519, passportToVC, verifyPassportVC,
  signRequestMessage, verifyRequestSignature,
} from '@atlasauth/pca-vc';
import { issuePassport } from '@atlasauth/pca';
import { generateKeyPairSync } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
// raw 32-byte Ed25519 public key = last 32 bytes of the SPKI DER encoding
const rawPub = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
const issuerDid = didKeyFromEd25519(rawPub);

// Passport → VC (SD-JWT), then verify + reconstruct.
const vc = await passportToVC(issuePassport({ model_id: 'm', operator: 'op', hardware_rooted: true, issued_at: 1 }), {
  issuerKey: privateKey, issuerDid, subjectDid: issuerDid, ttlSec: 3600,
});
const { passport, issuerDid: iss, subjectDid } = await verifyPassportVC(vc, publicKey);

// RFC 9421 + Web Bot Auth: sign a request, then verify it.
const signed = signRequestMessage({
  method: 'POST', url: 'https://api.acme.com/v1/orders',
  headers: { 'content-type': 'application/json' },
  key: privateKey, keyid: issuerDid, signatureAgent: 'https://bots.acme.com',
});
// → Signature-Input, Signature, Signature-Agent header values
const ok = verifyRequestSignature({ method: 'POST', url: 'https://api.acme.com/v1/orders',
  headers: { 'content-type': 'application/json' }, ...signed }, publicKey);
```

## API

- `didKeyFromEd25519(publicKey: Uint8Array): string` / `ed25519FromDidKey(did): Uint8Array`
- `passportToVC(passport, { issuerKey, issuerDid, subjectDid, ttlSec? }): Promise<string>`
- `verifyPassportVC(vc, issuerVerifyKey): Promise<{ passport, issuerDid, subjectDid }>`
- `signRequestMessage({ method, url, headers, key, keyid, created?, signatureAgent? }): { signatureInput, signature, signatureAgent? }`
- `verifyRequestSignature({ method, url, headers, signatureInput, signature, signatureAgent? }, verifyKey): boolean`

## Status

Experimental. The SD-JWT VC and Web Bot Auth specifications are drafts and may change, and the cryptography in the PCA stack has not been independently audited.

What is validated:

- `did:key`: the base58btc codec reproduces the multiformats multibase test vectors (including leading zero bytes), decodes the Ed25519 `did:key` values printed in the did:key specification, rejects non-Ed25519 multicodecs and malformed identifiers, and agrees in both directions with the Python `multiformats` 0.3.1 and `base58` 2.1.1 libraries on 43 keys.
- SD-JWT VC: the credential verifies with the independent `@sd-jwt/core` 0.22.0 library (nested `credentialSubject._sd` disclosures resolve, a withheld disclosure stays hidden). `_sd_alg` is emitted at the top level of the payload, as RFC 9901 requires (credentials from releases that put it inside `credentialSubject` are rejected). `verifyPassportVC` is fail-closed: it pins EdDSA (a raw public key can no longer be used as an HMAC secret), checks `typ`, the VC 2.0 `@context` and credential type, `_sd_alg`, duplicate or unexpected disclosures, expiry and tampering.
- RFC 9421 signatures interoperate in both directions with the Python `http-message-signatures` 2.0.1 library (Ed25519), including rejection of a tampered method, URL, header or signature. `verifyRequestSignature` can require covered components and a maximum signature age.

Not validated: the RFC 9421 appendix test vectors (which use derived components such as `@path` that this package does not sign), the Web Bot Auth key-directory flow, and conformance of the emitted VC against a W3C JSON-LD validator. `verifyPassportVC` does not check that the `iss` DID matches the verification key you pass; do that in your key-resolution step.

## License

MIT - see LICENSE

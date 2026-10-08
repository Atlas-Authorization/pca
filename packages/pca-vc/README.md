# @atlasauth/pca-vc

Emit the PCA **agent passport** in the converging verifiable-identity formats: a **W3C Verifiable
Credential 2.0** (as an **SD-JWT VC**) bound to a **did:key**, and request signatures per **RFC 9421 HTTP
Message Signatures** using the **Web Bot Auth** `Signature-Agent` pattern.

## Honest framing

PCA's `AgentPassport` (`@atlasauth/pca`, `passport.ts`) is the **source of truth** — a content-addressed,
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

## Usage

```ts
import {
  didKeyFromEd25519, passportToVC, verifyPassportVC,
  signRequestMessage, verifyRequestSignature,
} from '@atlasauth/pca-vc';
import { issuePassport } from '@atlasauth/pca';
import { generateKeyPairSync } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const issuerDid = didKeyFromEd25519(/* raw 32-byte Ed25519 public key */ rawPub);

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

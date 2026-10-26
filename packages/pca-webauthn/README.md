# @atlasauth/pca-webauthn

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Phishing-resistant human co-sign for Proof-Carrying Authority step-up, using WebAuthn / FIDO2 passkeys.
The WebAuthn challenge is set equal to the PCA step-up challenge, `sha256(thresholdMessage(pcactn))`
(the FROST `action_digest`), so a valid assertion is cryptographic evidence that a human holding a
hardware-bound credential approved this exact action and no other. A look-alike origin fails the origin and
`rpIdHash` checks; a replayed old assertion fails the challenge check.

This package is the server-side verifier. It runs in Node (no WebAuthn library or CBOR dependency): ES256
(P-256) and EdDSA (Ed25519) via `@noble/curves`, SHA-256 via `@noble/hashes`, and a small built-in COSE key
reader. Every entry point fails closed and does not throw on hostile input.

## Install

```sh
npm i @atlasauth/pca-webauthn @atlasauth/pca
```

## Usage

```ts
import {
  buildStepUpChallenge,
  stepUpChallengeB64u,
  verifyAssertion,
  coseKeyToJwk,
} from '@atlasauth/pca-webauthn';

// 1) A PCA action needs step-up. Derive the challenge from it (a PCActn, its body, or the digest).
const challenge = buildStepUpChallenge(pcactn);          // 32 bytes
const challengeB64u = stepUpChallengeB64u(pcactn);       // base64url, send to the browser

// 2) In the browser, ask the passkey to sign that exact challenge:
//    navigator.credentials.get({ publicKey: { challenge, rpId: 'example.com', userVerification: 'required', ... } })
//    and post back response.authenticatorData, response.clientDataJSON, response.signature.

// 3) On the server, verify the assertion against the credential key registered earlier.
const res = verifyAssertion(
  {
    authenticatorData,   // Uint8Array (already base64url-decoded)
    clientDataJSON,      // Uint8Array
    signature,           // Uint8Array
    publicKey: credentialPublicKey, // a JWK, or a raw COSE_Key as Uint8Array (see coseKeyToJwk)
  },
  {
    expectedChallenge: challenge,
    rpId: 'example.com',
    origins: ['https://example.com'],
    requireUV: true,
  },
);
if (res.ok) {
  // human approved this action: res.alg, res.signCount, res.flags
} else {
  console.error(res.reason);
}
```

## API

- `buildStepUpChallenge(pcactnOrDigest): Uint8Array`, `stepUpChallengeB64u(pcactnOrDigest): string`
- `verifyAssertion(assertion, { expectedChallenge, rpId, origins, requireUV, requireLowS?, storedSignCount?, onSignCountRegression?, rejectCrossOrigin? }): { ok: true, alg, signCount, flags } | { ok: false, reason }`
- `coseKeyToJwk(coseKey: Uint8Array)` - decode a stored COSE_Key into an ES256 or EdDSA JWK.
- `parseAuthenticatorData(bytes)` - parse the fixed 37-byte authenticator data header.

## Clone detection (signature counter)

Pass the counter you stored for the credential and the verifier enforces the W3C rule after the signature checks out: if either the reported or the stored counter is non-zero, the reported one must be strictly greater, otherwise the assertion is refused and your hook runs. Both zero means the authenticator has no counter (most synced passkeys) and passes. Store the returned `signCount` yourself after each accepted assertion.

```ts
const res = verifyAssertion(assertion, {
  expectedChallenge: challenge,
  rpId: 'example.com',
  origins: ['https://example.com'],
  requireUV: true,
  storedSignCount: credential.signCount, // from your database; omit to skip the check
  onSignCountRegression: ({ storedSignCount, reportedSignCount }) => flagCredential(credential.id),
});
```

The hook runs only for an assertion whose signature verified, so forged input cannot trigger it. Optional `rejectCrossOrigin: true` also refuses ceremonies that ran in a cross-origin iframe.

## Failure modes

`verifyAssertion` returns `{ ok: false, reason }` and never throws. Every row below is a test asserting the exact reason text.

| Input | `reason` |
| --- | --- |
| authenticatorData, clientDataJSON or signature not bytes | `authenticatorData is not bytes` (and the clientDataJSON / signature equivalents) |
| authenticatorData over 4096, clientDataJSON over 8192, or signature over 1024 bytes | `... is too large` |
| empty `rpId` or empty `origins` | `rpId is required`, `origins allowlist is empty` |
| clientDataJSON not UTF-8, not JSON, or not an object | `clientDataJSON is not valid UTF-8`, `... is not valid JSON`, `... is not a JSON object` |
| `type` is not `webauthn.get` | `clientData.type is not "webauthn.get" (<got>)` |
| `challenge` missing, padded, wrong alphabet or non-canonical | `clientData.challenge is missing or not canonical base64url` |
| `expectedChallenge` string not decodable | `expectedChallenge is not decodable` |
| `challenge` differs from the step-up challenge | `clientData.challenge does not match the step-up challenge` |
| `crossOrigin: true` with `rejectCrossOrigin` | `clientData.crossOrigin is true` |
| origin missing, or not exactly in the allow-list (look-alike host, other port) | `clientData.origin is missing`, `clientData.origin "<o>" is not in the allowlist` |
| authenticatorData under 37 bytes | `authenticatorData is too short (< 37 bytes)` |
| `rpIdHash` differs from `sha256(rpId)` | `rpIdHash does not match sha256(rpId)` |
| User Present unset; User Verified unset when `requireUV` | `User Present (UP) flag is not set`, `User Verified (UV) flag is required but not set` |
| credential key unsupported or malformed (not ES256 / Ed25519) | `public key could not be resolved: ...` |
| signature does not verify (tampered, over other data, wrong key, wrong algorithm for the key) | `assertion signature did not verify` |
| `storedSignCount` not a uint32 | `storedSignCount is not a uint32` |
| counter did not increase | `signCount did not increase (possible cloned authenticator)` |
| any unexpected error, including a throwing hook | `verification error (fail closed): ...` |

## Status

Maturity is experimental. The assertion rules follow W3C WebAuthn (Level 2, section 7.2) for authentication ceremonies only. Credential registration and attestation are out of scope: you supply the registered public key, and nothing here checks an attestation statement. Only ES256 and EdDSA credentials are supported. The challenge must be canonical base64url. EdDSA is verified strictly (RFC 8032, not ZIP-215; small-order and mixed-order keys are refused). ES256 accepts high-S signatures by default because many authenticators produce them; set `requireLowS: true` to refuse them when every enrolled authenticator signs low-S. The cryptography has not been independently audited and a mutation-testing run has not been made for this package.

What is validated:

- Agreement with an established library: 26 assertions (ES256 and EdDSA; valid, wrong challenge, origin, rpId, ceremony type, missing UP or UV, flipped signature bit, and three counter cases) were judged by `@simplewebauthn/server` 14.0.3, and this verifier reaches the same verdict on every one.
- Each failure row above, and the counter rule, with exact reason text.
- The W3C specification publishes no assertion test vectors with keys, so there are no official vectors to reproduce; the comparison above is the substitute.

## License

MIT - see LICENSE

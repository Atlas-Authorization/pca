# @atlasauth/pca-webauthn

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
- `verifyAssertion(assertion, { expectedChallenge, rpId, origins, requireUV }): { ok: true, alg, signCount, flags } | { ok: false, reason }`
- `coseKeyToJwk(coseKey: Uint8Array)` - decode a stored COSE_Key into an ES256 or EdDSA JWK.
- `parseAuthenticatorData(bytes)` - parse the fixed 37-byte authenticator data header.

## Status

`verifyAssertion` checks the ceremony type, challenge, origin, `rpIdHash`, the User Present flag (and User
Verified when `requireUV`), and the signature. It does not track the signature counter: if you want clone
detection, compare the returned `signCount` against your stored value. Credential registration
(attestation) is out of scope; you supply the registered public key. Only ES256 and EdDSA credentials are
supported. The cryptography has not been independently audited.

## License

MIT - see LICENSE

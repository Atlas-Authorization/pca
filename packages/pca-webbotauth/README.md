# @atlasauth/pca-webbotauth

Web Bot Auth for Proof-Carrying Authority. It signs outbound agent HTTP requests with RFC 9421 HTTP Message
Signatures in the `web-bot-auth` profile (Ed25519, `Signature-Agent`, `tag="web-bot-auth"`), so a PCA agent
can pass automated-traffic bot verification, and can optionally carry its per-action PCActn proof in the
same request. The proof travels in the `PCA-Action` header, which is a covered signature component, so it
cannot be swapped without breaking the signature.

The signing key is the same raw Ed25519 `KeyPair` (`generateKeyPair()` from `@atlasauth/pca`) that signs a
PCActn. Signing and verification use `node:crypto`. Verification fails closed: any parse error, stale
window, wrong tag, unknown key or bad signature returns `{ valid: false, reason }` and never throws.

## Install

```sh
npm i @atlasauth/pca-webbotauth @atlasauth/pca
```

## Usage

```ts
import { agent, generateKeyPair } from '@atlasauth/pca';
import {
  jwkThumbprint,
  buildKeyDirectory,
  signRequestWithProof,
  verifySignedRequestWithProof,
} from '@atlasauth/pca-webbotauth';

const AUD = 'https://api.acme.com';
const principal = generateKeyPair();
const a = agent({ principal, goal: 'orders', permissions: { orders: ['create'] }, aud: AUD });
const { pcactn } = a.act('orders.create', 'order:1', { sku: 'x' }, { aud: AUD });

// The agent's Ed25519 identity for HTTP signing, published in a key directory.
const key = generateKeyPair();
const keyid = jwkThumbprint(key.publicKey);
const directory = buildKeyDirectory([{ publicKey: key.publicKey, keyid }]);
// Serve it at /.well-known/http-message-signatures-directory (see directoryHandler below).

// Agent side: sign the request and attach the proof.
const url = 'https://api.acme.com/v1/orders';
const signed = signRequestWithProof({
  method: 'POST',
  url,
  headers: { 'content-type': 'application/json' },
  key,
  keyid,
  agentDirectoryUrl: 'https://bots.acme.com',
  coverHeaders: ['content-type'],
  pcactn,
});
// signed.headers holds only the headers the signer added (Signature-Input, Signature,
// Signature-Agent, PCA-Action); merge them with your own:
const headers = { 'content-type': 'application/json', ...signed.headers };
// fetch(url, { method: 'POST', headers, body })

// Verifier side: check the signature and extract the signature-bound PCActn.
const res = await verifySignedRequestWithProof(
  { method: 'POST', url, headers },
  { jwks: directory },
);
if (res.valid) {
  // res.pcactn is the proof; now verify it with the PCA verifier from @atlasauth/pca.
}
```

`signRequest` / `verifySignedRequest` are the same without the PCActn binding.

## API

- `signRequest`, `signRequestWithProof` - return `{ signatureInput, signature, signatureAgent?, covered, headers }`;
  merge `headers` into the outbound request's own headers. Signatures default to a 300 second lifetime (`expiresInSec`).
  `agentDirectoryKey` emits the dictionary form of `Signature-Agent` (`<key>="<url>"`, covered as
  `"signature-agent";key="<key>"`); without it the legacy bare-string form is used. `components` replaces the default
  `@authority @method @path`.
- `verifySignedRequest`, `verifySignedRequestWithProof` - options: `resolveKey` or `jwks`, `now`,
  `clockSkewSec`, `maxAgeSec`, `requiredTag`, `requireExpires`, `label`, and `expectedPCActn` (with proof).
- `buildKeyDirectory`, `resolveFromDirectory`, `jwkThumbprint`, `directoryHandler(keys)` - the key
  directory (JWKS) and a framework-agnostic handler for `WELL_KNOWN_DIRECTORY_PATH`.
- `proofHeaders`, `decodeProofHeader` - encode and decode the `PCA-Action` header.

## Status

A valid signature proves that the holder of the `keyid` key signed this request's method, authority, path
and covered headers inside the freshness window. It does not by itself prove the action is authorized; that
is the job of the PCActn verifier in `@atlasauth/pca`. The Web Bot Auth and directory specifications are
IETF drafts and may change. The cryptography has not been independently audited.

What is validated:

- RFC 9421 Appendix B: the Ed25519 example (B.2.6) verifies, the RFC 7638 thumbprint of the Appendix B.1.4 key matches
  the keyid used in the Web Bot Auth draft, and the RSA-PSS, ECDSA and HMAC examples are never accepted.
- Web Bot Auth architecture draft-05 Appendix A: the Ed25519 vectors with no `Signature-Agent` and with the legacy
  string `Signature-Agent` are reproduced byte for byte by `signRequest` and verified. The draft's dictionary-form
  vector (A.2.2) carries a signature made over the unquoted member value, which contradicts both RFC 9421 section 2.1.2
  and the signature base printed beside it; this package and Cloudflare's reference library both follow RFC 9421, so
  they do not accept that published signature, and requests with the dictionary form signed here verify there.
- Interoperability with Cloudflare's `web-bot-auth` 0.2.0 in both directions, including a `Signature-Agent` member with
  parameters (`type=directory`).
- Verification is fail-closed and each rejection test asserts its reason: changed method, authority, path or covered
  header, flipped signature, other key, expired or future `created`/`expires`, wrong tag, unsupported algorithm,
  missing `@authority`, unsupported derived components or component parameters, and a missing or altered
  `Signature-Agent` member.

Not validated: only Ed25519 is supported (RSA-PSS, ECDSA and HMAC signatures are refused); component parameters other
than `key` on string members (`sf`, `bs`, `req`, `name`) and the response-side components are refused; the signed
directory response and `Signature-Agent` card formats of the drafts are not implemented; there are no vectors for the
directory handler beyond its own tests.

## License

MIT - see LICENSE

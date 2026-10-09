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
- `verifySignedRequest`, `verifySignedRequestWithProof` - options: `resolveKey` or `jwks`, `now`,
  `clockSkewSec`, `maxAgeSec`, `requiredTag`, `label`, and `expectedPCActn` (with proof).
- `buildKeyDirectory`, `resolveFromDirectory`, `jwkThumbprint`, `directoryHandler(keys)` - the key
  directory (JWKS) and a framework-agnostic handler for `WELL_KNOWN_DIRECTORY_PATH`.
- `proofHeaders`, `decodeProofHeader` - encode and decode the `PCA-Action` header.

## Status

A valid signature proves that the holder of the `keyid` key signed this request's method, authority, path
and covered headers inside the freshness window. It does not by itself prove the action is authorized; that
is the job of the PCActn verifier in `@atlasauth/pca`. The Web Bot Auth and directory specifications are
IETF drafts and may change. The cryptography has not been independently audited.

## License

MIT - see LICENSE

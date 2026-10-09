# @atlasauth/pca-gnap

A [GNAP (RFC 9635)](https://www.rfc-editor.org/rfc/rfc9635) bridge for Proof-Carrying Authority (PCA), defining an "agent-GNAP" profile. A GNAP grant request is turned into an attenuated, key-bound PCA capability; a GNAP `access` rights array becomes the capability's policy predicates; multi-hop delegation can only narrow authority; GNAP continuation maps to a PCA step-up; and key-bound requests use detached-JWS (`jwsd`) proofs.

## Install

```sh
npm i @atlasauth/pca-gnap
```

Depends on `@atlasauth/pca` and `jose`.

## Usage

```ts
import { generateKeyPair, b64u } from '@atlasauth/pca';
import {
  grantRequestToCapability, authorizeGnapAction, gnapActionResource,
  capabilityToGrantResponse, verifyGnapToken, signGnapRequest, verifyGnapRequest,
} from '@atlasauth/pca-gnap';

const principal = generateKeyPair();
const agent = generateKeyPair();

// A GNAP grant request, bound to the agent's Ed25519 client key.
const req = {
  access_token: { access: [{ type: 'repo', actions: ['read', 'write'], locations: ['main'] }] },
  client: { key: { proof: 'jwsd', jwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(agent.publicKey) } } },
};

// Authorization server: mint a root capability (pass `parent` to delegate a narrower hop instead).
const { chain } = grantRequestToCapability(req, {
  issuerSecret: principal.secretKey,
  issuerPublic: b64u(principal.publicKey),
});

// Effective authority = root envelope AND every hop's recorded rights. Fails closed.
const res = gnapActionResource('repo', 'main');
authorizeGnapAction(chain, { verb: 'read', resource: res });   // { allowed: true }
authorizeGnapAction(chain, { verb: 'delete', resource: res }); // { allowed: false, reason }

// Hand the chain back as a GNAP access token, and verify it on the way in.
const response = capabilityToGrantResponse(chain, { expiresIn: 3600 });
verifyGnapToken(response.access_token!.value, { expectedRootIssuer: b64u(principal.publicKey) }).ok; // true

// Key-bound request: detached-JWS proof over the body, verified against the holder key.
const { detachedJws, holder } = await signGnapRequest({
  body: req, key: agent, htm: 'POST', uri: 'https://as.example/gnap',
});
await verifyGnapRequest({ detachedJws, body: req, holder, htm: 'POST', uri: 'https://as.example/gnap' }); // { ok: true, ... }
```

## API

- Grants: `grantRequestToCapability`, `capabilityToGrantResponse`, `encodeBoundToken`, `verifyGnapToken`, `grantedAccessOf`.
- Access model: `accessToPredicates`, `accessContains`, `accessWithin`, `clampAccess`, `gnapActionResource`, `authorizeGnapAction`.
- Key-bound requests: `signGnapRequest`, `verifyGnapRequest` (GNAP `jwsd`, EdDSA; optional `ath` token binding).
- Step-up: `gnapRequestRequiresStepUp`, `beginGnapContinuation`, `gnapStepUpShare`, `completeGnapContinuation`.
- `AGENT_GNAP_PROFILE`: the machine-readable profile description.

Delegated hops are clamped to the issuer's own authority at issue time (`clampToIssuer`, default on) and are denied at action time if they exceed it.

## Status

Experimental. The profile is defined by this package, not by an IETF document, and it implements only the GNAP subset it needs: a single access token per request, `jwsd` as the verified proof method, and no `httpsig` or `mtls` verification. The cryptography is unaudited.

## License

MIT - see LICENSE

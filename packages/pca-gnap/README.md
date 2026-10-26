# @atlasauth/pca-gnap

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

Experimental. The profile is defined by this package on top of RFC 9635; it is not an IETF profile. The cryptography is unaudited.

## Supported subset (the contract)

| GNAP feature | Support |
|---|---|
| Single access token request (`access_token.access`) | supported |
| Multiple access tokens (array), `subject`, `user`, `access_token.flags` semantics | not supported: a request without `access_token.access` is refused |
| Client key proof `jwsd` (detached JWS, EdDSA, `typ` `gnap-binding-jwsd`) | supported, verified |
| Client key proof `httpsig`, `mtls`, `jwsd-vc`, any other or missing method | not supported: refused at grant time |
| Client key as a reference string | not supported: refused |
| Client key type | OKP / Ed25519 JWK only |
| Interaction and continuation | maps to a PCA step-up (see API) |

Nothing outside this table is silently ignored where it would widen authority: only the rights in `access_token.access` can be granted, and delegated hops can only narrow them.

## Failure modes

| Missing or invalid | Result |
|---|---|
| `client.key.proof` not `jwsd` (string or `{ method }`), even with a holder override | `GnapError`: unsupported client key proof method |
| no OKP/Ed25519 `jwk` and no holder override, or non-canonical key encoding | `GnapError`: cannot resolve holder |
| `access_token.access` missing, not an array, or a malformed item | `GnapError` |
| `jwsd` bad signature, tampered body, wrong holder, wrong `typ` or `alg`, stale `created`, wrong `htm`/`uri`, wrong `ath` | `verifyGnapRequest` returns `{ ok: false, reason }` |
| non-canonical detached-JWS spelling | `{ ok: false, reason }` before the signature check |
| access token malformed, broken chain, wrong root issuer | `verifyGnapToken` returns `{ ok: false }` |
| action outside the root envelope or any hop's rights | `authorizeGnapAction` returns `{ allowed: false, reason }` |

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the detached JWS (protected and signature segments): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

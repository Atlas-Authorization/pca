# @atlasauth/pca-idjag

ID-JAG / OAuth Cross-App Access bridge for Proof-Carrying Authority (PCA). An ID-JAG (Identity Assertion Authorization Grant, `draft-ietf-oauth-identity-assertion-authz-grant`) is a JWT an enterprise identity provider mints so an agent app can act on a named user's behalf against one other app: `sub` is the human, `act` is the agent, `aud` is the single target app, and `scope` is the delegated authority. This package verifies such a grant, projects it onto a PCA principal and a signed root capability, and builds the two OAuth requests used in the flow (RFC 8693 token exchange to obtain a grant, RFC 7523 jwt-bearer to redeem one).

## Install

```sh
npm i @atlasauth/pca-idjag @atlasauth/pca @atlasauth/pca-oidc
```

## Usage

```ts
import { generateKeyPair, encodeKey, verifyChain } from '@atlasauth/pca';
import { verifyIdJag, idJagToCapability, tokenExchangeRequest, jwtBearerAssertion } from '@atlasauth/pca-idjag';

// 1. Verify the ID-JAG. Fails closed (throws IdJagVerificationError) on any signature, issuer,
//    audience, expiry, nonce, actor or scope problem.
const grant = await verifyIdJag(idJagJwt, {
  issuer: 'https://idp.example.com',
  audience: 'https://resource.example.com',   // must be the single audience of the grant
  jwksUri: 'https://idp.example.com/.well-known/jwks.json', // or `discover: true`, or an injected `key`
  requiredScopes: ['calendar.read'],
});
grant.sub;     // the human
grant.agent;   // the acting app (act.sub)
grant.scopes;  // ['calendar.read', 'mail.send']

// 2. Project it onto a signed PCA root capability: authority = scopes, holder = the agent's PCA key.
const human = generateKeyPair();   // the human root key that signs the capability
const agentKey = generateKeyPair();
const { capability } = idJagToCapability(grant, {
  principalSecret: human.secretKey,
  principalPublic: encodeKey(human.publicKey),
  holder: encodeKey(agentKey.publicKey),
});
verifyChain([capability], encodeKey(human.publicKey)); // { ok: true }

// 3. The OAuth legs of the flow (plain request descriptions; you send them).
const obtain = tokenExchangeRequest({
  tokenEndpoint: 'https://idp.example.com/oauth2/token',
  subjectToken: userIdToken,
  audience: 'https://resource.example.com',
  scope: ['calendar.read'],
  clientId: 'agent-app-7',
});
const redeem = jwtBearerAssertion({
  tokenEndpoint: 'https://resource.example.com/token',
  assertion: idJagJwt,
  scope: 'calendar.read',
}).request;   // { url, method, headers, params, body }
```

## API

- `verifyIdJag(jwt, options)` returns an `IdJagGrant`; throws `IdJagVerificationError` (with a `code`).
- `idJagToPcaPrincipal(grant, opts?)`, `idJagToCapability(grant, opts)` map a grant to a PCA principal / signed root capability.
- `readIdJagAuthority(cap)`, `readIdJagProvenance(cap)`, `isIdJagAuthorityCaveat`, `isIdJagProvenanceCaveat` read the caveats back.
- `tokenExchangeRequest(opts)`, `jwtBearerAssertion(opts)` build the RFC 8693 / RFC 7523 requests; the `GRANT_TYPE_*`, `TOKEN_TYPE_*` and `CLIENT_ASSERTION_TYPE_JWT_BEARER` URN constants are exported.

## Status

The ID-JAG specification is an IETF draft and may change. JWT checks are delegated to `@atlasauth/pca-oidc`; only asymmetric algorithms are accepted by default. This package does not send any network request except the optional JWKS / discovery fetch. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE

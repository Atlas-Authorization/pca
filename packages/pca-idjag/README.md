# @atlasauth/pca-idjag

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

Pinned to `draft-ietf-oauth-identity-assertion-authz-grant-04` (21 May 2026). The draft is a moving IETF document; this package follows revision 04 and will be re-pinned when a new revision changes the grant. JWT checks are delegated to `@atlasauth/pca-oidc`; only asymmetric algorithms are accepted by default. This package does not send any network request except the optional JWKS / discovery fetch. PCA cryptography has not been independently audited.

This package is a profile of the draft's grant: it additionally REQUIRES the `act` (agent) and `scope` claims, which the draft marks optional, and accepts exactly one `aud`. Default verification does not check the header `typ`, `client_id` or `jti`; turn on `strictDraft` for the draft's section 3.1 shape.

### Strict mode

```ts
const grant = await verifyIdJag(jwt, {
  issuer, audience, key,
  strictDraft: true,                 // typ "oauth-id-jag+jwt", client_id and jti present
  clientId: 'resource-app-client',   // optional: client_id must equal this
  consumeJti: async (jti, exp) => store.insertIfAbsent(jti, exp), // REQUIRED in strict mode; false = already used
});
```

## Failure modes

`verifyIdJag` throws `IdJagVerificationError` with a `code` in every row; it never returns a partial grant.

| Missing or invalid | Result (`code`) |
|---|---|
| empty token, missing options, missing issuer or audience | `invalid_token` / `config` |
| `strictDraft` without `consumeJti` | `config` |
| bad signature, wrong issuer, expired, wrong nonce, disallowed algorithm | the underlying verification code (unchanged from `@atlasauth/pca-oidc`) |
| `aud` is not exactly the one expected audience | `audience` |
| `act` missing or without a string `sub` | `actor` |
| `scope`/`scopes` missing, or a required scope absent | `scope` |
| strict: wrong or missing `typ`, missing `client_id` or `jti`, `client_id` mismatch | `grant` |
| strict: `jti` already used, or the `consumeJti` store throws or returns anything but `true` | `grant` |

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the ID-JAG (via `verifyIdToken`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

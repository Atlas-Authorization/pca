# @atlasauth/pca-idjag

> Maturity: **production** (supported for production use), pinned to draft-ietf-oauth-identity-assertion-authz-grant-04. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
//    audience, expiry, nonce, actor, scope, typ, client_id or jti problem. Strict draft mode is the default.
const grant = await verifyIdJag(idJagJwt, {
  issuer: 'https://idp.example.com',
  audience: 'https://resource.example.com',   // must be the single audience of the grant
  jwksUri: 'https://idp.example.com/.well-known/jwks.json', // or `discover: true`, or an injected `key`
  requiredScopes: ['calendar.read'],
  clientId: 'resource-app-client',  // the client authenticated at the token endpoint
  consumeJti: async (jti, exp) => store.insertIfAbsent(jti, exp), // single-use store; false = already used
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

Production, pinned to `draft-ietf-oauth-identity-assertion-authz-grant-04` (21 May 2026). The draft is a moving IETF document; this package follows revision 04, and a later revision that changes the grant is a new release, not a silent change. JWT checks are delegated to `@atlasauth/pca-oidc`; only asymmetric algorithms are accepted by default. This package does not send any network request except the optional JWKS / discovery fetch. It keeps no state: the single-use store is yours (`consumeJti`). Cross-language conformance does not apply: this is a bridge to an OAuth draft, not a PCA wire format. The draft carries no signed example vectors, so the tests build signed grants at test time and an independent implementation cross-checks them (see Cross-check). PCA cryptography has not been independently audited.

This package is a profile of the draft's grant: it additionally REQUIRES the `act` (agent) and `scope` claims, which the draft marks optional, and accepts exactly one `aud`.

### Strict mode (the default)

`verifyIdJag` enforces the draft's section 3.1 shape unless you pass `strictDraft: false`: header `typ` `oauth-id-jag+jwt`, a `client_id` equal to `clientId`, a `jti`, and a single-use `consumeJti`. `clientId` and `consumeJti` are therefore required; omitting either throws a `config` error instead of quietly verifying less. The `jti` is consumed last, after every other check has passed.

```ts
const grant = await verifyIdJag(jwt, {
  issuer, audience, key,
  clientId: 'resource-app-client',
  consumeJti: async (jti, exp) => store.insertIfAbsent(jti, exp), // true = fresh, anything else = refused
});
// loose mode, only if you accept no typ / client_id / jti checks and no replay protection:
await verifyIdJag(jwt, { issuer, audience, key, strictDraft: false });
```

## Failure modes

`verifyIdJag` throws `IdJagVerificationError` with a `code` in every row; it never returns a partial grant.

| Missing or invalid | Result (`code`) |
|---|---|
| empty token, missing options, missing issuer or audience | `invalid_token` / `config` |
| `consumeJti` or `clientId` missing (strict mode, the default) | `config` |
| token longer than 16384 characters | `invalid_token` |
| bad signature, wrong issuer, expired, wrong nonce, disallowed algorithm | the underlying verification code (unchanged from `@atlasauth/pca-oidc`) |
| `aud` is not exactly the one expected audience | `audience` |
| `act` missing or without a string `sub` | `actor` |
| `scope`/`scopes` missing, or a required scope absent | `scope` |
| wrong or missing `typ`, missing `client_id` or `jti`, `client_id` mismatch (strict mode) | `grant` |
| `jti` already used (strict mode), or the `consumeJti` store throws or returns anything but `true` | `grant` |

## Limits

- Pinned to revision 04 of the draft. Later revisions are not followed until a release says so.
- The grant must carry `act` and `scope` and exactly one `aud`; the draft allows more, this profile does not.
- Single-use state is the caller's `consumeJti`; use a shared durable store across instances.
- Asymmetric JWS algorithms only. Network access is limited to the optional JWKS / discovery fetch.
- `tokenExchangeRequest` and `jwtBearerAssertion` build request descriptions only; they send nothing.

## Cross-check

`crosscheck/crosscheck.py` builds and signs ID-JAGs by hand (no JOSE library; only the Ed25519 primitive from `cryptography`) into `fixtures/python-vectors.json`, which the tests verify with this package, including negative variants. It also verifies the grants the package-side test mints. From the package directory:

```sh
python3 crosscheck/crosscheck.py
PCA_CROSSCHECK_OUT=crosscheck/out/ours.json npx vitest run src/crosscheck.test.ts
python3 crosscheck/crosscheck.py --verify-ours crosscheck/out/ours.json
```

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the ID-JAG (via `verifyIdToken`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

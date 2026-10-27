# @atlasauth/pca-oidc

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Root a Proof-Carrying Authority (PCA) grant in a real OIDC-authenticated human. Verify an OpenID Connect ID token (signature, `iss`, `aud`, `exp`/`iat`/`nbf`, `nonce`, `azp`) against the provider's discovery document and JWKS, then map its subject and claims to a PCA principal: a signed-in-subject caveat to embed in the root grant, plus the Ed25519 key the capability chain roots at when the token binds one through a `cnf` confirmation claim.

## Install

```sh
npm i @atlasauth/pca-oidc
```

Depends on `@atlasauth/pca` and `jose`.

## Usage

```ts
import { verifyIdToken, oidcPrincipal } from '@atlasauth/pca-oidc';
import { mintGrant, DEFAULT_RISK_POLICY } from '@atlasauth/pca';

// 1. Verify the ID token. `discover: true` resolves the JWKS from the issuer's discovery document.
const claims = await verifyIdToken(idToken, {
  issuer: 'https://accounts.example.com',
  audience: 'my-client-id',
  nonce, // the nonce you sent in the auth request
  discover: true,
});

// 2. Map it to a PCA principal.
const principal = oidcPrincipal(claims);
// principal.principalId        -> "<iss>#<sub>"
// principal.subjectCaveat      -> caveat recording which human authorized the grant
// principal.principalPublic    -> b64u Ed25519 key from the token's `cnf` OKP JWK (if present)

// 3. Mint a grant rooted at that human (the human's key signs; see @atlasauth/pca).
const { grant } = mintGrant({
  principalSecret, // the human's Ed25519 secret key
  principalPublic: principal.principalPublic!,
  holder: agentPublicKey,
  goal: 'book travel',
  envelope: { predicates: [], caveats: [principal.subjectCaveat], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
});
```

If the token carries no `cnf` key, pass the human's key yourself: `oidcPrincipal(claims, { principalPublic })`. When both are present they must match.

## API

- `verifyIdToken(idToken, options)` - verified claims; throws `OidcVerificationError` with a stable `code`. Options include `issuer`, `audience`, `nonce`, `authorizedParty`, `clockToleranceSec`, `maxTokenAgeSec`, `algorithms` (asymmetric only by default), and one key source: `key`, `jwksUri`, or `discover`.
- `discoverOidc(issuer, options?)`, `discoveryUrl(issuer)` - fetch the provider metadata. Options: `fetch`, `signal`, `maxBytes` (default 1 MiB), `requireHttps` (issuer and `jwks_uri`)
- `createOidcJwks({ jwksUri, ... })`, `createOidcJwksFromIssuer(issuer, ...)` - a caching key resolver for `verifyIdToken`'s `key` option that fails closed on stale or unreachable keys (see below)
- `verifyIdToken` also takes `accessToken` and `code`: when set, the token's `at_hash` / `c_hash` must be present and match (OIDC Core 3.1.3.6)
- `oidcPrincipal(claims, options?)` - build the principal descriptor
- `isOidcSubjectCaveat(caveat)`, `OIDC_SUBJECT_CAVEAT`

## Key caching that fails closed

`verifyIdToken({ jwksUri })` builds a fresh remote key set on every call. For a long-running service use the resolver instead:

```ts
import { createOidcJwksFromIssuer, verifyIdToken } from '@atlasauth/pca-oidc';

const key = await createOidcJwksFromIssuer('https://accounts.example.com', { cacheMaxAgeSec: 600, cooldownSec: 30 });
const claims = await verifyIdToken(idToken, { issuer: 'https://accounts.example.com', audience: 'my-client-id', key, nonce });
```

Keys are cached for `cacheMaxAgeSec`. Past that they are refetched, and if the refetch fails the token is refused with code `keys`: a stale key set is never used. A `kid` that is not in the cached set triggers at most one refetch per `cooldownSec`, so a key rotation is picked up without a fetch storm. `https` is required for the `jwks_uri` unless you pass `requireHttps: false` (local tests).

## Failure modes

Every row ends in a typed error; nothing downgrades to a pass. `OidcVerificationError.code` is shown.

| Missing or invalid | Result |
| --- | --- |
| `idToken` empty / not a string | `invalid_token` |
| `issuer` or `audience` option missing | `config` |
| no key source (`key`, `jwksUri`, `discover`) | `config` |
| non-canonical token spelling (padding, `+` `/`, whitespace, duplicate header keys) | `invalid_token` |
| `alg` `none`, any symmetric alg, or an alg outside `algorithms` | `invalid_token` |
| bad signature / wrong key | `signature` |
| `iss` differs from the pinned `issuer` (exact string) | `issuer` |
| `aud` does not contain `audience` | `audience` |
| `exp` missing or in the past | `expired` |
| `iat` missing, or older than `maxTokenAgeSec` | `issued_at` |
| `nbf` in the future | `not_before` |
| `sub` missing | `claims` |
| `nonce` expected but absent or different | `nonce` |
| several audiences and no `azp`, or `azp` is not you | `azp` |
| `accessToken` given and `at_hash` absent or different | `at_hash` |
| `code` given and `c_hash` absent or different | `c_hash` |
| JWKS unreachable, non-2xx, not a JWK Set, oversize, or stale | `keys` |
| discovery: network error, non-2xx, not JSON, not an object, no `issuer` / `jwks_uri`, issuer differs from the requested one, oversize, non-https when `requireHttps` | `OidcDiscoveryError` |

## Limits

- Pinned to OpenID Connect Core 1.0 (errata set 2) and OpenID Connect Discovery 1.0 (errata set 2). The `at_hash` example pair from Core (`jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y` hashes to `77QmUPtjPfzWtF2AnpK9RQ`) is reproduced in the tests.
- The nonce is checked only when you pass one; always pass the nonce you sent. `at_hash` / `c_hash` are checked only when you pass the value.
- `requireHttps` is off by default in `discoverOidc` for compatibility; set it in production. Redirects on the discovery request are followed by `fetch`; the issuer equality check still applies to the returned document.
- Replay of an ID token is not tracked here; ID tokens are one-time login proofs, so bind them with `nonce`.
- Signature verification is delegated to `jose`. Nothing here is a hardware or remote-attestation claim.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). PCA's cryptography has not been independently audited. ID-token verification is delegated to `jose`.

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the ID token (rejected with code `invalid_token`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

# @atlasauth/pca-oidc

> Maturity: **production** (supported for production use), pinned to OpenID Connect Core 1.0 and OpenID Connect Discovery 1.0 (errata set 2). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Root a Proof-Carrying Authority (PCA) grant in a real OIDC-authenticated human. Verify an OpenID Connect ID token (signature, `iss`, `aud`, `exp`/`iat`/`nbf`, `nonce`, `azp`, `at_hash`/`c_hash`) against the provider's discovery document and JWKS, then map its subject and claims to a PCA principal: a signed-in-subject caveat to embed in the root grant, plus the Ed25519 key the capability chain roots at when the token binds one through a `cnf` confirmation claim.

## Install

```sh
npm i @atlasauth/pca-oidc
```

Depends on `@atlasauth/pca` and `jose`.

## Quick start

```ts
import { createOidcJwks, oidcPrincipal, verifyIdToken } from '@atlasauth/pca-oidc';

// Build the key resolver once per issuer and reuse it: it caches keys, refuses stale or unreachable ones.
const key = createOidcJwks({ jwksUri: 'https://accounts.example.com/jwks' });

// Verify the ID token. Pass the nonce you sent in the authorization request.
const claims = await verifyIdToken(idToken, {
  issuer: 'https://accounts.example.com',
  audience: 'my-client-id',
  key,
  nonce: 'n1',
});

// Map it to a PCA principal.
const principal = oidcPrincipal(claims);
// principal.principalId      -> "https://accounts.example.com#<sub>"
// principal.subjectCaveat    -> caveat recording which human authorized the grant
// principal.principalPublic  -> b64u Ed25519 key from the token's `cnf` OKP JWK (if present)
```

Then mint the root grant with `mintGrant` from `@atlasauth/pca`, signed by the human's key (`principalPublic`), with `principal.subjectCaveat` among the envelope caveats. `verifyChain(chain, principal.principalPublic)` anchors the chain in the OIDC human.

If the token carries no `cnf` key, pass the human's key yourself: `oidcPrincipal(claims, { principalPublic })`. When both are present they must match.

To resolve the key endpoint from the issuer's discovery document instead, use `await createOidcJwksFromIssuer('https://accounts.example.com')`.

## API

- `verifyIdToken(idToken, options)` returns the verified claims or throws `OidcVerificationError` with a stable `code`. Options:
  - `issuer` (required, exact string), `audience` (required, string or array)
  - `nonce`, `authorizedParty`, `accessToken` (checks `at_hash`), `code` (checks `c_hash`)
  - `clockToleranceSec` (default 0), `maxTokenAgeSec`, `algorithms` (default: the asymmetric set `DEFAULT_ID_TOKEN_ALGS`)
  - one key source, in this order of precedence: `key` (a key, JWK or resolver), `jwksUri`, or `discover: true`
  - `requireHttps` (default `true`): applies to `jwksUri`, the issuer when discovering, and the discovered `jwks_uri`
  - `fetch`: used for the discovery request; the key-set request uses the global `fetch`
- `createOidcJwks({ jwksUri, fetch?, cacheMaxAgeSec? = 600, cooldownSec? = 30, maxBytes? = 1 MiB, timeoutMs? = 5000, requireHttps? = true, now? })`: a caching key resolver to pass as `key`
- `createOidcJwksFromIssuer(issuer, options?)`: discovery, then `createOidcJwks`
- `discoverOidc(issuer, { fetch?, signal?, maxBytes? = 1 MiB, requireHttps? = true })`, `discoveryUrl(issuer)`
- `oidcPrincipal(claims, { principalPublic? })`, `isOidcSubjectCaveat(caveat)`, `OIDC_SUBJECT_CAVEAT`
- Constants: `DEFAULT_ID_TOKEN_ALGS`, `DEFAULT_MAX_DISCOVERY_BYTES`, `DEFAULT_JWKS_TIMEOUT_MS`

## Key caching that fails closed

Keys fetched by `createOidcJwks` are used for `cacheMaxAgeSec`. Past that they are refetched, and if the refetch fails the token is refused with code `keys`: a stale key set is never used. A `kid` that is not in the cached set triggers at most one refetch per `cooldownSec`, so a key rotation is picked up without a fetch storm. A request that does not answer within `timeoutMs` is aborted and the token refused. A NaN, negative or infinite age, cooldown, size or timeout is refused when the resolver is built, and a clock that returns a non-finite time refuses every token.

`verifyIdToken({ jwksUri })` and `verifyIdToken({ discover: true })` build the same resolver for that one call, so every call fetches the key set. Build the resolver once and pass it as `key` to cache.

## Failure modes

Every row ends in a typed error; nothing downgrades to a pass. `OidcVerificationError.code` is shown.

| Missing or invalid | Result |
| --- | --- |
| `idToken` empty or not a string | `invalid_token` |
| options missing, or `issuer` or `audience` missing | `config` |
| no key source (`key`, `jwksUri`, `discover`) | `config` |
| `jwksUri` empty, or not https while `requireHttps` is on (the default) | `config` |
| non-canonical token spelling (padding, `+` `/`, whitespace, duplicate header keys) | `invalid_token` |
| `alg` `none`, any symmetric alg, or an alg outside `algorithms` | `invalid_token` |
| bad signature or wrong key | `signature` |
| `kid` not in the key set | `invalid_token` |
| `iss` differs from the pinned `issuer` (exact string) | `issuer` |
| `aud` does not contain `audience` | `audience` |
| `exp` missing or in the past | `expired` |
| `iat` missing, or older than `maxTokenAgeSec` | `issued_at` |
| `nbf` in the future | `not_before` |
| `sub` missing | `claims` |
| `nonce` given and the token's is absent or different | `nonce` |
| several audiences and no `azp`, or `azp` is not you | `azp` |
| `accessToken` given and `at_hash` absent or different | `at_hash` |
| `code` given and `c_hash` absent or different | `c_hash` |
| key set unreachable, non-2xx, not a JWK Set, a key that is not an object, oversize, timed out, or stale and not refetchable | `keys` |
| resolver clock returns NaN or infinity | `keys` |
| resolver option NaN, negative or infinite | `TypeError` when the resolver is built |
| discovery: network error, non-2xx, not JSON, not an object, no `issuer` or `jwks_uri`, issuer differs from the requested one, oversize, http issuer or `jwks_uri` while `requireHttps` is on | `OidcDiscoveryError` |
| `oidcPrincipal`: `iss` or `sub` missing, or a supplied key that is not canonical base64url of 32 bytes | `TypeError` |
| `oidcPrincipal`: supplied key differs from the token's `cnf` key | `Error` |

## Limits

- Pinned to OpenID Connect Core 1.0 and OpenID Connect Discovery 1.0, both incorporating errata set 2. The `at_hash` example pair from Core (`jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y` hashes to `77QmUPtjPfzWtF2AnpK9RQ`) is reproduced in the tests.
- `nonce`, `at_hash` and `c_hash` are checked only when you pass the value. The authorization code flow with PKCE may legitimately omit the nonce; whenever you sent one, pass it.
- Replay of an ID token is not tracked here. ID tokens are one-time login proofs: bind them with `nonce` and a short `maxTokenAgeSec`.
- Redirects on the discovery and key-set requests are followed by `fetch`; the issuer equality check still applies to the returned document.
- Signature verification is delegated to `jose`. Nothing here is a hardware or remote-attestation claim.
- Cross-language conformance does not apply: this is a TypeScript bridge over the OIDC wire format, not a PCA wire format.

## Changes in 0.5

- `discoverOidc` and `createOidcJwksFromIssuer` require https for the issuer and the `jwks_uri` by default. Pass `requireHttps: false` for a local test issuer.
- `verifyIdToken({ jwksUri })` and `verifyIdToken({ discover: true })` use the fail-closed resolver: https required, a size cap, a 5 s timeout, and code `keys` on any key-set failure.
- `createOidcJwks` takes `timeoutMs` and refuses invalid numeric options and a non-finite clock.

## Status

Production. Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). ID-token verification is delegated to `jose`.

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the ID token (rejected with code `invalid_token`): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe, replay or ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.

## License

MIT - see LICENSE

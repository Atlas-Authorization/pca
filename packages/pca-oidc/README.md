# @atlasauth/pca-oidc

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
- `discoverOidc(issuer, options?)`, `discoveryUrl(issuer)` - fetch the provider metadata
- `oidcPrincipal(claims, options?)` - build the principal descriptor
- `isOidcSubjectCaveat(caveat)`, `OIDC_SUBJECT_CAVEAT`

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). PCA's cryptography has not been independently audited. ID-token verification is delegated to `jose`.

## License

MIT - see LICENSE

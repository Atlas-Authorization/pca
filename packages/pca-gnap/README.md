# @atlasauth/pca-gnap

> Maturity: **production** (supported for production use), pinned to RFC 9635 with the `jwsd` key-proof method only. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
await verifyGnapRequest({
  detachedJws, body: req, holder, htm: 'POST', uri: 'https://as.example/gnap',
  seenProof: (id, exp) => store.hasOrAdd(id, exp), // required: a replay store (or replayCheck: 'unchecked')
}); // { ok: true, ... }
```

## API

- Grants: `grantRequestToCapability`, `capabilityToGrantResponse`, `encodeBoundToken`, `verifyGnapToken`, `grantedAccessOf`.
- Access model: `accessToPredicates`, `accessContains`, `accessWithin`, `clampAccess`, `gnapActionResource`, `authorizeGnapAction`.
- Key-bound requests: `signGnapRequest`, `verifyGnapRequest` (GNAP `jwsd`, EdDSA; optional `ath` token binding).
- Step-up: `gnapRequestRequiresStepUp`, `beginGnapContinuation`, `gnapStepUpShare`, `completeGnapContinuation`.
- `AGENT_GNAP_PROFILE`: the machine-readable profile description.

Delegated hops are clamped to the issuer's own authority at issue time (`clampToIssuer`, default on) and are denied at action time if they exceed it.

## Status

Production, for the supported subset below, pinned to RFC 9635 (a published RFC, not a draft). The profile (how GNAP maps onto PCA capabilities) is defined by this package; it is not an IETF profile. The package keeps no state: replay state is the store you supply. Cross-language conformance does not apply: this is a bridge to an IETF protocol, not a PCA wire format. RFC 9635 publishes no signed example for this profile, so the tests build signed requests at test time and an independent implementation cross-checks them (see Cross-check).

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
| replay store (`seenProof`) missing and no `replayCheck: 'unchecked'` | `verifyGnapRequest` throws `GnapError` before reading the proof |
| detached JWS longer than 8192 characters | `{ ok: false, reason }` |
| proof already seen, or the replay store throws or answers anything but `false` | `{ ok: false, reason }` |
| `jwsd` bad signature, tampered body, wrong holder, wrong `typ` or `alg`, stale `created`, wrong `htm`/`uri`, wrong `ath` | `verifyGnapRequest` returns `{ ok: false, reason }` |
| non-canonical detached-JWS spelling | `{ ok: false, reason }` before the signature check |
| middle segment present and not the SHA-256 digest of the content you pass | `{ ok: false, reason: 'not a DETACHED compact JWS' }` |
| access token malformed, broken chain, wrong root issuer | `verifyGnapToken` returns `{ ok: false }` |
| action outside the root envelope or any hop's rights | `authorizeGnapAction` returns `{ allowed: false, reason }` |

## Limits

- The proof covers the SHA-256 digest of the request CONTENT (RFC 9635 section 7.3.3). Pass `body` as the exact bytes (a `string` or `Uint8Array`) your HTTP layer sends or received; any other value is hashed as its strict canonical JSON, so the sender must then transmit exactly that text. No content (`body: undefined`) signs an empty payload. The empty middle segment of a detached JWS and the RFC's own spelling (the digest in the middle) are both accepted.
- The one signed example the RFC prints is RS256 and is refused (EdDSA only); `fixtures/rfc9635-example.json` holds it and the tests verify its signature independently. The RFC text spells its `typ` two ways (`gnap-binding+jwsd` inside the example, `gnap-binding-jwsd` in the text and the media type registration); this package requires the registered `gnap-binding-jwsd`.
- Supported subset only (table above): single access token request, `jwsd` proof, OKP / Ed25519 client keys. Anything else is refused, never ignored.
- A `jwsd` proof is valid for `maxAgeSec` (default 300 s) and is single-use only through your `seenProof` store; share it across verifier instances. The store is called last, after every other check, so a refused proof is not consumed.
- The access token this package issues is a self-contained, key-bound PCA capability chain, not an opaque handle; revocation is the PCA revocation mechanism, not GNAP token management.
- GNAP continuation maps to a PCA step-up; other interaction modes are out of scope.

## Cross-check

`crosscheck/crosscheck.py` builds detached JWS values by hand (no JOSE library; only the Ed25519 primitive from `cryptography`) into `fixtures/python-vectors.json`, which the tests verify with this package, positive and negative. It also verifies requests the package signs. From the package directory:

```sh
python3 crosscheck/crosscheck.py
PCA_CROSSCHECK_OUT=crosscheck/out/ours.json npx vitest run src/crosscheck.test.ts
python3 crosscheck/crosscheck.py --verify-ours crosscheck/out/ours.json
```

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the detached JWS (protected and signature segments): one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
